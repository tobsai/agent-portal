'use strict';

/**
 * routes/scheduled.js — /api/scheduled
 *
 * GET  /api/scheduled — list scheduled tasks with enriched fields
 * POST /api/scheduled — register (or update) a scheduled task
 *   Uses INSERT OR REPLACE / ON CONFLICT semantics so repeated heartbeat
 *   registrations normalise to a single row per (name, schedule) pair.
 *
 * @param {object} deps
 * @param {object}   deps.db
 * @param {Function} deps.requireAuth
 * @param {Function} deps.requireAgentKey
 * @returns {import('express').Router}
 */
const { Router } = require('express');

module.exports = function scheduledRouter({ db, requireAuth, requireAgentKey }) {
  const router = Router();

  // GET /api/scheduled — list scheduled tasks
  router.get('/scheduled', requireAuth, async (req, res) => {
    try {
      // Table may not exist yet; return empty list gracefully
      const rows = await db.query('SELECT * FROM scheduled_tasks ORDER BY next_run_at ASC').catch(() => []);

      // Enrich response with normalised field names for UI consumption
      // last_outcome is included via row spread and exposed as lastOutcome
      const scheduled = rows.map(row => ({
        ...row,
        nextRun:       row.next_run_at,
        lastRun:       row.last_run_at,
        lastRunStatus: row.last_status,
        lastOutcome:   row.last_outcome || null,
      }));

      res.json({ scheduled, total: scheduled.length });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * POST /api/scheduled — register or update a scheduled task.
   *
   * Body:
   *   id            TEXT  (optional — generated from name+schedule if omitted)
   *   name          TEXT  required
   *   schedule      TEXT  required  (cron expression or human string)
   *   schedule_human TEXT optional
   *   enabled       BOOL  optional (default true)
   *   next_run_at   TEXT  optional (ISO timestamp)
   *
   * Idempotent: repeated calls with the same (name, schedule) pair update
   * the existing row rather than creating a duplicate. This eliminates the
   * inflation caused by heartbeat re-registrations (NEXT-059).
   *
   * TODO(lewis): post outcome string to /api/status after cron completion
   */
  router.post('/scheduled', requireAgentKey, async (req, res) => {
    try {
      const { name, schedule, schedule_human, enabled, next_run_at } = req.body;

      if (!name || typeof name !== 'string') {
        return res.status(400).json({ error: '"name" is required' });
      }
      if (!schedule || typeof schedule !== 'string') {
        return res.status(400).json({ error: '"schedule" is required' });
      }

      const now = new Date().toISOString();
      const id  = `${name.toLowerCase().replace(/\s+/g, '-')}-${Buffer.from(schedule).toString('base64').slice(0, 8)}`;

      // ON CONFLICT on (name, schedule) unique index — update in place
      await db.run(
        `INSERT INTO scheduled_tasks
           (id, name, schedule, schedule_human, enabled, next_run_at, updated_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7)
         ON CONFLICT (name, schedule) DO UPDATE SET
           schedule_human = excluded.schedule_human,
           enabled        = excluded.enabled,
           next_run_at    = excluded.next_run_at,
           updated_at     = excluded.updated_at`,
        [
          id,
          name,
          schedule,
          schedule_human || null,
          enabled === false ? 0 : 1,
          next_run_at || null,
          now,
        ]
      );

      const row = await db.get('SELECT * FROM scheduled_tasks WHERE name = $1 AND schedule = $2', [name, schedule]);
      res.json({ success: true, task: row });
    } catch (err) {
      console.error('[scheduled] POST error:', err);
      res.status(500).json({ error: err.message });
    }
  });

  return router;
};

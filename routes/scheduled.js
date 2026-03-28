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
   * PATCH /api/scheduled/:id — write back outcome after a cron run.
   *
   * Body (all fields optional, only provided fields are updated):
   *   last_run_at   TEXT  ISO timestamp of when the task last ran
   *   last_status   TEXT  'success' | 'error' | 'running' | ...
   *   last_outcome  TEXT  human-readable outcome string shown in the UI
   *   next_run_at   TEXT  ISO timestamp of the next scheduled run
   *
   * Returns 404 if the task ID does not exist.
   * Returns 400 if no updatable fields are provided.
   *
   * TODO(lewis): cron jobs should call this endpoint after each run to record
   * their outcome — without it, the error filter tab stays permanently empty
   * and lastOutcome never renders in work.html.
   */
  router.patch('/scheduled/:id', requireAgentKey, async (req, res) => {
    try {
      const { id } = req.params;
      const { last_run_at, last_status, last_outcome, next_run_at } = req.body;

      const VALID_STATUSES = ['success', 'error', 'running', 'skipped', 'unknown'];

      // Reject if last_status is provided but not a known value
      if (last_status !== undefined && !VALID_STATUSES.includes(last_status)) {
        return res.status(400).json({
          error: `"last_status" must be one of: ${VALID_STATUSES.join(', ')}`,
        });
      }

      // Validate ISO-ish timestamps when provided (cheap string check)
      for (const [field, value] of [['last_run_at', last_run_at], ['next_run_at', next_run_at]]) {
        if (value !== undefined && (typeof value !== 'string' || isNaN(Date.parse(value)))) {
          return res.status(400).json({ error: `"${field}" must be a valid ISO timestamp` });
        }
      }

      if (last_outcome !== undefined && typeof last_outcome !== 'string') {
        return res.status(400).json({ error: '"last_outcome" must be a string' });
      }

      const updates = { last_run_at, last_status, last_outcome, next_run_at };
      const provided = Object.entries(updates).filter(([, v]) => v !== undefined);

      if (provided.length === 0) {
        return res.status(400).json({ error: 'No updatable fields provided' });
      }

      const existing = await db.get('SELECT * FROM scheduled_tasks WHERE id = $1', [id]);
      if (!existing) {
        return res.status(404).json({ error: 'Scheduled task not found' });
      }

      const now = new Date().toISOString();

      // Build SET clause with $1…$N for the updated fields, $N+1 for updated_at.
      // id goes at the end as $N+2 (WHERE clause) so that positional ? bindings
      // work correctly after the SQLite adapter's $N→? replacement.
      const values     = provided.map(([, v]) => v);
      const setClauses = provided.map(([col], i) => `${col} = $${i + 1}`).join(', ');
      const updatedAtIdx = values.length + 1;
      const idIdx        = values.length + 2;

      await db.run(
        `UPDATE scheduled_tasks SET ${setClauses}, updated_at = $${updatedAtIdx} WHERE id = $${idIdx}`,
        [...values, now, id]
      );

      const updated = await db.get('SELECT * FROM scheduled_tasks WHERE id = $1', [id]);

      // Enrich with UI field aliases (mirrors GET /api/scheduled)
      res.json({
        success: true,
        task: {
          ...updated,
          nextRun:       updated.next_run_at,
          lastRun:       updated.last_run_at,
          lastRunStatus: updated.last_status,
          lastOutcome:   updated.last_outcome || null,
        },
      });
    } catch (err) {
      console.error('[scheduled] PATCH error:', err);
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

  // DELETE /api/scheduled/:id — remove a scheduled task
  router.delete('/scheduled/:id', requireAgentKey, async (req, res) => {
    try {
      const { id } = req.params;
      const existing = await db.get('SELECT * FROM scheduled_tasks WHERE id = $1', [id]);
      if (!existing) {
        return res.status(404).json({ error: 'Scheduled task not found' });
      }
      await db.run('DELETE FROM scheduled_tasks WHERE id = $1', [id]);
      res.json({ success: true, deleted: id });
    } catch (err) {
      console.error('[scheduled] DELETE error:', err);
      res.status(500).json({ error: err.message });
    }
  });

  return router;
};

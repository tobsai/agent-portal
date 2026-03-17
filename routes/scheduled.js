'use strict';

/**
 * routes/scheduled.js — /api/scheduled
 *
 * Placeholder for scheduled task management.
 * To be implemented when the scheduled tasks feature is built.
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
      res.json({ scheduled: rows, total: rows.length });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
};

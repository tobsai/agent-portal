'use strict';

/**
 * routes/activity.js — /api/activity
 *
 * Returns recent activity (signals) as a flat feed, suitable for the
 * agent-portal dashboard activity panel.
 *
 * @param {object} deps
 * @param {object}   deps.db
 * @param {Function} deps.requireAuth
 * @returns {import('express').Router}
 */
const { Router } = require('express');

module.exports = function activityRouter({ db, requireAuth }) {
  const router = Router();

  // GET /api/activity — recent signals as an activity feed
  router.get('/activity', requireAuth, async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
      const rows = await db.query(
        'SELECT * FROM signals ORDER BY created_at DESC LIMIT $1',
        [limit]
      );
      res.json({ activity: rows, total: rows.length });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  return router;
};

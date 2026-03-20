'use strict';

/**
 * routes/activity.js — /api/activity
 *
 * DEPRECATED (NEXT-088). This route is a dead alias for GET /api/signals.
 *
 * Decision: deprecate, not align.
 *
 * Rationale:
 *   1. No client code in work.html (or any other public asset) calls this
 *      endpoint — confirmed by full source audit in NEXT-088.
 *   2. The response shape { activity: [], total: N } differs from the canonical
 *      GET /api/signals shape { signals: [], total: N }, so a silent alias
 *      would mislead future consumers into treating them as interchangeable.
 *   3. GET /api/signals is strictly richer: it JOINs work_tasks to resolve
 *      task_label, supports query filters (level, task_id, initiative_id), and
 *      will return the true DB count once NEXT-088 lands. Duplicating that
 *      contract in a second route creates a maintenance surface with no upside.
 *   4. A 410 Gone is the correct HTTP status: the resource existed, it is now
 *      intentionally removed, and the replacement is documented.
 *
 * Replacement: GET /api/signals (all existing query params preserved).
 *
 * @param {object} deps
 * @param {object}   deps.db          — not used; kept for interface compatibility
 * @param {Function} deps.requireAuth
 * @returns {import('express').Router}
 */
const { Router } = require('express');

module.exports = function activityRouter({ db, requireAuth }) {
  const router = Router();

  /**
   * GET /api/activity — GONE
   *
   * Returns HTTP 410 with a migration notice.
   * requireAuth is still applied so unauthenticated callers get 401, not 410 —
   * that preserves the auth contract and avoids leaking endpoint existence to
   * unauthenticated scanners.
   */
  router.get('/activity', requireAuth, (_req, res) => {
    res.status(410).json({
      error:       'Gone',
      message:     'GET /api/activity has been removed. Use GET /api/signals instead.',
      replacement: '/api/signals',
    });
  });

  return router;
};

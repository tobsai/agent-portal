'use strict';

/**
 * lib/device-registry.js — Push device token registration routes.
 * Extracted from routes/chat.js (NEXT-039 Part 2).
 *
 * @param {object} deps
 * @param {object}   deps.db          — database module
 * @param {Function} deps.requireAuth — auth middleware
 * @returns {import('express').Router}
 */
const { Router } = require('express');

module.exports = function createDeviceRegistry({ db, requireAuth }) {
  const router = Router();

  // ============ PUSH DEVICES ============
  router.post('/devices/register', requireAuth, async (req, res) => {
    try {
      const { platform, token, bundleId } = req.body;
      if (!token) return res.status(400).json({ error: 'Token required' });

      const userId = req.user?.id || req.agent?.id;
      if (!userId) return res.status(401).json({ error: 'User not identified' });

      const now = new Date().toISOString();
      await db.run(`
        INSERT INTO push_tokens (user_id, platform, token, bundle_id, updated_at)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (token) DO UPDATE SET
          user_id = $1,
          platform = $2,
          bundle_id = $4,
          updated_at = $5
      `, [userId, platform || 'ios', token, bundleId || 'com.mapletree.agent-portal', now]);

      console.log(`[push] Registered ${platform || 'ios'} token for user ${userId}: ${token.substring(0, 8)}...`);
      res.json({ ok: true });
    } catch (err) {
      console.error('[push] Registration error:', err);
      res.status(500).json({ error: 'Registration failed' });
    }
  });

  router.delete('/devices/unregister', requireAuth, async (req, res) => {
    try {
      const { token } = req.body;
      if (!token) return res.status(400).json({ error: 'Token required' });
      await db.run('DELETE FROM push_tokens WHERE token = $1', [token]);
      res.json({ ok: true });
    } catch (err) {
      res.status(500).json({ error: 'Unregister failed' });
    }
  });

  return router;
};

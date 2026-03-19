'use strict';

/**
 * lib/push.js — Push notification delivery to all registered devices.
 * Extracted from server.js (NEXT-039 Part 2).
 *
 * @param {object} deps
 * @param {object} deps.db    — database module (query, run)
 * @param {object} deps.apns  — lib/apns module (sendChatNotification, isConfigured)
 */
module.exports = function createPush({ db, apns }) {
  /**
   * Send push notifications to all registered devices for a user.
   * Called internally when an agent message is finalized.
   */
  async function pushToAllDevices(message, senderName = 'Agent Portal') {
    if (!apns.isConfigured()) return;

    try {
      const tokens = await db.query('SELECT token, platform FROM push_tokens');
      if (!tokens || tokens.length === 0) return;

      console.log(`[push] Sending to ${tokens.length} device(s)`);

      const results = await Promise.allSettled(
        tokens.map(t => apns.sendChatNotification(t.token, message, senderName))
      );

      // Clean up invalid tokens
      for (let i = 0; i < results.length; i++) {
        const result = results[i];
        if (result.status === 'fulfilled' && result.value.error === 'BadDeviceToken') {
          console.log(`[push] Removing invalid token: ${tokens[i].token.substring(0, 8)}...`);
          await db.run('DELETE FROM push_tokens WHERE token = $1', [tokens[i].token]);
        }
      }
    } catch (err) {
      console.error('[push] Error sending notifications:', err);
    }
  }

  return { pushToAllDevices };
};

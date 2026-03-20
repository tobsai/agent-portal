'use strict';

/**
 * lib/push.js — Push notification delivery to all registered devices.
 * Extracted from server.js (NEXT-039 Part 2).
 *
 * @param {object} deps
 * @param {object} deps.db           — database module (query, run)
 * @param {object} deps.apns         — lib/apns module (sendChatNotification, isConfigured)
 * @param {Function} [deps.uuidv4]   — UUID v4 generator (required for signal emit)
 * @param {Function} [deps.broadcast] — broadcast(event, data) (optional)
 */
module.exports = function createPush({ db, apns, uuidv4, broadcast }) {
  /**
   * Send push notifications to all registered devices for a user.
   * Called internally when an agent message is finalized.
   *
   * When APNS push fails (non-2xx from provider or exception), captures to Sentry
   * (if SENTRY_DSN is configured) and emits a `level: 'warn'` signal.
   */
  async function pushToAllDevices(message, senderName = 'Agent Portal') {
    if (!apns.isConfigured()) return;

    let tokens = [];
    try {
      tokens = await db.query('SELECT token, platform FROM push_tokens');
      if (!tokens || tokens.length === 0) return;

      console.log(`[push] Sending to ${tokens.length} device(s)`);

      const results = await Promise.allSettled(
        tokens.map(t => apns.sendChatNotification(t.token, message, senderName))
      );

      // Tally failures and clean up invalid tokens
      const failures = [];
      for (let i = 0; i < results.length; i++) {
        const result = results[i];
        if (result.status === 'fulfilled' && result.value.error === 'BadDeviceToken') {
          console.log(`[push] Removing invalid token: ${tokens[i].token.substring(0, 8)}...`);
          await db.run('DELETE FROM push_tokens WHERE token = $1', [tokens[i].token]);
        } else if (result.status === 'rejected') {
          failures.push(result.reason?.message || 'unknown error');
        } else if (result.status === 'fulfilled' && result.value.error) {
          // Non-BadDeviceToken APNS errors (e.g. Unregistered, ExpiredProviderToken)
          failures.push(result.value.error);
        }
      }

      if (failures.length > 0) {
        const errorSummary = [...new Set(failures)].join('; ');
        const signalMessage = `Push delivery failed: ${failures.length} device${failures.length > 1 ? 's' : ''} — ${errorSummary}`;
        console.error(`[push] ${signalMessage}`);
        _captureFailure(tokens.length, errorSummary, { db, uuidv4, broadcast });
      }
    } catch (err) {
      console.error('[push] Error sending notifications:', err);
      const signalMessage = `Push delivery failed: ${tokens.length} device${tokens.length !== 1 ? 's' : ''} — ${err.message}`;
      _captureFailure(tokens.length, err.message, { db, uuidv4, broadcast });
    }
  }

  return { pushToAllDevices };
};

/**
 * Capture a push delivery failure to Sentry and emit a warning signal.
 * Best-effort — swallows all errors to avoid cascading failures.
 *
 * @param {number} deviceCount
 * @param {string} errorMsg
 * @param {object} deps — { db, uuidv4, broadcast }
 */
function _captureFailure(deviceCount, errorMsg, deps) {
  const signalMessage = `Push delivery failed: ${deviceCount} device${deviceCount !== 1 ? 's' : ''} — ${errorMsg}`;

  // Sentry capture — only if DSN is configured
  if (process.env.SENTRY_DSN) {
    try {
      const Sentry = require('@sentry/node');
      Sentry.captureException(new Error(signalMessage), {
        tags: { subsystem: 'push-delivery' },
        extra: { deviceCount, errorMsg },
      });
    } catch (e) {
      console.error('[push] Sentry capture failed:', e.message);
    }
  }

  // Signal emit — only if deps are available (uuidv4 is the gating dependency)
  if (deps && deps.db && deps.uuidv4) {
    const { insertSignal } = require('./signals');
    insertSignal(deps.db, deps.uuidv4, { level: 'warning', message: signalMessage })
      .then(row => { if (row && deps.broadcast) deps.broadcast('work:signal', row); })
      .catch(e => console.error('[push] Signal insert failed:', e.message));
  }
}

'use strict';

/**
 * lib/webhook-delivery.js — Fire-and-forget webhook delivery for inbound messages.
 *
 * When the portal server receives an inbound message from the iOS app
 * (POST /api/channels/:id/messages), this module POSTs the event payload
 * to the configured WEBHOOK_URL so the OpenClaw plugin's onInbound() handler
 * can route it to the active agent session.
 *
 * Environment variables:
 *   WEBHOOK_URL    — target URL (default: http://127.0.0.1:3001/inbound)
 *   WEBHOOK_SECRET — HMAC key for X-Portal-Signature header
 *   SENTRY_DSN     — if set, failed deliveries are captured to Sentry
 *
 * Payload shape:
 *   { event: "message", channelId, sessionKey, text, senderId, timestamp }
 *
 * Header:
 *   X-Portal-Signature: sha256=<hmac-sha256-hex>
 */

const crypto = require('crypto');

const DEFAULT_WEBHOOK_URL = 'http://127.0.0.1:3001/inbound';

/**
 * Attempt a single HTTP POST to the webhook URL.
 * Resolves with the response status code, throws on network error.
 *
 * @param {string} url
 * @param {string} body  — JSON-stringified payload
 * @param {string} signature
 * @returns {Promise<number>} HTTP status code
 */
async function postOnce(url, body, signature) {
  const res = await fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'X-Portal-Signature': signature,
    },
    body,
    // 5-second timeout via AbortSignal (Node 18+ or undici)
    signal: AbortSignal.timeout ? AbortSignal.timeout(5000) : undefined,
  });
  return res.status;
}

/**
 * Deliver a webhook notification for an inbound user message.
 * Fire-and-forget — call without await. Single retry on 5xx responses.
 *
 * When delivery fails after retry (5xx or network error), captures to Sentry
 * and emits a `level: 'error'` signal via insertSignal(), if deps are provided.
 *
 * @param {object} params
 * @param {string} params.channelId   — portal channel UUID
 * @param {string} params.sessionKey  — gateway session key for this channel
 * @param {string} params.text        — message content
 * @param {string} params.senderId    — user ID or identifier
 * @param {string} [params.timestamp] — ISO timestamp (defaults to now)
 * @param {object} [params._deps]     — injected for signal emit (db, uuidv4, broadcast)
 * @returns {Promise<void>}
 */
async function deliverInboundWebhook({ channelId, sessionKey, text, senderId, timestamp, _deps }) {
  const webhookUrl = process.env.WEBHOOK_URL || DEFAULT_WEBHOOK_URL;
  const webhookSecret = process.env.WEBHOOK_SECRET || '';

  const payload = {
    event: 'message',
    channelId,
    sessionKey,
    text,
    senderId,
    timestamp: timestamp || new Date().toISOString(),
  };
  const body = JSON.stringify(payload);

  const hmac = crypto.createHmac('sha256', webhookSecret);
  hmac.update(body);
  const signature = `sha256=${hmac.digest('hex')}`;

  let finalError = null;
  let finalStatus = null;

  try {
    const status = await postOnce(webhookUrl, body, signature);
    if (status >= 500) {
      // Single retry on server-side errors
      console.warn(`[webhook] 5xx from ${webhookUrl} (${status}), retrying once…`);
      try {
        const retryStatus = await postOnce(webhookUrl, body, signature);
        if (retryStatus >= 500) {
          finalStatus = retryStatus;
          finalError = new Error(`HTTP ${retryStatus}`);
        }
      } catch (retryErr) {
        finalError = retryErr;
      }
    }
  } catch (err) {
    finalError = err;
  }

  if (finalError) {
    const errorMsg = finalStatus ? `HTTP ${finalStatus}` : finalError.message;
    console.error(`[webhook] inbound delivery failed after retry: ${errorMsg}`);
    _captureFailure(webhookUrl, errorMsg, _deps);
  }
}

/**
 * Capture a delivery failure to Sentry and emit a signal.
 * Best-effort — swallows all errors to avoid cascading failures.
 *
 * @param {string}  url      — the webhook URL that failed
 * @param {string}  errorMsg — human-readable failure description
 * @param {object}  [deps]   — { db, uuidv4, broadcast } — optional
 */
function _captureFailure(url, errorMsg, deps) {
  // Sentry capture — only if DSN is configured
  if (process.env.SENTRY_DSN) {
    try {
      const Sentry = require('@sentry/node');
      Sentry.captureException(new Error(`Webhook delivery failed: ${url} — ${errorMsg}`), {
        tags: { subsystem: 'webhook-delivery' },
        extra: { url, errorMsg },
      });
    } catch (e) {
      console.error('[webhook] Sentry capture failed:', e.message);
    }
  }

  // Signal emit — only if deps are injected (i.e. the server is running)
  if (deps && deps.db && deps.uuidv4) {
    const { insertSignal } = require('./signals');
    const message = `Webhook delivery failed: ${url} — ${errorMsg}`;
    insertSignal(deps.db, deps.uuidv4, { level: 'error', message })
      .then(row => { if (row && deps.broadcast) deps.broadcast('work:signal', row); })
      .catch(e => console.error('[webhook] Signal insert failed:', e.message));
  }
}

module.exports = { deliverInboundWebhook };

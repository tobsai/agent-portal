/**
 * lib/gateway-client.js
 * Native OpenClaw Gateway WebSocket client for Agent Portal.
 *
 * Connects to the gateway using its native protocol.
 * Handles auth, reconnection, and dynamic session management.
 *
 * Protocol:
 *   sessions.list   — list available sessions
 *   sessions.create — create a new session
 *   chat.send       — outbound message to a session
 *   chat.delta      — inbound streaming/final response from agent
 *   chat.history    — fetch session history
 *   chat.inject     — inject a note without triggering agent run
 */

'use strict';

const WebSocket = require('ws');
const { EventEmitter } = require('events');
const fs = require('fs');
const path = require('path');

// ── Config ────────────────────────────────────────────────────────────────────

const GATEWAY_URL = process.env.GATEWAY_WS_URL_LOCAL || process.env.GATEWAY_WS_URL?.replace(/^http/, 'ws') || 'ws://127.0.0.1:18789';
const RECONNECT_DELAY_MS = 3000;
const REQUEST_TIMEOUT_MS = 15000;
const PING_INTERVAL_MS = 25000;

/**
 * Resolve gateway auth token.
 * Priority: env var → openclaw.json gateway.auth.token/password
 */
function resolveGatewayToken() {
  if (process.env.GATEWAY_TOKEN) return process.env.GATEWAY_TOKEN;
  try {
    const cfgPath = path.join(process.env.HOME || '~', '.openclaw', 'openclaw.json');
    const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    const auth = cfg?.gateway?.auth || {};
    return auth.token || auth.password || '';
  } catch {
    return '';
  }
}

// ── GatewayClient ─────────────────────────────────────────────────────────────

class GatewayClient extends EventEmitter {
  constructor() {
    super();
    this.ws = null;
    this.authenticated = false;
    this.reconnectTimer = null;
    this.pingTimer = null;
    this.pendingRequests = new Map(); // reqId → { resolve, reject, timer }
    this.reqCounter = 0;
    this._destroyed = false;
  }

  // ── Public API ──────────────────────────────────────────────────────────────

  /**
   * Connect to the gateway. Idempotent — safe to call multiple times.
   */
  connect() {
    if (this._destroyed) return;
    if (this.ws && (
      this.ws.readyState === WebSocket.OPEN ||
      this.ws.readyState === WebSocket.CONNECTING
    )) return;

    const token = resolveGatewayToken();
    console.log('[gateway-client] connecting to', GATEWAY_URL);

    this.ws = new WebSocket(GATEWAY_URL, {
      headers: {
        Authorization: `Bearer ${token}`,
        Origin: 'https://talos.mtree.io',
      },
    });

    this.ws.on('open', () => this._onOpen());
    this.ws.on('message', (data, isBinary) => this._onMessage(isBinary ? data : data.toString()));
    this.ws.on('close', (code, reason) => this._onClose(code, reason));
    this.ws.on('error', (err) => this._onError(err));
  }

  /**
   * List available sessions from the gateway.
   * @returns {Promise<Array<{sessionKey: string, label: string, lastMessage: string, updatedAt: string}>>}
   */
  async listSessions() {
    const res = await this._request('sessions.list', {});
    return res.sessions || [];
  }

  /**
   * Create a new session on the gateway.
   * @param {string} label - human-readable session name
   * @returns {Promise<{sessionKey: string, label: string}>}
   */
  async createSession(label) {
    return this._request('sessions.create', { label });
  }

  /**
   * Send a message to a session.
   * @param {string} sessionKey - e.g. 'portal:general'
   * @param {string} text       - message text
   * @param {string} [idempotencyKey]
   * @returns {Promise<object>} gateway response payload
   */
  async sendMessage(sessionKey, text, idempotencyKey) {
    if (!sessionKey || typeof sessionKey !== 'string') {
      throw new Error('sendMessage: sessionKey is required');
    }
    if (!text || typeof text !== 'string' || !text.trim()) {
      throw new Error('sendMessage: text is required');
    }
    if (!this.isReady) {
      throw new Error('Gateway not connected');
    }
    return this._request('chat.send', {
      sessionKey,
      message: text.trim(),
      ...(idempotencyKey ? { idempotencyKey } : {}),
    });
  }

  /**
   * Fetch history for a session.
   * @param {string} sessionKey
   * @param {number} [limit=50]
   * @returns {Promise<{ messages: Array }>}
   */
  async requestHistory(sessionKey, limit = 50) {
    return this._request('chat.history', { sessionKey, limit });
  }

  /**
   * Inject a system note into a session (no agent run).
   * @param {string} sessionKey
   * @param {string} text
   */
  async inject(sessionKey, text) {
    return this._request('chat.inject', { sessionKey, text });
  }

  /**
   * Whether the client is currently authenticated and ready.
   */
  get isReady() {
    return this.authenticated && this.ws?.readyState === WebSocket.OPEN;
  }

  /**
   * Tear down the client permanently.
   */
  destroy() {
    this._destroyed = true;
    this._clearTimers();
    if (this.ws) {
      try { this.ws.close(1000, 'client destroyed'); } catch {}
      this.ws = null;
    }
    this._rejectAllPending(new Error('GatewayClient destroyed'));
  }

  // ── Internal ────────────────────────────────────────────────────────────────

  _onOpen() {
    console.log('[gateway-client] connected, awaiting challenge');
  }

  _onMessage(text) {
    let msg;
    try { msg = JSON.parse(text); } catch { return; }

    // ── Auth handshake ──────────────────────────────────────────────────────
    if (msg.event === 'connect.challenge') {
      this._handleChallenge(msg.payload?.nonce || '');
      return;
    }

    if (msg.type === 'res' && typeof msg.id === 'string' && msg.id.startsWith('gw-connect-')) {
      if (msg.ok) {
        this.authenticated = true;
        console.log('[gateway-client] authenticated ✓');
        this._startPing();
        this.emit('connected');
      } else {
        console.error('[gateway-client] auth failed:', msg.error?.message);
        this.ws?.close(1008, 'auth failed');
      }
      return;
    }

    // ── Pending request responses ───────────────────────────────────────────
    if (msg.type === 'res' && msg.id && this.pendingRequests.has(msg.id)) {
      const pending = this.pendingRequests.get(msg.id);
      this.pendingRequests.delete(msg.id);
      clearTimeout(pending.timer);
      if (msg.ok) pending.resolve(msg.payload || msg);
      else pending.reject(new Error(msg.error?.message || 'Request failed'));
      return;
    }

    // ── Inbound events ──────────────────────────────────────────────────────
    if (msg.event === 'chat.delta' || msg.event === 'chat') {
      this._handleChatEvent(msg);
      return;
    }

    // Pass through any other events for consumers
    this.emit('event', msg);
  }

  _handleChallenge(nonce) {
    const token = resolveGatewayToken();
    const connectId = `gw-connect-${Date.now()}`;

    const params = {
      minProtocol: 3,
      maxProtocol: 3,
      client: { id: 'webchat-ui', version: '1.0.0', platform: 'web', mode: 'webchat' },
      role: 'operator',
      scopes: ['operator.read', 'operator.write', 'operator.admin'],
      auth: { token },
      userAgent: 'agent-portal/gateway-client',
    };

    // Optional device signature (if configured)
    const privateKeyPem = process.env.WEBCHAT_DEVICE_PRIVATE_KEY || '';
    const publicKeyB64  = process.env.WEBCHAT_DEVICE_PUBLIC_KEY  || '';
    if (privateKeyPem && publicKeyB64) {
      try {
        const crypto = require('crypto');
        const raw = Buffer.from(publicKeyB64, 'base64url');
        const deviceId = crypto.createHash('sha256').update(raw).digest('hex');
        const signedAt = Date.now();
        const scopes = 'operator.read,operator.write,operator.admin';
        const payload = ['v2', deviceId, 'webchat-ui', 'webchat', 'operator', scopes, String(signedAt), token, nonce].join('|');
        const privKey = crypto.createPrivateKey({ key: privateKeyPem, format: 'pem', type: 'pkcs8' });
        const sig = crypto.sign(null, Buffer.from(payload), privKey);
        params.device = { id: deviceId, publicKey: publicKeyB64, signature: sig.toString('base64url'), signedAt, nonce };
      } catch (err) {
        console.warn('[gateway-client] device signing failed (token-only):', err.message);
      }
    }

    this.ws.send(JSON.stringify({ type: 'req', id: connectId, method: 'connect', params }));
  }

  _handleChatEvent(msg) {
    const payload = msg.payload || msg.data || {};
    const sessionKey = payload.sessionKey || payload.session_key;
    const state = payload.state;

    const event = {
      sessionKey,
      state,
      text: payload.text || payload.message?.content || '',
      message: payload.message,
      raw: payload,
    };

    // Streaming delta
    if (state === 'delta' || state === 'streaming') {
      this.emit('delta', event);
      return;
    }

    // Error state
    if (state === 'error') {
      this.emit('agentError', { ...event, errorMessage: payload.errorMessage });
      return;
    }

    // Final response
    if (state === 'final') {
      this.emit('message', event);
      return;
    }

    // Fallback for non-state events
    this.emit('chatEvent', event);
  }

  _onClose(code, reason) {
    this.authenticated = false;
    this._clearTimers();
    this._rejectAllPending(new Error('Gateway disconnected'));
    console.log(`[gateway-client] disconnected (${code})`);
    this.emit('disconnected', { code, reason: reason?.toString() });
    if (!this._destroyed) this._scheduleReconnect();
  }

  _onError(err) {
    console.error('[gateway-client] error:', err.message);
  }

  _scheduleReconnect() {
    if (this.reconnectTimer || this._destroyed) return;
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, RECONNECT_DELAY_MS);
  }

  _startPing() {
    this._clearPing();
    this.pingTimer = setInterval(() => {
      if (this.ws?.readyState === WebSocket.OPEN) {
        try { this.ws.ping(); } catch {}
      }
    }, PING_INTERVAL_MS);
  }

  _clearPing() {
    if (this.pingTimer) { clearInterval(this.pingTimer); this.pingTimer = null; }
  }

  _clearTimers() {
    if (this.reconnectTimer) { clearTimeout(this.reconnectTimer); this.reconnectTimer = null; }
    this._clearPing();
  }

  _request(method, params, timeoutMs = REQUEST_TIMEOUT_MS) {
    return new Promise((resolve, reject) => {
      if (!this.isReady) {
        reject(new Error('Gateway not connected'));
        return;
      }
      const id = `gw-req-${Date.now()}-${++this.reqCounter}`;
      const timer = setTimeout(() => {
        this.pendingRequests.delete(id);
        reject(new Error(`${method} timed out`));
      }, timeoutMs);
      this.pendingRequests.set(id, { resolve, reject, timer });
      this.ws.send(JSON.stringify({ type: 'req', id, method, params }));
    });
  }

  _rejectAllPending(err) {
    for (const [id, pending] of this.pendingRequests.entries()) {
      clearTimeout(pending.timer);
      pending.reject(err);
      this.pendingRequests.delete(id);
    }
  }
}

// ── Singleton ─────────────────────────────────────────────────────────────────

const gatewayClient = new GatewayClient();

module.exports = {
  gatewayClient,
  GatewayClient,
};

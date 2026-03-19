'use strict';

const WebSocket = require('ws');

/**
 * lib/chat-gateway.js — Gateway WebSocket connection, event routing, reconnection,
 * and the native gateway client event wiring.
 * Extracted from server.js (NEXT-027 Part 1).
 *
 * @param {object} deps
 * @param {object}   deps.chatState           — chat-state module instance
 * @param {object}   deps.broadcast           — broadcast module instance ({ broadcastChatEvent, broadcastChannelEvent })
 * @param {Function} deps.sendAgentMessage    — unified message pipeline
 * @param {object}   deps.gatewayClient       — native gateway client (lib/gateway-client.js)
 * @returns {object} Gateway functions and proxy setup
 */
module.exports = function createChatGateway({ chatState, broadcast, sendAgentMessage, gatewayClient }) {
  const {
    CHAT_SESSION_KEY,
    gatewayPendingReqs,
    chatMessageBuffer,
    CHAT_BUFFER_LIMIT,
    resolveAgent,
    normalizeChatMessage,
    pushChatMessage,
    isRecentUserSend,
    sessionChannelMap,
    getLastActiveChannelId,
    getLastActiveSessionKey,
  } = chatState;

  const { broadcastChatEvent, broadcastChannelEvent } = broadcast;

  let chatGatewayWs = null;
  let chatGatewayAuthenticated = false;
  let chatGatewayReconnectTimer = null;
  let chatGatewayReqCounter = 0;

  function buildGatewayConnectParams(nonce = '') {
    const token = process.env.GATEWAY_TOKEN || '';
    const privateKeyPem = process.env.WEBCHAT_DEVICE_PRIVATE_KEY || '';
    const publicKeyB64 = process.env.WEBCHAT_DEVICE_PUBLIC_KEY || '';
    const params = {
      minProtocol: 3, maxProtocol: 3,
      client: { id: 'webchat-ui', version: '1.0.0', platform: 'web', mode: 'webchat' },
      role: 'operator',
      scopes: ['operator.read', 'operator.write', 'operator.admin'],
      auth: { token },
      userAgent: 'agent-portal-chat-api/1.0'
    };

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
        console.error('[chat-api] device auth signing failed:', err.message);
      }
    }

    return params;
  }

  function scheduleChatGatewayReconnect() {
    if (chatGatewayReconnectTimer) return;
    chatGatewayReconnectTimer = setTimeout(() => {
      chatGatewayReconnectTimer = null;
      connectChatGateway();
    }, 3000);
  }

  function chatGatewayRequest(method, params, timeoutMs = 15000) {
    return new Promise((resolve, reject) => {
      if (!chatGatewayWs || chatGatewayWs.readyState !== WebSocket.OPEN || !chatGatewayAuthenticated) {
        reject(new Error('Gateway not connected'));
        return;
      }
      const id = `chat-${Date.now()}-${++chatGatewayReqCounter}`;
      const timer = setTimeout(() => {
        gatewayPendingReqs.delete(id);
        reject(new Error(`${method} timed out`));
      }, timeoutMs);
      gatewayPendingReqs.set(id, {
        resolve: (payload) => { clearTimeout(timer); resolve(payload); },
        reject: (error) => { clearTimeout(timer); reject(error); }
      });
      chatGatewayWs.send(JSON.stringify({ type: 'req', id, method, params }));
    });
  }

  async function refreshChatHistoryFromGateway() {
    try {
      const response = await chatGatewayRequest('chat.history', { sessionKey: CHAT_SESSION_KEY });
      const history = (response.payload?.messages || []).map(normalizeChatMessage).filter(Boolean);
      chatMessageBuffer.length = 0;
      history.slice(-CHAT_BUFFER_LIMIT).forEach(pushChatMessage);
    } catch (err) {
      console.error('[chat-api] failed to refresh history:', err.message);
    }
  }

  function connectChatGateway() {
    if (chatGatewayWs && (chatGatewayWs.readyState === WebSocket.OPEN || chatGatewayWs.readyState === WebSocket.CONNECTING)) return;
    const rawGwUrl = (process.env.GATEWAY_WS_URL || '').trim();
    if (!rawGwUrl) return;
    const gwUrl = rawGwUrl.replace(/^https?/, 'ws').replace(/^(?!wss?:\/\/)/, 'wss://');

    chatGatewayWs = new WebSocket(gwUrl, { headers: { Origin: 'https://talos.mtree.io' } });

    chatGatewayWs.on('message', async (data, isBinary) => {
      const text = isBinary ? data : data.toString();
      let msg;
      try {
        msg = JSON.parse(text);
      } catch {
        return;
      }

      if (msg.event === 'connect.challenge') {
        const connectId = `chat-connect-${Date.now()}`;
        chatGatewayWs.send(JSON.stringify({ type: 'req', id: connectId, method: 'connect', params: buildGatewayConnectParams(msg.payload?.nonce || '') }));
        return;
      }

      if (msg.type === 'res' && typeof msg.id === 'string' && msg.id.startsWith('chat-connect-')) {
        chatGatewayAuthenticated = !!msg.ok;
        broadcastChatEvent('status', { connected: chatGatewayAuthenticated });
        if (!msg.ok) {
          broadcastChatEvent('error', { message: msg.error?.message || 'Gateway auth failed' });
          return;
        }
        // No chat.subscribe needed — gateway pushes chat/agent events automatically after connect
        await refreshChatHistoryFromGateway();
        return;
      }

      if (msg.type === 'res' && gatewayPendingReqs.has(msg.id)) {
        const pending = gatewayPendingReqs.get(msg.id);
        gatewayPendingReqs.delete(msg.id);
        if (msg.ok) pending.resolve(msg);
        else pending.reject(new Error(msg.error?.message || 'Gateway request failed'));
        return;
      }

      if (msg.event === 'chat') {
        const payload = msg.payload || msg.data || {};
        const state = payload.state;
        // Determine which agent this event is from
        const lastActiveSessionKey = getLastActiveSessionKey();
        const eventSessionKey = payload.sessionKey || lastActiveSessionKey;
        const eventAgent = resolveAgent(eventSessionKey, payload.agentId);
        if (state === 'delta') {
          broadcastChatEvent('typing', { active: true, agentId: eventAgent?.id });
          return;
        }
        if (state === 'error') {
          broadcastChatEvent('typing', { active: false });
          broadcastChatEvent('error', { message: payload.errorMessage || 'Agent error' });
          return;
        }
        if (state === 'final') {
          broadcastChatEvent('typing', { active: false });
        }
        const normalized = normalizeChatMessage(payload.message || payload);
        if (normalized) {
          if (normalized.role === 'user' && isRecentUserSend(normalized.text)) {
            return;
          }
          const added = pushChatMessage(normalized);
          if (!added) return;
          broadcastChatEvent('message', normalized);
          // Persist + broadcast + push via unified pipeline for agent messages
          if (normalized.role === 'assistant' && normalized.text) {
            const agentName = eventAgent?.name || 'Agent Portal';
            const agentEmoji = eventAgent?.emoji || '';
            const agentId = eventAgent?.id || null;
            const lastActiveChannelId = getLastActiveChannelId();
            sendAgentMessage(lastActiveChannelId, normalized.text, agentName, agentEmoji, agentId).catch(() => {});
          }
        }
      }
    });

    chatGatewayWs.on('close', () => {
      chatGatewayAuthenticated = false;
      broadcastChatEvent('status', { connected: false });
      for (const [id, pending] of gatewayPendingReqs.entries()) {
        pending.reject(new Error('Gateway disconnected'));
        gatewayPendingReqs.delete(id);
      }
      scheduleChatGatewayReconnect();
    });

    chatGatewayWs.on('error', () => {});
  }

  // ── Wire native gateway client events ─────────────────────────────
  function wireGatewayClientEvents() {
    // chat.delta → typing indicator to all SSE clients + per-DM-channel SSE
    gatewayClient.on('delta', ({ agentId, sessionKey }) => {
      broadcastChatEvent('typing', { active: true, agentId });
      // Also fan typing indicator to channel SSE subscribers for this session's DM channel
      const dmChannelId = sessionChannelMap.get(sessionKey);
      if (dmChannelId) {
        broadcastChannelEvent(dmChannelId, 'typing', { active: true, agentId });
      }
    });

    // final agent message → push to chat buffer + channel DB + push notifications
    gatewayClient.on('message', async (event) => {
      const { agentId, sessionKey, text, message } = event;
      broadcastChatEvent('typing', { active: false });

      // Resolve the correct channel for this reply
      const lastActiveChannelId = getLastActiveChannelId();
      const resolvedChannelId = sessionChannelMap.get(sessionKey) || lastActiveChannelId;

      // Build a normalized message compatible with the existing chat buffer
      const normalized = normalizeChatMessage({
        role: 'assistant',
        content: text || message?.content || '',
        id: `gw-${Date.now()}`,
        timestamp: new Date().toISOString(),
      });
      if (!normalized) return;

      const added = pushChatMessage(normalized);
      if (added) broadcastChatEvent('message', normalized);

      // Persist + broadcast + push via unified pipeline
      if (normalized.text) {
        const agent = resolveAgent(sessionKey, agentId);
        sendAgentMessage(resolvedChannelId, normalized.text, agent?.name || 'Agent Portal', agent?.emoji || '', agent?.id || null).catch(() => {});
      }
    });

    gatewayClient.on('agentError', ({ agentId, errorMessage }) => {
      broadcastChatEvent('typing', { active: false });
      broadcastChatEvent('error', { message: errorMessage || 'Agent error' });
    });

    gatewayClient.on('connected', () => {
      console.log('[gateway-client] native connection ready');
      broadcastChatEvent('status', { connected: true, native: true });
    });

    gatewayClient.on('disconnected', () => {
      console.log('[gateway-client] native connection lost, reconnecting...');
      broadcastChatEvent('status', { connected: false, native: true });
    });
  }

  /** Getter for current gateway auth state (used by health route) */
  function getGatewayState() {
    return { authenticated: chatGatewayAuthenticated, ws: chatGatewayWs };
  }

  return {
    connectChatGateway,
    chatGatewayRequest,
    wireGatewayClientEvents,
    getGatewayState,
  };
};

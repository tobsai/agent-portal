'use strict';

const { deliverInboundWebhook } = require('../lib/webhook-delivery');

/**
 * routes/chat.js — /api/chat/*, /api/chat-debug, /api/tts, /api/chat-config,
 *                  /api/chat-sign, /api/model, /api/channels, /api/devices
 *
 * @param {object} deps
 * @param {object}   deps.db
 * @param {object[]} deps.AGENTS
 * @param {string}   deps.CHAT_SESSION_KEY
 * @param {number}   deps.CHAT_BUFFER_LIMIT
 * @param {Function} deps.requireAuth
 * @param {Function} deps.requireAgentKey
 * @param {Function} deps.uuidv4
 * @param {string}   deps.JWT_SECRET
 * @param {object}   deps.jwt                 — jsonwebtoken module
 * @param {Function} deps.broadcast           — broadcast(event, data)
 * @param {Function} deps.broadcastChatEvent  — broadcastChatEvent(event, data)
 * @param {Function} deps.broadcastChannelEvent — broadcastChannelEvent(channelId, event, data)
 * @param {Function} deps.connectChatGateway
 * @param {Function} deps.chatGatewayRequest  — chatGatewayRequest(type, data): Promise
 * @param {object}   deps.gatewayClient       — native gateway client
 * @param {Function} deps.sendAgentMessage    — sendAgentMessage(channelId, content, name, emoji, senderId): Promise<message>
 * @param {Function} deps.pushToAllDevices    — pushToAllDevices(message, senderName): Promise
 * @param {Function} deps.trackUserSend       — trackUserSend(message)
 * @param {Function} deps.pushChatMessage     — pushChatMessage(entry) → boolean
 * @param {Function} deps.getChatState        — () => { authenticated, ws, buffer, sseClients, channelSseClients, lastActiveChannelId, lastActiveSessionKey, sessionChannelMap }
 * @param {Function} deps.setChatState        — ({ lastActiveChannelId?, lastActiveSessionKey?, sessionChannelMap?: { sessionKey, channelId } })
 * @param {Map}      deps.sessionChannelMap   — Maps sessionKey → channelId for DM reply routing (shared reference)
 * @param {object}   deps.apns                — apns module
 * @param {string}   deps.publicDir
 * @returns {import('express').Router}
 */
const { Router } = require('express');
const path = require('path');
const fs = require('fs');

module.exports = function chatRouter(deps) {
  const {
    db, AGENTS, CHAT_SESSION_KEY, CHAT_BUFFER_LIMIT,
    requireAuth, requireAgentKey, uuidv4,
    JWT_SECRET, jwt,
    broadcast, broadcastChatEvent, broadcastChannelEvent,
    connectChatGateway, chatGatewayRequest,
    gatewayClient,
    sendAgentMessage, pushToAllDevices,
    trackUserSend, pushChatMessage, getChatState, setChatState,
    sessionChannelMap,
    apns,
    publicDir,
  } = deps;

  const router = Router();

  // ============ CHAT DEBUG ============
  const chatDebugLog = [];
  router.post('/chat-debug', (req, res) => {
    chatDebugLog.push({ ...req.body, ip: req.ip, at: new Date().toISOString() });
    if (chatDebugLog.length > 50) chatDebugLog.shift();
    res.json({ ok: true });
  });
  router.get('/chat-debug', (req, res) => {
    if (!req.isAuthenticated()) return res.status(401).json({ error: 'unauthorized' });
    res.json(chatDebugLog);
  });

  // ============ CHAT ENDPOINTS ============
  router.get('/chat/messages', requireAuth, (req, res) => {
    connectChatGateway();
    const { buffer: chatMessageBuffer } = getChatState();
    const rawLimit = parseInt(req.query.limit, 10);
    const limit = Number.isFinite(rawLimit) ? Math.max(1, Math.min(rawLimit, CHAT_BUFFER_LIMIT)) : 50;
    const before = req.query.before;
    let end = chatMessageBuffer.length;
    if (before) {
      const beforeIndex = chatMessageBuffer.findIndex(m => m.id === before);
      if (beforeIndex >= 0) end = beforeIndex;
    }
    const start = Math.max(0, end - limit);
    res.json({
      messages: chatMessageBuffer.slice(start, end),
      hasMore: start > 0
    });
  });

  router.post('/chat/send', requireAuth, async (req, res) => {
    connectChatGateway();
    const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
    if (!message) return res.status(400).json({ error: 'message is required' });
    const { authenticated: chatGatewayAuthenticated } = getChatState();
    if (!chatGatewayAuthenticated) return res.status(503).json({ error: 'Gateway unavailable' });

    const idempotencyKey = req.body?.idempotencyKey || `idemp-${uuidv4()}`;
    try {
      await chatGatewayRequest('chat.send', { sessionKey: CHAT_SESSION_KEY, message, idempotencyKey });
      const entry = { id: `msg-${uuidv4()}`, role: 'user', text: message, timestamp: new Date().toISOString(), status: 'delivered' };
      trackUserSend(message);
      const added = pushChatMessage(entry);
      if (added) broadcastChatEvent('message', entry);
      res.json({ id: entry.id, status: 'delivered' });
    } catch (err) {
      res.status(502).json({ error: err.message || 'Failed to send message' });
    }
  });

  router.get('/chat/stream', async (req, res) => {
    // SSE connections cannot send Authorization headers, so JWT is passed as ?token=
    // This path runs ONLY when jwtMiddleware (Bearer header) did not already authenticate.
    if (!req.isAuthenticated()) {
      const queryToken = typeof req.query?.token === 'string' ? req.query.token : '';
      if (queryToken && !queryToken.startsWith('ak_')) {
        try {
          const decoded = jwt.verify(queryToken, JWT_SECRET);
          const user = await db.get('SELECT * FROM users WHERE id = $1', [decoded.userId]);
          if (user) {
            await new Promise((resolve, reject) => req.logIn(user, { session: false }, err => err ? reject(err) : resolve()));
          } else {
            console.warn('[auth:chatStream] JWT decoded but user not found, id:', decoded.userId);
          }
        } catch (err) {
          if (err.name === 'TokenExpiredError') {
            console.warn('[auth:chatStream] query token expired:', err.message);
            return res.status(401).json({ error: 'Token expired' });
          }
          // Invalid token — log and fall through to the 401 below
          console.warn('[auth:chatStream] invalid query token:', err.name, err.message);
        }
      }
    }
    if (!req.isAuthenticated()) return res.status(401).json({ error: 'Authentication required' });

    res.setHeader('Content-Type', 'text/event-stream');
    res.setHeader('Cache-Control', 'no-cache, no-transform');
    res.setHeader('Connection', 'keep-alive');
    res.setHeader('X-Accel-Buffering', 'no');
    if (typeof res.flushHeaders === 'function') res.flushHeaders();
    connectChatGateway();

    const { sseClients: chatSseClients, authenticated: chatGatewayAuthenticated } = getChatState();
    const writeSseEvent = (r, event, data) => r.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);

    const client = {
      res,
      keepalive: setInterval(() => res.write(': keepalive\n\n'), 25000)
    };
    chatSseClients.add(client);
    writeSseEvent(res, 'status', { connected: chatGatewayAuthenticated });

    req.on('close', () => {
      clearInterval(client.keepalive);
      chatSseClients.delete(client);
    });
  });

  // Chat config (returns proxy WS URL)
  router.get('/chat/config', requireAuth, (req, res) => {
    const proxyWsUrl = (req.protocol === 'https' ? 'wss' : 'ws') + '://' + req.get('host') + '/ws/gateway';
    res.json({
      gatewayWsUrl: proxyWsUrl,
      gatewayToken: '',
      hasDeviceIdentity: false,
      proxyMode: true
    });
  });

  // ============ TTS ============
  router.post('/tts', requireAuth, async (req, res) => {
    const apiKey = process.env.ELEVENLABS_API_KEY;
    if (!apiKey) return res.status(503).json({ error: 'TTS not configured' });

    const { text, voiceId = process.env.ELEVENLABS_VOICE_ID || '21m00Tcm4TlvDq8ikWAM' } = req.body || {};
    if (!text || typeof text !== 'string') return res.status(400).json({ error: 'text is required' });
    if (text.length > 5000) return res.status(400).json({ error: 'text too long (max 5000 chars)' });

    try {
      const elevenRes = await fetch(`https://api.elevenlabs.io/v1/text-to-speech/${encodeURIComponent(voiceId)}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'xi-api-key': apiKey },
        body: JSON.stringify({
          text,
          model_id: 'eleven_multilingual_v2',
          voice_settings: { stability: 0.5, similarity_boost: 0.75 },
        }),
      });

      if (!elevenRes.ok) {
        const errBody = await elevenRes.text().catch(() => '');
        console.error('[tts] ElevenLabs error:', elevenRes.status, errBody);
        return res.status(502).json({ error: 'TTS generation failed' });
      }

      res.set('Content-Type', 'audio/mpeg');
      res.set('Cache-Control', 'no-store');
      const reader = elevenRes.body.getReader();
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(value);
      }
      res.end();
    } catch (err) {
      console.error('[tts] Error:', err.message);
      if (!res.headersSent) res.status(500).json({ error: 'TTS request failed' });
    }
  });

  router.post('/tts/stream', requireAuth, async (req, res) => {
    const apiKey = process.env.ELEVENLABS_API_KEY;
    if (!apiKey) return res.status(503).json({ error: 'TTS not configured' });

    const { text, voiceId = process.env.ELEVENLABS_VOICE_ID || '21m00Tcm4TlvDq8ikWAM' } = req.body || {};
    if (!text || typeof text !== 'string') return res.status(400).json({ error: 'text is required' });
    if (text.length > 8000) return res.status(400).json({ error: 'text too long' });

    const sentences = text.match(/[^.!?]+[.!?]+[\s]*/g) || [text];

    res.set('Content-Type', 'audio/mpeg');
    res.set('Cache-Control', 'no-store');
    res.set('Transfer-Encoding', 'chunked');

    try {
      for (let i = 0; i < sentences.length; i++) {
        const sentence = sentences[i].trim();
        if (!sentence) continue;

        const elevenRes = await fetch(
          `https://api.elevenlabs.io/v1/text-to-speech/${encodeURIComponent(voiceId)}/stream`,
          {
            method: 'POST',
            headers: { 'Content-Type': 'application/json', 'xi-api-key': apiKey },
            body: JSON.stringify({
              text: sentence,
              model_id: 'eleven_flash_v2_5',
              voice_settings: { stability: 0.4, similarity_boost: 0.75, speed: 1.1 },
            }),
          }
        );

        if (!elevenRes.ok) {
          console.error('[tts/stream] ElevenLabs error chunk', i, elevenRes.status);
          continue;
        }

        const reader = elevenRes.body.getReader();
        while (true) {
          const { done, value } = await reader.read();
          if (done) break;
          if (!res.writableEnded) res.write(value);
        }
      }
    } catch (err) {
      console.error('[tts/stream] Error:', err.message);
    } finally {
      if (!res.writableEnded) res.end();
    }
  });

  // ============ CHAT CONFIG / SIGN ============
  router.get('/chat-config', requireAuth, (req, res) => {
    res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
    res.set('Pragma', 'no-cache');
    const proxyWsUrl = (req.protocol === 'https' ? 'wss' : 'ws') + '://' + req.get('host') + '/ws/gateway';
    const config = {
      gatewayWsUrl: proxyWsUrl,
      gatewayToken: '',
      hasDeviceIdentity: false,
      proxyMode: true
    };
    console.log('[chat-config] served:', { wsUrl: config.gatewayWsUrl, proxyMode: true });
    res.json(config);
  });

  router.post('/chat-sign', requireAuth, (req, res) => {
    console.log('[chat-sign] called with nonce:', req.body?.nonce?.substring(0, 8) || 'none');
    const { nonce } = req.body || {};
    const token = process.env.GATEWAY_TOKEN || '';
    const deviceId = process.env.WEBCHAT_DEVICE_ID || '';
    const publicKeyRaw = process.env.WEBCHAT_DEVICE_PUBLIC_KEY || '';
    const privateKeyPem = process.env.WEBCHAT_DEVICE_PRIVATE_KEY || '';

    if (!deviceId || !publicKeyRaw || !privateKeyPem) {
      return res.json({ device: null, error: 'Device identity not configured' });
    }

    try {
      const crypto = require('crypto');
      const signedAt = Date.now();
      const scopes = 'operator.read,operator.write,operator.admin';
      const version = nonce ? 'v2' : 'v1';
      const parts = [version, deviceId, 'webchat-ui', 'webchat', 'operator', scopes, String(signedAt), token];
      if (nonce) parts.push(nonce);
      const payload = parts.join('|');
      const key = crypto.createPrivateKey(privateKeyPem);
      const sig = crypto.sign(null, Buffer.from(payload, 'utf8'), key);
      const device = { id: deviceId, publicKey: publicKeyRaw, signature: sig.toString('base64url'), signedAt };
      if (nonce) device.nonce = nonce;
      res.json({ device });
    } catch (e) {
      console.error('Device signing failed:', e.message);
      res.json({ device: null, error: 'Signing failed' });
    }
  });

  // ============ MODEL SELECTOR ============
  const MODEL_OVERRIDE_PATH = path.join(publicDir, '..', 'data', 'model-override.json');
  const MODEL_DEFAULT = 'anthropic/claude-opus-4-6';

  router.get('/model', requireAuth, (req, res) => {
    try {
      const data = JSON.parse(fs.readFileSync(MODEL_OVERRIDE_PATH, 'utf8'));
      res.json({ model: data.model || MODEL_DEFAULT });
    } catch {
      res.json({ model: MODEL_DEFAULT });
    }
  });

  router.post('/model', requireAuth, (req, res) => {
    const { model } = req.body || {};
    if (!model || typeof model !== 'string') return res.status(400).json({ error: 'model is required' });
    const allowed = [
      'anthropic/claude-opus-4-6',
      'anthropic/claude-sonnet-4-6',
      'xai/grok-4-1-fast-reasoning',
      'xai/grok-4-1-fast-non-reasoning',
      'xai/grok-3',
    ];
    if (!allowed.includes(model)) return res.status(400).json({ error: 'unknown model' });

    try {
      fs.mkdirSync(path.dirname(MODEL_OVERRIDE_PATH), { recursive: true });
      fs.writeFileSync(MODEL_OVERRIDE_PATH, JSON.stringify({ model }, null, 2));
      res.json({ success: true, model, note: 'Model preference saved. Gateway restart required on host to apply.' });
    } catch (err) {
      res.status(500).json({ error: err.message });
    }
  });

  // ============ CHANNELS ============
  router.get('/channels', requireAuth, async (req, res) => {
    try {
      const channels = await db.query('SELECT * FROM channels WHERE is_dm IS NOT TRUE ORDER BY created_at');
      res.json(channels);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.post('/channels', requireAuth, async (req, res) => {
    try {
      const { name, description } = req.body;
      if (!name) return res.status(400).json({ error: 'Name required' });
      const id = uuidv4();
      const safeName = name.toLowerCase().replace(/[^a-z0-9-]/g, '-');
      await db.run(
        'INSERT INTO channels (id, name, description, created_by) VALUES ($1, $2, $3, $4)',
        [id, safeName, description || '', req.user?.id || req.agent?.id]
      );
      if (req.user?.id) {
        await db.run('INSERT INTO channel_members (channel_id, user_id) VALUES ($1, $2)', [id, req.user.id]);
      }
      const channel = await db.get('SELECT * FROM channels WHERE id = $1', [id]);
      res.status(201).json(channel);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.delete('/channels/:id', requireAuth, async (req, res) => {
    try {
      await db.run('DELETE FROM messages WHERE channel_id = $1', [req.params.id]);
      await db.run('DELETE FROM channel_members WHERE channel_id = $1', [req.params.id]);
      await db.run('DELETE FROM channels WHERE id = $1', [req.params.id]);
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.post('/channels/:id/join', requireAuth, async (req, res) => {
    try {
      if (req.user?.id) {
        await db.run(
          'INSERT INTO channel_members (channel_id, user_id) VALUES ($1, $2) ON CONFLICT DO NOTHING',
          [req.params.id, req.user.id]
        );
      }
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.post('/channels/:id/leave', requireAuth, async (req, res) => {
    try {
      if (req.user?.id) {
        await db.run(
          'DELETE FROM channel_members WHERE channel_id = $1 AND user_id = $2',
          [req.params.id, req.user.id]
        );
      }
      res.json({ ok: true });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.get('/channels/:id/messages', requireAuth, async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit) || 50, 200);
      const before = req.query.before;
      let messages;
      if (before) {
        messages = await db.query(
          'SELECT * FROM messages WHERE channel_id = $1 AND created_at < $2 ORDER BY created_at DESC LIMIT $3',
          [req.params.id, before, limit]
        );
      } else {
        messages = await db.query(
          'SELECT * FROM messages WHERE channel_id = $1 ORDER BY created_at DESC LIMIT $2',
          [req.params.id, limit]
        );
      }
      res.json(messages.reverse());
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.post('/channels/:id/messages', requireAuth, async (req, res) => {
    try {
      const { content, mentions, is_delta } = req.body;
      if (!content) return res.status(400).json({ error: 'Content required' });

      const senderType = req.agent ? 'agent' : 'user';
      const senderId = req.agent?.id || req.user?.id;
      const senderName = req.agent?.name || req.user?.name || 'Unknown';
      const senderEmoji = req.agent ? (AGENTS.find(a => a.id === req.agent.id)?.emoji || '') : '';

      // Delta messages: broadcast as SSE delta, skip DB persistence
      if (is_delta === true) {
        const deltaPayload = {
          content,
          sender_type: senderType,
          sender_id: senderId,
          sender_name: senderName,
          sender_emoji: senderEmoji,
          is_delta: true,
        };
        broadcastChannelEvent(req.params.id, 'delta', deltaPayload);
        return res.status(200).json({ ok: true, delta: true });
      }

      const id = uuidv4();
      let message;
      if (senderType === 'agent') {
        message = await sendAgentMessage(req.params.id, content, senderName, senderEmoji, senderId);
        if (!message) return res.status(500).json({ error: 'Failed to store message' });
      } else {
        await db.run(
          'INSERT INTO messages (id, channel_id, sender_type, sender_id, sender_name, sender_emoji, content, mentions) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
          [id, req.params.id, senderType, senderId, senderName, senderEmoji, content, JSON.stringify(mentions || [])]
        );
        message = await db.get('SELECT * FROM messages WHERE id = $1', [id]);
        broadcastChannelEvent(req.params.id, 'message', message);
      }

      // Route messages to agents
      if (senderType === 'user') {
        setChatState({ lastActiveChannelId: req.params.id });

        const channel = await db.get('SELECT * FROM channels WHERE id = $1', [req.params.id]);
        const isDm = channel?.is_dm && channel?.dm_agent_id;

        if (isDm) {
          const dmAgent = AGENTS.find(a => a.id === channel.dm_agent_id);
          if (dmAgent) {
            const sessionKeyForAgent = id => `portal:dm-${id}`;
            const dmSessionKey = sessionKeyForAgent(dmAgent.id);
            setChatState({ lastActiveSessionKey: dmSessionKey });

            // Register the session → channel mapping so that when the agent replies
            // via the native gateway client, wireGatewayClientEvents() routes the
            // response to this exact channel rather than lastActiveChannelId (which
            // is a global and can be clobbered by concurrent messages).
            if (sessionChannelMap) {
              sessionChannelMap.set(dmSessionKey, req.params.id);
            } else {
              setChatState({ sessionChannelMap: { sessionKey: dmSessionKey, channelId: req.params.id } });
            }

            // Notify OpenClaw plugin's onInbound() handler — fire-and-forget
            deliverInboundWebhook({
              channelId: req.params.id,
              sessionKey: dmSessionKey,
              text: content,
              senderId: senderId || 'user',
              timestamp: message?.created_at || new Date().toISOString(),
              // Pass deps so delivery failures emit signals and capture to Sentry
              _deps: { db, uuidv4, broadcast },
            }).catch(() => {});

            if (gatewayClient.isReady) {
              try {
                trackUserSend(content);
                await gatewayClient.sendUserMessage(dmSessionKey, content, message.id);
                console.log('[channels] DM routed via native gateway client to', dmAgent.id, '(sessionKey:', dmSessionKey + ')');
              } catch (err) {
                console.error('[channels] Native client DM failed, falling back:', err.message);
                if (dmAgent.sessionKey) {
                  try {
                    await chatGatewayRequest('chat.send', { sessionKey: dmAgent.sessionKey, message: content, idempotencyKey: message.id });
                  } catch (e2) {
                    console.error('[channels] Legacy DM fallback also failed:', e2.message);
                  }
                }
              }
            } else if (dmAgent.sessionKey) {
              setChatState({ lastActiveSessionKey: dmAgent.sessionKey });
              // Also register in sessionChannelMap so any native-client reply later routes correctly
              if (sessionChannelMap) {
                sessionChannelMap.set(dmAgent.sessionKey, req.params.id);
              } else {
                setChatState({ sessionChannelMap: { sessionKey: dmAgent.sessionKey, channelId: req.params.id } });
              }
              try {
                trackUserSend(content);
                await chatGatewayRequest('chat.send', { sessionKey: dmAgent.sessionKey, message: content, idempotencyKey: message.id });
              } catch (err) {
                console.error('[channels] Failed to route DM to agent:', dmAgent.id, err.message);
              }
            }
          }
        } else {
          setChatState({ lastActiveSessionKey: CHAT_SESSION_KEY });
          const routedAgentIds = new Set();

          if (mentions?.length > 0) {
            for (const mention of mentions) {
              const agent = AGENTS.find(a => a.id === mention);
              if (agent?.sessionKey) {
                routedAgentIds.add(agent.id);
                try {
                  trackUserSend(content);
                  await chatGatewayRequest('chat.send', { sessionKey: agent.sessionKey, message: content, idempotencyKey: message.id });
                } catch (err) {
                  console.error('[channels] Failed to route to agent:', agent.id, err.message);
                }
              }
            }
          }

          if (routedAgentIds.size === 0) {
            const defaultAgent = AGENTS.find(a => a.sessionKey === CHAT_SESSION_KEY);
            if (defaultAgent?.sessionKey) {
              try {
                trackUserSend(content);
                await chatGatewayRequest('chat.send', { sessionKey: defaultAgent.sessionKey, message: content, idempotencyKey: message.id });
              } catch (err) {
                console.error('[channels] Failed to route to default agent:', err.message);
              }
            }
          }
        }
      }

      res.status(201).json(message);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // SSE stream for a channel
  router.get('/channels/:id/stream', requireAuth, (req, res) => {
    res.writeHead(200, {
      'Content-Type': 'text/event-stream',
      'Cache-Control': 'no-cache',
      'Connection': 'keep-alive',
      'X-Accel-Buffering': 'no'
    });
    res.write(':ok\n\n');

    const channelId = req.params.id;
    const { channelSseClients } = getChatState();
    if (!channelSseClients.has(channelId)) channelSseClients.set(channelId, new Set());
    const client = { res, userId: req.user?.id };
    channelSseClients.get(channelId).add(client);

    req.on('close', () => {
      channelSseClients.get(channelId)?.delete(client);
    });
  });

  // NOTE: Push device routes (POST /devices/register, DELETE /devices/unregister)
  // were extracted to lib/device-registry.js (NEXT-039 Part 2).

  return router;
};

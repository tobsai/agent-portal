require('dotenv').config();

// Sentry must be initialized before everything else
const Sentry = require('@sentry/node');
if (process.env.SENTRY_DSN) {
  Sentry.init({
    dsn: process.env.SENTRY_DSN,
    environment: process.env.NODE_ENV || 'development',
    tracesSampleRate: 0.1,
  });
}

// PostHog analytics
const { posthog, captureEvent, shutdown: shutdownPostHog } = require('./lib/posthog');
const apns = require('./lib/apns');

const express = require('express');
const session = require('express-session');
const passport = require('passport');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const http = require('http');
const WebSocket = require('ws');

const jwt = require('jsonwebtoken');
const { JWT_SECRET, configurePassport, jwtMiddleware, requireAuth, requireAgentKey, requireAdmin } = require('./lib/auth');

// ── Native Gateway Client (Phase 1: OpenClaw channel integration) ──────────
const { gatewayClient, sessionKeyForAgent, agentIdForSessionKey } = require('./lib/gateway-client');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ noServer: true });
const gwProxy = new WebSocket.Server({ noServer: true });

// Manual upgrade handling for multiple WS paths
server.on('upgrade', (req, socket, head) => {
  const pathname = new URL(req.url, 'http://localhost').pathname;
  if (pathname === '/ws/gateway') {
    gwProxy.handleUpgrade(req, socket, head, (ws) => gwProxy.emit('connection', ws, req));
  } else if (pathname === '/ws') {
    wss.handleUpgrade(req, socket, head, (ws) => wss.emit('connection', ws, req));
  } else {
    socket.destroy();
  }
});

// Gateway WebSocket proxy - handles auth server-side so clients don't need device identity
gwProxy.on('connection', (clientWs, req) => {
  const gwUrl = (process.env.GATEWAY_WS_URL || '').replace(/^https?/, 'ws').replace(/^(?!wss?:\/\/)/, 'wss://');
  if (!gwUrl) { clientWs.close(1008, 'Gateway not configured'); return; }
  console.log('[gw-proxy] new client, connecting to:', gwUrl);
  const gwWs = new WebSocket(gwUrl, { headers: { Origin: 'https://talos.mtree.io' } });
  let authenticated = false;
  let clientQueue = [];

  gwWs.on('open', () => console.log('[gw-proxy] upstream connected'));

  gwWs.on('message', (data, isBinary) => {
    const text = isBinary ? data : data.toString();

    if (!authenticated) {
      try {
        const msg = JSON.parse(text);
        if (msg.event === 'connect.challenge') {
          const nonce = msg.payload?.nonce || '';
          console.log('[gw-proxy] intercepted challenge, signing server-side');

          const token = process.env.GATEWAY_TOKEN || '';
          const privateKeyPem = process.env.WEBCHAT_DEVICE_PRIVATE_KEY || '';
          const publicKeyB64 = process.env.WEBCHAT_DEVICE_PUBLIC_KEY || '';

          const connectParams = {
            minProtocol: 3, maxProtocol: 3,
            client: { id: 'webchat-ui', version: '1.0.0', platform: 'web', mode: 'webchat' },
            role: 'operator',
            scopes: ['operator.read', 'operator.write', 'operator.admin'],
            auth: { token },
            userAgent: 'agent-portal-proxy/1.0'
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
              connectParams.device = { id: deviceId, publicKey: publicKeyB64, signature: sig.toString('base64url'), signedAt, nonce };
              console.log('[gw-proxy] device auth attached (write scopes)');
            } catch (e) {
              console.error('[gw-proxy] device sign failed, falling back to token-only:', e.message);
            }
          } else {
            console.log('[gw-proxy] no device keys, using token-only (read-only)');
          }

          gwWs.send(JSON.stringify({ type: 'req', id: 'proxy-connect', method: 'connect', params: connectParams }));
          return;
        }

        if (msg.type === 'res' && msg.id === 'proxy-connect') {
          if (msg.ok) {
            authenticated = true;
            console.log('[gw-proxy] auth succeeded, piping');
            clientWs.send(JSON.stringify({ event: 'proxy.connected', payload: { status: 'ok' } }));
            for (const queued of clientQueue) {
              if (gwWs.readyState === WebSocket.OPEN) gwWs.send(queued);
            }
            clientQueue = [];
          } else {
            console.error('[gw-proxy] auth failed:', msg.error);
            clientWs.send(JSON.stringify({ event: 'proxy.error', payload: { error: msg.error?.message || 'Auth failed' } }));
            clientWs.close(1008, msg.error?.message || 'Auth failed');
          }
          return;
        }
      } catch (e) { /* not JSON, pass through */ }
    }

    // NOTE: Push notifications are handled server-side via wireGatewayClientEvents → sendAgentMessage.
    // The gw-proxy path only fires for actively-connected WebSocket clients (app in foreground),
    // at which point iOS suppresses push notifications anyway. Firing here also caused duplicate
    // pushes (one per connected client + one from sendAgentMessage). Removed 2026-03-17.

    if (clientWs.readyState === WebSocket.OPEN) clientWs.send(text);
  });

  gwWs.on('close', (code, reason) => {
    console.log('[gw-proxy] upstream closed:', code);
    const safeCode = (code === 1005 || code === 1006 || !code) ? 1000 : code;
    if (clientWs.readyState === WebSocket.OPEN || clientWs.readyState === WebSocket.CONNECTING) {
      clientWs.close(safeCode, reason);
    }
  });
  gwWs.on('error', (err) => { console.error('[gw-proxy] upstream error:', err.message); clientWs.close(1011, 'Gateway error'); });

  clientWs.on('message', (data, isBinary) => {
    const text = isBinary ? data : data.toString();
    if (!authenticated) {
      try {
        const msg = JSON.parse(text);
        if (msg.method === 'connect') {
          console.log('[gw-proxy] skipping client connect (proxy handles auth)');
          return;
        }
      } catch (e) { /* not JSON */ }
      clientQueue.push(text);
      return;
    }
    if (gwWs.readyState === WebSocket.OPEN) gwWs.send(text);
  });
  clientWs.on('close', () => { if (gwWs.readyState === WebSocket.OPEN || gwWs.readyState === WebSocket.CONNECTING) gwWs.close(); });
  clientWs.on('error', () => { if (gwWs.readyState === WebSocket.OPEN || gwWs.readyState === WebSocket.CONNECTING) gwWs.close(); });
});

// ============ AGENTS REGISTRY ============
const AGENTS = [
  { id: 'lewis', name: 'Lewis', emoji: '📚', sessionKey: 'agent:main:main', avatarUrl: '/assets/lewis-avatar.png' },
  { id: 'marty', name: 'Marty', emoji: '🎯', sessionKey: 'agent:marty:main', avatarUrl: '/assets/marty-avatar.jpg' },
  { id: 'pascal', name: 'Pascal', emoji: '⚙️', sessionKey: 'agent:pascal:main', avatarUrl: '/assets/pascal-avatar.jpg' },
  { id: 'milton', name: 'Milton', emoji: '💰', sessionKey: 'agent:milton:main', avatarUrl: '/assets/milton-avatar.jpg' }
];

// ============ CHAT GATEWAY ============
const CHAT_SESSION_KEY = 'agent:main:main';
const CHAT_BUFFER_LIMIT = 200;
const chatMessageBuffer = [];
const chatSseClients = new Set();
const gatewayPendingReqs = new Map();
const recentUserSends = new Map();
const RECENT_USER_SEND_TTL = 30000;

function userContentKey(text) { return (text || '').slice(0, 200); }
function trackUserSend(text) {
  const key = userContentKey(text);
  recentUserSends.set(key, Date.now());
  if (recentUserSends.size > 50) {
    const now = Date.now();
    for (const [k, ts] of recentUserSends) {
      if (now - ts > RECENT_USER_SEND_TTL) recentUserSends.delete(k);
    }
  }
}
function isRecentUserSend(text) {
  const key = userContentKey(text);
  const ts = recentUserSends.get(key);
  if (!ts) return false;
  if (Date.now() - ts > RECENT_USER_SEND_TTL) { recentUserSends.delete(key); return false; }
  recentUserSends.delete(key);
  return true;
}

let chatGatewayWs = null;
let chatGatewayAuthenticated = false;
// Track last channel that sent a message so agent replies go back to the right channel
let lastActiveChannelId = null;
let lastActiveSessionKey = CHAT_SESSION_KEY; // tracks which agent session is currently active
let chatGatewayReconnectTimer = null;
let chatGatewayReqCounter = 0;

function writeSseEvent(res, event, data) {
  res.write(`event: ${event}\n`);
  res.write(`data: ${JSON.stringify(data)}\n\n`);
}

function broadcastChatEvent(event, data) {
  for (const client of chatSseClients) {
    writeSseEvent(client.res, event, data);
  }
}

// ============ CHANNEL SSE ============
const channelSseClients = new Map(); // channelId -> Set<{res, userId}>

function broadcastChannelEvent(channelId, event, data) {
  const clients = channelSseClients.get(channelId);
  if (clients) {
    for (const client of clients) {
      writeSseEvent(client.res, event, data);
    }
  }
  const allClients = channelSseClients.get('__all__');
  if (allClients) {
    for (const client of allClients) {
      writeSseEvent(client.res, event, { ...data, channelId });
    }
  }
}

function normalizeChatText(content) {
  if (typeof content === 'string') return content;
  if (Array.isArray(content)) {
    return content
      .filter(part => part && part.type === 'text' && typeof part.text === 'string')
      .map(part => part.text)
      .join('\n');
  }
  return '';
}

function looksLikeToolOutput(text) {
  if (!text || text.length < 5) return false;
  const trimmed = text.trim();
  if (/^\{"data":\{/.test(trimmed)) return true;
  if (/^\{"errors":\[/.test(trimmed)) return true;
  if (/^[\s\S]*➜\s/.test(trimmed) && trimmed.includes('workspace')) return true;
  if (trimmed.startsWith('ID:') && trimmed.includes('Vault:')) return true;
  return false;
}

function normalizeChatMessage(message) {
  if (!message || (message.role !== 'user' && message.role !== 'assistant')) return null;
  const text = normalizeChatText(message.content || message.text || '');
  if (!text) return null;
  if (message.role === 'assistant' && looksLikeToolOutput(text)) return null;
  const id = message.id || `msg-${message.role}-${simpleHash(text)}-${Math.floor(Date.now() / 15000)}`;
  return {
    id,
    role: message.role,
    text,
    timestamp: message.timestamp || new Date().toISOString(),
    status: message.status || 'delivered'
  };
}

function simpleHash(str) {
  let hash = 0;
  for (let i = 0; i < Math.min(str.length, 200); i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash |= 0;
  }
  return Math.abs(hash).toString(36);
}

function pushChatMessage(message) {
  const index = chatMessageBuffer.findIndex(m => m.id === message.id);
  if (index >= 0) { chatMessageBuffer[index] = message; return false; }
  const msgTime = new Date(message.timestamp || Date.now()).getTime();
  const dup = chatMessageBuffer.find(m =>
    m.role === message.role && m.text === message.text &&
    Math.abs(new Date(m.timestamp || 0).getTime() - msgTime) < 30000
  );
  if (dup) return false;
  chatMessageBuffer.push(message);
  while (chatMessageBuffer.length > CHAT_BUFFER_LIMIT) chatMessageBuffer.shift();
  return true;
}

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

// ── Unified agent→user message pipeline ────────────────────────────────────
// All agent message deliveries must flow through this function to guarantee
// DB persistence, SSE broadcast, and push notification all happen together.
async function sendAgentMessage(channelId, content, senderName, senderEmoji, senderId) {
  if (!dbReady || !content) return null;
  try {
    let channel;
    if (channelId) {
      channel = await db.get('SELECT id FROM channels WHERE id = $1', [channelId]);
    }
    if (!channel) {
      channel = await db.get("SELECT id FROM channels WHERE name = 'general'");
    }
    if (!channel) return null;

    const id = uuidv4();
    await db.run(
      'INSERT INTO messages (id, channel_id, sender_type, sender_id, sender_name, sender_emoji, content, mentions) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
      [id, channel.id, 'agent', senderId, senderName, senderEmoji, content, '[]']
    );
    const message = await db.get('SELECT * FROM messages WHERE id = $1', [id]);
    if (message) broadcastChannelEvent(channel.id, 'message', message);

    // Push notification — errors must not block message delivery
    try {
      await pushToAllDevices(content, senderName);
    } catch (err) {
      console.error('[sendAgentMessage] Push notification error:', err.message);
    }

    return message || null;
  } catch (err) {
    console.error('[sendAgentMessage] Failed:', err.message);
    return null;
  }
}

// Stores an agent message from the gateway into the channels DB and broadcasts to channel SSE
let dbReady = false;

async function storeAgentMessageInChannel(normalizedMsg, sessionKey, channelId = null) {
  if (!dbReady) return;
  try {
    const agent = AGENTS.find(a => a.sessionKey === sessionKey);
    if (!agent) return;

    let channel;
    if (channelId) {
      channel = await db.get('SELECT id FROM channels WHERE id = $1', [channelId]);
    }
    // For DM channels: if channelId is a DM channel for this agent, use it; otherwise fall back to general
    if (!channel) {
      channel = await db.get("SELECT id FROM channels WHERE name = 'general'");
    }
    if (!channel) return;

    const id = uuidv4();
    await db.run(
      'INSERT INTO messages (id, channel_id, sender_type, sender_id, sender_name, sender_emoji, content, mentions) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
      [id, channel.id, 'agent', agent.id, agent.name, agent.emoji, normalizedMsg.text, '[]']
    );
    const message = await db.get('SELECT * FROM messages WHERE id = $1', [id]);
    if (message) broadcastChannelEvent(channel.id, 'message', message);
  } catch (err) {
    console.error('[chat-api] storeAgentMessageInChannel failed:', err.message);
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
      const eventSessionKey = payload.sessionKey || lastActiveSessionKey;
      const eventAgent = AGENTS.find(a => a.sessionKey === eventSessionKey);
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

connectChatGateway();

// ── Phase 1: Wire native gateway client events ─────────────────────────────
// The native client (lib/gateway-client.js) connects directly to ws://127.0.0.1:18789.
// It supplements the existing proxy path; both can run in parallel during rollout.
// Once Phase 2 is complete the proxy path (gwProxy) and connectChatGateway will be removed.

function wireGatewayClientEvents() {
  // chat.delta → typing indicator to all SSE clients
  gatewayClient.on('delta', ({ agentId, sessionKey }) => {
    broadcastChatEvent('typing', { active: true, agentId });
    // Also broadcast to channel SSE clients watching this session's DM channel
    // (channel lookup deferred to Phase 2)
  });

  // final agent message → push to chat buffer + channel DB + push notifications
  gatewayClient.on('message', async (event) => {
    const { agentId, sessionKey, text, message } = event;
    broadcastChatEvent('typing', { active: false });

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
      const agent = AGENTS.find(a => a.sessionKey === sessionKey || a.id === agentId);
      sendAgentMessage(lastActiveChannelId, normalized.text, agent?.name || 'Agent Portal', agent?.emoji || '', agent?.id || null).catch(() => {});
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

// Start native gateway client (connects to ws://127.0.0.1:18789)
// Only if GATEWAY_TOKEN is set (same guard as the existing proxy path)
if (process.env.GATEWAY_TOKEN) {
  wireGatewayClientEvents();
  gatewayClient.connect();
  console.log('[gateway-client] native client starting');
}

const PORT = process.env.PORT || 3847;

// Trust proxy for Railway
app.set('trust proxy', 1);

// ============ DATABASE SETUP ============
const { db, isProduction } = require('./lib/db');

// ============ SESSION SETUP ============
let sessionStore;
if (isProduction && db.pool) {
  const pgSession = require('connect-pg-simple')(session);
  sessionStore = new pgSession({ pool: db.pool, createTableIfMissing: true });
}

const sessionMiddleware = session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: isProduction,
    maxAge: 30 * 24 * 60 * 60 * 1000
  }
});

app.use(sessionMiddleware);
app.use(passport.initialize());
app.use(passport.session());

configurePassport(db);

// ============ MIDDLEWARE ============
app.use(express.json({ limit: '10mb' }));

const wsClients = new Set();
wss.on('connection', (ws) => {
  wsClients.add(ws);
  ws.on('close', () => wsClients.delete(ws));
  ws.on('error', () => wsClients.delete(ws));
});

function broadcast(event, data) {
  // WebSocket broadcast (used by work.html)
  const msg = JSON.stringify({ event, data });
  wsClients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(msg); });
  // SSE broadcast for work events (picked up by chat.html work widget)
  if (event.startsWith('work:')) {
    broadcastChatEvent(event, data);
  }
}

// JWT auth middleware for mobile app — runs before API routes
app.use('/api', jwtMiddleware(db));

// requireAuth, requireAgentKey, requireAdmin imported from lib/auth

// ============ STATIC ============
app.get('/', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/chat');
  // Show login page if it exists, otherwise redirect to Google OAuth
  const loginPath = path.join(__dirname, 'public', 'login.html');
  if (require('fs').existsSync(loginPath)) return res.sendFile(loginPath);
  res.redirect('/auth/google');
});

app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));
app.use('/downloads', express.static(path.join(__dirname, 'public', 'downloads')));
app.get('/favicon.ico', (req, res) => res.sendFile(path.join(__dirname, 'public', 'favicon.ico')));
app.get('/favicon.svg', (req, res) => res.sendFile(path.join(__dirname, 'public', 'favicon.svg')));

app.get('/download', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'download.html'));
});

// Redirect old /c to canonical /chat
app.get('/c', (req, res) => res.redirect('/chat'));

app.get('/chat', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/auth/google');
  res.set('Cache-Control', 'no-store, no-cache, must-revalidate');
  res.set('Pragma', 'no-cache');
  res.set('Expires', '0');
  res.sendFile(path.join(__dirname, 'public', 'chat.html'));
});

// ============ CHAT DEBUG ============
const chatDebugLog = [];
app.post('/api/chat-debug', (req, res) => {
  chatDebugLog.push({ ...req.body, ip: req.ip, at: new Date().toISOString() });
  if (chatDebugLog.length > 50) chatDebugLog.shift();
  res.json({ ok: true });
});
app.get('/api/chat-debug', (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'unauthorized' });
  res.json(chatDebugLog);
});

// ============ CHAT ENDPOINTS ============
app.get('/api/chat/messages', requireAuth, (req, res) => {
  connectChatGateway();
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

app.post('/api/chat/send', requireAuth, async (req, res) => {
  connectChatGateway();
  const message = typeof req.body?.message === 'string' ? req.body.message.trim() : '';
  if (!message) return res.status(400).json({ error: 'message is required' });
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

app.get('/api/chat/stream', async (req, res) => {
  if (!req.isAuthenticated()) {
    const queryToken = typeof req.query?.token === 'string' ? req.query.token : '';
    if (queryToken && !queryToken.startsWith('ak_')) {
      try {
        const decoded = jwt.verify(queryToken, JWT_SECRET);
        const user = await db.get('SELECT * FROM users WHERE id = $1', [decoded.userId]);
        if (user) {
          // Use req.logIn with session:false to satisfy Passport contract
          await new Promise((resolve, reject) => req.logIn(user, { session: false }, err => err ? reject(err) : resolve()));
        }
      } catch (err) {}
    }
  }
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Authentication required' });

  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache, no-transform');
  res.setHeader('Connection', 'keep-alive');
  res.setHeader('X-Accel-Buffering', 'no');
  if (typeof res.flushHeaders === 'function') res.flushHeaders();
  connectChatGateway();

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
app.get('/api/chat/config', requireAuth, (req, res) => {
  const proxyWsUrl = (req.protocol === 'https' ? 'wss' : 'ws') + '://' + req.get('host') + '/ws/gateway';
  res.json({
    gatewayWsUrl: proxyWsUrl,
    gatewayToken: '',
    hasDeviceIdentity: false,
    proxyMode: true
  });
});

// ============ TTS ============
app.post('/api/tts', requireAuth, async (req, res) => {
  const apiKey = process.env.ELEVENLABS_API_KEY;
  if (!apiKey) return res.status(503).json({ error: 'TTS not configured' });

  const { text, voiceId = process.env.ELEVENLABS_VOICE_ID || '21m00Tcm4TlvDq8ikWAM' } = req.body || {};
  if (!text || typeof text !== 'string') return res.status(400).json({ error: 'text is required' });
  if (text.length > 5000) return res.status(400).json({ error: 'text too long (max 5000 chars)' });

  try {
    const elevenRes = await fetch(`https://api.elevenlabs.io/v1/text-to-speech/${encodeURIComponent(voiceId)}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'xi-api-key': apiKey,
      },
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
    const pump = async () => {
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        res.write(value);
      }
      res.end();
    };
    await pump();
  } catch (err) {
    console.error('[tts] Error:', err.message);
    if (!res.headersSent) res.status(500).json({ error: 'TTS request failed' });
  }
});

app.post('/api/tts/stream', requireAuth, async (req, res) => {
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
app.get('/api/chat-config', requireAuth, (req, res) => {
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

app.post('/api/chat-sign', requireAuth, (req, res) => {
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
const { execFile } = require('child_process');

const MODEL_OVERRIDE_PATH = path.join(__dirname, 'data', 'model-override.json');
const MODEL_DEFAULT = 'anthropic/claude-opus-4-6';

app.get('/api/model', requireAuth, (req, res) => {
  try {
    const data = JSON.parse(fs.readFileSync(MODEL_OVERRIDE_PATH, 'utf8'));
    res.json({ model: data.model || MODEL_DEFAULT });
  } catch {
    res.json({ model: MODEL_DEFAULT });
  }
});

app.post('/api/model', requireAuth, (req, res) => {
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
    fs.mkdirSync(path.join(__dirname, 'data'), { recursive: true });
    fs.writeFileSync(MODEL_OVERRIDE_PATH, JSON.stringify({ model }, null, 2));
    res.json({ success: true, model, note: 'Model preference saved. Gateway restart required on host to apply.' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ AUTH ROUTES ============
app.get('/auth/google', (req, res, next) => {
  const state = req.query.mobile === '1' ? 'mobile' : 'web';
  passport.authenticate('google', { scope: ['profile', 'email'], state })(req, res, next);
});
app.get('/auth/google/callback',
  (req, res, next) => {
    passport.authenticate('google', { failureRedirect: '/?auth=failed' }, (err, user) => {
      if (err) {
        console.error('[auth] Google callback error:', err);
        return res.redirect('/?auth=error');
      }
      if (!user) {
        return res.redirect('/?auth=failed');
      }
      req.logIn(user, (loginErr) => {
        if (loginErr) {
          console.error('[auth] Login error:', loginErr);
          return res.redirect('/?auth=error');
        }
        if (req.query.state === 'mobile') {
          const token = jwt.sign({ userId: user.id, email: user.email }, JWT_SECRET, { expiresIn: '90d' });
          return res.redirect(`com.mapletree.agent-portal://auth/callback?token=${encodeURIComponent(token)}`);
        }
        res.redirect('/chat');
      });
    })(req, res, next);
  }
);
app.get('/auth/logout', (req, res) => { req.logout(() => res.redirect('/')); });

app.get('/api/me', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ id: req.user.id, name: req.user.name, email: req.user.email, picture: req.user.picture, isAdmin: req.user.is_admin });
  } else { res.json(null); }
});

// ============ PUSH NOTIFICATIONS ============
app.post('/api/devices/register', requireAuth, async (req, res) => {
  try {
    const { platform, token, bundleId } = req.body;
    if (!token) return res.status(400).json({ error: 'Token required' });

    const userId = req.user?.id || req.agent?.id;
    if (!userId) return res.status(401).json({ error: 'User not identified' });

    // Upsert: update user_id and timestamp if token already exists
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

app.delete('/api/devices/unregister', requireAuth, async (req, res) => {
  try {
    const { token } = req.body;
    if (!token) return res.status(400).json({ error: 'Token required' });
    await db.run('DELETE FROM push_tokens WHERE token = $1', [token]);
    res.json({ ok: true });
  } catch (err) {
    res.status(500).json({ error: 'Unregister failed' });
  }
});

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

// ============ WORK, STATUS, SIGNALS ============
app.use('/api', require('./routes/work')({
  db,
  requireAuth,
  requireAgentKey,
  uuidv4,
  broadcast,
  publicDir: path.join(__dirname, 'public'),
}));

app.get('/work', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'work.html'));
});

// ============ AGENTS, DM, SUBAGENTS ============
app.use('/api', require('./routes/agents')({
  db,
  AGENTS,
  requireAuth,
  requireAdmin,
  uuidv4,
  publicDir: path.join(__dirname, 'public'),
}));

app.get('/subagents', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'subagents.html'));
});

// ============ HEALTH CHECK ============
app.use('/api', require('./routes/health')({
  gatewayClient,
  getChatState: () => ({ authenticated: chatGatewayAuthenticated, ws: chatGatewayWs }),
}));

// ============ ERROR HANDLING ============
if (process.env.SENTRY_DSN) {
  Sentry.setupExpressErrorHandler(app);
}

app.use((err, req, res, next) => {
  console.error('Unhandled error:', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ============ START ============
async function start() {
  await db.init();

  // Auto-create general channel
  const generalChannel = await db.get("SELECT id FROM channels WHERE name = 'general'");
  if (!generalChannel) {
    await db.run(
      "INSERT INTO channels (id, name, description, is_default) VALUES ($1, 'general', 'General discussion', true)",
      [uuidv4()]
    );
    console.log('✅ Created default #general channel');
  }

  dbReady = true;

  server.listen(PORT, () => {
    console.log(`🚀 Agent Portal running at http://localhost:${PORT}`);
    console.log(`🔒 Google Auth: ${process.env.GOOGLE_CLIENT_ID ? 'Enabled' : 'Disabled'}`);
    console.log(`🗄️  Database: ${isProduction ? 'PostgreSQL' : 'SQLite'}`);
    console.log(`🔌 WebSocket: ws://localhost:${PORT}/ws`);
  });
}

start().catch(console.error);

// ============ PROCESS-LEVEL CRASH HANDLERS ============
let isShuttingDown = false;

async function gracefulCrashExit(reason, error) {
  if (isShuttingDown) return;
  isShuttingDown = true;

  console.error(`\n💀 [CRASH HANDLER] ${reason}:`);
  console.error(error);

  if (process.env.SENTRY_DSN) {
    try {
      Sentry.captureException(error);
      await Sentry.flush(2000);
    } catch (e) { /* best effort */ }
  }

  try { await shutdownPostHog(); } catch (e) { /* best effort */ }

  try {
    server.close();
  } catch (e) { /* best effort */ }

  setTimeout(() => {
    console.log('[CRASH HANDLER] Exiting cleanly for auto-restart...');
    process.exit(0);
  }, 1000);
}

process.on('uncaughtException', (error) => {
  gracefulCrashExit('Uncaught Exception', error);
});

process.on('unhandledRejection', (reason) => {
  gracefulCrashExit('Unhandled Rejection', reason);
});

process.on('SIGTERM', async () => {
  console.log('SIGTERM received, shutting down gracefully...');
  await shutdownPostHog();
  process.exit(0);
});

process.on('SIGINT', async () => {
  console.log('SIGINT received, shutting down gracefully...');
  await shutdownPostHog();
  process.exit(0);
});

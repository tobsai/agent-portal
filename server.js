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
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const http = require('http');
const WebSocket = require('ws');

const jwt = require('jsonwebtoken');
const JWT_SECRET = process.env.SESSION_SECRET || 'agent-portal-dev-secret';

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

    // Intercept finalized agent messages for push notifications
    if (authenticated) {
      try {
        const msg = JSON.parse(text);
        if (msg.event === 'chat.delta' && msg.payload?.state === 'final' && msg.payload?.text) {
          // Fire push notification asynchronously (don't block the proxy)
          pushToAllDevices(msg.payload.text).catch(err => {
            console.error('[gw-proxy] Push notification error:', err.message);
          });
        }
      } catch (e) { /* not JSON or parse error, ignore */ }
    }

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
  { id: 'lewis', name: 'Lewis', emoji: '📚', sessionKey: 'agent:main:main' },
  { id: 'marty', name: 'Marty', emoji: '🔬' },
  { id: 'echo', name: 'Echo', emoji: '🎮' },
  { id: 'pascal', name: 'Pascal', emoji: '💻', sessionKey: 'agent:pascal:main' },
  { id: 'milton', name: 'Milton', emoji: '📊', sessionKey: 'agent:milton:main' }
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
      if (state === 'delta') {
        broadcastChatEvent('typing', { active: true });
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
        // Also persist agent messages to channels DB
        if (normalized.role === 'assistant') {
          storeAgentMessageInChannel(normalized, CHAT_SESSION_KEY, lastActiveChannelId).catch(() => {});
          // Fire push notification to all registered devices
          if (normalized.text) {
            const agentForSession = AGENTS.find(a => a.sessionKey === CHAT_SESSION_KEY);
            const agentName = agentForSession?.name || 'Agent Portal';
            pushToAllDevices(normalized.text, agentName).catch(err =>
              console.error('[chat-gateway] Push notification error:', err.message)
            );
          }
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

const PORT = process.env.PORT || 3847;

// Trust proxy for Railway
app.set('trust proxy', 1);

// ============ DATABASE SETUP ============
let db;
const isProduction = !!process.env.DATABASE_URL;

if (isProduction) {
  const { Pool } = require('pg');
  const pgPool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL.includes('railway') ? { rejectUnauthorized: false } : false
  });

  db = {
    async init() {
      await pgPool.query(`
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY,
          google_id TEXT UNIQUE NOT NULL,
          email TEXT NOT NULL,
          name TEXT,
          picture TEXT,
          is_admin BOOLEAN DEFAULT false,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS agents (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          api_key TEXT UNIQUE NOT NULL,
          created_by TEXT REFERENCES users(id),
          created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS usage_records (
          id SERIAL PRIMARY KEY,
          agent_id TEXT REFERENCES agents(id),
          timestamp TIMESTAMPTZ DEFAULT NOW(),
          model TEXT,
          input_tokens INTEGER DEFAULT 0,
          output_tokens INTEGER DEFAULT 0,
          cache_read_tokens INTEGER,
          cache_write_tokens INTEGER,
          session_key TEXT,
          event_type TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_usage_agent_time ON usage_records(agent_id, timestamp DESC);

        CREATE TABLE IF NOT EXISTS channels (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL UNIQUE,
          description TEXT DEFAULT '',
          created_by TEXT,
          is_default BOOLEAN DEFAULT false,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS channel_members (
          channel_id TEXT,
          user_id TEXT,
          joined_at TIMESTAMPTZ DEFAULT NOW(),
          PRIMARY KEY (channel_id, user_id)
        );

        CREATE TABLE IF NOT EXISTS messages (
          id TEXT PRIMARY KEY,
          channel_id TEXT,
          sender_type TEXT NOT NULL,
          sender_id TEXT NOT NULL,
          sender_name TEXT NOT NULL,
          sender_emoji TEXT,
          content TEXT NOT NULL,
          mentions TEXT DEFAULT '[]',
          reply_to TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );
        CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id, created_at DESC);

        CREATE TABLE IF NOT EXISTS sessions (
          sid VARCHAR NOT NULL COLLATE "default",
          sess JSON NOT NULL,
          expire TIMESTAMP(6) NOT NULL,
          PRIMARY KEY (sid)
        );
        CREATE INDEX IF NOT EXISTS IDX_session_expire ON sessions (expire);

        CREATE TABLE IF NOT EXISTS push_tokens (
          id SERIAL PRIMARY KEY,
          user_id TEXT REFERENCES users(id),
          platform TEXT NOT NULL DEFAULT 'ios',
          token TEXT NOT NULL,
          bundle_id TEXT DEFAULT 'com.mapletree.agent-portal',
          created_at TIMESTAMPTZ DEFAULT NOW(),
          updated_at TIMESTAMPTZ DEFAULT NOW(),
          UNIQUE(token)
        );
      `);
    },
    async query(sql, params = []) {
      const result = await pgPool.query(sql, params);
      return result.rows;
    },
    async get(sql, params = []) {
      const rows = await this.query(sql, params);
      return rows[0] || null;
    },
    async run(sql, params = []) {
      await pgPool.query(sql, params);
    },
    pool: pgPool
  };
} else {
  let Database;
  try { Database = require('better-sqlite3'); } catch (e) {
    console.error('better-sqlite3 not available, SQLite fallback disabled');
    console.error('Set DATABASE_URL for PostgreSQL');
    process.exit(1);
  }
  const dataDir = path.join(__dirname, 'data');
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

  const sqliteDb = new Database(path.join(dataDir, 'portal.db'));

  db = {
    async init() {
      sqliteDb.exec(`
        CREATE TABLE IF NOT EXISTS users (
          id TEXT PRIMARY KEY,
          google_id TEXT UNIQUE NOT NULL,
          email TEXT NOT NULL,
          name TEXT,
          picture TEXT,
          is_admin INTEGER DEFAULT 0,
          created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS agents (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          api_key TEXT UNIQUE NOT NULL,
          created_by TEXT,
          created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS usage_records (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          agent_id TEXT,
          timestamp TEXT DEFAULT (datetime('now')),
          model TEXT,
          input_tokens INTEGER DEFAULT 0,
          output_tokens INTEGER DEFAULT 0,
          cache_read_tokens INTEGER,
          cache_write_tokens INTEGER,
          session_key TEXT,
          event_type TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_usage_agent_time ON usage_records(agent_id, timestamp DESC);
        CREATE TABLE IF NOT EXISTS channels (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL UNIQUE,
          description TEXT DEFAULT '',
          created_by TEXT,
          is_default INTEGER DEFAULT 0,
          created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS channel_members (
          channel_id TEXT,
          user_id TEXT,
          joined_at TEXT DEFAULT (datetime('now')),
          PRIMARY KEY (channel_id, user_id)
        );
        CREATE TABLE IF NOT EXISTS messages (
          id TEXT PRIMARY KEY,
          channel_id TEXT,
          sender_type TEXT NOT NULL,
          sender_id TEXT NOT NULL,
          sender_name TEXT NOT NULL,
          sender_emoji TEXT,
          content TEXT NOT NULL,
          mentions TEXT DEFAULT '[]',
          reply_to TEXT,
          created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id, created_at DESC);
        CREATE TABLE IF NOT EXISTS push_tokens (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id TEXT,
          platform TEXT NOT NULL DEFAULT 'ios',
          token TEXT NOT NULL UNIQUE,
          bundle_id TEXT DEFAULT 'com.mapletree.agent-portal',
          created_at TEXT DEFAULT (datetime('now')),
          updated_at TEXT DEFAULT (datetime('now'))
        );
      `);
    },
    async query(sql, params = []) {
      const sqliteSql = sql.replace(/\$(\d+)/g, '?');
      return sqliteDb.prepare(sqliteSql).all(...params);
    },
    async get(sql, params = []) {
      const sqliteSql = sql.replace(/\$(\d+)/g, '?');
      return sqliteDb.prepare(sqliteSql).get(...params);
    },
    async run(sql, params = []) {
      const sqliteSql = sql.replace(/\$(\d+)/g, '?');
      sqliteDb.prepare(sqliteSql).run(...params);
    }
  };
}

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

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await db.get('SELECT * FROM users WHERE id = $1', [id]);
    done(null, user);
  } catch (err) { done(err, null); }
});

if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
  passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback'
  }, async (accessToken, refreshToken, profile, done) => {
    try {
      let user = await db.get('SELECT * FROM users WHERE google_id = $1', [profile.id]);
      if (!user) {
        const id = uuidv4();
        const email = profile.emails?.[0]?.value || '';
        const isFirstUser = !(await db.get('SELECT id FROM users LIMIT 1'));
        await db.run(
          'INSERT INTO users (id, google_id, email, name, picture, is_admin) VALUES ($1, $2, $3, $4, $5, $6)',
          [id, profile.id, email, profile.displayName, profile.photos?.[0]?.value, isFirstUser]
        );
        user = await db.get('SELECT * FROM users WHERE id = $1', [id]);
      }
      done(null, user);
    } catch (err) { done(err, null); }
  }));
}

// ============ MIDDLEWARE ============
app.use(express.json({ limit: '10mb' }));

const wsClients = new Set();
wss.on('connection', (ws) => {
  wsClients.add(ws);
  ws.on('close', () => wsClients.delete(ws));
  ws.on('error', () => wsClients.delete(ws));
});

function broadcast(event, data) {
  const msg = JSON.stringify({ event, data });
  wsClients.forEach(c => { if (c.readyState === WebSocket.OPEN) c.send(msg); });
}

// JWT auth middleware for mobile app — runs before API routes
app.use('/api', async (req, res, next) => {
  if (req.isAuthenticated()) return next();
  const authHeader = req.headers.authorization;
  if (authHeader && authHeader.startsWith('Bearer ')) {
    const token = authHeader.slice(7);
    if (token.startsWith('ak_')) return next();
    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user = await db.get('SELECT * FROM users WHERE id = $1', [decoded.userId]);
      if (user) {
        req.user = user;
        req.isAuthenticated = () => true;
      }
    } catch (e) { /* invalid token, continue unauthenticated */ }
  }
  next();
});

function requireAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) return requireAgentKey(req, res, next);
  res.status(401).json({ error: 'Authentication required' });
}

async function requireAgentKey(req, res, next) {
  const key = req.headers.authorization?.replace('Bearer ', '');
  if (!key) return res.status(401).json({ error: 'API key required' });
  const agent = await db.get('SELECT * FROM agents WHERE api_key = $1', [key]);
  if (!agent) return res.status(401).json({ error: 'Invalid API key' });
  req.agent = agent;
  next();
}

function requireAdmin(req, res, next) {
  if (req.user?.is_admin) return next();
  res.status(403).json({ error: 'Admin access required' });
}

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
          req.user = user;
          req.isAuthenticated = () => true;
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

app.post('/api/bootstrap', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Login first' });
  try {
    await db.run('UPDATE users SET is_admin = true WHERE id = $1', [req.user.id]);
    const existing = await db.get('SELECT id FROM agents LIMIT 1');
    if (existing) return res.json({ message: 'Already bootstrapped', agentExists: true });
    const id = uuidv4();
    const apiKey = 'ak_' + uuidv4().replace(/-/g, '');
    await db.run(
      'INSERT INTO agents (id, name, api_key, created_by) VALUES ($1, $2, $3, $4)',
      [id, 'Talos', apiKey, req.user.id]
    );
    res.json({ message: 'Bootstrapped! Agent created.', agent: { id, name: 'Talos', apiKey } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============ AGENTS ============
// Returns the hardcoded AGENTS registry (for @-mention autocomplete etc.)
app.get('/api/agents', (req, res) => {
  res.json(AGENTS.map(a => ({ id: a.id, name: a.name, emoji: a.emoji })));
});

// DB agent management (for API key auth)
app.post('/api/agents', requireAuth, async (req, res) => {
  try {
    if (!req.user.is_admin) {
      const existingAgents = await db.get('SELECT id FROM agents LIMIT 1');
      if (!existingAgents) {
        await db.run('UPDATE users SET is_admin = true WHERE id = $1', [req.user.id]);
        req.user.is_admin = true;
      } else {
        return res.status(403).json({ error: 'Admin access required' });
      }
    }
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Agent name required' });
    const id = uuidv4();
    const apiKey = 'ak_' + uuidv4().replace(/-/g, '');
    await db.run('INSERT INTO agents (id, name, api_key, created_by) VALUES ($1, $2, $3, $4)', [id, name, apiKey, req.user.id]);
    res.status(201).json({ id, name, apiKey });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/agents/:id', requireAuth, requireAdmin, async (req, res) => {
  try { await db.run('DELETE FROM agents WHERE id = $1', [req.params.id]); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/agents/:id/key', requireAuth, requireAdmin, async (req, res) => {
  try {
    const agent = await db.get('SELECT api_key FROM agents WHERE id = $1', [req.params.id]);
    if (!agent) return res.status(404).json({ error: 'Agent not found' });
    res.json({ apiKey: agent.api_key });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============ CHANNELS ============
app.get('/api/channels', requireAuth, async (req, res) => {
  try {
    const channels = await db.query('SELECT * FROM channels ORDER BY created_at');
    res.json(channels);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/channels', requireAuth, async (req, res) => {
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

app.delete('/api/channels/:id', requireAuth, async (req, res) => {
  try {
    await db.run('DELETE FROM messages WHERE channel_id = $1', [req.params.id]);
    await db.run('DELETE FROM channel_members WHERE channel_id = $1', [req.params.id]);
    await db.run('DELETE FROM channels WHERE id = $1', [req.params.id]);
    res.json({ ok: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/channels/:id/join', requireAuth, async (req, res) => {
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

app.post('/api/channels/:id/leave', requireAuth, async (req, res) => {
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

app.get('/api/channels/:id/messages', requireAuth, async (req, res) => {
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

app.post('/api/channels/:id/messages', requireAuth, async (req, res) => {
  try {
    const { content, mentions } = req.body;
    if (!content) return res.status(400).json({ error: 'Content required' });

    const id = uuidv4();
    const senderType = req.agent ? 'agent' : 'user';
    const senderId = req.agent?.id || req.user?.id;
    const senderName = req.agent?.name || req.user?.name || 'Unknown';
    const senderEmoji = req.agent ? (AGENTS.find(a => a.id === req.agent.id)?.emoji || '') : '';

    await db.run(
      'INSERT INTO messages (id, channel_id, sender_type, sender_id, sender_name, sender_emoji, content, mentions) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
      [id, req.params.id, senderType, senderId, senderName, senderEmoji, content, JSON.stringify(mentions || [])]
    );

    const message = await db.get('SELECT * FROM messages WHERE id = $1', [id]);

    broadcastChannelEvent(req.params.id, 'message', message);

    // Route messages to agents
    if (senderType === 'user') {
      // Track which channel is active so agent replies route back here
      lastActiveChannelId = req.params.id;

      const routedAgentIds = new Set();

      // Route to explicitly @-mentioned agents
      if (mentions?.length > 0) {
        for (const mention of mentions) {
          const agent = AGENTS.find(a => a.id === mention);
          if (agent?.sessionKey) {
            routedAgentIds.add(agent.id);
            try {
              trackUserSend(content);
              await chatGatewayRequest('chat.send', {
                sessionKey: agent.sessionKey,
                message: content,
                idempotencyKey: id
              });
            } catch (err) {
              console.error('[channels] Failed to route to agent:', agent.id, err.message);
            }
          }
        }
      }

      // If no agents were explicitly mentioned, route to the default agent
      if (routedAgentIds.size === 0) {
        const defaultAgent = AGENTS.find(a => a.sessionKey === CHAT_SESSION_KEY);
        if (defaultAgent?.sessionKey) {
          try {
            trackUserSend(content);
            await chatGatewayRequest('chat.send', {
              sessionKey: defaultAgent.sessionKey,
              message: content,
              idempotencyKey: id
            });
          } catch (err) {
            console.error('[channels] Failed to route to default agent:', err.message);
          }
        }
      }
    }

    res.status(201).json(message);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// SSE stream for a channel
app.get('/api/channels/:id/stream', requireAuth, (req, res) => {
  res.writeHead(200, {
    'Content-Type': 'text/event-stream',
    'Cache-Control': 'no-cache',
    'Connection': 'keep-alive',
    'X-Accel-Buffering': 'no'
  });
  res.write(':ok\n\n');

  const channelId = req.params.id;
  if (!channelSseClients.has(channelId)) channelSseClients.set(channelId, new Set());
  const client = { res, userId: req.user?.id };
  channelSseClients.get(channelId).add(client);

  req.on('close', () => {
    channelSseClients.get(channelId)?.delete(client);
  });
});

// ============ AGENT THINKING STATUS ============
let agentThinkingStatus = { status: 'idle', task: null, timestamp: null };
let thinkingExpireTimer = null;

app.post('/api/status', requireAgentKey, (req, res) => {
  try {
    const { status, task } = req.body;
    if (!status || !['thinking', 'idle'].includes(status)) {
      return res.status(400).json({ error: 'status must be "thinking" or "idle"' });
    }

    if (thinkingExpireTimer) {
      clearTimeout(thinkingExpireTimer);
      thinkingExpireTimer = null;
    }

    const timestamp = new Date().toISOString();
    agentThinkingStatus = { status, task: task || null, timestamp };
    broadcast('agent:status', agentThinkingStatus);

    if (status === 'thinking') {
      thinkingExpireTimer = setTimeout(() => {
        agentThinkingStatus = { status: 'idle', task: null, timestamp: new Date().toISOString() };
        broadcast('agent:status', agentThinkingStatus);
        thinkingExpireTimer = null;
        console.log('[status] Auto-expired thinking status to idle');
      }, 5 * 60 * 1000);
    }

    res.json({ success: true, status: agentThinkingStatus });
  } catch (err) {
    console.error('Error updating agent thinking status:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/status', requireAuth, (req, res) => {
  res.json(agentThinkingStatus);
});

// ============ AGENT HEALTH MONITORING ============
let agentHealthStatus = {};

app.post('/api/agent-health', requireAgentKey, (req, res) => {
  try {
    const { agentId, iMessagePolling, heartbeatActive, gatewayUptime } = req.body;
    if (!agentId) return res.status(400).json({ error: 'agentId is required' });

    const now = new Date().toISOString();
    agentHealthStatus[agentId] = {
      agentId,
      lastReportedAt: now,
      iMessagePolling: iMessagePolling || {
        lastPoll: null,
        lastMessage: null,
        messagesQueued: 0,
        pollingActive: false
      },
      heartbeatActive: heartbeatActive !== undefined ? heartbeatActive : true,
      gatewayUptime: gatewayUptime || 0
    };

    broadcast('agent-health', agentHealthStatus[agentId]);
    res.json({ success: true, timestamp: now });
  } catch (err) {
    console.error('Error updating agent health:', err);
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/agent-health', requireAuth, (req, res) => {
  try {
    const agentId = req.query.agent_id;
    if (agentId) {
      const health = agentHealthStatus[agentId];
      if (!health) return res.status(404).json({ error: 'No health data for this agent' });

      const lastReportedAt = new Date(health.lastReportedAt);
      const now = new Date();
      const minutesSinceReport = Math.floor((now - lastReportedAt) / 1000 / 60);
      const lastPoll = health.iMessagePolling?.lastPoll ? new Date(health.iMessagePolling.lastPoll) : null;
      const minutesSincePoll = lastPoll ? Math.floor((now - lastPoll) / 1000 / 60) : null;

      return res.json({
        ...health,
        staleness: {
          reportStale: minutesSinceReport > 10,
          pollStale: minutesSincePoll !== null && minutesSincePoll > 15,
          minutesSinceReport,
          minutesSincePoll
        }
      });
    }
    res.json(agentHealthStatus);
  } catch (err) {
    console.error('Error fetching agent health:', err);
    res.status(500).json({ error: err.message });
  }
});

// ============ HEALTH CHECK ============
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.get('/api/gateway-status', (req, res) => {
  const gwUrl = (process.env.GATEWAY_WS_URL || '');
  res.json({
    gatewayAuthenticated: chatGatewayAuthenticated,
    gatewayWsState: chatGatewayWs ? chatGatewayWs.readyState : null,
    gatewayUrlConfigured: !!gwUrl,
    gatewayUrlPrefix: gwUrl ? gwUrl.substring(0, 20) + '...' : null,
    timestamp: new Date().toISOString()
  });
});

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

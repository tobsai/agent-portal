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
const createDeviceRegistry = require('./lib/device-registry');

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

// ── Extracted modules (NEXT-027 Part 1) ────────────────────────────────────
const createChatState = require('./lib/chat-state');
const createBroadcast = require('./lib/broadcast');
const createChatGateway = require('./lib/chat-gateway');

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

// gwProxy connection handler wired after chatGateway is constructed (see below)

// ============ CHAT STATE (extracted) ============
const chatState = createChatState();
const {
  AGENTS,
  CHAT_SESSION_KEY,
  CHAT_BUFFER_LIMIT,
  chatSseClients,
  channelSseClients,
  sessionChannelMap,
  trackUserSend,
  pushChatMessage,
  getChatState,
  setChatState,
} = chatState;

// ============ BROADCAST (extracted) ============
const { broadcastChatEvent, broadcastChannelEvent } = createBroadcast({
  chatSseClients,
  channelSseClients,
});

// ============ WEBHOOK DELIVERY ============
async function deliverWebhook(channelId, content, sender, timestamp) {
  const webhookUrl = process.env.WEBHOOK_URL;
  if (!webhookUrl) return; // webhook is optional

  const webhookSecret = process.env.WEBHOOK_SECRET || '';
  const payload = { type: 'message', channelId, content, sender, timestamp };
  const body = JSON.stringify(payload);

  try {
    const crypto = require('crypto');
    const hmac = crypto.createHmac('sha256', webhookSecret);
    hmac.update(body);
    const signature = `sha256=${hmac.digest('hex')}`;

    await fetch(webhookUrl, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'X-Portal-Signature': signature,
      },
      body,
    });
  } catch (err) {
    // Swallow errors — webhook failure must not break message delivery
    console.error('[webhook] delivery failed:', err.message);
  }
}

// ── Unified agent→user message pipeline ────────────────────────────────────
let dbReady = false;

async function sendAgentMessage(channelId, content, senderName, senderEmoji, senderId) {
  if (!dbReady || !content) return null;
  if (!senderId) senderId = (senderName || 'agent').toLowerCase().replace(/\s+/g, '-');
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
    const timestamp = new Date().toISOString();
    await db.run(
      'INSERT INTO messages (id, channel_id, sender_type, sender_id, sender_name, sender_emoji, content, mentions, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
      [id, channel.id, 'agent', senderId, senderName, senderEmoji, content, '[]', timestamp]
    );
    const message = await db.get('SELECT * FROM messages WHERE id = $1', [id]);
    if (message) broadcastChannelEvent(channel.id, 'message', message);

    // Push notification — errors must not block message delivery
    try {
      await pushToAllDevices(content, senderName);
    } catch (err) {
      console.error('[sendAgentMessage] Push notification error:', err.message);
    }

    // Webhook delivery — fire-and-forget
    deliverWebhook(channel.id, content, senderName, timestamp).catch(() => {});

    return message || null;
  } catch (err) {
    console.error('[sendAgentMessage] Failed:', err.message);
    return null;
  }
}

// ============ CHAT GATEWAY (extracted) ============
const chatGateway = createChatGateway({
  chatState,
  broadcast: { broadcastChatEvent, broadcastChannelEvent },
  sendAgentMessage,
  gatewayClient,
});
const { connectChatGateway, chatGatewayRequest } = chatGateway;

// Attach proxy handler (moved to lib/chat-gateway.js)
chatGateway.setupGwProxy(gwProxy);

// Augment getChatState to include gateway-owned fields
const originalGetChatState = getChatState;
function getFullChatState() {
  const state = originalGetChatState();
  const gwState = chatGateway.getGatewayState();
  return { ...state, authenticated: gwState.authenticated, ws: gwState.ws };
}

connectChatGateway();

// ── Phase 1: Wire native gateway client events ─────────────────────────────
if (process.env.GATEWAY_TOKEN) {
  chatGateway.wireGatewayClientEvents();
  gatewayClient.connect();
  console.log('[gateway-client] native client starting');
}

const PORT = process.env.PORT || 3847;

// Trust proxy for Railway
app.set('trust proxy', 1);

// ============ DATABASE SETUP ============
const { db, isProduction } = require('./lib/db');

// ============ PUSH NOTIFICATIONS ============
// uuidv4 and broadcast are passed so push failures emit signals to the dashboard.
// broadcast is defined below — but pushToAllDevices is only called after server
// start when broadcast is already wired, so the closure captures the correct ref.
const { pushToAllDevices } = require('./lib/push')({ db, apns, uuidv4, broadcast });

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

// ============ STATIC ============
app.get('/', (req, res) => {
  if (req.isAuthenticated()) return res.redirect('/chat');
  const loginPath = path.join(__dirname, 'public', 'login.html');
  if (require('fs').existsSync(loginPath)) return res.sendFile(loginPath);
  res.redirect('/auth/google');
});

app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));
app.use('/downloads', express.static(path.join(__dirname, 'public', 'downloads')));
// Static stylesheets — serve individual CSS files from public/ by name
app.get('/work.css', (req, res) => res.sendFile(path.join(__dirname, 'public', 'work.css')));
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

// ============ CHAT, TTS, CHANNELS ============
app.use('/api', require('./routes/chat')({
  db,
  AGENTS,
  CHAT_SESSION_KEY,
  CHAT_BUFFER_LIMIT,
  requireAuth,
  requireAgentKey,
  uuidv4,
  JWT_SECRET,
  jwt,
  broadcast,
  broadcastChatEvent,
  broadcastChannelEvent,
  connectChatGateway,
  chatGatewayRequest,
  gatewayClient,
  sendAgentMessage,
  pushToAllDevices,
  trackUserSend,
  pushChatMessage,
  getChatState: getFullChatState,
  setChatState,
  sessionChannelMap,
  apns,
  publicDir: path.join(__dirname, 'public'),
}));

// ============ DEVICE REGISTRATION ============
app.use('/api', createDeviceRegistry({ db, requireAuth }));

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

// ============ SCHEDULED TASKS ============
app.use('/api', require('./routes/scheduled')({ db, requireAuth, requireAgentKey }));

// ============ ACTIVITY FEED ============
app.use('/api', require('./routes/activity')({ db, requireAuth }));

// ============ HEALTH CHECK ============
app.use('/api', require('./routes/health')({
  db,
  gatewayClient,
  getChatState: () => chatGateway.getGatewayState(),
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

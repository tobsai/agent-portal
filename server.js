require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const http = require('http');
const WebSocket = require('ws');

const app = express();
const server = http.createServer(app);
const wss = new WebSocket.Server({ server, path: '/ws' });

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

        -- Work items: things the agent is/was working on
        CREATE TABLE IF NOT EXISTS work_items (
          id TEXT PRIMARY KEY,
          agent_id TEXT REFERENCES agents(id),
          title TEXT NOT NULL,
          description TEXT DEFAULT '',
          status TEXT DEFAULT 'active',
          category TEXT DEFAULT 'task',
          started_at TIMESTAMPTZ DEFAULT NOW(),
          completed_at TIMESTAMPTZ,
          metadata JSONB DEFAULT '{}'
        );

        -- Activity feed: timeline of events
        CREATE TABLE IF NOT EXISTS activity (
          id TEXT PRIMARY KEY,
          agent_id TEXT REFERENCES agents(id),
          work_item_id TEXT REFERENCES work_items(id) ON DELETE CASCADE,
          event_type TEXT NOT NULL,
          message TEXT NOT NULL,
          metadata JSONB DEFAULT '{}',
          created_at TIMESTAMPTZ DEFAULT NOW()
        );

        -- Scheduled items: cron jobs, reminders, heartbeats
        CREATE TABLE IF NOT EXISTS scheduled (
          id TEXT PRIMARY KEY,
          agent_id TEXT REFERENCES agents(id),
          name TEXT NOT NULL,
          schedule_type TEXT NOT NULL,
          schedule_expr TEXT,
          next_run TIMESTAMPTZ,
          last_run TIMESTAMPTZ,
          status TEXT DEFAULT 'active',
          metadata JSONB DEFAULT '{}'
        );

        -- Sub-agents: spawned sessions
        CREATE TABLE IF NOT EXISTS subagents (
          id TEXT PRIMARY KEY,
          agent_id TEXT REFERENCES agents(id),
          label TEXT,
          task TEXT NOT NULL,
          status TEXT DEFAULT 'running',
          session_key TEXT,
          started_at TIMESTAMPTZ DEFAULT NOW(),
          completed_at TIMESTAMPTZ,
          result TEXT,
          metadata JSONB DEFAULT '{}'
        );

        -- Someday/Maybe items
        CREATE TABLE IF NOT EXISTS someday_maybe (
          id TEXT PRIMARY KEY,
          agent_id TEXT REFERENCES agents(id),
          title TEXT NOT NULL,
          description TEXT DEFAULT '',
          category TEXT DEFAULT 'idea',
          status TEXT DEFAULT 'active',
          created_at TIMESTAMPTZ DEFAULT NOW(),
          last_reviewed TIMESTAMPTZ,
          metadata JSONB DEFAULT '{}'
        );

        -- Usage tracking
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

        -- Sessions table for connect-pg-simple
        CREATE TABLE IF NOT EXISTS sessions (
          sid VARCHAR NOT NULL COLLATE "default",
          sess JSON NOT NULL,
          expire TIMESTAMP(6) NOT NULL,
          PRIMARY KEY (sid)
        );
        CREATE INDEX IF NOT EXISTS IDX_session_expire ON sessions (expire);
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
  const Database = require('better-sqlite3');
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
        CREATE TABLE IF NOT EXISTS work_items (
          id TEXT PRIMARY KEY,
          agent_id TEXT,
          title TEXT NOT NULL,
          description TEXT DEFAULT '',
          status TEXT DEFAULT 'active',
          category TEXT DEFAULT 'task',
          started_at TEXT DEFAULT (datetime('now')),
          completed_at TEXT,
          metadata TEXT DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS activity (
          id TEXT PRIMARY KEY,
          agent_id TEXT,
          work_item_id TEXT,
          event_type TEXT NOT NULL,
          message TEXT NOT NULL,
          metadata TEXT DEFAULT '{}',
          created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE TABLE IF NOT EXISTS scheduled (
          id TEXT PRIMARY KEY,
          agent_id TEXT,
          name TEXT NOT NULL,
          schedule_type TEXT NOT NULL,
          schedule_expr TEXT,
          next_run TEXT,
          last_run TEXT,
          status TEXT DEFAULT 'active',
          metadata TEXT DEFAULT '{}'
        );
        CREATE TABLE IF NOT EXISTS subagents (
          id TEXT PRIMARY KEY,
          agent_id TEXT,
          label TEXT,
          task TEXT NOT NULL,
          status TEXT DEFAULT 'running',
          session_key TEXT,
          started_at TEXT DEFAULT (datetime('now')),
          completed_at TEXT,
          result TEXT,
          metadata TEXT DEFAULT '{}'
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
        CREATE TABLE IF NOT EXISTS someday_maybe (
          id TEXT PRIMARY KEY,
          agent_id TEXT,
          title TEXT NOT NULL,
          description TEXT DEFAULT '',
          category TEXT DEFAULT 'idea',
          status TEXT DEFAULT 'active',
          created_at TEXT DEFAULT (datetime('now')),
          last_reviewed TEXT,
          metadata TEXT DEFAULT '{}'
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
app.use(express.json());

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

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) return requireAgentKey(req, res, next);
  if (req.isAuthenticated()) return next();
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
  if (req.isAuthenticated()) {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
  } else {
    res.sendFile(path.join(__dirname, 'public', 'landing.html'));
  }
});

app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));

app.get('/dashboard', (req, res) => {
  if (!req.isAuthenticated()) return res.redirect('/');
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// ============ AUTH ROUTES ============
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));
app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/' }),
  (req, res) => res.redirect('/dashboard')
);
app.get('/auth/logout', (req, res) => { req.logout(() => res.redirect('/')); });
app.get('/api/me', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({ id: req.user.id, name: req.user.name, email: req.user.email, picture: req.user.picture, isAdmin: req.user.is_admin });
  } else { res.json(null); }
});

// Bootstrap: ensure first user is admin, and auto-create default agent if none exist
app.post('/api/bootstrap', async (req, res) => {
  if (!req.isAuthenticated()) return res.status(401).json({ error: 'Login first' });
  try {
    // Make this user admin
    await db.run('UPDATE users SET is_admin = true WHERE id = $1', [req.user.id]);
    
    // Check if any agents exist
    const existing = await db.get('SELECT id FROM agents LIMIT 1');
    if (existing) return res.json({ message: 'Already bootstrapped', agentExists: true });
    
    // Create default agent
    const id = uuidv4();
    const apiKey = 'ak_' + uuidv4().replace(/-/g, '');
    await db.run(
      'INSERT INTO agents (id, name, api_key, created_by) VALUES ($1, $2, $3, $4)',
      [id, 'Talos', apiKey, req.user.id]
    );
    
    res.json({ message: 'Bootstrapped! Agent created.', agent: { id, name: 'Talos', apiKey } });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============ AGENT ROUTES ============
app.get('/api/agents', requireAuth, async (req, res) => {
  try {
    res.json(await db.query('SELECT id, name, created_at FROM agents ORDER BY created_at DESC'));
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/agents', requireAuth, async (req, res) => {
  try {
    // Auto-promote first user to admin if no agents exist yet
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

// ============ WORK ITEMS ============
app.get('/api/work', requireAuth, async (req, res) => {
  try {
    const status = req.query.status || 'active';
    const limit = Math.min(parseInt(req.query.limit) || 50, 100);
    const items = await db.query(
      `SELECT w.*, a.name as agent_name FROM work_items w
       LEFT JOIN agents a ON w.agent_id = a.id
       WHERE w.status = $1
       ORDER BY w.started_at DESC LIMIT $2`,
      [status, limit]
    );
    res.json(items);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/work', requireAuth, async (req, res) => {
  try {
    const { title, description = '', category = 'task', status = 'active', metadata = {} } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });
    const id = uuidv4();
    const agentId = req.agent?.id || null;
    const now = new Date().toISOString();
    await db.run(
      'INSERT INTO work_items (id, agent_id, title, description, status, category, started_at, metadata) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
      [id, agentId, title, description, status, category, now, JSON.stringify(metadata)]
    );
    const item = await db.get('SELECT w.*, a.name as agent_name FROM work_items w LEFT JOIN agents a ON w.agent_id = a.id WHERE w.id = $1', [id]);
    broadcast('work:created', item);
    res.status(201).json(item);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/work/:id', requireAuth, async (req, res) => {
  try {
    const existing = await db.get('SELECT * FROM work_items WHERE id = $1', [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'Not found' });
    const { title, description, status, category, metadata } = req.body;
    const completedAt = (status === 'completed' && existing.status !== 'completed') ? new Date().toISOString() : existing.completed_at;
    await db.run(
      'UPDATE work_items SET title = $1, description = $2, status = $3, category = $4, completed_at = $5, metadata = $6 WHERE id = $7',
      [title ?? existing.title, description ?? existing.description, status ?? existing.status, category ?? existing.category, completedAt, JSON.stringify(metadata ?? JSON.parse(existing.metadata || '{}')), req.params.id]
    );
    const item = await db.get('SELECT w.*, a.name as agent_name FROM work_items w LEFT JOIN agents a ON w.agent_id = a.id WHERE w.id = $1', [req.params.id]);
    broadcast('work:updated', item);
    res.json(item);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/work/:id', requireAuth, async (req, res) => {
  try { await db.run('DELETE FROM work_items WHERE id = $1', [req.params.id]); broadcast('work:deleted', { id: req.params.id }); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

// ============ ACTIVITY FEED ============
app.get('/api/activity', requireAuth, async (req, res) => {
  try {
    const limit = Math.min(parseInt(req.query.limit) || 30, 100);
    const items = await db.query(
      `SELECT ac.*, a.name as agent_name FROM activity ac
       LEFT JOIN agents a ON ac.agent_id = a.id
       ORDER BY ac.created_at DESC LIMIT $1`,
      [limit]
    );
    res.json(items);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/activity', requireAuth, async (req, res) => {
  try {
    const { event_type, message, work_item_id, metadata = {} } = req.body;
    if (!message) return res.status(400).json({ error: 'Message required' });
    const id = uuidv4();
    const agentId = req.agent?.id || null;
    const now = new Date().toISOString();
    await db.run(
      'INSERT INTO activity (id, agent_id, work_item_id, event_type, message, metadata, created_at) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [id, agentId, work_item_id || null, event_type || 'update', message, JSON.stringify(metadata), now]
    );
    const item = await db.get('SELECT ac.*, a.name as agent_name FROM activity ac LEFT JOIN agents a ON ac.agent_id = a.id WHERE ac.id = $1', [id]);
    broadcast('activity:new', item);
    res.status(201).json(item);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============ SCHEDULED ============
app.get('/api/scheduled', requireAuth, async (req, res) => {
  try {
    const items = await db.query(
      `SELECT s.*, a.name as agent_name FROM scheduled s
       LEFT JOIN agents a ON s.agent_id = a.id
       ORDER BY s.next_run ASC`
    );
    res.json(items);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/scheduled', requireAuth, async (req, res) => {
  try {
    const { name, schedule_type, schedule_expr, next_run, metadata = {} } = req.body;
    if (!name || !schedule_type) return res.status(400).json({ error: 'Name and schedule_type required' });
    const id = uuidv4();
    const agentId = req.agent?.id || null;
    await db.run(
      'INSERT INTO scheduled (id, agent_id, name, schedule_type, schedule_expr, next_run, metadata) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [id, agentId, name, schedule_type, schedule_expr || null, next_run || null, JSON.stringify(metadata)]
    );
    const item = await db.get('SELECT s.*, a.name as agent_name FROM scheduled s LEFT JOIN agents a ON s.agent_id = a.id WHERE s.id = $1', [id]);
    broadcast('scheduled:updated', item);
    res.status(201).json(item);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/scheduled/:id', requireAuth, async (req, res) => {
  try {
    const existing = await db.get('SELECT * FROM scheduled WHERE id = $1', [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'Not found' });
    const { name, next_run, last_run, status, metadata } = req.body;
    await db.run(
      'UPDATE scheduled SET name = $1, next_run = $2, last_run = $3, status = $4, metadata = $5 WHERE id = $6',
      [name ?? existing.name, next_run !== undefined ? next_run : existing.next_run, last_run !== undefined ? last_run : existing.last_run, status ?? existing.status, JSON.stringify(metadata ?? JSON.parse(existing.metadata || '{}')), req.params.id]
    );
    const item = await db.get('SELECT s.*, a.name as agent_name FROM scheduled s LEFT JOIN agents a ON s.agent_id = a.id WHERE s.id = $1', [req.params.id]);
    broadcast('scheduled:updated', item);
    res.json(item);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============ SUB-AGENTS ============
app.get('/api/subagents', requireAuth, async (req, res) => {
  try {
    const items = await db.query(
      `SELECT s.*, a.name as agent_name FROM subagents s
       LEFT JOIN agents a ON s.agent_id = a.id
       ORDER BY s.started_at DESC LIMIT 30`
    );
    res.json(items);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/subagents', requireAuth, async (req, res) => {
  try {
    const { label, task, session_key, metadata = {} } = req.body;
    if (!task) return res.status(400).json({ error: 'Task required' });
    const id = uuidv4();
    const agentId = req.agent?.id || null;
    const now = new Date().toISOString();
    await db.run(
      'INSERT INTO subagents (id, agent_id, label, task, session_key, started_at, metadata) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [id, agentId, label || null, task, session_key || null, now, JSON.stringify(metadata)]
    );
    const item = await db.get('SELECT s.*, a.name as agent_name FROM subagents s LEFT JOIN agents a ON s.agent_id = a.id WHERE s.id = $1', [id]);
    broadcast('subagent:created', item);
    res.status(201).json(item);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/subagents/:id', requireAuth, async (req, res) => {
  try {
    const existing = await db.get('SELECT * FROM subagents WHERE id = $1', [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'Not found' });
    const { status, result, metadata } = req.body;
    const completedAt = (status === 'completed' || status === 'failed') && !existing.completed_at ? new Date().toISOString() : existing.completed_at;
    await db.run(
      'UPDATE subagents SET status = $1, result = $2, completed_at = $3, metadata = $4 WHERE id = $5',
      [status ?? existing.status, result ?? existing.result, completedAt, JSON.stringify(metadata ?? JSON.parse(existing.metadata || '{}')), req.params.id]
    );
    const item = await db.get('SELECT s.*, a.name as agent_name FROM subagents s LEFT JOIN agents a ON s.agent_id = a.id WHERE s.id = $1', [req.params.id]);
    broadcast('subagent:updated', item);
    res.json(item);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============ USAGE TRACKING ============
app.post('/api/usage', requireAuth, async (req, res) => {
  try {
    const { model, input_tokens = 0, output_tokens = 0, cache_read_tokens, cache_write_tokens, session_key, event_type } = req.body;
    const agentId = req.agent?.id || null;
    const now = new Date().toISOString();
    await db.run(
      'INSERT INTO usage_records (agent_id, timestamp, model, input_tokens, output_tokens, cache_read_tokens, cache_write_tokens, session_key, event_type) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
      [agentId, now, model || null, input_tokens, output_tokens, cache_read_tokens || null, cache_write_tokens || null, session_key || null, event_type || null]
    );
    res.status(201).json({ success: true });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/usage', requireAuth, async (req, res) => {
  try {
    const agentId = req.agent?.id || req.query.agent_id;
    const now = new Date();
    
    // Calculate time ranges
    const day24h = new Date(now - 24 * 60 * 60 * 1000).toISOString();
    const day7d = new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();
    const day30d = new Date(now - 30 * 24 * 60 * 60 * 1000).toISOString();
    
    const baseQuery = agentId 
      ? 'SELECT * FROM usage_records WHERE agent_id = $1 AND timestamp >= $2'
      : 'SELECT * FROM usage_records WHERE timestamp >= $1';
    
    const [last24h, last7d, last30d] = await Promise.all([
      agentId ? db.query(baseQuery, [agentId, day24h]) : db.query(baseQuery, [day24h]),
      agentId ? db.query(baseQuery, [agentId, day7d]) : db.query(baseQuery, [day7d]),
      agentId ? db.query(baseQuery, [agentId, day30d]) : db.query(baseQuery, [day30d])
    ]);
    
    // Aggregate by model
    function aggregate(records) {
      const result = { opus: { input: 0, output: 0, cache_read: 0, cache_write: 0 }, sonnet: { input: 0, output: 0, cache_read: 0, cache_write: 0 }, messages: 0, subagents: 0 };
      records.forEach(r => {
        const modelKey = r.model?.includes('opus') ? 'opus' : 'sonnet';
        result[modelKey].input += r.input_tokens || 0;
        result[modelKey].output += r.output_tokens || 0;
        result[modelKey].cache_read += r.cache_read_tokens || 0;
        result[modelKey].cache_write += r.cache_write_tokens || 0;
        if (r.event_type === 'message') result.messages++;
        if (r.event_type === 'subagent') result.subagents++;
      });
      result.opus.total = result.opus.input + result.opus.output;
      result.sonnet.total = result.sonnet.input + result.sonnet.output;
      result.total = result.opus.total + result.sonnet.total;
      return result;
    }
    
    res.json({
      last24h: aggregate(last24h),
      last7d: aggregate(last7d),
      last30d: aggregate(last30d)
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.get('/api/usage/history', requireAuth, async (req, res) => {
  try {
    const agentId = req.agent?.id || req.query.agent_id;
    const days = parseInt(req.query.days) || 7;
    const startDate = new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
    
    const query = agentId
      ? 'SELECT * FROM usage_records WHERE agent_id = $1 AND timestamp >= $2 ORDER BY timestamp ASC'
      : 'SELECT * FROM usage_records WHERE timestamp >= $1 ORDER BY timestamp ASC';
    const params = agentId ? [agentId, startDate] : [startDate];
    
    const records = await db.query(query, params);
    
    // Group by day
    const dailyMap = {};
    records.forEach(r => {
      const day = (r.timestamp instanceof Date ? r.timestamp.toISOString() : r.timestamp).split('T')[0]; // YYYY-MM-DD
      if (!dailyMap[day]) dailyMap[day] = { opus: 0, sonnet: 0, messages: 0, subagents: 0 };
      const modelKey = r.model?.includes('opus') ? 'opus' : 'sonnet';
      dailyMap[day][modelKey] += (r.input_tokens || 0) + (r.output_tokens || 0);
      if (r.event_type === 'message') dailyMap[day].messages++;
      if (r.event_type === 'subagent') dailyMap[day].subagents++;
    });
    
    // Convert to array of { date, opus, sonnet, total, messages, subagents }
    const history = Object.keys(dailyMap).sort().map(date => ({
      date,
      opus: dailyMap[date].opus,
      sonnet: dailyMap[date].sonnet,
      total: dailyMap[date].opus + dailyMap[date].sonnet,
      messages: dailyMap[date].messages,
      subagents: dailyMap[date].subagents
    }));
    
    res.json(history);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// ============ SOMEDAY/MAYBE ============
app.get('/api/someday', requireAuth, async (req, res) => {
  try {
    const status = req.query.status || 'active';
    const items = await db.query(
      `SELECT s.*, a.name as agent_name FROM someday_maybe s
       LEFT JOIN agents a ON s.agent_id = a.id
       WHERE s.status = $1
       ORDER BY s.created_at DESC`,
      [status]
    );
    res.json(items);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.post('/api/someday', requireAuth, async (req, res) => {
  try {
    const { title, description = '', category = 'idea', metadata = {} } = req.body;
    if (!title) return res.status(400).json({ error: 'Title required' });
    const id = uuidv4();
    const agentId = req.agent?.id || null;
    const now = new Date().toISOString();
    await db.run(
      'INSERT INTO someday_maybe (id, agent_id, title, description, category, created_at, metadata) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [id, agentId, title, description, category, now, JSON.stringify(metadata)]
    );
    const item = await db.get('SELECT s.*, a.name as agent_name FROM someday_maybe s LEFT JOIN agents a ON s.agent_id = a.id WHERE s.id = $1', [id]);
    broadcast('someday:created', item);
    res.status(201).json(item);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.patch('/api/someday/:id', requireAuth, async (req, res) => {
  try {
    const existing = await db.get('SELECT * FROM someday_maybe WHERE id = $1', [req.params.id]);
    if (!existing) return res.status(404).json({ error: 'Not found' });
    const { title, description, category, status, last_reviewed, metadata } = req.body;
    await db.run(
      'UPDATE someday_maybe SET title = $1, description = $2, category = $3, status = $4, last_reviewed = $5, metadata = $6 WHERE id = $7',
      [title ?? existing.title, description ?? existing.description, category ?? existing.category, status ?? existing.status, last_reviewed ?? existing.last_reviewed, JSON.stringify(metadata ?? JSON.parse(existing.metadata || '{}')), req.params.id]
    );
    const item = await db.get('SELECT s.*, a.name as agent_name FROM someday_maybe s LEFT JOIN agents a ON s.agent_id = a.id WHERE s.id = $1', [req.params.id]);
    broadcast('someday:updated', item);
    res.json(item);
  } catch (err) { res.status(500).json({ error: err.message }); }
});

app.delete('/api/someday/:id', requireAuth, async (req, res) => {
  try { await db.run('DELETE FROM someday_maybe WHERE id = $1', [req.params.id]); broadcast('someday:deleted', { id: req.params.id }); res.json({ success: true }); }
  catch (err) { res.status(500).json({ error: err.message }); }
});

// ============ DASHBOARD AGGREGATE ============
app.get('/api/dashboard', requireAuth, async (req, res) => {
  try {
    const now = new Date();
    const day24h = new Date(now - 24 * 60 * 60 * 1000).toISOString();
    const day7d = new Date(now - 7 * 24 * 60 * 60 * 1000).toISOString();
    
    const [active, completed, subagents, scheduled, activity, threadsOpen, threadsConcluded, somedayMaybe, usageToday, usageWeek] = await Promise.all([
      db.query(`SELECT w.*, a.name as agent_name FROM work_items w LEFT JOIN agents a ON w.agent_id = a.id WHERE w.status = 'active' AND w.category != 'conversation' ORDER BY w.started_at DESC LIMIT 20`),
      db.query(`SELECT w.*, a.name as agent_name FROM work_items w LEFT JOIN agents a ON w.agent_id = a.id WHERE w.status = 'completed' AND w.category != 'conversation' ORDER BY w.completed_at DESC LIMIT 10`),
      db.query(`SELECT s.*, a.name as agent_name FROM subagents s LEFT JOIN agents a ON s.agent_id = a.id ORDER BY s.started_at DESC LIMIT 10`),
      db.query(`SELECT s.*, a.name as agent_name FROM scheduled s LEFT JOIN agents a ON s.agent_id = a.id WHERE s.status = 'active' ORDER BY s.next_run ASC`),
      db.query(`SELECT ac.*, a.name as agent_name FROM activity ac LEFT JOIN agents a ON ac.agent_id = a.id ORDER BY ac.created_at DESC LIMIT 20`),
      db.query(`SELECT w.*, a.name as agent_name FROM work_items w LEFT JOIN agents a ON w.agent_id = a.id WHERE w.status = 'active' AND w.category = 'conversation' ORDER BY w.started_at DESC LIMIT 20`),
      db.query(`SELECT w.*, a.name as agent_name FROM work_items w LEFT JOIN agents a ON w.agent_id = a.id WHERE w.status = 'completed' AND w.category = 'conversation' ORDER BY w.completed_at DESC LIMIT 10`),
      db.query(`SELECT s.*, a.name as agent_name FROM someday_maybe s LEFT JOIN agents a ON s.agent_id = a.id WHERE s.status = 'active' ORDER BY s.created_at DESC LIMIT 20`),
      db.query('SELECT * FROM usage_records WHERE timestamp >= $1', [day24h]),
      db.query('SELECT * FROM usage_records WHERE timestamp >= $1', [day7d])
    ]);
    
    // Aggregate usage
    function aggregateUsage(records) {
      const result = { opus: 0, sonnet: 0, messages: 0, subagents: 0 };
      records.forEach(r => {
        const modelKey = r.model?.includes('opus') ? 'opus' : 'sonnet';
        result[modelKey] += (r.input_tokens || 0) + (r.output_tokens || 0);
        if (r.event_type === 'message') result.messages++;
        if (r.event_type === 'subagent') result.subagents++;
      });
      result.total = result.opus + result.sonnet;
      return result;
    }
    
    res.json({ 
      active, completed, subagents, scheduled, activity, threadsOpen, threadsConcluded, somedayMaybe,
      usage: {
        today: aggregateUsage(usageToday),
        week: aggregateUsage(usageWeek)
      }
    });
  } catch (err) { res.status(500).json({ error: err.message }); }
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============ START ============
async function start() {
  await db.init();
  server.listen(PORT, () => {
    console.log(`🚀 Agent Portal running at http://localhost:${PORT}`);
    console.log(`🔒 Google Auth: ${process.env.GOOGLE_CLIENT_ID ? 'Enabled' : 'Disabled'}`);
    console.log(`🗄️  Database: ${isProduction ? 'PostgreSQL' : 'SQLite'}`);
    console.log(`🔌 WebSocket: ws://localhost:${PORT}/ws`);
  });
}

start().catch(console.error);

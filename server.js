require('dotenv').config();
const express = require('express');
const session = require('express-session');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3847;

// ============ DATABASE SETUP ============
let db;
const isProduction = !!process.env.DATABASE_URL;

if (isProduction) {
  // PostgreSQL for production
  const { Pool } = require('pg');
  const pgPool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL.includes('railway') ? { rejectUnauthorized: false } : false
  });
  
  // PostgreSQL wrapper to match SQLite-like API
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
        
        CREATE TABLE IF NOT EXISTS tasks (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          status TEXT DEFAULT 'todo',
          notes TEXT DEFAULT '',
          created_by TEXT REFERENCES users(id),
          created_at TIMESTAMPTZ DEFAULT NOW(),
          updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        CREATE TABLE IF NOT EXISTS config (
          key TEXT PRIMARY KEY,
          value TEXT
        );
        
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
  // SQLite for local development
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
        
        CREATE TABLE IF NOT EXISTS tasks (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          status TEXT DEFAULT 'todo',
          notes TEXT DEFAULT '',
          created_by TEXT,
          created_at TEXT DEFAULT (datetime('now')),
          updated_at TEXT DEFAULT (datetime('now'))
        );
        
        CREATE TABLE IF NOT EXISTS config (
          key TEXT PRIMARY KEY,
          value TEXT
        );
      `);
    },
    async query(sql, params = []) {
      // Convert $1, $2 style to ? for SQLite
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

app.use(session({
  store: sessionStore,
  secret: process.env.SESSION_SECRET || 'dev-secret-change-me',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: isProduction,
    maxAge: 30 * 24 * 60 * 60 * 1000 // 30 days
  }
}));

// ============ PASSPORT SETUP ============
app.use(passport.initialize());
app.use(passport.session());

passport.serializeUser((user, done) => done(null, user.id));
passport.deserializeUser(async (id, done) => {
  try {
    const user = await db.get('SELECT * FROM users WHERE id = $1', [id]);
    done(null, user);
  } catch (err) {
    done(err, null);
  }
});

// Google OAuth Strategy (only if credentials provided)
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
    } catch (err) {
      done(err, null);
    }
  }));
}

// ============ MIDDLEWARE ============
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// SSE clients
let sseClients = [];

function broadcast(event, data) {
  sseClients.forEach(client => {
    client.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  });
}

// Auth check middleware
function requireAuth(req, res, next) {
  // Check for API key first (for agent access)
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ak_')) {
    return requireApiKey(req, res, next);
  }
  
  // Otherwise require logged-in user
  if (req.isAuthenticated()) {
    return next();
  }
  
  res.status(401).json({ error: 'Authentication required' });
}

// API key auth (for programmatic access)
let apiKey = null;
async function loadApiKey() {
  apiKey = await db.get('SELECT value FROM config WHERE key = $1', ['api_key']);
  if (!apiKey) {
    const newKey = 'ak_' + uuidv4().replace(/-/g, '');
    await db.run('INSERT INTO config (key, value) VALUES ($1, $2)', ['api_key', newKey]);
    apiKey = { value: newKey };
    console.log('\n🔑 Generated new API key:', newKey);
  }
}

function requireApiKey(req, res, next) {
  const authHeader = req.headers.authorization;
  const providedKey = authHeader?.replace('Bearer ', '');
  
  if (!apiKey || providedKey !== apiKey.value) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  next();
}

// Admin check
function requireAdmin(req, res, next) {
  if (req.user?.is_admin) {
    return next();
  }
  res.status(403).json({ error: 'Admin access required' });
}

// ============ AUTH ROUTES ============
app.get('/auth/google', passport.authenticate('google', { scope: ['profile', 'email'] }));

app.get('/auth/google/callback',
  passport.authenticate('google', { failureRedirect: '/login' }),
  (req, res) => res.redirect('/')
);

app.get('/auth/logout', (req, res) => {
  req.logout(() => res.redirect('/'));
});

app.get('/api/me', (req, res) => {
  if (req.isAuthenticated()) {
    res.json({
      id: req.user.id,
      name: req.user.name,
      email: req.user.email,
      picture: req.user.picture,
      isAdmin: req.user.is_admin
    });
  } else {
    res.json(null);
  }
});

// ============ SSE ============
app.get('/api/events', (req, res) => {
  res.setHeader('Content-Type', 'text/event-stream');
  res.setHeader('Cache-Control', 'no-cache');
  res.setHeader('Connection', 'keep-alive');
  res.flushHeaders();

  const clientId = Date.now();
  sseClients.push({ id: clientId, res });
  req.on('close', () => {
    sseClients = sseClients.filter(c => c.id !== clientId);
  });
});

// ============ TASK ROUTES ============
app.get('/api/tasks', async (req, res) => {
  try {
    const tasks = await db.query('SELECT * FROM tasks ORDER BY updated_at DESC');
    res.json(tasks);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/tasks', requireAuth, async (req, res) => {
  try {
    const { name, status = 'todo', notes = '' } = req.body;
    if (!name) return res.status(400).json({ error: 'Task name is required' });
    
    const id = uuidv4();
    const now = new Date().toISOString();
    const userId = req.user?.id || null;
    
    await db.run(
      'INSERT INTO tasks (id, name, status, notes, created_by, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7)',
      [id, name, status, notes, userId, now, now]
    );
    
    const task = await db.get('SELECT * FROM tasks WHERE id = $1', [id]);
    broadcast('task-created', task);
    res.status(201).json(task);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, status, notes } = req.body;
    
    const existing = await db.get('SELECT * FROM tasks WHERE id = $1', [id]);
    if (!existing) return res.status(404).json({ error: 'Task not found' });
    
    const now = new Date().toISOString();
    await db.run(
      'UPDATE tasks SET name = $1, status = $2, notes = $3, updated_at = $4 WHERE id = $5',
      [name ?? existing.name, status ?? existing.status, notes ?? existing.notes, now, id]
    );
    
    const task = await db.get('SELECT * FROM tasks WHERE id = $1', [id]);
    broadcast('task-updated', task);
    res.json(task);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const existing = await db.get('SELECT * FROM tasks WHERE id = $1', [id]);
    if (!existing) return res.status(404).json({ error: 'Task not found' });
    
    await db.run('DELETE FROM tasks WHERE id = $1', [id]);
    broadcast('task-deleted', { id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/tasks/:id/log', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { message } = req.body;
    
    const existing = await db.get('SELECT * FROM tasks WHERE id = $1', [id]);
    if (!existing) return res.status(404).json({ error: 'Task not found' });
    
    const now = new Date().toISOString();
    const timestamp = new Date().toLocaleString();
    const newNotes = existing.notes 
      ? `${existing.notes}\n[${timestamp}] ${message}`
      : `[${timestamp}] ${message}`;
    
    await db.run('UPDATE tasks SET notes = $1, updated_at = $2 WHERE id = $3', [newNotes, now, id]);
    
    const task = await db.get('SELECT * FROM tasks WHERE id = $1', [id]);
    broadcast('task-updated', task);
    res.json(task);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ ADMIN ROUTES ============
app.get('/api/admin/api-key', requireAuth, requireAdmin, async (req, res) => {
  res.json({ apiKey: apiKey?.value });
});

app.post('/api/admin/api-key/regenerate', requireAuth, requireAdmin, async (req, res) => {
  const newKey = 'ak_' + uuidv4().replace(/-/g, '');
  await db.run('UPDATE config SET value = $1 WHERE key = $2', [newKey, 'api_key']);
  apiKey = { value: newKey };
  res.json({ apiKey: newKey });
});

app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

// ============ START ============
async function start() {
  await db.init();
  await loadApiKey();
  
  app.listen(PORT, () => {
    console.log(`🚀 Agent Portal running at http://localhost:${PORT}`);
    console.log(`📋 API Key: ${apiKey?.value}`);
    console.log(`🔒 Google Auth: ${process.env.GOOGLE_CLIENT_ID ? 'Enabled' : 'Disabled (set GOOGLE_CLIENT_ID)'}`);
    console.log(`🗄️  Database: ${isProduction ? 'PostgreSQL' : 'SQLite'}`);
  });
}

start().catch(console.error);

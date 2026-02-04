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
        
        CREATE TABLE IF NOT EXISTS tasks (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          status TEXT DEFAULT 'queue',
          priority TEXT DEFAULT 'normal',
          due_date DATE,
          notes TEXT DEFAULT '',
          agent_id TEXT REFERENCES agents(id),
          created_by TEXT REFERENCES users(id),
          created_at TIMESTAMPTZ DEFAULT NOW(),
          updated_at TIMESTAMPTZ DEFAULT NOW()
        );
        
        CREATE TABLE IF NOT EXISTS task_events (
          id TEXT PRIMARY KEY,
          task_id TEXT REFERENCES tasks(id) ON DELETE CASCADE,
          agent_id TEXT REFERENCES agents(id),
          message TEXT NOT NULL,
          event_type TEXT DEFAULT 'update',
          created_at TIMESTAMPTZ DEFAULT NOW()
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
        
        CREATE TABLE IF NOT EXISTS tasks (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          status TEXT DEFAULT 'queue',
          priority TEXT DEFAULT 'normal',
          due_date TEXT,
          notes TEXT DEFAULT '',
          agent_id TEXT,
          created_by TEXT,
          created_at TEXT DEFAULT (datetime('now')),
          updated_at TEXT DEFAULT (datetime('now'))
        );
        
        CREATE TABLE IF NOT EXISTS task_events (
          id TEXT PRIMARY KEY,
          task_id TEXT,
          agent_id TEXT,
          message TEXT NOT NULL,
          event_type TEXT DEFAULT 'update',
          created_at TEXT DEFAULT (datetime('now'))
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

// WebSocket clients
const wsClients = new Set();

wss.on('connection', (ws, req) => {
  wsClients.add(ws);
  ws.on('close', () => wsClients.delete(ws));
  ws.on('error', () => wsClients.delete(ws));
});

function broadcast(event, data) {
  const message = JSON.stringify({ event, data });
  wsClients.forEach(client => {
    if (client.readyState === WebSocket.OPEN) {
      client.send(message);
    }
  });
}

// Auth middleware
function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    return requireAgentKey(req, res, next);
  }
  if (req.isAuthenticated()) return next();
  res.status(401).json({ error: 'Authentication required' });
}

// Agent API key middleware
async function requireAgentKey(req, res, next) {
  const authHeader = req.headers.authorization;
  const key = authHeader?.replace('Bearer ', '');
  
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

// ============ STATIC FILES ============
// Serve landing page for unauthenticated users
app.get('/', (req, res) => {
  if (req.isAuthenticated()) {
    res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
  } else {
    res.sendFile(path.join(__dirname, 'public', 'landing.html'));
  }
});

app.use('/assets', express.static(path.join(__dirname, 'public', 'assets')));

// Protected static files
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

// ============ AGENT ROUTES ============
app.get('/api/agents', requireAuth, async (req, res) => {
  try {
    const agents = await db.query('SELECT id, name, created_at FROM agents ORDER BY created_at DESC');
    res.json(agents);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/agents', requireAuth, requireAdmin, async (req, res) => {
  try {
    const { name } = req.body;
    if (!name) return res.status(400).json({ error: 'Agent name required' });
    
    const id = uuidv4();
    const apiKey = 'ak_' + uuidv4().replace(/-/g, '');
    
    await db.run(
      'INSERT INTO agents (id, name, api_key, created_by) VALUES ($1, $2, $3, $4)',
      [id, name, apiKey, req.user.id]
    );
    
    res.status(201).json({ id, name, apiKey });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/agents/:id', requireAuth, requireAdmin, async (req, res) => {
  try {
    await db.run('DELETE FROM agents WHERE id = $1', [req.params.id]);
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/agents/:id/key', requireAuth, requireAdmin, async (req, res) => {
  try {
    const agent = await db.get('SELECT api_key FROM agents WHERE id = $1', [req.params.id]);
    if (!agent) return res.status(404).json({ error: 'Agent not found' });
    res.json({ apiKey: agent.api_key });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ TASK ROUTES ============
app.get('/api/tasks', requireAuth, async (req, res) => {
  try {
    const tasks = await db.query(`
      SELECT t.*, a.name as agent_name 
      FROM tasks t 
      LEFT JOIN agents a ON t.agent_id = a.id 
      ORDER BY t.updated_at DESC
    `);
    res.json(tasks);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.get('/api/tasks/dashboard', requireAuth, async (req, res) => {
  try {
    const today = new Date().toISOString().split('T')[0];
    
    const [dueToday, queue, completed] = await Promise.all([
      db.query(`
        SELECT t.*, a.name as agent_name FROM tasks t 
        LEFT JOIN agents a ON t.agent_id = a.id 
        WHERE t.due_date = $1 AND t.status != 'done'
        ORDER BY t.priority DESC, t.updated_at DESC
      `, [today]),
      db.query(`
        SELECT t.*, a.name as agent_name FROM tasks t 
        LEFT JOIN agents a ON t.agent_id = a.id 
        WHERE t.status = 'queue' OR t.status = 'in-progress'
        ORDER BY t.priority DESC, t.updated_at DESC
        LIMIT 20
      `),
      db.query(`
        SELECT t.*, a.name as agent_name FROM tasks t 
        LEFT JOIN agents a ON t.agent_id = a.id 
        WHERE t.status = 'done' OR t.status = 'review'
        ORDER BY t.updated_at DESC
        LIMIT 20
      `)
    ]);
    
    res.json({ dueToday, queue, completed });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/tasks', requireAuth, async (req, res) => {
  try {
    const { name, status = 'queue', priority = 'normal', due_date, notes = '', agent_id } = req.body;
    if (!name) return res.status(400).json({ error: 'Task name required' });
    
    const id = uuidv4();
    const now = new Date().toISOString();
    const userId = req.user?.id || null;
    const agentId = req.agent?.id || agent_id || null;
    
    await db.run(
      'INSERT INTO tasks (id, name, status, priority, due_date, notes, agent_id, created_by, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)',
      [id, name, status, priority, due_date || null, notes, agentId, userId, now, now]
    );
    
    const task = await db.get('SELECT t.*, a.name as agent_name FROM tasks t LEFT JOIN agents a ON t.agent_id = a.id WHERE t.id = $1', [id]);
    broadcast('task:created', task);
    res.status(201).json(task);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.patch('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    const { id } = req.params;
    const { name, status, priority, due_date, notes } = req.body;
    
    const existing = await db.get('SELECT * FROM tasks WHERE id = $1', [id]);
    if (!existing) return res.status(404).json({ error: 'Task not found' });
    
    const now = new Date().toISOString();
    await db.run(
      'UPDATE tasks SET name = $1, status = $2, priority = $3, due_date = $4, notes = $5, updated_at = $6 WHERE id = $7',
      [name ?? existing.name, status ?? existing.status, priority ?? existing.priority, due_date !== undefined ? due_date : existing.due_date, notes ?? existing.notes, now, id]
    );
    
    const task = await db.get('SELECT t.*, a.name as agent_name FROM tasks t LEFT JOIN agents a ON t.agent_id = a.id WHERE t.id = $1', [id]);
    broadcast('task:updated', task);
    res.json(task);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/tasks/:id', requireAuth, async (req, res) => {
  try {
    await db.run('DELETE FROM tasks WHERE id = $1', [req.params.id]);
    broadcast('task:deleted', { id: req.params.id });
    res.json({ success: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ============ TASK EVENTS (Agent Updates) ============
app.get('/api/tasks/:id/events', requireAuth, async (req, res) => {
  try {
    const events = await db.query(`
      SELECT e.*, a.name as agent_name 
      FROM task_events e 
      LEFT JOIN agents a ON e.agent_id = a.id 
      WHERE e.task_id = $1 
      ORDER BY e.created_at DESC
    `, [req.params.id]);
    res.json(events);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/tasks/:id/events', requireAuth, async (req, res) => {
  try {
    const { id: taskId } = req.params;
    const { message, event_type = 'update' } = req.body;
    
    const task = await db.get('SELECT * FROM tasks WHERE id = $1', [taskId]);
    if (!task) return res.status(404).json({ error: 'Task not found' });
    
    const id = uuidv4();
    const agentId = req.agent?.id || null;
    const now = new Date().toISOString();
    
    await db.run(
      'INSERT INTO task_events (id, task_id, agent_id, message, event_type, created_at) VALUES ($1, $2, $3, $4, $5, $6)',
      [id, taskId, agentId, message, event_type, now]
    );
    
    // Update task's updated_at
    await db.run('UPDATE tasks SET updated_at = $1 WHERE id = $2', [now, taskId]);
    
    const event = await db.get('SELECT e.*, a.name as agent_name FROM task_events e LEFT JOIN agents a ON e.agent_id = a.id WHERE e.id = $1', [id]);
    broadcast('task:event', { taskId, event });
    
    // Also broadcast task update
    const updatedTask = await db.get('SELECT t.*, a.name as agent_name FROM tasks t LEFT JOIN agents a ON t.agent_id = a.id WHERE t.id = $1', [taskId]);
    broadcast('task:updated', updatedTask);
    
    res.status(201).json(event);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
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

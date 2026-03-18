'use strict';

/**
 * tests/helpers/createApp.js
 *
 * Factory for a test Express app. Uses an in-memory SQLite DB so tests are
 * fully isolated from the real portal.db and from production PostgreSQL.
 */

const express = require('express');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');

// ── Build an in-memory SQLite db object that matches lib/db.js interface ──────

function createTestDb() {
  const sqliteDb = new Database(':memory:');

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
    CREATE TABLE IF NOT EXISTS initiatives (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      status TEXT NOT NULL DEFAULT 'planned',
      priority TEXT NOT NULL DEFAULT 'P2',
      owner TEXT,
      target_date TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS work_tasks (
      id TEXT PRIMARY KEY,
      title TEXT NOT NULL,
      description TEXT,
      initiative_id TEXT,
      status TEXT NOT NULL DEFAULT 'backlog',
      assigned_to TEXT,
      requested_by TEXT,
      session_key TEXT,
      parent_task_id TEXT,
      started_at TEXT,
      completed_at TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS signals (
      id TEXT PRIMARY KEY,
      task_id TEXT,
      initiative_id TEXT,
      agent_id TEXT,
      session_key TEXT,
      level TEXT NOT NULL DEFAULT 'info',
      message TEXT NOT NULL,
      metadata TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
    CREATE TABLE IF NOT EXISTS channels (
      id TEXT PRIMARY KEY,
      name TEXT NOT NULL UNIQUE,
      description TEXT DEFAULT '',
      created_by TEXT,
      is_default INTEGER DEFAULT 0,
      is_dm INTEGER DEFAULT 0,
      dm_agent_id TEXT,
      dm_user_id TEXT,
      created_at TEXT DEFAULT (datetime('now'))
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
    CREATE TABLE IF NOT EXISTS channel_members (
      channel_id TEXT,
      user_id TEXT,
      joined_at TEXT DEFAULT (datetime('now')),
      PRIMARY KEY (channel_id, user_id)
    );
    CREATE INDEX IF NOT EXISTS idx_signals_created ON signals(created_at DESC);
  `);

  return {
    isProduction: false,
    async init() { /* already done above */ },
    async query(sql, params = []) {
      const sqliteSql = sql.replace(/\$(\d+)/g, '?');
      return sqliteDb.prepare(sqliteSql).all(...params);
    },
    async get(sql, params = []) {
      const sqliteSql = sql.replace(/\$(\d+)/g, '?');
      return sqliteDb.prepare(sqliteSql).get(...params) || null;
    },
    async run(sql, params = []) {
      const sqliteSql = sql.replace(/\$(\d+)/g, '?');
      sqliteDb.prepare(sqliteSql).run(...params);
    },
  };
}

// ── Static agents registry (mirrors server.js) ────────────────────────────────

const AGENTS = [
  { id: 'lewis',  name: 'Lewis',  emoji: '📚', sessionKey: 'agent:main:main',   avatarUrl: '/assets/lewis-avatar.png' },
  { id: 'pascal', name: 'Pascal', emoji: '⚙️',  sessionKey: 'agent:pascal:main', avatarUrl: '/assets/pascal-avatar.jpg' },
];

// ── App factory ───────────────────────────────────────────────────────────────

/**
 * @param {{ db?: object }} [opts]
 * @returns {{ app: import('express').Application, db: object, testAgentKey: string }}
 */
function createApp(opts = {}) {
  const db = opts.db || createTestDb();

  // Seed a test agent so agent-key-auth tests have a valid key
  const testAgentId  = uuidv4();
  const testAgentKey = 'ak_test_' + uuidv4().replace(/-/g, '');

  // Synchronous seed (SQLite in-memory, safe here)
  db.run(
    'INSERT INTO agents (id, name, api_key) VALUES ($1, $2, $3)',
    [testAgentId, 'TestAgent', testAgentKey]
  );

  // Auth helpers — thin wrappers that use OUR test db, not the singleton lib/db.js
  const requireAuth = (req, res, next) => {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) {
      return res.status(401).json({ error: 'Authentication required' });
    }
    // For testing, delegate to requireAgentKey path
    requireAgentKey(req, res, next);
  };

  const requireAgentKey = async (req, res, next) => {
    const key = req.headers.authorization?.replace('Bearer ', '');
    if (!key) return res.status(401).json({ error: 'API key required' });
    const agent = await db.get('SELECT * FROM agents WHERE api_key = $1', [key]);
    if (!agent) return res.status(401).json({ error: 'Invalid API key' });
    req.agent = agent;
    next();
  };

  const requireAdmin = (req, res, next) => {
    if (req.user?.is_admin) return next();
    res.status(403).json({ error: 'Admin access required' });
  };

  const broadcast = () => {}; // no-op in tests

  const app = express();
  app.use(express.json());

  // Stub isAuthenticated so session-less requests don't explode
  app.use((req, _res, next) => {
    if (!req.isAuthenticated) req.isAuthenticated = () => false;
    next();
  });

  // Mount routes
  const healthRouter    = require('../../routes/health');
  const agentsRouter    = require('../../routes/agents');
  const workRouter      = require('../../routes/work');
  const scheduledRouter = require('../../routes/scheduled');
  const activityRouter  = require('../../routes/activity');

  app.use('/api', healthRouter({
    gatewayClient: { isReady: false, ws: null },
    getChatState: () => ({ authenticated: false, ws: null }),
  }));

  app.use('/api', agentsRouter({
    db,
    AGENTS,
    requireAuth,
    requireAdmin,
    uuidv4,
    publicDir: __dirname,
  }));

  app.use('/api', workRouter({
    db,
    requireAuth,
    requireAgentKey,
    uuidv4,
    broadcast,
    publicDir: __dirname,
  }));

  app.use('/api', scheduledRouter({ db, requireAuth, requireAgentKey }));

  app.use('/api', activityRouter({ db, requireAuth }));

  return { app, db, testAgentKey };
}

module.exports = { createApp, createTestDb };

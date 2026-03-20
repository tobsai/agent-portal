'use strict';

/**
 * lib/db.js — Database connection and schema initialisation
 *
 * Exports a `db` object with:
 *   db.init()           — create tables / run migrations
 *   db.query(sql, [])   — returns array of rows
 *   db.get(sql, [])     — returns first row or null
 *   db.run(sql, [])     — executes without returning rows
 *   db.pool             — pg Pool (production only, undefined in dev)
 *   db.isProduction     — boolean
 */

const path = require('path');
const fs   = require('fs');

const isProduction = !!process.env.DATABASE_URL;

let db;

if (isProduction) {
  const { Pool } = require('pg');
  const pgPool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: process.env.DATABASE_URL.includes('railway') ? { rejectUnauthorized: false } : false
  });

  db = {
    isProduction: true,
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
          is_dm BOOLEAN DEFAULT false,
          dm_agent_id TEXT,
          dm_user_id TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );
        ALTER TABLE channels ADD COLUMN IF NOT EXISTS is_dm BOOLEAN DEFAULT false;
        ALTER TABLE channels ADD COLUMN IF NOT EXISTS dm_agent_id TEXT;
        ALTER TABLE channels ADD COLUMN IF NOT EXISTS dm_user_id TEXT;

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

        CREATE TABLE IF NOT EXISTS initiatives (
          id TEXT PRIMARY KEY,
          title TEXT NOT NULL,
          description TEXT,
          status TEXT NOT NULL DEFAULT 'planned',
          priority TEXT NOT NULL DEFAULT 'P2',
          owner TEXT,
          target_date TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS work_tasks (
          id TEXT PRIMARY KEY,
          title TEXT NOT NULL,
          description TEXT,
          initiative_id TEXT REFERENCES initiatives(id),
          status TEXT NOT NULL DEFAULT 'backlog',
          assigned_to TEXT,
          requested_by TEXT,
          session_key TEXT,
          parent_task_id TEXT,
          started_at TIMESTAMPTZ,
          completed_at TIMESTAMPTZ,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );

        CREATE TABLE IF NOT EXISTS signals (
          id TEXT PRIMARY KEY,
          task_id TEXT REFERENCES work_tasks(id) ON DELETE SET NULL,
          initiative_id TEXT REFERENCES initiatives(id) ON DELETE SET NULL,
          agent_id TEXT,
          session_key TEXT,
          task_label TEXT,
          level TEXT NOT NULL DEFAULT 'info',
          message TEXT NOT NULL,
          metadata TEXT,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );
        ALTER TABLE signals ADD COLUMN IF NOT EXISTS task_label TEXT;
        CREATE INDEX IF NOT EXISTS idx_signals_created ON signals(created_at DESC);
        CREATE INDEX IF NOT EXISTS idx_signals_task ON signals(task_id) WHERE task_id IS NOT NULL;
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
  const dataDir = path.join(__dirname, '..', 'data');
  if (!fs.existsSync(dataDir)) fs.mkdirSync(dataDir, { recursive: true });

  const sqliteDb = new Database(path.join(dataDir, 'portal.db'));

  db = {
    isProduction: false,
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
          is_dm INTEGER DEFAULT 0,
          dm_agent_id TEXT,
          dm_user_id TEXT,
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
          initiative_id TEXT REFERENCES initiatives(id),
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
          task_id TEXT REFERENCES work_tasks(id) ON DELETE SET NULL,
          initiative_id TEXT REFERENCES initiatives(id) ON DELETE SET NULL,
          agent_id TEXT,
          session_key TEXT,
          task_label TEXT,
          level TEXT NOT NULL DEFAULT 'info',
          message TEXT NOT NULL,
          metadata TEXT,
          created_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_signals_created ON signals(created_at DESC);

        CREATE TABLE IF NOT EXISTS scheduled_tasks (
          id TEXT PRIMARY KEY,
          name TEXT NOT NULL,
          schedule TEXT NOT NULL,
          schedule_human TEXT,
          enabled INTEGER DEFAULT 1,
          next_run_at TEXT,
          last_run_at TEXT,
          last_status TEXT,
          last_outcome TEXT,
          created_at TEXT DEFAULT (datetime('now')),
          updated_at TEXT DEFAULT (datetime('now'))
        );
        CREATE INDEX IF NOT EXISTS idx_scheduled_next_run ON scheduled_tasks(next_run_at) WHERE enabled = 1;
        CREATE UNIQUE INDEX IF NOT EXISTS idx_scheduled_tasks_dedup ON scheduled_tasks(name, schedule);

        CREATE TABLE IF NOT EXISTS agent_status (
          id INTEGER PRIMARY KEY DEFAULT 1,
          status TEXT NOT NULL DEFAULT 'idle',
          task TEXT,
          updated_at INTEGER NOT NULL
        );
      `);
      // Migrations: add columns to existing tables that may predate them
      // SQLite does not support ADD COLUMN IF NOT EXISTS, so we check pragmatically
      const signalCols = sqliteDb.pragma('table_info(signals)').map(c => c.name);
      if (!signalCols.includes('task_label')) {
        sqliteDb.exec('ALTER TABLE signals ADD COLUMN task_label TEXT');
      }
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

module.exports = { db, isProduction };

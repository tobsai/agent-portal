const express = require('express');
const Database = require('better-sqlite3');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');

const app = express();
const PORT = process.env.PORT || 3847;

// Ensure data directory exists BEFORE initializing database
const dataDir = path.join(__dirname, 'data');
if (!fs.existsSync(dataDir)) {
  fs.mkdirSync(dataDir, { recursive: true });
}

// Initialize database
const db = new Database(path.join(dataDir, 'portal.db'));

// Create tables
db.exec(`
  CREATE TABLE IF NOT EXISTS tasks (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    status TEXT DEFAULT 'todo',
    notes TEXT DEFAULT '',
    created_at TEXT DEFAULT (datetime('now')),
    updated_at TEXT DEFAULT (datetime('now'))
  );
  
  CREATE TABLE IF NOT EXISTS config (
    key TEXT PRIMARY KEY,
    value TEXT
  );
`);

// Generate or retrieve API key
let apiKey = db.prepare('SELECT value FROM config WHERE key = ?').get('api_key');
if (!apiKey) {
  const newKey = 'ak_' + uuidv4().replace(/-/g, '');
  db.prepare('INSERT INTO config (key, value) VALUES (?, ?)').run('api_key', newKey);
  apiKey = { value: newKey };
  console.log('\n🔑 Generated new API key:', newKey);
  console.log('   Save this key - you\'ll need it to push updates!\n');
}

// SSE clients
let sseClients = [];

// Middleware
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// API key auth middleware
function requireApiKey(req, res, next) {
  const authHeader = req.headers.authorization;
  const providedKey = authHeader?.replace('Bearer ', '');
  
  if (providedKey !== apiKey.value) {
    return res.status(401).json({ error: 'Invalid API key' });
  }
  next();
}

// Broadcast to all SSE clients
function broadcast(event, data) {
  sseClients.forEach(client => {
    client.res.write(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`);
  });
}

// SSE endpoint for real-time updates
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

// Get all tasks
app.get('/api/tasks', (req, res) => {
  const tasks = db.prepare('SELECT * FROM tasks ORDER BY updated_at DESC').all();
  res.json(tasks);
});

// Create task (requires API key)
app.post('/api/tasks', requireApiKey, (req, res) => {
  const { name, status = 'todo', notes = '' } = req.body;
  
  if (!name) {
    return res.status(400).json({ error: 'Task name is required' });
  }
  
  const id = uuidv4();
  const now = new Date().toISOString();
  
  db.prepare(`
    INSERT INTO tasks (id, name, status, notes, created_at, updated_at)
    VALUES (?, ?, ?, ?, ?, ?)
  `).run(id, name, status, notes, now, now);
  
  const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
  broadcast('task-created', task);
  res.status(201).json(task);
});

// Update task (requires API key)
app.patch('/api/tasks/:id', requireApiKey, (req, res) => {
  const { id } = req.params;
  const { name, status, notes } = req.body;
  
  const existing = db.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
  if (!existing) {
    return res.status(404).json({ error: 'Task not found' });
  }
  
  const now = new Date().toISOString();
  const updatedName = name ?? existing.name;
  const updatedStatus = status ?? existing.status;
  const updatedNotes = notes ?? existing.notes;
  
  db.prepare(`
    UPDATE tasks SET name = ?, status = ?, notes = ?, updated_at = ?
    WHERE id = ?
  `).run(updatedName, updatedStatus, updatedNotes, now, id);
  
  const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
  broadcast('task-updated', task);
  res.json(task);
});

// Delete task (requires API key)
app.delete('/api/tasks/:id', requireApiKey, (req, res) => {
  const { id } = req.params;
  
  const existing = db.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
  if (!existing) {
    return res.status(404).json({ error: 'Task not found' });
  }
  
  db.prepare('DELETE FROM tasks WHERE id = ?').run(id);
  broadcast('task-deleted', { id });
  res.json({ success: true });
});

// Append to task log (requires API key)
app.post('/api/tasks/:id/log', requireApiKey, (req, res) => {
  const { id } = req.params;
  const { message } = req.body;
  
  const existing = db.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
  if (!existing) {
    return res.status(404).json({ error: 'Task not found' });
  }
  
  const now = new Date().toISOString();
  const timestamp = new Date().toLocaleString();
  const newNotes = existing.notes 
    ? `${existing.notes}\n[${timestamp}] ${message}`
    : `[${timestamp}] ${message}`;
  
  db.prepare(`
    UPDATE tasks SET notes = ?, updated_at = ? WHERE id = ?
  `).run(newNotes, now, id);
  
  const task = db.prepare('SELECT * FROM tasks WHERE id = ?').get(id);
  broadcast('task-updated', task);
  res.json(task);
});

// Health check
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', timestamp: new Date().toISOString() });
});

app.listen(PORT, () => {
  console.log(`🚀 Agent Portal running at http://localhost:${PORT}`);
  console.log(`📋 API Key: ${apiKey.value}`);
});

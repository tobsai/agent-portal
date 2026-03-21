'use strict';

/**
 * routes/agents.js — /api/bootstrap, /api/agents, /api/dm/:agentId, /api/subagents
 *
 * @param {object} deps
 * @param {object} deps.db
 * @param {object[]} deps.AGENTS        — hardcoded agents registry
 * @param {Function} deps.requireAuth
 * @param {Function} deps.requireAdmin
 * @param {Function} deps.uuidv4
 * @param {string}   deps.publicDir     — __dirname/../public
 * @returns {import('express').Router}
 */
const { Router } = require('express');
const path = require('path');

module.exports = function agentsRouter({ db, AGENTS, requireAuth, requireAdmin, uuidv4, publicDir }) {
  const router = Router();

  // ============ BOOTSTRAP ============
  router.post('/bootstrap', async (req, res) => {
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
  router.get('/agents', (req, res) => {
    res.json(AGENTS.map(a => ({ id: a.id, name: a.name, emoji: a.emoji, avatarUrl: a.avatarUrl })));
  });

  // DB agent management (for API key auth)
  router.post('/agents', requireAuth, async (req, res) => {
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

  router.delete('/agents/:id', requireAuth, requireAdmin, async (req, res) => {
    try { await db.run('DELETE FROM agents WHERE id = $1', [req.params.id]); res.json({ success: true }); }
    catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.get('/agents/:id/key', requireAuth, requireAdmin, async (req, res) => {
    try {
      const agent = await db.get('SELECT api_key FROM agents WHERE id = $1', [req.params.id]);
      if (!agent) return res.status(404).json({ error: 'Agent not found' });
      res.json({ apiKey: agent.api_key });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ============ DM CHANNELS ============
  // Find or create a DM channel between the current user and an agent
  router.get('/dm/:agentId', requireAuth, async (req, res) => {
    try {
      const agent = AGENTS.find(a => a.id === req.params.agentId);
      if (!agent) return res.status(404).json({ error: 'Agent not found' });

      const userId = req.user.id;

      // Look for an existing DM channel for this user+agent pair
      let channel = await db.get(
        'SELECT * FROM channels WHERE is_dm = true AND dm_agent_id = $1 AND dm_user_id = $2',
        [agent.id, userId]
      );

      if (!channel) {
        // Create the DM channel
        const id = uuidv4();
        const safeName = `dm-${agent.id}-${userId.slice(0, 8)}`;
        await db.run(
          'INSERT INTO channels (id, name, description, created_by, is_dm, dm_agent_id, dm_user_id) VALUES ($1, $2, $3, $4, true, $5, $6)',
          [id, safeName, `DM with ${agent.name}`, userId, agent.id, userId]
        );
        await db.run('INSERT INTO channel_members (channel_id, user_id) VALUES ($1, $2)', [id, userId]);
        channel = await db.get('SELECT * FROM channels WHERE id = $1', [id]);
      }

      // Augment with agent info for the client
      res.json({ ...channel, agent: { id: agent.id, name: agent.name, emoji: agent.emoji } });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ============ SUBAGENT TREE ============
  // GET /api/subagents — build spawn tree from signals metadata.
  //
  // NOTE: This is a signals-based workaround. The OpenClaw Gateway does not yet
  // expose a native sessions.list API. When it does, replace the signals query
  // below with a gatewayClient._request('sessions.list', { includeEnded: true })
  // call and map the response to AgentNode shape (see lib/types.js).
  // See docs/SUBAGENT_API_GAP.md for full context and migration path.
  router.get('/subagents', requireAuth, async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit || '200', 10), 500);
      const since = req.query.since || null; // ISO timestamp filter
      const date = req.query.date || null; // YYYY-MM-DD filter (for today-only queries)

      let sql = 'SELECT * FROM signals WHERE metadata IS NOT NULL';
      const params = [];
      let idx = 1;

      if (date) {
        // Filter by date: created_at >= date 00:00:00 AND created_at < date+1 00:00:00
        const startOfDay = new Date(date + 'T00:00:00Z').toISOString();
        const endOfDay = new Date(new Date(date).getTime() + 86400000).toISOString();
        sql += ` AND created_at >= $${idx++} AND created_at < $${idx++}`;
        params.push(startOfDay, endOfDay);
      } else if (since) {
        sql += ` AND created_at >= $${idx++}`;
        params.push(since);
      }

      sql += ` ORDER BY created_at DESC LIMIT $${idx}`;
      params.push(limit);

      const rows = await db.query(sql, params);

      // Parse metadata and build node map
      const nodeMap = new Map(); // session_key → node

      function getOrCreate(key) {
        if (!nodeMap.has(key)) {
          nodeMap.set(key, {
            id: key,
            label: key,
            model: null,
            status: 'unknown',
            startedAt: null,
            endedAt: null,
            runtime: null,
            tokenCount: null,
            signals: [],
            children: [],
            parentId: null,
            depth: 0,
          });
        }
        return nodeMap.get(key);
      }

      // Process all signals with metadata
      for (const row of rows) {
        let meta = null;
        try { meta = row.metadata ? JSON.parse(row.metadata) : null; } catch (e) { continue; }
        if (!meta) continue;

        const sessionKey = row.session_key || meta.session_key || meta.sessionKey;
        if (!sessionKey) continue;

        const node = getOrCreate(sessionKey);

        // Update node fields from signal metadata
        if (meta.label || meta.name) node.label = meta.label || meta.name || sessionKey;
        if (meta.model) node.model = meta.model;
        if (meta.status) node.status = meta.status;
        if (meta.tokenCount !== undefined) node.tokenCount = meta.tokenCount;
        if (meta.tokens !== undefined) node.tokenCount = meta.tokens;

        // Track timing — signal-type → status mapping
        // Priority order (lowest → highest precedence): registered < active < done/error.
        // A terminal state (done/error) must not be overwritten by a late-arriving
        // registration signal; guard every status assignment accordingly.
        const TERMINAL_STATUSES = new Set(['done', 'complete', 'error', 'cancelled']);

        if (meta.type === 'registered') {
          // Registration fires at spawn time — captures the node even if the child
          // emits no further signals (NEXT-086).
          node.startedAt = node.startedAt || row.created_at;
          if (!TERMINAL_STATUSES.has(node.status) && node.status === 'unknown') {
            node.status = 'registered';
          }
          // Capture parent relationship declared at registration time
          if (meta.parentKey && meta.parentKey !== sessionKey && !node.parentId) {
            node.parentId = meta.parentKey;
            getOrCreate(meta.parentKey);
          }
        }
        if (meta.type === 'subagent_start' || meta.type === 'spawn') {
          node.startedAt = row.created_at;
          if (!TERMINAL_STATUSES.has(node.status)) {
            node.status = 'active';
          }
        }
        if (meta.type === 'subagent_end' || meta.type === 'complete' || meta.type === 'done') {
          node.endedAt = row.created_at;
          if (!meta.status) node.status = 'done';
        }
        if (meta.type === 'subagent_error' || meta.type === 'error') {
          node.endedAt = row.created_at;
          if (!meta.status) node.status = 'error';
        }

        // Earliest signal sets startedAt if not set
        if (!node.startedAt || new Date(row.created_at) < new Date(node.startedAt)) {
          node.startedAt = row.created_at;
        }
        // Latest signal updates endedAt candidate
        if (!node.endedAt || new Date(row.created_at) > new Date(node.endedAt)) {
          // Only set endedAt if status implies completion
          if (['done', 'complete', 'error', 'cancelled'].includes(node.status)) {
            node.endedAt = row.created_at;
          }
        }

        // Parent-child relationship (parentKey already handled for 'registered' above)
        const parentKey = meta.parent_session || meta.parentSession || meta.spawner || meta.parentKey;
        if (parentKey && parentKey !== sessionKey && !node.parentId) {
          node.parentId = parentKey;
          getOrCreate(parentKey); // ensure parent exists
        }

        // Push signal summary
        node.signals.push({
          id: row.id,
          level: row.level,
          message: row.message,
          createdAt: row.created_at,
        });
      }

      // Also scan ALL signals (not just with metadata) to find session_key patterns
      const allSessionKeys = await db.query(
        `SELECT DISTINCT session_key FROM signals WHERE session_key IS NOT NULL ORDER BY session_key`
      );

      for (const { session_key: sk } of allSessionKeys) {
        if (!sk) continue;
        const subagentMatch = sk.match(/^agent:([^:]+):subagent:(.+)$/);
        const mainMatch = sk.match(/^agent:main(?::cron:[^:]+)?$/);

        if (mainMatch) {
          const node = getOrCreate(sk);
          if (!node.label || node.label === sk) node.label = 'main';
          if (node.status === 'unknown') node.status = 'active';
        } else if (subagentMatch) {
          const node = getOrCreate(sk);
          if (!node.label || node.label === sk) node.label = sk.slice(0, 24) + '…';
        }
      }

      // Get signal counts per session_key for nodes not yet created
      const sessionSignals = await db.query(
        `SELECT session_key, COUNT(*) as count, MIN(created_at) as first_at, MAX(created_at) as last_at,
                SUM(CASE WHEN level = 'error' THEN 1 ELSE 0 END) as error_count
         FROM signals
         WHERE session_key IS NOT NULL
         GROUP BY session_key`
      );

      for (const row of sessionSignals) {
        const sk = row.session_key;
        const node = getOrCreate(sk);
        if (!node.startedAt) node.startedAt = row.first_at;
        node._signalCount = parseInt(row.count, 10);
        node._hasErrors = parseInt(row.error_count, 10) > 0;
      }

      // Second aggregation pass: enforce startedAt = MIN(created_at) across all signals
      // for each node, regardless of insertion order (NEXT-102).
      // This ensures startedAt is always the earliest signal's created_at, not the
      // first-seen signal in the iteration loop above.
      for (const node of nodeMap.values()) {
        if (node.signals.length === 0) continue;
        const minCreatedAt = node.signals.reduce((earliest, sig) => {
          return !earliest || new Date(sig.createdAt) < new Date(earliest)
            ? sig.createdAt
            : earliest;
        }, null);
        if (minCreatedAt) {
          node.startedAt = minCreatedAt;
        }
      }

      // Build tree structure: find roots (nodes with no parent or parent not in map)
      const roots = [];
      for (const [key, node] of nodeMap) {
        if (!node.parentId || !nodeMap.has(node.parentId)) {
          roots.push(node);
        } else {
          const parent = nodeMap.get(node.parentId);
          if (!parent.children.includes(node)) {
            parent.children.push(node);
          }
        }
      }

      // Compute runtime
      for (const node of nodeMap.values()) {
        if (node.startedAt) {
          const start = new Date(node.startedAt);
          const end = node.endedAt ? new Date(node.endedAt) : new Date();
          node.runtime = Math.floor((end - start) / 1000); // seconds
        }
      }

      // Sort roots and children by startedAt
      const sortByStart = (a, b) =>
        (a.startedAt ? new Date(a.startedAt) : 0) - (b.startedAt ? new Date(b.startedAt) : 0);
      roots.sort(sortByStart);
      for (const node of nodeMap.values()) {
        node.children.sort(sortByStart);
      }

      // ─── Compute failures summary (server-side; consumed by drill-down panel) ───
      // Walk the full node map (not just today's roots) and extract error nodes.
      // Each item exposes a pre-shaped lastMessage so the client needs zero reshaping.
      const failureItems = [];
      for (const node of nodeMap.values()) {
        if (node.status !== 'error') continue;
        // Pick the most informative signal: prefer error-level, fall back to last
        const errorSignal = node.signals.slice().reverse().find(s => s.level === 'error');
        const lastSignal  = node.signals.length > 0 ? node.signals[node.signals.length - 1] : null;
        const chosen      = errorSignal || lastSignal;
        failureItems.push({
          id:          node.id,
          label:       node.label || node.id,
          lastMessage: chosen ? chosen.message : null,
          runtime:     node.runtime,         // seconds | null
          startedAt:   node.startedAt,
          endedAt:     node.endedAt,
        });
      }
      // Sort newest-first for stable panel ordering
      failureItems.sort((a, b) =>
        new Date(b.startedAt || 0) - new Date(a.startedAt || 0)
      );

      res.json({
        tree:     roots,
        total:    nodeMap.size,
        failures: {
          count: failureItems.length,
          items: failureItems,
        },
        generatedAt: new Date().toISOString(),
      });
    } catch (err) {
      console.error('[subagents] Error building tree:', err);
      res.status(500).json({ error: err.message });
    }
  });

  return router;
};

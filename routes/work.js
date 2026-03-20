'use strict';

/**
 * routes/work.js — /api/status, /api/agent-health, /api/work, /api/signals
 *
 * @param {object} deps
 * @param {object}   deps.db
 * @param {Function} deps.requireAuth
 * @param {Function} deps.requireAgentKey
 * @param {Function} deps.uuidv4
 * @param {Function} deps.broadcast         — broadcast(event, data)
 * @param {string}   deps.publicDir
 * @returns {import('express').Router}
 */
const { Router } = require('express');
const path = require('path');

// insertSignal lives in lib/signals.js — shared with lib modules that need to
// emit signals without creating a circular lib → routes dependency.
const { insertSignal } = require('../lib/signals');

module.exports = function workRouter({ db, requireAuth, requireAgentKey, uuidv4, broadcast, publicDir }) {
  const router = Router();

  // ============ AGENT THINKING STATUS ============
  let agentThinkingStatus = { status: 'idle', task: null, timestamp: null };
  let thinkingExpireTimer = null;

  // Threshold (ms) below which the in-memory value is considered fresh enough
  // to skip a DB read on GET. 30 seconds matches the task spec.
  const STATUS_FRESH_MS = 30 * 1000;

  router.post('/status', requireAgentKey, async (req, res) => {
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
      const updatedAtMs = Date.now();
      agentThinkingStatus = { status, task: task || null, timestamp };

      // Persist to DB — single-row upsert on id = 1
      // TODO(lewis): post outcome string to /api/status after cron completion
      await db.run(
        `INSERT INTO agent_status (id, status, task, updated_at)
         VALUES (1, $1, $2, $3)
         ON CONFLICT(id) DO UPDATE SET
           status     = excluded.status,
           task       = excluded.task,
           updated_at = excluded.updated_at`,
        [status, task || null, updatedAtMs]
      );

      broadcast('agent:status', agentThinkingStatus);

      if (status === 'thinking') {
        thinkingExpireTimer = setTimeout(() => {
          const expiredTs = new Date().toISOString();
          agentThinkingStatus = { status: 'idle', task: null, timestamp: expiredTs };
          broadcast('agent:status', agentThinkingStatus);
          thinkingExpireTimer = null;
          console.log('[status] Auto-expired thinking status to idle');
          // Emit a visible warning signal so the expiry appears in the dashboard.
          // Best-effort — don't let signal failures block the status update.
          insertSignal(db, uuidv4, {
            level: 'warning',
            message: 'Thinking status auto-expired after 5 min of inactivity',
          }).then(row => { if (row) broadcast('work:signal', row); })
            .catch(e => console.error('[status] Auto-expire signal insert failed:', e));
          // Best-effort DB update on auto-expire; fire-and-forget
          db.run(
            `INSERT INTO agent_status (id, status, task, updated_at)
             VALUES (1, 'idle', NULL, $1)
             ON CONFLICT(id) DO UPDATE SET
               status     = 'idle',
               task       = NULL,
               updated_at = excluded.updated_at`,
            [Date.now()]
          ).catch(e => console.error('[status] DB expire update failed:', e));
        }, 5 * 60 * 1000);
      }

      res.json({ success: true, status: agentThinkingStatus });
    } catch (err) {
      console.error('Error updating agent thinking status:', err);
      res.status(500).json({ error: err.message });
    }
  });

  router.get('/status', requireAuth, async (req, res) => {
    try {
      // Prefer in-memory if it was updated within the freshness window
      const inMemoryAge = agentThinkingStatus.timestamp
        ? Date.now() - new Date(agentThinkingStatus.timestamp).getTime()
        : Infinity;

      if (inMemoryAge <= STATUS_FRESH_MS) {
        return res.json(agentThinkingStatus);
      }

      // Stale in-memory (e.g. after a process restart) — fall back to DB
      const row = await db.get('SELECT * FROM agent_status WHERE id = 1').catch(() => null);
      if (row) {
        const dbAge = Date.now() - row.updated_at;
        const dbStatus = {
          status:    row.status,
          task:      row.task || null,
          timestamp: new Date(row.updated_at).toISOString(),
        };
        // Rehydrate in-memory so subsequent GETs don't hit the DB again
        agentThinkingStatus = dbStatus;
        return res.json(dbStatus);
      }

      // No DB row yet — return the default idle state
      res.json(agentThinkingStatus);
    } catch (err) {
      console.error('Error reading agent thinking status:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ============ AGENT HEALTH MONITORING ============
  let agentHealthStatus = {};

  router.post('/agent-health', requireAgentKey, async (req, res) => {
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

      // Persist to DB so health data survives process restarts / redeploys
      await db.run(
        `INSERT INTO agent_health (agent_id, health_data, updated_at)
         VALUES ($1, $2, $3)
         ON CONFLICT(agent_id) DO UPDATE SET
           health_data = excluded.health_data,
           updated_at  = excluded.updated_at`,
        [agentId, JSON.stringify(agentHealthStatus[agentId]), Date.now()]
      );

      broadcast('agent-health', agentHealthStatus[agentId]);
      res.json({ success: true, timestamp: now });
    } catch (err) {
      console.error('Error updating agent health:', err);
      res.status(500).json({ error: err.message });
    }
  });

  /**
   * Compute staleness thresholds for an agent health record.
   * Thresholds are server-authoritative — the client only renders what we provide.
   *
   * @param {object} health — entry from agentHealthStatus
   * @returns {{ minutesSinceReport: number, minutesSincePoll: number|null,
   *             reportStale: boolean, pollStale: boolean,
   *             stalenessLevel: 'ok'|'stale'|'dead' }}
   */
  function computeStaleness(health) {
    const now = new Date();
    const lastReportedAt = new Date(health.lastReportedAt);
    const minutesSinceReport = Math.floor((now - lastReportedAt) / 1000 / 60);
    const lastPoll = health.iMessagePolling?.lastPoll ? new Date(health.iMessagePolling.lastPoll) : null;
    const minutesSincePoll = lastPoll ? Math.floor((now - lastPoll) / 1000 / 60) : null;

    const stalenessLevel = minutesSinceReport > 15 ? 'dead'
                         : minutesSinceReport > 5  ? 'stale'
                         :                           'ok';

    return {
      minutesSinceReport,
      minutesSincePoll,
      reportStale: minutesSinceReport > 5,
      pollStale: minutesSincePoll !== null && minutesSincePoll > 15,
      stalenessLevel,
    };
  }

  router.get('/agent-health', requireAuth, async (req, res) => {
    try {
      // Rehydrate from DB on cold start (e.g. after a Railway redeploy) when
      // in-memory store is empty. DB is the durable backing; memory is the hot path.
      if (Object.keys(agentHealthStatus).length === 0) {
        const rows = await db.query('SELECT agent_id, health_data FROM agent_health', []).catch(() => []);
        for (const row of rows) {
          try {
            agentHealthStatus[row.agent_id] = JSON.parse(row.health_data);
          } catch (parseErr) {
            console.warn(`[agent-health] Failed to parse DB row for ${row.agent_id}:`, parseErr);
          }
        }
      }

      const agentId = req.query.agent_id;
      if (agentId) {
        const health = agentHealthStatus[agentId];
        if (!health) return res.status(404).json({ error: 'No health data for this agent' });

        return res.json({
          ...health,
          staleness: computeStaleness(health),
        });
      }

      // Return all agents enriched with staleness data
      const enriched = {};
      for (const [id, health] of Object.entries(agentHealthStatus)) {
        enriched[id] = { ...health, staleness: computeStaleness(health) };
      }
      res.json(enriched);
    } catch (err) {
      console.error('Error fetching agent health:', err);
      res.status(500).json({ error: err.message });
    }
  });

  // ============ WORK TRACKING ============
  // GET /api/work — returns initiatives, tasks, and recent signals together
  router.get('/work', requireAuth, async (req, res) => {
    try {
      const initiatives = await db.query('SELECT * FROM initiatives ORDER BY priority, created_at');
      const tasks = await db.query('SELECT * FROM work_tasks ORDER BY created_at DESC');
      const signals = await db.query('SELECT * FROM signals ORDER BY created_at DESC LIMIT 100');
      res.json({ initiatives, tasks, signals });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.post('/work/initiatives', requireAuth, async (req, res) => {
    try {
      const { title, description, status, priority, owner, target_date } = req.body;
      if (!title) return res.status(400).json({ error: 'title required' });
      const id = uuidv4();
      await db.run(
        'INSERT INTO initiatives (id, title, description, status, priority, owner, target_date) VALUES ($1, $2, $3, $4, $5, $6, $7)',
        [id, title, description || null, status || 'planned', priority || 'P2', owner || null, target_date || null]
      );
      const row = await db.get('SELECT * FROM initiatives WHERE id = $1', [id]);
      broadcast('work:initiative:created', row);
      res.status(201).json(row);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.post('/work/tasks', requireAuth, async (req, res) => {
    try {
      const { title, description, initiative_id, status, assigned_to, requested_by, session_key } = req.body;
      if (!title) return res.status(400).json({ error: 'title required' });
      const id = uuidv4();
      await db.run(
        'INSERT INTO work_tasks (id, title, description, initiative_id, status, assigned_to, requested_by, session_key) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
        [id, title, description || null, initiative_id || null, status || 'backlog', assigned_to || null, requested_by || null, session_key || null]
      );
      const row = await db.get('SELECT * FROM work_tasks WHERE id = $1', [id]);
      broadcast('work:task:created', row);
      res.status(201).json(row);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  router.put('/work/tasks/:id', requireAuth, async (req, res) => {
    try {
      const { status, assigned_to, title, description } = req.body;
      const updates = [];
      const params = [];
      let idx = 1;

      if (title !== undefined) { updates.push(`title = $${idx++}`); params.push(title); }
      if (description !== undefined) { updates.push(`description = $${idx++}`); params.push(description); }
      if (assigned_to !== undefined) { updates.push(`assigned_to = $${idx++}`); params.push(assigned_to); }
      if (status !== undefined) {
        updates.push(`status = $${idx++}`); params.push(status);
        const completed_at = (status === 'done' || status === 'complete') ? new Date().toISOString() : null;
        const started_at_sql = status === 'active' ? `started_at = COALESCE(started_at, $${idx++})` : null;
        updates.push(`completed_at = $${idx++}`); params.push(completed_at);
        if (started_at_sql) { updates.push(started_at_sql); params.push(new Date().toISOString()); }
      }

      if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });
      params.push(req.params.id);
      await db.run(`UPDATE work_tasks SET ${updates.join(', ')} WHERE id = $${idx}`, params);

      const row = await db.get('SELECT * FROM work_tasks WHERE id = $1', [req.params.id]);
      if (!row) return res.status(404).json({ error: 'not found' });
      broadcast('work:task:updated', row);
      res.json(row);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // PUT /api/work/initiatives/:id — update initiative
  router.put('/work/initiatives/:id', requireAuth, async (req, res) => {
    try {
      const { title, description, status, priority, owner, target_date } = req.body;
      const updates = [];
      const params = [];
      let idx = 1;
      if (title !== undefined) { updates.push(`title = $${idx++}`); params.push(title); }
      if (description !== undefined) { updates.push(`description = $${idx++}`); params.push(description); }
      if (status !== undefined) { updates.push(`status = $${idx++}`); params.push(status); }
      if (priority !== undefined) { updates.push(`priority = $${idx++}`); params.push(priority); }
      if (owner !== undefined) { updates.push(`owner = $${idx++}`); params.push(owner); }
      if (target_date !== undefined) { updates.push(`target_date = $${idx++}`); params.push(target_date); }
      if (updates.length === 0) return res.status(400).json({ error: 'No fields to update' });
      params.push(req.params.id);
      await db.run(`UPDATE initiatives SET ${updates.join(', ')} WHERE id = $${idx}`, params);
      const row = await db.get('SELECT * FROM initiatives WHERE id = $1', [req.params.id]);
      if (!row) return res.status(404).json({ error: 'not found' });
      broadcast('work:initiative:updated', row);
      res.json(row);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // ============ SIGNALS ============
  // GET /api/signals — fetch recent signals (auth required: user session OR agent key)
  router.get('/signals', requireAuth, async (req, res) => {
    try {
      const limit = Math.min(parseInt(req.query.limit || '50', 10), 200);
      const task_id = req.query.task_id || null;
      const initiative_id = req.query.initiative_id || null;
      const level = req.query.level || null;

      // JOIN with work_tasks to resolve task_label from session_key match
      let sql = `
        SELECT s.*,
               COALESCE(s.task_label, wt.title) AS task_label
        FROM signals s
        LEFT JOIN work_tasks wt
          ON wt.session_key IS NOT NULL
         AND wt.session_key != ''
         AND s.session_key = wt.session_key`;
      const conditions = [];
      const params = [];
      let idx = 1;

      if (task_id) { conditions.push(`s.task_id = $${idx++}`); params.push(task_id); }
      if (initiative_id) { conditions.push(`s.initiative_id = $${idx++}`); params.push(initiative_id); }
      if (level) { conditions.push(`s.level = $${idx++}`); params.push(level); }

      if (conditions.length) sql += ' WHERE ' + conditions.join(' AND ');
      sql += ` ORDER BY s.created_at DESC LIMIT $${idx}`;
      params.push(limit);

      const rows = await db.query(sql, params);
      res.json({ signals: rows, total: rows.length });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // POST /api/signals — agents post real-time status signals
  router.post('/signals', requireAgentKey, async (req, res) => {
    try {
      const { task_id, initiative_id, session_key, level, message, metadata } = req.body;
      if (!message) return res.status(400).json({ error: 'message required' });

      const row = await insertSignal(db, uuidv4, {
        task_id, initiative_id, agent_id: req.agent?.id || null,
        session_key, level, message, metadata,
      });
      broadcast('work:signal', row);
      res.status(201).json(row);
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  // POST /api/work (agent-friendly combined endpoint)
  // Accepts { type: 'initiative'|'task'|'signal', ...fields }
  router.post('/work', requireAgentKey, async (req, res) => {
    try {
      const { type } = req.body;
      if (!type) return res.status(400).json({ error: 'type required: initiative | task | signal' });

      if (type === 'signal') {
        const { task_id, initiative_id, session_key, level, message, metadata } = req.body;
        if (!message) return res.status(400).json({ error: 'message required' });

        const row = await insertSignal(db, uuidv4, {
          task_id, initiative_id, agent_id: req.agent?.id || null,
          session_key, level, message, metadata,
        });
        broadcast('work:signal', row);
        return res.status(201).json(row);
      }

      if (type === 'task') {
        const { title, description, initiative_id, status, assigned_to, requested_by, session_key } = req.body;
        if (!title) return res.status(400).json({ error: 'title required' });
        const id = uuidv4();
        await db.run(
          'INSERT INTO work_tasks (id, title, description, initiative_id, status, assigned_to, requested_by, session_key) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
          [id, title, description || null, initiative_id || null, status || 'active', assigned_to || null, requested_by || null, session_key || null]
        );
        const row = await db.get('SELECT * FROM work_tasks WHERE id = $1', [id]);
        broadcast('work:task:created', row);
        return res.status(201).json(row);
      }

      if (type === 'initiative') {
        const { title, description, status, priority, owner, target_date } = req.body;
        if (!title) return res.status(400).json({ error: 'title required' });
        const id = uuidv4();
        await db.run(
          'INSERT INTO initiatives (id, title, description, status, priority, owner, target_date) VALUES ($1, $2, $3, $4, $5, $6, $7)',
          [id, title, description || null, status || 'active', priority || 'P2', owner || null, target_date || null]
        );
        const row = await db.get('SELECT * FROM initiatives WHERE id = $1', [id]);
        broadcast('work:initiative:created', row);
        return res.status(201).json(row);
      }

      res.status(400).json({ error: 'Unknown type. Use: initiative | task | signal' });
    } catch (err) { res.status(500).json({ error: err.message }); }
  });

  return router;
};

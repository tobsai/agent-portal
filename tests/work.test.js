'use strict';

/**
 * tests/work.test.js
 *
 * GET /api/work requires a valid agent key. Verifies the response shape:
 * { initiatives, tasks, signals }.
 *
 * Also covers agent health persistence (NEXT-095):
 *   POST /api/agent-health — upserts to DB
 *   GET  /api/agent-health — rehydrates from DB on cold start
 */

// describe/it/expect are globally available via vitest globals:true
const request = require('supertest');
const { createApp } = require('./helpers/createApp');

describe('GET /api/work', () => {
  const { app, testAgentKey } = createApp();

  it('returns 200 with valid agent key', async () => {
    const res = await request(app)
      .get('/api/work')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.status).toBe(200);
  });

  it('response has initiatives, tasks, and signals arrays', async () => {
    const res = await request(app)
      .get('/api/work')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(Array.isArray(res.body.initiatives)).toBe(true);
    expect(Array.isArray(res.body.tasks)).toBe(true);
    expect(Array.isArray(res.body.signals)).toBe(true);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).get('/api/work');
    expect(res.status).toBe(401);
  });
});

describe('POST /api/agent-health — DB persistence (NEXT-095)', () => {
  it('persists health data to the agent_health table', async () => {
    const { app, db, testAgentKey } = createApp();

    const res = await request(app)
      .post('/api/agent-health')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({
        agentId: 'lewis',
        heartbeatActive: true,
        gatewayUptime: 3600,
        iMessagePolling: { lastPoll: null, lastMessage: null, messagesQueued: 0, pollingActive: false },
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);

    // Verify row was written to DB
    const row = await db.get('SELECT * FROM agent_health WHERE agent_id = $1', ['lewis']);
    expect(row).not.toBeNull();

    const parsed = JSON.parse(row.health_data);
    expect(parsed.agentId).toBe('lewis');
    expect(parsed.heartbeatActive).toBe(true);
    expect(parsed.gatewayUptime).toBe(3600);
  });

  it('upserts on repeated POST — does not create duplicates', async () => {
    const { app, db, testAgentKey } = createApp();

    await request(app)
      .post('/api/agent-health')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ agentId: 'lewis', gatewayUptime: 100 });

    await request(app)
      .post('/api/agent-health')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ agentId: 'lewis', gatewayUptime: 200 });

    const rows = await db.query('SELECT * FROM agent_health WHERE agent_id = $1', ['lewis']);
    expect(rows).toHaveLength(1);

    const parsed = JSON.parse(rows[0].health_data);
    expect(parsed.gatewayUptime).toBe(200);
  });
});

describe('GET /api/agent-health — DB rehydration on cold start (NEXT-095)', () => {
  it('rehydrates from DB when in-memory map is empty (simulates restart)', async () => {
    // Seed the DB directly before mounting the app, then verify GET reads from DB
    const { createTestDb } = require('./helpers/createApp');
    const db = createTestDb();

    const healthPayload = {
      agentId: 'lewis',
      lastReportedAt: new Date().toISOString(),
      heartbeatActive: true,
      gatewayUptime: 9999,
      iMessagePolling: { lastPoll: null, lastMessage: null, messagesQueued: 0, pollingActive: false },
    };

    // Write directly to DB (bypassing the in-memory map — simulates a prior process run)
    await db.run(
      `INSERT INTO agent_health (agent_id, health_data, updated_at)
       VALUES ($1, $2, $3)
       ON CONFLICT(agent_id) DO UPDATE SET
         health_data = excluded.health_data,
         updated_at  = excluded.updated_at`,
      ['lewis', JSON.stringify(healthPayload), Date.now()]
    );

    // Mount a fresh app instance with this pre-seeded DB
    // The in-memory agentHealthStatus map starts empty in this fresh workRouter instance
    const { app, testAgentKey } = createApp({ db });

    const res = await request(app)
      .get('/api/agent-health')
      .set('Authorization', `Bearer ${testAgentKey}`);

    expect(res.status).toBe(200);
    expect(res.body['lewis']).toBeDefined();
    expect(res.body['lewis'].gatewayUptime).toBe(9999);
    expect(res.body['lewis'].staleness).toBeDefined();
  });

  it('returns in-memory data without hitting DB when map is populated', async () => {
    const { app, testAgentKey } = createApp();

    // POST health so in-memory map is populated
    await request(app)
      .post('/api/agent-health')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ agentId: 'pascal', gatewayUptime: 42, heartbeatActive: false });

    const res = await request(app)
      .get('/api/agent-health')
      .set('Authorization', `Bearer ${testAgentKey}`);

    expect(res.status).toBe(200);
    expect(res.body['pascal']).toBeDefined();
    expect(res.body['pascal'].gatewayUptime).toBe(42);
    expect(res.body['pascal'].staleness).toBeDefined();
  });
});

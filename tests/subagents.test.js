'use strict';

/**
 * tests/subagents.test.js
 *
 * GET /api/subagents — builds a spawn tree from signals metadata.
 * Requires a valid agent key (requireAuth).
 */

const request = require('supertest');
const { createApp } = require('./helpers/createApp');

describe('GET /api/subagents', () => {
  const { app, testAgentKey } = createApp();

  it('returns 200 with valid agent key', async () => {
    const res = await request(app)
      .get('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.status).toBe(200);
  });

  it('response has tree and total fields', async () => {
    const res = await request(app)
      .get('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.body).toHaveProperty('tree');
    expect(Array.isArray(res.body.tree)).toBe(true);
    expect(typeof res.body.total).toBe('number');
    expect(res.body).toHaveProperty('generatedAt');
  });

  it('returns empty tree when no signals exist', async () => {
    const res = await request(app)
      .get('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.status).toBe(200);
    expect(res.body.tree).toHaveLength(0);
    expect(res.body.total).toBe(0);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).get('/api/subagents');
    expect(res.status).toBe(401);
  });

  it('builds tree nodes when signals have session_key metadata', async () => {
    // Seed a signal with subagent metadata using the agent key
    await request(app)
      .post('/api/signals')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({
        session_key: 'agent:main:main',
        level: 'info',
        message: 'Main agent started',
        metadata: { type: 'spawn', label: 'main', status: 'active' },
      });

    const res = await request(app)
      .get('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`);

    expect(res.status).toBe(200);
    expect(res.body.total).toBeGreaterThan(0);
    expect(res.body.tree.length).toBeGreaterThan(0);
  });
});

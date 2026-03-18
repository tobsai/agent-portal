'use strict';

/**
 * tests/scheduled.test.js
 *
 * GET /api/scheduled — lists scheduled tasks (placeholder; returns empty list gracefully).
 * Requires a valid agent key (requireAuth).
 */

const request = require('supertest');
const { createApp } = require('./helpers/createApp');

describe('GET /api/scheduled', () => {
  const { app, testAgentKey } = createApp();

  it('returns 200 with valid agent key', async () => {
    const res = await request(app)
      .get('/api/scheduled')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.status).toBe(200);
  });

  it('response has scheduled array and total', async () => {
    const res = await request(app)
      .get('/api/scheduled')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.body).toHaveProperty('scheduled');
    expect(Array.isArray(res.body.scheduled)).toBe(true);
    expect(typeof res.body.total).toBe('number');
  });

  it('returns empty list when no scheduled tasks exist', async () => {
    const res = await request(app)
      .get('/api/scheduled')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.body.scheduled).toHaveLength(0);
    expect(res.body.total).toBe(0);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).get('/api/scheduled');
    expect(res.status).toBe(401);
  });
});

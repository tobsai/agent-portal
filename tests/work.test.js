'use strict';

/**
 * tests/work.test.js
 *
 * GET /api/work requires a valid agent key. Verifies the response shape:
 * { initiatives, tasks, signals }.
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

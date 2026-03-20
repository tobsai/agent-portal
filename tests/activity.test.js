'use strict';

/**
 * tests/activity.test.js
 *
 * GET /api/activity — DEPRECATED in NEXT-088.
 *
 * The route now returns HTTP 410 Gone with a migration pointer to
 * GET /api/signals. These tests verify the deprecation contract:
 *   - Unauthenticated requests still get 401 (auth check runs before 410)
 *   - Authenticated requests get 410
 *   - Response body has the expected deprecation shape
 */

const request = require('supertest');
const { createApp } = require('./helpers/createApp');

describe('GET /api/activity (deprecated — NEXT-088)', () => {
  const { app, testAgentKey } = createApp();

  it('returns 401 without auth', async () => {
    const res = await request(app).get('/api/activity');
    expect(res.status).toBe(401);
  });

  it('returns 410 Gone with valid agent key', async () => {
    const res = await request(app)
      .get('/api/activity')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.status).toBe(410);
  });

  it('response body includes error, message, and replacement fields', async () => {
    const res = await request(app)
      .get('/api/activity')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.body).toHaveProperty('error', 'Gone');
    expect(res.body).toHaveProperty('message');
    expect(typeof res.body.message).toBe('string');
    expect(res.body).toHaveProperty('replacement', '/api/signals');
  });

  it('replacement field points to /api/signals', async () => {
    const res = await request(app)
      .get('/api/activity')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.body.replacement).toBe('/api/signals');
  });
});

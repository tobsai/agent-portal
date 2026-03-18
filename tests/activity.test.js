'use strict';

/**
 * tests/activity.test.js
 *
 * GET /api/activity — returns recent signals as an activity feed.
 * Requires a valid agent key (requireAuth).
 */

const request = require('supertest');
const { createApp } = require('./helpers/createApp');

describe('GET /api/activity', () => {
  const { app, testAgentKey } = createApp();

  it('returns 200 with valid agent key', async () => {
    const res = await request(app)
      .get('/api/activity')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.status).toBe(200);
  });

  it('response has activity array and total', async () => {
    const res = await request(app)
      .get('/api/activity')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.body).toHaveProperty('activity');
    expect(Array.isArray(res.body.activity)).toBe(true);
    expect(typeof res.body.total).toBe('number');
  });

  it('returns empty feed when no signals exist', async () => {
    const res = await request(app)
      .get('/api/activity')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.body.activity).toHaveLength(0);
    expect(res.body.total).toBe(0);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).get('/api/activity');
    expect(res.status).toBe(401);
  });

  it('reflects newly posted signals', async () => {
    // Post a signal first
    await request(app)
      .post('/api/signals')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ message: 'Activity feed test signal', level: 'info' });

    const res = await request(app)
      .get('/api/activity')
      .set('Authorization', `Bearer ${testAgentKey}`);

    expect(res.status).toBe(200);
    expect(res.body.activity.length).toBeGreaterThan(0);
    const found = res.body.activity.find(
      /** @param {{ message: string }} s */ s => s.message === 'Activity feed test signal'
    );
    expect(found).toBeTruthy();
  });
});

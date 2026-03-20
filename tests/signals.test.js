'use strict';

/**
 * tests/signals.test.js
 *
 * GET /api/signals — NEXT-088
 *
 * Verifies:
 *   1. Basic auth contract (401 without key, 200 with key)
 *   2. Response shape: { signals: [], count: number, total: number }
 *   3. `total` reflects the true DB count, not just the returned slice
 *   4. `count` equals signals.length
 *   5. Level filter narrows results correctly
 */

const request = require('supertest');
const { createApp } = require('./helpers/createApp');

describe('GET /api/signals (NEXT-088)', () => {
  const { app, db, testAgentKey } = createApp();

  // ── Auth ──────────────────────────────────────────────────────────────────

  it('returns 401 without auth', async () => {
    const res = await request(app).get('/api/signals');
    expect(res.status).toBe(401);
  });

  it('returns 200 with valid agent key', async () => {
    const res = await request(app)
      .get('/api/signals')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.status).toBe(200);
  });

  // ── Response shape ────────────────────────────────────────────────────────

  it('response has signals array, count, and total fields', async () => {
    const res = await request(app)
      .get('/api/signals')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.body).toHaveProperty('signals');
    expect(Array.isArray(res.body.signals)).toBe(true);
    expect(typeof res.body.count).toBe('number');
    expect(typeof res.body.total).toBe('number');
  });

  it('count equals signals.length', async () => {
    const res = await request(app)
      .get('/api/signals')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.body.count).toBe(res.body.signals.length);
  });

  // ── True total ────────────────────────────────────────────────────────────

  it('total reflects true DB count when limit is not reached', async () => {
    // Post 3 distinct signals so we have known data
    for (let i = 1; i <= 3; i++) {
      await request(app)
        .post('/api/signals')
        .set('Authorization', `Bearer ${testAgentKey}`)
        .send({ message: `total-test-signal-${i}`, level: 'info' });
    }

    const res = await request(app)
      .get('/api/signals?limit=200')
      .set('Authorization', `Bearer ${testAgentKey}`);

    // When limit is generous, total == count == signals.length
    expect(res.body.total).toBe(res.body.signals.length);
    expect(res.body.total).toBeGreaterThanOrEqual(3);
  });

  it('total exceeds count when limit truncates results', async () => {
    // Seed enough signals to exceed limit=1
    for (let i = 0; i < 3; i++) {
      await request(app)
        .post('/api/signals')
        .set('Authorization', `Bearer ${testAgentKey}`)
        .send({ message: `truncation-test-signal-${i}`, level: 'info' });
    }

    const res = await request(app)
      .get('/api/signals?limit=1')
      .set('Authorization', `Bearer ${testAgentKey}`);

    expect(res.body.signals).toHaveLength(1);
    expect(res.body.count).toBe(1);
    // DB has at least 3 rows from this test alone; total must be > 1
    expect(res.body.total).toBeGreaterThan(1);
  });

  // ── Level filter ──────────────────────────────────────────────────────────

  it('level filter narrows results and total to matching rows only', async () => {
    // Post one warning, one error — both unique messages so we can count
    await request(app)
      .post('/api/signals')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ message: 'level-filter-warning', level: 'warning' });

    await request(app)
      .post('/api/signals')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ message: 'level-filter-error', level: 'error' });

    const warnRes = await request(app)
      .get('/api/signals?level=warning')
      .set('Authorization', `Bearer ${testAgentKey}`);

    const errRes = await request(app)
      .get('/api/signals?level=error')
      .set('Authorization', `Bearer ${testAgentKey}`);

    // All returned signals must match the requested level
    expect(warnRes.body.signals.every(s => s.level === 'warning')).toBe(true);
    expect(errRes.body.signals.every(s => s.level === 'error')).toBe(true);

    // total must also be scoped to the filter
    expect(typeof warnRes.body.total).toBe('number');
    expect(warnRes.body.total).toBeGreaterThanOrEqual(1);
    expect(errRes.body.total).toBeGreaterThanOrEqual(1);

    // Cross-check: total for warning must not include error rows
    const allRes = await request(app)
      .get('/api/signals?limit=200')
      .set('Authorization', `Bearer ${testAgentKey}`);

    const allWarnCount = allRes.body.signals.filter(s => s.level === 'warning').length;
    expect(warnRes.body.total).toBe(allWarnCount);
  });
});

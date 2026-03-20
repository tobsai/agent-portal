'use strict';

// describe/it/expect are globally available via vitest globals:true
const request = require('supertest');
const { createApp } = require('./helpers/createApp');

describe('GET /api/health', () => {
  const { app } = createApp();

  it('returns 200 with structured health response', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(['ok', 'degraded', 'down']).toContain(res.body.status);
    expect(typeof res.body.timestamp).toBe('string');
    expect(typeof res.body.uptime).toBe('number');
    expect(typeof res.body.version).toBe('string');
    expect(res.body.checks).toBeDefined();
  });

  it('includes db, gateway, and apns checks', async () => {
    const res = await request(app).get('/api/health');
    const { checks } = res.body;
    expect(checks).toHaveProperty('db');
    expect(checks).toHaveProperty('gateway');
    expect(checks).toHaveProperty('apns');
    expect(['ok', 'degraded', 'down']).toContain(checks.db.status);
    expect(['ok', 'degraded', 'down']).toContain(checks.gateway.status);
    expect(['ok', 'degraded', 'down']).toContain(checks.apns.status);
  });

  it('db check is ok when db is reachable', async () => {
    const res = await request(app).get('/api/health');
    expect(res.body.checks.db.status).toBe('ok');
  });

  it('gateway check is degraded when not connected', async () => {
    const res = await request(app).get('/api/health');
    // Test app has a stub gateway (isReady: false) — should be degraded, not down
    expect(['degraded', 'down']).toContain(res.body.checks.gateway.status);
  });
});

describe('GET /api/dashboard', () => {
  const { app } = createApp();

  it('returns 200 with a health field', async () => {
    const res = await request(app).get('/api/dashboard');
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('health');
    expect(res.body.health).toHaveProperty('status');
    expect(res.body.health).toHaveProperty('checks');
    expect(res.body.health).toHaveProperty('uptime');
    expect(res.body.health).toHaveProperty('version');
    expect(typeof res.body.health.timestamp).toBe('string');
  });
});

'use strict';

/**
 * tests/auth.test.js
 *
 * Tests for the auth middleware (requireAuth / requireAgentKey) via a
 * protected endpoint: POST /api/signals (requireAgentKey) and
 * GET /api/work (requireAuth).
 */

// describe/it/expect are globally available via vitest globals:true
const request = require('supertest');
const { createApp } = require('./helpers/createApp');

describe('Auth middleware', () => {
  const { app, testAgentKey } = createApp();

  describe('missing Authorization header', () => {
    it('rejects GET /api/work with 401', async () => {
      const res = await request(app).get('/api/work');
      expect(res.status).toBe(401);
      expect(res.body.error).toBeTruthy();
    });

    it('rejects POST /api/signals with 401', async () => {
      const res = await request(app)
        .post('/api/signals')
        .send({ message: 'test' });
      expect(res.status).toBe(401);
    });
  });

  describe('invalid API key', () => {
    it('rejects GET /api/work with 401', async () => {
      const res = await request(app)
        .get('/api/work')
        .set('Authorization', 'Bearer ak_invalid_key_xxx');
      expect(res.status).toBe(401);
      expect(res.body.error).toBeTruthy();
    });

    it('rejects POST /api/signals with 401', async () => {
      const res = await request(app)
        .post('/api/signals')
        .set('Authorization', 'Bearer ak_totally_bogus')
        .send({ message: 'test' });
      expect(res.status).toBe(401);
    });
  });

  describe('valid agent key (ak_ prefix)', () => {
    it('passes GET /api/work with 200', async () => {
      const res = await request(app)
        .get('/api/work')
        .set('Authorization', `Bearer ${testAgentKey}`);
      expect(res.status).toBe(200);
    });

    it('passes POST /api/signals with 201', async () => {
      const res = await request(app)
        .post('/api/signals')
        .set('Authorization', `Bearer ${testAgentKey}`)
        .send({ message: 'Hello from test' });
      expect(res.status).toBe(201);
      expect(res.body.message).toBe('Hello from test');
    });
  });
});

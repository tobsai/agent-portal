'use strict';

/**
 * tests/auth.test.js
 *
 * Tests for the auth middleware (requireAuth / requireAgentKey) via a
 * test-only protected endpoint: GET /api/test-protected.
 */

const request = require('supertest');
const { createApp } = require('./helpers/createApp');

describe('Auth middleware', () => {
  const { app, testAgentKey } = createApp();

  describe('missing Authorization header', () => {
    it('rejects with 401', async () => {
      const res = await request(app).get('/api/test-protected');
      expect(res.status).toBe(401);
      expect(res.body.error).toBeTruthy();
    });
  });

  describe('invalid API key', () => {
    it('rejects with 401', async () => {
      const res = await request(app)
        .get('/api/test-protected')
        .set('Authorization', 'Bearer ak_invalid_key_xxx');
      expect(res.status).toBe(401);
      expect(res.body.error).toBeTruthy();
    });
  });

  describe('valid agent key (ak_ prefix)', () => {
    it('passes with 200', async () => {
      const res = await request(app)
        .get('/api/test-protected')
        .set('Authorization', `Bearer ${testAgentKey}`);
      expect(res.status).toBe(200);
      expect(res.body.ok).toBe(true);
    });
  });
});

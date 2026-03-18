'use strict';

/**
 * tests/agents.test.js
 *
 * GET /api/agents is a public endpoint — returns the static AGENTS registry.
 */

// describe/it/expect are globally available via vitest globals:true
const request = require('supertest');
const { createApp } = require('./helpers/createApp');

describe('GET /api/agents', () => {
  const { app } = createApp();

  it('returns 200 with an array', async () => {
    const res = await request(app).get('/api/agents');
    expect(res.status).toBe(200);
    expect(Array.isArray(res.body)).toBe(true);
  });

  it('each agent has id, name, emoji, avatarUrl', async () => {
    const res = await request(app).get('/api/agents');
    for (const agent of res.body) {
      expect(agent).toHaveProperty('id');
      expect(agent).toHaveProperty('name');
      expect(agent).toHaveProperty('emoji');
      expect(agent).toHaveProperty('avatarUrl');
    }
  });

  it('requires no Authorization header', async () => {
    const res = await request(app).get('/api/agents');
    // Public endpoint — should never be 401
    expect(res.status).not.toBe(401);
    expect(res.status).not.toBe(403);
  });
});

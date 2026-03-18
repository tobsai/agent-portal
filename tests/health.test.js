'use strict';

// describe/it/expect are globally available via vitest globals:true
const request = require('supertest');
const { createApp } = require('./helpers/createApp');

describe('GET /api/health', () => {
  const { app } = createApp();

  it('returns 200 with status ok', async () => {
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body).toMatchObject({ status: 'ok' });
    expect(typeof res.body.timestamp).toBe('string');
  });
});

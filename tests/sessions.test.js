'use strict';

const request = require('supertest');
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const jwt = require('jsonwebtoken');
const { createTestDb } = require('./helpers/createApp');
const chatRouter = require('../routes/chat');

function buildSessionsApp(db) {
  const app = express();
  app.use(express.json());

  const requireAuth = (req, res, next) => next();

  const router = chatRouter({
    db,
    AGENTS: [],
    CHAT_SESSION_KEY: 'portal:dm-lewis',
    CHAT_BUFFER_LIMIT: 50,
    requireAuth,
    requireAgentKey: requireAuth,
    uuidv4,
    JWT_SECRET: 'test-secret',
    jwt,
    broadcast: () => {},
    broadcastChatEvent: () => {},
    broadcastChannelEvent: () => {},
    connectChatGateway: () => {},
    chatGatewayRequest: async () => {},
    gatewayClient: {
      isReady: false,
      listSessions: async () => [],
      requestHistory: async () => ({ messages: [] }),
    },
    sendAgentMessage: async () => null,
    pushToAllDevices: async () => {},
    trackUserSend: () => {},
    pushChatMessage: () => true,
    getChatState: () => ({
      authenticated: false,
      buffer: [],
      sseClients: new Set(),
      channelSseClients: new Map(),
      lastActiveChannelId: null,
      lastActiveSessionKey: null,
    }),
    setChatState: () => {},
    sessionChannelMap: new Map(),
    apns: { isConfigured: false },
    publicDir: '/tmp',
  });

  app.use('/api', router);
  return app;
}

describe('PATCH /api/sessions/bulk', () => {
  let db, app;

  beforeEach(() => {
    db = createTestDb();
    app = buildSessionsApp(db);
  });

  it('returns 400 if updates is not an array', async () => {
    const res = await request(app)
      .patch('/api/sessions/bulk')
      .send({ updates: 'not-an-array' });
    expect(res.status).toBe(400);
    expect(res.body.error).toBeTruthy();
  });

  it('updates sessions and returns count', async () => {
    const res = await request(app)
      .patch('/api/sessions/bulk')
      .send({
        updates: [
          { sessionKey: 'portal:test-1', hidden: true, displayName: 'Test One', pinned: false },
          { sessionKey: 'portal:test-2', hidden: false, displayName: 'Test Two', pinned: true },
        ],
      });
    expect(res.status).toBe(200);
    expect(res.body.updated).toBe(2);

    const row1 = await db.get('SELECT * FROM session_meta WHERE session_key = $1', ['portal:test-1']);
    expect(row1).toBeTruthy();
    expect(!!row1.hidden).toBe(true);
    expect(row1.display_name).toBe('Test One');

    const row2 = await db.get('SELECT * FROM session_meta WHERE session_key = $1', ['portal:test-2']);
    expect(row2).toBeTruthy();
    expect(!!row2.hidden).toBe(false);
    expect(!!row2.pinned).toBe(true);
    expect(row2.display_name).toBe('Test Two');
  });

  it('skips entries without sessionKey', async () => {
    const res = await request(app)
      .patch('/api/sessions/bulk')
      .send({
        updates: [
          { hidden: true },
          { sessionKey: 'portal:valid', hidden: false },
        ],
      });
    expect(res.status).toBe(200);
    expect(res.body.updated).toBe(1);
  });

  it('upserts existing session_meta rows', async () => {
    // Pre-seed a row
    const now = new Date().toISOString();
    await db.run(
      'INSERT INTO session_meta (session_key, display_name, hidden, pinned, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6)',
      ['portal:existing', 'Old Name', 0, 0, now, now]
    );

    const res = await request(app)
      .patch('/api/sessions/bulk')
      .send({ updates: [{ sessionKey: 'portal:existing', displayName: 'New Name', hidden: true }] });
    expect(res.status).toBe(200);
    expect(res.body.updated).toBe(1);

    const row = await db.get('SELECT * FROM session_meta WHERE session_key = $1', ['portal:existing']);
    expect(row.display_name).toBe('New Name');
    expect(!!row.hidden).toBe(true);
  });
});

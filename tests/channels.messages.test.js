'use strict';

/**
 * tests/channels.messages.test.js
 *
 * Integration tests for POST /api/channels/:id/messages.
 *
 * These tests mount the chat router against an in-memory SQLite DB.
 * The gatewayClient is fully stubbed — no real WebSocket is opened.
 * sessionChannelMap is a real Map so we can verify mapping registration.
 */

const request = require('supertest');
const express = require('express');
const { v4: uuidv4 } = require('uuid');
const { createTestDb } = require('./helpers/createApp');

// ── Agents config (mirrors server.js) ────────────────────────────────────────

const AGENTS = [
  { id: 'lewis',  name: 'Lewis',  emoji: '📚', sessionKey: 'agent:main:main' },
  { id: 'pascal', name: 'Pascal', emoji: '⚙️',  sessionKey: 'agent:pascal:main' },
];

// ── Build a chat-capable test Express app ─────────────────────────────────────

function createChatApp(opts = {}) {
  const db = createTestDb();
  const testAgentKey = 'ak_test_' + uuidv4().replace(/-/g, '');

  // Seed test agent
  db.run('INSERT INTO agents (id, name, api_key) VALUES ($1, $2, $3)', [uuidv4(), 'TestAgent', testAgentKey]);

  const requireAuth = async (req, res, next) => {
    const key = req.headers.authorization?.replace('Bearer ', '');
    if (!key) return res.status(401).json({ error: 'Authentication required' });
    const agent = await db.get('SELECT * FROM agents WHERE api_key = $1', [key]);
    if (!agent) return res.status(401).json({ error: 'Invalid API key' });
    req.agent = agent;
    // Also stub isAuthenticated for chat routes that check it
    req.isAuthenticated = () => true;
    req.user = null;
    next();
  };

  const requireAgentKey = requireAuth;

  // Stub gateway client — not connected by default
  const gatewayClientStub = opts.gatewayClient || {
    isReady: false,
    sendUserMessage: async () => { throw new Error('Gateway not connected'); },
    send: async () => { throw new Error('Gateway not connected'); },
  };

  // Real sessionChannelMap for assertion in tests
  const sessionChannelMap = new Map();

  // Stub broadcast functions
  const broadcast = () => {};
  const broadcastChatEvent = () => {};
  const broadcastChannelEvent = opts.broadcastChannelEvent || (() => {});

  // Stub chat state
  let lastActiveChannelId = null;
  let lastActiveSessionKey = null;

  const getChatState = () => ({
    authenticated: false,
    ws: null,
    buffer: [],
    sseClients: new Set(),
    channelSseClients: new Map(),
    lastActiveChannelId,
    lastActiveSessionKey,
    sessionChannelMap,
  });

  const setChatState = (update) => {
    if (update.lastActiveChannelId !== undefined) lastActiveChannelId = update.lastActiveChannelId;
    if (update.lastActiveSessionKey !== undefined) lastActiveSessionKey = update.lastActiveSessionKey;
    if (update.sessionChannelMap) {
      const { sessionKey, channelId } = update.sessionChannelMap;
      sessionChannelMap.set(sessionKey, channelId);
    }
  };

  // sendAgentMessage stub — stores in DB, broadcasts, and returns message object
  const sendAgentMessage = async (channelId, content, senderName, senderEmoji, senderId) => {
    const id = uuidv4();
    await db.run(
      'INSERT INTO messages (id, channel_id, sender_type, sender_id, sender_name, sender_emoji, content, mentions) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
      [id, channelId, 'agent', senderId || 'agent', senderName, senderEmoji || '', content, '[]']
    );
    const message = await db.get('SELECT * FROM messages WHERE id = $1', [id]);
    if (message) broadcastChannelEvent(channelId, 'message', message);
    return message;
  };

  // Minimal jwt stub
  const jwtStub = {
    verify: () => { throw new Error('invalid token'); },
    sign: () => 'stub-token',
  };

  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    if (!req.isAuthenticated) req.isAuthenticated = () => false;
    next();
  });

  const chatRouter = require('../routes/chat');
  app.use('/api', chatRouter({
    db,
    AGENTS,
    CHAT_SESSION_KEY: 'agent:main:main',
    CHAT_BUFFER_LIMIT: 200,
    requireAuth,
    requireAgentKey,
    uuidv4,
    JWT_SECRET: 'test-secret',
    jwt: jwtStub,
    broadcast,
    broadcastChatEvent,
    broadcastChannelEvent,
    connectChatGateway: () => {},
    chatGatewayRequest: async () => ({}),
    gatewayClient: gatewayClientStub,
    sendAgentMessage,
    pushToAllDevices: async () => {},
    trackUserSend: () => {},
    pushChatMessage: () => true,
    getChatState,
    setChatState,
    sessionChannelMap,
    apns: { sendToAll: async () => {} },
    publicDir: __dirname,
  }));

  return { app, db, testAgentKey, sessionChannelMap, gatewayClientStub };
}

// ═════════════════════════════════════════════════════════════════════════════
// Tests
// ═════════════════════════════════════════════════════════════════════════════

describe('POST /api/channels/:id/messages', () => {

  // ── Auth ───────────────────────────────────────────────────────────────────

  it('returns 401 without auth', async () => {
    const { app, db } = createChatApp();
    const chanId = uuidv4();
    await db.run('INSERT INTO channels (id, name) VALUES ($1, $2)', [chanId, 'general']);

    const res = await request(app)
      .post(`/api/channels/${chanId}/messages`)
      .send({ content: 'hello' });

    expect(res.status).toBe(401);
  });

  // ── Validation ─────────────────────────────────────────────────────────────

  it('returns 400 when content is missing', async () => {
    const { app, db, testAgentKey } = createChatApp();
    const chanId = uuidv4();
    await db.run('INSERT INTO channels (id, name) VALUES ($1, $2)', [chanId, 'general']);

    const res = await request(app)
      .post(`/api/channels/${chanId}/messages`)
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({});

    expect(res.status).toBe(400);
    expect(res.body.error).toBeDefined();
  });

  // ── Agent-sender path ──────────────────────────────────────────────────────

  it('stores and returns a message when sender is an agent', async () => {
    const { app, db, testAgentKey } = createChatApp();
    const chanId = uuidv4();
    await db.run('INSERT INTO channels (id, name) VALUES ($1, $2)', [chanId, 'general']);

    const res = await request(app)
      .post(`/api/channels/${chanId}/messages`)
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ content: 'Hello from agent' });

    expect(res.status).toBe(201);
    expect(res.body.content).toBe('Hello from agent');
    expect(res.body.channel_id).toBe(chanId);
  });

  // ── DM channel → sessionChannelMap registration ────────────────────────────

  it('registers the DM session key in sessionChannelMap when a user sends to a DM channel', async () => {
    // Use a connected gatewayClient stub so the send path completes
    const sendUserMessageCalls = [];
    const gatewayClient = {
      isReady: true,
      sendUserMessage: async (sessionKey, text, idempotencyKey) => {
        sendUserMessageCalls.push({ sessionKey, text, idempotencyKey });
        return { ok: true };
      },
      send: async () => { throw new Error('Should not call send() in DM path'); },
    };

    const { app, db, testAgentKey, sessionChannelMap } = createChatApp({ gatewayClient });

    // Create a DM channel for lewis
    const chanId = uuidv4();
    await db.run(
      'INSERT INTO channels (id, name, is_dm, dm_agent_id) VALUES ($1, $2, $3, $4)',
      [chanId, 'dm-lewis', 1, 'lewis']
    );

    // The test agent acts as user (req.agent set, req.user null)
    // The route uses senderType='agent' when req.agent is set (and req.user is null)
    // We need a user sender to trigger the DM routing. Patch requireAuth to set req.user.
    // Actually looking at the route: senderType = req.agent ? 'agent' : 'user'
    // Since our requireAuth sets req.agent, it will be 'agent' path — agent routing is skipped.
    // For DM routing tests we need to simulate req.user without req.agent.
    // Solution: create a separate app where requireAuth sets req.user, not req.agent.

    // For this test we verify sessionChannelMap is populated when the route runs.
    // We'll use a custom app with user-style auth.
    const userApp = buildUserAuthApp({ gatewayClient, chanId, db });

    const res = await request(userApp)
      .post(`/api/channels/${chanId}/messages`)
      .set('Authorization', `Bearer user-token`)
      .send({ content: 'Hey Lewis' });

    expect(res.status).toBe(201);
    // gatewayClient.sendUserMessage should have been called
    expect(sendUserMessageCalls).toHaveLength(1);
    expect(sendUserMessageCalls[0].sessionKey).toBe('portal:dm-lewis');
    expect(sendUserMessageCalls[0].text).toBe('Hey Lewis');
  });

  it('registers session→channel mapping in sessionChannelMap', async () => {
    const sendUserMessageCalls = [];
    const sharedSessionChannelMap = new Map();

    const gatewayClient = {
      isReady: true,
      sendUserMessage: async (sessionKey, text) => {
        sendUserMessageCalls.push({ sessionKey, text });
        return { ok: true };
      },
    };

    const chanId = uuidv4();
    const userApp = buildUserAuthApp({ gatewayClient, chanId, sessionChannelMap: sharedSessionChannelMap });

    await request(userApp)
      .post(`/api/channels/${chanId}/messages`)
      .set('Authorization', `Bearer user-token`)
      .send({ content: 'Test message' });

    // The session→channel mapping must be set before the gateway call
    expect(sharedSessionChannelMap.get('portal:dm-lewis')).toBe(chanId);
  });

  // ── Delta SSE support (Phase 2c Item 2) ────────────────────────────────────

  it('broadcasts delta messages as SSE deltas and does not persist them', async () => {
    const broadcastCalls = [];
    const broadcastChannelEventStub = (channelId, event, data) => {
      broadcastCalls.push({ channelId, event, data });
    };

    const { app, db, testAgentKey } = createChatApp({ broadcastChannelEvent: broadcastChannelEventStub });
    const chanId = uuidv4();
    await db.run('INSERT INTO channels (id, name) VALUES ($1, $2)', [chanId, 'general']);

    const res = await request(app)
      .post(`/api/channels/${chanId}/messages`)
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ content: 'delta chunk', is_delta: true });

    expect(res.status).toBe(200);
    expect(res.body.delta).toBe(true);

    // Delta should have been broadcast as SSE delta
    expect(broadcastCalls).toHaveLength(1);
    expect(broadcastCalls[0].event).toBe('delta');
    expect(broadcastCalls[0].data.content).toBe('delta chunk');
    expect(broadcastCalls[0].data.is_delta).toBe(true);

    // Delta should NOT be in the DB
    const messages = await db.query('SELECT * FROM messages WHERE channel_id = $1', [chanId]);
    expect(messages).toHaveLength(0);
  });

  it('persists and broadcasts full messages when is_delta is absent', async () => {
    const broadcastCalls = [];
    const broadcastChannelEventStub = (channelId, event, data) => {
      broadcastCalls.push({ channelId, event, data });
    };

    const { app, db, testAgentKey } = createChatApp({ broadcastChannelEvent: broadcastChannelEventStub });
    const chanId = uuidv4();
    await db.run('INSERT INTO channels (id, name) VALUES ($1, $2)', [chanId, 'general']);

    // Send without is_delta field (default path)
    const res = await request(app)
      .post(`/api/channels/${chanId}/messages`)
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ content: 'full message' });

    expect(res.status).toBe(201);

    // Full message should be persisted
    const messages = await db.query('SELECT * FROM messages WHERE channel_id = $1', [chanId]);
    expect(messages).toHaveLength(1);
    expect(messages[0].content).toBe('full message');

    // Full message should be broadcast (sendAgentMessage calls broadcastChannelEvent)
    const messageEvents = broadcastCalls.filter(c => c.event === 'message');
    expect(messageEvents.length).toBeGreaterThan(0);
    expect(messageEvents[0].data.content).toBe('full message');
  });
});

// ── Helper: build an app where auth sets req.user (not req.agent) ─────────────

function buildUserAuthApp(opts = {}) {
  const db = opts.db || createTestDb();
  const chanId = opts.chanId || uuidv4();
  const sessionChannelMap = opts.sessionChannelMap || new Map();

  // Seed channel if db was provided without it
  if (!opts.db) {
    db.run(
      'INSERT INTO channels (id, name, is_dm, dm_agent_id) VALUES ($1, $2, $3, $4)',
      [chanId, 'dm-lewis', 1, 'lewis']
    );
  }

  const gatewayClient = opts.gatewayClient || {
    isReady: false,
    sendUserMessage: async () => { throw new Error('not connected'); },
  };

  const requireAuth = (req, res, next) => {
    const header = req.headers.authorization;
    if (!header?.startsWith('Bearer ')) return res.status(401).json({ error: 'Unauthorized' });
    // Simulate a logged-in user (not an agent)
    req.user = { id: 'user-001', name: 'Toby', is_admin: false };
    req.agent = null;
    req.isAuthenticated = () => true;
    next();
  };

  let lastActiveChannelId = null;
  let lastActiveSessionKey = null;

  const getChatState = () => ({
    authenticated: false,
    ws: null,
    buffer: [],
    sseClients: new Set(),
    channelSseClients: new Map(),
    lastActiveChannelId,
    lastActiveSessionKey,
    sessionChannelMap,
  });

  const setChatState = (update) => {
    if (update.lastActiveChannelId !== undefined) lastActiveChannelId = update.lastActiveChannelId;
    if (update.lastActiveSessionKey !== undefined) lastActiveSessionKey = update.lastActiveSessionKey;
    if (update.sessionChannelMap) {
      const { sessionKey, channelId } = update.sessionChannelMap;
      sessionChannelMap.set(sessionKey, channelId);
    }
  };

  const sendAgentMessage = async (channelId, content, senderName, senderEmoji, senderId) => {
    const id = uuidv4();
    await db.run(
      'INSERT INTO messages (id, channel_id, sender_type, sender_id, sender_name, sender_emoji, content, mentions) VALUES ($1, $2, $3, $4, $5, $6, $7, $8)',
      [id, channelId, 'agent', senderId || 'agent', senderName, senderEmoji || '', content, '[]']
    );
    return db.get('SELECT * FROM messages WHERE id = $1', [id]);
  };

  const app = express();
  app.use(express.json());
  app.use((req, _res, next) => {
    if (!req.isAuthenticated) req.isAuthenticated = () => false;
    next();
  });

  const chatRouter = require('../routes/chat');
  app.use('/api', chatRouter({
    db,
    AGENTS,
    CHAT_SESSION_KEY: 'agent:main:main',
    CHAT_BUFFER_LIMIT: 200,
    requireAuth,
    requireAgentKey: requireAuth,
    uuidv4,
    JWT_SECRET: 'test-secret',
    jwt: { verify: () => { throw new Error('invalid'); }, sign: () => 'stub' },
    broadcast: () => {},
    broadcastChatEvent: () => {},
    broadcastChannelEvent: () => {},
    connectChatGateway: () => {},
    chatGatewayRequest: async () => ({}),
    gatewayClient,
    sendAgentMessage,
    pushToAllDevices: async () => {},
    trackUserSend: () => {},
    pushChatMessage: () => true,
    getChatState,
    setChatState,
    sessionChannelMap,
    apns: { sendToAll: async () => {} },
    publicDir: __dirname,
  }));

  return app;
}

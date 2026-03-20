'use strict';

/**
 * tests/subagents.test.js
 *
 * GET /api/subagents — builds a spawn tree from signals metadata.
 * POST /api/subagents — registers a sub-agent at spawn time (NEXT-086).
 *
 * Requires a valid agent key (requireAuth).
 */

const request = require('supertest');
const { createApp } = require('./helpers/createApp');

describe('GET /api/subagents', () => {
  const { app, testAgentKey } = createApp();

  it('returns 200 with valid agent key', async () => {
    const res = await request(app)
      .get('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.status).toBe(200);
  });

  it('response has tree and total fields', async () => {
    const res = await request(app)
      .get('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.body).toHaveProperty('tree');
    expect(Array.isArray(res.body.tree)).toBe(true);
    expect(typeof res.body.total).toBe('number');
    expect(res.body).toHaveProperty('generatedAt');
  });

  it('returns empty tree when no signals exist', async () => {
    const res = await request(app)
      .get('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.status).toBe(200);
    expect(res.body.tree).toHaveLength(0);
    expect(res.body.total).toBe(0);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).get('/api/subagents');
    expect(res.status).toBe(401);
  });

  it('builds tree nodes when signals have session_key metadata', async () => {
    // Seed a signal with subagent metadata using the agent key
    await request(app)
      .post('/api/signals')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({
        session_key: 'agent:main:main',
        level: 'info',
        message: 'Main agent started',
        metadata: { type: 'spawn', label: 'main', status: 'active' },
      });

    const res = await request(app)
      .get('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`);

    expect(res.status).toBe(200);
    expect(res.body.total).toBeGreaterThan(0);
    expect(res.body.tree.length).toBeGreaterThan(0);
  });

  it('response includes failures summary with count and items', async () => {
    const res = await request(app)
      .get('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.status).toBe(200);
    expect(res.body).toHaveProperty('failures');
    expect(typeof res.body.failures.count).toBe('number');
    expect(Array.isArray(res.body.failures.items)).toBe(true);
  });

  it('failure items have required drill-down fields when errors exist', async () => {
    // Seed an error-status signal for a subagent session
    await request(app)
      .post('/api/signals')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({
        session_key: 'agent:main:subagent:fail-test-001',
        level: 'error',
        message: 'Simulated subagent failure for test',
        metadata: {
          type: 'subagent_error',
          label: 'fail-test-001',
          status: 'error',
        },
      });

    const res = await request(app)
      .get('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`);

    expect(res.status).toBe(200);
    expect(res.body.failures.count).toBeGreaterThan(0);

    const item = res.body.failures.items[0];
    expect(item).toHaveProperty('id');
    expect(item).toHaveProperty('label');
    expect(item).toHaveProperty('lastMessage');
    expect(item).toHaveProperty('runtime');
    expect(item).toHaveProperty('startedAt');
    expect(item).toHaveProperty('endedAt');
  });
});

// ─────────────────────────────────────────────────────────────────────────────
// POST /api/subagents — sub-agent registration on spawn (NEXT-086)
// ─────────────────────────────────────────────────────────────────────────────

describe('POST /api/subagents', () => {
  const { app, testAgentKey } = createApp();

  it('returns 401 without auth', async () => {
    const res = await request(app)
      .post('/api/subagents')
      .send({ session_key: 'agent:main:subagent:no-auth-test' });
    expect(res.status).toBe(401);
  });

  it('returns 400 when session_key is missing', async () => {
    const res = await request(app)
      .post('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ label: 'Missing session key' });
    expect(res.status).toBe(400);
    expect(res.body.error).toMatch(/session_key/i);
  });

  it('returns 201 with valid payload', async () => {
    const res = await request(app)
      .post('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ session_key: 'agent:main:subagent:reg-test-001', label: 'reg-test-001' });
    expect(res.status).toBe(201);
    expect(res.body).toHaveProperty('id');
    expect(res.body).toHaveProperty('message');
  });

  it('persists a signal with type=registered and session_key', async () => {
    const sessionKey = 'agent:main:subagent:reg-persist-001';

    await request(app)
      .post('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ session_key: sessionKey, label: 'reg-persist-001' });

    // Verify via GET /api/subagents — tree should include a node for this key
    const treeRes = await request(app)
      .get('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`);

    expect(treeRes.status).toBe(200);
    const allNodes = flattenTree(treeRes.body.tree);
    const node = allNodes.find(n => n.id === sessionKey);
    expect(node).toBeTruthy();
    expect(node.label).toBe('reg-persist-001');
  });

  it('registered node has status="registered" before any other signals', async () => {
    const sessionKey = 'agent:main:subagent:reg-status-test-001';

    await request(app)
      .post('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ session_key: sessionKey, label: 'reg-status-test-001' });

    const treeRes = await request(app)
      .get('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`);

    const allNodes = flattenTree(treeRes.body.tree);
    const node = allNodes.find(n => n.id === sessionKey);
    expect(node).toBeTruthy();
    expect(node.status).toBe('registered');
  });

  it('registration does not override terminal status when later signals arrive', async () => {
    const sessionKey = 'agent:main:subagent:reg-terminal-test-001';

    // First: seed a done-status signal
    await request(app)
      .post('/api/signals')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({
        session_key: sessionKey,
        level: 'info',
        message: 'Sub-agent completed',
        metadata: { type: 'subagent_end', label: 'reg-terminal-test-001', status: 'done' },
      });

    // Then: post a registration signal (e.g., late or replayed)
    await request(app)
      .post('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ session_key: sessionKey, label: 'reg-terminal-test-001' });

    const treeRes = await request(app)
      .get('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`);

    const allNodes = flattenTree(treeRes.body.tree);
    const node = allNodes.find(n => n.id === sessionKey);
    expect(node).toBeTruthy();
    // Done status from the end signal should not be overwritten by the registration
    expect(node.status).toBe('done');
  });

  it('stores parent_key relationship in the tree when provided', async () => {
    const parentKey = 'agent:main:cron:parent-test-001';
    const childKey  = 'agent:main:subagent:reg-child-001';

    // Register child with parent
    await request(app)
      .post('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ session_key: childKey, label: 'child-001', parent_key: parentKey });

    const treeRes = await request(app)
      .get('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`);

    const allNodes = flattenTree(treeRes.body.tree);
    const child = allNodes.find(n => n.id === childKey);
    expect(child).toBeTruthy();
    expect(child.parentId).toBe(parentKey);
  });

  it('optional model field is captured in the tree node', async () => {
    const sessionKey = 'agent:main:subagent:reg-model-test-001';

    await request(app)
      .post('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ session_key: sessionKey, label: 'reg-model-test-001', model: 'anthropic/claude-sonnet-4-6' });

    const treeRes = await request(app)
      .get('/api/subagents')
      .set('Authorization', `Bearer ${testAgentKey}`);

    const allNodes = flattenTree(treeRes.body.tree);
    const node = allNodes.find(n => n.id === sessionKey);
    expect(node).toBeTruthy();
    expect(node.model).toBe('anthropic/claude-sonnet-4-6');
  });
});

// ─── Helpers ──────────────────────────────────────────────────────────────────

/** Flatten a tree array (depth-first) into a flat list of nodes. */
function flattenTree(nodes, out = []) {
  for (const n of nodes) {
    out.push(n);
    if (Array.isArray(n.children)) flattenTree(n.children, out);
  }
  return out;
}

'use strict';

/**
 * tests/signals-sentry.test.js
 *
 * Tests for NEXT-081:
 *   1. Webhook delivery failure → signal emitted at level 'error'
 *   2. Push delivery failure   → signal emitted at level 'warning'
 *   3. /api/health response includes sentry field
 */

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { createTestDb } from './helpers/createApp';
import request from 'supertest';

// ── Helper: minimal express app scoped to health route ──────────────────────
import express from 'express';
import { createRequire } from 'module';
const require = createRequire(import.meta.url);

function createHealthApp({ db, sentryDsn } = {}) {
  const testDb = db || createTestDb();
  const app = express();
  app.use(express.json());
  if (sentryDsn !== undefined) {
    process.env.SENTRY_DSN = sentryDsn;
  } else {
    delete process.env.SENTRY_DSN;
  }
  const healthRouter = require('../routes/health');
  app.use('/api', healthRouter({
    gatewayClient: { isReady: false, ws: null },
    getChatState: () => ({ authenticated: false, ws: null }),
    db: testDb,
  }));
  return app;
}

// ── 1. Webhook delivery failure → emits error signal ───────────────────────

describe('deliverInboundWebhook — signal emit on failure', () => {
  let deliverInboundWebhook;
  let db;
  const uuidv4 = () => crypto.randomUUID();
  const broadcast = vi.fn();

  beforeEach(async () => {
    vi.resetModules();
    vi.stubGlobal('fetch', vi.fn());
    delete process.env.SENTRY_DSN;
    db = createTestDb();
    // Dynamically re-import so module-level env changes take effect
    ({ deliverInboundWebhook } = await import('../lib/webhook-delivery.js'));
  });

  afterEach(() => {
    vi.restoreAllMocks();
    delete process.env.WEBHOOK_URL;
    delete process.env.SENTRY_DSN;
  });

  it('emits an error signal when all retries fail with 5xx', async () => {
    fetch.mockResolvedValue({ status: 503 }); // both initial + retry fail
    await deliverInboundWebhook({
      channelId: 'ch-1',
      sessionKey: 'portal:dm-lewis',
      text: 'hello',
      senderId: 'user-1',
      _deps: { db, uuidv4, broadcast },
    });

    // Allow micro-task queue to flush (fire-and-forget insertSignal)
    await new Promise(r => setTimeout(r, 10));

    const signals = await db.query('SELECT * FROM signals ORDER BY created_at DESC LIMIT 5');
    expect(signals.length).toBe(1);
    expect(signals[0].level).toBe('error');
    expect(signals[0].message).toMatch(/Webhook delivery failed/);
    expect(signals[0].message).toMatch(/HTTP 503/);
    expect(broadcast).toHaveBeenCalledWith('work:signal', expect.objectContaining({ level: 'error' }));
  });

  it('emits an error signal when a network error occurs', async () => {
    fetch.mockRejectedValue(new Error('ECONNREFUSED'));
    await deliverInboundWebhook({
      channelId: 'ch-1',
      sessionKey: 'portal:dm-lewis',
      text: 'hello',
      senderId: 'user-1',
      _deps: { db, uuidv4, broadcast },
    });

    await new Promise(r => setTimeout(r, 10));

    const signals = await db.query('SELECT * FROM signals ORDER BY created_at DESC LIMIT 5');
    expect(signals.length).toBe(1);
    expect(signals[0].level).toBe('error');
    expect(signals[0].message).toMatch(/Webhook delivery failed/);
  });

  it('does NOT emit a signal on success (2xx)', async () => {
    fetch.mockResolvedValue({ status: 200 });
    await deliverInboundWebhook({
      channelId: 'ch-1',
      sessionKey: 'portal:dm-lewis',
      text: 'hello',
      senderId: 'user-1',
      _deps: { db, uuidv4, broadcast },
    });

    await new Promise(r => setTimeout(r, 10));

    const signals = await db.query('SELECT * FROM signals ORDER BY created_at DESC LIMIT 5');
    expect(signals.length).toBe(0);
  });

  it('does NOT crash when Sentry is configured (mock DSN, mocked require)', async () => {
    process.env.SENTRY_DSN = 'https://fake@sentry.io/123';
    // Sentry.captureException is not available in test context — should swallow error
    fetch.mockResolvedValue({ status: 500 });
    fetch.mockResolvedValueOnce({ status: 500 }).mockResolvedValueOnce({ status: 500 });

    await expect(
      deliverInboundWebhook({
        channelId: 'ch-1',
        sessionKey: 'portal:dm-lewis',
        text: 'hello',
        senderId: 'user-1',
        _deps: { db, uuidv4, broadcast },
      })
    ).resolves.toBeUndefined();
  });
});

// ── 2. Push failure → emits warning signal ──────────────────────────────────

describe('pushToAllDevices — signal emit on APNS failure', () => {
  let db;
  const uuidv4 = () => crypto.randomUUID();
  const broadcast = vi.fn();

  beforeEach(async () => {
    db = createTestDb();
    broadcast.mockClear();
    delete process.env.SENTRY_DSN;

    // Seed a fake push token
    await db.run(
      'INSERT INTO push_tokens (token, platform) VALUES ($1, $2)',
      ['device-token-abc', 'ios']
    ).catch(() => {
      // Table may not exist in base schema — seed via raw exec
    });
  });

  afterEach(() => {
    delete process.env.SENTRY_DSN;
  });

  it('emits a warning signal when APNS returns a non-BadDeviceToken error', async () => {
    const mockApns = {
      isConfigured: () => true,
      sendChatNotification: vi.fn().mockResolvedValue({ error: 'Unregistered' }),
    };

    // Manually seed push_tokens table (it may not be in base createTestDb schema)
    try {
      await db.run('CREATE TABLE IF NOT EXISTS push_tokens (token TEXT PRIMARY KEY, platform TEXT)');
      await db.run("INSERT OR IGNORE INTO push_tokens (token, platform) VALUES ('device-token-abc', 'ios')");
    } catch (_) { /* already exists */ }

    const createPush = require('../lib/push');
    const { pushToAllDevices } = createPush({ db, apns: mockApns, uuidv4, broadcast });

    await pushToAllDevices('Hello', 'Agent Portal');

    // Allow micro-task queue to flush
    await new Promise(r => setTimeout(r, 20));

    const signals = await db.query('SELECT * FROM signals ORDER BY created_at DESC LIMIT 5');
    expect(signals.length).toBeGreaterThanOrEqual(1);
    const warnSignal = signals.find(s => s.level === 'warning');
    expect(warnSignal).toBeDefined();
    expect(warnSignal.message).toMatch(/Push delivery failed/);
    expect(warnSignal.message).toMatch(/Unregistered/);
    expect(broadcast).toHaveBeenCalledWith('work:signal', expect.objectContaining({ level: 'warning' }));
  });

  it('emits a warning signal when APNS throws an exception', async () => {
    const mockApns = {
      isConfigured: () => true,
      sendChatNotification: vi.fn().mockRejectedValue(new Error('APNS timeout')),
    };

    try {
      await db.run('CREATE TABLE IF NOT EXISTS push_tokens (token TEXT PRIMARY KEY, platform TEXT)');
      await db.run("INSERT OR IGNORE INTO push_tokens (token, platform) VALUES ('device-token-xyz', 'ios')");
    } catch (_) { /* already exists */ }

    const createPush = require('../lib/push');
    const { pushToAllDevices } = createPush({ db, apns: mockApns, uuidv4, broadcast });

    await pushToAllDevices('Hello', 'Agent Portal');

    await new Promise(r => setTimeout(r, 20));

    const signals = await db.query('SELECT * FROM signals ORDER BY created_at DESC LIMIT 5');
    const warnSignal = signals.find(s => s.level === 'warning');
    expect(warnSignal).toBeDefined();
    expect(warnSignal.message).toMatch(/Push delivery failed/);
  });

  it('does NOT emit a signal when all pushes succeed', async () => {
    const mockApns = {
      isConfigured: () => true,
      sendChatNotification: vi.fn().mockResolvedValue({ status: 200 }),
    };

    try {
      await db.run('CREATE TABLE IF NOT EXISTS push_tokens (token TEXT PRIMARY KEY, platform TEXT)');
      await db.run("INSERT OR IGNORE INTO push_tokens (token, platform) VALUES ('device-token-ok', 'ios')");
    } catch (_) { /* already exists */ }

    const createPush = require('../lib/push');
    const { pushToAllDevices } = createPush({ db, apns: mockApns, uuidv4, broadcast });

    await pushToAllDevices('Hello', 'Agent Portal');

    await new Promise(r => setTimeout(r, 20));

    const signals = await db.query('SELECT * FROM signals WHERE level = $1', ['warning']);
    expect(signals.length).toBe(0);
  });
});

// ── 3. /api/health — sentry field ───────────────────────────────────────────

describe('GET /api/health — sentry field', () => {
  afterEach(() => {
    delete process.env.SENTRY_DSN;
  });

  it('reports sentry: ok when SENTRY_DSN is set', async () => {
    process.env.SENTRY_DSN = 'https://fake@sentry.io/123';
    const app = createHealthApp({ sentryDsn: 'https://fake@sentry.io/123' });
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.checks.sentry).toBeDefined();
    expect(res.body.checks.sentry.configured).toBe(true);
    expect(res.body.checks.sentry.status).toBe('ok');
  });

  it('reports sentry: unconfigured when SENTRY_DSN is not set', async () => {
    const app = createHealthApp({ sentryDsn: undefined });
    const res = await request(app).get('/api/health');
    expect(res.status).toBe(200);
    expect(res.body.checks.sentry).toBeDefined();
    expect(res.body.checks.sentry.configured).toBe(false);
    expect(res.body.checks.sentry.status).toBe('unconfigured');
  });

  it('overall health is not degraded purely due to sentry being unconfigured', async () => {
    const app = createHealthApp({ sentryDsn: undefined });
    const res = await request(app).get('/api/health');
    // The overall status should be 'ok' or 'degraded' for other reasons (gateway),
    // but not 'down'. sentry:unconfigured must not drag it to 'down'.
    expect(['ok', 'degraded']).toContain(res.body.status);
    // And the overall status must NOT be 'down' solely because of sentry
    // (we can verify by confirming sentry is not a 'down' check)
    expect(res.body.checks.sentry.status).not.toBe('down');
  });
});

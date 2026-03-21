'use strict';

/**
 * tests/scheduled.test.js
 *
 * GET  /api/scheduled — lists scheduled tasks.
 * POST /api/scheduled — registers (or deduplicates) a scheduled task.
 *
 * NEXT-059: verifies that repeated registrations with the same (name, schedule)
 * normalise to a single row, eliminating heartbeat count inflation.
 */

const request = require('supertest');
const { createApp } = require('./helpers/createApp');

describe('GET /api/scheduled', () => {
  const { app, testAgentKey } = createApp();

  it('returns 200 with valid agent key', async () => {
    const res = await request(app)
      .get('/api/scheduled')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.status).toBe(200);
  });

  it('response has scheduled array and total', async () => {
    const res = await request(app)
      .get('/api/scheduled')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.body).toHaveProperty('scheduled');
    expect(Array.isArray(res.body.scheduled)).toBe(true);
    expect(typeof res.body.total).toBe('number');
  });

  it('returns empty list when no scheduled tasks exist', async () => {
    const res = await request(app)
      .get('/api/scheduled')
      .set('Authorization', `Bearer ${testAgentKey}`);
    expect(res.body.scheduled).toHaveLength(0);
    expect(res.body.total).toBe(0);
  });

  it('returns 401 without auth', async () => {
    const res = await request(app).get('/api/scheduled');
    expect(res.status).toBe(401);
  });

  it('returns lastOutcome field for each task', async () => {
    const { app: freshApp, testAgentKey: freshKey } = createApp();
    // Register a task so there is at least one row
    await request(freshApp)
      .post('/api/scheduled')
      .set('Authorization', `Bearer ${freshKey}`)
      .send({ name: 'outcome-test', schedule: '0 * * * *' });

    const res = await request(freshApp)
      .get('/api/scheduled')
      .set('Authorization', `Bearer ${freshKey}`);
    expect(res.status).toBe(200);
    expect(res.body.scheduled[0]).toHaveProperty('lastOutcome');
  });
});

describe('POST /api/scheduled — deduplication (NEXT-059)', () => {
  it('registering the same task twice yields a single row', async () => {
    const { app, testAgentKey } = createApp();
    const payload = { name: 'heartbeat-check', schedule: '*/5 * * * *' };

    const r1 = await request(app)
      .post('/api/scheduled')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send(payload);
    expect(r1.status).toBe(200);

    const r2 = await request(app)
      .post('/api/scheduled')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send(payload);
    expect(r2.status).toBe(200);

    const list = await request(app)
      .get('/api/scheduled')
      .set('Authorization', `Bearer ${testAgentKey}`);
    const matching = list.body.scheduled.filter(t => t.name === 'heartbeat-check');
    expect(matching).toHaveLength(1);
  });

  it('registering tasks with different schedules creates separate rows', async () => {
    const { app, testAgentKey } = createApp();

    await request(app)
      .post('/api/scheduled')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ name: 'health-check', schedule: '*/10 * * * *' });

    await request(app)
      .post('/api/scheduled')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ name: 'health-check', schedule: '*/30 * * * *' });

    const list = await request(app)
      .get('/api/scheduled')
      .set('Authorization', `Bearer ${testAgentKey}`);
    const matching = list.body.scheduled.filter(t => t.name === 'health-check');
    expect(matching).toHaveLength(2);
  });

  it('returns 400 when name is missing', async () => {
    const { app, testAgentKey } = createApp();
    const res = await request(app)
      .post('/api/scheduled')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ schedule: '0 * * * *' });
    expect(res.status).toBe(400);
  });

  it('returns 400 when schedule is missing', async () => {
    const { app, testAgentKey } = createApp();
    const res = await request(app)
      .post('/api/scheduled')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ name: 'missing-sched' });
    expect(res.status).toBe(400);
  });

  it('returns 401 without agent key', async () => {
    const { app } = createApp();
    const res = await request(app)
      .post('/api/scheduled')
      .send({ name: 'test', schedule: '0 * * * *' });
    expect(res.status).toBe(401);
  });
});

describe('PATCH /api/scheduled/:id — outcome write-back (NEXT-079)', () => {
  /** Helper: register a task and return its id */
  async function registerTask(app, key, overrides = {}) {
    const res = await request(app)
      .post('/api/scheduled')
      .set('Authorization', `Bearer ${key}`)
      .send({ name: 'outcome-task', schedule: '0 * * * *', ...overrides });
    return res.body.task.id;
  }

  it('returns 404 when task id does not exist', async () => {
    const { app, testAgentKey } = createApp();
    const res = await request(app)
      .patch('/api/scheduled/nonexistent-id')
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ last_status: 'success' });
    expect(res.status).toBe(404);
  });

  it('returns 401 without agent key', async () => {
    const { app } = createApp();
    const res = await request(app)
      .patch('/api/scheduled/any-id')
      .send({ last_status: 'success' });
    expect(res.status).toBe(401);
  });

  it('updates last_status and last_outcome on the task row', async () => {
    const { app, testAgentKey } = createApp();
    const id = await registerTask(app, testAgentKey);

    const res = await request(app)
      .patch(`/api/scheduled/${id}`)
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({
        last_status:  'success',
        last_outcome: 'Completed 12 items in 4.2 s',
        last_run_at:  '2026-03-20T15:00:00.000Z',
        next_run_at:  '2026-03-20T16:00:00.000Z',
      });

    expect(res.status).toBe(200);
    expect(res.body.success).toBe(true);
    expect(res.body.task.last_status).toBe('success');
    expect(res.body.task.last_outcome).toBe('Completed 12 items in 4.2 s');
    expect(res.body.task.lastOutcome).toBe('Completed 12 items in 4.2 s');
    expect(res.body.task.lastRunStatus).toBe('success');
  });

  it('supports partial updates — only provided fields change', async () => {
    const { app, testAgentKey } = createApp();
    const id = await registerTask(app, testAgentKey);

    // First write: set an outcome
    await request(app)
      .patch(`/api/scheduled/${id}`)
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ last_status: 'success', last_outcome: 'First run OK' });

    // Second write: update only last_status
    const res = await request(app)
      .patch(`/api/scheduled/${id}`)
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ last_status: 'error' });

    expect(res.status).toBe(200);
    // last_outcome should be unchanged from the first write
    expect(res.body.task.last_outcome).toBe('First run OK');
    expect(res.body.task.last_status).toBe('error');
  });

  it('returns 400 when no updatable fields are provided', async () => {
    const { app, testAgentKey } = createApp();
    const id = await registerTask(app, testAgentKey);
    const res = await request(app)
      .patch(`/api/scheduled/${id}`)
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({});
    expect(res.status).toBe(400);
  });

  it('returns 400 for an invalid last_status value', async () => {
    const { app, testAgentKey } = createApp();
    const id = await registerTask(app, testAgentKey);
    const res = await request(app)
      .patch(`/api/scheduled/${id}`)
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ last_status: 'kaboom' });
    expect(res.status).toBe(400);
  });

  it('returns 400 for an invalid last_run_at timestamp', async () => {
    const { app, testAgentKey } = createApp();
    const id = await registerTask(app, testAgentKey);
    const res = await request(app)
      .patch(`/api/scheduled/${id}`)
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ last_run_at: 'not-a-date' });
    expect(res.status).toBe(400);
  });

  it('returns 400 for an invalid next_run_at timestamp', async () => {
    const { app, testAgentKey } = createApp();
    const id = await registerTask(app, testAgentKey);
    const res = await request(app)
      .patch(`/api/scheduled/${id}`)
      .set('Authorization', `Bearer ${testAgentKey}`)
      .send({ next_run_at: 12345 });
    expect(res.status).toBe(400);
  });
});

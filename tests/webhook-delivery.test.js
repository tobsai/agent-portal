'use strict';

import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';

// We test the module in isolation by mocking fetch
let deliverInboundWebhook;

beforeEach(async () => {
  vi.resetModules();
  vi.stubGlobal('fetch', vi.fn());
  ({ deliverInboundWebhook } = await import('../lib/webhook-delivery.js'));
});

afterEach(() => {
  vi.restoreAllMocks();
  delete process.env.WEBHOOK_URL;
  delete process.env.WEBHOOK_SECRET;
});

const baseParams = {
  channelId: 'ch-123',
  sessionKey: 'portal:dm-lewis',
  text: 'Hello agent',
  senderId: 'user-abc',
  timestamp: '2026-03-18T00:00:00.000Z',
};

describe('deliverInboundWebhook', () => {
  it('sends POST to default URL when WEBHOOK_URL is unset', async () => {
    fetch.mockResolvedValue({ status: 200 });
    await deliverInboundWebhook(baseParams);
    expect(fetch).toHaveBeenCalledTimes(1);
    const [url] = fetch.mock.calls[0];
    expect(url).toBe('http://127.0.0.1:3001/inbound');
  });

  it('sends POST to configured WEBHOOK_URL', async () => {
    process.env.WEBHOOK_URL = 'http://example.com/hook';
    fetch.mockResolvedValue({ status: 200 });
    await deliverInboundWebhook(baseParams);
    expect(fetch.mock.calls[0][0]).toBe('http://example.com/hook');
  });

  it('includes correct payload shape', async () => {
    fetch.mockResolvedValue({ status: 200 });
    await deliverInboundWebhook(baseParams);
    const body = JSON.parse(fetch.mock.calls[0][1].body);
    expect(body).toMatchObject({
      event: 'message',
      channelId: 'ch-123',
      sessionKey: 'portal:dm-lewis',
      text: 'Hello agent',
      senderId: 'user-abc',
      timestamp: '2026-03-18T00:00:00.000Z',
    });
  });

  it('sets X-Portal-Signature header with sha256= prefix', async () => {
    process.env.WEBHOOK_SECRET = 'test-secret';
    fetch.mockResolvedValue({ status: 200 });
    await deliverInboundWebhook(baseParams);
    const headers = fetch.mock.calls[0][1].headers;
    expect(headers['X-Portal-Signature']).toMatch(/^sha256=[0-9a-f]{64}$/);
  });

  it('signature matches expected HMAC for known payload', async () => {
    const { createHmac } = await import('crypto');
    process.env.WEBHOOK_SECRET = 'secret123';
    fetch.mockResolvedValue({ status: 200 });
    await deliverInboundWebhook(baseParams);
    const body = fetch.mock.calls[0][1].body;
    const expected = `sha256=${createHmac('sha256', 'secret123').update(body).digest('hex')}`;
    const actual = fetch.mock.calls[0][1].headers['X-Portal-Signature'];
    expect(actual).toBe(expected);
  });

  it('retries once on 5xx response', async () => {
    fetch
      .mockResolvedValueOnce({ status: 500 })
      .mockResolvedValueOnce({ status: 200 });
    await deliverInboundWebhook(baseParams);
    expect(fetch).toHaveBeenCalledTimes(2);
  });

  it('does not retry on 4xx response', async () => {
    fetch.mockResolvedValue({ status: 401 });
    await deliverInboundWebhook(baseParams);
    expect(fetch).toHaveBeenCalledTimes(1);
  });

  it('swallows network errors without throwing', async () => {
    fetch.mockRejectedValue(new Error('ECONNREFUSED'));
    await expect(deliverInboundWebhook(baseParams)).resolves.toBeUndefined();
  });

  it('swallows retry network errors without throwing', async () => {
    fetch
      .mockResolvedValueOnce({ status: 503 })
      .mockRejectedValueOnce(new Error('timeout'));
    await expect(deliverInboundWebhook(baseParams)).resolves.toBeUndefined();
  });
});

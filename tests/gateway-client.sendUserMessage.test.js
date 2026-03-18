'use strict';

/**
 * tests/gateway-client.sendUserMessage.test.js
 *
 * Unit tests for GatewayClient.sendUserMessage(sessionKey, text, idempotencyKey).
 *
 * These tests do NOT open a real WebSocket — they exercise the public contract
 * of sendUserMessage() in isolation using a minimal GatewayClient instance.
 */

const { GatewayClient } = require('../lib/gateway-client');

describe('GatewayClient.sendUserMessage()', () => {
  let client;

  beforeEach(() => {
    client = new GatewayClient();
  });

  afterEach(() => {
    // Destroy without a live WS — safe, just clears timers/state
    client._destroyed = true;
    client._clearTimers();
  });

  // ── Validation errors (no connection needed) ───────────────────────────────

  it('rejects when sessionKey is missing', async () => {
    await expect(client.sendUserMessage(null, 'hello')).rejects.toThrow('sessionKey is required');
  });

  it('rejects when sessionKey is empty string', async () => {
    await expect(client.sendUserMessage('', 'hello')).rejects.toThrow('sessionKey is required');
  });

  it('rejects when text is missing', async () => {
    await expect(client.sendUserMessage('portal:dm-lewis', null)).rejects.toThrow('text is required');
  });

  it('rejects when text is empty string', async () => {
    await expect(client.sendUserMessage('portal:dm-lewis', '  ')).rejects.toThrow('text is required');
  });

  // ── Not-connected state ────────────────────────────────────────────────────

  it('rejects with descriptive error when gateway is not connected', async () => {
    // Client is freshly constructed — not authenticated, no WS open
    await expect(
      client.sendUserMessage('portal:dm-lewis', 'hello')
    ).rejects.toThrow('Gateway not connected');
  });

  // ── Connected-path: verifies correct wire format ───────────────────────────

  it('sends the correct JSON frame to the gateway when connected', async () => {
    // Simulate an authenticated, open WebSocket by stubbing internals
    const sent = [];
    client.authenticated = true;
    client.ws = {
      readyState: 1, // WebSocket.OPEN
      send: (data) => sent.push(JSON.parse(data)),
    };

    // Resolve the pending request immediately to avoid hanging test
    const origRequest = client._request.bind(client);
    client._request = async (method, params) => {
      // Call original to push to pendingRequests map, then immediately resolve
      const promise = origRequest(method, params, 100 /* short timeout */);
      // Grab the last pending request ID and resolve it
      const ids = [...client.pendingRequests.keys()];
      const id = ids[ids.length - 1];
      if (id) {
        const pending = client.pendingRequests.get(id);
        client.pendingRequests.delete(id);
        clearTimeout(pending.timer);
        pending.resolve({ ok: true });
      }
      return promise;
    };

    await client.sendUserMessage('portal:dm-lewis', 'Hello Lewis');

    expect(sent).toHaveLength(1);
    const frame = sent[0];
    expect(frame.type).toBe('req');
    expect(frame.method).toBe('chat.send');
    expect(frame.params.sessionKey).toBe('portal:dm-lewis');
    expect(frame.params.message).toBe('Hello Lewis');
  });

  it('includes idempotencyKey in the frame when provided', async () => {
    const sent = [];
    client.authenticated = true;
    client.ws = {
      readyState: 1,
      send: (data) => sent.push(JSON.parse(data)),
    };

    client._request = async (method, params) => {
      const promise = new Promise((resolve) => resolve({ ok: true }));
      // Also push to sent via the original ws.send call — simulate it
      const id = `gw-req-test-${Date.now()}`;
      client.ws.send(JSON.stringify({ type: 'req', id, method, params }));
      return promise;
    };

    await client.sendUserMessage('portal:dm-lewis', 'Hello', 'idem-key-001');

    const frame = sent[0];
    expect(frame.params.idempotencyKey).toBe('idem-key-001');
  });

  it('trims whitespace from text before sending', async () => {
    const sent = [];
    client.authenticated = true;
    client.ws = {
      readyState: 1,
      send: (data) => sent.push(JSON.parse(data)),
    };

    client._request = async (method, params) => {
      client.ws.send(JSON.stringify({ type: 'req', id: 'x', method, params }));
      return { ok: true };
    };

    await client.sendUserMessage('portal:dm-lewis', '  trimmed  ');
    expect(sent[0].params.message).toBe('trimmed');
  });
});

'use strict';

/**
 * tests/gateway-client.test.js
 *
 * Unit tests for GatewayClient — sendMessage, listSessions, createSession,
 * requestHistory, and dynamic session routing.
 *
 * These tests do NOT open a real WebSocket — they exercise the public contract
 * in isolation using a minimal GatewayClient instance.
 */

const { GatewayClient } = require('../lib/gateway-client');

describe('GatewayClient', () => {
  let client;

  beforeEach(() => {
    client = new GatewayClient();
  });

  afterEach(() => {
    client._destroyed = true;
    client._clearTimers();
  });

  // ── Helper: stub a connected gateway ────────────────────────────────────────

  function stubConnected(client) {
    const sent = [];
    client.authenticated = true;
    client.ws = {
      readyState: 1, // WebSocket.OPEN
      send: (data) => sent.push(JSON.parse(data)),
    };

    // Auto-resolve pending requests
    const origRequest = client._request.bind(client);
    client._request = async (method, params) => {
      const promise = origRequest(method, params, 100);
      const ids = [...client.pendingRequests.keys()];
      const id = ids[ids.length - 1];
      if (id) {
        const pending = client.pendingRequests.get(id);
        client.pendingRequests.delete(id);
        clearTimeout(pending.timer);
        pending.resolve({ sessions: [], sessionKey: 'portal:test', label: 'Test', messages: [] });
      }
      return promise;
    };
    return sent;
  }

  // ── sendMessage ─────────────────────────────────────────────────────────────

  describe('sendMessage()', () => {
    it('rejects when sessionKey is missing', async () => {
      await expect(client.sendMessage(null, 'hello')).rejects.toThrow('sessionKey is required');
    });

    it('rejects when sessionKey is empty string', async () => {
      await expect(client.sendMessage('', 'hello')).rejects.toThrow('sessionKey is required');
    });

    it('rejects when text is missing', async () => {
      await expect(client.sendMessage('portal:general', null)).rejects.toThrow('text is required');
    });

    it('rejects when text is empty string', async () => {
      await expect(client.sendMessage('portal:general', '  ')).rejects.toThrow('text is required');
    });

    it('rejects when gateway is not connected', async () => {
      await expect(
        client.sendMessage('portal:general', 'hello')
      ).rejects.toThrow('Gateway not connected');
    });

    it('sends the correct JSON frame when connected', async () => {
      const sent = stubConnected(client);
      await client.sendMessage('portal:general', 'Hello Lewis');

      expect(sent).toHaveLength(1);
      const frame = sent[0];
      expect(frame.type).toBe('req');
      expect(frame.method).toBe('chat.send');
      expect(frame.params.sessionKey).toBe('portal:general');
      expect(frame.params.message).toBe('Hello Lewis');
    });

    it('includes idempotencyKey in the frame when provided', async () => {
      const sent = stubConnected(client);
      await client.sendMessage('portal:general', 'Hello', 'idem-001');

      expect(sent[0].params.idempotencyKey).toBe('idem-001');
    });

    it('trims whitespace from text before sending', async () => {
      const sent = stubConnected(client);
      await client.sendMessage('portal:general', '  trimmed  ');
      expect(sent[0].params.message).toBe('trimmed');
    });

    it('routes to any dynamic session key', async () => {
      const sent = stubConnected(client);
      await client.sendMessage('portal:fort', 'fort message');
      expect(sent[0].params.sessionKey).toBe('portal:fort');
    });
  });

  // ── listSessions ────────────────────────────────────────────────────────────

  describe('listSessions()', () => {
    it('rejects when gateway is not connected', async () => {
      await expect(client.listSessions()).rejects.toThrow('Gateway not connected');
    });

    it('sends sessions.list request and returns sessions array', async () => {
      const sent = stubConnected(client);
      const result = await client.listSessions();

      expect(sent).toHaveLength(1);
      expect(sent[0].method).toBe('sessions.list');
      expect(Array.isArray(result)).toBe(true);
    });
  });

  // ── createSession ───────────────────────────────────────────────────────────

  describe('createSession()', () => {
    it('rejects when gateway is not connected', async () => {
      await expect(client.createSession('Fort')).rejects.toThrow('Gateway not connected');
    });

    it('sends sessions.create with label', async () => {
      const sent = stubConnected(client);
      const result = await client.createSession('Fort');

      expect(sent).toHaveLength(1);
      expect(sent[0].method).toBe('sessions.create');
      expect(sent[0].params.label).toBe('Fort');
      expect(result.sessionKey).toBe('portal:test');
    });
  });

  // ── requestHistory ──────────────────────────────────────────────────────────

  describe('requestHistory()', () => {
    it('rejects when gateway is not connected', async () => {
      await expect(client.requestHistory('portal:general')).rejects.toThrow('Gateway not connected');
    });

    it('sends chat.history with sessionKey and limit', async () => {
      const sent = stubConnected(client);
      await client.requestHistory('portal:fort', 100);

      expect(sent).toHaveLength(1);
      expect(sent[0].method).toBe('chat.history');
      expect(sent[0].params.sessionKey).toBe('portal:fort');
      expect(sent[0].params.limit).toBe(100);
    });

    it('defaults limit to 50', async () => {
      const sent = stubConnected(client);
      await client.requestHistory('portal:general');
      expect(sent[0].params.limit).toBe(50);
    });
  });

  // ── No hardcoded agent session keys ─────────────────────────────────────────

  describe('no hardcoded agent mappings', () => {
    it('does not export AGENT_SESSION_KEYS', () => {
      const mod = require('../lib/gateway-client');
      expect(mod.AGENT_SESSION_KEYS).toBeUndefined();
    });

    it('does not export sessionKeyForAgent', () => {
      const mod = require('../lib/gateway-client');
      expect(mod.sessionKeyForAgent).toBeUndefined();
    });

    it('does not export agentIdForSessionKey', () => {
      const mod = require('../lib/gateway-client');
      expect(mod.agentIdForSessionKey).toBeUndefined();
    });
  });
});

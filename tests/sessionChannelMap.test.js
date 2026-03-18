'use strict';

/**
 * tests/sessionChannelMap.test.js
 *
 * Verifies that the sessionChannelMap correctly maps DM session keys to their
 * originating channel IDs, and that the wireGatewayClientEvents() logic
 * (simulated here) routes agent replies to the correct channel.
 *
 * This is a unit test — it does not start a server or open a DB.
 */

describe('sessionChannelMap — DM reply routing', () => {
  const CHANNEL_LEWIS_DM = 'chan-lewis-dm-uuid-001';
  const CHANNEL_GENERAL  = 'chan-general-uuid-002';
  const SESSION_LEWIS     = 'portal:dm-lewis';

  /**
   * Simulate the behaviour of wireGatewayClientEvents() message handler:
   * resolve channel from sessionChannelMap, falling back to lastActiveChannelId.
   */
  function resolveChannel(sessionChannelMap, sessionKey, lastActiveChannelId) {
    return sessionChannelMap.get(sessionKey) || lastActiveChannelId;
  }

  it('routes DM reply to the correct DM channel when mapping is present', () => {
    const sessionChannelMap = new Map();
    sessionChannelMap.set(SESSION_LEWIS, CHANNEL_LEWIS_DM);

    const resolved = resolveChannel(sessionChannelMap, SESSION_LEWIS, CHANNEL_GENERAL);
    expect(resolved).toBe(CHANNEL_LEWIS_DM);
  });

  it('falls back to lastActiveChannelId when no mapping exists for the session key', () => {
    const sessionChannelMap = new Map();
    // No mapping registered — user has not yet sent a DM

    const resolved = resolveChannel(sessionChannelMap, SESSION_LEWIS, CHANNEL_GENERAL);
    expect(resolved).toBe(CHANNEL_GENERAL);
  });

  it('resolves null when neither sessionChannelMap nor lastActiveChannelId is set', () => {
    const sessionChannelMap = new Map();

    const resolved = resolveChannel(sessionChannelMap, SESSION_LEWIS, null);
    expect(resolved).toBeNull();
  });

  it('returns undefined/falsy when map has no entry and lastActive is undefined', () => {
    const sessionChannelMap = new Map();

    const resolved = resolveChannel(sessionChannelMap, SESSION_LEWIS, undefined);
    expect(resolved).toBeFalsy();
  });

  it('maps multiple agents to independent channels without cross-contamination', () => {
    const sessionChannelMap = new Map();
    const CHANNEL_MARTY_DM = 'chan-marty-dm-uuid-003';
    const SESSION_MARTY     = 'portal:dm-marty';

    sessionChannelMap.set(SESSION_LEWIS, CHANNEL_LEWIS_DM);
    sessionChannelMap.set(SESSION_MARTY, CHANNEL_MARTY_DM);

    expect(resolveChannel(sessionChannelMap, SESSION_LEWIS, CHANNEL_GENERAL)).toBe(CHANNEL_LEWIS_DM);
    expect(resolveChannel(sessionChannelMap, SESSION_MARTY, CHANNEL_GENERAL)).toBe(CHANNEL_MARTY_DM);
  });

  it('allows a session key to be re-bound when a new conversation starts', () => {
    const sessionChannelMap = new Map();
    const CHANNEL_NEW_DM = 'chan-lewis-dm-new-session-004';

    sessionChannelMap.set(SESSION_LEWIS, CHANNEL_LEWIS_DM);
    expect(resolveChannel(sessionChannelMap, SESSION_LEWIS, null)).toBe(CHANNEL_LEWIS_DM);

    // User starts a new DM session (e.g. on a different device or after re-auth)
    sessionChannelMap.set(SESSION_LEWIS, CHANNEL_NEW_DM);
    expect(resolveChannel(sessionChannelMap, SESSION_LEWIS, null)).toBe(CHANNEL_NEW_DM);
  });

  it('general channel messages still route correctly after a DM mapping is set', () => {
    const sessionChannelMap = new Map();
    sessionChannelMap.set(SESSION_LEWIS, CHANNEL_LEWIS_DM);

    // A general channel message arrives on a different session key
    const GENERAL_SESSION_KEY = 'agent:main:main';
    const resolved = resolveChannel(sessionChannelMap, GENERAL_SESSION_KEY, CHANNEL_GENERAL);
    expect(resolved).toBe(CHANNEL_GENERAL);
  });
});

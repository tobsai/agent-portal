'use strict';

/**
 * lib/chat-state.js — Chat state management: agents registry, message buffers,
 * SSE client tracking, normalization, and dedup helpers.
 * Extracted from server.js (NEXT-027 Part 1).
 *
 * @returns {object} Chat state and helper functions
 */
module.exports = function createChatState() {
  // ============ AGENTS REGISTRY ============
  const AGENTS = [
    { id: 'lewis', name: 'Lewis', emoji: '📚', sessionKey: 'portal:lewis', avatarUrl: '/assets/lewis-avatar.png' },
    { id: 'marty', name: 'Marty', emoji: '🎯', sessionKey: 'portal:marty', avatarUrl: '/assets/marty-avatar.jpg' },
    { id: 'pascal', name: 'Pascal', emoji: '⚙️', sessionKey: 'portal:pascal', avatarUrl: '/assets/pascal-avatar.jpg' },
    { id: 'milton', name: 'Milton', emoji: '💰', sessionKey: 'portal:milton', avatarUrl: '/assets/milton-avatar.jpg' }
  ];

  /**
   * Resolve an agent from a session key or agentId.
   * Handles sub-agent keys like "agent:main:subagent:uuid" by extracting the parent agent.
   * Falls back to agentId string match.
   */
  function resolveAgent(sessionKey, agentId) {
    // Direct session key match first
    let agent = AGENTS.find(a => a.sessionKey === sessionKey);
    if (agent) return agent;

    // Direct agentId match
    if (agentId) {
      agent = AGENTS.find(a => a.id === agentId);
      if (agent) return agent;
    }

    // Parse sub-agent session keys: "agent:<parentAgentId>:subagent:<uuid>"
    if (sessionKey) {
      const parts = sessionKey.split(':');
      if (parts.length >= 2 && parts[0] === 'agent') {
        const parentAgentId = parts[1];
        // Map 'main' to 'lewis'
        const mappedId = parentAgentId === 'main' ? 'lewis' : parentAgentId;
        agent = AGENTS.find(a => a.id === mappedId);
        if (agent) return agent;
      }
    }

    return null;
  }

  const CHAT_SESSION_KEY = 'portal:lewis';
  const CHAT_BUFFER_LIMIT = 200;
  const chatMessageBuffer = [];
  const chatSseClients = new Set();
  const channelSseClients = new Map(); // channelId -> Set<{res, userId}>
  const gatewayPendingReqs = new Map();
  const recentUserSends = new Map();
  const RECENT_USER_SEND_TTL = 30000;

  /**
   * Maps gateway session keys → channel IDs so that agent replies route back to
   * the correct DM (or general) channel when the native client fires a 'message'
   * event.  Populated by routes/chat.js when a user sends to a channel; read by
   * wireGatewayClientEvents() in chat-gateway.js.
   *
   * Key:   sessionKey  (e.g. 'portal:dm-lewis')
   * Value: channelId   (UUID of the channel the reply should route to)
   */
  const sessionChannelMap = new Map();

  // Track last channel that sent a message so agent replies go back to the right channel
  let lastActiveChannelId = null;
  let lastActiveSessionKey = CHAT_SESSION_KEY; // tracks which agent session is currently active

  function userContentKey(text) { return (text || '').slice(0, 200); }

  function trackUserSend(text) {
    const key = userContentKey(text);
    recentUserSends.set(key, Date.now());
    if (recentUserSends.size > 50) {
      const now = Date.now();
      for (const [k, ts] of recentUserSends) {
        if (now - ts > RECENT_USER_SEND_TTL) recentUserSends.delete(k);
      }
    }
  }

  function isRecentUserSend(text) {
    const key = userContentKey(text);
    const ts = recentUserSends.get(key);
    if (!ts) return false;
    if (Date.now() - ts > RECENT_USER_SEND_TTL) { recentUserSends.delete(key); return false; }
    recentUserSends.delete(key);
    return true;
  }

  function normalizeChatText(content) {
    if (typeof content === 'string') return content;
    if (Array.isArray(content)) {
      return content
        .filter(part => part && part.type === 'text' && typeof part.text === 'string')
        .map(part => part.text)
        .join('\n');
    }
    return '';
  }

  function looksLikeToolOutput(text) {
    if (!text || text.length < 5) return false;
    const trimmed = text.trim();
    if (/^\{"data":\{/.test(trimmed)) return true;
    if (/^\{"errors":\[/.test(trimmed)) return true;
    if (/^[\s\S]*➜\s/.test(trimmed) && trimmed.includes('workspace')) return true;
    if (trimmed.startsWith('ID:') && trimmed.includes('Vault:')) return true;
    return false;
  }

  function simpleHash(str) {
    let hash = 0;
    for (let i = 0; i < Math.min(str.length, 200); i++) {
      hash = ((hash << 5) - hash) + str.charCodeAt(i);
      hash |= 0;
    }
    return Math.abs(hash).toString(36);
  }

  function normalizeChatMessage(message) {
    if (!message || (message.role !== 'user' && message.role !== 'assistant')) return null;
    const text = normalizeChatText(message.content || message.text || '');
    if (!text) return null;
    if (message.role === 'assistant' && looksLikeToolOutput(text)) return null;
    const id = message.id || `msg-${message.role}-${simpleHash(text)}-${Math.floor(Date.now() / 15000)}`;
    return {
      id,
      role: message.role,
      text,
      timestamp: message.timestamp || new Date().toISOString(),
      status: message.status || 'delivered'
    };
  }

  function pushChatMessage(message) {
    const index = chatMessageBuffer.findIndex(m => m.id === message.id);
    if (index >= 0) { chatMessageBuffer[index] = message; return false; }
    const msgTime = new Date(message.timestamp || Date.now()).getTime();
    const dup = chatMessageBuffer.find(m =>
      m.role === message.role && m.text === message.text &&
      Math.abs(new Date(m.timestamp || 0).getTime() - msgTime) < 30000
    );
    if (dup) return false;
    chatMessageBuffer.push(message);
    while (chatMessageBuffer.length > CHAT_BUFFER_LIMIT) chatMessageBuffer.shift();
    return true;
  }

  /** Helper: expose mutable chat state to route modules */
  function getChatState() {
    return {
      buffer: chatMessageBuffer,
      sseClients: chatSseClients,
      channelSseClients,
      lastActiveChannelId,
      lastActiveSessionKey,
      sessionChannelMap,
    };
  }

  function setChatState(updates) {
    if ('lastActiveChannelId' in updates) lastActiveChannelId = updates.lastActiveChannelId;
    if ('lastActiveSessionKey' in updates) lastActiveSessionKey = updates.lastActiveSessionKey;
    if ('sessionChannelMap' in updates) {
      // Caller passes { sessionKey, channelId } — update the shared Map entry
      const { sessionKey, channelId } = updates.sessionChannelMap;
      if (sessionKey && channelId) sessionChannelMap.set(sessionKey, channelId);
    }
  }

  return {
    AGENTS,
    resolveAgent,
    CHAT_SESSION_KEY,
    CHAT_BUFFER_LIMIT,
    chatMessageBuffer,
    chatSseClients,
    channelSseClients,
    gatewayPendingReqs,
    sessionChannelMap,
    trackUserSend,
    isRecentUserSend,
    normalizeChatMessage,
    pushChatMessage,
    getChatState,
    setChatState,
    // Expose getters for mutable scalars
    getLastActiveChannelId: () => lastActiveChannelId,
    getLastActiveSessionKey: () => lastActiveSessionKey,
  };
};

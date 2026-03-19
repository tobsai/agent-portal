'use strict';

/**
 * lib/broadcast.js — SSE broadcast to connected clients (chat-wide and per-channel).
 * Extracted from server.js (NEXT-027 Part 1).
 *
 * @param {object} deps
 * @param {Set}    deps.chatSseClients     — Set of { res } SSE clients for global chat
 * @param {Map}    deps.channelSseClients  — Map<channelId, Set<{res, userId}>> for per-channel SSE
 * @returns {object} Broadcast functions
 */
module.exports = function createBroadcast({ chatSseClients, channelSseClients }) {
  function writeSseEvent(res, event, data) {
    res.write(`event: ${event}\n`);
    res.write(`data: ${JSON.stringify(data)}\n\n`);
  }

  function broadcastChatEvent(event, data) {
    for (const client of chatSseClients) {
      writeSseEvent(client.res, event, data);
    }
  }

  function broadcastChannelEvent(channelId, event, data) {
    const clients = channelSseClients.get(channelId);
    if (clients) {
      for (const client of clients) {
        writeSseEvent(client.res, event, data);
      }
    }
    const allClients = channelSseClients.get('__all__');
    if (allClients) {
      for (const client of allClients) {
        writeSseEvent(client.res, event, { ...data, channelId });
      }
    }
  }

  return { writeSseEvent, broadcastChatEvent, broadcastChannelEvent };
};

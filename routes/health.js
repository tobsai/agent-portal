'use strict';

/**
 * routes/health.js — /api/health, /api/gateway-status
 *
 * @param {object} deps
 * @param {object} deps.gatewayClient   — native gateway client instance
 * @param {Function} deps.getChatState  — () => { authenticated, ws } for the legacy proxy
 * @returns {import('express').Router}
 */
const { Router } = require('express');

module.exports = function healthRouter({ gatewayClient, getChatState }) {
  const router = Router();

  // GET /api/health
  router.get('/health', (req, res) => {
    res.json({ status: 'ok', timestamp: new Date().toISOString() });
  });

  // GET /api/gateway-status
  router.get('/gateway-status', (req, res) => {
    const gwUrl = process.env.GATEWAY_WS_URL || '';
    const { authenticated: chatGatewayAuthenticated, ws: chatGatewayWs } = getChatState();
    res.json({
      // Legacy proxy path
      gatewayAuthenticated: chatGatewayAuthenticated,
      gatewayWsState: chatGatewayWs ? chatGatewayWs.readyState : null,
      gatewayUrlConfigured: !!gwUrl,
      gatewayUrlPrefix: gwUrl ? gwUrl.substring(0, 20) + '...' : null,
      // Phase 1: native gateway client
      nativeClient: {
        ready: gatewayClient.isReady,
        wsState: gatewayClient.ws ? gatewayClient.ws.readyState : null,
      },
      timestamp: new Date().toISOString()
    });
  });

  return router;
};

'use strict';

/**
 * routes/health.js — /api/health, /api/gateway-status, /api/dashboard
 *
 * @param {object} deps
 * @param {object}   deps.gatewayClient   — native gateway client instance
 * @param {Function} deps.getChatState    — () => { authenticated, ws } for the legacy proxy
 * @param {object}   [deps.db]            — lib/db.js instance (required for /api/health structured checks)
 * @returns {import('express').Router}
 */
const { Router } = require('express');
const { runHealthCheck } = require('../lib/health');

module.exports = function healthRouter({ gatewayClient, getChatState, db }) {
  const router = Router();

  // GET /api/health — structured health check
  router.get('/health', async (req, res) => {
    try {
      const health = await runHealthCheck({ db, gatewayClient });
      const httpStatus = health.status === 'down' ? 503 : 200;
      res.status(httpStatus).json({
        ...health,
        timestamp: new Date().toISOString(),
      });
    } catch (err) {
      res.status(503).json({
        status: 'down',
        checks: {},
        uptime: Math.floor(process.uptime()),
        error: err.message,
        timestamp: new Date().toISOString(),
      });
    }
  });

  // GET /api/gateway-status — legacy gateway status (unchanged)
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

  // GET /api/dashboard — dashboard summary including health
  router.get('/dashboard', async (req, res) => {
    try {
      const health = await runHealthCheck({ db, gatewayClient });
      
      // Include scheduled task error count in top-level health for UI convenience
      const scheduledErrorCount = health.checks?.scheduled?.errorCount || 0;
      
      res.json({
        health: {
          ...health,
          scheduledErrorCount,
          timestamp: new Date().toISOString(),
        },
      });
    } catch (err) {
      res.status(503).json({ error: err.message });
    }
  });

  return router;
};

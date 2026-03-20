'use strict';

/**
 * lib/health.js — Structured health check logic
 *
 * Performs lightweight checks against:
 *   - Database (SQLite read test)
 *   - Gateway WebSocket connection (native client)
 *   - APNS signing key (key loaded, team ID configured)
 *
 * Returns a normalised health object:
 * {
 *   status:  'ok' | 'degraded' | 'down',
 *   checks: {
 *     db:      { status, message },
 *     gateway: { status, message, wsState },
 *     apns:    { status, message, configured },
 *   },
 *   uptime:   number,   // process.uptime() in seconds
 *   version:  string,   // package.json version
 * }
 *
 * No external dependencies — pure Node.js + project modules.
 */

const { version } = require('../package.json');

// ── Individual check helpers ──────────────────────────────────────────────────

/**
 * Check database connectivity via a lightweight read.
 * @param {object} db — lib/db.js instance
 */
async function checkDb(db) {
  try {
    if (!db) throw new Error('db not injected');
    // A simple 1-row read that works on both SQLite and PostgreSQL.
    await db.get('SELECT 1 AS ok');
    return { status: 'ok', message: 'read test passed' };
  } catch (err) {
    return { status: 'down', message: err.message };
  }
}

/**
 * Check gateway connectivity from the native GatewayClient singleton.
 * @param {object} gatewayClient — GatewayClient instance from lib/gateway-client.js
 */
function checkGateway(gatewayClient) {
  try {
    if (!gatewayClient) return { status: 'down', message: 'client not injected', wsState: null };

    const wsState = gatewayClient.ws ? gatewayClient.ws.readyState : null;
    const ready   = gatewayClient.isReady;

    // WebSocket readyState codes: 0=CONNECTING, 1=OPEN, 2=CLOSING, 3=CLOSED
    const stateLabel = wsState === null  ? 'absent'
                     : wsState === 0     ? 'connecting'
                     : wsState === 1     ? 'open'
                     : wsState === 2     ? 'closing'
                     :                    'closed';

    if (ready) {
      return { status: 'ok', message: 'authenticated and open', wsState: stateLabel };
    }
    if (wsState === 0) {
      return { status: 'degraded', message: 'connecting', wsState: stateLabel };
    }
    return { status: 'degraded', message: 'not connected', wsState: stateLabel };
  } catch (err) {
    return { status: 'down', message: err.message, wsState: null };
  }
}

/**
 * Check APNS configuration.
 * We don't attempt a live handshake — just verify the key is loadable and
 * TEAM_ID is configured (sufficient to indicate "push is armed").
 */
function checkApns() {
  try {
    const apns = require('./apns');
    const teamId = process.env.APNS_TEAM_ID;

    if (!teamId) {
      return { status: 'degraded', message: 'APNS_TEAM_ID not set — push disabled', configured: false };
    }

    const key = apns.loadSigningKey();
    if (!key) {
      return { status: 'degraded', message: 'signing key unavailable', configured: false };
    }

    return { status: 'ok', message: 'key loaded, team ID configured', configured: true };
  } catch (err) {
    return { status: 'degraded', message: err.message, configured: false };
  }
}

// ── Aggregate health check ────────────────────────────────────────────────────

/**
 * Check scheduled tasks for errors.
 * @param {object} db — lib/db.js instance
 */
async function checkScheduledTasks(db) {
  try {
    if (!db) throw new Error('db not injected');
    
    // Query for enabled tasks with error status
    const errorTasks = await db.query(
      `SELECT id, name, last_status, last_outcome, last_run_at 
       FROM scheduled_tasks 
       WHERE enabled = ${db.isProduction ? 'true' : '1'} 
         AND last_status = 'error'
       ORDER BY last_run_at DESC 
       LIMIT 5`
    ).catch(() => []);
    
    if (errorTasks.length > 0) {
      const taskNames = errorTasks.map(t => t.name).join(', ');
      return { 
        status: 'degraded', 
        message: `${errorTasks.length} scheduled task${errorTasks.length > 1 ? 's' : ''} failing: ${taskNames}`,
        errorCount: errorTasks.length,
      };
    }
    
    return { status: 'ok', message: 'all scheduled tasks healthy', errorCount: 0 };
  } catch (err) {
    // Gracefully handle missing table (scheduled tasks not yet implemented)
    return { status: 'ok', message: 'scheduled tasks not configured', errorCount: 0 };
  }
}

/**
 * Run all checks and return a structured health summary.
 *
 * @param {object} opts
 * @param {object} opts.db            — lib/db.js instance
 * @param {object} opts.gatewayClient — GatewayClient instance
 * @returns {Promise<object>} health summary
 */
async function runHealthCheck({ db, gatewayClient } = {}) {
  const [dbCheck, apnsCheck, scheduledCheck] = await Promise.all([
    checkDb(db),
    Promise.resolve(checkApns()),
    checkScheduledTasks(db),
  ]);
  const gatewayCheck = checkGateway(gatewayClient);

  const checks = {
    db:        dbCheck,
    gateway:   gatewayCheck,
    apns:      apnsCheck,
    scheduled: scheduledCheck,
  };

  // Aggregate status: any 'down' → 'down'; any 'degraded' → 'degraded'; else 'ok'
  const statuses = Object.values(checks).map(c => c.status);
  const overallStatus = statuses.includes('down')     ? 'down'
                      : statuses.includes('degraded') ? 'degraded'
                      :                                 'ok';

  return {
    status:  overallStatus,
    checks,
    uptime:  Math.floor(process.uptime()),
    version,
  };
}

module.exports = { runHealthCheck, checkDb, checkGateway, checkApns, checkScheduledTasks };

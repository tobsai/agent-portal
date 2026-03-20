'use strict';

/**
 * lib/signals.js — Shared signal insertion helper.
 *
 * Extracted from routes/work.js (NEXT-081) so that lib modules (webhook-delivery,
 * push) can emit signals without importing a route module — clean dependency
 * direction (lib → lib, never lib → routes).
 */

/** @type {string[]} */
const VALID_SIGNAL_LEVELS = ['info', 'success', 'warning', 'error', 'progress'];

/**
 * @typedef {object} SignalInput
 * @property {string|null} [task_id]
 * @property {string|null} [initiative_id]
 * @property {string|null} [agent_id]
 * @property {string|null} [session_key]
 * @property {string}      message
 * @property {string}      [level]       — info | success | warning | error | progress
 * @property {object|null} [metadata]
 */

/**
 * Insert a signal row and resolve task_label from session_key if present.
 * Returns the persisted row.
 *
 * @param {object}      db       — database client (query/run/get)
 * @param {Function}    uuidv4   — UUID v4 generator
 * @param {SignalInput} signal
 * @returns {Promise<object>}    — the inserted signal row
 */
async function insertSignal(db, uuidv4, signal) {
  const { task_id, initiative_id, agent_id, session_key, message, level, metadata } = signal;
  const sigLevel = VALID_SIGNAL_LEVELS.includes(level) ? level : 'info';
  const id = uuidv4();
  const metaStr = metadata ? JSON.stringify(metadata) : null;

  // Resolve task_label from session_key → work_tasks join (server-side)
  let taskLabel = null;
  if (session_key) {
    const taskRow = await db.get(
      'SELECT title FROM work_tasks WHERE session_key = $1 LIMIT 1',
      [session_key]
    );
    if (taskRow) taskLabel = taskRow.title;
  }

  await db.run(
    'INSERT INTO signals (id, task_id, initiative_id, agent_id, session_key, task_label, level, message, metadata) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)',
    [id, task_id || null, initiative_id || null, agent_id || null, session_key || null, taskLabel, sigLevel, message, metaStr]
  );

  return db.get('SELECT * FROM signals WHERE id = $1', [id]);
}

module.exports = { insertSignal, VALID_SIGNAL_LEVELS };

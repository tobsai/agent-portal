/**
 * lib/types.js — Shared type definitions (JSDoc shapes) for Agent Portal.
 *
 * No runtime exports — this file documents the data contracts used across
 * routes, services, and the gateway client. Import for JSDoc @type references.
 *
 * All timestamps are ISO 8601 strings (UTC).
 */

'use strict';

// ─── SubAgent / Session Tree ──────────────────────────────────────────────────

/**
 * @typedef {object} AgentSignalSummary
 * @property {string} id          - Signal row ID
 * @property {string} level       - 'info' | 'success' | 'warning' | 'error' | 'progress'
 * @property {string} message     - Signal message text
 * @property {string} createdAt   - ISO timestamp
 */

/**
 * @typedef {'active' | 'done' | 'complete' | 'error' | 'cancelled' | 'unknown'} AgentStatus
 */

/**
 * A node in the sub-agent spawn tree returned by GET /api/subagents.
 *
 * @typedef {object} AgentNode
 * @property {string}             id           - Session key (e.g. 'agent:main:subagent:uuid')
 * @property {string}             label        - Human-readable label or truncated session key
 * @property {AgentStatus}        status       - Current lifecycle status
 * @property {string|null}        model        - Model identifier (e.g. 'anthropic/claude-sonnet-4-6')
 * @property {string|null}        startedAt    - ISO timestamp of first signal
 * @property {string|null}        endedAt      - ISO timestamp of last signal (if finished)
 * @property {number|null}        runtime      - Elapsed seconds (null if no startedAt)
 * @property {number|null}        tokenCount   - Total tokens consumed (if reported via signal)
 * @property {string|null}        parentId     - Parent session key (null for root nodes)
 * @property {number}             depth        - Nesting depth (0 = root)
 * @property {AgentSignalSummary[]} signals    - Recent signals (up to 8 shown in UI)
 * @property {AgentNode[]}        children     - Child nodes (sub-agents spawned by this agent)
 * @property {number}             [_signalCount] - Total signal count (internal, for display)
 * @property {boolean}            [_hasErrors]   - True if any error-level signals exist
 */

/**
 * Response shape for GET /api/subagents.
 *
 * @typedef {object} SubagentTreeResponse
 * @property {AgentNode[]} tree         - Root nodes of the spawn hierarchy
 * @property {number}      total        - Total node count across all depths
 * @property {string}      generatedAt  - ISO timestamp of when the tree was built
 */

// ─── Signals ──────────────────────────────────────────────────────────────────

/**
 * Signal metadata shape for sub-agent lifecycle events.
 * POST to /api/signals with this structure in the `metadata` field.
 *
 * @typedef {object} SubagentSignalMetadata
 * @property {'spawn'|'subagent_start'|'subagent_end'|'subagent_error'|'done'|'complete'|'error'} type
 * @property {string}       [label]          - Human-readable agent label
 * @property {string}       [model]          - Model identifier
 * @property {AgentStatus}  [status]         - Explicit status override
 * @property {number}       [tokenCount]     - Token count at time of signal
 * @property {string}       [parent_session] - Parent session key (for tree edges)
 * @property {string}       [parentSession]  - Alias for parent_session
 * @property {string}       [spawner]        - Alias for parent_session
 */

// ─── Work Tracking (MT-180) ───────────────────────────────────────────────────

/**
 * @typedef {'p1'|'p2'|'p3'|'p4'} Priority
 */

/**
 * @typedef {'active'|'blocked'|'done'|'cancelled'} InitiativeStatus
 */

/**
 * @typedef {'todo'|'in_progress'|'done'|'blocked'|'cancelled'} TaskStatus
 */

/**
 * @typedef {object} WorkInitiative
 * @property {string}           id          - UUID
 * @property {string}           title
 * @property {string|null}      description
 * @property {Priority}         priority
 * @property {InitiativeStatus} status
 * @property {string}           createdAt
 * @property {string}           updatedAt
 */

/**
 * @typedef {object} WorkTask
 * @property {string}      id
 * @property {string}      initiativeId
 * @property {string}      title
 * @property {string|null} description
 * @property {TaskStatus}  status
 * @property {string}      createdAt
 * @property {string}      updatedAt
 */

// Export nothing — this file is for JSDoc @type references only.
module.exports = {};

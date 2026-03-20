# TECH_DEBT.md — Agent Portal

Track shortcuts and deferred architectural work here. Do not build on top of them.

---

## [NEXT-086] Sub-agent tree is signal-derived, not session-native

**File:** `routes/agents.js` — `GET /api/subagents`
**Added:** 2026-03-20

The spawn tree is reconstructed by scanning the `signals` table for rows whose
`metadata` column encodes `session_key`, parent relationships, and status
transitions. This is a workaround because the OpenClaw Gateway does not yet
expose a `sessions.list` API.

The `POST /api/subagents` registration endpoint (NEXT-086) improves this by
writing a `type: "registered"` signal at spawn time, giving the tree a foothold
even for fast sub-agents. It does not change the underlying data model.

**Migration path:** When the Gateway exposes `sessions.list`, replace the entire
signals-scan loop in `GET /api/subagents` with a single `gatewayClient._request`
call and map the response to `AgentNode` shape. The `registered` status should
then come from the Gateway session state, not a synthetic signal. See the inline
`NOTE:` comment at the top of the route for the full context.

---

## Signal ordering in tree builder assumes chronological signal arrival

**File:** `routes/agents.js` — signal processing loop
**Added:** 2026-03-20

Signals are fetched `ORDER BY created_at ASC` (after the DESC→ASC fix made in
NEXT-086), but the in-memory loop applies status updates in iteration order.
If two signals for the same session arrive out-of-wall-clock-order (e.g., a late
retry inserts a `registered` signal after a `done` signal), the terminal-status
guard (`TERMINAL_STATUSES` set) prevents regression, but the `startedAt` timing
could still be wrong.

**Correct fix:** After collecting all signals into nodes, derive `startedAt` from
`MIN(created_at)` across signals, not from the first-seen signal. This would
require a second aggregation pass or a DB-level `GROUP BY session_key` query.
Deferred because signal ordering is reliable in practice (Gateway emits in order)
and the impact is cosmetic (displayed timing only).

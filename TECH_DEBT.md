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

## [NEXT-087] Inline failure detail falls back silently when id match fails

**File:** `public/work.html` — `rowsEl.innerHTML` map
**Added:** 2026-03-20
**Fixed:** NEXT-087 (source convergence pass)

Prior to NEXT-087, the subagent row detail mixed `agent.*` (from the tree node)
and `failureDetail.*` (from `_currentFailures`) — `startedAt`/`endedAt`/`runtime`
came from `agent.*` while `lastMessage` came from `failureDetail`. This meant
timing data could be rendered even when `lastMessage` was unavailable, producing
the silent `(No error message available)` fallback.

**Fix:** The detail section now derives all fields exclusively from `failureDetail`
(server-shaped from `data.failures.items`). A row is only rendered as `expandable`
when `failureDetail !== null`. The `runtime` inline variable from the outer scope
was retained only for the metric chip (not the drill-down), which avoids a second
lookup but is a cosmetic duplication worth noting.

**Residual shortcut:** `runtime` for the metric chip still comes from `agent.runtime`
(tree node), which is computed independently from `failureDetail.runtime`. They
should be the same value, but they traverse different code paths. If they diverge,
the chip and the detail panel would show different durations. Acceptable risk
until the tree builder is replaced with a Gateway session API (see NEXT-086 debt).

---

## [NEXT-087] Accordion behavior split between two surfaces

**File:** `public/work.html` — `toggleSubagentRow` / `toggleFailureRow`
**Added:** 2026-03-20
**Fixed:** NEXT-087

The metrics panel used accordion (NEXT-056); the subagent row list used
independent multi-expand (NEXT-071). Unified in NEXT-087 to per-section
accordion. The two toggle functions remain separate because they operate on
different DOM structures (`.sa-failure-item` vs `.subagent-row.expandable`).
A further pass could extract a single `accordionToggle(el, containerSelector,
itemSelector)` utility, but the current duplication is minor.

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

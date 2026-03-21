# TECH_DEBT.md — Agent Portal

---

## [NEXT-088] Signal count `_dbTotal` not updated on live WebSocket push

**File:** `public/work.html` — `renderSignal` / `_updateSignalsFooter`
**Added:** 2026-03-20

When a live signal arrives over WebSocket, `renderSignal(sig, true)` inserts it
into `_allSignals` but does not update `_dbTotal`. The footer therefore shows the
DB total from the last `fetchSignals()` HTTP call, not the current DB state.

In practice the drift is minor: `fetchSignals()` is triggered on every level
filter change, and `_dbTotal` from the last poll is always within one signal of
truth for a live panel. The next full fetch (reconnect, filter toggle, page load)
will correct it.

**Correct fix:** Increment `_dbTotal` atomically when a new signal is pushed via
WebSocket, and handle the case where `_dbTotal` was zero (first signal ever).
This removes the one-off drift without adding another round-trip.

**Deferred because:** The window is always sub-second and the copy "Showing newest
N of M" is a floor, never an overcount.

---

Track shortcuts and deferred architectural work here. Do not build on top of them.

---

## [NEXT-088 routing] GET /api/activity 410 wiring ✅

**Files:** `routes/activity.js`, `server.js`
**Added:** 2026-03-21
**Resolved:** 2026-03-21 (NEXT-103)

Concern: after NEXT-088 deprecated `/api/activity`, it was unclear whether the
410 was properly wired or whether any internal callers (work.html, lib modules,
other routes) still called the old path.

**Confirmed by NEXT-103 audit:**
- `routes/activity.js` returns HTTP 410 Gone with `{ error, message, replacement }`.
  Auth middleware fires first — unauthenticated callers get 401, not 410, which
  preserves the auth contract and avoids leaking endpoint existence to scanners.
- No public assets (work.html or any HTML/JS file under `public/`) reference
  `/api/activity` — grep of the entire public directory returns zero matches.
- No route or lib module calls `/api/activity` internally.
- All four deprecation tests in `tests/activity.test.js` pass (401, 410, body
  shape, replacement field).

No code changes required. Concern closed.

---

## [NEXT-094 routing] insertSignal() as single signal write path ✅

**Files:** `lib/signals.js`, `routes/work.js`, `lib/webhook-delivery.js`, `lib/push.js`
**Added:** 2026-03-21
**Resolved:** 2026-03-21 (NEXT-103)

Concern: after NEXT-094 extracted `insertSignal()` into `lib/signals.js`, it was
unconfirmed whether all signal insert call sites had been consolidated or whether
any raw `INSERT INTO signals` SQL still existed outside the helper.

**Confirmed by NEXT-103 audit:**
- Zero raw `INSERT INTO signals` SQL exists outside `lib/signals.js`.
- All six call sites use `insertSignal()` from `lib/signals.js`:
    1. `routes/work.js`  POST /api/signals
    2. `routes/work.js`  POST /api/work { type: 'signal' }
    3. `routes/work.js`  POST /api/subagents
    4. `routes/work.js`  POST /api/status (auto-expire, best-effort)
    5. `lib/webhook-delivery.js`  deliverInboundWebhook() (best-effort)
    6. `lib/push.js`     pushToAllDevices() (best-effort)
- Routing map documented as inline JSDoc comment in `routes/work.js` (NEXT-103).

No code changes required. Concern closed.

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

## Signal ordering in tree builder assumes chronological signal arrival ✅

**File:** `routes/agents.js` — signal processing loop
**Added:** 2026-03-20
**Resolved:** 2026-03-21 (NEXT-102)

Signals are fetched `ORDER BY created_at ASC` (after the DESC→ASC fix made in
NEXT-086), but the in-memory loop applies status updates in iteration order.
If two signals for the same session arrive out-of-wall-clock-order (e.g., a late
retry inserts a `registered` signal after a `done` signal), the terminal-status
guard (`TERMINAL_STATUSES` set) prevents regression, but the `startedAt` timing
could still be wrong.

**Fix applied:** Added a second aggregation pass after all signals are collected.
For each node, `startedAt` is now set to `MIN(sig.createdAt)` across all signals
in `node.signals[]`, ensuring correctness regardless of insertion order.
cosmetic (displayed timing only).

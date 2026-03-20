# CREATIVE_PASS_APR.md — Agent Portal Dashboard Creative Pass (Next Wave)

**Date:** 2026-03-20
**Author:** Marty (product / creative)
**Scope:** `public/work.html`, `public/work.css`, `routes/work.js`, `routes/scheduled.js`, `routes/activity.js`
**Predecessor:** `CREATIVE_PASS_MAR_27.md` (all four gaps now shipped)

---

## 1. UX Gaps — Signals / Tasks Interaction Model

All four March gaps shipped, but the panel now surfaces a new set of coherence issues.

### 1a. The "Digest" button label is backwards — always

**File:** `work.html:131` (signals header), `work.html:207–210` (`_updateSignalsModeBtn`)

When the user is in **All** mode, the button reads `All` — meaning clicking it will switch to Digest.  
When the user is in **Digest** mode, the button reads `Digest` — meaning clicking it will switch to All.

The button is labelled with the *current* state, not the *action*. Standard affordance: a toggle button describes what happens on click, not the current state. A user in Digest mode reading `Digest` on the button will reasonably assume clicking it will *do digest again*, not exit digest.

**Fix (5 min):** Either (a) label by target state (`Switch to Digest` / `Switch to All`), or (b) treat it as an explicit toggle with an icon (`≡ Digest` with an active/inactive class).

---

### 1b. Signal count badge reflects in-memory buffer, not actual DB count

**File:** `work.html:318–321` (`_updateSignalsFooter`)

The footer reads `N signals — refreshes live`. `N` is `_allSignals.length`, capped at `MAX_SIGNALS`. If the DB has 3,000 signals and the buffer is capped at 100, the footer says `100 signals`. That reads as "only 100 signals exist" to the user, when it means "showing the newest 100 of many more."

**Fix (10 min):** Change copy to `Showing newest 100 — refreshes live` (or pass the `total` field from `GET /api/signals` response and render it).

---

### 1c. Signal task pills only appear when `session_key` matches a `work_tasks` row

**File:** `routes/work.js:243–248` (POST /api/signals), `routes/work.js:196–203` (GET /api/signals JOIN)

Signals that don't originate from a registered task (e.g. heartbeat pings, ad-hoc cron output) always render without a task pill. This is architecturally correct but creates a visual divide: some signals have context labels, some don't. The blank ones look like they're missing data.

**Gap:** There's no fallback label for "system" or "heartbeat" signals — the pill slot stays empty.

**Fix (15 min):** For signals where `task_label` is null but `session_key` is not null, render the session key prefix as a muted fallback pill (`agent:main:cron:…`). Already extracted in `_signalTaskPill` — add a fallback branch:
```js
if (!sig.task_label && sig.session_key) {
  return `<span class="signal-task-pill muted">${escHtml(sig.session_key.slice(0, 20))}…</span>`;
}
```

---

### 1d. Signals panel has no acknowledgment / clear mechanism

**File:** `work.html:130–135` (signals header area)

Post-NEXT-060, digest mode exists but there's no way to mark signals as seen, clear noise, or filter to a specific task or session. After a busy heartbeat cycle the panel fills with low-level `info` / `progress` signals that obscure `error` / `warning` entries.

**Observation (not proposing an immediate ticket):** The signals panel needs either (a) a "clear viewed" sweep, (b) a level filter in the header (matching the existing `/api/signals?level=` query param already supported server-side), or (c) auto-fade for `info`/`progress` signals after 60s. Option (b) is trivially wired — the API param exists; the UI just doesn't expose it.

---

### 1e. Two failure drill-down surfaces, inconsistent behavior

**File:** `work.html:715–740` (failures panel from metrics row click) vs. `work.html:795–810` (inline expansion in the recent sub-agent list)

The metrics panel failure drill-down (NEXT-056) uses **accordion** expand (one open at a time). The inline row expansion on the recent-agents list (NEXT-071) uses **independent** expand (multiple may be open simultaneously). Different affordances, same UI surface, no visual hint explaining why.

Also: the failures panel is populated from `data.failures` (server-shaped), while the inline expansion re-queries `_currentFailures` by `agent.id`. If a failure item appears in the recent list but its `id` doesn't match anything in `_currentFailures`, the inline detail renders `(No error message available)` even though the panel would show the message. The two sources need to converge.

**Fix (20 min):** Standardise on accordion for both, or add visual differentiation. For the ID-match issue, ensure the subagent list and failures list both derive from the same server response object.

---

## 2. Scheduled Task `last_outcome` Population

### Current State

`last_outcome` is a `TEXT` column in `scheduled_tasks` (defined `lib/db.js:308`). The `GET /api/scheduled` route correctly exposes it as `lastOutcome` (`routes/scheduled.js:35`). The UI renders it in `scheduled-card-outcome` when non-null (`work.html:882`).

**Problem:** `last_outcome` is never written. The `POST /api/scheduled` route (`routes/scheduled.js:51–91`) only accepts `name`, `schedule`, `schedule_human`, `enabled`, `next_run_at`. There is no `PATCH /api/scheduled/:id` or `POST /api/scheduled/:id/run-result` endpoint that writes `last_outcome`, `last_run_at`, or `last_status`.

The two `TODO(lewis)` comments flag this:
- `routes/scheduled.js:59` — "post outcome string to /api/status after cron completion"
- `routes/work.js:46` — same
- `work.html:872` — same

The intent was to have the cron process POST an outcome string after each run, but that API endpoint **does not exist**. `POST /api/status` only accepts `thinking | idle` status and a task description; it has no outcome field.

### UX Dead-End Assessment

**Yes, today it is a dead-end.** Every scheduled card shows either:
- Nothing in the outcome slot (most common)
- `Last run failed` as a static fallback when `last_status === 'error'`

The `last_status` and `last_run_at` fields are also never written (the `POST /api/scheduled` upsert does not touch them). So the error filter tab (`scheduledFilter === 'errors'`) will always be empty — there are no rows with `last_status === 'error'` because nothing sets it.

### What Would Fix It

**Server:** Add `PATCH /api/scheduled/:id` (agent-key auth) accepting:
```json
{
  "last_run_at": "<ISO>",
  "last_status": "ok | error",
  "last_outcome": "Checked 3 items, 0 errors",
  "next_run_at": "<ISO>"
}
```
This is a natural post-cron callback. The heartbeat that currently does `POST /api/scheduled` (registration) would do a second call after task completion.

**Client:** No change needed; the rendering code already handles `lastOutcome` and the status dot classes (`ok`, `error`, `none`) correctly.

**Complexity:** ~30 min server-side. The UX scaffolding is already wired; only the write path is missing.

---

## 3. Observability Blind Spots

### 3a. Agent health is entirely in-memory — lost on restart

**File:** `routes/work.js:130` (`let agentHealthStatus = {}`)

`agentHealthStatus` is a plain in-memory object. On any Railway redeploy or process crash, all health data is gone. The staleness indicator (NEXT-061) then shows nothing at all until the next agent heartbeat, which is typically 5 minutes. Lewis gets a false "no data" reading post-deploy.

**Mitigation needed:** Persist health rows to DB on POST, read from DB on GET when in-memory is empty (same pattern already used for `agentThinkingStatus` after NEXT-059 — `routes/work.js:62–85`).

---

### 3b. Webhook delivery failures are silently swallowed

**File:** `server.js:75–100` (`deliverWebhook`)

Webhook errors are caught and logged only to `console.error`. No signal is emitted to the portal, no Sentry event is captured, and the error count has no surface in the UI. If the webhook endpoint goes down, Lewis won't know until he reads server logs — which he cannot do in production.

**Fix:** On delivery failure, capture to Sentry (already initialized in `server.js:6–11`) and/or emit a `level: 'warning'` signal to the signals panel with a message like `Webhook delivery failed: <url prefix>`.

---

### 3c. Push notification failures are also silent

**File:** `server.js:113–118` (`sendAgentMessage`)

Push errors are caught with `console.error` only. Same pattern as webhooks — no visibility in the dashboard.

---

### 3d. Sub-agent tree only shows agents that posted signals

**File:** `docs/SUBAGENT_API_GAP.md` (documented)

This is already documented, but worth restating in operational terms: any sub-agent that completes in under ~5 seconds before its first signal POST will never appear in the Work dashboard tree. Short, successful sub-agents are invisible. Short, failed sub-agents may also be invisible if they errored before emitting a signal.

**Current gap:** There is no "fast sub-agent never checked in" alert. Lewis cannot distinguish between "no sub-agents ran" and "sub-agents ran too fast to signal."

---

### 3e. `POST /api/work` (combined endpoint) and `POST /api/signals` are functionally duplicated

**File:** `routes/work.js:272–346` (POST /api/work) vs. `routes/work.js:225–267` (POST /api/signals)

The signal insertion logic is copy-pasted verbatim in both handlers — including the `task_label` resolution query and the `broadcast` call. If one is patched (e.g. to add outcome tracking or signal deduplication), the other will diverge. This has already happened: the `task_label` resolution was added to `POST /api/signals` first and later copy-pasted into `POST /api/work`.

**Fix:** Extract a `insertSignal(db, broadcast, req.agent, fields)` helper in `routes/work.js` and call it from both routes. ~20 min refactor.

---

### 3f. `GET /api/activity` is a dead alias for `GET /api/signals`

**File:** `routes/activity.js`

`GET /api/activity` is a `SELECT * FROM signals ORDER BY created_at DESC` with a limit. It returns a different shape (`{ activity: rows }` vs. `{ signals: rows, total: rows.length }`), skips the JOIN with `work_tasks`, and lacks all query filters (`task_id`, `initiative_id`, `level`). Nothing in `work.html` calls it. It appears to be a legacy endpoint that was superseded when `GET /api/signals` was upgraded.

**Recommendation:** Either deprecate and remove, or align it with `GET /api/signals` (including the JOIN) and document which surface should call which.

---

### 3g. Status auto-expire timer is not logged to signals

**File:** `routes/work.js:58–74` (expire timer callback)

When the 5-minute thinking auto-expire fires, it logs to `console.log` only. The transition to `idle` is broadcast over WebSocket but not written as a signal. If Lewis is reviewing the signals panel after a long run, he has no record that the status was auto-expired (vs. the agent explicitly going idle).

**Fix (5 min):** On auto-expire, insert a `level: 'warning'` signal: `"Agent thinking status auto-expired (no idle confirmation received after 5m)"`. This creates an audit trail and makes silent timeouts visible.

---

## 4. Quick Wins (≤30 min each)

| # | Description | File / Line | Estimate |
|---|-------------|-------------|----------|
| QW-1 | Fix Digest button label (describes current state, not action) | `work.html:207–210` | 5 min |
| QW-2 | Signals footer: "Showing newest N" instead of false total | `work.html:318–321` | 5 min |
| QW-3 | Expose level filter in signals header (API param already exists) | `work.html:130`, `routes/work.js:180` | 15 min |
| QW-4 | Auto-expire signal: emit warning-level signal on status expire | `routes/work.js:58–74` | 5 min |
| QW-5 | Extract `insertSignal()` helper to eliminate POST duplication | `routes/work.js:225–346` | 20 min |
| QW-6 | Add `PATCH /api/scheduled/:id` for outcome write-back | `routes/scheduled.js` | 30 min |
| QW-7 | Session-key fallback pill in `_signalTaskPill` for unregistered signals | `work.html:215–220` | 10 min |

---

## Standing Observations (Architectural)

- **`agentHealthStatus` is process-local with no persistence.** Follows the pre-NEXT-059 pattern for `agentThinkingStatus`. Should be elevated to DB-backed before the next hardening pass — same TTL/rehydration logic already exists in `routes/work.js:73–86`.
- **`GET /api/activity` vs `GET /api/signals` drift.** Two endpoints for the same data with diverging field shapes. One should own the contract; the other should be removed or redirected.
- **Duplicate signal insert logic is active tech debt.** `routes/work.js` has two nearly-identical 30-line blocks. Each bug fix or enhancement requires a dual patch.
- **No `PATCH` route for scheduled tasks.** The DB schema supports `last_status`, `last_run_at`, `last_outcome` but no agent can write to them. The error filter tab is therefore permanently empty and the outcome slot is always blank. The UX scaffolding is sound; the write path is the only missing piece.

---

*End of creative pass. Four tickets from MAR_27 shipped cleanly — the panel is materially better. The above represents the next natural wave, not regressions.*

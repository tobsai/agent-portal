# NEXT-056: Agent Portal Creative Pass — Dashboard Discovery
**Date:** 2026-03-19 (first pass) / 2026-03-20 (second pass)
**Author:** Marty (sub-agent, Product Owner)
**Status:** ✅ Two quick wins implemented + findings documented

---

## What Was Audited

- `public/work.html` — the main dashboard (Work Tracking view)
- `routes/activity.js` — `/api/activity` (signals feed)
- `routes/scheduled.js` — `/api/scheduled` (scheduled tasks list)
- `routes/agents.js` — `/api/subagents` (sub-agent tree + metrics)
- `routes/health.js` — `/api/dashboard`, `/api/gateway-status`
- `routes/work.js` — `/api/status`, `/api/agent-health`, `/api/signals`, `/api/work`

---

## Implemented: #1 — Scheduled Tasks Widget (Mar 19)

**Gap:** `/api/scheduled` returns tasks with name, schedule, last_status, last_outcome, next/last run timestamps — none visible on dashboard.

**What was built:** Card grid on `work.html` above the sub-agent widget, full-width. Tabs for Active / Errors / All. Status dots, outcome snippets, relative next/last run timestamps, error count badge in title. Auto-refreshes every 60s. Errors sort to top.

**Files changed:** `public/work.html` (~297 lines CSS + HTML + JS)

---

## Implemented: #2 — Current Work Status Banner (Mar 20)

**Gap:** `/api/status` returns `{status, task, timestamp}` and the server already broadcasts `agent:status` via WebSocket. A working Lewis emits this on every heartbeat. Zero dashboard surface — the only consumer was the nav connection dot.

**What was built:** A banner element (`#status-banner`) rendered full-width above the stats area. When `status === 'thinking'` or `'working'`:
- Banner becomes visible (CSS class toggle, no inline style)
- Shows pulsing indigo dot + "WORKING" label + task description + elapsed time ticker
- Elapsed time counts up from the signal's server `timestamp` via a 1-second `setInterval`
- Hidden automatically when status returns to `'idle'`

**Data sources (both wired):**
- WebSocket: `agent:status` events update instantly
- HTTP poll: `loadAgentStatus()` calls `/api/status` every 30s as fallback for missed WS events

**Architectural standard met:**
- No inline styles — all appearance controlled via `.status-banner` / `.status-banner.visible` CSS classes
- No hardcoded data — task text comes entirely from server
- No new npm deps
- Follows existing WS event handler pattern

**Files changed:** `public/work.html` (CSS block ~55 lines, HTML ~7 lines, JS ~55 lines)

---

## Remaining Gaps (Not Yet Implemented)

### 3. Live Signal Outcome Annotations
**Current state:** Signal panel shows raw log lines. When a scheduled task or sub-agent completes, the outcome is buried in signal text with no visual tie to the triggering task.
**Proposed fix:** When a signal's `session_key` matches a known scheduled task or sub-agent label (already fetched in the SA widget), annotate it inline with the task name. Purely frontend — match signal metadata against cached data.
**Estimated effort:** 2–3h (client-side only, no route changes)

### 4. Digest Mode for the Signals Panel
**Current state:** A single sub-agent run can generate 40+ signals that flood the view and bury meaningful events. No grouping or collapsing.
**Proposed fix:** A "digest" toggle on the signals panel collapses rows by `session_key`, showing 1 entry per session with the highest-severity signal and a count badge. Expand on click.
**Estimated effort:** 3–4h (client-side grouping logic, expand/collapse UX)

### 5. Subagent Failure Drill-Down Click Handler
**Current state:** The sub-agent metrics widget shows "N failures" with no interaction. The `metrics.failures.items` array (labels + last messages) is already rendered in the DOM.
**Proposed fix:** Make the failure count clickable — navigate to `/subagents?filter=errors` or open an inline panel. Data is already present, zero API changes needed.
**Estimated effort:** 30–45 min

### 6. Agent Health Staleness Indicator (new gap found)
**Current state:** `/api/agent-health` returns `{ staleness: { reportStale, pollStale, minutesSinceReport, minutesSincePoll } }` — none of this is surfaced anywhere. If Lewis goes silent, the operator has no dashboard signal.
**Proposed fix:** A small badge or row in the health widget showing "Last heartbeat: Xm ago" + yellow/red coloring when stale. Maps directly to `minutesSinceReport` from the endpoint.
**Estimated effort:** 1–2h (needs a new `/api/agent-health` fetch + render block in the health card)

---

## Architectural Flags

1. **`/api/status` is ephemeral.** Posted by Lewis on each heartbeat, not persisted to DB. If process restarts, status resets to idle even if work was in flight. For reliability, persist to an `agent_status` table row.

2. **Scheduled tasks may have duplicate IDs.** Tasks re-registered on each heartbeat without deduplication. A unique constraint on `(name, schedule_kind, schedule_value)` would clean this up and prevent the count inflation visible in the UI.

3. **`/api/subagents` uses signals-only tree building.** Known workaround (see `docs/SUBAGENT_API_GAP.md`). When Gateway exposes native `sessions.list`, migrate the tree to that as authoritative source.

4. **`last_outcome` field is rarely populated.** Many scheduled tasks have `last_status: "ok"` but `last_outcome: null`. Lewis should post an outcome string on task completion — it's the most useful single field to surface in the UI.

5. **`work.html` CSS is inline, not in `style.css`.** The page-level stylesheet (`public/style.css`) targets the old kanban board layout and has no shared tokens with the newer indigo-themed pages. Work to unify these into a shared token layer is worth a dedicated ticket before the CSS grows further.

---

## What Should Wait for SPEC-CHAT-REFACTOR.md Approval

- Changes to the signals panel layout that touch channel/DM routing context
- A "conversation context" column showing what Toby last discussed per agent
- The "respond to agent" quick-reply field in the signals panel
- Any new action buttons that trigger agent behavior from the dashboard

# NEXT-056: Agent Portal Creative Pass — Dashboard Discovery
**Date:** 2026-03-19  
**Author:** Marty (sub-agent, Product Owner)  
**Status:** ✅ Quick win implemented + findings documented

---

## What Was Audited

- `public/work.html` — the main dashboard (Work Tracking view)
- `routes/activity.js` — `/api/activity` (signals feed)
- `routes/scheduled.js` — `/api/scheduled` (scheduled tasks list)
- `routes/agents.js` — `/api/subagents` (sub-agent tree + metrics)
- `routes/health.js` — `/api/dashboard`, `/api/gateway-status`

---

## Identified Gaps (3–5 High-Value Additions)

### 1. ✅ Scheduled Tasks Widget [IMPLEMENTED]
**Gap:** `/api/scheduled` returns 57 tasks with name, schedule, last_status, last_outcome, last_run_at, next_run_at — none of this is visible on the dashboard.  
**Signal value:** This is literally "what is the agent doing autonomously." Heartbeats, morning briefings, email triage, project momentum checks — Toby wants exactly this.  
**Implementation:** Card grid on `work.html` — tabs for Active / Errors / All, status dots (green/red/grey), outcome snippets, relative time for next/last run. Error count badge inline with title.

### 2. Live Signal Outcome Annotations [NOT YET IMPLEMENTED]
**Gap:** The right-hand signals panel shows raw log lines. When a scheduled task or sub-agent completes, the outcome is buried in signal text with no visual tie to the task that triggered it.  
**What to add:** When a signal contains a session_key that matches a known scheduled task or sub-agent, annotate it with the task name in the signal panel.  
**Complexity:** Low (purely frontend — match signal metadata against cached task list). No route changes needed.

### 3. Current Work Status Banner [NOT YET IMPLEMENTED]
**Gap:** `/api/status` returns `{ status: "idle"/"working", task: "...", timestamp }` — currently used only in the nav header connection dot. There's no prominent "Lewis is currently working on: [task]" surface on the dashboard.  
**What to add:** A sticky banner or top card under the page header showing the current task with elapsed time when status is not idle. Would instantly answer "what is Lewis doing right now."  
**Complexity:** Very low — the data is already fetched for the nav badge. Just render it more prominently when non-idle.

### 4. Recent Activity Feed with Deduplication [NOT YET IMPLEMENTED]
**Gap:** `/api/activity` returns up to 200 signals as a flat feed, which maps 1:1 with the existing signals panel. However, the existing panel has no grouping — a single sub-agent run can generate 40+ signals, which flood the view and bury meaningful events.  
**What to add:** A "digest mode" toggle on the signals panel that collapses runs by session_key, showing 1 collapsed row per session with the most significant signal (highest level or last message). Expand on click.  
**Complexity:** Medium — needs client-side grouping logic. No API changes required.

### 5. Subagent Metrics on Error Drill-Down [NOT YET IMPLEMENTED]
**Gap:** The sub-agent widget shows "N failures" but clicking it does nothing. The `/api/subagents` `metrics.failures.items` array already contains labels + last messages for the 5 most recent failures.  
**What to add:** Make the failure count in the SA metrics widget clickable — open an inline panel or jump to `/subagents?filter=errors`. Near-zero effort since the data is already in the DOM.  
**Complexity:** Very low — one `onclick` handler, no API changes.

---

## What Was Implemented: #1 — Scheduled Tasks Widget

**Why this one:**  
It fills the biggest visibility gap with the clearest, most direct signal for Toby: it answers "what is the agent doing on schedule" without any inference or drill-down. The `/api/scheduled` endpoint is populated, stable, and returns exactly the fields needed for a good card view. No architectural risk, no new routes, no dependencies.

**What it shows:**
- Card grid: one card per task, filterable by Active / Errors / All
- Each card: task name, human-readable schedule, last outcome snippet, relative time for next + last run, status dot (green/red/grey)
- Error count badge inline in the widget title (e.g., "3 errors")
- Auto-refreshes every 60 seconds
- Errors sort to the top

**Location:** Above the sub-agent widget on `work.html`, spanning full width of the layout grid.

**Commit:** `feat: agent portal dashboard quick win — scheduled tasks widget on work.html` (`acd7bc5`)

---

## What Should Wait for SPEC-CHAT-REFACTOR.md Approval

- Any changes to the signals panel layout that touch channel/DM routing context
- A "conversation context" column showing what Toby last discussed per agent
- The "respond to agent" quick-reply field in the signals panel
- Any new action buttons that trigger agent behavior from the dashboard

---

## Architectural Flags

1. **`/api/status` is ephemeral.** The current task status (`{ status, task, timestamp }`) is posted by Lewis on each heartbeat but is not persisted to the DB — if the process restarts, status resets to idle even if work was in flight. For the "current work banner" to be reliable, the status should be persisted to a `agent_status` table row.

2. **Scheduled tasks have duplicate IDs.** The `/api/scheduled` response contains duplicate task names (e.g., "Image Certification Batch" appears twice with different UUIDs). This suggests tasks are being re-registered on each heartbeat without deduplication. A unique constraint on `(name, schedule_kind, schedule_value)` would clean this up.

3. **`/api/subagents` uses signals-only tree building.** This is a known workaround (see `docs/SUBAGENT_API_GAP.md`). If/when the OpenClaw Gateway exposes a native `sessions.list` API, the sub-agent tree should migrate to that as the authoritative source.

4. **`last_outcome` field is rarely populated.** Many scheduled tasks have `last_status: "ok"` but `last_outcome: null`. Lewis should be encouraged to post an outcome string on task completion — it's the single most useful thing to surface in the UI.

---

## Files Changed

- `public/work.html` — Scheduled tasks widget (CSS + HTML + JS, ~297 lines)
- `docs/CREATIVE_PASS_MAR_27.md` — This file
- `memory/agent-status.md` — Status block appended

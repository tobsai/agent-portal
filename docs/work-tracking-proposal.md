# MT-180: Work Tracking View — Proposal

**Author:** Marty (Product Owner, Agent Portal)  
**Date:** 2026-03-16  
**Status:** Draft — awaiting review before implementation

---

## Executive Summary

Agent Portal needs a work-tracking view that's purpose-built for agent orchestration — not generic task management or kanban. The model is **Initiatives → Tasks → Signals**: a three-tier hierarchy that mirrors how agents actually work, from long-horizon goals down to atomic observable events.

This is not Linear. It is not ProductBoard. It borrows structure from each but is adapted for the reality that the primary "workers" are AI agents, not humans.

---

## Inspiration Analysis

### What ProductPlan does well
- **Roadmap swimlanes** by initiative — visual, time-oriented, easy to scan
- **Portfolio view** — see all initiatives ranked by strategic weight
- **Initiative → item drill-down** — click a bar on the roadmap to see constituent work
- **Status badges** — simple In Progress / Complete / At Risk

### What ProductBoard does well
- **Intake → Prioritize → Build** funnel — work flows through stages
- **Feature cards** with rich metadata (impact score, effort, status, owner)
- **Insights panel** — customer signals linked to features (this maps to our Signals)
- **Objective linking** — every feature traces to a company objective

### What Linear does well
- **Speed and keyboard-first** — no friction to create an issue
- **Cycles** — sprint-like containers that autopurge completed work
- **Triage inbox** — raw incoming items before assignment
- **Status machine** — Backlog → Todo → In Progress → Done → Cancelled
- **Sub-issues** — arbitrary depth but practically capped at 2 levels

### What none of them model
- **Agent-as-worker** — all assume humans do the work
- **Signals** — atomic events emitted by agents (tool calls, decisions, completions)
- **Session lineage** — a Task spawned sub-agents; those sub-agents spawned more; you want the tree
- **Heartbeat cadence** — agents report health periodically; the view should surface that
- **Autonomous vs. requested** — some Tasks are initiated by agents proactively, some by humans; provenance matters

---

## Data Model

```
Initiative
├── id, title, description
├── status: draft | active | paused | complete | archived
├── owner: agent_id or user_id
├── target_date (optional)
├── priority: P1 | P2 | P3
└── Tasks[]

Task
├── id, title, description
├── initiative_id (nullable — Tasks can be orphaned/unassigned)
├── status: backlog | in-progress | blocked | done | cancelled
├── assigned_to: agent_id (primary executor)
├── requested_by: user_id | agent_id
├── session_key (the OpenClaw session that owns this task)
├── started_at, completed_at
├── parent_task_id (nullable — for sub-tasks)
└── Signals[]

Signal
├── id, task_id
├── type: tool_call | decision | message | error | spawn | complete | heartbeat
├── content (text or JSON)
├── agent_id
├── session_key
├── created_at
└── metadata (arbitrary JSON)
```

---

## Views

### 1. Roadmap View (inspired by ProductPlan)
**Purpose:** Strategic overview across all active Initiatives.

```
┌──────────────────────────────────────────────────────────────────────┐
│  🗺  Roadmap                           [Q1 2026] [Q2] [Q3]  [+ New] │
├──────────────────────────────────────────────────────────────────────┤
│                    Jan   Feb   Mar   Apr   May   Jun                 │
│  P1 Agent Portal  [══════════●────────────]                          │
│  P2 FamilyOS      [────────────────●══════════════════]              │
│  P3 InkSight      [──────────────────────────────────●]              │
│  P3 Find Detour   [─●]                                               │
└──────────────────────────────────────────────────────────────────────┘
```

- **Bars** represent Initiative duration (start → target_date)
- **●** marks current progress point based on Task completion ratio
- **Color** encodes status: blue=active, amber=at-risk, green=complete, grey=paused
- **Click a bar** → drill into Initiative detail (Task list)
- **Quarter toggle** → shift time window
- **+ New** → opens Initiative creation modal

---

### 2. Board View (inspired by Linear)
**Purpose:** Day-to-day task management with status flow.

```
┌───────────┐  ┌────────────┐  ┌────────────┐  ┌──────────┐
│  Backlog  │  │ In Progress│  │  Blocked   │  │   Done   │
│           │  │            │  │            │  │          │
│ [Task A]  │  │ [Task C]   │  │ [Task E]   │  │ [Task F] │
│  Lewis    │  │  Marty ●   │  │  Echo ⚠    │  │  Lewis ✓ │
│  P2       │  │  P1        │  │  P1        │  │  P2      │
│           │  │            │  │            │  │          │
│ [Task B]  │  │ [Task D]   │  │            │  │ [Task G] │
│  Pascal   │  │  Milton ●  │  │            │  │  Marty ✓ │
│  P3       │  │  P2        │  │            │  │  P1      │
└───────────┘  └────────────┘  └────────────┘  └──────────┘
```

- **Cards** show: title, assigned agent (with avatar), priority, age
- **●** = agent currently active on this task (live indicator)
- **⚠** = blocked (shows blocker reason on hover)
- **Drag** to move between columns (updates status)
- **Click card** → Task detail drawer (see below)
- **Filter bar**: by Initiative, Agent, Priority, Date range

---

### 3. Task Detail Drawer
**Purpose:** Full context on one task — work done, signals, sub-agent tree.

```
┌─────────────────────────────────────────────────────────────────────┐
│  ← Back to Board                                        [Edit] [⋮]  │
│                                                                      │
│  📋 MT-177: Refactor channel routing logic                           │
│  In Progress · Marty · P1 · Initiative: Agent Portal                │
│                                                                      │
│  ─────────────────── Sub-agent Tree ──────────────────────          │
│  └─ marty-portal-bugs (main)                                         │
│     ├─ Session: agent:main:subagent:4387... ✓ complete               │
│     └─ Session: agent:main:subagent:9ac2... ● in progress            │
│                                                                      │
│  ─────────────────── Signal Timeline ─────────────────────          │
│  21:14  📨 Task created by Lewis                                     │
│  21:14  🔧 tool_call: Read server.js (Marty)                         │
│  21:15  🔧 tool_call: Edit chat.html — renderChannelList (Marty)     │
│  21:16  🚀 spawn: subagent 4387f8c5 (Marty)                          │
│  21:18  ✅ complete: sub-task MT-179 (Marty)                          │
│  21:19  ✅ complete: sub-task MT-181 (Marty)                          │
│  21:19  ✅ complete: sub-task MT-182 (Marty)                          │
│  21:19  🔧 tool_call: git push origin main (Marty)                   │
└─────────────────────────────────────────────────────────────────────┘
```

- **Sub-agent tree** shows live session lineage (from `/api/subagents`)
- **Signal timeline** is a chronological feed of Signals linked to this Task
- **Signal icons**: 📨 message, 🔧 tool_call, 🚀 spawn, ✅ complete, ⚠ error, 💓 heartbeat
- **Expandable signals**: click to see full content (tool input/output, error trace, etc.)

---

### 4. Initiative Detail Page
**Purpose:** Full drill-down into one Initiative — progress, tasks, blockers.

```
┌─────────────────────────────────────────────────────────────────────┐
│  🏗  Agent Portal                           Status: Active · P1      │
│  Owner: Lewis · Target: Q2 2026 · 4 tasks / 12 total                │
│                                                                      │
│  Progress: ███████░░░░░░ 37%                                         │
│                                                                      │
│  ─────────────── Tasks ───────────────────────────────────          │
│  ✅ MT-176  Fix WebSocket reconnect                Lewis  Done        │
│  ✅ MT-178  Add Sentry error tracking              Lewis  Done        │
│  ● MT-179  DM section separation                  Marty  In Prog     │
│  ○ MT-180  Work tracking view                     Marty  Backlog     │
│  ○ MT-183  Mobile PWA support                     Echo   Backlog     │
│                                                                      │
│  ─────────────── Recent Signals ──────────────────────────          │
│  21:19  ✅ MT-179 complete (Marty)                                    │
│  21:18  ✅ MT-181 complete (Marty)                                    │
│  21:14  🚀 Subagent spawned for MT-179/181/182                       │
└─────────────────────────────────────────────────────────────────────┘
```

---

### 5. Signal Feed (new — no analogue in inspiration tools)
**Purpose:** Raw observable event stream across all agents and tasks. This is the "heartbeat of the system."

```
┌─────────────────────────────────────────────────────────────────────┐
│  📡 Signal Feed                    [All Agents ▾] [All Types ▾]     │
├─────────────────────────────────────────────────────────────────────┤
│  21:19  ✅  Marty      MT-182 complete: connection indicator moved   │
│  21:18  🔧  Marty      tool_call: git commit -m "fix(MT-179…"        │
│  21:17  🔧  Marty      tool_call: Edit server.js +favicon routes     │
│  21:16  🔧  Marty      tool_call: Write favicon.ico                  │
│  21:15  🔧  Marty      tool_call: Edit chat.html renderChannelList   │
│  21:14  🚀  Lewis      spawn: marty-portal-bugs subagent             │
│  21:00  💓  Lewis      heartbeat: HEARTBEAT_OK                       │
│  20:45  📨  Toby       message: fix these 3 bugs in agent-portal     │
└─────────────────────────────────────────────────────────────────────┘
```

- **Real-time SSE stream** (same pattern as existing chat stream)
- **Filter by agent, signal type, initiative, task, date range**
- **Click any signal** → open Task it belongs to (if linked)
- **Search signals** by content

---

## Navigation & Entry Points

The Work Tracking view lives as a top-level nav item: **Work** (or **📋 Work**).

Sub-navigation:
```
Work
├── Roadmap      (Initiative timeline view)
├── Board        (Kanban task view — default landing)
├── Initiatives  (List/grid of all Initiatives)
└── Signals      (Real-time signal feed)
```

---

## API Sketch

New endpoints needed (to be designed in MT-180 implementation ticket):

```
GET  /api/work/initiatives          → list Initiatives
POST /api/work/initiatives          → create Initiative
GET  /api/work/initiatives/:id      → Initiative + Tasks
PUT  /api/work/initiatives/:id      → update (status, dates, etc.)

GET  /api/work/tasks                → list Tasks (filterable)
POST /api/work/tasks                → create Task
GET  /api/work/tasks/:id            → Task + Signals + sub-agent tree
PUT  /api/work/tasks/:id            → update (status, assignee, etc.)

GET  /api/work/signals              → Signal feed (SSE or paginated)
POST /api/work/signals              → emit Signal (used by agents)

GET  /api/work/board                → Tasks grouped by status (for Board view)
GET  /api/work/roadmap              → Initiatives with date ranges (for Roadmap view)
```

---

## Key Differences from Inspiration Tools

| Feature | ProductPlan | ProductBoard | Linear | Agent Portal |
|---------|------------|--------------|--------|--------------|
| Primary worker | Human PM | Human team | Human eng | **AI Agent** |
| Work unit | Feature | Feature | Issue | **Task** |
| Observation layer | None | Insights (customer) | None | **Signals** |
| Session lineage | None | None | None | **Sub-agent tree** |
| Live activity | None | None | None | **SSE Signal feed** |
| Hierarchy | Initiative→Feature | Initiative→Feature | Initiative→Issue | **Initiative→Task→Signal** |
| Autonomy tracking | None | None | None | **autonomous vs. requested** |

---

## Implementation Phases

### Phase 1 (MVP — 1 sprint)
- DB schema: `initiatives`, `tasks`, `signals` tables
- Board view with status columns
- Task creation + assignment to agent
- Signals emitted automatically by gateway events (spawns, completions, errors)

### Phase 2
- Roadmap view (Initiative timeline bars)
- Task detail drawer with Signal timeline
- Initiative detail page

### Phase 3
- Signal Feed with real-time SSE
- Sub-agent tree visualization
- Integration with existing `/api/subagents` and `/api/activity`

---

## Open Questions

1. **Signal ingestion**: Should agents actively POST signals, or should the portal passively observe gateway events and auto-create them? Likely hybrid — gateway events auto-emit signals, agents can additionally POST explicit signals for milestone moments.

2. **Task creation flow**: Who creates Tasks? Options: (a) manually by Toby in the UI, (b) agents self-report tasks via API, (c) Lewis creates Tasks from Slack messages automatically. Recommend option (c) as default — Lewis is already tracking work; it should flow into the portal.

3. **Orphan signals**: Signals not linked to any Task (e.g., heartbeats). Should they show in the Signal Feed? Yes — unlinked signals should be visible but with a "unassigned" label.

4. **Task vs. Channel relationship**: A DM channel to Marty for a bug fix is essentially a Task. Do we link DM channels to Tasks? Probably yes — Task ID as optional metadata on a channel.

---

*Next step: Review with Toby. On approval, create MT-180-impl as the implementation ticket and spawn a coding agent for Phase 1.*

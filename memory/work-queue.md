# Agent Portal — Work Queue

**Last Updated:** 2026-03-18 12:30 CDT

---

## Phase 2: Sub-Agent Visual Tree

### ✅ DONE — Sub-Agent Tree Visualization (P2)
**Completed:** 2026-03-18  
**Status:** Live at https://talos.mtree.io/subagents

**What was built:**
- API endpoint: `GET /api/subagents` — returns nested tree from `signals` metadata
- Frontend: `public/subagents.html` — collapsible tree UI with status indicators, filters, live updates
- Navigation: Integrated into top nav (Work / Chat / Sub-Agents)
- Features: Expand/collapse, status filtering (All/Active/Done/Errors), auto-refresh, WebSocket push

**Details:** See `memory/agent-status.md`

---

## Sovereign: Finance Dashboard

### ✅ DONE — Quick-Add Transaction Feature (P2)
**Completed:** 2026-03-18 12:30 CDT  
**Agent:** Milton (finance agent)  
**Status:** Production-ready

**What was built:**
- `POST /api/transactions` endpoint — validates and inserts manual transactions with `source: 'manual'`
- `QuickAddModal` component — 3-field form (amount, description, category), slide-up animation, keyboard-friendly
- Persistent "+" FAB in bottom-left corner — always visible, opens modal
- Auto-refresh integration — `router.refresh()` updates dashboard KPIs immediately after save

**UX Contract:** ≤3 taps from landing page to save ✅  
**Details:** See `~/projects/sovereign/memory/agent-status.md`

---

## Backlog (Priority TBD)

### iOS App (P1 — BLOCKED)
- Xcode project creation (human task — Toby)
- APNS integration (server-side complete)
- Channel plugin (Phase 2a/2b/2c complete)

### Other Enhancements
- Sub-agent spawn controls (pause/resume/cancel from UI)
- Timeline view (Gantt-style)
- Click-to-inspect modal (full signal history)
- Export tree as JSON/SVG

---

**Notes:**
- All Phase 2 deliverables complete
- Next priority: iOS app Xcode setup (requires Toby)

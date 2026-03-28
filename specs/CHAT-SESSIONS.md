# Spec: Chat Sessions — Gateway-Backed Session Sidebar

**Author:** Lewis  
**Date:** 2026-03-28  
**Status:** Draft  
**Priority:** P1

---

## Problem

The Agent Portal chat has a single hardcoded session (`portal:dm-lewis`) and a vestigial "channels" abstraction backed by a Postgres table with one row ("general"). There's no way to:

- See other gateway sessions (heartbeats, sub-agents, cron runs)
- Create new conversation sessions for specific topics (News, Echo Chamber, etc.)
- Hide sessions you don't care about
- Have friendly names that stay consistent between the portal and the gateway

## Goal

Replace the channels abstraction with a **gateway-session-first sidebar** that reflects real OpenClaw sessions with human-readable names, supports hiding/archiving, and lets Toby create new sessions for any purpose.

---

## Design Principles

1. **Gateway is the source of truth** for session existence and history. The portal DB stores only metadata the gateway doesn't own (display name, visibility, sort order).
2. **Friendly names push to the gateway** via `sessions.patch` so they're consistent everywhere (Control UI, CLI, portal).
3. **All sessions visible by default** — user hides what they don't want to see. No auto-filtering.
4. **Sub-agents are first-class** — they appear in the sidebar (nested under their parent) but can be hidden individually.

---

## Architecture

### Data Flow

```
┌─────────────┐     sessions.list      ┌──────────────┐
│  Gateway     │ ◄─────────────────────►│ Agent Portal │
│  (sessions)  │     chat.history       │  (Express)   │
│              │     chat.send          │              │
│              │     sessions.patch     │              │
└─────────────┘                        └──────┬───────┘
                                              │
                                    ┌─────────▼─────────┐
                                    │  Postgres          │
                                    │  session_meta      │
                                    │  (display, hidden, │
                                    │   sort_order, etc) │
                                    └───────────────────┘
```

### New DB Table: `session_meta`

Replaces the `channels` table (which will be deprecated/removed in a later migration).

```sql
CREATE TABLE IF NOT EXISTS session_meta (
  session_key TEXT PRIMARY KEY,           -- gateway session key (e.g. "agent:main:portal:news")
  display_name TEXT,                      -- friendly name (e.g. "News")
  hidden BOOLEAN DEFAULT false,           -- user-controlled visibility
  pinned BOOLEAN DEFAULT false,           -- pinned to top of sidebar
  sort_order INTEGER DEFAULT 0,           -- manual ordering
  icon TEXT,                              -- optional emoji or icon name
  category TEXT DEFAULT 'conversation',   -- "conversation" | "system" | "subagent"
  parent_session_key TEXT,                -- for sub-agents: parent session key
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

### Session Key Convention

New sessions created from the portal use the pattern:
```
portal:<slug>
```

Examples:
- `portal:news` → "News"
- `portal:echo-chamber` → "Echo Chamber"
- `portal:familyos` → "FamilyOS"

Existing sessions keep their gateway-assigned keys. The `display_name` in `session_meta` controls what appears in the sidebar.

---

## API Changes

### New Endpoints

#### `GET /api/sessions`

Returns merged view: gateway sessions + portal metadata.

```json
{
  "sessions": [
    {
      "sessionKey": "agent:main:portal:general",
      "displayName": "Main",
      "category": "conversation",
      "hidden": false,
      "pinned": true,
      "lastMessage": "Good morning, sir.",
      "lastMessageAt": "2026-03-28T15:30:00Z",
      "agentId": "main",
      "model": "anthropic/claude-opus-4-6",
      "unread": false,
      "isSubagent": false
    },
    {
      "sessionKey": "agent:main:subagent:uuid-1234",
      "displayName": "FamilyOS branding sub-agent",
      "category": "subagent",
      "parentSessionKey": "agent:main:portal:general",
      "hidden": false,
      "pinned": false,
      "lastMessageAt": "2026-03-28T14:00:00Z",
      "isSubagent": true
    }
  ]
}
```

**Query params:**
- `?hidden=true` — include hidden sessions (default: exclude)
- `?category=conversation` — filter by category

**Logic:**
1. Call gateway `sessions.list` to get all live sessions
2. LEFT JOIN with `session_meta` for display names + visibility
3. Sessions without a `session_meta` row use auto-generated display names (see naming rules below)
4. Respect `hidden` flag

#### `POST /api/sessions`

Create a new session.

```json
{
  "displayName": "Echo Chamber",
  "icon": "📡",
  "category": "conversation"
}
```

**Logic:**
1. Slugify `displayName` → `portal:echo-chamber`
2. Send initial `chat.send` to the gateway with that `sessionKey` to create the session
3. Push `displayName` as label to gateway via `sessions.patch`
4. Insert `session_meta` row
5. Return the new session object

#### `PATCH /api/sessions/:sessionKey`

Update session metadata.

```json
{
  "displayName": "Echo Chamber v2",
  "hidden": true,
  "pinned": false
}
```

**Logic:**
1. Upsert `session_meta` row
2. If `displayName` changed, push to gateway via `sessions.patch` (label field)

#### `DELETE /api/sessions/:sessionKey`

Hides the session (soft delete). Does NOT delete gateway session data.

```json
{ "hidden": true }
```

### Modified Endpoints

#### `GET /api/channels/:channelId/messages` → `GET /api/sessions/:sessionKey/messages`

Fetches messages from the gateway session via `chat.history`.

```json
{
  "messages": [
    {
      "id": "msg-1",
      "role": "user",
      "text": "What's happening in AI today?",
      "timestamp": "2026-03-28T15:30:00Z",
      "agent": { "id": "lewis", "name": "Lewis", "emoji": "📚" }
    }
  ]
}
```

**Params:** `?limit=50&before=<messageId>`

#### `POST /api/channels/:channelId/messages` → `POST /api/sessions/:sessionKey/messages`

Sends a message to the gateway session via `chat.send`.

```json
{
  "text": "What's the latest AI news?",
  "sessionKey": "portal:news"
}
```

---

## Frontend Changes

### Sidebar

The sidebar replaces the current channel list with a session list:

```
┌─────────────────────────┐
│ ⊕ New Session           │
├─────────────────────────┤
│ 📌 PINNED               │
│  📚 Main                │
├─────────────────────────┤
│ 💬 CONVERSATIONS        │
│  📡 Echo Chamber        │
│  📰 News                │
│  🎮 Echo Unchained      │
├─────────────────────────┤
│ 🤖 SUB-AGENTS           │
│  └ FamilyOS branding    │
│  └ Detour API fix       │
├─────────────────────────┤
│ ⚙️ SYSTEM  (collapsed)  │
│  └ Heartbeat            │
│  └ Cron: news-digest    │
├─────────────────────────┤
│ 👁️ Show hidden (3)      │
└─────────────────────────┘
```

**Interactions:**
- **Click** → switch active session, load history from gateway
- **Right-click / long-press** → context menu: Rename, Hide, Pin/Unpin, Delete
- **"+ New Session"** → modal: enter name, optional icon
- **"Show hidden"** → toggle hidden sessions (greyed out, with "Unhide" option)

### Chat Area

- Chat area remains largely the same
- Session name displayed in header (editable inline)
- Agent avatar/name shown per message (already works for Lewis)
- Active session key stored in `localStorage` and restored on reload

### Auto-Generated Display Names

Sessions without a `session_meta.display_name` get auto-generated names:

| Session Key Pattern | Display Name |
|---|---|
| `agent:main:portal:general` | "Main" |
| `agent:main:portal:dm-lewis` | "Lewis" |
| `agent:main:heartbeat` | "Heartbeat" |
| `agent:main:cron:<name>` | "Cron: <name>" |
| `agent:main:subagent:<uuid>` | Label from gateway, or "Sub-agent <short-uuid>" |
| `agent:main:slack:dm-<id>` | "Slack DM" |
| `agent:main:telegram:<id>` | "Telegram" |
| `portal:<slug>` | Title-cased slug |

---

## Migration Plan

### Phase 1: Add `session_meta` table + new API endpoints
- Create `session_meta` table
- Implement `GET/POST/PATCH/DELETE /api/sessions`
- Pre-populate `session_meta` with `display_name: "Main"` for `portal:dm-lewis` (remapped to `agent:main:portal:general`)
- Keep old channel endpoints working (backward compat for iOS app)

### Phase 2: Update frontend
- Replace channel sidebar with session sidebar
- Wire up session creation, hiding, renaming
- Switch message loading to use `GET /api/sessions/:key/messages`
- Switch message sending to route to correct gateway session

### Phase 3: Mobile & Desktop Apps
- Update iOS app (SwiftUI/WKWebView) to use new `/api/sessions` endpoints
- Session sidebar in native UI (UITableView/List) mirroring web sidebar
- Push notifications scoped per-session (not just global)
- Desktop app (if/when built): Electron or native — same API surface
- Offline: cache `session_meta` locally, sync on reconnect

### Phase 4: Cleanup
- Remove `channels` table and related endpoints
- Remove `channel_members` table
- Remove `sessionChannelMap` bridge code in `chat-gateway.js`
- Drop legacy `/api/channels/*` routes once mobile is migrated

---

## Gateway Integration Notes

### Available Gateway WS Methods

| Method | Purpose |
|---|---|
| `sessions.list` | Get all sessions with metadata |
| `sessions.patch` | Update session label, model, thinking |
| `chat.history` | Get messages for a specific `sessionKey` |
| `chat.send` | Send message to a specific `sessionKey` |
| `chat.abort` | Abort active run on a `sessionKey` |

### Session Lifecycle

- Sessions are created lazily by the gateway when the first `chat.send` targets a new `sessionKey`
- No explicit "create session" API needed on the gateway side
- The portal creates sessions by sending the first message
- Gateway session expiry (`idleMinutes: 10080`) may clean up old sessions — `session_meta` rows persist regardless, so hidden/renamed sessions survive gateway restarts

### Real-Time Updates

The existing WebSocket connection (`chat-gateway.js`) already receives events for all sessions. The refactor needs to:

1. Route incoming `message` events to the correct sidebar session (not just `lastActiveChannelId`)
2. Show unread indicators on non-active sessions
3. Update `lastMessageAt` in the sidebar when events arrive

---

## Non-Goals (for now)

- **Multi-agent routing**: Each session talks to Lewis (main agent). Multi-agent DMs (Marty, Pascal, Milton) remain separate agent configs, not session-level.
- **Shared sessions**: No multi-user collaboration. Single-user portal.
- **Search across sessions**: Full-text search across all sessions. Future feature.
- **Session archiving with export**: Download session transcripts. Future feature.

---

## Open Questions

1. **Session limit** — Should the sidebar cap at N sessions, or rely on hiding/collapsing to manage clutter? Current gateway has ~30 sessions. Recommendation: no cap, but collapse categories by default.

2. **iOS app** — The iOS app uses the `/api/channels` endpoints. Phase 3 migration needs to update it. For now, keep old endpoints working.

3. **Agent-scoped sessions** — If Marty or Pascal agents are added later, should sessions be scoped per-agent? Current design treats all sessions under the `main` agent. Recommendation: defer, handle when multi-agent is real.

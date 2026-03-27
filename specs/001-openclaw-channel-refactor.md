# Spec 001: Agent Portal → OpenClaw Channel Refactor

**Status:** Draft — awaiting Toby review
**Date:** 2026-03-26
**Author:** Lewis

---

## Vision

Agent Portal becomes a **Telegram-quality chat skin over OpenClaw**. Not a platform, not a dashboard — a beautiful, fast, purpose-built interface for talking to Lewis and managing conversations through channels (OpenClaw sessions).

```
Agent Portal (web + iOS)
        │
        ▼
   OpenClaw (gateway WS protocol)
        │
        ├── Sessions → AP channels
        ├── LCM → context management
        ├── / commands → native
        ├── Sub-agents → spawned within channels
        └── All existing infra
```

## Principles

1. **OpenClaw is the backend.** AP stores nothing about conversations, context, or agent state. It's a client.
2. **Channels = OpenClaw sessions.** Each channel in the sidebar maps 1:1 to an OpenClaw session.
3. **Preserve what works.** Chat UI, voice, sidebar, auth, push, PWA — all stay.
4. **Slash commands are native.** Messages starting with `/` are forwarded to OpenClaw and rendered appropriately.
5. **Sub-agents are invisible plumbing.** Lewis orchestrates them. Users see results in-channel, not agent management UI.

---

## What Stays (Untouched)

| Component | Location | Notes |
|-----------|----------|-------|
| Chat message UI | `public/chat.html` (message rendering, bubbles, markdown, typing indicators) | Core UX — keep exactly as-is |
| Voice commands | `public/chat.html` (mic button, silence threshold) + iOS VoiceUI | Working on both platforms |
| Sidebar shell | `public/chat.html` (sidebar layout, channel list rendering, create button) | Visual structure stays, data source changes |
| Google OAuth | `lib/auth.js` + Passport config | Keep, works fine |
| Push notifications | `lib/apns.js`, `lib/push.js` | Keep (pending Xcode capability enable) |
| PWA manifest | `public/manifest.json` | Keep |
| Connection indicator | `public/chat.html` (status dot) | Keep, rewire to new WS |
| Device registry | `lib/device-registry.js` | Keep for push token registration |
| iOS app shell | `ios/AgentPortal/` | Keep — WKWebView + voice + push |

## What Gets Removed

| Component | Location | Reason |
|-----------|----------|--------|
| Work view | `public/work.html`, `/api/work` routes | Replaced by OpenClaw native tracking |
| Sub-agent view | `public/subagents.html`, `/api/subagents` routes | Sub-agents are invisible now |
| Agent roster/DMs | Per-agent DM channels (marty, pascal, milton) in sidebar + `AGENT_SESSION_KEYS` | Only one agent: Lewis |
| Activity dashboard | `/api/activity` routes, activity timeline | Observability moves to `/status` command |
| Scheduled tasks view | `/api/scheduled` routes | Use `/` commands in-channel |
| Chat state DB | `lib/chat-state.js`, `lib/db.js` (channel/message tables) | OpenClaw owns conversation state |
| Signals system | `lib/signals.js` | Was for multi-agent tracking |
| Webhook delivery | `lib/webhook-delivery.js` | Agent portal webhook push — not needed |
| PostHog | `lib/posthog.js` | Optional, can re-add later |
| Game asset viewer | `public/assets/` | Move to Echo project if needed |
| Channel plugin package | `packages/openclaw-channel-agent-portal/` | Replaced by direct gateway WS |

## What Gets Rewired

### 1. Gateway Client (`lib/gateway-client.js`)

**Current:** Hardcoded session keys (`portal:dm-lewis`, `portal:dm-marty`, etc.) mapping to per-agent DM channels.

**New:** Dynamic session management. The client can:
- List available sessions (`sessions.list`)
- Create new sessions (user creates a channel)
- Send messages to any session by key
- Receive deltas/responses scoped to a session

```js
// Old
const AGENT_SESSION_KEYS = {
  lewis: 'portal:dm-lewis',
  marty: 'portal:dm-marty',
  // ...
};

// New
class GatewayClient {
  async listSessions() { /* sessions.list via WS */ }
  async createSession(label) { /* sessions.create via WS */ }
  async sendMessage(sessionKey, text) { /* chat.send */ }
  // Incoming deltas routed by sessionKey to correct channel
}
```

### 2. Sidebar Channels

**Current:** Hardcoded channels (general, dm-lewis, dm-marty, dm-pascal, dm-milton) loaded from DB.

**New:** Channels populated from `sessions.list`. User can create new channels (= new OpenClaw sessions). Each channel shows:
- Session label (user-editable name)
- Last message preview
- Unread indicator
- Status (active session / idle)

```
┌─────────────────────────┐
│ Agent Portal         [+] │
│─────────────────────────│
│ 📚 General               │  ← Main Lewis session
│ 🏰 Fort                  │  ← Fort project session
│ 🗺️ Detour                │  ← Detour project session
│ 💰 Finance               │  ← Finance/budget session
│ 📝 Quick question         │  ← Ad-hoc session
└─────────────────────────┘
```

### 3. Message Routing

**Current:** Messages go through `chat-state.js` → DB → broadcast. Gateway responses come back via `chat.delta`.

**New:** Messages go directly to OpenClaw via `chat.send` with the active channel's `sessionKey`. Responses stream back via `chat.delta`. No local DB involved.

### 4. Slash Commands

**Current:** Not supported — messages starting with `/` are sent as regular text.

**New:** Messages starting with `/` are sent to OpenClaw as-is. OpenClaw processes them and returns the result. The AP renders the response (which may be structured — status cards, model info, etc.) in the chat.

Special rendering for known commands:
- `/status` → formatted status card
- `/model` → model info display
- `/reasoning` → toggle indicator in UI

### 5. Server Simplification

**Current:** `server.js` (464 lines) + 15 lib files (3,001 lines) = ~3,500 lines handling routes, DB, WS, agents, signals, webhooks, activity.

**New:** `server.js` (~150 lines) + 3-4 lib files (~500 lines):
- `lib/auth.js` — Google OAuth (unchanged)
- `lib/gateway-client.js` — OpenClaw WS client (rewritten)
- `lib/push.js` — APNs push (unchanged)
- `lib/device-registry.js` — push token storage (unchanged)

Routes:
- `GET /` → serves `chat.html`
- `GET /api/health` → health check
- `GET /api/me` → authenticated user info
- `POST /api/devices` → register push token
- `WS /ws/gateway` → proxy to OpenClaw gateway

Everything else (sessions, messages, history, commands) flows through the WebSocket.

---

## Chat History

**Current:** Stored in PostgreSQL (`messages` table), fetched via custom API.

**New:** Fetched from OpenClaw via `chat.history` WS command per session. AP caches nothing — OpenClaw's LCM handles context compression and history.

The frontend requests history when switching channels:
```js
// User clicks "Fort" channel
gateway.send('chat.history', { sessionKey: 'portal:fort', limit: 50 });
// Renders messages in chat area
```

---

## Channel Creation

Users can create channels via the [+] button in the sidebar:
1. User clicks [+], enters a name (e.g., "Fort")
2. AP sends a session creation request to OpenClaw
3. New session appears in sidebar
4. User can start chatting in the new context window

Channels can also be created by Lewis (me) when I determine a conversation needs its own context — surfaced in the sidebar automatically.

---

## Sub-Agent Visibility

When Lewis spawns a sub-agent to handle work in a channel, the user sees:
- A system message: "⚡ Working on this..." (or similar)
- Streamed progress if the sub-agent is producing output
- Final result rendered as a message from Lewis

No separate sub-agent UI. No agent roster. The sub-agent is an implementation detail.

---

## Database Changes

**Drop:**
- `channels` table
- `messages` table  
- `chat_sessions` table
- `agents` table
- `signals` table
- `work_items` table
- `scheduled_tasks` table
- `activity_log` table

**Keep:**
- `sessions` table (Express sessions for auth)
- `devices` table (push token registration)

This is a massive DB simplification. PostgreSQL stays for auth sessions and push tokens only.

---

## Migration Path

This is a refactor-in-place on `main`, not a rewrite. Steps:

### Phase 1: Rewire Gateway Client
- Rewrite `lib/gateway-client.js` for dynamic sessions
- Update `chat.html` to populate sidebar from `sessions.list`
- Remove hardcoded agent DM channels
- Slash command passthrough

### Phase 2: Strip Backend
- Remove routes: `/api/work`, `/api/activity`, `/api/scheduled`, `/api/subagents`, `/api/signals`
- Remove lib files: `chat-state.js`, `db.js` (replace with minimal push-token-only DB), `signals.js`, `webhook-delivery.js`, `posthog.js`, `broadcast.js`
- Remove pages: `work.html`, `subagents.html`, `download.html`, `assets/`
- Simplify `server.js` to ~150 lines

### Phase 3: Channel UX Polish
- Channel creation flow ([+] button)
- Channel rename/delete
- Unread indicators
- Last message preview in sidebar
- Slash command result rendering

### Phase 4: iOS Alignment
- Update iOS WebView to work with new chat.html
- Push notification payloads scoped to channel/session
- Voice command → message in active channel

---

## Environment Variables (Post-Refactor)

| Var | Notes |
|-----|-------|
| `SESSION_SECRET` | Express session signing |
| `DATABASE_URL` | PostgreSQL (auth sessions + push tokens only) |
| `GOOGLE_CLIENT_ID` | OAuth |
| `GOOGLE_CLIENT_SECRET` | OAuth |
| `GATEWAY_WS_URL` | `wss://gw.mtree.io` |
| `GATEWAY_TOKEN` | Auth token for gateway WS |
| `APNS_KEY_ID` | Push notifications |
| `APNS_TEAM_ID` | Push notifications |
| `APNS_SIGNING_KEY` | Push notifications |
| `SENTRY_DSN` | Error tracking (optional) |

Removed: `FEATURE_ACTIVITY_DASHBOARD`, `POSTHOG_API_KEY`, `PORTAL_API_KEY` (work endpoints gone).

---

## Future: Desktop App (Phase 5+)

Tauri or Electron wrapper around the same `chat.html` web UI. Benefits:
- Native window management, system tray, global keyboard shortcuts
- Native push notifications (no APNs dependency on desktop)
- Menu bar presence — always one click away
- Same codebase as web — no divergence

Not a tonight deliverable. Spec when web + iOS are solid.

---

## Success Criteria

1. Chat UI looks and feels identical to current (no regression)
2. Sidebar shows OpenClaw sessions as channels
3. User can create/rename/switch channels
4. Slash commands work (`/status`, `/model`, etc.)
5. Voice commands work (web + iOS)
6. Push notifications work (once Xcode capability enabled)
7. `server.js` + libs < 700 lines total
8. No local message/conversation storage — OpenClaw owns it all
9. All existing tests that cover auth, health, push still pass
10. New tests for: session listing, channel creation, slash command routing

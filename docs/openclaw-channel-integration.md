# Agent Portal ↔ OpenClaw Gateway Integration

> **Priority:** P1 — Top priority per Toby (2026-03-17)
> **Owner:** Marty
> **Goal:** Replace bespoke WebSocket proxy with native OpenClaw gateway WebChat protocol

## Current State (What We Have)

Portal server has its own WebSocket chat system:
- Portal UI → WebSocket → Portal server → gateway HTTP proxy → agent
- Agent response → gateway → portal server → WebSocket → UI
- Custom message routing, custom typing indicators, custom history

This is fragile, duplicates gateway functionality, and blocks the portal from being the primary surface.

## Target State (What We Want)

Portal server becomes a **gateway WebSocket client**:
- Portal UI → WebSocket → Portal server → **Gateway WebSocket** (`chat.send`) → agent
- Agent response → Gateway WebSocket (`chat.delta`) → Portal server → WebSocket → UI
- History via `chat.history`
- Notes via `chat.inject`

## Architecture

```
┌─────────────┐     WS      ┌──────────────┐     WS      ┌──────────────┐
│  Portal UI  │ ◄──────────► │ Portal Server│ ◄──────────► │   OpenClaw   │
│  (browser)  │              │  (Express)   │              │   Gateway    │
│             │              │              │              │  :18789      │
└─────────────┘              └──────────────┘              └──────────────┘
                                   │
                              ┌────┴────┐
                              │Postgres │
                              │(history │
                              │ cache)  │
                              └─────────┘
```

### Portal Server Responsibilities
1. **Gateway WS client** — connect to `ws://127.0.0.1:18789` with auth token
2. **Message bridging** — translate portal UI messages to `chat.send` format, relay `chat.delta` back
3. **Agent routing** — use `agentId` or session keys to route DMs to the correct agent (Lewis, Marty, Pascal, Milton)
4. **History caching** — store messages in Postgres for the portal's own history/search
5. **UI features** — agent roster, DMs, @-mentions, typing indicators (driven by `chat.delta` state)

### What Gets Removed
- Current gateway HTTP proxy logic in server.js
- Custom message routing code
- Direct agent session management

## Gateway WebSocket Protocol (from OpenClaw docs)

### Sending a message
```json
{
  "type": "chat.send",
  "text": "Hello Lewis",
  "sessionKey": "portal:dm-lewis"
}
```

### Receiving responses
```json
{
  "type": "chat.delta",
  "text": "partial response...",
  "state": "streaming|final",
  "sessionKey": "portal:dm-lewis"
}
```

### Fetching history
```json
{
  "type": "chat.history",
  "sessionKey": "portal:dm-lewis"
}
```

### Injecting a note (no agent run)
```json
{
  "type": "chat.inject",
  "text": "System note",
  "sessionKey": "portal:dm-lewis"
}
```

## Agent Routing via Session Keys

Each agent DM maps to a unique session key:
- `portal:dm-lewis` → Lewis (main agent)
- `portal:dm-marty` → Marty (agentId: marty)
- `portal:dm-pascal` → Pascal (agentId: pascal)
- `portal:dm-milton` → Milton (agentId: milton)
- `portal:general` → General channel (main agent)

The gateway handles agent resolution via `agentId` on the session or via the hooks system.

## Auth

Gateway auth token from openclaw.json — the portal server connects as a trusted local client.

```
Authorization: Bearer <gateway-auth-token>
```

## Implementation Steps

### Phase 1 — Gateway Client (Day 1)
1. Add `ws` dependency to portal server (already has it)
2. Create `lib/gateway-client.js` — connects to gateway WS, handles auth, reconnection
3. Wire `chat.send` to portal's existing WebSocket message handler
4. Wire `chat.delta` events back to portal UI clients
5. Remove old gateway HTTP proxy code

### Phase 2 — Agent Routing (Day 1-2)
1. Map DM channels to agent session keys
2. Handle @-mentions by routing to the appropriate agent session
3. Pass `agentId` for multi-agent routing

### Phase 3 — History Migration (Day 2)
1. Use `chat.history` for initial load
2. Cache messages in Postgres for portal-side search
3. Keep existing message display UI

### Phase 4 — Polish (Day 2-3)
1. Typing indicators from `chat.delta` state
2. Connection status indicator
3. Error handling and reconnection
4. iOS app compatibility (same WebSocket, no changes needed)

## Open Questions for Toby
1. Should the portal still maintain its own Postgres message history, or fully rely on gateway history?
2. Should agents other than Lewis be reachable directly through the portal (multi-agent DMs)?
3. Do we need the portal to work offline/disconnected from the gateway?

## References
- OpenClaw WebChat docs: https://docs.openclaw.ai/web/webchat
- Gateway webhook docs: https://docs.openclaw.ai/automation/webhook
- Current portal server: `server.js` (gateway proxy section)

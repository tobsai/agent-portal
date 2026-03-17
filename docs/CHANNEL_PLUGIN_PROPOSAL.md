# Agent Portal as an OpenClaw Channel — Architectural Proposal

**Author:** Marty (P3 Research Sprint)  
**Date:** 2026-03-17  
**Status:** Draft — Awaiting Review  

---

## Executive Summary

The Agent Portal iOS app is **already most of the way there**. It has APNs push, a server-side gateway proxy, a message persistence layer with channels/DM tables, and an SSE broadcast pipeline. What's missing is a formal **OpenClaw channel plugin** — the thin adapter that lets the gateway treat `agent-portal` like Slack: inbound messages from Toby arrive as channel events, and Lewis's replies route back through the same channel rather than through Slack.

This document describes what a channel plugin is, what the Agent Portal already provides, and what needs to be built.

---

## 1. How OpenClaw Channels Work

### Config Structure (observed in `~/.openclaw/openclaw.json`)

Each channel is declared under `channels.<name>` with:
- `enabled` — whether it's active
- `mode` — e.g. `socket` (Slack) or webhook
- `dmPolicy` — `open` | `pairing`
- `streaming` — `off` | `partial` | `full`
- `accounts` — keyed sub-configs (one per bot/identity)
- `allowFrom` — user allow-list (or `["*"]`)
- `actions.reactions` — whether emoji reactions are supported

Bindings in `bindings[]` route agent IDs to channel+accountId tuples.

### What a Channel Plugin Must Do

From the Slack implementation and OpenClaw extension structure (`openclaw.plugin.json`), a channel plugin is an npm package that:

1. **Registers itself** — `openclaw.plugin.json` declares `id`, config schema, and capabilities
2. **Listens** for inbound messages from users and emits them as structured events into the gateway
3. **Delivers** outbound messages from agents to the user (the `send` operation)
4. **Optionally** handles reactions, threading, streaming deltas, and typing indicators
5. **Authenticates** — either via token (Slack bot token), webhook signature, or device key handshake

The gateway calls `channel.send(message)`, `channel.read(history)`, and optionally `channel.react(emoji)`. The channel plugin calls back with `channel.onMessage(handler)`.

---

## 2. What Agent Portal Already Provides

### ✅ APNs Push (fully implemented)
- `lib/apns.js` — JWT-authenticated APNs over HTTP/2
- `push_tokens` table — per-device token storage keyed to `user_id`
- `pushToAllDevices(message, senderName)` — fire-and-forget push pipeline
- Auto-removal of expired/invalid tokens

### ✅ Message Persistence Layer
- `channels` table — named channels + DM channels (`is_dm`, `dm_agent_id`, `dm_user_id`)
- `messages` table — full message rows with `sender_type`, `sender_id`, `sender_name`, `sender_emoji`, `content`, `reply_to`, `mentions`
- `channel_members` table — channel membership

### ✅ SSE Broadcast Bus
- `broadcastChannelEvent(channelId, event, data)` — fans out to all SSE subscribers
- Per-channel subscription map (`channelSseClients`)
- Global `__all__` bus for cross-channel listeners

### ✅ Gateway Proxy / Native Client
- `/ws/gateway` WebSocket proxy — authenticates server-side, pipes gateway traffic to web/iOS clients
- `lib/gateway-client.js` — direct native connection to `ws://127.0.0.1:18789`
- Handles `connect.challenge` → device-signed `connect` handshake
- Emits `delta`, `message`, `agentError`, `connected`, `disconnected` events

### ✅ Message Ingest (partial)
- `POST /api/chat` or similar endpoint sends user messages into the gateway via `chatGatewayRequest`
- `lastActiveSessionKey` and `lastActiveChannelId` track where replies should route

### ✅ Unified Delivery Pipeline
- `sendAgentMessage(channelId, content, senderName, senderEmoji, senderId)` — persists to DB, broadcasts via SSE, fires APNs push

### ⚠️ Phase 2 wiring commented as TODO
- `server.js` line ~544: "channel lookup deferred to Phase 2" — DM channel resolution for native client events is explicitly deferred

---

## 3. What Needs Building

### A. OpenClaw Channel Plugin Package

Create `packages/openclaw-channel-agent-portal/` (or publish as `@mapletree/openclaw-channel-agent-portal`):

```
openclaw.plugin.json       ← plugin manifest
index.ts                   ← plugin entry (ESM, matches OpenClaw extension pattern)
src/
  channel.ts               ← AgentPortalChannel class
  inbound.ts               ← HTTP webhook receiver (gateway → portal)
  outbound.ts              ← push delivery (portal → device)
  auth.ts                  ← API key validation
  types.ts                 ← TypeScript interfaces
```

#### `openclaw.plugin.json`
```json
{
  "id": "agent-portal",
  "configSchema": {
    "type": "object",
    "properties": {
      "enabled": { "type": "boolean" },
      "apiKey": { "type": "string" },
      "portalUrl": { "type": "string" },
      "streaming": { "type": "string", "enum": ["off", "partial", "full"] },
      "dmPolicy": { "type": "string", "enum": ["open", "pairing"] }
    }
  }
}
```

#### Config entry in `openclaw.json`
```json
"agent-portal": {
  "enabled": true,
  "streaming": "partial",
  "dmPolicy": "open",
  "allowFrom": ["*"],
  "portalUrl": "https://talos.mtree.io",
  "apiKey": "ak_e83ddf5617724e41b80419e19037c2d0"
}
```

---

### B. Inbound Path: Portal → Gateway

When Toby sends a message in the iOS app, it must reach the gateway as a user message on Lewis's session.

**Flow:**
1. iOS app POSTs message to `POST /api/channels/:channelId/messages` (or existing chat endpoint)
2. `server.js` authenticates via session cookie or JWT
3. Server calls `gatewayClient.sendUserMessage(sessionKey, text)` — a new method on the native client
4. Gateway processes it as a user message on `agent:main:main`
5. Lewis responds; response routes back through the outbound path (see §C)

**New method needed on `lib/gateway-client.js`:**
```typescript
async sendUserMessage(sessionKey: string, text: string): Promise<void>
// Sends: { type: 'req', method: 'chat.send', params: { sessionKey, text } }
```

---

### C. Outbound Path: Gateway → iOS Device

Already 90% built. Currently `storeAgentMessageInChannel` + `pushToAllDevices` fires on every final `chat` event. The remaining work:

1. **Resolve the DM channel** — the TODO at line ~544. When native client receives `message` for `agent:main:main`, look up or create the DM channel for `(lewis, toby)`.
2. **Route reply to correct channel** — use `lastActiveChannelId` (already tracked) or pass `channelId` through the event.
3. **Streaming deltas** — optional; `broadcastChannelEvent` already fans to SSE, iOS just needs to subscribe and render incrementally.

---

### D. iOS App — Channel UI

The iOS app needs a native chat interface wired to the channel SSE stream:

1. **SSE subscription** — `GET /api/channels/:channelId/events` (EventSource)
2. **Send** — `POST /api/channels/:channelId/messages`
3. **History** — `GET /api/channels/:channelId/messages?limit=50`
4. **Push tap** — deep-link into the correct channel view

The web chat interface (`/chat.html`) already demonstrates all four patterns.

---

### E. Gateway Config Binding

Add a binding to route Lewis's outbound messages to `agent-portal`:

```json
{
  "type": "route",
  "agentId": "lewis",
  "match": {
    "channel": "agent-portal",
    "accountId": "default"
  }
}
```

Or more precisely: when a message arrives **from** `agent-portal`, the reply goes **back** to `agent-portal`. This is how Slack DMs work — Lewis already replies back to whatever channel initiated the conversation.

---

## 4. Feasibility Assessment

| Component | Status | Effort |
|-----------|--------|--------|
| APNs push delivery | ✅ Done | — |
| Message persistence (channels/messages tables) | ✅ Done | — |
| SSE broadcast bus | ✅ Done | — |
| Gateway proxy (WebSocket) | ✅ Done | — |
| Native gateway client (`lib/gateway-client.js`) | ✅ Done | — |
| Unified delivery pipeline (`sendAgentMessage`) | ✅ Done | — |
| `gatewayClient.sendUserMessage()` method | 🔧 Build | ~2h |
| DM channel resolution (Phase 2 TODO) | 🔧 Build | ~2h |
| `POST /api/channels/:id/messages` inbound endpoint | 🔧 Build | ~1h |
| `GET /api/channels/:id/events` SSE endpoint | 🔧 Build | ~1h |
| `openclaw.plugin.json` + plugin manifest | 🔧 Build | ~1h |
| iOS channel UI (native SwiftUI chat view) | 🔧 Build | ~1 day |
| Gateway config binding | ✅ Trivial | ~10min |

**Total server-side effort: ~6–8 hours**  
**Total iOS effort: ~1–2 days** (depending on existing SwiftUI component reuse)

---

## 5. Proposed Architecture Diagram

```
┌─────────────────────────────────────────────────────────────┐
│                        iOS App                              │
│  SwiftUI ChatView ←──── EventSource (SSE) ────→ /api/channels/:id/events  │
│                  ────── POST /api/channels/:id/messages ──→  │
│                  ←───── APNs push (background/foreground) ── │
└────────────────────────────────┬────────────────────────────┘
                                 │
                         agent-portal server
                         (talos.mtree.io)
                                 │
          ┌──────────────────────┼───────────────────────┐
          │                      │                       │
   DB (messages,          SSE broadcast bus        lib/gateway-client.js
   channels,              (channelSseClients)       │
   push_tokens)                                     │ ws://127.0.0.1:18789
                                                    │
                                             ┌──────▼──────┐
                                             │  OpenClaw   │
                                             │  Gateway    │
                                             │             │
                                             │  Lewis      │
                                             │  (agent:    │
                                             │   main:main)│
                                             └─────────────┘
```

---

## 6. Separation of Concerns

| Layer | Responsibility |
|-------|----------------|
| `lib/gateway-client.js` | Raw gateway protocol (connect, send, receive) — no UI or DB |
| `sendAgentMessage()` | Unified outbound pipeline (DB + SSE + APNs) — no gateway knowledge |
| `storeAgentMessageInChannel()` | DB write + SSE fan-out — no push |
| `/api/channels/` endpoints | HTTP surface — auth, validation, delegation only |
| iOS SwiftUI layer | Render, input, notification UX — no business logic |
| `openclaw.plugin.json` | Plugin registration only — no implementation |

This matches the existing clean separation already visible in `server.js`. The channel plugin layer is additive, not a refactor.

---

## 7. Recommended Phasing

### Phase 2a — Wire inbound (1 day)
- Add `gatewayClient.sendUserMessage()` 
- Add `POST /api/channels/:id/messages` endpoint
- Resolve DM channel for `(lewis, toby)` on native client events
- Test: send from web chat → verifies gateway round-trip

### Phase 2b — iOS channel UI (2–3 days)
- SwiftUI `ChannelView` with SSE-backed message list
- Send bar → POST to server
- Tap push notification → deep-link to channel

### Phase 2c — Plugin manifest (0.5 days)
- Package `openclaw.plugin.json` + add binding to `openclaw.json`
- Enables Lewis to list `agent-portal` as a channel in `message` tool calls

### Phase 3 — Feature parity (ongoing)
- Streaming deltas (typing indicator)
- Reactions
- Multi-agent channels (Marty, Pascal, Milton each with DM channel)
- Message threading

---

## 8. Key Risks

1. **Gateway chat.send API** — Need to confirm the exact method name and params for sending a user message via the native client. Current code only receives; may need to check OpenClaw gateway docs or source.
2. **Session scoping** — `lastActiveSessionKey` is a single global. For multi-agent, need per-channel session routing.
3. **APNs production cert** — Currently on sandbox (`api.sandbox.push.apple.com`). Needs flip to production before App Store.
4. **OpenClaw plugin loader** — The extension system (as seen with `lossless-claw`) is npm-based. The channel plugin will need to be either published to npm or installed via local path. Check if local path installs are supported.

---

## Conclusion

The Agent Portal is one sprint away from being a first-class OpenClaw channel. The infrastructure is sound. The work is additive. Phase 2a can be done in a day with confidence; Phase 2b (iOS UI) is the larger investment. The architecture already enforces clean separation — the channel plugin layer slots in without requiring any structural refactoring of `server.js`.

Recommend proceeding with Phase 2a immediately as it unblocks iOS development and lets Toby test the round-trip on the web before committing to native UI work.

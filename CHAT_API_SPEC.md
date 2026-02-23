# Chat API Consolidation Spec

## Goal
Unify web and iOS chat into a single API contract. The portal server handles all gateway communication. Clients are thin renderers — no WebSocket logic, no auth, no gateway protocol knowledge.

## Architecture

```
[Web chat.html] ──REST──▶ [Portal API] ──WS──▶ [OpenClaw Gateway]
[iOS SwiftUI]   ──REST──▶ [Portal API] ──WS──▶ [OpenClaw Gateway]
```

### Portal API Endpoints

#### `GET /api/chat/messages?limit=50&before=<id>`
Returns chat history. Auth: session cookie (web) or JWT (iOS).

```json
{
  "messages": [
    {
      "id": "msg-abc123",
      "role": "user" | "assistant",
      "text": "Hello",
      "timestamp": "2026-02-22T21:00:00Z",
      "status": "delivered" | "pending" | "error"
    }
  ],
  "hasMore": true
}
```

#### `POST /api/chat/send`
Send a message. Auth: session cookie (web) or JWT (iOS).

```json
// Request
{ "message": "Hello Talos", "idempotencyKey": "uuid" }

// Response
{ "id": "msg-abc123", "status": "delivered" }
```

#### `GET /api/chat/stream` (SSE)
Server-Sent Events for real-time updates. Replaces WebSocket for clients.

Events:
- `message` — new message (user or assistant)
- `typing` — assistant is generating
- `status` — connection status change
- `error` — error notification

```
event: message
data: {"id":"msg-xyz","role":"assistant","text":"Hello sir","timestamp":"..."}

event: typing
data: {"active":true}

event: status  
data: {"connected":true}
```

### Portal Server (server.js)

The server maintains ONE persistent WebSocket connection to the gateway (singleton, reconnects automatically). It:

1. Authenticates with device identity (already working)
2. Subscribes to `chat.subscribe` for the main session
3. Stores recent messages in memory (ring buffer, ~200 messages)
4. Broadcasts to connected SSE clients
5. Handles `POST /api/chat/send` by calling `chat.send` on the gateway WS

### Web Client (chat.html)

Thin renderer:
- `fetch('/api/chat/messages')` on load for history
- `EventSource('/api/chat/stream')` for real-time
- `fetch('/api/chat/send', { method: 'POST', body })` to send
- NO WebSocket code
- NO auth/signing logic
- NO gateway protocol knowledge

### iOS Client (ChatView.swift)

Thin renderer:
- Same REST endpoints as web
- URLSession for messages + send
- URLSession streaming for SSE (or polling as fallback)
- NO WebSocket code  
- NO DeviceIdentityManager usage for chat
- NO gateway protocol knowledge

## Migration Plan

1. Add new REST + SSE endpoints to server.js alongside existing WS proxy
2. Update chat.html to use REST + SSE
3. Update iOS to use REST + SSE
4. Remove old `/ws/gateway` proxy, `/api/chat-sign`, device auth code from clients
5. Remove DeviceIdentityManager from iOS (or keep for future non-chat use)

## Key Decisions

- **SSE over WebSocket for clients**: Simpler, works through all CDNs/proxies, no upgrade handshake issues. Server-to-client is the main flow; client-to-server is just POST.
- **Singleton gateway connection**: One WS connection managed by the server, not per-client. Reduces gateway load and auth complexity.
- **In-memory message buffer**: No database needed for chat history — gateway is the source of truth. Server keeps ~200 recent messages for quick page loads.
- **Auth stays as-is**: Web uses session cookies, iOS uses JWT. No changes needed.

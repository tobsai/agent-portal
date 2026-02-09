# Chat Interface Setup

## Overview

The chat interface allows you to interact with the OpenClaw gateway directly from the web browser. The architecture uses a client-side WebSocket connection from the browser to the OpenClaw gateway (via cloudflared tunnel).

## Architecture

```
Browser (talos.mtree.io/chat)
    ↓ WebSocket
Cloudflared Tunnel
    ↓
OpenClaw Gateway (localhost:18789)
```

## Setup Steps

### 1. Expose the OpenClaw Gateway via Cloudflared Tunnel

The OpenClaw gateway runs on `ws://localhost:18789` and needs to be accessible from the public internet.

#### Option A: Quick Tunnel (Temporary URL)
```bash
cloudflared tunnel --url ws://localhost:18789
```

This will output a temporary URL like: `https://xxxxx.trycloudflare.com`

#### Option B: Named Tunnel (Permanent URL)
```bash
# Create a tunnel
cloudflared tunnel create openclaw-gateway

# Configure the tunnel
# Edit ~/.cloudflared/config.yml:
tunnel: <TUNNEL_ID>
credentials-file: /path/to/credentials.json

ingress:
  - hostname: gateway.mtree.io
    service: ws://localhost:18789
  - service: http_status:404

# Route DNS
cloudflared tunnel route dns openclaw-gateway gateway.mtree.io

# Run the tunnel
cloudflared tunnel run openclaw-gateway
```

**Recommendation:** Use Option B for production with a subdomain like `gateway.mtree.io`

### 2. Configure Railway Environment Variable

Add the tunnel URL to Railway:

```bash
# Using Railway CLI
railway variables set GATEWAY_WS_URL=wss://gateway.mtree.io

# Or via Railway Dashboard:
# Project Settings → Variables → GATEWAY_WS_URL = wss://gateway.mtree.io
```

**Important:** Use `wss://` (WebSocket Secure) not `ws://` for production tunnels.

### 3. Deploy

```bash
git add .
git commit -m "Add chat interface"
git push
```

Railway will automatically deploy and restart the service.

## Testing Locally

1. Start the OpenClaw gateway (if not already running):
   ```bash
   # The gateway should already be running on localhost:18789
   ```

2. Create a local tunnel:
   ```bash
   cloudflared tunnel --url ws://localhost:18789
   ```

3. Set the environment variable:
   ```bash
   export GATEWAY_WS_URL=wss://xxxxx.trycloudflare.com
   ```

4. Start the agent portal:
   ```bash
   npm start
   ```

5. Visit `http://localhost:3847/chat` and log in.

## Authentication & Security

- **Web UI:** Protected by Google OAuth (same as dashboard)
- **Gateway WebSocket:** Requires auth token in query parameter
- **Token:** `e47aac9b981f6c8c842f05c2c0eb2607eec63c18be16f13c8498ac11973282a4` (stored in client-side code)

⚠️ **Security Note:** The auth token is visible in the client-side JavaScript. For production, consider moving the WebSocket connection to server-side relay or using short-lived tokens.

## OpenClaw Gateway Protocol

The chat UI uses the following message types:

### Client → Gateway

**Send message:**
```json
{
  "type": "chat.send",
  "message": "Your message here"
}
```

**Request history:**
```json
{
  "type": "chat.history"
}
```

### Gateway → Client

**Chat message:**
```json
{
  "type": "chat.message",
  "role": "assistant",
  "content": "Response text",
  "timestamp": "2026-02-09T18:05:00.000Z"
}
```

**Chat history:**
```json
{
  "type": "chat.history",
  "messages": [
    {
      "role": "user",
      "content": "Hello",
      "timestamp": "2026-02-09T18:05:00.000Z"
    },
    {
      "role": "assistant",
      "content": "Hi there!",
      "timestamp": "2026-02-09T18:05:05.000Z"
    }
  ]
}
```

**Error:**
```json
{
  "type": "error",
  "message": "Error description"
}
```

## Features

✅ **Implemented:**
- Clean iMessage-style UI with dark mode
- Google OAuth protection
- Real-time WebSocket connection
- Auto-reconnect on disconnect
- Message history loading
- Typing indicators
- Timestamp formatting
- Mobile responsive
- Auto-scroll to bottom

## Files Modified/Created

- **server.js:** Added `/chat` route and `/api/chat/config` endpoint
- **public/chat.html:** Full chat interface (new file)
- **public/dashboard.html:** Added "Chat" button to header
- **CHAT_SETUP.md:** This documentation (new file)

## Troubleshooting

**"Not configured" error:**
- Check that `GATEWAY_WS_URL` environment variable is set in Railway
- Verify the value starts with `wss://` (not `ws://`)
- Restart the Railway service after setting the variable

**"Connection error" / keeps reconnecting:**
- Verify the cloudflared tunnel is running
- Check the gateway is accessible: `curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" https://gateway.mtree.io`
- Check browser console for WebSocket errors

**Gateway not receiving messages:**
- Verify the auth token matches the gateway configuration
- Check gateway logs for authentication errors

## Next Steps (Optional Improvements)

1. **Server-side relay:** Move WebSocket connection to server-side to hide auth token
2. **Message persistence:** Store chat history in PostgreSQL
3. **Multi-user support:** Separate chat sessions per user
4. **File uploads:** Support sending images/files
5. **Rich formatting:** Markdown rendering in messages
6. **Notifications:** Browser notifications for new messages

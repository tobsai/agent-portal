# Agent Portal — Project Source of Truth
Last updated: 2026-02-22

## What This Is
Agent Portal is Talos's personal AI agent dashboard — a real-time web interface at `talos.mtree.io` that shows task status (Kanban-style), activity logs, sub-agent runs, scheduled jobs, and includes a WebSocket-based chat interface that connects directly to the OpenClaw gateway.

## Status
🟢 **Live** — running on Railway at https://talos.mtree.io. Google OAuth is live. Chat interface is built and deployed. WebSocket gateway proxy is operational.

## Stack
- **Runtime**: Node.js (CommonJS, `server.js`)
- **Framework**: Express 4
- **Auth**: Passport.js + Google OAuth 2.0 (`passport-google-oauth20`)
- **Sessions**: `express-session` + `connect-pg-simple` (PostgreSQL-backed sessions)
- **WebSocket**: `ws` library — two servers: `/ws` (portal updates) and `/ws/gateway` (proxy to OpenClaw gateway)
- **Database**: PostgreSQL in production (Railway), SQLite (`better-sqlite3`) in local dev
- **Observability**: Sentry (`@sentry/node`), PostHog analytics
- **Auth tokens**: JWT (`jsonwebtoken`) for API key validation

## Deployment
- **URL**: https://talos.mtree.io
- **Railway project**: `9d7b61b4-c326-4571-873f-cefa31e5ea7f`
- **Deploy**: Auto-deploy on `git push` to `main` via Railway GitHub integration
- **Health check**: `GET /api/health`
- **Key env vars**:
  - `DATABASE_URL` — PostgreSQL connection string (Railway-injected)
  - `SESSION_SECRET` — Express session + JWT secret
  - `GOOGLE_CLIENT_ID` / `GOOGLE_CLIENT_SECRET` — OAuth
  - `GATEWAY_WS_URL` — OpenClaw gateway WebSocket URL (e.g. `wss://gw.mtree.io`)
  - `SENTRY_DSN` — Error tracking
  - `FEATURE_ACTIVITY_DASHBOARD` — `true` to enable activity dashboard tab
- **API Key** (Talos's key): `ak_e83ddf5617724e41b80419e19037c2d0`

## Commands
```bash
npm install       # Install deps
npm start         # Start server (port from PORT env or 3000)
npm run dev       # Same — no hot-reload, restart manually
# No test suite, no lint config
```

## Current Focus / Next Steps
- Gateway WebSocket proxy (`/ws/gateway`) is live — chat interface connects to OpenClaw via `gw.mtree.io` tunnel
- Activity dashboard behind feature flag (`FEATURE_ACTIVITY_DASHBOARD=true`)
- Sub-agent tracking via `/api/subagents` endpoint
- Next: iOS companion app (bundle ID `com.mapletree.agent-portal`, Apple ID pending)

## Key Files & Structure
```
agent-portal/
├── server.js           # All backend logic — Express routes, WS servers, DB, auth
├── package.json
├── railway.json        # Railway deploy config (health check: /api/health)
├── lib/
│   └── posthog.js      # Analytics helper
├── public/
│   ├── dashboard.html  # MAIN PAGE — served at /. Two-panel layout: Live Sessions (left) + Chat (right, first-class). Activity timeline below, collapsed by default.
│   ├── index.html      # Kanban board UI (requires auth) — NOT the main landing page
│   ├── chat.html       # iMessage-style standalone chat (connects to gateway WS)
│   ├── game.html       # Game asset viewer — sprite/tileset browser with version support
│   ├── style.css
│   └── app.js
└── data/
    └── portal.db       # SQLite DB (local dev only — not used in production)
```

## Agent Rules
- **NEVER use `railway up` directly** — always `git push` to trigger Railway's GitHub-connected auto-deploy. Direct `railway up` breaks routing and causes outages.
- The gateway proxy (`/ws/gateway`) forwards WebSocket connections to `GATEWAY_WS_URL`. If chat is broken, check that env var and the cloudflared tunnel (`gw.mtree.io`).
- In production, sessions are stored in PostgreSQL (via `connect-pg-simple`). In local dev without `DATABASE_URL`, falls back to SQLite.
- Sentry is initialized before everything else — keep it at the top of `server.js`.
- API key format: `ak_` prefix + 32 hex chars. Stored in DB, validated on every write endpoint.
- The README still mentions SSE — the implementation now uses WebSocket (`ws`) not SSE. The README is slightly outdated.
- **dashboard.html is the root page (`/`)** — not index.html. index.html is the Kanban board, accessible via nav.
- **Chat in dashboard is first-class**: the right panel (`.panel-right`) embeds the chat iframe at 50% width. `.split-container` has `min-height: 55vh` to ensure chat is never cramped. The activity timeline below is collapsed by default.
- **game.html default asset**: `init()` prefers the first versioned asset (`a.version` truthy) over unversioned ones, since versioned assets (e.g. Hero sprite) render first in the sidebar. Falls back to `g.assets[0]` if no versioned asset exists.

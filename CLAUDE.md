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
- **⛔ NEVER run `railway up`** — it creates a new orphan service every time. Push to `main` and Railway handles the rest.
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
npm test          # Run test suite (vitest run)
npm run test:watch      # Watch mode
npm run test:coverage   # Coverage report (v8)
```

## Testing

**Stack**: [Vitest](https://vitest.dev/) v4 + [Supertest](https://github.com/ladjs/supertest)

**Approach**: Integration-style tests via Supertest — full Express app, real route handlers, in-memory SQLite (no live DB, no network calls). Mock at module boundaries (DB injected into `createApp()`), not inside functions.

**Test files**:
| File | What it covers |
|------|---------------|
| `tests/health.test.js` | `GET /api/health` — 200 + `{ status: 'ok' }` |
| `tests/auth.test.js` | `requireAuth` / `requireAgentKey` — missing token (401), invalid token (401), valid `ak_` key (200/201) |
| `tests/agents.test.js` | `GET /api/agents` — 200 + array, public endpoint (no auth required) |
| `tests/work.test.js` | `GET /api/work` — 200 with valid key, 401 without |

**Test helper**: `tests/helpers/createApp.js` — factory that wires an Express app with:
- In-memory SQLite (`:memory:`) — fully isolated, no disk I/O
- Seeded test agent (`ak_test_...`) for agent-key auth tests
- Inline `requireAuth` / `requireAgentKey` that use the test DB, not the `lib/db.js` singleton
- `broadcast = () => {}` no-op so WebSocket events don't fail silently

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

## ⚠️ Tech Debt & Architectural Problems

### ~~🔴 Critical: God Object — `server.js`~~ ✅ Resolved
Refactored from 2,136 → 908 lines. Routes now in `routes/` (health.js, agents.js, work.js, chat.js, scheduled.js); shared code in `lib/` (db.js, auth.js).

### ~~🔴 No Test Suite~~ ✅ Resolved
Vitest + Supertest suite added. 13 tests across 4 files. In-memory SQLite isolation. Run with `npm test`.

### 🟡 CI Workflow Is Wrong
`.github/workflows/deploy.yml` uses a Railway GraphQL mutation to force a deploy on push. This is unnecessary — Railway already auto-deploys via GitHub integration. Worse, if both run simultaneously, you risk duplicate deploys.
- **Fix**: Replace with `echo "Railway deploys via GitHub integration"` (no-op, like family-os) or delete the workflow entirely.

### 🟡 No Linting or Formatting Config
No ESLint config, no Prettier, no `devDependencies`. Code style is uncontrolled.
- **Suggested fix**: Add `eslint` + `eslint-config-node` minimal config. Single devDependency cost for significant long-term maintainability gain.

### 🟡 Dual Auth Concern: Session + JWT
The app uses both `express-session` (for browser OAuth flows) and JWT (for API key validation). This is common but the boundary is blurry — audit that every route uses the correct auth mechanism and neither is accidentally bypassed.

### 🟢 Minor: CommonJS in 2026
`server.js` uses `require()` throughout. Not wrong, but if this is ever split into modules, adopting ESM would align it with the rest of the stack (InkSight, newer Next.js projects all use ESM).

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

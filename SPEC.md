# Agent Portal — Product Spec
Last updated: 2026-03-11

## Vision & Goals
Talos's personal AI agent dashboard — real-time visibility into what the AI agent is doing, has done, and has planned. The primary surface is `talos.mtree.io`. Goal: give Toby a single window into agent activity with a first-class chat interface.

This is an **observability tool**, not a task manager. Think flight-deck, not Kanban.

## Current Status
🟢 **Live** at https://talos.mtree.io

- ✅ Google OAuth authentication
- ✅ WebSocket gateway proxy (`/ws/gateway` → `gw.mtree.io`)
- ✅ Real-time chat interface (first-class, 50% of dashboard width)
- ✅ Activity dashboard (behind `FEATURE_ACTIVITY_DASHBOARD=true`)
- ✅ Sub-agent tracking (`/api/subagents`)
- ✅ Scheduled task display
- ✅ Work items list
- ✅ Usage stats
- ✅ Game asset viewer (`/game.html`)
- 🔄 iOS companion app in development (see `agent-portal-ios` project)

## Key Features

### Dashboard (`/`)
Two-panel layout: Live Sessions (left) + Chat (right). Activity timeline below, collapsed by default. Chat is first-class — not an afterthought.

### Chat
iMessage-style interface. Connects to OpenClaw gateway via WebSocket proxy. Streaming message support. Also available standalone at `/chat.html`.

### Game Asset Viewer (`/game.html`)
Sprite and tileset browser with version support. Used to preview Echo Unchained game assets. Prefers versioned assets (renders hero first).

### API Endpoints
- `GET /api/health` — health check
- `GET /api/me` — authenticated user info
- `GET /api/work` — work items
- `GET /api/activity` — activity log
- `GET /api/scheduled` — scheduled tasks
- `GET /api/subagents` — sub-agent sessions
- `GET /api/usage` — current usage stats
- `POST /api/work` — create work item (requires API key)

## Technical Architecture

### Backend
- Express 4 + CommonJS (`server.js` — single file)
- Two WebSocket servers: `/ws` (portal updates) and `/ws/gateway` (gateway proxy)
- Sessions in PostgreSQL (`connect-pg-simple`) in prod; SQLite fallback in local dev
- JWT-based API key validation (`ak_` prefix + 32 hex chars)

### Frontend
- Vanilla HTML/CSS/JS (no build step)
- `public/dashboard.html` — root page (`/`)
- `public/index.html` — Kanban board (not the main page)

### Auth Flow
Google OAuth → Passport.js → session cookie → all protected routes

## Deployment
- **URL**: https://talos.mtree.io
- **Railway project**: `9d7b61b4-c326-4571-873f-cefa31e5ea7f`
- **Deploy**: `git push` to `main` (Railway GitHub auto-deploy)
- **Health check**: `/api/health`
- **API key**: `ak_e83ddf5617724e41b80419e19037c2d0`

### Required Environment Variables
| Var | Notes |
|-----|-------|
| `DATABASE_URL` | Railway PostgreSQL (auto-injected) |
| `SESSION_SECRET` | Express session + JWT secret |
| `GOOGLE_CLIENT_ID` | OAuth |
| `GOOGLE_CLIENT_SECRET` | OAuth |
| `GATEWAY_WS_URL` | `wss://gw.mtree.io` |
| `SENTRY_DSN` | Error tracking |
| `FEATURE_ACTIVITY_DASHBOARD` | `true` to enable activity tab |

## Known Limitations / Tech Debt
- `server.js` is monolithic — all routes, WS logic, and DB init in one file
- README references SSE but implementation uses WebSocket — README is outdated
- Local dev uses SQLite but prod uses PostgreSQL — slight schema divergence risk
- No automated tests
- Game asset viewer is a bit of a bolt-on — not deeply integrated

## Roadmap / Next Steps
1. iOS companion app (`agent-portal-ios`) — native SwiftUI, already in progress
2. Activity dashboard feature flag → GA when stable
3. Refactor `server.js` into route modules (when complexity demands it)
4. Add pagination to activity log (grows unbounded)
5. Consider notifications (push via iOS app or email digest)

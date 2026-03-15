# Agent Portal Chat Refactor Spec

## Goal
Strip the agent-portal down to TWO features only:
1. **Real-time chat** with channels
2. **Low-latency voice chat** via ElevenLabs

Everything else (dashboard, tasks, architecture, docs, game assets) gets removed.

## Architecture

### Stack (unchanged)
- Express + PostgreSQL + Socket.io/WebSocket
- Google OAuth (web) + JWT (mobile/embedded)
- Railway deployment

### Database Changes
**KEEP**: users, sessions, agents, usage_records
**REMOVE**: work_items, activity, scheduled, subagents, someday_maybe, scheduled_tasks, tool_usage, subagent_activity, thread_activity, live_sessions, docs

**NEW TABLES**:
```sql
CREATE TABLE IF NOT EXISTS channels (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL UNIQUE,
  description TEXT DEFAULT '',
  created_by TEXT REFERENCES users(id),
  is_default BOOLEAN DEFAULT false,
  created_at TIMESTAMPTZ DEFAULT NOW()
);

CREATE TABLE IF NOT EXISTS channel_members (
  channel_id TEXT REFERENCES channels(id) ON DELETE CASCADE,
  user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
  joined_at TIMESTAMPTZ DEFAULT NOW(),
  PRIMARY KEY (channel_id, user_id)
);

CREATE TABLE IF NOT EXISTS messages (
  id TEXT PRIMARY KEY,
  channel_id TEXT REFERENCES channels(id) ON DELETE CASCADE,
  sender_type TEXT NOT NULL, -- 'user' or 'agent'
  sender_id TEXT NOT NULL,   -- user.id or agent name (e.g. 'lewis')
  sender_name TEXT NOT NULL,
  sender_emoji TEXT,         -- agent-specific emoji (📚 for Lewis)
  content TEXT NOT NULL,
  mentions TEXT[] DEFAULT '{}', -- array of @-mentioned agent/user IDs
  created_at TIMESTAMPTZ DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_messages_channel ON messages(channel_id, created_at DESC);
```

### API Routes

**KEEP**:
- `GET /` → redirect to `/c` (chat)
- `GET /c` → chat.html
- Auth routes (Google OAuth + JWT)
- `GET /api/me`
- `GET /api/health`
- WebSocket gateway proxy (`/ws/gateway`)
- Chat API endpoints (refactored for channels)

**NEW**:
- `GET /api/channels` — list channels user belongs to
- `POST /api/channels` — create channel
- `DELETE /api/channels/:id` — delete channel
- `POST /api/channels/:id/join` — join channel
- `POST /api/channels/:id/leave` — leave channel
- `GET /api/channels/:id/messages?limit=50&before=<cursor>` — paginated messages
- `POST /api/channels/:id/messages` — send message to channel
- `GET /api/channels/:id/stream` — SSE stream for channel

**REMOVE**: All dashboard, tasks, docs, game, architecture, activity, scheduled, subagent, usage, tool-usage routes.

### Real-time Events (SSE per channel)
- `message` — new message in channel
- `typing` — agent is typing (includes agent emoji)
- `presence` — user/agent online/offline
- `channel.update` — channel metadata changed

### Chat Features
1. **Speech bubbles** — user messages right-aligned (indigo), agent messages left-aligned (dark surface)
2. **Typing indicator** — shows agent emoji (📚 for Lewis) + bouncing dots
3. **Channels** — sidebar with user-created channels, click to switch
4. **@-mentions** — type `@` to get autocomplete of agents + users. Mentioned agents get the message routed to them.
5. **Message history** — persisted in PostgreSQL, paginated loading

### Voice Features
1. **ElevenLabs WebSocket streaming** — use `wss://api.elevenlabs.io/v1/text-to-speech/{voice_id}/stream-input` for lowest latency
2. **STT** — Browser Web Speech API or Deepgram for speech-to-text
3. **Push-to-talk** — hold mic button to speak, release to send
4. **Auto-play responses** — stream TTS audio as it arrives
5. **Voice activity indicator** — show waveform when agent is speaking

### Agents Registry
For @-mention autocomplete and routing:
```javascript
const AGENTS = [
  { id: 'lewis', name: 'Lewis', emoji: '📚' },
  { id: 'marty', name: 'Marty', emoji: '🔬' },
  { id: 'echo', name: 'Echo', emoji: '🎮' }
];
```

### Web UI Layout
```
┌─────────────────────────────────────────┐
│ Header: Lewis logo + connection status  │
├──────┬──────────────────────────────────┤
│      │                                  │
│  CH  │     Message area                 │
│  AN  │     (speech bubbles)             │
│  NE  │                                  │
│  LS  │     📚 ···  (typing indicator)   │
│      │                                  │
│  #g  ├──────────────────────────────────┤
│  #d  │ 📎 [message input...] 🎙️ ➤     │
│  +   │                                  │
├──────┴──────────────────────────────────┤
```

### Electron App
- Electron wrapper around `https://talos.mtree.io/c`
- Window: 1200x800 default, resizable
- Tray icon with unread badge
- Native notifications for new messages
- Auto-update via electron-updater (later)

### iOS App Updates
- Strip to chat + voice only (same as web)
- WKWebView pointing to `/c?embed=1&token=<jwt>`
- Voice button integration with native audio

# SUBAGENT_API_GAP.md

## Gap: Native Gateway Sub-Agent List API

**Date documented:** 2026-03-18  
**Feature:** Sub-Agent Tree View (`GET /api/subagents`)  
**Status:** Implemented with signals-based workaround

---

## The Gap

The OpenClaw Gateway does not expose a native API method for listing active or recent sub-agent sessions. The native gateway client (`lib/gateway-client.js`) supports:

- `chat.send` — send a message to an agent session
- `chat.history` — fetch session message history
- `chat.inject` — inject a note without triggering an agent run

There is **no** equivalent of:
- `sessions.list` — list all sessions with status, runtime, model, token counts
- `sessions.get(id)` — get details for a specific session
- `subagents.list` — enumerate child sessions spawned from a parent

A `_request('sessions.list', {})` call would return a gateway error or time out.

---

## Current Implementation (Signals-Based Workaround)

`GET /api/subagents` builds the agent tree from the **signals** table in the portal's own PostgreSQL database. Agents and sub-agents that POST to `POST /api/signals` with structured metadata in the `metadata` field allow the portal to reconstruct the spawn hierarchy.

### How the tree is built

1. Query all `signals` rows where `metadata IS NOT NULL`
2. Parse each signal's `metadata` JSON looking for:
   - `metadata.type` — `spawn | subagent_start | subagent_end | subagent_error | done | complete | error`
   - `metadata.label` or `metadata.name` — human-readable agent label
   - `metadata.model` — model identifier (e.g. `anthropic/claude-sonnet-4-6`)
   - `metadata.status` — agent status
   - `metadata.tokenCount` or `metadata.tokens` — token usage
   - `metadata.parent_session` or `metadata.parentSession` — parent session key (for tree edges)
3. Also scan `DISTINCT session_key` from all signals to detect known patterns:
   - `agent:main` — root agent
   - `agent:main:subagent:<uuid>` — sub-agent spawned from main
   - `agent:main:cron:<uuid>` — cron-spawned session
4. Build a node map keyed by session key, wire parent→child relationships
5. Return a depth-first tree with roots at the top

### Limitation

The tree only shows agents that **have emitted signals** via the portal. Agents that:
- Run entirely inside the gateway without POSTing signals
- Are not connected via the portal channel (`portal:dm-lewis` etc.)
- Finish before posting any signal

...will not appear in the tree.

This is why the tree may appear sparse for fast sub-agents or offline sessions.

---

## What a Native API Would Provide

If the gateway exposed `sessions.list`, we could return:

```json
{
  "sessions": [
    {
      "sessionKey": "agent:main:subagent:8c35909d-...",
      "label": "marty-subagent-tree-view",
      "status": "active",
      "model": "anthropic/claude-sonnet-4-6",
      "totalTokens": 12450,
      "startedAt": "2026-03-18T19:26:00Z",
      "endedAt": null,
      "parentSessionKey": "agent:main:cron:fa4b90c5-...",
      "task": "Build Sub-Agent Tree View for Agent Portal..."
    }
  ]
}
```

This would be richer and more reliable than signal inference:
- Real-time token counts from the gateway's LLM context
- Accurate start/end timestamps from the session lifecycle
- Parent-child relationships natively tracked by the gateway
- Agents that don't emit signals would still appear

---

## TODO: When Gateway Supports Native Session Listing

In `routes/agents.js`, the `GET /api/subagents` handler should:

1. Call `gatewayClient._request('sessions.list', { includeEnded: true, since: req.query.since })`
2. Map the response to the `AgentNode` shape (see `lib/types.js`)
3. Fall back to the signals-based approach if the method returns a gateway error (for backward compat)

```js
// TODO: Replace signals-based tree with native gateway sessions.list when available.
// See docs/SUBAGENT_API_GAP.md for full context.
// try {
//   const data = await gatewayClient._request('sessions.list', { includeEnded: true });
//   return res.json(buildTreeFromSessions(data.sessions));
// } catch (err) {
//   if (err.message.includes('unknown method')) { /* fall through to signals */ }
//   else throw err;
// }
```

---

## Signals Contract (for Agent Authors)

To appear correctly in the tree, agents should POST to `/api/signals` with metadata:

```json
{
  "level": "info",
  "message": "Sub-agent started: marty-subagent-tree-view",
  "session_key": "agent:main:subagent:8c35909d-...",
  "metadata": {
    "type": "spawn",
    "label": "marty-subagent-tree-view",
    "model": "anthropic/claude-sonnet-4-6",
    "parent_session": "agent:main:cron:fa4b90c5-...",
    "status": "active"
  }
}
```

And on completion:

```json
{
  "level": "success",
  "message": "Sub-agent done",
  "session_key": "agent:main:subagent:8c35909d-...",
  "metadata": {
    "type": "subagent_end",
    "status": "done",
    "tokenCount": 12450
  }
}
```

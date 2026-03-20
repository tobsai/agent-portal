# PLUGIN_INSTALL_READY.md

**Package:** `openclaw-channel-agent-portal`  
**Verified by:** Pascal (NEXT-028)  
**Date:** 2026-03-19  
**Status:** ✅ READY TO INSTALL

---

## Summary

The `openclaw-channel-agent-portal` plugin package has been verified and built. It is ready for Lewis to install into the OpenClaw extensions directory.

---

## What Was Done

### Issues Found and Fixed

1. **`dist/` directory was missing** — The package uses TypeScript (`index.ts`) and requires a build step. `dist/index.js` did not exist. Fixed by installing `typescript` as a dev dependency and running `npm run build`. The compiled output now exists at `dist/index.js` with full CommonJS exports and type declarations (`dist/index.d.ts`).

2. **`openclaw.plugin.json` had wrong `main` field** — It pointed to `"index.js"` (the raw TypeScript source root, which is not executable). Fixed to `"dist/index.js"` to match `package.json`.

### Verification Checklist

| Check | Result |
|-------|--------|
| `package.json` `name` field | ✅ `openclaw-channel-agent-portal` |
| `package.json` `main` field | ✅ `dist/index.js` |
| `dist/index.js` exists | ✅ Built from TypeScript source |
| CommonJS exports present | ✅ `createPlugin` + `default` |
| No hardcoded prod-breaking URLs | ✅ `portalUrl` is runtime config; `127.0.0.1` for webhook listener is correct (local-only) |
| No dev-only requires | ✅ Only `http`, `https`, `crypto` (Node built-ins) |
| `openclaw.plugin.json` `main` | ✅ Fixed to `dist/index.js` |
| Node can `require()` the package | ✅ Verified |

---

## openclaw.json Config Lewis Must Add

Add the following to `~/.openclaw/openclaw.json`:

```json
{
  "channels": {
    "portal": {
      "enabled": true,
      "streaming": "partial",
      "dmPolicy": "open",
      "allowFrom": ["*"],
      "portalUrl": "https://talos.mtree.io",
      "apiKey": "ak_e83ddf5617724e41b80419e19037c2d0",
      "webhookSecret": "<generate-a-random-secret>",
      "webhookPort": 3001
    }
  },
  "bindings": [
    { "agentId": "lewis", "channel": "portal", "target": "user" }
  ]
}
```

> ⚠️ **`webhookSecret`** must be a random string you generate (e.g. `openssl rand -hex 32`). This same value must be set as `WEBHOOK_SECRET` in the Agent Portal Railway environment variables so the portal can sign inbound webhook POSTs.

---

## Extension Install Path

The package must be placed (or symlinked) at:

```
/opt/homebrew/lib/node_modules/openclaw/extensions/portal/
```

The full package directory is at:

```
~/projects/agent-portal/packages/openclaw-channel-agent-portal/
```

Suggested install command:

```bash
ln -s ~/projects/agent-portal/packages/openclaw-channel-agent-portal \
  /opt/homebrew/lib/node_modules/openclaw/extensions/portal
```

Or copy if symlinks are not supported by the extension loader.

---

## Remaining Blockers (Non-Package)

These are **not package issues** — the plugin code itself is correct — but they must be in place for end-to-end function:

1. **`WEBHOOK_SECRET` env var on Railway** — Must match `webhookSecret` in `openclaw.json`. The portal server must POST to `http://127.0.0.1:3001/inbound` on the Mac Mini where OpenClaw runs.

2. **`WEBHOOK_URL` env var on Railway** — The Agent Portal server must know where to send inbound webhook events. Set to `http://127.0.0.1:3001/inbound` (or the appropriate reachable address if portal runs remotely — but since both run on the Mac Mini, localhost is correct).

3. **Phase 2 TODO in `server.js`** — Per `CHANNEL_PLUGIN_PROPOSAL.md`, DM channel resolution for native client events is deferred (~line 544, commented "channel lookup deferred to Phase 2"). The plugin sends and receives correctly, but the portal server side must complete this wiring for the full round-trip.

4. **OpenClaw extension loader** — The extension loading mechanism (local path vs. npm-published) should be confirmed. The Slack plugin pattern suggests the directory name (`portal`) must match the channel ID declared in `openclaw.plugin.json` (`"id": "portal"`). ✅ These match.

---

## Package File Manifest

```
packages/openclaw-channel-agent-portal/
├── dist/
│   ├── index.js          ← compiled CommonJS (main entry)
│   └── index.d.ts        ← TypeScript declarations
├── node_modules/
│   └── typescript/       ← dev dependency (build only)
├── index.ts              ← TypeScript source
├── openclaw.plugin.json  ← plugin manifest (fixed)
├── package.json          ← npm manifest
└── package-lock.json
```

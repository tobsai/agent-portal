"use strict";
/**
 * openclaw-channel-agent-portal
 *
 * OpenClaw channel plugin for the Agent Portal.
 *
 * Bridges OpenClaw's ChannelPlugin interface to the Agent Portal HTTP API,
 * enabling the gateway to deliver outbound messages to iOS clients subscribed
 * to the portal SSE stream, and to receive inbound messages from iOS clients.
 *
 * Required openclaw.json config:
 * ──────────────────────────────
 *   "channels": {
 *     "portal": {
 *       "enabled": true,
 *       "streaming": "partial",
 *       "dmPolicy": "open",
 *       "allowFrom": ["*"],
 *       "portalUrl": "https://talos.mtree.io",
 *       "apiKey": "ak_e83ddf5617724e41b80419e19037c2d0",
 *       "webhookSecret": "<random-secret>",
 *       "webhookPort": 3001
 *     }
 *   },
 *   "bindings": [
 *     { "agentId": "lewis", "channel": "portal", "target": "user" }
 *   ]
 *
 * NOTE: The extension directory must be symlinked or copied into
 *   /opt/homebrew/lib/node_modules/openclaw/extensions/portal/
 * OR registered via the extensions config key (pending OpenClaw support).
 */
var __createBinding = (this && this.__createBinding) || (Object.create ? (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    var desc = Object.getOwnPropertyDescriptor(m, k);
    if (!desc || ("get" in desc ? !m.__esModule : desc.writable || desc.configurable)) {
      desc = { enumerable: true, get: function() { return m[k]; } };
    }
    Object.defineProperty(o, k2, desc);
}) : (function(o, m, k, k2) {
    if (k2 === undefined) k2 = k;
    o[k2] = m[k];
}));
var __setModuleDefault = (this && this.__setModuleDefault) || (Object.create ? (function(o, v) {
    Object.defineProperty(o, "default", { enumerable: true, value: v });
}) : function(o, v) {
    o["default"] = v;
});
var __importStar = (this && this.__importStar) || (function () {
    var ownKeys = function(o) {
        ownKeys = Object.getOwnPropertyNames || function (o) {
            var ar = [];
            for (var k in o) if (Object.prototype.hasOwnProperty.call(o, k)) ar[ar.length] = k;
            return ar;
        };
        return ownKeys(o);
    };
    return function (mod) {
        if (mod && mod.__esModule) return mod;
        var result = {};
        if (mod != null) for (var k = ownKeys(mod), i = 0; i < k.length; i++) if (k[i] !== "default") __createBinding(result, mod, k[i]);
        __setModuleDefault(result, mod);
        return result;
    };
})();
Object.defineProperty(exports, "__esModule", { value: true });
exports.createPlugin = createPlugin;
const http = __importStar(require("http"));
const https = __importStar(require("https"));
// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
/**
 * Derive the portal channel ID for a given gateway session key.
 *
 * The session key encodes the agent ID in the form `portal:dm-<agentId>`.
 * We POST to `/api/channels` search or resolve endpoint on the portal to
 * find the matching DM channel UUID.
 *
 * Resolved channel IDs are cached in-process for the lifetime of the plugin
 * to avoid repeated HTTP round-trips on every outbound message.
 */
const channelIdCache = new Map();
async function resolveChannelId(portalUrl, apiKey, sessionKey) {
    const cached = channelIdCache.get(sessionKey);
    if (cached)
        return cached;
    // Derive agentId from sessionKey: "portal:dm-lewis" → "lewis"
    const agentId = sessionKey.replace(/^portal:dm-/, '');
    if (!agentId || agentId === sessionKey) {
        throw new Error(`[portal-plugin] Cannot derive agentId from sessionKey "${sessionKey}". ` +
            `Expected format: "portal:dm-<agentId>"`);
    }
    const url = `${portalUrl}/api/dm/${encodeURIComponent(agentId)}`;
    const data = await httpGet(url, apiKey);
    const parsed = JSON.parse(data);
    if (!parsed?.id) {
        throw new Error(`[portal-plugin] Portal returned no channel ID for agentId "${agentId}"`);
    }
    channelIdCache.set(sessionKey, parsed.id);
    return parsed.id;
}
/** Minimal HTTP GET helper — avoids runtime dependency on node-fetch / axios. */
function httpGet(url, apiKey) {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const lib = parsed.protocol === 'https:' ? https : http;
        const options = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path: parsed.pathname + parsed.search,
            method: 'GET',
            headers: {
                Authorization: `Bearer ${apiKey}`,
                Accept: 'application/json',
            },
        };
        const req = lib.request(options, (res) => {
            let body = '';
            res.on('data', (chunk) => { body += chunk.toString(); });
            res.on('end', () => {
                if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                    resolve(body);
                }
                else {
                    reject(new Error(`[portal-plugin] GET ${url} → HTTP ${res.statusCode}: ${body}`));
                }
            });
        });
        req.on('error', reject);
        req.end();
    });
}
/** Minimal HTTP POST helper — posts JSON, returns response body. */
function httpPost(url, apiKey, body) {
    return new Promise((resolve, reject) => {
        const parsed = new URL(url);
        const lib = parsed.protocol === 'https:' ? https : http;
        const payload = JSON.stringify(body);
        const options = {
            hostname: parsed.hostname,
            port: parsed.port || (parsed.protocol === 'https:' ? 443 : 80),
            path: parsed.pathname + parsed.search,
            method: 'POST',
            headers: {
                Authorization: `Bearer ${apiKey}`,
                'Content-Type': 'application/json',
                'Content-Length': Buffer.byteLength(payload),
                Accept: 'application/json',
            },
        };
        const req = lib.request(options, (res) => {
            let responseBody = '';
            res.on('data', (chunk) => { responseBody += chunk.toString(); });
            res.on('end', () => {
                if (res.statusCode && res.statusCode >= 200 && res.statusCode < 300) {
                    resolve(responseBody);
                }
                else {
                    reject(new Error(`[portal-plugin] POST ${url} → HTTP ${res.statusCode}: ${responseBody}`));
                }
            });
        });
        req.on('error', reject);
        req.write(payload);
        req.end();
    });
}
// ---------------------------------------------------------------------------
// Implementation
// ---------------------------------------------------------------------------
class AgentPortalChannelPlugin {
    constructor(config) {
        this.channelId = 'portal';
        this.webhookServer = null;
        this.portalUrl = config.portalUrl.replace(/\/$/, '');
        this.apiKey = config.apiKey;
        this.webhookSecret = config.webhookSecret;
        this.webhookPort = config.webhookPort ?? 3001;
    }
    /**
     * Deliver an outbound message from the agent to iOS clients via the portal.
     *
     * Flow:
     *   1. Resolve the portal channel UUID from the gateway session key
     *      (uses in-process cache after first lookup).
     *   2. POST message to `/api/channels/:channelId/messages` with the
     *      agent API key. The portal fans it out to SSE subscribers and
     *      sends an APNs push notification.
     *
     * The `isDelta` flag maps to partial streaming: when true, the portal
     * emits an `event: delta` SSE frame instead of a full `event: message`.
     * This requires the portal to support a `?delta=true` query param or
     * a `X-Delta: true` header on the POST — implemented on the portal side
     * in Phase 2c as `broadcastChannelEvent(channelId, 'delta', ...)`.
     *
     * NOTE: If the portal does not yet support native delta delivery over
     * the `/api/channels/:id/messages` REST surface, full messages are sent
     * on every call and isDelta is logged but not forwarded. The SSE delta
     * path on the iOS client will accumulate them correctly regardless.
     */
    async send(message) {
        let channelId;
        try {
            channelId = await resolveChannelId(this.portalUrl, this.apiKey, message.sessionKey);
        }
        catch (err) {
            console.error('[portal-plugin] send() — channel resolution failed:', err);
            // Do not swallow: let the caller (gateway) handle the delivery failure.
            throw err;
        }
        const body = {
            content: message.text,
            sender_type: 'agent',
            idempotency_key: message.id,
        };
        if (message.isDelta) {
            body.is_delta = true;
        }
        try {
            await httpPost(`${this.portalUrl}/api/channels/${channelId}/messages`, this.apiKey, body);
            console.log(`[portal-plugin] send() → channel ${channelId}` +
                ` (${message.isDelta ? 'delta' : 'full'}, id=${message.id})`);
        }
        catch (err) {
            console.error('[portal-plugin] send() — HTTP POST failed:', err);
            throw err;
        }
    }
    /**
     * Register an inbound webhook listener for messages arriving from iOS clients.
     *
     * The portal POSTs to `http://127.0.0.1:<webhookPort>/inbound` each time a
     * user sends a message to a DM channel. This plugin verifies the request
     * signature (HMAC-SHA256 of the raw body using `webhookSecret`) and then
     * invokes `handler(text, sessionKey)` so the gateway can route the message
     * to the correct agent session.
     *
     * Webhook payload (from portal):
     * ```json
     * {
     *   "id": "<event-uuid>",
     *   "channelId": "<channel-uuid>",
     *   "agentId": "lewis",
     *   "sessionKey": "portal:dm-lewis",
     *   "text": "Hello, Lewis!",
     *   "receivedAt": "2026-03-18T11:00:00.000Z"
     * }
     * ```
     *
     * Signature verification:
     *   The portal sets `X-Portal-Signature: sha256=<hex>` on every POST.
     *   This is HMAC-SHA256 of the raw request body using `webhookSecret`.
     *   Requests with missing or invalid signatures are rejected with HTTP 401.
     *
     * NOTE: The portal server must be configured with:
     *   - `WEBHOOK_URL=http://127.0.0.1:<webhookPort>/inbound`
     *   - `WEBHOOK_SECRET=<same value as webhookSecret in this config>`
     *
     * The webhook listener is started once and remains active for the plugin lifetime.
     * Calling `onInbound()` a second time replaces the handler but does not
     * create a second listener.
     */
    onInbound(handler) {
        if (this.webhookServer) {
            // Replace handler on an already-running server by re-registering.
            // The server reference is reused; only the handler closure changes.
            console.log('[portal-plugin] onInbound() — replacing existing handler');
        }
        this.webhookServer = this.startWebhookServer(handler);
        console.log(`[portal-plugin] onInbound() — webhook listener on port ${this.webhookPort}`);
    }
    // ---------------------------------------------------------------------------
    // Private: webhook HTTP server
    // ---------------------------------------------------------------------------
    startWebhookServer(handler) {
        if (this.webhookServer) {
            this.webhookServer.close();
        }
        const server = http.createServer((req, res) => {
            if (req.method !== 'POST' || req.url !== '/inbound') {
                res.writeHead(404);
                res.end();
                return;
            }
            let rawBody = '';
            req.on('data', (chunk) => { rawBody += chunk.toString(); });
            req.on('end', () => {
                // Verify HMAC-SHA256 signature
                const signature = req.headers['x-portal-signature'];
                if (!this.verifySignature(rawBody, signature)) {
                    console.warn('[portal-plugin] webhook — signature verification failed');
                    res.writeHead(401, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Invalid signature' }));
                    return;
                }
                let event;
                try {
                    event = JSON.parse(rawBody);
                }
                catch {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Invalid JSON' }));
                    return;
                }
                if (!event.text || !event.sessionKey) {
                    res.writeHead(400, { 'Content-Type': 'application/json' });
                    res.end(JSON.stringify({ error: 'Missing required fields: text, sessionKey' }));
                    return;
                }
                console.log(`[portal-plugin] webhook ← inbound (sessionKey=${event.sessionKey}, ` +
                    `channelId=${event.channelId}, len=${event.text.length})`);
                // Acknowledge immediately; invoke handler asynchronously to avoid
                // blocking the HTTP response on agent processing time.
                res.writeHead(200, { 'Content-Type': 'application/json' });
                res.end(JSON.stringify({ ok: true }));
                // Invoke in next tick so the HTTP response is flushed first.
                setImmediate(() => {
                    try {
                        handler(event.text, event.sessionKey);
                    }
                    catch (err) {
                        console.error('[portal-plugin] inbound handler threw:', err);
                    }
                });
            });
            req.on('error', (err) => {
                console.error('[portal-plugin] webhook request error:', err);
                res.writeHead(500);
                res.end();
            });
        });
        server.listen(this.webhookPort, '127.0.0.1', () => {
            console.log(`[portal-plugin] webhook server listening on 127.0.0.1:${this.webhookPort}`);
        });
        server.on('error', (err) => {
            if (err.code === 'EADDRINUSE') {
                console.error(`[portal-plugin] webhook port ${this.webhookPort} already in use. ` +
                    `Set a different webhookPort in openclaw.json channels.portal config.`);
            }
            else {
                console.error('[portal-plugin] webhook server error:', err);
            }
        });
        return server;
    }
    /**
     * Verify the HMAC-SHA256 signature from the portal.
     * Expected header: `X-Portal-Signature: sha256=<hex>`
     */
    verifySignature(body, signature) {
        if (!signature || Array.isArray(signature))
            return false;
        const [prefix, receivedHex] = signature.split('=');
        if (prefix !== 'sha256' || !receivedHex)
            return false;
        // Use Node's built-in crypto — no runtime dependency.
        // eslint-disable-next-line @typescript-eslint/no-require-imports
        const crypto = require('crypto');
        const expected = crypto
            .createHmac('sha256', this.webhookSecret)
            .update(body, 'utf8')
            .digest('hex');
        // Constant-time comparison to prevent timing attacks.
        try {
            return crypto.timingSafeEqual(Buffer.from(receivedHex, 'hex'), Buffer.from(expected, 'hex'));
        }
        catch {
            // Buffer lengths differ → invalid hex or mismatched lengths.
            return false;
        }
    }
}
// ---------------------------------------------------------------------------
// Export
// ---------------------------------------------------------------------------
/**
 * Factory function invoked by the OpenClaw runtime to create the plugin.
 * Receives the merged config from `channels.portal` in `openclaw.json`.
 */
function createPlugin(config) {
    return new AgentPortalChannelPlugin(config);
}
exports.default = createPlugin;

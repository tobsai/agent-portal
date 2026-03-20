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
/**
 * Configuration injected by the OpenClaw runtime from openclaw.json.
 * All fields map to the `channels.portal` config block.
 */
export interface PluginConfig {
    /** Base URL of the Agent Portal server, e.g. "https://talos.mtree.io" */
    portalUrl: string;
    /** Agent API key (ak_...) issued by the portal */
    apiKey: string;
    /**
     * Shared secret used to verify inbound webhook requests from the portal.
     * The portal signs each request with HMAC-SHA256; this value must match
     * `WEBHOOK_SECRET` in the portal's environment.
     */
    webhookSecret: string;
    /**
     * Local port for the inbound webhook HTTP listener.
     * The portal must be configured to POST to http://127.0.0.1:<webhookPort>/inbound.
     * Defaults to 3001 if not specified.
     */
    webhookPort?: number;
}
/**
 * Represents an inbound message event received from an iOS client via the portal.
 */
export interface ChannelEvent {
    /** Unique event ID (UUID v4) */
    id: string;
    /** Portal channel UUID the message was sent to */
    channelId: string;
    /** Agent ID derived from the channel's dm_agent_id field */
    agentId: string;
    /** Gateway session key for routing this message to the correct agent session */
    sessionKey: string;
    /** Plain-text message content */
    text: string;
    /** ISO-8601 timestamp of when the portal received the message */
    receivedAt: string;
}
interface OutboundMessage {
    id: string;
    sessionKey: string;
    text: string;
    isDelta?: boolean;
}
interface ChannelPlugin {
    channelId: string;
    send(message: OutboundMessage): Promise<void>;
    onInbound?(handler: (text: string, sessionKey: string) => void): void;
}
/**
 * Factory function invoked by the OpenClaw runtime to create the plugin.
 * Receives the merged config from `channels.portal` in `openclaw.json`.
 */
export declare function createPlugin(config: PluginConfig): ChannelPlugin;
export default createPlugin;

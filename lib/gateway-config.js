'use strict';

const fs = require('fs');
const path = require('path');

function resolveGatewayUrl() {
  return process.env.GATEWAY_WS_URL_LOCAL
    || process.env.GATEWAY_WS_URL?.replace(/^http/, 'ws')
    || 'ws://127.0.0.1:18789';
}

function resolveGatewayOrigin(gatewayUrl = resolveGatewayUrl()) {
  if (process.env.GATEWAY_ORIGIN) return process.env.GATEWAY_ORIGIN;
  try {
    const url = new URL(gatewayUrl);
    url.protocol = url.protocol === 'wss:' ? 'https:' : 'http:';
    url.pathname = '/';
    url.search = '';
    url.hash = '';
    return url.origin;
  } catch {
    return undefined;
  }
}

function resolveGatewayToken() {
  if (process.env.GATEWAY_TOKEN) return process.env.GATEWAY_TOKEN;
  try {
    const cfgPath = path.join(process.env.HOME || '~', '.openclaw', 'openclaw.json');
    const cfg = JSON.parse(fs.readFileSync(cfgPath, 'utf8'));
    const auth = cfg?.gateway?.auth || {};
    return auth.token || auth.password || '';
  } catch {
    return '';
  }
}

function normalizeGatewayWsUrl(rawUrl = '') {
  return rawUrl.trim().replace(/^https?/, 'ws').replace(/^(?!wss?:\/\/)/, 'wss://');
}

module.exports = {
  normalizeGatewayWsUrl,
  resolveGatewayOrigin,
  resolveGatewayToken,
  resolveGatewayUrl
};

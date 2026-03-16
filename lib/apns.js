/**
 * Apple Push Notification Service (APNs) client using HTTP/2.
 * Uses the P8 signing key for JWT-based authentication.
 */

const crypto = require('crypto');
const http2 = require('http2');
const fs = require('fs');
const path = require('path');

// APNs configuration
const APNS_HOST = process.env.APNS_HOST || 'api.sandbox.push.apple.com'; // Use api.push.apple.com for production
const APNS_PORT = 443;
const KEY_ID = process.env.APNS_KEY_ID || '26F3CKN67P';
const TEAM_ID = process.env.APNS_TEAM_ID; // Apple Developer Team ID (10-char alphanumeric, e.g. 'ABCDE12345')
const BUNDLE_ID = process.env.APNS_BUNDLE_ID || 'com.mapletree.agent-portal';

let signingKey = null;
let jwtToken = null;
let jwtIssuedAt = 0;

/**
 * Load the P8 signing key from disk.
 */
function loadSigningKey() {
  if (signingKey) return signingKey;
  
  // Try environment variable first (for Railway/production)
  if (process.env.APNS_SIGNING_KEY) {
    try {
      const keyData = process.env.APNS_SIGNING_KEY.replace(/\\n/g, '\n');
      signingKey = crypto.createPrivateKey({
        key: keyData,
        format: 'pem'
      });
      console.log('[APNs] Signing key loaded from APNS_SIGNING_KEY env');
      return signingKey;
    } catch (err) {
      console.error('[APNs] Failed to parse APNS_SIGNING_KEY:', err.message);
    }
  }
  
  // Fall back to file path
  const keyPath = process.env.APNS_KEY_PATH || path.join(process.env.HOME || '/root', '.openclaw/credentials/AuthKey_26F3CKN67P.p8');
  
  try {
    const keyData = fs.readFileSync(keyPath, 'utf8');
    signingKey = crypto.createPrivateKey({
      key: keyData,
      format: 'pem'
    });
    console.log('[APNs] Signing key loaded from', keyPath);
    return signingKey;
  } catch (err) {
    console.error('[APNs] Failed to load signing key:', err.message);
    return null;
  }
}

/**
 * Generate a JWT token for APNs authentication.
 * Tokens are valid for up to 60 minutes; we refresh at 50 minutes.
 */
function getJWT() {
  const now = Math.floor(Date.now() / 1000);
  
  // Refresh if older than 50 minutes
  if (jwtToken && (now - jwtIssuedAt) < 3000) {
    return jwtToken;
  }
  
  const key = loadSigningKey();
  if (!key) return null;
  
  const header = Buffer.from(JSON.stringify({
    alg: 'ES256',
    kid: KEY_ID,
    typ: 'JWT'
  })).toString('base64url');
  
  const payload = Buffer.from(JSON.stringify({
    iss: TEAM_ID,
    iat: now
  })).toString('base64url');
  
  const sigInput = `${header}.${payload}`;
  const signature = crypto.sign('SHA256', Buffer.from(sigInput), key);
  
  // ES256 signature needs to be converted from DER to raw r||s format
  const rawSig = derToRaw(signature);
  
  jwtToken = `${sigInput}.${rawSig.toString('base64url')}`;
  jwtIssuedAt = now;
  
  console.log('[APNs] JWT refreshed');
  return jwtToken;
}

/**
 * Convert DER-encoded ECDSA signature to raw r||s format (64 bytes).
 */
function derToRaw(derSig) {
  // DER format: 0x30 [total-len] 0x02 [r-len] [r] 0x02 [s-len] [s]
  let offset = 2; // skip 0x30 and total length
  
  // Read r
  if (derSig[offset] !== 0x02) throw new Error('Invalid DER signature');
  offset++;
  const rLen = derSig[offset];
  offset++;
  let r = derSig.subarray(offset, offset + rLen);
  offset += rLen;
  
  // Read s
  if (derSig[offset] !== 0x02) throw new Error('Invalid DER signature');
  offset++;
  const sLen = derSig[offset];
  offset++;
  let s = derSig.subarray(offset, offset + sLen);
  
  // Pad/trim to 32 bytes each
  if (r.length > 32) r = r.subarray(r.length - 32);
  if (s.length > 32) s = s.subarray(s.length - 32);
  
  const raw = Buffer.alloc(64);
  r.copy(raw, 32 - r.length);
  s.copy(raw, 64 - s.length);
  
  return raw;
}

/**
 * Send a push notification to a single device.
 * @param {string} deviceToken - APNs device token (hex string)
 * @param {object} payload - APNs payload (aps + custom data)
 * @param {object} options - Optional headers (expiration, priority, collapse-id)
 * @returns {Promise<{success: boolean, statusCode?: number, error?: string}>}
 */
function sendPush(deviceToken, payload, options = {}) {
  return new Promise((resolve) => {
    const jwt = getJWT();
    if (!jwt) {
      return resolve({ success: false, error: 'No signing key available' });
    }
    
    const client = http2.connect(`https://${APNS_HOST}:${APNS_PORT}`);
    
    client.on('error', (err) => {
      console.error('[APNs] Connection error:', err.message);
      resolve({ success: false, error: err.message });
    });
    
    const headers = {
      ':method': 'POST',
      ':path': `/3/device/${deviceToken}`,
      'authorization': `bearer ${jwt}`,
      'apns-topic': BUNDLE_ID,
      'apns-push-type': options.pushType || 'alert',
      'apns-priority': String(options.priority || 10),
      'apns-expiration': String(options.expiration || 0)
    };
    
    if (options.collapseId) {
      headers['apns-collapse-id'] = options.collapseId;
    }
    
    const body = JSON.stringify(payload);
    const req = client.request(headers);
    
    let responseData = '';
    let statusCode;
    
    req.on('response', (hdrs) => {
      statusCode = hdrs[':status'];
    });
    
    req.on('data', (chunk) => {
      responseData += chunk;
    });
    
    req.on('end', () => {
      client.close();
      if (statusCode === 200) {
        resolve({ success: true, statusCode });
      } else {
        let error = `HTTP ${statusCode}`;
        try {
          const parsed = JSON.parse(responseData);
          error = parsed.reason || error;
        } catch (e) {}
        console.error(`[APNs] Push failed: ${error} (token: ${deviceToken.substring(0, 8)}...)`);
        resolve({ success: false, statusCode, error });
      }
    });
    
    req.on('error', (err) => {
      client.close();
      resolve({ success: false, error: err.message });
    });
    
    req.end(body);
  });
}

/**
 * Send a chat message notification to a device.
 * @param {string} deviceToken - APNs device token
 * @param {string} message - Message text
 * @param {string} senderName - Sender display name
 */
async function sendChatNotification(deviceToken, message, senderName = 'Lewis') {
  // Truncate message for notification
  let body = message
    .replace(/\*\*/g, '')
    .replace(/__/g, '')
    .replace(/```[\s\S]*?```/g, '[code]')
    .replace(/`[^`]+`/g, '$&')
    .replace(/\[media attached:.*?\]/g, '[image]');
  
  if (body.length > 200) {
    body = body.substring(0, 200) + '…';
  }
  
  const payload = {
    aps: {
      alert: {
        title: `📚 ${senderName}`,
        body: body
      },
      sound: 'default',
      badge: 1,
      'thread-id': 'agent-chat',
      'mutable-content': 1
    }
  };
  
  return sendPush(deviceToken, payload, {
    collapseId: 'agent-chat-latest',
    priority: 10
  });
}

/**
 * Check if APNs is configured and ready.
 */
function isConfigured() {
  if (!TEAM_ID) {
    console.warn('[APNs] APNS_TEAM_ID not set — push disabled');
    return false;
  }
  return !!loadSigningKey();
}

module.exports = {
  sendPush,
  sendChatNotification,
  isConfigured,
  loadSigningKey
};

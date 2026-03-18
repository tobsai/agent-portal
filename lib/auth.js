'use strict';

/**
 * lib/auth.js — Passport.js config, JWT decode, and auth middleware
 *
 * Auth strategy functions (one responsibility each):
 *   authenticateSession(req, res, next) — Passport session check via req.user
 *   authenticateJWT(db)(req, res, next) — Bearer JWT decode → req.user (logs failures)
 *   authenticateAgentKey(req, res, next) — ak_ API key check → req.agent (logs failures)
 *
 * Composed middleware:
 *   jwtMiddleware(db)   — global /api middleware: runs authenticateJWT only
 *   requireAuth         — explicit OR chain: session OR JWT (already resolved) OR agent key
 *   requireAgentKey     — agent API key only (standalone, no session/JWT fallback)
 *   requireAdmin        — admin users only
 *
 * Exports:
 *   JWT_SECRET, configurePassport, jwtMiddleware,
 *   requireAuth, requireAgentKey, requireAdmin
 */

const passport       = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt            = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const JWT_SECRET = process.env.SESSION_SECRET || 'agent-portal-dev-secret';

// ---------------------------------------------------------------------------
// Passport setup
// ---------------------------------------------------------------------------

/**
 * Wire Passport serialise/deserialise and the Google OAuth strategy.
 * Call once at startup, before app.use(passport.session()).
 * @param {object} db  — db module from lib/db.js
 */
function configurePassport(db) {
  passport.serializeUser((user, done) => done(null, user.id));

  passport.deserializeUser(async (id, done) => {
    try {
      const user = await db.get('SELECT * FROM users WHERE id = $1', [id]);
      done(null, user);
    } catch (err) { done(err, null); }
  });

  if (process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET) {
    passport.use(new GoogleStrategy({
      clientID:     process.env.GOOGLE_CLIENT_ID,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET,
      callbackURL:  process.env.GOOGLE_CALLBACK_URL || '/auth/google/callback'
    }, async (accessToken, refreshToken, profile, done) => {
      try {
        let user = await db.get('SELECT * FROM users WHERE google_id = $1', [profile.id]);
        if (!user) {
          const id    = uuidv4();
          const email = profile.emails?.[0]?.value || '';
          const isFirstUser = !(await db.get('SELECT id FROM users LIMIT 1'));
          await db.run(
            'INSERT INTO users (id, google_id, email, name, picture, is_admin) VALUES ($1, $2, $3, $4, $5, $6)',
            [id, profile.id, email, profile.displayName, profile.photos?.[0]?.value, isFirstUser]
          );
          user = await db.get('SELECT * FROM users WHERE id = $1', [id]);
        }
        done(null, user);
      } catch (err) { done(err, null); }
    }));
  }
}

// ---------------------------------------------------------------------------
// Strategy: Session (Passport)
// ---------------------------------------------------------------------------

/**
 * Pass if the request is already authenticated via Passport session.
 * Does NOT reject — callers compose this with other strategies.
 */
function authenticateSession(req, res, next) {
  // req.isAuthenticated() is Passport's contract: true when req.user is set via
  // session deserialization or req.logIn({ session: false }).
  if (req.isAuthenticated()) return next();
  next();
}

// ---------------------------------------------------------------------------
// Strategy: Bearer JWT
// ---------------------------------------------------------------------------

/**
 * Attempt to decode a Bearer JWT from the Authorization header.
 * On success, calls req.logIn(user, { session: false }) so that
 * req.isAuthenticated() returns true for the remainder of the request.
 *
 * Failures are LOGGED — never silently swallowed.
 *   - TokenExpiredError → logged as warn (expired), does NOT reject (caller decides)
 *   - JsonWebTokenError → logged as warn (invalid), does NOT reject
 *   - User not found    → logged as warn
 *
 * NOTE: ak_-prefixed tokens are agent API keys — skipped here; handled by authenticateAgentKey.
 *
 * @param {object} db
 * @returns {Function} Express middleware
 */
function authenticateJWT(db) {
  return async (req, res, next) => {
    if (req.isAuthenticated()) return next(); // already authenticated — short-circuit

    const authHeader = req.headers.authorization;
    if (!authHeader?.startsWith('Bearer ')) return next(); // no Bearer header

    const token = authHeader.slice(7);
    if (token.startsWith('ak_')) return next(); // agent key — not a JWT, skip

    try {
      const decoded = jwt.verify(token, JWT_SECRET);
      const user    = await db.get('SELECT * FROM users WHERE id = $1', [decoded.userId]);
      if (user) {
        // Use req.logIn to integrate with Passport's isAuthenticated() contract.
        // session: false — do not persist token-based auth to the session store.
        req.logIn(user, { session: false }, (err) => {
          if (err) {
            console.warn('[auth:jwt] logIn error:', err.message);
            return next(err);
          }
          next();
        });
        return;
      }
      console.warn('[auth:jwt] user not found for decoded id:', decoded.userId);
    } catch (e) {
      if (e.name === 'TokenExpiredError') {
        console.warn('[auth:jwt] token expired:', e.message);
      } else {
        console.warn('[auth:jwt] token invalid:', e.name, e.message);
      }
    }
    next(); // JWT failed — fall through unauthenticated
  };
}

// ---------------------------------------------------------------------------
// Strategy: Agent API Key (ak_)
// ---------------------------------------------------------------------------

/**
 * Attempt to authenticate via an ak_-prefixed API key in the Authorization header.
 * On success, sets req.agent to the matching agent row.
 *
 * Failures are LOGGED — never silently swallowed.
 * Does NOT reject — callers compose this with other strategies.
 *
 * @param {object} req
 * @param {object} res
 * @param {Function} next
 */
async function authenticateAgentKey(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader?.startsWith('Bearer ')) return next(); // no Bearer header

  const key = authHeader.slice(7);
  if (!key.startsWith('ak_')) return next(); // not an agent key

  // db is required lazily to avoid circular dep at module load time.
  const db = require('./db').db;
  try {
    const agent = await db.get('SELECT * FROM agents WHERE api_key = $1', [key]);
    if (agent) {
      req.agent = agent;
      return next();
    }
    console.warn('[auth:agentKey] invalid key:', key.substring(0, 8) + '...');
  } catch (e) {
    console.warn('[auth:agentKey] DB error:', e.message);
  }
  next(); // key failed — fall through unauthenticated
}

// ---------------------------------------------------------------------------
// Global /api middleware: JWT decode pass (session auth already handled by Passport)
// ---------------------------------------------------------------------------

/**
 * Apply to all /api routes before route handlers.
 * Runs authenticateJWT so that JWT-based callers have req.user set
 * by the time requireAuth runs.
 *
 * @param {object} db
 * @returns {Function} Express middleware
 */
function jwtMiddleware(db) {
  return authenticateJWT(db);
}

// ---------------------------------------------------------------------------
// Composed: requireAuth — explicit OR chain
// ---------------------------------------------------------------------------

/**
 * Require authentication via any supported strategy.
 *
 * Explicit OR chain (evaluated in order):
 *   1. Session (Passport): req.isAuthenticated() — already resolved by session middleware
 *   2. JWT: req.isAuthenticated() — already resolved by jwtMiddleware applied upstream
 *   3. Agent key: req.agent — resolved inline here
 *
 * If none succeed → 401.
 */
async function requireAuth(req, res, next) {
  // Strategies 1 & 2 are already resolved upstream (Passport session + jwtMiddleware).
  if (req.isAuthenticated()) return next();

  // Strategy 3: agent key (inline — avoids a second middleware hop for this common path).
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) {
    const key = authHeader.slice(7);
    if (key.startsWith('ak_')) {
      const db = require('./db').db;
      try {
        const agent = await db.get('SELECT * FROM agents WHERE api_key = $1', [key]);
        if (agent) {
          req.agent = agent;
          return next();
        }
        console.warn('[auth:requireAuth] invalid agent key:', key.substring(0, 8) + '...');
      } catch (e) {
        console.warn('[auth:requireAuth] DB error checking agent key:', e.message);
        return res.status(500).json({ error: 'Auth check failed' });
      }
      return res.status(401).json({ error: 'Invalid API key' });
    }
    // Bearer token present but not ak_ and not a valid JWT (would have set req.user upstream).
    console.warn('[auth:requireAuth] Bearer token present but not authenticated (invalid/expired JWT or missing ak_ prefix)');
  }

  res.status(401).json({ error: 'Authentication required' });
}

// ---------------------------------------------------------------------------
// Standalone: requireAgentKey — agent API key only
// ---------------------------------------------------------------------------

/**
 * Require authentication via agent API key only.
 * Use on routes that should ONLY accept agent keys (not session/JWT).
 */
async function requireAgentKey(req, res, next) {
  const key = req.headers.authorization?.replace('Bearer ', '');
  if (!key) return res.status(401).json({ error: 'API key required' });
  const db = require('./db').db;
  try {
    const agent = await db.get('SELECT * FROM agents WHERE api_key = $1', [key]);
    if (agent) {
      req.agent = agent;
      return next();
    }
    console.warn('[auth:requireAgentKey] invalid key:', key.substring(0, 8) + '...');
    return res.status(401).json({ error: 'Invalid API key' });
  } catch (e) {
    console.warn('[auth:requireAgentKey] DB error:', e.message);
    return res.status(500).json({ error: 'Auth check failed' });
  }
}

// ---------------------------------------------------------------------------
// Standalone: requireAdmin
// ---------------------------------------------------------------------------

/**
 * Allow admin users only (session or JWT-authenticated with is_admin flag).
 */
function requireAdmin(req, res, next) {
  if (req.user?.is_admin) return next();
  res.status(403).json({ error: 'Admin access required' });
}

// ---------------------------------------------------------------------------
// Exports
// ---------------------------------------------------------------------------

module.exports = {
  JWT_SECRET,
  configurePassport,
  jwtMiddleware,
  requireAuth,
  requireAgentKey,
  requireAdmin,
  // Named strategy exports (for testing / advanced composition)
  authenticateSession,
  authenticateJWT,
  authenticateAgentKey,
};

'use strict';

/**
 * lib/auth.js — Passport.js config, JWT decode, and auth middleware
 *
 * Exports:
 *   JWT_SECRET
 *   configurePassport(passport, db)  — wire serialize/deserialize + Google strategy
 *   jwtMiddleware(db)                — Express middleware: decode Bearer JWT → req.user
 *   requireAuth(req, res, next)      — allow session user OR agent key
 *   requireAgentKey(req, res, next)  — allow agent API key only
 *   requireAdmin(req, res, next)     — allow admin users only
 */

const passport     = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const jwt          = require('jsonwebtoken');
const { v4: uuidv4 } = require('uuid');

const JWT_SECRET = process.env.SESSION_SECRET || 'agent-portal-dev-secret';

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

/**
 * Express middleware: decode a Bearer JWT on /api routes and populate req.user.
 * Uses proper Passport contract (req.logIn / req.user) instead of monkey-patching
 * req.isAuthenticated.
 *
 * NOTE: ak_ prefixed tokens are agent API keys — skip JWT decode and let
 * requireAgentKey handle them downstream.
 *
 * @param {object} db
 * @returns {Function} Express middleware
 */
function jwtMiddleware(db) {
  return async (req, res, next) => {
    if (req.isAuthenticated()) return next();

    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      const token = authHeader.slice(7);
      if (token.startsWith('ak_')) return next(); // agent key — handled later
      try {
        const decoded = jwt.verify(token, JWT_SECRET);
        const user    = await db.get('SELECT * FROM users WHERE id = $1', [decoded.userId]);
        if (user) {
          // Use req.logIn to properly integrate with Passport session serialisation.
          // Pass session:false so we don't persist the token-based session to the store.
          req.logIn(user, { session: false }, (err) => {
            if (err) return next(err);
            next();
          });
          return;
        }
      } catch (e) { /* invalid/expired token — fall through unauthenticated */ }
    }
    next();
  };
}

/**
 * Allow requests authenticated via session OR agent API key.
 */
function requireAuth(req, res, next) {
  if (req.isAuthenticated()) return next();
  const authHeader = req.headers.authorization;
  if (authHeader?.startsWith('Bearer ')) return requireAgentKey(req, res, next);
  res.status(401).json({ error: 'Authentication required' });
}

/**
 * Allow requests authenticated via agent API key only.
 */
async function requireAgentKey(req, res, next) {
  const key = req.headers.authorization?.replace('Bearer ', '');
  if (!key) return res.status(401).json({ error: 'API key required' });
  // db is injected per-call to avoid circular dep at module load time
  // The caller must have initialised db before mounting routes.
  const db = require('./db').db;
  const agent = await db.get('SELECT * FROM agents WHERE api_key = $1', [key]);
  if (!agent) return res.status(401).json({ error: 'Invalid API key' });
  req.agent = agent;
  next();
}

/**
 * Allow admin users only.
 */
function requireAdmin(req, res, next) {
  if (req.user?.is_admin) return next();
  res.status(403).json({ error: 'Admin access required' });
}

module.exports = {
  JWT_SECRET,
  configurePassport,
  jwtMiddleware,
  requireAuth,
  requireAgentKey,
  requireAdmin,
};

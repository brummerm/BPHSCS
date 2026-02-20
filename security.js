'use strict';
/**
 * security.js
 * Centralised security middleware: rate limiters, input validators,
 * field-length limits, and a production-safe error handler.
 */

const rateLimit = require('express-rate-limit');

// ── Rate limiters ────────────────────────────────────────────────────────────

/**
 * Auth endpoints (login / change-password).
 * 10 attempts per IP per 15 minutes; only failed requests count.
 */
const authLimiter = rateLimit({
  windowMs:              15 * 60 * 1000,
  max:                   10,
  standardHeaders:       true,
  legacyHeaders:         false,
  skipSuccessfulRequests:true,
  message: { error: 'Too many login attempts. Please try again in 15 minutes.' },
});

/**
 * Registration endpoint.
 * 5 accounts per IP per hour — prevents automated account farming.
 */
const registerLimiter = rateLimit({
  windowMs:       60 * 60 * 1000,
  max:            5,
  standardHeaders:true,
  legacyHeaders:  false,
  message: { error: 'Too many registration attempts. Please try again later.' },
});

/**
 * Code execution endpoint.
 * 20 runs per user (falls back to IP) per minute.
 */
const runLimiter = rateLimit({
  windowMs:       60 * 1000,
  max:            20,
  standardHeaders:true,
  legacyHeaders:  false,
  keyGenerator:  (req) => String(req.session?.userId || req.ip),
  message: { error: 'Too many code executions. Please wait a moment.' },
});

/**
 * General API limiter applied to all /api and /auth routes.
 * 300 requests per IP per minute — blocks automated scraping.
 */
const apiLimiter = rateLimit({
  windowMs:       60 * 1000,
  max:            300,
  standardHeaders:true,
  legacyHeaders:  false,
  message: { error: 'Too many requests. Please slow down.' },
});

// ── Field-length limits ───────────────────────────────────────────────────────
// All sizes are in characters (strings) unless noted.

const LIMITS = {
  username:     320,      // max RFC 5321 email length
  password:     128,
  first_name:   64,
  last_name:    64,
  filename:     100,
  language:     20,
  class_code:   64,
  title:        200,
  description:  5_000,
  note:         2_000,
  content:      500_000,  // 500 KB per saved file
  code:         500_000,  // 500 KB for execution
  starter_code: 500_000,
};

// ── Input validators ─────────────────────────────────────────────────────────

/**
 * Ensure a value is a string within the allowed length.
 * Returns the trimmed value, or throws a descriptive Error.
 */
function validateString(value, fieldName, { required = true, maxLen } = {}) {
  const limit = maxLen ?? LIMITS[fieldName] ?? 10_000;

  if (value === undefined || value === null || value === '') {
    if (required) throw Object.assign(new Error(`${fieldName} is required`), { status: 400 });
    return '';
  }
  if (typeof value !== 'string') {
    throw Object.assign(new Error(`${fieldName} must be a string`), { status: 400 });
  }
  if (value.length > limit) {
    throw Object.assign(
      new Error(`${fieldName} must be ${limit.toLocaleString()} characters or fewer`),
      { status: 400 }
    );
  }
  return value.trim();
}

/**
 * Parse and validate a route/body parameter as a safe positive integer.
 * Rejects floats, negative numbers, strings with extra characters, etc.
 */
function validateId(value, fieldName = 'id') {
  const str = String(value ?? '').trim();
  const n   = parseInt(str, 10);
  if (!Number.isInteger(n) || n <= 0 || String(n) !== str) {
    throw Object.assign(new Error(`Invalid ${fieldName}`), { status: 400 });
  }
  return n;
}

// ── Production-safe error handler ────────────────────────────────────────────

/**
 * Express error-handling middleware (must be registered last).
 * Hides internal details from clients in production.
 */
function errorHandler(err, req, res, next) { // eslint-disable-line no-unused-vars
  const isProd  = process.env.NODE_ENV === 'production';
  const status  = err.status || 500;

  // Always log on the server side
  if (!isProd || status >= 500) {
    console.error(`[${new Date().toISOString()}] ${req.method} ${req.path} →`, err.message);
  }

  // Never expose stack traces or internal messages in production
  const message = isProd && status === 500
    ? 'An internal server error occurred'
    : err.message || 'An error occurred';

  res.status(status).json({ error: message });
}

module.exports = {
  authLimiter,
  registerLimiter,
  runLimiter,
  apiLimiter,
  validateString,
  validateId,
  errorHandler,
  LIMITS,
};
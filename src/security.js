/**
 * ThreatPulse — Security Module
 * httpOnly cookie auth, CSRF protection, cookie parsing
 * Zero external dependencies
 */

const crypto = require('crypto');

// ============================================
// CONFIG
// ============================================
const IS_PRODUCTION = process.env.NODE_ENV === 'production' || !!process.env.RAILWAY_ENVIRONMENT;

const COOKIE_DEFAULTS = {
  httpOnly: true,
  secure: IS_PRODUCTION,
  sameSite: 'strict',
  path: '/'
};

const ACCESS_TOKEN_EXPIRY = 15 * 60;        // 15 minutes
const REFRESH_TOKEN_EXPIRY = 7 * 24 * 60 * 60; // 7 days

// ============================================
// COOKIE PARSER (lightweight, no dependency)
// ============================================

function cookieParser(req, res, next) {
  const raw = req.headers.cookie;
  req.cookies = {};
  if (!raw) return next();

  raw.split(';').forEach(pair => {
    const idx = pair.indexOf('=');
    if (idx === -1) return;
    const key = pair.slice(0, idx).trim();
    const value = pair.slice(idx + 1).trim();
    // Only decode if it looks URL-encoded
    try { req.cookies[key] = decodeURIComponent(value); }
    catch { req.cookies[key] = value; }
  });
  next();
}

// ============================================
// COOKIE HELPERS
// ============================================

function setAccessTokenCookie(res, token) {
  res.cookie('tp_access', token, {
    ...COOKIE_DEFAULTS,
    maxAge: ACCESS_TOKEN_EXPIRY * 1000
  });
}

function setRefreshTokenCookie(res, token) {
  res.cookie('tp_refresh', token, {
    ...COOKIE_DEFAULTS,
    maxAge: REFRESH_TOKEN_EXPIRY * 1000,
    path: '/api/auth'  // only sent to auth endpoints
  });
}

function clearAuthCookies(res) {
  res.clearCookie('tp_access', COOKIE_DEFAULTS);
  res.clearCookie('tp_refresh', { ...COOKIE_DEFAULTS, path: '/api/auth' });
  res.clearCookie('tp_csrf', { ...COOKIE_DEFAULTS, httpOnly: false });
}

// ============================================
// CSRF PROTECTION (double-submit cookie)
// ============================================

function generateCsrfToken() {
  return crypto.randomBytes(32).toString('hex');
}

function setCsrfCookie(res) {
  const token = generateCsrfToken();
  res.cookie('tp_csrf', token, {
    ...COOKIE_DEFAULTS,
    httpOnly: false,   // JS must read it to send in X-CSRF-Token header
    maxAge: REFRESH_TOKEN_EXPIRY * 1000
  });
  return token;
}

function validateCsrf(req) {
  // Skip CSRF check for GET/HEAD/OPTIONS
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return true;

  const cookieToken = req.cookies?.tp_csrf;
  const headerToken = req.headers['x-csrf-token'];

  if (!cookieToken || !headerToken) return false;
  if (cookieToken.length < 32 || headerToken.length < 32) return false;

  // Constant-time comparison
  try {
    return crypto.timingSafeEqual(
      Buffer.from(cookieToken),
      Buffer.from(headerToken)
    );
  } catch {
    return false;
  }
}

function csrfMiddleware(req, res, next) {
  if (!validateCsrf(req)) {
    return res.status(403).json({ error: 'CSRF token missing or invalid' });
  }
  next();
}

module.exports = {
  // Config
  ACCESS_TOKEN_EXPIRY,
  REFRESH_TOKEN_EXPIRY,
  IS_PRODUCTION,
  COOKIE_DEFAULTS,

  // Middleware
  cookieParser,
  csrfMiddleware,

  // Cookie helpers
  setAccessTokenCookie,
  setRefreshTokenCookie,
  clearAuthCookies,

  // CSRF
  setCsrfCookie,
  generateCsrfToken,
  validateCsrf
};

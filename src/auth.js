/**
 * ThreatPulse — Authentication Module
 * httpOnly cookie-based JWT auth with refresh tokens + CSRF
 * Zero external dependencies — uses Node.js built-in crypto
 */

const crypto = require('crypto');
const db = require('./database');
const security = require('./security');

// ============================================
// CONFIG
// ============================================
const IS_PRODUCTION = process.env.NODE_ENV === 'production' || !!process.env.RAILWAY_ENVIRONMENT;

// JWT secret must be stable across restarts, or every session silently invalidates
const JWT_SECRET = (() => {
  if (process.env.JWT_SECRET && process.env.JWT_SECRET.length >= 32) {
    return process.env.JWT_SECRET;
  }
  if (IS_PRODUCTION) {
    console.error('[FATAL] JWT_SECRET is missing or too short (min 32 chars). Refusing to start in production.');
    console.error('        Generate one with:  node -e "console.log(require(\'crypto\').randomBytes(48).toString(\'hex\'))"');
    process.exit(1);
  }
  console.warn('[Auth] ⚠️  JWT_SECRET not set — using an ephemeral secret. Sessions will reset on every restart.');
  console.warn('[Auth] ⚠️  Set a stable JWT_SECRET in your .env for persistent sessions.');
  return crypto.randomBytes(64).toString('hex');
})();
const ACCESS_TOKEN_EXPIRY = security.ACCESS_TOKEN_EXPIRY;    // 15 min
const REFRESH_TOKEN_EXPIRY = security.REFRESH_TOKEN_EXPIRY;  // 7 days
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 15;
const PASSWORD_MIN_LENGTH = 8;

// Token blacklist (in-memory, for logout)
const tokenBlacklist = new Set();
// Refresh token store: refreshToken → { userId, username, role, expiresAt, replacedBy?, graceUntil? }
const refreshTokens = new Map();
// Guest tokens are tracked separately so a flood of anonymous /auth/guest calls
// (each mints a 7-day refresh token) can't grow memory without bound or evict
// registered users' sessions.
const guestRefreshTokens = new Set();
const MAX_REFRESH_TOKENS = 50000;
const MAX_GUEST_REFRESH_TOKENS = 10000;
// After rotation the old refresh token stays usable briefly, so parallel requests
// that all got a 401 and all refresh with the same cookie don't log the user out.
const REFRESH_GRACE_MS = 30 * 1000;
const GUEST_USERNAME = 'guest';

// SQLite's datetime('now') format ("YYYY-MM-DD HH:MM:SS", UTC). Expiry columns are
// compared against datetime('now') as strings, so an ISO "…T…Z" value would sort
// after it for the rest of the day and never expire on time.
function sqliteDateTime(ms) {
  return new Date(ms).toISOString().slice(0, 19).replace('T', ' ');
}

// ============================================
// PASSWORD HASHING (crypto.scryptSync)
// ============================================

function generateSalt() {
  return crypto.randomBytes(32).toString('hex');
}

function hashPassword(password, salt) {
  return crypto.scryptSync(password, salt, 64).toString('hex');
}

function verifyPassword(password, salt, storedHash) {
  const hash = crypto.scryptSync(password, salt, 64);
  const storedBuffer = Buffer.from(storedHash, 'hex');
  if (hash.length !== storedBuffer.length) return false;
  return crypto.timingSafeEqual(hash, storedBuffer);
}

function validatePasswordStrength(password) {
  if (typeof password !== 'string' || !password) {
    return { valid: false, error: 'Password is required' };
  }
  if (password.length < PASSWORD_MIN_LENGTH) {
    return { valid: false, error: `Password must be at least ${PASSWORD_MIN_LENGTH} characters` };
  }
  if (!/[A-Z]/.test(password)) {
    return { valid: false, error: 'Password must contain at least one uppercase letter' };
  }
  if (!/[a-z]/.test(password)) {
    return { valid: false, error: 'Password must contain at least one lowercase letter' };
  }
  if (!/[0-9]/.test(password)) {
    return { valid: false, error: 'Password must contain at least one number' };
  }
  return { valid: true };
}

// ============================================
// JWT TOKENS (HMAC-SHA256, no dependencies)
// ============================================

function base64UrlEncode(data) {
  return Buffer.from(data).toString('base64url');
}

function base64UrlDecode(str) {
  return Buffer.from(str, 'base64url').toString('utf8');
}

function createToken(payload) {
  const header = { alg: 'HS256', typ: 'JWT' };
  const now = Math.floor(Date.now() / 1000);
  const tokenPayload = {
    ...payload,
    iat: now,
    exp: now + ACCESS_TOKEN_EXPIRY
  };

  const headerEncoded = base64UrlEncode(JSON.stringify(header));
  const payloadEncoded = base64UrlEncode(JSON.stringify(tokenPayload));
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${headerEncoded}.${payloadEncoded}`)
    .digest('base64url');

  return `${headerEncoded}.${payloadEncoded}.${signature}`;
}

function createRefreshToken(user) {
  const token = crypto.randomBytes(48).toString('hex');
  const expiresAt = Date.now() + REFRESH_TOKEN_EXPIRY * 1000;
  refreshTokens.set(token, {
    userId: user.id,
    username: user.username,
    role: user.role,
    expiresAt
  });
  if (user.username === GUEST_USERNAME) {
    guestRefreshTokens.add(token);
    while (guestRefreshTokens.size > MAX_GUEST_REFRESH_TOKENS) {
      revokeRefreshToken(guestRefreshTokens.values().next().value);
    }
  }
  // Backstop: Map iterates in insertion order, so the first key is the oldest
  while (refreshTokens.size > MAX_REFRESH_TOKENS) {
    revokeRefreshToken(refreshTokens.keys().next().value);
  }
  return token;
}

function verifyToken(token) {
  try {
    if (tokenBlacklist.has(token)) return null;

    const parts = token.split('.');
    if (parts.length !== 3) return null;

    const [headerEncoded, payloadEncoded, signature] = parts;

    // Verify signature
    const expectedSignature = crypto
      .createHmac('sha256', JWT_SECRET)
      .update(`${headerEncoded}.${payloadEncoded}`)
      .digest('base64url');

    const sigBuf = Buffer.from(signature);
    const expBuf = Buffer.from(expectedSignature);
    if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) return null;

    // Decode and check expiry
    const payload = JSON.parse(base64UrlDecode(payloadEncoded));
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) return null;

    return payload;
  } catch (e) {
    return null;
  }
}

// Returns { token, entry, viaGrace } for a usable refresh token, else null.
// A token that was already rotated is accepted only within REFRESH_GRACE_MS, and
// then resolves to its (still live, not yet rotated) successor.
function verifyRefreshToken(token) {
  const entry = refreshTokens.get(token);
  if (!entry) return null;
  const now = Date.now();
  if (now > entry.expiresAt) {
    revokeRefreshToken(token);
    return null;
  }
  if (entry.replacedBy) {
    const successor = refreshTokens.get(entry.replacedBy);
    if (now > entry.graceUntil || !successor || successor.replacedBy || now > successor.expiresAt) {
      revokeRefreshToken(token);
      return null;
    }
    return { token: entry.replacedBy, entry: successor, viaGrace: true };
  }
  return { token, entry, viaGrace: false };
}

function blacklistToken(token) {
  tokenBlacklist.add(token);
  // Auto-clean after expiry
  setTimeout(() => tokenBlacklist.delete(token), ACCESS_TOKEN_EXPIRY * 1000);
}

function revokeRefreshToken(token) {
  refreshTokens.delete(token);
  guestRefreshTokens.delete(token);
}

// Revoke every refresh token of a user (e.g. after a password change), optionally
// keeping the caller's current session.
function revokeUserSessions(userId, keepToken = null) {
  for (const [rt, entry] of refreshTokens) {
    if (entry.userId === userId && rt !== keepToken) revokeRefreshToken(rt);
  }
}

// ============================================
// AUTH MIDDLEWARE — reads from httpOnly cookie first, Bearer header as fallback
// ============================================

const MUST_CHANGE_ALLOWED_PATHS = new Set(['/api/auth/me', '/api/auth/password', '/api/auth/logout']);

function requireAuth(req, res, next) {
  let token = null;

  // 1. Try httpOnly cookie (primary)
  if (req.cookies && req.cookies.tp_access) {
    token = req.cookies.tp_access;
  }
  // 2. Fallback to Bearer header (API clients, scripts, mobile)
  else if (req.headers.authorization && req.headers.authorization.startsWith('Bearer ')) {
    token = req.headers.authorization.slice(7);
  }

  if (!token) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  // Verify user still exists and is active
  const user = db.getUserById(payload.userId);
  if (!user || !user.is_active) {
    return res.status(401).json({ error: 'Account disabled or not found' });
  }

  // A forced password change (first-run admin) must be done before anything else —
  // the UI modal alone doesn't stop direct API use with the initial password.
  if (user.must_change_password) {
    const fullPath = `${req.baseUrl || ''}${req.path || ''}`.toLowerCase().replace(/\/+$/, '');
    if (!MUST_CHANGE_ALLOWED_PATHS.has(fullPath)) {
      return res.status(403).json({
        success: false,
        error: 'You must change your password before continuing.',
        mustChangePassword: true
      });
    }
  }

  req.user = {
    id: user.id,
    username: user.username,
    displayName: user.display_name,
    role: user.role,
    email: user.email || null,
    mustChangePassword: !!user.must_change_password
  };
  req.token = token;
  next();
}

function requireAdmin(req, res, next) {
  if (!req.user || req.user.role !== 'admin') {
    return res.status(403).json({ error: 'Admin access required' });
  }
  next();
}

// ============================================
// AUTH OPERATIONS
// ============================================

function registerUser(username, displayName, password, inviteCode, email = null) {
  // Input validation
  if (!username || username.length < 3 || username.length > 32) {
    return { success: false, error: 'Username must be 3-32 characters' };
  }
  if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
    return { success: false, error: 'Username can only contain letters, numbers, dots, hyphens, and underscores' };
  }
  // The shared guest account is created lazily on the first anonymous visit; on a
  // fresh (ephemeral) deploy someone could otherwise register it first and own the
  // workspace every anonymous visitor is dropped into.
  if (username.toLowerCase() === GUEST_USERNAME) {
    return { success: false, error: 'Username already taken' };
  }
  if (!displayName || displayName.length < 2 || displayName.length > 64) {
    return { success: false, error: 'Display name must be 2-64 characters' };
  }
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { success: false, error: 'Valid email address is required' };
  }

  // Password strength check
  const pwCheck = validatePasswordStrength(password);
  if (!pwCheck.valid) return { success: false, error: pwCheck.error };

  // Verify invite code — but only when open registration is disabled.
  // Open registration (default) lets anyone sign up with no invite code.
  const requireInvite = process.env.REQUIRE_INVITE_CODE === 'true';
  if (requireInvite) {
    const codeResult = db.validateInviteCode(inviteCode);
    if (!codeResult.valid) {
      return { success: false, error: codeResult.error };
    }
  }

  // Check if username exists
  const existing = db.getUserByUsername(username);
  if (existing) {
    return { success: false, error: 'Username already taken' };
  }

  // Check if email already used
  const existingEmail = db.getUserByEmail(email);
  if (existingEmail) {
    return { success: false, error: 'Email already registered' };
  }

  // Create user (invite code stored only if one was actually used)
  const salt = generateSalt();
  const passwordHash = hashPassword(password, salt);
  const cleanInvite = requireInvite ? inviteCode : null;
  const result = db.createUser(username, displayName, passwordHash, salt, 'analyst', cleanInvite, email);

  if (!result.success) {
    return { success: false, error: result.error };
  }

  // Mark invite code as used (only when one was required/used)
  if (requireInvite) {
    db.useInviteCode(inviteCode, result.id);
  }

  // Create default notification settings for this user
  db.createUserNotificationSettings(result.id);

  // New users start with an empty source list — they add their own feeds
  console.log(`[Auth] New user "${username}" (id=${result.id}) — empty source list`);

  // Generate access + refresh tokens
  const userObj = { id: result.id, username, role: 'analyst' };
  const accessToken = createToken({ userId: userObj.id, username: userObj.username, role: userObj.role });
  const refreshToken = createRefreshToken(userObj);

  return {
    success: true,
    accessToken,
    refreshToken,
    user: { id: result.id, username, displayName, role: 'analyst', email }
  };
}

function loginUser(identifier, password) {
  if (!identifier || !password || typeof password !== 'string') {
    return { success: false, error: 'Username/email and password are required' };
  }

  // Allow logging in with either a username or an email address
  let user = db.getUserByUsername(identifier);
  if (!user && identifier.includes('@')) {
    user = db.getUserByEmail(identifier);
  }
  if (!user) {
    return { success: false, error: 'Invalid username/email or password' };
  }

  // Check account lockout
  if (user.locked_until) {
    const lockTime = new Date(user.locked_until);
    if (lockTime > new Date()) {
      const minsLeft = Math.ceil((lockTime - new Date()) / 60000);
      return { success: false, error: `Account locked. Try again in ${minsLeft} minute(s)` };
    }
    // Lock expired, reset
    db.unlockAccount(user.id);
  }

  // Verify password
  if (!verifyPassword(password, user.salt, user.password_hash)) {
    db.incrementFailedLogins(user.id);

    // Check if we need to lock
    const updated = db.getUserById(user.id);
    if (updated.failed_login_attempts >= MAX_FAILED_ATTEMPTS) {
      const lockUntil = new Date(Date.now() + LOCKOUT_DURATION_MINUTES * 60000).toISOString();
      db.lockAccount(user.id, lockUntil);
      return { success: false, error: `Too many failed attempts. Account locked for ${LOCKOUT_DURATION_MINUTES} minutes.` };
    }

    return { success: false, error: 'Invalid username/email or password' };
  }

  // Only reveal that an account is disabled to someone who knows its password
  if (!user.is_active) {
    return { success: false, error: 'Account has been disabled. Contact admin.' };
  }

  // Success — reset failed attempts and update last login
  db.resetFailedLogins(user.id);
  db.updateUserLastLogin(user.id);

  const accessToken = createToken({ userId: user.id, username: user.username, role: user.role });
  const refreshToken = createRefreshToken(user);

  return {
    success: true,
    accessToken,
    refreshToken,
    user: {
      id: user.id,
      username: user.username,
      displayName: user.display_name,
      role: user.role,
      email: user.email || null,
      mustChangePassword: !!user.must_change_password
    }
  };
}

function refreshAccessToken(refreshTokenStr) {
  if (!refreshTokenStr) return { success: false, error: 'Refresh token required' };

  const found = verifyRefreshToken(refreshTokenStr);
  if (!found) return { success: false, error: 'Invalid or expired refresh token' };
  const { entry } = found;

  // Verify user still exists and is active
  const user = db.getUserById(entry.userId);
  if (!user || !user.is_active) {
    revokeRefreshToken(found.token);
    revokeRefreshToken(refreshTokenStr);
    return { success: false, error: 'Account disabled or not found' };
  }

  let newRefreshToken;
  if (found.viaGrace) {
    // A concurrent request already rotated this token — hand back the same successor
    newRefreshToken = found.token;
  } else {
    // Rotate: the old token keeps working only for a short grace window
    newRefreshToken = createRefreshToken(user);
    entry.replacedBy = newRefreshToken;
    entry.graceUntil = Date.now() + REFRESH_GRACE_MS;
  }

  const newAccessToken = createToken({ userId: user.id, username: user.username, role: user.role });

  return {
    success: true,
    accessToken: newAccessToken,
    refreshToken: newRefreshToken,
    user: {
      id: user.id,
      username: user.username,
      displayName: user.display_name,
      role: user.role,
      email: user.email || null,
      mustChangePassword: !!user.must_change_password
    }
  };
}

// Works without a valid access token: an idle tab's access token is usually
// expired by the time the user clicks "log out", and the refresh token must still
// be revoked. Returns the user id when it can be determined (for the audit log).
function logoutUser(req) {
  let userId = null;

  // Blacklist access token
  const authz = req.headers?.authorization;
  const accessToken = req.cookies?.tp_access || req.token ||
    (authz && authz.startsWith('Bearer ') ? authz.slice(7) : null);
  if (accessToken) {
    const payload = verifyToken(accessToken);
    if (payload) {
      userId = payload.userId;
      blacklistToken(accessToken);
    }
  }

  // Revoke refresh token (and, if it was a just-rotated one, its successor)
  const refreshToken = req.cookies?.tp_refresh;
  if (refreshToken) {
    const entry = refreshTokens.get(refreshToken);
    if (entry) {
      if (userId == null) userId = entry.userId;
      if (entry.replacedBy) revokeRefreshToken(entry.replacedBy);
    }
    revokeRefreshToken(refreshToken);
  }

  return { success: true, userId };
}

// ============================================
// FIRST-RUN SETUP
// ============================================

function generateInitialAdminPassword() {
  const random = crypto.randomBytes(12).toString('base64').replace(/[^a-zA-Z0-9]/g, '');
  return `Tp${random}9!`;
}

function ensureAdminExists() {
  const users = db.getAllUsers();
  if (users.length === 0) {
    console.log('[Auth] No users found — creating default admin...');
    const salt = generateSalt();
    const initialPassword = process.env.ADMIN_INITIAL_PASSWORD || generateInitialAdminPassword();
    const passwordHash = hashPassword(initialPassword, salt);
    const adminEmail = process.env.ADMIN_EMAIL || null;
    const result = db.createUser('admin', 'Administrator', passwordHash, salt, 'admin', null, adminEmail);
    if (result.success) {
      db.createUserNotificationSettings(result.id);
      db.setMustChangePassword(result.id, 1);

      console.log('[Auth] Default admin created');
      console.log('[Auth] FIRST-RUN ADMIN CREDENTIALS (shown once)');
      console.log(`[Auth] Username: admin`);
      console.log(`[Auth] Password: ${initialPassword}`);
      console.log('[Auth] You will be required to change this password on first login.');

      // Generate 10 invite codes for the team
      for (let i = 1; i <= 10; i++) {
        const code = crypto.randomBytes(4).toString('hex').toUpperCase();
        db.createInviteCode(result.id, code);
      }
      console.log('[Auth] Generated 10 invite codes for team registration ✓');
      const codes = db.getValidInviteCodes();
      codes.forEach(c => console.log(`  📧 Invite code: ${c.code}`));
    }
  }
}

// Clean expired refresh tokens every hour
setInterval(() => {
  const now = Date.now();
  for (const [token, entry] of refreshTokens) {
    if (now > entry.expiresAt || (entry.graceUntil && now > entry.graceUntil)) revokeRefreshToken(token);
  }
}, 60 * 60 * 1000);

// ============================================
// INPUT SANITIZATION
// ============================================

function sanitizeString(str, maxLength = 255) {
  if (typeof str !== 'string') return '';
  return str.trim().slice(0, maxLength);
}

function validateUrl(url) {
  let parsed;
  try {
    parsed = new URL(url);
  } catch {
    return false;
  }

  if (!['http:', 'https:'].includes(parsed.protocol)) return false;

  let hostname = parsed.hostname.toLowerCase();
  if (hostname.startsWith('[') && hostname.endsWith(']')) hostname = hostname.slice(1, -1);

  if (hostname === 'localhost' || hostname.endsWith('.localhost')) return false;
  if (hostname.endsWith('.internal') || hostname.endsWith('.local')) return false;

  if (hostname.includes(':')) {
    if (hostname === '::1' || hostname === '::') return false;
    if (hostname.startsWith('fe80')) return false;
    if (/^f[cd][0-9a-f]{2}:/.test(hostname)) return false;
    if (hostname.startsWith('::ffff:')) {
      return validateUrl(`http://${hostname.split(':').pop()}`);
    }
    return true;
  }

  const m = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = parseInt(m[1], 10);
    const b = parseInt(m[2], 10);
    if ([a, b, parseInt(m[3], 10), parseInt(m[4], 10)].some(o => o > 255)) return false;
    if (a === 0 || a === 127) return false;
    if (a === 10) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 169 && b === 254) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a >= 224) return false;
    return true;
  }

  return true;
}

// ============================================
// FORGOT / RESET PASSWORD
// ============================================

function forgotPassword(email) {
  const genericResponse = { success: true, message: 'If an account with that email exists, a reset link has been sent.' };

  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { success: false, error: 'Valid email address is required' };
  }

  const user = db.getUserByEmail(email);
  if (!user) return genericResponse;

  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = sqliteDateTime(Date.now() + 60 * 60 * 1000);

  db.createPasswordResetToken(user.id, token, expiresAt);
  db.cleanupExpiredResetTokens();

  return {
    ...genericResponse,
    _token: token,
    _userId: user.id,
    _email: user.email,
    _username: user.username
  };
}

function resetPassword(token, newPassword) {
  if (!token) return { success: false, error: 'Reset token is required' };

  const pwCheck = validatePasswordStrength(newPassword);
  if (!pwCheck.valid) return { success: false, error: pwCheck.error };

  const tokenRow = db.validatePasswordResetToken(token);
  if (!tokenRow) {
    return { success: false, error: 'Invalid or expired reset token' };
  }

  const salt = generateSalt();
  const passwordHash = hashPassword(newPassword, salt);
  db.updateUserPassword(tokenRow.user_id, passwordHash, salt);
  db.markResetTokenUsed(token);
  db.logAudit(tokenRow.user_id, 'password_reset', 'Password reset via email token', null);

  // Revoke all sessions for this user on password reset
  revokeUserSessions(tokenRow.user_id);

  return { success: true, message: 'Password has been reset successfully' };
}

// ============================================
// GUEST ACCESS (open public dashboard — no sign-in required)
// ============================================
// A single shared "guest" account lets anonymous visitors use the dashboard
// without registering. Everyone shares the same guest workspace.
// (GUEST_USERNAME is defined in CONFIG above.)

function getOrCreateGuestUser() {
  let guest = db.getUserByUsername(GUEST_USERNAME);
  if (!guest) {
    const salt = generateSalt();
    // Unusable random password — guests never log in with a password
    const passwordHash = hashPassword(crypto.randomBytes(32).toString('hex'), salt);
    const result = db.createUser(GUEST_USERNAME, 'Guest', passwordHash, salt, 'analyst', null, null);
    if (!result.success) return { success: false, error: result.error };
    db.createUserNotificationSettings(result.id);
    guest = db.getUserById(result.id);
  }
  if (!guest) return { success: false, error: 'Failed to initialize guest account' };
  // Admins can switch guest access off by disabling the guest account
  if (!guest.is_active) return { success: false, disabled: true, error: 'Guest access is disabled. Please sign in.' };

  const userObj = { id: guest.id, username: guest.username, role: 'analyst' };
  const accessToken = createToken({ userId: userObj.id, username: userObj.username, role: 'analyst' });
  const refreshToken = createRefreshToken(userObj);
  db.logAudit(guest.id, 'guest_access', 'Guest session created', null);

  return {
    success: true,
    accessToken,
    refreshToken,
    user: { id: guest.id, username: guest.username, displayName: guest.display_name, role: 'analyst', email: null }
  };
}

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  refreshAccessToken,
  requireAuth,
  requireAdmin,
  ensureAdminExists,
  forgotPassword,
  resetPassword,
  getOrCreateGuestUser,
  sanitizeString,
  validateUrl,
  validatePasswordStrength,
  // used by the password-change route (were missing → every change crashed)
  verifyPassword,
  generateSalt,
  hashPassword,
  revokeUserSessions,
  sqliteDateTime,
  GUEST_USERNAME,
  MAX_GUEST_REFRESH_TOKENS,
  _refreshTokenCount: () => refreshTokens.size,
  _guestRefreshTokenCount: () => guestRefreshTokens.size,
  setCookies: security,  // pass through for routes
};

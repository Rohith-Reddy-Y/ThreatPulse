/**
 * ThreatPulse — Authentication Module
 * Handles password hashing, JWT tokens, and auth middleware
 * Zero external dependencies — uses Node.js built-in crypto
 */

const crypto = require('crypto');
const db = require('./database');

// ============================================
// CONFIG
// ============================================
const IS_PRODUCTION = process.env.NODE_ENV === 'production' || !!process.env.RAILWAY_ENVIRONMENT;

// JWT secret must be stable across restarts, or every session silently invalidates
// (and multi-instance deployments break). Require it in production; warn in development.
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
const JWT_EXPIRY = 24 * 60 * 60; // 24 hours in seconds
const MAX_FAILED_ATTEMPTS = 5;
const LOCKOUT_DURATION_MINUTES = 15;
const PASSWORD_MIN_LENGTH = 8;

// Token blacklist (in-memory, cleared on restart — acceptable for this scale)
const tokenBlacklist = new Set();

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
    exp: now + JWT_EXPIRY
  };

  const headerEncoded = base64UrlEncode(JSON.stringify(header));
  const payloadEncoded = base64UrlEncode(JSON.stringify(tokenPayload));
  const signature = crypto
    .createHmac('sha256', JWT_SECRET)
    .update(`${headerEncoded}.${payloadEncoded}`)
    .digest('base64url');

  return `${headerEncoded}.${payloadEncoded}.${signature}`;
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

    if (signature !== expectedSignature) return null;

    // Decode and check expiry
    const payload = JSON.parse(base64UrlDecode(payloadEncoded));
    const now = Math.floor(Date.now() / 1000);
    if (payload.exp && payload.exp < now) return null;

    return payload;
  } catch (e) {
    return null;
  }
}

function blacklistToken(token) {
  tokenBlacklist.add(token);
  // Auto-clean expired tokens every hour
  setTimeout(() => tokenBlacklist.delete(token), JWT_EXPIRY * 1000);
}

// ============================================
// AUTH MIDDLEWARE
// ============================================

function requireAuth(req, res, next) {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Authentication required' });
  }

  const token = authHeader.slice(7);
  const payload = verifyToken(token);
  if (!payload) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }

  // Verify user still exists and is active
  const user = db.getUserById(payload.userId);
  if (!user || !user.is_active) {
    return res.status(401).json({ error: 'Account disabled or not found' });
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
  if (!displayName || displayName.length < 2 || displayName.length > 64) {
    return { success: false, error: 'Display name must be 2-64 characters' };
  }
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { success: false, error: 'Valid email address is required' };
  }

  // Password strength check
  const pwCheck = validatePasswordStrength(password);
  if (!pwCheck.valid) return { success: false, error: pwCheck.error };

  // Verify invite code
  const codeResult = db.validateInviteCode(inviteCode);
  if (!codeResult.valid) {
    return { success: false, error: codeResult.error };
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

  // Create user
  const salt = generateSalt();
  const passwordHash = hashPassword(password, salt);
  const result = db.createUser(username, displayName, passwordHash, salt, 'analyst', inviteCode, email);

  if (!result.success) {
    return { success: false, error: result.error };
  }

  // Mark invite code as used
  db.useInviteCode(inviteCode, result.id);

  // Create default notification settings for this user
  db.createUserNotificationSettings(result.id);

  // Generate token
  const token = createToken({ userId: result.id, username, role: 'analyst' });

  return {
    success: true,
    token,
    user: { id: result.id, username, displayName, role: 'analyst' }
  };
}

function loginUser(username, password) {
  if (!username || !password) {
    return { success: false, error: 'Username and password required' };
  }

  const user = db.getUserByUsername(username);
  if (!user) {
    return { success: false, error: 'Invalid username or password' };
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

  // Check if account is active
  if (!user.is_active) {
    return { success: false, error: 'Account has been disabled. Contact admin.' };
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

    return { success: false, error: 'Invalid username or password' };
  }

  // Success — reset failed attempts and update last login
  db.resetFailedLogins(user.id);
  db.updateUserLastLogin(user.id);

  const token = createToken({ userId: user.id, username: user.username, role: user.role });

  return {
    success: true,
    token,
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

function logoutUser(token) {
  blacklistToken(token);
  return { success: true };
}

// ============================================
// FIRST-RUN SETUP
// ============================================

function generateInitialAdminPassword() {
  // Meets the strength policy (upper, lower, digit, symbol, length) by construction.
  const random = crypto.randomBytes(12).toString('base64').replace(/[^a-zA-Z0-9]/g, '');
  return `Tp${random}9!`;
}

function ensureAdminExists() {
  const users = db.getAllUsers();
  if (users.length === 0) {
    console.log('[Auth] No users found — creating default admin...');
    const salt = generateSalt();
    // Use a caller-supplied password if provided, otherwise generate a strong random one.
    const initialPassword = process.env.ADMIN_INITIAL_PASSWORD || generateInitialAdminPassword();
    const passwordHash = hashPassword(initialPassword, salt);
    const adminEmail = process.env.ADMIN_EMAIL || null;
    const result = db.createUser('admin', 'Administrator', passwordHash, salt, 'admin', null, adminEmail);
    if (result.success) {
      db.createUserNotificationSettings(result.id);
      // Force the admin to set their own password on first login.
      db.setMustChangePassword(result.id, 1);

      console.log('[Auth] Default admin created ✓');
      console.log('[Auth] ┌──────────────────────────────────────────────┐');
      console.log('[Auth] │  FIRST-RUN ADMIN CREDENTIALS (shown once)     │');
      console.log('[Auth] ├──────────────────────────────────────────────┤');
      console.log('[Auth] │  Username: admin');
      console.log(`[Auth] │  Password: ${initialPassword}`);
      console.log('[Auth] └──────────────────────────────────────────────┘');
      console.log('[Auth] ⚠️  You will be required to change this password on first login.');

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

  // Only allow http/https
  if (!['http:', 'https:'].includes(parsed.protocol)) return false;

  let hostname = parsed.hostname.toLowerCase();
  // Strip IPv6 brackets: http://[::1]/ -> ::1
  if (hostname.startsWith('[') && hostname.endsWith(']')) hostname = hostname.slice(1, -1);

  // Block local / internal hostnames
  if (hostname === 'localhost' || hostname.endsWith('.localhost')) return false;
  if (hostname.endsWith('.internal') || hostname.endsWith('.local')) return false;

  // IPv6 checks
  if (hostname.includes(':')) {
    if (hostname === '::1' || hostname === '::') return false;      // loopback / unspecified
    if (hostname.startsWith('fe80')) return false;                 // link-local
    if (/^f[cd][0-9a-f]{2}:/.test(hostname)) return false;         // unique local fc00::/7
    if (hostname.startsWith('::ffff:')) {                          // IPv4-mapped IPv6
      return validateUrl(`http://${hostname.split(':').pop()}`);
    }
    return true;
  }

  // IPv4 checks — block all private / reserved ranges
  const m = hostname.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (m) {
    const a = parseInt(m[1], 10);
    const b = parseInt(m[2], 10);
    if ([a, b, parseInt(m[3], 10), parseInt(m[4], 10)].some(o => o > 255)) return false;
    if (a === 0 || a === 127) return false;               // this-host / loopback
    if (a === 10) return false;                           // 10.0.0.0/8
    if (a === 172 && b >= 16 && b <= 31) return false;    // 172.16.0.0/12
    if (a === 192 && b === 168) return false;             // 192.168.0.0/16
    if (a === 169 && b === 254) return false;             // link-local + cloud metadata (169.254.169.254)
    if (a === 100 && b >= 64 && b <= 127) return false;   // CGNAT 100.64.0.0/10
    if (a >= 224) return false;                           // multicast / reserved
    return true;
  }

  // Regular hostname — allow (DNS-rebinding is out of scope for this validator)
  return true;
}

// ============================================
// FORGOT / RESET PASSWORD
// ============================================

function forgotPassword(email) {
  // Always return success to prevent user enumeration
  const genericResponse = { success: true, message: 'If an account with that email exists, a reset link has been sent.' };
  
  if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
    return { success: false, error: 'Valid email address is required' };
  }

  const user = db.getUserByEmail(email);
  if (!user) return genericResponse; // Don't reveal if email exists

  // Generate secure token (32 bytes = 64 hex chars)
  const token = crypto.randomBytes(32).toString('hex');
  const expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString(); // 1 hour

  db.createPasswordResetToken(user.id, token, expiresAt);
  db.cleanupExpiredResetTokens();

  return {
    ...genericResponse,
    _token: token,       // Internal: used by API route to send email
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

  // Change password
  const salt = generateSalt();
  const passwordHash = hashPassword(newPassword, salt);
  db.updateUserPassword(tokenRow.user_id, passwordHash, salt);

  // Mark token as used
  db.markResetTokenUsed(token);

  // Audit log
  db.logAudit(tokenRow.user_id, 'password_reset', 'Password reset via email token', null);

  return { success: true, message: 'Password has been reset successfully' };
}

module.exports = {
  registerUser,
  loginUser,
  logoutUser,
  requireAuth,
  requireAdmin,
  ensureAdminExists,
  sanitizeString,
  validateUrl,
  validatePasswordStrength,
  createToken,
  verifyToken,
  forgotPassword,
  resetPassword,
  hashPassword,
  verifyPassword,
  generateSalt
};

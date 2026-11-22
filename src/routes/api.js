/**
 * ThreatPulse — API Routes (v2 Multi-User)
 * All routes are user-scoped with JWT authentication
 */

const express = require('express');
const router = express.Router();
const db = require('../database');
const auth = require('../auth');
const security = require('../security');
const crypto = require('crypto');
const geo = require('../geo');
const landscape = require('../landscape');
const attackKb = require('../attack-kb');
const analytics = require('../analytics');
const sourceCatalog = require('../source-catalog');
const {
  sendAlertEmail, sendVerificationEmail, isEmailConfigured, describeEmail,
  sendPasswordResetEmail, sendPasswordChangedEmail, sendEmailChangedEmails, sendWelcomeEmail,
} = require('../notifications/email-notifier');
const { sendTelegramAlert } = require('../notifications/telegram-notifier');
const { sendTeamsAlert } = require('../notifications/teams-notifier');
const { sendWhatsAppAlert } = require('../notifications/whatsapp-notifier');

// ============================================
// FORGOT-PASSWORD THROTTLE
// ============================================
let forgotPasswordThrottle = new Map();
// Clean expired entries every 15 minutes
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of forgotPasswordThrottle) {
    if (now >= entry.resetAt) forgotPasswordThrottle.delete(key);
  }
}, 15 * 60 * 1000);

// ============================================
// GUEST RESTRICTIONS
// ============================================
// Every anonymous visitor shares the single "guest" account, so guests must not be
// able to change shared state (sources, notification targets, account settings)
// or trigger expensive work.
function denyGuest(req, res, next) {
  if (req.user && req.user.username === 'guest') {
    return res.status(403).json({ success: false, error: 'Please sign in or register to use this feature.' });
  }
  next();
}

// Read scope for article/source/stat queries: admins see everything (null),
// the shared guest account sees built-in system content only, and every other
// user sees only their own rows.
function readScope(user) {
  if (user.role === 'admin') return null;
  if (user.username === 'guest') return db.SYSTEM_SCOPE;
  return user.id;
}

// ============================================
// INPUT HELPERS
// ============================================
// Express parses query strings with qs: "?a=1&a=2" is an array and "?a[b]=1" an
// object. Filters expect one string; anything else is treated as absent (binding
// an array/object made better-sqlite3 throw -> HTTP 500).
function qstr(v, max = 200) {
  return typeof v === 'string' ? auth.sanitizeString(v, max) : undefined;
}

function clampInt(v, def, min, max) {
  const n = parseInt(v, 10);
  return Number.isFinite(n) ? Math.min(Math.max(n, min), max) : def;
}

// Public base URL for links in emails. Without BASE_URL the Host header used to
// be trusted, which lets anyone point a victim's reset link at their own host;
// Render sets RENDER_EXTERNAL_URL automatically, so prefer that.
function publicBaseUrl(req) {
  const configured = process.env.BASE_URL || process.env.RENDER_EXTERNAL_URL;
  if (configured) return configured.replace(/\/+$/, '');
  console.warn('[Auth] ⚠️  BASE_URL not set — link uses the request Host header.');
  return `${req.protocol}://${req.get('host')}`;
}

// "Your password was changed" notice — fire-and-forget, never blocks the change.
function notifyPasswordChanged(userId, method, req) {
  try {
    const u = db.getUserById(userId);
    if (!u || !u.email || !isEmailConfigured()) return;
    sendPasswordChangedEmail(u.email, u.display_name || u.username, method, req && req.ip, publicBaseUrl(req))
      .catch((e) => console.error('[API] Password-changed notice failed:', e.message));
  } catch (e) { console.error('[API] Password-changed notice error:', e.message); }
}

// Source types the aggregator knows. 'browser' drives a headless Chrome at the
// URL (redirects/DNS are not re-validated there) and 'darkweb' spends the
// server's abuse.ch quota, so only admins may choose them. ('blog'/'other' are
// offered by the dashboard form.)
const SOURCE_TYPES = ['rss', 'blog', 'api', 'other', 'website', 'custom'];
const ADMIN_SOURCE_TYPES = [...SOURCE_TYPES, 'browser', 'darkweb'];
const MAX_SOURCES_PER_USER = (() => {
  const v = parseInt(process.env.MAX_SOURCES_PER_USER, 10);
  return Number.isFinite(v) && v > 0 ? v : 100;
})();

// Returns an error string, or null when type/category are acceptable.
function checkSourceTypeAndCategory(user, type, category) {
  if (type !== undefined) {
    const allowed = user.role === 'admin' ? ADMIN_SOURCE_TYPES : SOURCE_TYPES;
    if (typeof type !== 'string' || !allowed.includes(type)) return `Invalid source type. Allowed: ${allowed.join(', ')}`;
  }
  if (category !== undefined) {
    if (typeof category !== 'string' || !/^[a-z0-9_-]{1,30}$/i.test(category)) return 'Invalid category';
  }
  return null;
}

// One address only: commas/semicolons/angle brackets would let a user fan alert
// and test emails out to arbitrary recipient lists.
const EMAIL_RE = /^[^\s@,;<>"()\\]+@[^\s@,;<>"()\\]+\.[^\s@,;<>"()\\]+$/;
const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const isMasked = (v) => typeof v === 'string' && v.includes('...');

// Notification settings: validate each field the dashboard form sends.
// Returns { error } or { clean } (only the fields that were supplied).
function validateNotificationSettings(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return { error: 'Invalid settings' };
  const clean = {};
  const has = (k) => Object.prototype.hasOwnProperty.call(body, k) && body[k] !== undefined;
  const str = (k, max) => {
    const v = body[k];
    if (v === null || v === '') return '';
    if (typeof v === 'number' && Number.isFinite(v)) return String(v);
    if (typeof v !== 'string') return null;
    const s = auth.sanitizeString(v, max + 1);
    return s.length > max ? null : s;
  };
  for (const k of ['email_enabled', 'telegram_enabled', 'teams_enabled', 'whatsapp_enabled', 'digest_mode']) {
    if (!has(k)) continue;
    const v = body[k];
    if (![0, 1, true, false, '0', '1'].includes(v)) return { error: `${k} must be 0 or 1` };
    clean[k] = (v === true || v === 1 || v === '1') ? 1 : 0;
  }
  const rules = {
    email: [255, (s) => EMAIL_RE.test(s), 'Notification email must be a single valid address'],
    telegram_chat_id: [64, (s) => /^(-?\d{1,20}|@[A-Za-z0-9_]{4,64})$/.test(s), 'Invalid Telegram chat id'],
    telegram_bot_token: [256, (s) => isMasked(s) || /^[0-9]+:[A-Za-z0-9_-]+$/.test(s), 'Invalid Telegram bot token'],
    teams_webhook: [2048, (s) => auth.validateUrl(s) && /^https?:\/\//i.test(s), 'Teams webhook must be a public http(s) URL'],
    whatsapp_number: [32, (s) => /^\+?[0-9 ()-]{5,32}$/.test(s), 'Invalid WhatsApp number'],
    whatsapp_apikey: [128, (s) => isMasked(s) || /^[A-Za-z0-9_-]+$/.test(s), 'Invalid WhatsApp API key'],
    severity_threshold: [10, (s) => SEVERITIES.includes(s), 'Invalid severity threshold'],
    keywords_filter: [1000, () => true, 'Keywords filter is too long (max 1000 characters)'],
  };
  for (const [k, [max, ok, msg]] of Object.entries(rules)) {
    if (!has(k)) continue;
    const s = str(k, max);
    if (s === null) return { error: msg };
    if (s === '') {
      if (k === 'severity_threshold') return { error: msg };
      clean[k] = null;   // empty clears the channel
      continue;
    }
    if (!ok(s)) return { error: msg };
    clean[k] = s;
  }
  return { clean };
}

// Per-user throttle for test notifications: each one sends a real email /
// webhook / chat message to an address the user typed (not verified).
const NOTIFY_TEST_MAX = 10;
const NOTIFY_TEST_WINDOW_MS = 10 * 60 * 1000;
const notifyTestThrottle = new Map();

function consumeNotifyTest(userId) {
  const now = Date.now();
  if (notifyTestThrottle.size > 10000) {
    for (const [k, e] of notifyTestThrottle) if (now >= e.resetAt) notifyTestThrottle.delete(k);
  }
  let e = notifyTestThrottle.get(userId);
  if (!e || now >= e.resetAt) { e = { count: 0, resetAt: now + NOTIFY_TEST_WINDOW_MS }; notifyTestThrottle.set(userId, e); }
  if (e.count >= NOTIFY_TEST_MAX) return Math.ceil((e.resetAt - now) / 1000);
  e.count++;
  return 0;
}

// Source types whose fetchers are platform machinery rather than "a feed URL":
// 'browser' drives headless Chrome on every fetch cycle and 'darkweb' spends
// the operator's abuse.ch quota. The built-in sources use them; the UI never
// offers them to users, so only admins may create or switch a source to them.
const ADMIN_ONLY_SOURCE_TYPES = new Set(['browser', 'darkweb']);
function sourceTypeAllowed(user, type) {
  if (user.role === 'admin') return true;
  return !ADMIN_ONLY_SOURCE_TYPES.has(String(type == null ? '' : type).trim().toLowerCase());
}

// The server-wide TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID are the operator's. Only
// admins fall back to them; otherwise any registered user could make the
// operator's bot post into the operator's chat (or into a chat of their choice),
// and their private alerts would land in the operator's chat.
function telegramTarget(user, settings) {
  const envFallback = user && user.role === 'admin';
  return {
    token: settings.telegram_bot_token || (envFallback ? process.env.TELEGRAM_BOT_TOKEN : null),
    chatId: settings.telegram_chat_id || (envFallback ? process.env.TELEGRAM_CHAT_ID : null),
  };
}

// Manual fetch cooldown (non-admins) — a full fetch is heavy on a small VM.

// "Fetch now": admins run the full platform fetch; everyone else fetches only
// their OWN enabled sources (all they can see anyway). Previously a user's click
// started the full ~200-source run (minutes on a 0.1-CPU host), put every other
// user on a shared 5-minute cooldown, and the UI announced "Feeds updated" after
// 5 seconds while nothing of theirs had been fetched yet.
const USER_FETCH_COOLDOWN_MS = 60 * 1000;
const USER_FETCH_WAIT_MS = 25 * 1000;     // answer with the result if it's done by then
const userFetchLast = new Map();          // userId -> last start time
const userFetchRunning = new Set();       // userIds with a fetch in flight

function ownEnabledSources(userId) {
  return db.getDb().prepare('SELECT * FROM sources WHERE user_id = ? AND enabled = 1').all(userId);
}

// Fetch the given sources in the background and alert on new articles, exactly
// like a scheduled run would. Resolves with the aggregator result (or null).
function fetchInBackground(aggregator, sources) {
  if (!aggregator || typeof aggregator.fetchSources !== 'function' || !sources.length) return Promise.resolve(null);
  return aggregator.fetchSources(sources).then(async (result) => {
    if (result && result.newArticles && result.newArticles.length) await handleNotifications(result.newArticles);
    return result;
  }).catch((e) => { console.error('[API] Background fetch error:', e.message); return null; });
}

// ============================================
// AUTH ROUTES (public)
// ============================================

// Public, non-sensitive server facts the sign-in screen needs: whether the
// register form must show the invite-code field (it was always hidden, so with
// REQUIRE_INVITE_CODE=true nobody could register), whether this server can send
// email (reset links / verification codes), and when the database was created
// if this boot created it (ephemeral hosting: earlier accounts are gone).
router.get('/auth/config', (req, res) => {
  res.json({
    requireInvite: auth.inviteRequired(),
    emailEnabled: isEmailConfigured(),
    dbCreatedAt: db.getDbInfo().createdAt
  });
});

router.post('/auth/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const ip = req.ip || req.connection?.remoteAddress;
    const identifier = auth.sanitizeString(username, 255);
    const result = await auth.loginUser(identifier, password, ip);

    if (result.success) {
      // Set httpOnly cookies
      security.setAccessTokenCookie(res, result.accessToken);
      security.setRefreshTokenCookie(res, result.refreshToken);
      // Set CSRF token (readable by JS, sent as X-CSRF-Token header)
      security.setCsrfCookie(res);

      db.logAudit(result.user.id, 'login', 'Successful login', ip);
      return res.json({ success: true, user: result.user });
    } else {
      db.logAudit(null, 'login_failed', `Failed login for: ${identifier}`, ip);
      return res.json(result);
    }
  } catch (error) {
    console.error('[API] Login error:', error.message);
    res.status(500).json({ success: false, error: 'Login failed' });
  }
});

router.post('/auth/register', async (req, res) => {
  try {
    const { username, displayName, password, inviteCode, email } = req.body;
    const ip = req.ip || req.connection?.remoteAddress;
    const result = await auth.registerUser(
      auth.sanitizeString(username, 32),
      auth.sanitizeString(displayName, 64),
      password,
      auth.sanitizeString(inviteCode, 32),
      auth.sanitizeString(email, 255)
    );

    if (result.success) {
      // Set httpOnly cookies
      security.setAccessTokenCookie(res, result.accessToken);
      security.setRefreshTokenCookie(res, result.refreshToken);
      security.setCsrfCookie(res);

      db.logAudit(result.user.id, 'register', 'New user registered', ip);
      if (result.user.email && isEmailConfigured()) {
        sendWelcomeEmail(result.user.email, result.user.displayName || result.user.username, result.user.username, publicBaseUrl(req))
          .catch((e) => console.error('[API] Welcome email failed:', e.message));
      }
      return res.json({ success: true, user: result.user });
    }

    return res.json(result);
  } catch (error) {
    console.error('[API] Register error:', error.message);
    res.status(500).json({ success: false, error: 'Registration failed' });
  }
});

const FORGOT_MSG_EMAIL = 'If an account with that email exists, a reset link has been sent.';
// Without SMTP no email ever leaves the server: saying "a link has been sent"
// left users waiting for nothing. Same text for every address (no enumeration).
const FORGOT_MSG_NO_EMAIL = 'This server cannot send email. If an account with that email exists, a reset link was created — ask the administrator to give it to you (Admin panel → Password Resets).';

router.post('/auth/forgot-password', async (req, res) => {
  const canEmail = isEmailConfigured();
  const genericMessage = canEmail ? FORGOT_MSG_EMAIL : FORGOT_MSG_NO_EMAIL;
  // Simple per-IP throttle: max 3 forgot-password requests per 15 minutes
  const ip = req.ip || req.connection?.remoteAddress || 'unknown';
  if (!forgotPasswordThrottle) forgotPasswordThrottle = new Map();
  const now = Date.now();
  const windowMs = 15 * 60 * 1000;
  const key = `forgot:${ip}`;
  const entry = forgotPasswordThrottle.get(key);
  if (entry && now < entry.resetAt && entry.count >= 3) {
    // Still return generic success to prevent enumeration
    return res.json({ success: true, message: genericMessage, emailDelivery: canEmail });
  }
  if (!entry || now >= entry.resetAt) {
    forgotPasswordThrottle.set(key, { count: 1, resetAt: now + windowMs });
  } else {
    entry.count++;
  }

  try {
    const { email } = req.body;
    const result = auth.forgotPassword(auth.sanitizeString(email, 255));

    // If a user was found, email the reset link. Sent in the background so the
    // response time is the same whether or not the address has an account.
    if (result._token && result._email) {
      // Prefer the configured public URL; falling back to the Host header lets an
      // attacker poison reset links (publicBaseUrl warns when it has to).
      const resetLink = `${publicBaseUrl(req)}/?reset=${result._token}`;
      if (canEmail) {
        sendPasswordResetEmail(result._email, result._name || result._username, resetLink, ip)
          .then((r) => {
            if (r.success) console.log(`[Auth] Password reset email sent to user #${result._userId}`);
            else console.log(`[Auth] ⚠️  Reset email to user #${result._userId} failed: ${r.error} — the link is in Admin → Password Resets`);
          })
          .catch((e) => console.error('[Auth] Reset email error:', e.message));
      } else {
        // SECURITY: the link is never returned in the HTTP response; without email
        // it is only reachable by admins (logs / Admin → Password Resets).
        console.log(`[Auth] Email not configured — reset link for user #${result._userId}: ${resetLink}`);
      }
    }

    // Always return generic success (no user enumeration)
    res.json(result.success
      ? { success: true, message: genericMessage, emailDelivery: canEmail }
      : { success: false, error: result.error });
  } catch (error) {
    console.error('[API] Forgot password error:', error.message);
    res.status(500).json({ success: false, error: 'Request failed' });
  }
});

router.post('/auth/reset-password', async (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const result = await auth.resetPassword(
      auth.sanitizeString(token, 128),
      newPassword
    );
    
    if (result.success) {
      console.log('[Auth] Password reset completed via token');
      notifyPasswordChanged(result._userId, 'reset', req);
    }
    res.json({ success: result.success, message: result.message, error: result.error });
  } catch (error) {
    console.error('[API] Reset password error:', error.message);
    res.status(500).json({ success: false, error: 'Reset failed' });
  }
});

// No requireAuth: the access token is often already expired when the user logs
// out, and the refresh token must still be revoked and the cookies cleared.
// (Still CSRF-protected — /auth/logout is not in the exemption list.)
router.post('/auth/logout', (req, res) => {
  try {
    const { userId } = auth.logoutUser(req);
    security.clearAuthCookies(res);
    if (userId != null) db.logAudit(userId, 'logout', null, req.ip);
    res.json({ success: true });
  } catch (error) {
    console.error('[API] Logout error:', error.message);
    security.clearAuthCookies(res);
    res.status(500).json({ success: false, error: 'Logout failed' });
  }
});

router.get('/auth/me', auth.requireAuth, (req, res) => {
  // Return a fresh CSRF token so the client always has one
  security.setCsrfCookie(res);
  res.json({
    success: true,
    user: req.user
  });
});

// Guest session — lets anonymous visitors use the dashboard without signing in
router.post('/auth/guest', async (req, res) => {
  try {
    const result = await auth.getOrCreateGuestUser();
    if (!result.success) {
      return res.status(result.disabled ? 403 : 500).json({ success: false, error: result.error });
    }
    security.setAccessTokenCookie(res, result.accessToken);
    security.setRefreshTokenCookie(res, result.refreshToken);
    security.setCsrfCookie(res);
    res.json({ success: true, user: result.user });
  } catch (error) {
    console.error('[API] Guest access error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to initialize guest session' });
  }
});

// Refresh access + refresh tokens using the refresh-token cookie
router.post('/auth/refresh', (req, res) => {
  const refreshToken = req.cookies?.tp_refresh;
  if (!refreshToken) {
    return res.status(401).json({ success: false, error: 'No refresh token' });
  }

  const result = auth.refreshAccessToken(refreshToken);
  if (!result.success) {
    security.clearAuthCookies(res);
    return res.status(401).json(result);
  }

  security.setAccessTokenCookie(res, result.accessToken);
  security.setRefreshTokenCookie(res, result.refreshToken);
  security.setCsrfCookie(res);
  res.json({ success: true, user: result.user });
});

router.put('/auth/password', auth.requireAuth, denyGuest, async (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, error: 'Current and new password are required' });
    }
    const user = db.getUserById(req.user.id);

    // Timing-safe verification of the current password
    if (!(await auth.verifyPassword(currentPassword, user.salt, user.password_hash))) {
      return res.status(400).json({ success: false, error: 'Current password is incorrect' });
    }

    const pwCheck = auth.validatePasswordStrength(newPassword);
    if (!pwCheck.valid) return res.status(400).json({ success: false, error: pwCheck.error });

    // Prevent reusing the same password
    if (await auth.verifyPassword(newPassword, user.salt, user.password_hash)) {
      return res.status(400).json({ success: false, error: 'New password must be different from the current one' });
    }

    // Generate verification code (6 digits)
    const code = String(crypto.randomInt(100000, 1000000));
    const expiresAt = auth.sqliteDateTime(Date.now() + 15 * 60 * 1000); // 15 mins

    // Hash the new password and store it as newHash:newSalt in target_value
    const newSalt = auth.generateSalt();
    const newHash = await auth.hashPassword(newPassword, newSalt);
    const targetValue = `${newHash}:${newSalt}`;

    const userEmail = user.email || req.user.email;
    const emailReady = !!userEmail && isEmailConfigured();

    // Apply directly (the current password was already verified) when:
    //  - this is the forced first-login change, or
    //  - no email/SMTP is available to deliver a code (otherwise the account
    //    could never complete the change and would be locked out).
    if (user.must_change_password || !emailReady) {
      db.updateUserPassword(req.user.id, newHash, newSalt); // also clears must_change_password
      auth.revokeUserSessions(req.user.id, req.cookies?.tp_refresh); // log out other sessions
      db.logAudit(req.user.id, 'password_change',
        user.must_change_password ? 'Forced first-login password change' : 'Password changed (email verification unavailable)', req.ip);
      notifyPasswordChanged(req.user.id, user.must_change_password ? 'forced' : 'change', req);
      return res.json({ success: true, verificationRequired: false, message: 'Password updated successfully' });
    }

    const codeId = db.createVerificationCode(req.user.id, 'password_change', targetValue, code, expiresAt);

    // Send code to current email. If it can't be delivered, say so instead of
    // telling the user to wait for a code that will never arrive.
    const sent = await sendVerificationEmail(userEmail, req.user.displayName, 'password_change', code);
    if (!sent || !sent.success) {
      if (codeId) db.deleteVerificationCode(codeId);
      return res.status(502).json({ success: false, error: 'Could not send the verification email. Please try again later.' });
    }

    res.json({ success: true, verificationRequired: true, type: 'password_change', email: userEmail });
  } catch (error) {
    console.error('[API] Change password error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to initiate password change' });
  }
});

router.put('/auth/email', auth.requireAuth, denyGuest, async (req, res) => {
  try {
    const email = auth.sanitizeString(req.body.email, 255);
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, error: 'Valid email address is required' });
    }
    // Step-up: the verification code goes to the NEW address, so without this a
    // stolen/borrowed session could move the account to an attacker's mailbox
    // and then take it over for good via "forgot password" — the very thing the
    // current-password check on PUT /auth/password exists to prevent.
    const user = db.getUserById(req.user.id);
    if (!(await auth.verifyPassword(req.body.currentPassword, user.salt, user.password_hash))) {
      return res.status(400).json({ success: false, error: 'Current password is incorrect' });
    }
    // Ensure email isn't already used by a different account
    const existing = db.getUserByEmail(email);
    if (existing && existing.id !== req.user.id) {
      return res.status(409).json({ success: false, error: 'Email already registered to another account' });
    }

    const previousEmail = req.user.email;
    if (email === previousEmail) {
      return res.status(400).json({ success: false, error: 'That is already your email address' });
    }

    // No SMTP: a verification code could never be delivered, so the change could
    // never complete (the user was told to enter a code that never came). Apply
    // it directly — the same policy as password changes without email.
    if (!isEmailConfigured()) {
      db.updateUserEmail(req.user.id, email);
      db.logAudit(req.user.id, 'email_change', `Email updated to ${email} (email verification unavailable)`, req.ip);
      return res.json({ success: true, verificationRequired: false, email, message: 'Email address updated' });
    }

    // Generate verification code (6 digits)
    const code = String(crypto.randomInt(100000, 1000000));
    const expiresAt = auth.sqliteDateTime(Date.now() + 15 * 60 * 1000); // 15 mins

    const codeId = db.createVerificationCode(req.user.id, 'email_change', email, code, expiresAt);

    // Send verification code to the NEW email address
    const sent = await sendVerificationEmail(email, req.user.displayName, 'email_change', code);
    if (!sent || !sent.success) {
      if (codeId) db.deleteVerificationCode(codeId);
      return res.status(502).json({ success: false, error: 'Could not send the verification email. Please check the address and try again.' });
    }

    res.json({ success: true, verificationRequired: true, type: 'email_change', email });
  } catch (error) {
    console.error('[API] Change email error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to initiate email change' });
  }
});

router.post('/auth/verify-change', auth.requireAuth, denyGuest, (req, res) => {
  try {
    const { type, code } = req.body;
    if (!type || !code) {
      return res.status(400).json({ success: false, error: 'Verification type and code are required' });
    }
    // Arrays/objects used to reach the SQL bind and come back as a 500
    if (!['email_change', 'password_change'].includes(type) ||
        !((typeof code === 'string' && /^\d{6}$/.test(code.trim())) || (Number.isInteger(code) && code >= 100000 && code <= 999999))) {
      return res.status(400).json({ success: false, error: 'Invalid or expired verification code' });
    }

    const verification = db.validateVerificationCode(req.user.id, type, String(code).trim());
    if (!verification) {
      return res.status(400).json({ success: false, error: 'Invalid or expired verification code' });
    }

    if (type === 'email_change') {
      const newEmail = verification.target_value;
      const previousEmail = req.user.email;

      db.updateUserEmail(req.user.id, newEmail);
      db.logAudit(req.user.id, 'email_change', `Email updated to ${newEmail} via verification code`, req.ip);
      db.deleteVerificationCode(verification.id);

      // Confirm to the new address and warn the old one
      sendEmailChangedEmails(req.user.displayName || req.user.username, previousEmail, newEmail, publicBaseUrl(req))
        .catch((mailErr) => console.error('[API] Email-change notice failed:', mailErr.message));

      return res.json({ success: true, email: newEmail, message: 'Email address updated successfully' });

    } else if (type === 'password_change') {
      const [newHash, newSalt] = verification.target_value.split(':');

      db.updateUserPassword(req.user.id, newHash, newSalt); // also clears must_change_password
      auth.revokeUserSessions(req.user.id, req.cookies?.tp_refresh); // log out other sessions
      db.logAudit(req.user.id, 'password_change', 'Password changed via verification code', req.ip);
      notifyPasswordChanged(req.user.id, 'change', req);
      db.deleteVerificationCode(verification.id);

      return res.json({ success: true, message: 'Password updated successfully' });
    }

    res.status(400).json({ success: false, error: 'Unsupported verification type' });
  } catch (error) {
    console.error('[API] Verification error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to verify change' });
  }
});

// ============================================
// ARTICLES (user-scoped, require auth)
// ============================================

router.get('/articles', auth.requireAuth, (req, res) => {
  try {
    const q = req.query || {};
    const time_range = qstr(q.time_range, 10);

    // Translate time_range shorthand to start/end dates
    let startDate = qstr(q.start_date, 40);
    let endDate = qstr(q.end_date, 40);
    if (time_range && time_range !== 'custom' && time_range !== 'all') {
      const now = new Date();
      endDate = now.toISOString();
      const ranges = { '1h': 60*60*1000, '6h': 6*60*60*1000, '12h': 12*60*60*1000, '24h': 24*60*60*1000, '7d': 7*24*60*60*1000, '30d': 30*24*60*60*1000 };
      // own keys only: "constructor"/"__proto__" used to resolve to Object.prototype
      // members -> Invalid Date -> RangeError -> 500
      if (Object.prototype.hasOwnProperty.call(ranges, time_range)) {
        startDate = new Date(now.getTime() - ranges[time_range]).toISOString();
      }
    }

    const result = db.getArticles({
      page: clampInt(q.page, 1, 1, 1000000),
      limit: clampInt(q.limit, 50, 1, 200),
      category: qstr(q.category, 50),
      severity: qstr(q.severity, 20),
      search: qstr(q.search, 200),
      source_type: qstr(q.source_type, 20),
      startDate,
      endDate,
      // Admin sees all articles; guests only built-in system content; users their own.
      userId: readScope(req.user),
      sector: qstr(q.sector, 100),
      threat_actor: qstr(q.threat_actor, 100),
      has_poc: qstr(q.has_poc, 5),
      has_mitre: qstr(q.has_mitre, 5),
      is_patched: qstr(q.is_patched, 5)
    });
    // TTPs per report: tactic, technique (linked to MITRE), the procedure sentence,
    // and whether the report cites the ID or only describes the behaviour
    if (result && Array.isArray(result.articles)) {
      result.articles = result.articles.map((a) => ({ ...a, ttps: attackKb.analyzeTtps(a) }));
    }
    res.json(result);
  } catch (error) {
    console.error('[API] Error fetching articles:', error.message);
    res.status(500).json({ error: 'Failed to fetch articles' });
  }
});

// Threat geography: countries named in the caller's own
// articles, attributed actor origins, origin -> target arcs. Cached briefly per
// scope (a 0.1-CPU host shouldn't rescan thousands of rows on every poll).
const geoCache = new Map();
const GEO_TTL_MS = 3 * 60 * 1000;
router.get('/geo', auth.requireAuth, (req, res) => {
  try {
    const days = [1, 7, 30].includes(parseInt(req.query.days, 10)) ? parseInt(req.query.days, 10) : 7;
    const scope = readScope(req.user);
    const key = `${scope === null ? 'all' : scope}:${days}`;
    const hit = geoCache.get(key);
    if (hit && Date.now() - hit.at < GEO_TTL_MS) return res.json(hit.data);
    const since = new Date(Date.now() - days * 86400000).toISOString();
    const data = geo.buildGeo(db.getGeoArticles(scope, since), days);
    if (geoCache.size > 500) geoCache.delete(geoCache.keys().next().value);
    geoCache.set(key, { at: Date.now(), data });
    res.json(data);
  } catch (error) {
    console.error('[API] Geo error:', error.message);
    res.status(500).json({ error: 'Failed to build threat geography' });
  }
});

// Threat Landscape: ATT&CK techniques (explicit vs inferred), threat actors,
// vulnerabilities, sectors and countries — from the caller's own articles.
const landscapeCache = new Map();
router.get('/landscape', auth.requireAuth, (req, res) => {
  try {
    const days = [1, 7, 30].includes(parseInt(req.query.days, 10)) ? parseInt(req.query.days, 10) : 7;
    const scope = readScope(req.user);
    const key = `${scope === null ? 'all' : scope}:${days}`;
    const hit = landscapeCache.get(key);
    if (hit && Date.now() - hit.at < GEO_TTL_MS) return res.json(hit.data);
    const since = new Date(Date.now() - days * 86400000).toISOString();
    const data = landscape.buildLandscape(db.getGeoArticles(scope, since), days);
    if (landscapeCache.size > 500) landscapeCache.delete(landscapeCache.keys().next().value);
    landscapeCache.set(key, { at: Date.now(), data });
    res.json(data);
  } catch (error) {
    console.error('[API] Landscape error:', error.message);
    res.status(500).json({ error: 'Failed to build threat landscape' });
  }
});

// Analytics page: severity over time, KPIs vs previous period, categories,
// top sources, top sources / techniques over time — caller's own reports.
const analyticsCache = new Map();
router.get('/analytics', auth.requireAuth, async (req, res) => {
  try {
    const days = [1, 7, 14, 30].includes(parseInt(req.query.days, 10)) ? parseInt(req.query.days, 10) : 7;
    const tz = Math.max(-840, Math.min(840, parseInt(req.query.tz, 10) || 0));
    const scope = readScope(req.user);
    const key = `${scope === null ? 'all' : scope}:${days}:${tz}`;
    const hit = analyticsCache.get(key);
    if (hit && Date.now() - hit.at < GEO_TTL_MS) return res.json(hit.data);
    const since = new Date(Date.now() - 2 * days * 86400000).toISOString();
    const rows = db.getGeoArticles(scope, since, 10000);
    const sources = scope === null ? db.getAllSources() : scope === db.SYSTEM_SCOPE ? db.getSystemSources() : db.getSourcesForUser(scope);
    const data = await analytics.buildAnalytics(rows, sources, { days, tz });
    if (analyticsCache.size > 500) analyticsCache.delete(analyticsCache.keys().next().value);
    analyticsCache.set(key, { at: Date.now(), data });
    res.json(data);
  } catch (error) {
    console.error('[API] Analytics error:', error.message);
    res.status(500).json({ error: 'Failed to build analytics' });
  }
});

router.get('/articles/stats', auth.requireAuth, (req, res) => {
  try {
    // Admin sees platform-wide totals; guests system content only; users their own.
    // ?tz = viewer's offset in minutes east of UTC, so "today" is their today
    const stats = db.getArticleStats(readScope(req.user), { tzOffsetMinutes: req.query.tz });
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

router.get('/search', auth.requireAuth, (req, res) => {
  try {
    const { q, limit } = req.query;
    const query = auth.sanitizeString(q, 200);
    if (!query) return res.json([]);   // whitespace-only used to match everything
    const results = db.searchArticles(
      query,
      clampInt(limit, 50, 1, 200),
      readScope(req.user)
    );
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Search failed' });
  }
});

// ============================================
// ARTICLE REVIEWS (require auth)
// ============================================

// Reviews are shown on the article to everyone who can see it, so a user may
// only review articles they can see: their own (admins: any). Previously any
// user could attach reviews/notes to another user's article by id, and a
// missing article surfaced as a 500 (FK error).
function loadReviewableArticle(req, res) {
  const articleId = security.parseId(req.params.id);
  const article = articleId !== null ? db.getArticleById(articleId) : null;
  if (!article) { res.status(404).json({ success: false, error: 'Article not found' }); return null; }
  if (req.user.role !== 'admin' && article.user_id !== req.user.id) {
    res.status(403).json({ success: false, error: 'Not authorized to review this article' });
    return null;
  }
  return articleId;
}

router.post('/articles/:id/review', auth.requireAuth, denyGuest, (req, res) => {
  try {
    const articleId = loadReviewableArticle(req, res);
    if (articleId === null) return;
    const result = db.startReview(articleId, req.user.id);
    db.logAudit(req.user.id, 'review_start', `Started reviewing article ${articleId}`, req.ip);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to start review' });
  }
});

router.put('/articles/:id/review', auth.requireAuth, denyGuest, (req, res) => {
  try {
    const articleId = loadReviewableArticle(req, res);
    if (articleId === null) return;
    const { notes } = req.body;
    const result = db.completeReview(articleId, req.user.id, auth.sanitizeString(notes, 500));
    db.logAudit(req.user.id, 'review_complete', `Completed review of article ${articleId}`, req.ip);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to complete review' });
  }
});

router.post('/articles/:id/escalate', auth.requireAuth, denyGuest, (req, res) => {
  try {
    const articleId = loadReviewableArticle(req, res);
    if (articleId === null) return;
    const { notes } = req.body;
    const result = db.escalateArticle(articleId, req.user.id, auth.sanitizeString(notes, 500));
    db.logAudit(req.user.id, 'escalate', `Escalated article ${articleId}`, req.ip);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to escalate' });
  }
});

// ============================================
// SOURCES (user-scoped, require auth)
// ============================================

router.get('/sources', auth.requireAuth, (req, res) => {
  try {
    // Admins see the full platform source list, guests only the built-in system
    // sources (never other users' private feed URLs); users see only their own.
    const scope = readScope(req.user);
    const sources = scope === null
      ? db.getAllSources()
      : scope === db.SYSTEM_SCOPE
        ? db.getSystemSources()
        : db.getSourcesForUser(scope);
    res.json({ sources });
  } catch (error) {
    console.error('[API] Error fetching sources:', error.message);
    res.status(500).json({ error: 'Failed to fetch sources' });
  }
});

router.post('/sources', auth.requireAuth, denyGuest, (req, res) => {
  try {
    const { url, name } = req.body;
    // Empty/absent -> defaults (the form always sends both)
    const type = req.body.type === undefined || req.body.type === '' ? 'rss' : req.body.type;
    const category = req.body.category === undefined || req.body.category === '' ? 'news' : req.body.category;
    const cleanUrl = auth.sanitizeString(url, 2048);
    const cleanName = auth.sanitizeString(name, 128);

    if (!cleanUrl) return res.status(400).json({ error: 'URL is required' });
    if (!cleanName) return res.status(400).json({ error: 'Name is required' });
    if (!auth.validateUrl(cleanUrl)) {
      return res.status(400).json({ error: 'Invalid URL. Only http/https URLs to public hosts are allowed.' });
    }
    if (!sourceTypeAllowed(req.user, type)) {
      return res.status(403).json({ error: 'This source type is reserved for administrators' });
    }
    const typeErr = checkSourceTypeAndCategory(req.user, type, category);
    if (typeErr) return res.status(400).json({ error: typeErr });
    // Every source is fetched each cycle for everyone: an uncapped list let one
    // account stretch the shared fetch cycle indefinitely.
    if (req.user.role !== 'admin') {
      const count = db.getDb().prepare('SELECT COUNT(*) AS c FROM sources WHERE user_id = ?').get(req.user.id).c;
      if (count >= MAX_SOURCES_PER_USER) {
        return res.status(400).json({ error: `Source limit reached (max ${MAX_SOURCES_PER_USER} per account)` });
      }
    }

    const result = db.addSource({
      name: cleanName,
      url: cleanUrl,
      type,
      category,
      added_by: 'user',
      user_id: req.user.id
    });

    if (result.success) {
      db.logAudit(req.user.id, 'source_add', `Added source: ${cleanName}`, req.ip);
      // Fetch the new source right away instead of leaving it at "Not yet
      // fetched" until the next scheduled run (up to 15 minutes).
      const created = db.getDb().prepare('SELECT * FROM sources WHERE id = ?').get(result.id);
      const aggregator = req.app && req.app.get ? req.app.get('aggregator') : null;
      const fetching = !!(created && aggregator && typeof aggregator.fetchSources === 'function');
      if (fetching) fetchInBackground(aggregator, [created]);
      res.status(201).json({ success: true, id: result.id, fetching });
    } else {
      res.status(409).json({ success: false, error: result.error });
    }
  } catch (error) {
    console.error('[API] Error adding source:', error.message);
    res.status(500).json({ error: 'Failed to add source' });
  }
});

router.put('/sources/:id', auth.requireAuth, denyGuest, (req, res) => {
  try {
    const sourceId = security.parseId(req.params.id);
    // Check ownership
    const source = sourceId !== null && db.getDb().prepare('SELECT * FROM sources WHERE id = ?').get(sourceId);
    if (!source) return res.status(404).json({ error: 'Source not found' });
    // System sources (user_id NULL) are admin-only — previously anyone could edit them.
    if (source.user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not authorized to modify this source' });
    }
    if (req.body && req.body.type !== undefined && !sourceTypeAllowed(req.user, req.body.type)) {
      return res.status(403).json({ error: 'This source type is reserved for administrators' });
    }

    // Validate URL / name if being updated (an empty string used to skip validation)
    const updates = { ...req.body };
    if (updates.url !== undefined) {
      updates.url = auth.sanitizeString(updates.url, 2048);
      if (!updates.url || !auth.validateUrl(updates.url)) {
        return res.status(400).json({ error: 'Invalid URL' });
      }
    }
    if (updates.name !== undefined) {
      updates.name = auth.sanitizeString(updates.name, 128);
      if (!updates.name) return res.status(400).json({ error: 'Name is required' });
    }
    // type/category used to be stored unchecked (any length; arrays/objects -> 500)
    const typeErr = checkSourceTypeAndCategory(req.user, updates.type, updates.category);
    if (typeErr) return res.status(400).json({ error: typeErr });
    if (updates.enabled !== undefined && ![0, 1, true, false, '0', '1'].includes(updates.enabled)) {
      return res.status(400).json({ error: 'enabled must be 0 or 1' });
    }

    const result = db.updateSource(sourceId, updates);
    if (!result.success && /already exists/.test(result.error || '')) return res.status(409).json(result);
    res.json(result);
  } catch (error) {
    console.error('[API] Error updating source:', error.message);
    res.status(500).json({ error: 'Failed to update source' });
  }
});

router.delete('/sources/:id', auth.requireAuth, denyGuest, (req, res) => {
  try {
    const sourceId = security.parseId(req.params.id);
    const source = sourceId !== null && db.getDb().prepare('SELECT * FROM sources WHERE id = ?').get(sourceId);
    if (!source) return res.status(404).json({ error: 'Source not found' });
    
    // Only source owner or admin can delete
    if (source.user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not authorized to delete this source' });
    }

    const result = db.deleteSource(sourceId);
    if (result.success) {
      db.logAudit(req.user.id, 'source_delete', `Deleted source: ${source.name}`, req.ip);
      res.json(result);
    } else {
      res.status(400).json(result);
    }
  } catch (error) {
    console.error('[API] Error deleting source:', error.message);
    res.status(500).json({ error: 'Failed to delete source' });
  }
});

// ============================================
// FETCH TRIGGER (require auth)
// ============================================

router.post('/fetch-now', auth.requireAuth, denyGuest, async (req, res) => {
  try {
    const aggregator = req.app.get('aggregator');
    if (!aggregator) return res.status(500).json({ error: 'Aggregator not initialized' });

    if (req.user.role === 'admin') {
      if (aggregator.getStatus && aggregator.getStatus().isRunning) {
        return res.json({ success: true, scope: 'all', alreadyRunning: true, completed: false,
          message: 'A full fetch is already running. New articles will appear as it progresses.' });
      }
      res.json({ success: true, scope: 'all', completed: false,
        message: 'Full fetch of all sources started. This can take several minutes; new articles appear as they arrive.' });
      const result = await aggregator.fetchAllSources();
      if (result && result.newArticles && result.newArticles.length > 0) {
        await handleNotifications(result.newArticles);
      }
      return;
    }

    const userId = req.user.id;
    const sources = ownEnabledSources(userId);
    if (sources.length === 0) {
      return res.status(400).json({ success: false, error: 'You have no enabled sources to fetch. Add a source first.' });
    }
    if (userFetchRunning.has(userId)) {
      return res.json({ success: true, scope: 'own', alreadyRunning: true, completed: false,
        message: 'Your sources are already being fetched.' });
    }
    const wait = (userFetchLast.get(userId) || 0) + USER_FETCH_COOLDOWN_MS - Date.now();
    if (wait > 0) {
      return res.status(429).json({ success: false, error: `You fetched recently. Try again in ${Math.ceil(wait / 1000)} second(s).` });
    }
    userFetchLast.set(userId, Date.now());
    userFetchRunning.add(userId);
    if (userFetchLast.size > 10000) userFetchLast.delete(userFetchLast.keys().next().value);

    const job = fetchInBackground(aggregator, sources).finally(() => userFetchRunning.delete(userId));
    let timer;
    const timeout = new Promise(resolve => { timer = setTimeout(() => resolve('timeout'), USER_FETCH_WAIT_MS); });
    const outcome = await Promise.race([job, timeout]);
    clearTimeout(timer);
    if (outcome === 'timeout') {
      return res.json({ success: true, scope: 'own', completed: false, sources: sources.length,
        message: `Fetching your ${sources.length} source(s) — still running; new articles will appear shortly.` });
    }
    const newCount = outcome ? outcome.new || 0 : 0;
    const errors = outcome ? outcome.errors || 0 : 0;
    res.json({ success: true, scope: 'own', completed: true, sources: sources.length, newArticles: newCount, errors,
      message: `Fetched ${sources.length} source(s): ${newCount} new article(s)${errors ? `, ${errors} source(s) failed (see the source list)` : ''}.` });
  } catch (error) {
    console.error('[API] Fetch error:', error.message);
    if (!res.headersSent && !res.done) res.status(500).json({ success: false, error: 'Fetch failed' });
  }
});

router.get('/status', auth.requireAuth, (req, res) => {
  try {
    const aggregator = req.app.get('aggregator');
    const status = aggregator ? aggregator.getStatus() : { isRunning: false };
    res.json(status);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get status' });
  }
});

// ============================================
// NOTIFICATIONS (user-scoped, require auth)
// ============================================

router.get('/notifications/settings', auth.requireAuth, (req, res) => {
  try {
    const settings = db.getNotificationSettings(req.user.id) || {};
    // Mask sensitive secrets before sending to the browser
    if (settings.telegram_bot_token) {
      settings.telegram_bot_token = settings.telegram_bot_token.slice(0, 8) + '...' + settings.telegram_bot_token.slice(-6);
    }
    if (settings.whatsapp_apikey) {
      settings.whatsapp_apikey = '...' + String(settings.whatsapp_apikey).slice(-3);
    }
    res.json(settings);
  } catch (error) {
    res.status(500).json({ error: 'Failed to get settings' });
  }
});

router.put('/notifications/settings', auth.requireAuth, denyGuest, (req, res) => {
  try {
    // Fields used to be stored unvalidated: arrays/objects -> 500, megabyte
    // strings, comma-separated recipient lists for alert/test emails, internal
    // webhook URLs, unknown severity thresholds.
    const { error, clean } = validateNotificationSettings(req.body);
    if (error) return res.status(400).json({ success: false, error });
    const result = db.updateNotificationSettings(clean, req.user.id);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

router.post('/notifications/test', auth.requireAuth, denyGuest, async (req, res) => {
  try {
    const { type } = req.body;
    const settings = db.getNotificationSettings(req.user.id);
    if (!settings) return res.status(400).json({ error: 'No notification settings configured' });
    const wait = consumeNotifyTest(req.user.id);
    if (wait) {
      res.setHeader('Retry-After', String(wait));
      return res.status(429).json({ success: false, error: 'Too many test notifications. Please wait a few minutes.' });
    }

    const testArticle = {
      title: '🔔 ThreatPulse Test Notification',
      description: `This is a test notification for ${req.user.displayName}. Your alerts are working!`,
      url: 'https://threatpulse.app',
      severity: 'high',
      source_name: 'ThreatPulse',
      published_date: new Date().toISOString()
    };

    if (type === 'email') {
      if (!settings.email) return res.status(400).json({ error: 'No email address configured' });
      return res.json(await sendAlertEmail([testArticle], settings.email));
    } else if (type === 'telegram') {
      const { token, chatId } = telegramTarget(req.user, settings);
      if (!token || !chatId) return res.status(400).json({ error: 'Telegram not configured' });
      return res.json(await sendTelegramAlert([testArticle], token, chatId));
    } else if (type === 'teams') {
      if (!settings.teams_webhook) return res.status(400).json({ error: 'Teams webhook not configured' });
      return res.json(await sendTeamsAlert([testArticle], settings.teams_webhook));
    } else if (type === 'whatsapp') {
      if (!settings.whatsapp_number || !settings.whatsapp_apikey) return res.status(400).json({ error: 'WhatsApp not configured' });
      return res.json(await sendWhatsAppAlert([testArticle], settings.whatsapp_number, settings.whatsapp_apikey));
    }

    res.status(400).json({ error: 'Invalid notification type' });
  } catch (error) {
    res.status(500).json({ error: 'Test failed' });
  }
});

// ============================================
// ADMIN ROUTES (require admin)
// ============================================

router.get('/admin/users', auth.requireAuth, auth.requireAdmin, (req, res) => {
  try {
    res.json({ users: db.getAllUsers() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch users' });
  }
});

router.put('/admin/users/:id', auth.requireAuth, auth.requireAdmin, (req, res) => {
  try {
    const userId = security.parseId(req.params.id);
    if (userId === null) return res.status(400).json({ success: false, error: 'Invalid user id' });
    const target = db.getUserById(userId);
    if (!target) return res.status(404).json({ success: false, error: 'User not found' });
    const body = req.body || {};
    const updates = {};

    if (body.display_name !== undefined) {
      const name = auth.sanitizeString(body.display_name, 65);
      if (name.length < 2 || name.length > 64) {
        return res.status(400).json({ success: false, error: 'Display name must be 2-64 characters' });
      }
      updates.display_name = name;
    }
    if (body.role !== undefined) {
      if (!['admin', 'analyst'].includes(body.role)) {
        return res.status(400).json({ success: false, error: 'Role must be "admin" or "analyst"' });
      }
      updates.role = body.role;
    }
    if (body.is_active !== undefined) {
      if (![0, 1, true, false].includes(body.is_active)) {
        return res.status(400).json({ success: false, error: 'is_active must be 0 or 1' });
      }
      updates.is_active = body.is_active ? 1 : 0;
    }

    // An admin locking themselves out could leave the instance with no admin at all
    // (no SMTP / admin email → no recovery path short of editing the database).
    if (userId === req.user.id && (updates.role === 'analyst' || updates.is_active === 0)) {
      return res.status(400).json({ success: false, error: 'You cannot demote or disable your own account' });
    }
    // The shared guest account is used by every anonymous visitor: promoting it
    // would make the whole internet an admin.
    if (target.username === auth.GUEST_USERNAME && updates.role === 'admin') {
      return res.status(400).json({ success: false, error: 'The shared guest account cannot be made an admin' });
    }

    const result = db.updateUser(userId, updates);
    if (!result.success) return res.status(400).json(result);
    db.logAudit(req.user.id, 'admin_user_update', `Updated user ${userId}: ${JSON.stringify(updates)}`, req.ip);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

router.delete('/admin/users/:id', auth.requireAuth, auth.requireAdmin, (req, res) => {
  try {
    const userId = security.parseId(req.params.id);
    if (userId === null) return res.status(400).json({ success: false, error: 'Invalid user id' });
    if (userId === req.user.id) return res.status(400).json({ success: false, error: 'Cannot delete yourself' });
    if (!db.getUserById(userId)) return res.status(404).json({ success: false, error: 'User not found' });
    // One transaction: deleteUser issues several DELETEs, and a failure part-way
    // (e.g. the FK from invite_codes.created_by) used to wipe the user's sources and
    // articles while leaving the account in place. Invite codes the user created are
    // handed to the acting admin so that FK no longer blocks the delete.
    const d = db.getDb();
    let result;
    try {
      d.transaction(() => {
        d.prepare('UPDATE invite_codes SET created_by = ? WHERE created_by = ?').run(req.user.id, userId);
        result = db.deleteUser(userId);
        if (!result.success) throw Object.assign(new Error('rollback'), { rollback: true });
      })();
    } catch (e) {
      if (!e.rollback) throw e;
    }
    if (result.success) {
      db.logAudit(req.user.id, 'admin_user_delete', `Deleted user ${userId}`, req.ip);
    }
    res.status(result.success ? 200 : 400).json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

router.post('/admin/invite-codes', auth.requireAuth, auth.requireAdmin, (req, res) => {
  try {
    const code = crypto.randomBytes(4).toString('hex').toUpperCase();
    const result = db.createInviteCode(req.user.id, code);
    db.logAudit(req.user.id, 'invite_code_create', `Created invite code: ${code}`, req.ip);
    res.json({ success: true, code });
  } catch (error) {
    res.status(500).json({ error: 'Failed to create invite code' });
  }
});

router.get('/admin/invite-codes', auth.requireAuth, auth.requireAdmin, (req, res) => {
  try {
    res.json({ codes: db.getValidInviteCodes() });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch invite codes' });
  }
});

router.get('/admin/articles', auth.requireAuth, auth.requireAdmin, (req, res) => {
  try {
    const q = req.query || {};
    const result = db.getArticles({
      page: clampInt(q.page, 1, 1, 1000000),
      limit: clampInt(q.limit, 50, 1, 200),
      category: qstr(q.category, 50),
      severity: qstr(q.severity, 20),
      search: qstr(q.search, 200)
      // No userId filter — god view
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch articles' });
  }
});

// Admin: one entry per unique feed across all users (duplicates folded,
// built-in vs user-submitted, with every contributor's name)
router.get('/admin/source-catalog', auth.requireAuth, auth.requireAdmin, (req, res) => {
  try {
    res.json(sourceCatalog.buildCatalog(db.getAllSources(), db.getAllUsers()));
  } catch (error) {
    console.error('[API] Source catalog error:', error.message);
    res.status(500).json({ error: 'Failed to build source catalog' });
  }
});

router.get('/admin/sources', auth.requireAuth, auth.requireAdmin, (req, res) => {
  try {
    const sources = db.getAllSources();
    // Enrich with user info
    const users = {};
    db.getAllUsers().forEach(u => users[u.id] = u.display_name);
    const enriched = sources.map(s => ({
      ...s,
      added_by_name: s.user_id ? (users[s.user_id] || 'Unknown') : 'System'
    }));
    res.json({ sources: enriched });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch sources' });
  }
});

router.get('/admin/stats', auth.requireAuth, auth.requireAdmin, (req, res) => {
  try {
    const stats = db.getArticleStats(); // No user filter
    const d = db.getDb();
    stats.totalUsers = d.prepare('SELECT COUNT(*) as count FROM users WHERE is_active = 1').get().count;
    stats.totalSourcesAll = d.prepare('SELECT COUNT(*) as count FROM sources').get().count;
    stats.errorsToday = d.prepare("SELECT COUNT(*) as count FROM sources WHERE last_error IS NOT NULL AND last_fetched >= date('now')").get().count;
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

router.get('/admin/audit-log', auth.requireAuth, auth.requireAdmin, (req, res) => {
  try {
    // A negative LIMIT means "no limit" in SQLite
    const limit = clampInt(req.query.limit, 100, 1, 500);
    res.json({ log: db.getAuditLog(limit) });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch audit log' });
  }
});

// Admin: view pending password reset tokens (for manual recovery)
router.get('/admin/reset-tokens', auth.requireAuth, auth.requireAdmin, (req, res) => {
  try {
    // Manual recovery only: with SMTP working the user gets the link by email,
    // so the token is never shown. Links for OTHER admin accounts are always
    // withheld — otherwise one admin could take over another admin's account.
    const emailWorks = isEmailConfigured();
    const pending = db.getPendingResetTokens().map((t) => {
      const owner = db.getUserById(t.user_id);
      const otherAdmin = owner && owner.role === 'admin' && owner.id !== req.user.id;
      const withheld = emailWorks || otherAdmin;
      return {
        id: t.id, user_id: t.user_id, username: t.username, email: t.email,
        expires_at: t.expires_at, created_at: t.created_at,
        token: withheld ? null : t.token,
        withheld: withheld ? (otherAdmin ? 'admin_account' : 'emailed') : null,
      };
    });
    if (pending.some((t) => t.token)) db.logAudit(req.user.id, 'reset_tokens_view', `Viewed ${pending.filter((t) => t.token).length} reset link(s)`, req.ip);
    res.json({ tokens: pending });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch reset tokens' });
  }
});

// Admin: email delivery status + a test message to the admin's own address
router.get('/admin/email-status', auth.requireAuth, auth.requireAdmin, (req, res) => {
  const d = describeEmail();
  const me = db.getUserById(req.user.id);
  res.json({
    configured: !!d.provider, provider: d.provider || null, from: d.from || null, problem: d.problem || null,
    adminEmail: (me && me.email) || null, inviteRequired: auth.inviteRequired(),
  });
});

router.post('/admin/email-test', auth.requireAuth, auth.requireAdmin, async (req, res) => {
  try {
    const me = db.getUserById(req.user.id);
    if (!me || !me.email) return res.status(400).json({ success: false, error: 'Your admin account has no email address. Add one with Change Email first.' });
    if (!isEmailConfigured()) return res.status(400).json({ success: false, error: 'Email delivery is not configured. Set BREVO_API_KEY and MAIL_FROM on the server.' });
    const wait = consumeNotifyTest(req.user.id);
    if (wait) return res.status(429).json({ success: false, error: `Too many test messages — try again in ${wait}s` });
    const r = await sendWelcomeEmail(me.email, me.display_name || me.username, me.username, publicBaseUrl(req));
    db.logAudit(req.user.id, 'email_test', r.success ? `Test email sent to ${me.email}` : `Test email failed: ${r.error}`, req.ip);
    res.status(r.success ? 200 : 502).json(r.success ? { success: true, to: me.email } : { success: false, error: r.error });
  } catch (e) {
    res.status(500).json({ success: false, error: 'Failed to send test email' });
  }
});

// Admin: AI settings — configure Gemini/Tavily keys from the UI (no SSH needed)
const maskSecret = (v) => (v ? String(v).slice(0, 8) + '...' + String(v).slice(-4) : null);

router.get('/admin/ai-settings', auth.requireAuth, auth.requireAdmin, (req, res) => {
  try {
    const groq = db.getSetting('groq_api_key');
    const tavily = db.getSetting('tavily_api_key');
    res.json({
      groq_api_key: maskSecret(groq),
      tavily_api_key: maskSecret(tavily),
      groq_set: !!(groq || process.env.GROQ_API_KEY),
      tavily_set: !!(tavily || process.env.TAVILY_API_KEY),
      model: process.env.GROQ_MODEL || 'llama-3.3-70b-versatile'
    });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch AI settings' });
  }
});

router.put('/admin/ai-settings', auth.requireAuth, auth.requireAdmin, (req, res) => {
  try {
    // Keys go into an Authorization header: refuse anything that isn't a plausible
    // key (megabyte strings, whitespace/CR/LF, control characters).
    for (const key of ['groq_api_key', 'tavily_api_key']) {
      const v = req.body?.[key];
      if (typeof v === 'string' && (v.trim().length > 512 || /[\s\u0000-\u001f\u007f]/.test(v.trim()))) {
        return res.status(400).json({ success: false, error: `Invalid ${key}` });
      }
    }
    const apply = (key, value) => {
      if (typeof value !== 'string') return;
      const v = value.trim();
      if (v && !v.includes('...')) db.setSetting(key, v);   // real value -> save
      else if (v === '') db.setSetting(key, null);          // empty -> clear
      // masked value ("...") -> leave unchanged
    };
    apply('groq_api_key', req.body?.groq_api_key);
    apply('tavily_api_key', req.body?.tavily_api_key);
    db.logAudit(req.user.id, 'ai_settings_update', 'Updated AI API keys', req.ip);
    res.json({ success: true });
  } catch (error) {
    console.error('[API] Save AI settings error:', error.message);
    res.status(500).json({ error: 'Failed to save AI settings' });
  }
});

// ============================================
// NOTIFICATION HANDLER
// ============================================

async function handleNotifications(newArticles) {
  try {
    if (!newArticles || newArticles.length === 0) return;

    console.log(`[Notifications] ${newArticles.length} new articles to process`);

    // Group articles by owning user (fully isolated — each user only gets alerts
    // for threats found in their OWN sources).
    // Articles from system sources have user_id NULL until the startup orphan
    // migration hands them to the admin — which never happens on a fresh DB
    // (admin is created after the schema), i.e. on every Render boot. Route
    // them to the same owner that migration would pick: the first admin.
    const allUsers = db.getAllUsers();
    const firstAdmin = allUsers.filter(u => u.role === 'admin').sort((a, b) => a.id - b.id)[0];
    const articlesByUser = {};
    for (const article of newArticles) {
      const ownerId = article.user_id || (firstAdmin && firstAdmin.id);
      if (!ownerId) continue;
      if (!articlesByUser[ownerId]) articlesByUser[ownerId] = [];
      articlesByUser[ownerId].push(article);
    }

    for (const user of allUsers) {
      if (!user.is_active) continue;   // deactivated accounts get no alerts
      let userArticles = articlesByUser[user.id];
      if (!userArticles || userArticles.length === 0) continue;

      const settings = db.getNotificationSettings(user.id);
      if (!settings) continue;

      // Severity threshold filter
      const sevOrder = { critical: 4, high: 3, medium: 2, low: 1 };
      const threshold = sevOrder[settings.severity_threshold] || 2;
      userArticles = userArticles.filter(a => (sevOrder[a.severity] || 1) >= threshold);

      // Keyword filter
      if (settings.keywords_filter && settings.keywords_filter.trim()) {
        const keywords = settings.keywords_filter.split(',').map(k => k.trim().toLowerCase()).filter(Boolean);
        if (keywords.length > 0) {
          userArticles = userArticles.filter(a => {
            const text = `${a.title || ''} ${a.description || ''} ${a.tags || ''} ${a.cve_id || ''} ${a.threat_actors || ''} ${a.mitre_ids || ''}`.toLowerCase();
            return keywords.some(kw => text.includes(kw));
          });
        }
      }

      if (userArticles.length === 0) continue;

      const logAll = (via, recipient, result) => {
        for (const article of userArticles) {
          db.logNotification({
            article_id: article.id, user_id: user.id, sent_via: via, recipient,
            status: result.success ? 'sent' : 'failed', error_message: result.error || null
          });
        }
      };

      // Telegram
      const { token: tgToken, chatId: tgChat } = telegramTarget(user, settings);
      if (settings.telegram_enabled && tgToken && tgChat) {
        console.log(`[Notifications] ${user.username}: ${userArticles.length} via Telegram`);
        logAll('telegram', tgChat, await sendTelegramAlert(userArticles, tgToken, tgChat));
      }

      // Microsoft Teams
      if (settings.teams_enabled && settings.teams_webhook) {
        console.log(`[Notifications] ${user.username}: ${userArticles.length} via Teams`);
        logAll('teams', 'teams-channel', await sendTeamsAlert(userArticles, settings.teams_webhook));
      }

      // WhatsApp
      if (settings.whatsapp_enabled && settings.whatsapp_number && settings.whatsapp_apikey) {
        console.log(`[Notifications] ${user.username}: ${userArticles.length} via WhatsApp`);
        logAll('whatsapp', settings.whatsapp_number, await sendWhatsAppAlert(userArticles, settings.whatsapp_number, settings.whatsapp_apikey));
      }

      // Email
      if (settings.email_enabled && settings.email) {
        console.log(`[Notifications] ${user.username}: ${userArticles.length} via Email`);
        logAll('email', settings.email, await sendAlertEmail(userArticles, settings.email));
      }
    }

    // Mark all processed articles as notified
    const articleIds = newArticles.map(a => a.id).filter(Boolean);
    if (articleIds.length > 0) db.markAsNotified(articleIds);

  } catch (error) {
    console.error(`[Notifications] Error: ${error.message}`);
  }
}

module.exports = router;
module.exports.handleNotifications = handleNotifications;
module.exports._resetFetchThrottle = () => { userFetchLast.clear(); userFetchRunning.clear(); };

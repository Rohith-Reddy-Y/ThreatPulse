/**
 * ThreatPulse — API Routes (v2 Multi-User)
 * All routes are user-scoped with JWT authentication
 */

const express = require('express');
const router = express.Router();
const db = require('../database');
const auth = require('../auth');
const { sendAlertEmail } = require('../notifications/email-notifier');
const { sendTelegramAlert } = require('../notifications/telegram-notifier');
const { sendTeamsAlert } = require('../notifications/teams-notifier');
const { sendWhatsAppAlert } = require('../notifications/whatsapp-notifier');

// ============================================
// AUTH ROUTES (public)
// ============================================

router.post('/auth/login', (req, res) => {
  try {
    const { username, password } = req.body;
    const ip = req.ip || req.connection?.remoteAddress;
    // Accept a username OR an email as the identifier (emails can be up to 255 chars)
    const identifier = auth.sanitizeString(username, 255);
    const result = auth.loginUser(identifier, password);

    if (result.success) {
      db.logAudit(result.user.id, 'login', 'Successful login', ip);
    } else {
      db.logAudit(null, 'login_failed', `Failed login for: ${identifier}`, ip);
    }

    res.json(result);
  } catch (error) {
    console.error('[API] Login error:', error.message);
    res.status(500).json({ success: false, error: 'Login failed' });
  }
});

router.post('/auth/register', (req, res) => {
  try {
    const { username, displayName, password, inviteCode, email } = req.body;
    const ip = req.ip || req.connection?.remoteAddress;
    const result = auth.registerUser(
      auth.sanitizeString(username, 32),
      auth.sanitizeString(displayName, 64),
      password,
      auth.sanitizeString(inviteCode, 32),
      auth.sanitizeString(email, 255)
    );

    if (result.success) {
      db.logAudit(result.user.id, 'register', 'New user registered', ip);
    }

    res.json(result);
  } catch (error) {
    console.error('[API] Register error:', error.message);
    res.status(500).json({ success: false, error: 'Registration failed' });
  }
});

router.post('/auth/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    const result = auth.forgotPassword(auth.sanitizeString(email, 255));

    // If user was found, send reset email
    if (result._token && result._email) {
      const baseUrl = process.env.BASE_URL || `${req.protocol}://${req.get('host')}`;
      const resetLink = `${baseUrl}/?reset=${result._token}`;
      
      try {
        const { sendAlertEmail } = require('../notifications/email-notifier');
        const resetArticle = [{
          title: '🔑 Password Reset Request',
          description: `Hello ${result._username}, you (or someone) requested a password reset. Click the link below to reset your password. This link expires in 1 hour. If you did not request this, ignore this email.`,
          url: resetLink,
          source_name: 'ThreatPulse Security',
          published_date: new Date().toISOString(),
          category: 'advisory',
          severity: 'high',
          cve_id: null,
          is_patched: -1,
          has_poc: 0,
          tags: 'password-reset'
        }];
        await sendAlertEmail(resetArticle, result._email);
        console.log(`[Auth] Password reset email sent to ${result._email}`);
      } catch (emailErr) {
        console.error(`[Auth] Failed to send reset email: ${emailErr.message}`);
      }
    }

    // Always return generic success (no user enumeration)
    res.json({ success: result.success, message: result.message, error: result.error });
  } catch (error) {
    console.error('[API] Forgot password error:', error.message);
    res.status(500).json({ success: false, error: 'Request failed' });
  }
});

router.post('/auth/reset-password', (req, res) => {
  try {
    const { token, newPassword } = req.body;
    const result = auth.resetPassword(
      auth.sanitizeString(token, 128),
      newPassword
    );
    
    if (result.success) {
      console.log('[Auth] Password reset completed via token');
    }
    
    res.json(result);
  } catch (error) {
    console.error('[API] Reset password error:', error.message);
    res.status(500).json({ success: false, error: 'Reset failed' });
  }
});

router.post('/auth/logout', auth.requireAuth, (req, res) => {
  auth.logoutUser(req.token);
  db.logAudit(req.user.id, 'logout', null, req.ip);
  res.json({ success: true });
});

router.get('/auth/me', auth.requireAuth, (req, res) => {
  res.json({
    success: true,
    user: req.user
  });
});

router.put('/auth/password', auth.requireAuth, (req, res) => {
  try {
    const { currentPassword, newPassword } = req.body;
    if (!currentPassword || !newPassword) {
      return res.status(400).json({ success: false, error: 'Current and new password are required' });
    }
    const user = db.getUserById(req.user.id);

    // Timing-safe verification of the current password
    if (!auth.verifyPassword(currentPassword, user.salt, user.password_hash)) {
      return res.status(400).json({ success: false, error: 'Current password is incorrect' });
    }

    const pwCheck = auth.validatePasswordStrength(newPassword);
    if (!pwCheck.valid) return res.status(400).json({ success: false, error: pwCheck.error });

    // Prevent reusing the same password
    if (auth.verifyPassword(newPassword, user.salt, user.password_hash)) {
      return res.status(400).json({ success: false, error: 'New password must be different from the current one' });
    }

    const salt = auth.generateSalt();
    const newHash = auth.hashPassword(newPassword, salt);
    db.updateUserPassword(req.user.id, newHash, salt); // also clears must_change_password
    db.logAudit(req.user.id, 'password_change', 'Password changed', req.ip);

    res.json({ success: true });
  } catch (error) {
    console.error('[API] Change password error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to change password' });
  }
});

router.put('/auth/email', auth.requireAuth, (req, res) => {
  try {
    const email = auth.sanitizeString(req.body.email, 255);
    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return res.status(400).json({ success: false, error: 'Valid email address is required' });
    }
    // Ensure email isn't already used by a different account
    const existing = db.getUserByEmail(email);
    if (existing && existing.id !== req.user.id) {
      return res.status(409).json({ success: false, error: 'Email already registered to another account' });
    }
    db.updateUserEmail(req.user.id, email);
    db.logAudit(req.user.id, 'email_change', `Email updated to ${email}`, req.ip);
    res.json({ success: true, email });
  } catch (error) {
    console.error('[API] Change email error:', error.message);
    res.status(500).json({ success: false, error: 'Failed to update email' });
  }
});

// ============================================
// ARTICLES (user-scoped, require auth)
// ============================================

router.get('/articles', auth.requireAuth, (req, res) => {
  try {
    const { page, limit, category, severity, search, source_type, start_date, end_date, sector, threat_actor, has_poc, has_mitre, is_patched } = req.query;
    const result = db.getArticles({
      page: parseInt(page) || 1,
      limit: Math.min(parseInt(limit) || 50, 200),
      category,
      severity,
      search: auth.sanitizeString(search, 200),
      source_type,
      startDate: start_date,
      endDate: end_date,
      // Admin sees all articles; regular users are isolated to their own.
      userId: req.user.role === 'admin' ? null : req.user.id,
      sector,
      threat_actor: auth.sanitizeString(threat_actor, 100),
      has_poc,
      has_mitre,
      is_patched
    });
    res.json(result);
  } catch (error) {
    console.error('[API] Error fetching articles:', error.message);
    res.status(500).json({ error: 'Failed to fetch articles' });
  }
});

router.get('/articles/stats', auth.requireAuth, (req, res) => {
  try {
    // Admin sees platform-wide totals; users see only their own.
    const stats = db.getArticleStats(req.user.role === 'admin' ? null : req.user.id);
    res.json(stats);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch stats' });
  }
});

router.get('/search', auth.requireAuth, (req, res) => {
  try {
    const { q, limit } = req.query;
    if (!q) return res.json([]);
    const results = db.searchArticles(
      auth.sanitizeString(q, 200),
      Math.min(parseInt(limit) || 50, 200),
      req.user.role === 'admin' ? null : req.user.id
    );
    res.json(results);
  } catch (error) {
    res.status(500).json({ error: 'Search failed' });
  }
});

// ============================================
// ARTICLE REVIEWS (require auth)
// ============================================

router.post('/articles/:id/review', auth.requireAuth, (req, res) => {
  try {
    const articleId = parseInt(req.params.id);
    const result = db.startReview(articleId, req.user.id);
    db.logAudit(req.user.id, 'review_start', `Started reviewing article ${articleId}`, req.ip);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to start review' });
  }
});

router.put('/articles/:id/review', auth.requireAuth, (req, res) => {
  try {
    const articleId = parseInt(req.params.id);
    const { notes } = req.body;
    const result = db.completeReview(articleId, req.user.id, auth.sanitizeString(notes, 500));
    db.logAudit(req.user.id, 'review_complete', `Completed review of article ${articleId}`, req.ip);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to complete review' });
  }
});

router.post('/articles/:id/escalate', auth.requireAuth, (req, res) => {
  try {
    const articleId = parseInt(req.params.id);
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
    const sources = db.getSourcesForUser(req.user.id);
    res.json({ sources });
  } catch (error) {
    console.error('[API] Error fetching sources:', error.message);
    res.status(500).json({ error: 'Failed to fetch sources' });
  }
});

router.post('/sources', auth.requireAuth, (req, res) => {
  try {
    const { url, name, type = 'rss', category = 'news' } = req.body;
    const cleanUrl = auth.sanitizeString(url, 2048);
    const cleanName = auth.sanitizeString(name, 128);

    if (!cleanUrl) return res.status(400).json({ error: 'URL is required' });
    if (!cleanName) return res.status(400).json({ error: 'Name is required' });
    if (!auth.validateUrl(cleanUrl)) {
      return res.status(400).json({ error: 'Invalid URL. Only http/https URLs to public hosts are allowed.' });
    }

    const result = db.addSource({
      name: cleanName,
      url: cleanUrl,
      type: auth.sanitizeString(type, 20),
      category: auth.sanitizeString(category, 30),
      added_by: 'user',
      user_id: req.user.id
    });

    if (result.success) {
      db.logAudit(req.user.id, 'source_add', `Added source: ${cleanName}`, req.ip);
      res.status(201).json({ success: true, id: result.id });
    } else {
      res.status(409).json({ success: false, error: result.error });
    }
  } catch (error) {
    console.error('[API] Error adding source:', error.message);
    res.status(500).json({ error: 'Failed to add source' });
  }
});

router.put('/sources/:id', auth.requireAuth, (req, res) => {
  try {
    const { id } = req.params;
    const sourceId = parseInt(id);
    // Check ownership
    const source = db.getDb().prepare('SELECT * FROM sources WHERE id = ?').get(sourceId);
    if (!source) return res.status(404).json({ error: 'Source not found' });
    if (source.user_id && source.user_id !== req.user.id && req.user.role !== 'admin') {
      return res.status(403).json({ error: 'Not authorized to modify this source' });
    }

    // Validate URL if being updated
    if (req.body.url) {
      if (!auth.validateUrl(req.body.url)) {
        return res.status(400).json({ error: 'Invalid URL' });
      }
    }

    const result = db.updateSource(sourceId, req.body);
    res.json(result);
  } catch (error) {
    console.error('[API] Error updating source:', error.message);
    res.status(500).json({ error: 'Failed to update source' });
  }
});

router.delete('/sources/:id', auth.requireAuth, (req, res) => {
  try {
    const sourceId = parseInt(req.params.id);
    const source = db.getDb().prepare('SELECT * FROM sources WHERE id = ?').get(sourceId);
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

router.post('/fetch-now', auth.requireAuth, async (req, res) => {
  try {
    const aggregator = req.app.get('aggregator');
    if (!aggregator) return res.status(500).json({ error: 'Aggregator not initialized' });

    res.json({ success: true, message: 'Fetch started' });

    const result = await aggregator.fetchAllSources();
    if (result.newArticles && result.newArticles.length > 0) {
      await handleNotifications(result.newArticles);
    }
  } catch (error) {
    console.error('[API] Fetch error:', error.message);
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

router.put('/notifications/settings', auth.requireAuth, (req, res) => {
  try {
    const result = db.updateNotificationSettings(req.body, req.user.id);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to save settings' });
  }
});

router.post('/notifications/test', auth.requireAuth, async (req, res) => {
  try {
    const { type } = req.body;
    const settings = db.getNotificationSettings(req.user.id);
    if (!settings) return res.status(400).json({ error: 'No notification settings configured' });

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
      const token = settings.telegram_bot_token || process.env.TELEGRAM_BOT_TOKEN;
      const chatId = settings.telegram_chat_id || process.env.TELEGRAM_CHAT_ID;
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
    const userId = parseInt(req.params.id);
    const result = db.updateUser(userId, req.body);
    db.logAudit(req.user.id, 'admin_user_update', `Updated user ${userId}: ${JSON.stringify(req.body)}`, req.ip);
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to update user' });
  }
});

router.delete('/admin/users/:id', auth.requireAuth, auth.requireAdmin, (req, res) => {
  try {
    const userId = parseInt(req.params.id);
    if (userId === req.user.id) return res.status(400).json({ error: 'Cannot delete yourself' });
    const result = db.deleteUser(userId);
    if (result.success) {
      db.logAudit(req.user.id, 'admin_user_delete', `Deleted user ${userId}`, req.ip);
    }
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to delete user' });
  }
});

router.post('/admin/invite-codes', auth.requireAuth, auth.requireAdmin, (req, res) => {
  try {
    const crypto = require('crypto');
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
    const { page, limit, category, severity, search } = req.query;
    const result = db.getArticles({
      page: parseInt(page) || 1,
      limit: Math.min(parseInt(limit) || 50, 200),
      category,
      severity,
      search
      // No userId filter — god view
    });
    res.json(result);
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch articles' });
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
    const limit = Math.min(parseInt(req.query.limit) || 100, 500);
    res.json({ log: db.getAuditLog(limit) });
  } catch (error) {
    res.status(500).json({ error: 'Failed to fetch audit log' });
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
    const articlesByUser = {};
    for (const article of newArticles) {
      if (!article.user_id) continue;
      if (!articlesByUser[article.user_id]) articlesByUser[article.user_id] = [];
      articlesByUser[article.user_id].push(article);
    }

    const allUsers = db.getAllUsers();

    for (const user of allUsers) {
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
      const tgToken = settings.telegram_bot_token || process.env.TELEGRAM_BOT_TOKEN;
      const tgChat = settings.telegram_chat_id || process.env.TELEGRAM_CHAT_ID;
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

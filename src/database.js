const Database = require('better-sqlite3');
const path = require('path');
const crypto = require('crypto');
const fs = require('fs');
const { enrichArticle } = require('./enrich');

// Auto-detect Railway's persistent volume at /data, otherwise fallback to local project directory
const defaultDbPath = fs.existsSync('/data') 
  ? '/data/threatpulse.db' 
  : path.join(__dirname, '..', 'threatpulse.db');

const DB_PATH = process.env.DB_PATH || defaultDbPath;

let db;

function getDb() {
  if (!db) {
    db = new Database(DB_PATH);
    db.pragma('journal_mode = WAL');
    db.pragma('foreign_keys = ON');
    initializeSchema();
  }
  return db;
}

function initializeSchema() {
  const d = getDb();

  // Step 1: Create only NEW tables (these don't exist in old databases)
  d.exec(`
    CREATE TABLE IF NOT EXISTS users (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      username TEXT UNIQUE NOT NULL,
      display_name TEXT NOT NULL,
      password_hash TEXT NOT NULL,
      salt TEXT NOT NULL,
      role TEXT DEFAULT 'analyst',
      is_active INTEGER DEFAULT 1,
      invite_code TEXT,
      last_login TEXT,
      failed_login_attempts INTEGER DEFAULT 0,
      locked_until TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS invite_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      code TEXT UNIQUE NOT NULL,
      created_by INTEGER NOT NULL,
      used_by INTEGER,
      used_at TEXT,
      expires_at TEXT,
      FOREIGN KEY (created_by) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS password_reset_tokens (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      token TEXT UNIQUE NOT NULL,
      expires_at TEXT NOT NULL,
      used INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS article_reviews (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      article_id INTEGER NOT NULL,
      user_id INTEGER NOT NULL,
      status TEXT DEFAULT 'reviewing',
      started_at TEXT DEFAULT (datetime('now')),
      completed_at TEXT,
      notes TEXT,
      FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE,
      FOREIGN KEY (user_id) REFERENCES users(id)
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER,
      action TEXT NOT NULL,
      details TEXT,
      ip_address TEXT,
      created_at TEXT DEFAULT (datetime('now'))
    );
  `);

  // Step 2: Ensure core tables exist (for fresh installs)
  d.exec(`
    CREATE TABLE IF NOT EXISTS sources (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      name TEXT NOT NULL,
      url TEXT NOT NULL,
      type TEXT NOT NULL DEFAULT 'rss',
      category TEXT DEFAULT 'news',
      enabled INTEGER DEFAULT 1,
      added_by TEXT DEFAULT 'system',
      user_id INTEGER,
      last_fetched TEXT,
      last_error TEXT,
      fetch_count INTEGER DEFAULT 0,
      created_at TEXT DEFAULT (datetime('now')),
      UNIQUE(url, user_id)
    );

    CREATE TABLE IF NOT EXISTS articles (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      url_hash TEXT UNIQUE NOT NULL,
      title TEXT NOT NULL,
      description TEXT,
      url TEXT NOT NULL,
      source_name TEXT,
      source_type TEXT DEFAULT 'rss',
      source_id INTEGER,
      user_id INTEGER,
      author TEXT,
      published_date TEXT,
      fetched_date TEXT DEFAULT (datetime('now')),
      category TEXT DEFAULT 'news',
      severity TEXT DEFAULT 'medium',
      cve_id TEXT,
      is_patched INTEGER DEFAULT -1,
      has_poc INTEGER DEFAULT 0,
      tags TEXT,
      mitre_ids TEXT,
      sector TEXT,
      threat_actors TEXT,
      notified INTEGER DEFAULT 0,
      FOREIGN KEY (source_id) REFERENCES sources(id) ON DELETE SET NULL
    );

    CREATE TABLE IF NOT EXISTS notification_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      article_id INTEGER,
      user_id INTEGER,
      sent_via TEXT,
      sent_at TEXT DEFAULT (datetime('now')),
      recipient TEXT,
      status TEXT DEFAULT 'sent',
      error_message TEXT,
      FOREIGN KEY (article_id) REFERENCES articles(id) ON DELETE CASCADE
    );

    CREATE TABLE IF NOT EXISTS verification_codes (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      user_id INTEGER NOT NULL,
      type TEXT NOT NULL,
      target_value TEXT,
      code TEXT NOT NULL,
      expires_at TEXT NOT NULL,
      created_at TEXT DEFAULT (datetime('now')),
      FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
    );
  `);

  // Step 3: ALTER TABLE migrations — add new columns to existing tables
  const columnMigrations = [
    'ALTER TABLE sources ADD COLUMN user_id INTEGER',
    'ALTER TABLE articles ADD COLUMN user_id INTEGER',
    'ALTER TABLE articles ADD COLUMN sector TEXT',
    'ALTER TABLE articles ADD COLUMN threat_actors TEXT',
    'ALTER TABLE articles ADD COLUMN mitre_ids TEXT',
    'ALTER TABLE notification_log ADD COLUMN user_id INTEGER',
  ];
  for (const sql of columnMigrations) {
    try { d.prepare(sql).run(); } catch(e) { /* column already exists */ }
  }

  // Step 4: Migrate old notification_settings table (may have CHECK constraint or missing user_id)
  try {
    const cols = d.prepare("PRAGMA table_info(notification_settings)").all();
    const hasUserId = cols.some(c => c.name === 'user_id');
    if (cols.length > 0 && !hasUserId) {
      console.log('[DB] Migrating notification_settings table to per-user...');
      const oldSettings = d.prepare('SELECT * FROM notification_settings').all();
      d.exec('DROP TABLE notification_settings');
      d.exec(`
        CREATE TABLE notification_settings (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER UNIQUE,
          email TEXT,
          telegram_chat_id TEXT,
          telegram_bot_token TEXT,
          email_enabled INTEGER DEFAULT 0,
          telegram_enabled INTEGER DEFAULT 0,
          severity_threshold TEXT DEFAULT 'high',
          keywords_filter TEXT,
          digest_mode INTEGER DEFAULT 0,
          smtp_host TEXT, smtp_port TEXT, smtp_user TEXT, smtp_pass TEXT,
          created_at TEXT DEFAULT (datetime('now')),
          updated_at TEXT DEFAULT (datetime('now'))
        )
      `);
      for (const old of oldSettings) {
        try {
          d.prepare('INSERT INTO notification_settings (email, telegram_chat_id, telegram_bot_token, email_enabled, telegram_enabled, severity_threshold, keywords_filter, digest_mode) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(
            old.email, old.telegram_chat_id, old.telegram_bot_token, old.email_enabled, old.telegram_enabled, old.severity_threshold, old.keywords_filter, old.digest_mode
          );
        } catch(e) {}
      }
      console.log('[DB] notification_settings migrated ✓');
    } else if (cols.length === 0) {
      // Table doesn't exist at all — create it fresh
      d.exec(`
        CREATE TABLE notification_settings (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          user_id INTEGER UNIQUE,
          email TEXT,
          telegram_chat_id TEXT,
          telegram_bot_token TEXT,
          email_enabled INTEGER DEFAULT 0,
          telegram_enabled INTEGER DEFAULT 0,
          severity_threshold TEXT DEFAULT 'high',
          keywords_filter TEXT,
          digest_mode INTEGER DEFAULT 0,
          smtp_host TEXT, smtp_port TEXT, smtp_user TEXT, smtp_pass TEXT,
          created_at TEXT DEFAULT (datetime('now')),
          updated_at TEXT DEFAULT (datetime('now'))
        )
      `);
    }
  } catch(e) {
    console.log('[DB] notification_settings migration note:', e.message);
  }

  // Add smtp + extra notification-channel columns if missing
  const notifMigrations = [
    'ALTER TABLE notification_settings ADD COLUMN smtp_host TEXT',
    'ALTER TABLE notification_settings ADD COLUMN smtp_port TEXT',
    'ALTER TABLE notification_settings ADD COLUMN smtp_user TEXT',
    'ALTER TABLE notification_settings ADD COLUMN smtp_pass TEXT',
    // Microsoft Teams (incoming webhook)
    'ALTER TABLE notification_settings ADD COLUMN teams_webhook TEXT',
    'ALTER TABLE notification_settings ADD COLUMN teams_enabled INTEGER DEFAULT 0',
    // WhatsApp (via CallMeBot free API)
    'ALTER TABLE notification_settings ADD COLUMN whatsapp_number TEXT',
    'ALTER TABLE notification_settings ADD COLUMN whatsapp_apikey TEXT',
    'ALTER TABLE notification_settings ADD COLUMN whatsapp_enabled INTEGER DEFAULT 0',
  ];
  for (const sql of notifMigrations) {
    try { d.prepare(sql).run(); } catch(e) { /* column already exists */ }
  }

  // Add email column to users if missing
  try { d.prepare('ALTER TABLE users ADD COLUMN email TEXT').run(); console.log('[DB] Added email column to users ✓'); } catch(e) { /* already exists */ }

  // Add must_change_password flag to users if missing (forces password change on first login)
  try { d.prepare('ALTER TABLE users ADD COLUMN must_change_password INTEGER DEFAULT 0').run(); } catch(e) { /* already exists */ }

  // Step 5: Create indexes AFTER all columns are guaranteed to exist
  const indexes = [
    'CREATE INDEX IF NOT EXISTS idx_articles_published ON articles(published_date DESC)',
    'CREATE INDEX IF NOT EXISTS idx_articles_category ON articles(category)',
    'CREATE INDEX IF NOT EXISTS idx_articles_severity ON articles(severity)',
    'CREATE INDEX IF NOT EXISTS idx_articles_cve ON articles(cve_id)',
    'CREATE INDEX IF NOT EXISTS idx_articles_source ON articles(source_name)',
    'CREATE INDEX IF NOT EXISTS idx_articles_notified ON articles(notified)',
    'CREATE INDEX IF NOT EXISTS idx_articles_url_hash ON articles(url_hash)',
    'CREATE INDEX IF NOT EXISTS idx_articles_user ON articles(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_articles_sector ON articles(sector)',
    'CREATE INDEX IF NOT EXISTS idx_sources_user ON sources(user_id)',
    'CREATE INDEX IF NOT EXISTS idx_reviews_article ON article_reviews(article_id)',
    'CREATE INDEX IF NOT EXISTS idx_reviews_user ON article_reviews(user_id)',
  ];
  for (const sql of indexes) {
    try { d.exec(sql); } catch(e) { /* index already exists */ }
  }

  // Step 5b: Migrate sources UNIQUE constraint from url-only to (url, user_id)
  // so different users can each have the same source URL independently.
  try {
    const hasOldUnique = d.prepare(
      "SELECT sql FROM sqlite_master WHERE type='table' AND name='sources'"
    ).get();
    if (hasOldUnique && hasOldUnique.sql && hasOldUnique.sql.includes('url TEXT NOT NULL UNIQUE')) {
      console.log('[DB] Migrating sources table: url UNIQUE -> UNIQUE(url, user_id)...');
      d.exec(`
        CREATE TABLE sources_new (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          name TEXT NOT NULL,
          url TEXT NOT NULL,
          type TEXT NOT NULL DEFAULT 'rss',
          category TEXT DEFAULT 'news',
          enabled INTEGER DEFAULT 1,
          added_by TEXT DEFAULT 'system',
          user_id INTEGER,
          last_fetched TEXT,
          last_error TEXT,
          fetch_count INTEGER DEFAULT 0,
          created_at TEXT DEFAULT (datetime('now')),
          UNIQUE(url, user_id)
        );
        INSERT INTO sources_new SELECT * FROM sources;
        DROP TABLE sources;
        ALTER TABLE sources_new RENAME TO sources;
        CREATE INDEX IF NOT EXISTS idx_sources_user ON sources(user_id);
      `);
      console.log('[DB] Sources table migrated successfully ✓');
    }
  } catch(e) {
    console.warn('[DB] Sources UNIQUE migration note:', e.message);
  }

  // Step 6: Assign orphaned sources/articles (user_id IS NULL) to admin user
  try {
    const admin = d.prepare("SELECT id FROM users WHERE role = 'admin' ORDER BY id ASC LIMIT 1").get();
    if (admin) {
      const orphanedSources = d.prepare('UPDATE sources SET user_id = ? WHERE user_id IS NULL').run(admin.id);
      const orphanedArticles = d.prepare('UPDATE articles SET user_id = ? WHERE user_id IS NULL').run(admin.id);
      if (orphanedSources.changes > 0 || orphanedArticles.changes > 0) {
        console.log(`[DB] Assigned ${orphanedSources.changes} orphaned sources and ${orphanedArticles.changes} orphaned articles to admin (id=${admin.id})`);
      }
    }
  } catch(e) {
    console.log('[DB] Orphan migration note:', e.message);
  }
}

// --- URL Hash for dedup ---
function hashUrl(url) {
  return crypto.createHash('sha256').update(url.trim().toLowerCase()).digest('hex');
}

// ============================================
// USER CRUD
// ============================================

function createUser(username, displayName, passwordHash, salt, role = 'analyst', inviteCode = null, email = null) {
  try {
    const result = getDb().prepare(
      'INSERT INTO users (username, display_name, password_hash, salt, role, invite_code, email) VALUES (?, ?, ?, ?, ?, ?, ?)'
    ).run(username, displayName, passwordHash, salt, role, inviteCode, email);
    return { success: true, id: result.lastInsertRowid };
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return { success: false, error: 'Username already exists' };
    }
    return { success: false, error: err.message };
  }
}

function getUserByUsername(username) {
  return getDb().prepare('SELECT * FROM users WHERE username = ?').get(username);
}

function getUserById(id) {
  return getDb().prepare('SELECT * FROM users WHERE id = ?').get(id);
}

function getUserByEmail(email) {
  return getDb().prepare('SELECT * FROM users WHERE email = ?').get(email);
}

function updateUserEmail(userId, email) {
  getDb().prepare('UPDATE users SET email = ? WHERE id = ?').run(email, userId);
}

// Password reset tokens
function createPasswordResetToken(userId, token, expiresAt) {
  // Invalidate any existing tokens for this user
  getDb().prepare('UPDATE password_reset_tokens SET used = 1 WHERE user_id = ? AND used = 0').run(userId);
  getDb().prepare(
    'INSERT INTO password_reset_tokens (user_id, token, expires_at) VALUES (?, ?, ?)'
  ).run(userId, token, expiresAt);
}

function validatePasswordResetToken(token) {
  const row = getDb().prepare(
    'SELECT * FROM password_reset_tokens WHERE token = ? AND used = 0 AND expires_at > datetime(\'now\')'
  ).get(token);
  return row || null;
}

function markResetTokenUsed(token) {
  getDb().prepare('UPDATE password_reset_tokens SET used = 1 WHERE token = ?').run(token);
}

function cleanupExpiredResetTokens() {
  getDb().prepare('DELETE FROM password_reset_tokens WHERE expires_at < datetime(\'now\') OR used = 1').run();
}

function getAllUsers() {
  return getDb().prepare(
    `SELECT u.id, u.username, u.display_name, u.role, u.is_active, u.last_login, u.created_at,
     (SELECT COUNT(*) FROM sources WHERE user_id = u.id) as source_count
     FROM users u ORDER BY u.created_at ASC`
  ).all();
}

function updateUser(id, updates) {
  const allowed = ['display_name', 'role', 'is_active'];
  const fields = [];
  const values = [];
  for (const [key, val] of Object.entries(updates)) {
    if (allowed.includes(key)) {
      fields.push(`${key} = ?`);
      values.push(val);
    }
  }
  if (fields.length === 0) return { success: false, error: 'No valid fields' };
  values.push(id);
  getDb().prepare(`UPDATE users SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  return { success: true };
}

function updateUserPassword(id, passwordHash, salt) {
  // Changing the password always clears the "must change password" flag
  getDb().prepare('UPDATE users SET password_hash = ?, salt = ?, must_change_password = 0 WHERE id = ?').run(passwordHash, salt, id);
  return { success: true };
}

function setMustChangePassword(id, value) {
  getDb().prepare('UPDATE users SET must_change_password = ? WHERE id = ?').run(value ? 1 : 0, id);
  return { success: true };
}

function updateUserLastLogin(id) {
  getDb().prepare("UPDATE users SET last_login = datetime('now') WHERE id = ?").run(id);
}

function incrementFailedLogins(id) {
  getDb().prepare('UPDATE users SET failed_login_attempts = failed_login_attempts + 1 WHERE id = ?').run(id);
}

function resetFailedLogins(id) {
  getDb().prepare('UPDATE users SET failed_login_attempts = 0 WHERE id = ?').run(id);
}

function lockAccount(id, untilDate) {
  getDb().prepare('UPDATE users SET locked_until = ? WHERE id = ?').run(untilDate, id);
}

function unlockAccount(id) {
  getDb().prepare('UPDATE users SET locked_until = NULL, failed_login_attempts = 0 WHERE id = ?').run(id);
}

function deleteUser(id) {
  // Don't allow deleting the last admin
  const user = getUserById(id);
  if (!user) return { success: false, error: 'User not found' };
  if (user.role === 'admin') {
    const adminCount = getDb().prepare("SELECT COUNT(*) as count FROM users WHERE role = 'admin' AND is_active = 1").get().count;
    if (adminCount <= 1) return { success: false, error: 'Cannot delete the last admin' };
  }
  // Delete user's sources and their articles
  getDb().prepare('DELETE FROM article_reviews WHERE user_id = ?').run(id);
  getDb().prepare('DELETE FROM notification_settings WHERE user_id = ?').run(id);
  getDb().prepare('DELETE FROM notification_log WHERE user_id = ?').run(id);
  getDb().prepare('DELETE FROM articles WHERE user_id = ?').run(id);
  getDb().prepare('DELETE FROM sources WHERE user_id = ?').run(id);
  getDb().prepare('DELETE FROM users WHERE id = ?').run(id);
  return { success: true };
}

// ============================================
// INVITE CODES
// ============================================

function createInviteCode(adminId, code, expiresAt = null) {
  try {
    const result = getDb().prepare(
      'INSERT INTO invite_codes (code, created_by, expires_at) VALUES (?, ?, ?)'
    ).run(code, adminId, expiresAt);
    return { success: true, id: result.lastInsertRowid };
  } catch (err) {
    return { success: false, error: err.message };
  }
}

function validateInviteCode(code) {
  if (!code) return { valid: false, error: 'Invite code is required' };
  const invite = getDb().prepare('SELECT * FROM invite_codes WHERE code = ?').get(code);
  if (!invite) return { valid: false, error: 'Invalid invite code' };
  if (invite.used_by) return { valid: false, error: 'Invite code already used' };
  if (invite.expires_at && new Date(invite.expires_at) < new Date()) {
    return { valid: false, error: 'Invite code has expired' };
  }
  return { valid: true, invite };
}

function useInviteCode(code, userId) {
  getDb().prepare(
    "UPDATE invite_codes SET used_by = ?, used_at = datetime('now') WHERE code = ?"
  ).run(userId, code);
}

function getValidInviteCodes() {
  return getDb().prepare(
    'SELECT ic.*, u.username as created_by_name, u2.username as used_by_name FROM invite_codes ic LEFT JOIN users u ON ic.created_by = u.id LEFT JOIN users u2 ON ic.used_by = u2.id ORDER BY ic.id DESC'
  ).all();
}

// ============================================
// SOURCE CRUD (user-scoped)
// ============================================

function getAllSources() {
  return getDb().prepare('SELECT * FROM sources ORDER BY added_by DESC, name ASC').all();
}

// Fully isolated: each user sees ONLY their own sources.
// New users start empty and build their own source list.
function getSourcesForUserFixed(userId) {
  return getDb().prepare(
    `SELECT s.*, u.display_name as added_by_name
     FROM sources s
     LEFT JOIN users u ON s.user_id = u.id
     WHERE s.user_id = ?
     ORDER BY s.name ASC`
  ).all(userId);
}

function getEnabledSources() {
  return getDb().prepare('SELECT * FROM sources WHERE enabled = 1 ORDER BY type, name').all();
}

function getEnabledSourcesForUser(userId) {
  return getDb().prepare(
    'SELECT * FROM sources WHERE enabled = 1 AND (user_id = ? OR user_id IS NULL) ORDER BY type, name'
  ).all(userId);
}

function getSourcesByType(type) {
  return getDb().prepare('SELECT * FROM sources WHERE type = ? AND enabled = 1').all(type);
}

function addSource({ name, url, type = 'rss', category = 'news', added_by = 'user', user_id = null }) {
  try {
    const result = getDb().prepare(
      'INSERT INTO sources (name, url, type, category, added_by, user_id) VALUES (?, ?, ?, ?, ?, ?)'
    ).run(name, url, type, category, added_by, user_id);
    return { id: result.lastInsertRowid, success: true };
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return { success: false, error: 'Source URL already exists for this user' };
    }
    throw err;
  }
}

function updateSource(id, updates) {
  const allowed = ['name', 'url', 'type', 'category', 'enabled'];
  const fields = [];
  const values = [];
  for (const [key, val] of Object.entries(updates)) {
    if (allowed.includes(key)) {
      fields.push(`${key} = ?`);
      values.push(val);
    }
  }
  if (fields.length === 0) return { success: false, error: 'No valid fields to update' };
  values.push(id);
  getDb().prepare(`UPDATE sources SET ${fields.join(', ')} WHERE id = ?`).run(...values);
  return { success: true };
}

function deleteSource(id) {
  const source = getDb().prepare('SELECT * FROM sources WHERE id = ?').get(id);
  if (!source) return { success: false, error: 'Source not found' };
  // Delete articles from this source too
  getDb().prepare('DELETE FROM articles WHERE source_id = ?').run(id);
  getDb().prepare('DELETE FROM sources WHERE id = ?').run(id);
  return { success: true };
}

function canUserModifySource(userId, sourceId) {
  const source = getDb().prepare('SELECT * FROM sources WHERE id = ?').get(sourceId);
  if (!source) return false;
  // User can modify their own sources, admins can modify any
  return source.user_id === userId || source.added_by === 'system';
}

function updateSourceFetchStatus(id, { last_fetched, last_error = null }) {
  getDb().prepare(
    'UPDATE sources SET last_fetched = ?, last_error = ?, fetch_count = fetch_count + 1 WHERE id = ?'
  ).run(last_fetched, last_error, id);
}

// ============================================
// ARTICLE CRUD (user-scoped)
// ============================================

function insertArticle(article) {
  // Centralized enrichment — fills sector / threat_actors / mitre_ids for every
  // source (RSS, CVE, CISA KEV, dark web, scraped) that didn't set them.
  enrichArticle(article);
  const urlHash = hashUrl(article.url);
  try {
    const result = getDb().prepare(`
      INSERT INTO articles (url_hash, title, description, url, source_name, source_type, source_id, user_id, author, published_date, category, severity, cve_id, is_patched, has_poc, tags, mitre_ids, sector, threat_actors)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      urlHash,
      article.title || 'Untitled',
      article.description || '',
      article.url,
      article.source_name || 'Unknown',
      article.source_type || 'rss',
      article.source_id || null,
      article.user_id || null,
      article.author || null,
      article.published_date || new Date().toISOString(),
      article.category || 'news',
      article.severity || 'medium',
      article.cve_id || null,
      article.is_patched !== undefined ? article.is_patched : -1,
      article.has_poc || 0,
      article.tags || null,
      article.mitre_ids || null,
      article.sector || null,
      article.threat_actors || null
    );
    return { id: result.lastInsertRowid, success: true, isNew: true };
  } catch (err) {
    if (err.message.includes('UNIQUE')) {
      return { success: true, isNew: false };
    }
    throw err;
  }
}

function insertArticles(articles) {
  const insertMany = getDb().transaction((items) => {
    let newCount = 0;
    const newArticles = [];
    for (const article of items) {
      const result = insertArticle(article);
      if (result.isNew) {
        newCount++;
        newArticles.push({ ...article, id: result.id });
      }
    }
    return { newCount, newArticles };
  });
  return insertMany(articles);
}

function getArticles({ page = 1, limit = 50, category, severity, search, source_type, startDate, endDate, userId, sector, threat_actor, has_poc, has_mitre, is_patched } = {}) {
  let where = [];
  let params = [];

  // User scoping: fully isolated — each user sees only their own articles.
  // (Admin bypasses this by calling getArticles without userId.)
  if (userId) {
    where.push('articles.user_id = ?');
    params.push(userId);
  }

  if (category && category !== 'all') {
    where.push('articles.category = ?');
    params.push(category);
  }
  if (severity && severity !== 'all') {
    where.push('articles.severity = ?');
    params.push(severity);
  }
  if (source_type && source_type !== 'all') {
    where.push('articles.source_type = ?');
    params.push(source_type);
  }
  if (sector && sector !== 'all') {
    where.push('articles.sector = ?');
    params.push(sector);
  }
  if (threat_actor) {
    where.push('articles.threat_actors LIKE ?');
    params.push(`%${threat_actor}%`);
  }
  // Detection-engineering filters
  if (has_poc === '1' || has_poc === 1 || has_poc === true) {
    where.push('articles.has_poc = 1');
  }
  if (has_mitre === '1' || has_mitre === 1 || has_mitre === true) {
    where.push("articles.mitre_ids IS NOT NULL AND articles.mitre_ids != ''");
  }
  if (is_patched === '1' || is_patched === '0') {
    where.push('articles.is_patched = ?');
    params.push(parseInt(is_patched, 10));
  }
  if (search) {
    where.push('(articles.title LIKE ? OR articles.description LIKE ? OR articles.cve_id LIKE ? OR articles.author LIKE ? OR articles.tags LIKE ? OR articles.threat_actors LIKE ?)');
    const term = `%${search}%`;
    params.push(term, term, term, term, term, term);
  }
  if (startDate) {
    where.push('articles.published_date >= ?');
    params.push(startDate);
  }
  if (endDate) {
    where.push('articles.published_date <= ?');
    params.push(endDate);
  }

  const whereClause = where.length > 0 ? `WHERE ${where.join(' AND ')}` : '';
  const offset = (page - 1) * limit;

  const countRow = getDb().prepare(`SELECT COUNT(*) as total FROM articles ${whereClause}`).get(...params);
  const total = countRow.total;
  const totalPages = Math.ceil(total / limit);

  // Join with reviews to include review status
  const articles = getDb().prepare(
    `SELECT articles.*,
     (SELECT display_name FROM users WHERE users.id = articles.user_id) as owner_name,
     (SELECT json_group_array(json_object('user_id', ar.user_id, 'username', u.display_name, 'status', ar.status, 'started_at', ar.started_at, 'completed_at', ar.completed_at, 'notes', ar.notes))
      FROM article_reviews ar JOIN users u ON ar.user_id = u.id WHERE ar.article_id = articles.id) as reviews
     FROM articles ${whereClause} ORDER BY articles.published_date DESC LIMIT ? OFFSET ?`
  ).all(...params, limit, offset);

  return { articles, total, page, totalPages };
}

function getArticleStats(userId = null) {
  const d = getDb();
  // Fully isolated per user; admin passes no userId to see totals across everyone.
  const userFilter = userId ? `AND user_id = ${parseInt(userId)}` : '';

  const threatsToday = d.prepare(
    `SELECT COUNT(*) as count FROM articles WHERE date(published_date) = date('now') ${userFilter}`
  ).get().count;

  const criticalVulns = d.prepare(
    `SELECT COUNT(*) as count FROM articles WHERE severity = 'critical' AND date(published_date) >= date('now', '-7 days') ${userFilter}`
  ).get().count;

  const pocsDetected = d.prepare(
    `SELECT COUNT(*) as count FROM articles WHERE has_poc = 1 AND date(published_date) >= date('now', '-7 days') ${userFilter}`
  ).get().count;

  const sourceFilter = userId ? `AND user_id = ${parseInt(userId)}` : '';
  const activeSources = d.prepare(
    `SELECT COUNT(*) as count FROM sources WHERE enabled = 1 ${sourceFilter}`
  ).get().count;

  const lastFetch = d.prepare(
    `SELECT MAX(fetched_date) as last FROM articles WHERE 1=1 ${userFilter}`
  ).get();

  const totalArticles = d.prepare(
    `SELECT COUNT(*) as count FROM articles WHERE 1=1 ${userFilter}`
  ).get().count;

  return {
    threatsToday,
    criticalVulns,
    pocsDetected,
    activeSources,
    totalArticles,
    lastUpdated: lastFetch?.last || null
  };
}

function getUnnotifiedArticles(severityThreshold = 'high') {
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const articles = getDb().prepare(
    `SELECT * FROM articles WHERE notified = 0 ORDER BY published_date DESC`
  ).all();
  return articles;
}

function markAsNotified(articleIds) {
  if (articleIds.length === 0) return;
  const placeholders = articleIds.map(() => '?').join(',');
  getDb().prepare(`UPDATE articles SET notified = 1 WHERE id IN (${placeholders})`).run(...articleIds);
}

function searchArticles(query, limit = 50, userId = null) {
  const term = `%${query}%`;
  const userFilter = userId ? `AND user_id = ?` : '';
  const params = userId
    ? [term, term, term, term, term, userId, limit]
    : [term, term, term, term, term, limit];
  return getDb().prepare(
    `SELECT * FROM articles WHERE (title LIKE ? OR description LIKE ? OR cve_id LIKE ? OR tags LIKE ? OR author LIKE ?) ${userFilter} ORDER BY published_date DESC LIMIT ?`
  ).all(...params);
}

// ============================================
// ARTICLE REVIEWS
// ============================================

function startReview(articleId, userId) {
  // Check if user is already reviewing this article
  const existing = getDb().prepare(
    "SELECT * FROM article_reviews WHERE article_id = ? AND user_id = ? AND status = 'reviewing'"
  ).get(articleId, userId);
  if (existing) return { success: true, review: existing };

  const result = getDb().prepare(
    'INSERT INTO article_reviews (article_id, user_id, status) VALUES (?, ?, ?)'
  ).run(articleId, userId, 'reviewing');
  return { success: true, id: result.lastInsertRowid };
}

function completeReview(articleId, userId, notes = null) {
  getDb().prepare(
    "UPDATE article_reviews SET status = 'reviewed', completed_at = datetime('now'), notes = ? WHERE article_id = ? AND user_id = ? AND status = 'reviewing'"
  ).run(notes, articleId, userId);
  return { success: true };
}

function escalateArticle(articleId, userId, notes = null) {
  // Check if there's an existing review
  const existing = getDb().prepare(
    'SELECT * FROM article_reviews WHERE article_id = ? AND user_id = ?'
  ).get(articleId, userId);

  if (existing) {
    getDb().prepare(
      "UPDATE article_reviews SET status = 'escalated', notes = ? WHERE article_id = ? AND user_id = ?"
    ).run(notes, articleId, userId);
  } else {
    getDb().prepare(
      "INSERT INTO article_reviews (article_id, user_id, status, notes) VALUES (?, ?, 'escalated', ?)"
    ).run(articleId, userId, notes);
  }
  return { success: true };
}

function getArticleReviews(articleId) {
  return getDb().prepare(
    `SELECT ar.*, u.display_name, u.username 
     FROM article_reviews ar JOIN users u ON ar.user_id = u.id 
     WHERE ar.article_id = ? ORDER BY ar.started_at DESC`
  ).all(articleId);
}

// ============================================
// NOTIFICATION SETTINGS (per-user)
// ============================================

function createUserNotificationSettings(userId) {
  try {
    getDb().prepare('INSERT INTO notification_settings (user_id) VALUES (?)').run(userId);
  } catch(e) { /* already exists */ }
}

function getNotificationSettings(userId = null) {
  if (userId) {
    return getDb().prepare('SELECT * FROM notification_settings WHERE user_id = ?').get(userId);
  }
  // Fallback: get the first/old settings row
  return getDb().prepare('SELECT * FROM notification_settings LIMIT 1').get();
}

function updateNotificationSettings(settings, userId = null) {
  const allowed = ['email', 'telegram_chat_id', 'telegram_bot_token', 'email_enabled', 'telegram_enabled',
    'teams_webhook', 'teams_enabled', 'whatsapp_number', 'whatsapp_apikey', 'whatsapp_enabled',
    'severity_threshold', 'keywords_filter', 'digest_mode'];
  const fields = [];
  const values = [];
  for (const [key, val] of Object.entries(settings)) {
    if (allowed.includes(key)) {
      // Skip masked secrets (don't overwrite a real value with its masked form)
      if ((key === 'telegram_bot_token' || key === 'whatsapp_apikey') && val && String(val).includes('...')) continue;
      fields.push(`${key} = ?`);
      values.push(val);
    }
  }
  if (fields.length === 0) return { success: false };
  fields.push("updated_at = datetime('now')");
  
  if (userId) {
    // Ensure row exists first (upsert)
    try {
      getDb().prepare('INSERT OR IGNORE INTO notification_settings (user_id) VALUES (?)').run(userId);
    } catch(e) {}
    getDb().prepare(`UPDATE notification_settings SET ${fields.join(', ')} WHERE user_id = ?`).run(...values, userId);
  } else {
    getDb().prepare(`UPDATE notification_settings SET ${fields.join(', ')} WHERE id = 1`).run(...values);
  }
  return { success: true };
}

function logNotification({ article_id, user_id = null, sent_via, recipient, status = 'sent', error_message = null }) {
  getDb().prepare(
    'INSERT INTO notification_log (article_id, user_id, sent_via, recipient, status, error_message) VALUES (?, ?, ?, ?, ?, ?)'
  ).run(article_id, user_id, sent_via, recipient, status, error_message);
}

// ============================================
// AUDIT LOG
// ============================================

function logAudit(userId, action, details = null, ipAddress = null) {
  getDb().prepare(
    'INSERT INTO audit_log (user_id, action, details, ip_address) VALUES (?, ?, ?, ?)'
  ).run(userId, action, details, ipAddress);
}

function getAuditLog(limit = 100) {
  return getDb().prepare(
    `SELECT al.*, u.username FROM audit_log al LEFT JOIN users u ON al.user_id = u.id ORDER BY al.created_at DESC LIMIT ?`
  ).all(limit);
}

// Verification codes for email/password updates
function createVerificationCode(userId, type, targetValue, code, expiresAt) {
  getDb().prepare('DELETE FROM verification_codes WHERE user_id = ? AND type = ?').run(userId, type);
  getDb().prepare(
    'INSERT INTO verification_codes (user_id, type, target_value, code, expires_at) VALUES (?, ?, ?, ?, ?)'
  ).run(userId, type, targetValue, code, expiresAt);
}

function validateVerificationCode(userId, type, code) {
  const row = getDb().prepare(
    "SELECT * FROM verification_codes WHERE user_id = ? AND type = ? AND code = ? AND expires_at > datetime('now')"
  ).get(userId, type, code);
  return row || null;
}

function deleteVerificationCode(id) {
  getDb().prepare('DELETE FROM verification_codes WHERE id = ?').run(id);
}

module.exports = {
  getDb,
  initializeSchema,
  // Users
  createUser,
  getUserByUsername,
  getUserById,
  getUserByEmail,
  getAllUsers,
  updateUser,
  updateUserPassword,
  setMustChangePassword,
  updateUserEmail,
  updateUserLastLogin,
  incrementFailedLogins,
  resetFailedLogins,
  lockAccount,
  unlockAccount,
  deleteUser,
  // Password Reset
  createPasswordResetToken,
  validatePasswordResetToken,
  markResetTokenUsed,
  cleanupExpiredResetTokens,
  // Invite Codes
  createInviteCode,
  validateInviteCode,
  useInviteCode,
  getValidInviteCodes,
  // Sources
  getAllSources,
  getSourcesForUser: getSourcesForUserFixed,
  getEnabledSources,
  getEnabledSourcesForUser,
  getSourcesByType,
  addSource,
  updateSource,
  deleteSource,
  canUserModifySource,
  updateSourceFetchStatus,
  // Articles
  insertArticle,
  insertArticles,
  getArticles,
  getArticleStats,
  getUnnotifiedArticles,
  markAsNotified,
  searchArticles,
  // Reviews
  startReview,
  completeReview,
  escalateArticle,
  getArticleReviews,
  // Notifications
  createUserNotificationSettings,
  getNotificationSettings,
  updateNotificationSettings,
  logNotification,
  // Audit
  logAudit,
  getAuditLog,
  // Verification Codes
  createVerificationCode,
  validateVerificationCode,
  deleteVerificationCode,
  // Utils
  hashUrl
};

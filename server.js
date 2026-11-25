/**
 * ╔══════════════════════════════════════════════════════════╗
 * ║           🛡️  ThreatPulse v2 — Server Entry Point       ║
 * ║   Multi-User Threat Intelligence Aggregation Platform    ║
 * ╚══════════════════════════════════════════════════════════╝
 */

require('dotenv').config();

const express = require('express');
const path = require('path');
const db = require('./src/database');
const apiRoutes = require('./src/routes/api');
const aiRoutes = require('./src/routes/ai');
const { handleNotifications } = require('./src/routes/api');
const aggregator = require('./src/feeds/aggregator');
const { seedDefaultSources } = require('./src/feeds/default-sources');
const mailer = require('./src/notifications/mailer');
const auth = require('./src/auth');

const app = express();
const PORT = process.env.PORT || 3000;

// Behind Caddy (docker network) req.ip would otherwise be the proxy's IP for every
// visitor, making rate limits global. Trust only private-network proxies, so a
// directly-exposed server can't be fooled by a spoofed X-Forwarded-For.
app.set('trust proxy', process.env.TRUST_PROXY || 'loopback, linklocal, uniquelocal');

// ============================================
// SECURITY MIDDLEWARE
// ============================================

// Cookie parser (httpOnly JWT + CSRF) — no dependency
const { cookieParser, csrfMiddleware } = require('./src/security');
app.use(cookieParser);

// CSRF protection on all state-changing requests
// (csrfMiddleware checks method internally, skips GET/HEAD/OPTIONS)
app.use('/api', (req, res, next) => {
  // Exempt login, register, forgot-password, reset-password, and refresh
  // from CSRF — these are the endpoints that establish/give tokens
  const csrfExempt = ['/auth/login', '/auth/register', '/auth/forgot-password',
                      '/auth/reset-password', '/auth/refresh', '/auth/guest'];
  if (csrfExempt.some(p => req.path === p)) {
    // These can't use the double-submit token (no session yet), so refuse
    // cross-site requests instead: blocks login CSRF / forced guest sessions.
    const site = req.get('sec-fetch-site');
    if (site === 'cross-site') return res.status(403).json({ success: false, error: 'Cross-site request blocked' });
    return next();
  }
  return csrfMiddleware(req, res, next);
});

// Security headers (Helmet-style, no dependency)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  // Blocks injected inline scripts / javascript: URLs from running.
  // The sha256 hashes allow the small inline <script> blocks in index.html and
  // admin.html — if you edit those blocks, regenerate the hashes (browser console
  // prints the expected hash when one is blocked).
  res.setHeader('Content-Security-Policy',
    "default-src 'self'; script-src 'self' 'sha256-rwPhTO8AH2YTkM4qY4TAdsfwG/NzhP/ujV/DyMysVbo=' 'sha256-NEKOWahk3VTXigudAbS/Ab55vpvYBInuLocngBFznf0=' 'sha256-ZpYQh6FbExcbZMpg++Z26FEb8DFc2iu8gJ2zbysByYk='; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
    "font-src 'self' https://fonts.gstatic.com data:; img-src 'self' data: https:; connect-src 'self'; " +
    "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'");
  if (process.env.NODE_ENV === 'production' || process.env.RAILWAY_ENVIRONMENT) {
    res.setHeader('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  }
  next();
});

// Rate limiting (simple in-memory, no dependency)
const rateLimitStore = new Map();
const RATE_LIMIT_WINDOW = 60000; // 1 minute
const RATE_LIMIT_MAX = 200; // requests per window
const AUTH_RATE_LIMIT_MAX = 30; // auth requests per window (per-account lockout handles brute force)

function rateLimit(maxRequests, bucket) {
  return (req, res, next) => {
    const ip = req.ip || req.connection?.remoteAddress || 'unknown';
    // Fixed bucket per limiter — avoids the mount-relative req.path collision that
    // previously double-counted auth requests and could lock out logins.
    const key = `${ip}:${bucket}`;
    const now = Date.now();

    if (!rateLimitStore.has(key)) {
      rateLimitStore.set(key, { count: 1, resetAt: now + RATE_LIMIT_WINDOW });
      return next();
    }

    const entry = rateLimitStore.get(key);
    if (now > entry.resetAt) {
      entry.count = 1;
      entry.resetAt = now + RATE_LIMIT_WINDOW;
      return next();
    }

    entry.count++;
    if (entry.count > maxRequests) {
      res.setHeader('Retry-After', Math.ceil((entry.resetAt - now) / 1000));
      return res.status(429).json({ error: 'Too many requests. Please try again later.' });
    }
    next();
  };
}

// Clean rate limit store periodically; also cap size to prevent memory growth
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) rateLimitStore.delete(key);
  }
  // If store still has 10k+ entries after cleanup, evict the oldest
  if (rateLimitStore.size > 10000) {
    const sorted = [...rateLimitStore.entries()].sort((a, b) => a[1].resetAt - b[1].resetAt);
    for (let i = 0; i < Math.min(1000, sorted.length); i++) {
      rateLimitStore.delete(sorted[i][0]);
    }
  }
}, 60000);

// ============================================
// CORE MIDDLEWARE
// ============================================
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// CORS — restrict in production
app.use((req, res, next) => {
  const origin = process.env.ALLOWED_ORIGIN || '*';
  res.header('Access-Control-Allow-Origin', origin);
  res.header('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization, X-CSRF-Token');
  if (req.method === 'OPTIONS') return res.sendStatus(200);
  next();
});

// Apply rate limiting — auth endpoints get a stricter, separate bucket.
const authLimiter = rateLimit(AUTH_RATE_LIMIT_MAX, 'auth');
const generalLimiter = rateLimit(RATE_LIMIT_MAX, 'general');
app.use('/api/auth', authLimiter);
app.use('/api', (req, res, next) => {
  // Auth endpoints are already covered by the stricter authLimiter above;
  // skip here so they aren't counted twice. (req.path is mount-relative: '/auth/...')
  if (req.path.startsWith('/auth')) return next();
  return generalLimiter(req, res, next);
});

// Health check (unauthenticated, outside /api so it isn't rate-limited) — for
// container/platform health probes (Fly, Render, Koyeb, etc.)
app.get('/healthz', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime(), timestamp: new Date().toISOString() });
});

// Serve static files. HTML/JS/CSS use "no-cache" so browsers always revalidate
// (via ETag) — this guarantees a redeploy reaches users immediately instead of
// serving a stale cached bundle.
app.use(express.static(path.join(__dirname, 'public'), {
  setHeaders: (res, filePath) => {
    if (/\.(html|js|css)$/i.test(filePath)) {
      res.setHeader('Cache-Control', 'no-cache');
    }
  }
}));

// ============================================
// API ROUTES
// ============================================
app.use('/api', apiRoutes);
app.use('/api/ai', aiRoutes);

// Make aggregator available to routes
app.set('aggregator', aggregator);

// Serve admin page
app.get('/admin', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin.html'));
});


// ============================================
// ERROR HANDLING — never expose internals
// ============================================
app.use((err, req, res, next) => {
  // Client errors raised by body parsing (malformed JSON → 400, body too large → 413)
  // carry their own status; report them as such instead of a 500.
  const status = err.status || err.statusCode;
  if (status >= 400 && status < 500) {
    return res.status(status).json({ success: false, error: err.expose ? err.message : 'Bad request' });
  }
  console.error('[Server] Unhandled error:', err.message);
  res.status(500).json({ error: 'Internal server error' });
});

// ============================================
// INITIALIZATION
// ============================================
function validateConfig() {
  const isProd = process.env.NODE_ENV === 'production' || !!process.env.RAILWAY_ENVIRONMENT;
  if (!isProd) return;

  // Non-fatal production warnings (JWT_SECRET is enforced fatally inside src/auth.js on load)
  if (!process.env.ALLOWED_ORIGIN || process.env.ALLOWED_ORIGIN === '*') {
    console.warn('[Config] ⚠️  ALLOWED_ORIGIN is not set — CORS is open to "*". Set it to your dashboard URL in production.');
  }
  if (!process.env.SMTP_HOST) {
    console.warn('[Config] ℹ️  SMTP not configured — email notifications and password-reset emails are disabled.');
  }
}

async function initialize() {
  console.log('\n');
  console.log('╔══════════════════════════════════════════════════════════╗');
  console.log('║           🛡️  ThreatPulse v2 — Starting Up...           ║');
  console.log('╚══════════════════════════════════════════════════════════╝');
  console.log('');

  // 0. Validate production configuration
  validateConfig();

  // 0. Restore the latest database snapshot (free hosting has no persistent disk)
  const dbBackup = require('./src/db-backup');
  await dbBackup.restore(db.getDbPath());

  // 1. Initialize database
  console.log('[Init] Initializing database...');
  db.getDb();
  console.log('[Init] Database ready ✓');

  // 1b. Keep it: snapshots every few minutes (when changed) and on shutdown
  dbBackup.schedule(db);

  // 2. Create default admin user + invite codes (first run only). Hashing is
  // async now, so wait for it: the admin must exist (and own the seeded
  // sources) before seeding and before the server accepts logins.
  console.log('[Init] Checking user accounts...');
  await auth.ensureAdminExists();

  // 3. Seed default sources (system-level, user_id = NULL)
  console.log('[Init] Seeding default threat intelligence sources...');
  seedDefaultSources(db);
  console.log('[Init] Sources ready ✓');

  // 4. Initialize email transporter
  console.log('[Init] Setting up email notifications...');
  mailer.logStatus();

  // 5. Register notification handler
  aggregator.setOnFetchComplete(async (newArticles) => {
    await handleNotifications(newArticles);
  });

  // 6. Start Express server
  app.listen(PORT, () => {
    console.log('');
    console.log('╔══════════════════════════════════════════════════════════╗');
    console.log(`║  🌐  ThreatPulse v2 is live at: http://localhost:${PORT}     ║`);
    console.log('╚══════════════════════════════════════════════════════════╝');
    console.log('');
    console.log('📊 Dashboard:    http://localhost:' + PORT);
    console.log('🔒 Admin Panel:  http://localhost:' + PORT + '/admin');
    console.log('📡 API:          http://localhost:' + PORT + '/api');
    console.log('');
  });

  // 6b. Render free tier: the service sleeps after 15 min without inbound
  // traffic, which would also stop the feed scheduler. Ping our own public URL
  // (RENDER_EXTERNAL_URL is set automatically by Render) every 10 minutes.
  if (process.env.RENDER_EXTERNAL_URL) {
    const https = require('https');
    const pingUrl = `${process.env.RENDER_EXTERNAL_URL.replace(/\/$/, '')}/healthz`;
    setInterval(() => {
      https.get(pingUrl, (r) => r.resume()).on('error', (e) => console.warn('[KeepAlive] ping failed:', e.message));
    }, 10 * 60 * 1000);
    console.log(`[Init] Keep-alive ping enabled → ${pingUrl} every 10 min ✓`);
  }

  // 6c. Event-loop lag monitor: logs whenever the process was blocked for >1s,
  // so a failed platform health check can be traced to what was running.
  let lagLast = Date.now();
  setInterval(() => {
    const now = Date.now();
    const lag = now - lagLast - 500;
    if (lag > 1000) console.warn(`[Lag] event loop blocked ~${lag} ms (fetching: ${aggregator.getStatus ? JSON.stringify(aggregator.getStatus().isRunning) : 'n/a'})`);
    lagLast = now;
  }, 500).unref();

  // 7. Start initial fetch after delay
  console.log('[Init] Starting initial feed fetch in 5 seconds...');
  setTimeout(async () => {
    try {
      const result = await aggregator.fetchAllSources();
      if (result.newArticles && result.newArticles.length > 0) {
        await handleNotifications(result.newArticles);
      }
      console.log('[Init] Initial fetch complete ✓');

      const cronExpr = process.env.FETCH_CRON || '*/15 * * * *';
      aggregator.startScheduler(cronExpr);
      console.log(`[Init] Scheduler active — fetching every ${cronExpr} ✓`);
      console.log('');
      console.log('🛡️  ThreatPulse v2 is fully operational!');
      console.log('   Press Ctrl+C to stop.\n');
    } catch (error) {
      console.error('[Init] Initial fetch error:', error.message);
      aggregator.startScheduler(process.env.FETCH_CRON || '*/15 * * * *');
    }
  }, 5000);

  // 8. Vulnerability priority intel (EPSS / CISA KEV / CVSS): shortly after start, then every 6 h
  const vulnIntel = require('./src/vuln-intel');
  const runVulnIntel = () => vulnIntel.refresh()
    .then((r) => r && r.cves && console.log(`[VulnIntel] ${r.cves} CVEs: EPSS ${r.epss}, CVSS ${r.cvss}, KEV catalog ${r.kev}`))
    .catch((e) => console.error('[VulnIntel] refresh error:', e.message));
  setTimeout(runVulnIntel, 90 * 1000).unref();
  setInterval(runVulnIntel, 6 * 3600 * 1000).unref();

  // 8b. PoC page scan: every new article/blog page is read for PoC / tool-release
  //     wording and code links (no GitHub API use), so niche technique research
  //     without a CVE shows up in the admin PoC tracker too.
  {
    const pocCheck = require('./src/poc-check');
    let scanBusy = false;
    const scanBatch = async () => {
      if (scanBusy) return;
      scanBusy = true;
      let found = 0;
      try {
        const todo = db.getArticlesToScanForPoc(30);
        for (let i = 0; i < todo.length; i += 3) {
          const results = await Promise.all(todo.slice(i, i + 3).map(async (a) => {
            try { return [a, await pocCheck.scanPage(a)]; } catch { return [a, { quotes: [], denied: [], links: [], fetched: false }]; }
          }));
          for (const [a, r] of results) if (db.savePocScan(a.url, r)) found++;
        }
        if (todo.length) console.log(`[PoC] Page scan: ${todo.length} article(s), ${found} with PoC evidence`);
      } catch (e) {
        console.error('[PoC] Page scan error:', e.message);
      } finally { scanBusy = false; }
    };
    setTimeout(scanBatch, 3 * 60 * 1000).unref();
    setInterval(scanBatch, 5 * 60 * 1000).unref();
    console.log('[Init] PoC page scan: every 5 min (wording + code links, all sources) ✓');
  }

  // 9. PoC checker in the background (only with a GitHub token: 5,000 req/h).
  //    Without one the 60 req/h budget is left for the admin's manual checks.
  if (process.env.GITHUB_TOKEN) {
    const pocCheck = require('./src/poc-check');
    let pocBusy = false;
    setInterval(async () => {
      if (pocBusy) return;
      pocBusy = true;
      try {
        for (const a of db.getUncheckedPocArticles(5)) {
          const r = await pocCheck.checkArticle(a);
          db.savePocCheck(a.id, r);
          if (r.rateLimited) break;
        }
      } catch (e) {
        console.error('[PoC] Background check error:', e.message);
      } finally { pocBusy = false; }
    }, 20 * 60 * 1000).unref();
    console.log('[Init] PoC checker: background checks every 20 min ✓');
  } else {
    console.log('[Init] PoC checker: manual only (set GITHUB_TOKEN for background checks)');
  }
}

// ============================================
// PROCESS HANDLERS
// ============================================
process.on('uncaughtException', (error) => {
  console.error('[Fatal] Uncaught exception:', error.message);
});

process.on('unhandledRejection', (reason) => {
  console.error('[Fatal] Unhandled rejection:', reason);
});

process.on('SIGINT', () => {
  console.log('\n[Shutdown] Closing ThreatPulse...');
  try {
    const database = db.getDb();
    if (database) database.close();
  } catch (e) {}
  console.log('[Shutdown] Goodbye! 🛡️\n');
  process.exit(0);
});

// ============================================
// START
// ============================================
initialize().catch((error) => {
  console.error('[Fatal] Startup failed:', error && error.stack ? error.stack : error);
  process.exit(1);
});

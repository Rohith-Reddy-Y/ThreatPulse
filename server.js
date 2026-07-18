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
const { handleNotifications } = require('./src/routes/api');
const aggregator = require('./src/feeds/aggregator');
const { seedDefaultSources } = require('./src/feeds/default-sources');
const { initTransporter } = require('./src/notifications/email-notifier');
const auth = require('./src/auth');

const app = express();
const PORT = process.env.PORT || 3000;

// ============================================
// SECURITY MIDDLEWARE
// ============================================

// Security headers (Helmet-style, no dependency)
app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  res.setHeader('X-XSS-Protection', '1; mode=block');
  res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.setHeader('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
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

// Clean rate limit store periodically
setInterval(() => {
  const now = Date.now();
  for (const [key, entry] of rateLimitStore) {
    if (now > entry.resetAt) rateLimitStore.delete(key);
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
  res.header('Access-Control-Allow-Headers', 'Content-Type, Authorization');
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

  // 1. Initialize database
  console.log('[Init] Initializing database...');
  db.getDb();
  console.log('[Init] Database ready ✓');

  // 2. Create default admin user + invite codes (first run only)
  console.log('[Init] Checking user accounts...');
  auth.ensureAdminExists();

  // 3. Seed default sources (system-level, user_id = NULL)
  console.log('[Init] Seeding default threat intelligence sources...');
  seedDefaultSources(db);
  console.log('[Init] Sources ready ✓');

  // 4. Initialize email transporter
  console.log('[Init] Setting up email notifications...');
  initTransporter();

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
initialize();

'use strict';
// Shared test helpers. Run tests with:  tests/run.sh
// (sets NODE_PATH=tests/shims/node_modules so better-sqlite3/express/axios/
// nodemailer resolve to the local shims — no npm install needed).
const fs = require('fs');
const os = require('os');
const path = require('path');

const SRC = path.join(__dirname, '..', 'src');
process.env.JWT_SECRET = process.env.JWT_SECRET || 'x'.repeat(48);
delete process.env.SMTP_HOST; delete process.env.SMTP_USER; delete process.env.SMTP_PASS;
delete process.env.TELEGRAM_BOT_TOKEN; delete process.env.TELEGRAM_CHAT_ID;

// api.js starts a 15-min cleanup interval at load; don't let it keep the test
// process alive.
const realSetInterval = global.setInterval;
global.setInterval = (...a) => { const t = realSetInterval(...a); if (t && t.unref) t.unref(); return t; };
// notifiers sleep between messages; make that instant in tests
const realSetTimeout = global.setTimeout;
global.setTimeout = (fn, ms, ...a) => realSetTimeout(fn, Math.min(ms || 0, 5), ...a);

// Keep test output readable
const quiet = () => {};
console.log = quiet; console.warn = quiet; console.error = quiet;

function tmpDbPath() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tp-test-'));
  return path.join(dir, 'threatpulse.db');
}

// Load the app modules against a (fresh or given) DB file. Clears the require
// cache so every call gets a new module-level db handle.
function load(dbPath = tmpDbPath()) {
  process.env.DB_PATH = dbPath;
  for (const k of Object.keys(require.cache)) {
    if (k.startsWith(SRC)) delete require.cache[k];
  }
  const db = require(path.join(SRC, 'database.js'));
  db.getDb();
  return { db, dbPath, get api() { return require(path.join(SRC, 'routes', 'api.js')); }, get auth() { return require(path.join(SRC, 'auth.js')); } };
}

let userSeq = 0;
function makeUser(db, { username, role = 'analyst', email = null, active = 1 } = {}) {
  username = username || `user${++userSeq}`;
  const r = db.createUser(username, username.toUpperCase(), 'h', 's', role, null, email);
  if (!active) db.updateUser(r.id, { is_active: 0 });
  const u = db.getUserById(r.id);
  return { id: u.id, username: u.username, displayName: u.display_name, role: u.role, email: u.email };
}

// Invoke an api.js route by method + express path, skipping auth.requireAuth
// (req.user is supplied directly) but running every other middleware.
async function call(env, method, routePath, { user, params = {}, body = {}, query = {}, app = {} } = {}) {
  const router = env.api;
  const auth = env.auth;
  const route = router.routes.find(r => r.method === method && r.path === routePath);
  if (!route) throw new Error(`No route ${method} ${routePath}`);
  const req = { user, params, body, query, ip: '127.0.0.1', headers: {}, cookies: {},
    app: { get: (k) => app[k] }, protocol: 'http', get: () => 'localhost' };
  const res = {
    statusCode: 200, body: undefined, done: false,
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; this.done = true; return this; },
    send(b) { this.body = b; this.done = true; return this; },
  };
  const handlers = route.handlers.filter(h => h !== auth.requireAuth);
  for (const h of handlers) {
    let nextCalled = false;
    await h(req, res, () => { nextCalled = true; });
    if (!nextCalled) break;
  }
  return res;
}

function art(overrides = {}) {
  const n = Math.random().toString(36).slice(2);
  return {
    title: `Generic article ${n}`,
    description: 'desc',
    url: `https://example.com/${n}`,
    source_name: 'Test',
    severity: 'medium',
    category: 'news',
    published_date: new Date().toISOString(),
    ...overrides,
  };
}

module.exports = { load, makeUser, call, art, tmpDbPath };

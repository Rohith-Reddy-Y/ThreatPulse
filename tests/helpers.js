/**
 * Test harness: loads the real auth/security/api modules against a throwaway
 * SQLite DB (node:sqlite shim) with stubbed npm deps, and dispatches fake
 * requests straight to the recorded route handlers. Test-only — the app never
 * requires anything under tests/.
 */
'use strict';
const path = require('path');
const os = require('os');
const fs = require('fs');
const Module = require('module');

const ROOT = path.join(__dirname, '..');
process.env.NODE_PATH = [path.join(__dirname, 'stubs', 'modules'), process.env.NODE_PATH || ''].filter(Boolean).join(path.delimiter);
Module._initPaths();

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tp-test-'));
process.env.DB_PATH = path.join(tmp, 'test.db');
process.env.JWT_SECRET = process.env.JWT_SECRET || 'x'.repeat(48);
delete process.env.SMTP_HOST;
delete process.env.REQUIRE_INVITE_CODE;

// The app's housekeeping intervals would keep the test process alive forever
const realSetInterval = global.setInterval;
global.setInterval = (...a) => { const t = realSetInterval(...a); if (t && t.unref) t.unref(); return t; };
const realSetTimeout = global.setTimeout;
global.setTimeout = (...a) => { const t = realSetTimeout(...a); if (t && t.unref) t.unref(); return t; };

// Silence the app's console noise unless DEBUG is set
if (!process.env.DEBUG) { console.log = () => {}; console.warn = () => {}; }

const db = require(path.join(ROOT, 'src/database'));
const auth = require(path.join(ROOT, 'src/auth'));
const security = require(path.join(ROOT, 'src/security'));
const router = require(path.join(ROOT, 'src/routes/api'));

function matchPath(pattern, actual) {
  const p = pattern.split('/'), a = actual.split('/');
  if (p.length !== a.length) return null;
  const params = {};
  for (let i = 0; i < p.length; i++) {
    if (p[i].startsWith(':')) params[p[i].slice(1)] = a[i];
    else if (p[i] !== a[i]) return null;
  }
  return params;
}

function makeRes() {
  const res = {
    statusCode: 200, body: undefined, cookies: {}, cleared: [], headers: {},
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; this.done = true; return this; },
    sendStatus(c) { this.statusCode = c; this.done = true; return this; },
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    header(k, v) { this.headers[k.toLowerCase()] = v; },
    cookie(name, value, opts) { this.cookies[name] = { value, opts }; },
    clearCookie(name, opts) { this.cleared.push({ name, opts }); delete this.cookies[name]; },
  };
  return res;
}

/**
 * Dispatch a fake request to the api router (mounted at /api).
 * opts: { body, cookies, headers, ip }
 */
async function request(method, url, opts = {}) {
  const [pathname, qs] = url.split('?');
  const rel = pathname.replace(/^\/api/, '');
  const route = router.routes.find(r => r.method === method && matchPath(r.path, rel));
  if (!route) throw new Error(`No route ${method} ${url}`);
  const req = {
    method, url: rel, originalUrl: url, baseUrl: '/api', path: rel,
    params: matchPath(route.path, rel),
    query: Object.fromEntries(new URLSearchParams(qs || '')),
    body: opts.body || {}, cookies: opts.cookies || {}, headers: opts.headers || {},
    ip: opts.ip || '1.2.3.4', protocol: 'https', get: () => 'example.test',
    app: { get: () => null },
  };
  const res = makeRes();
  // Middleware like requireAuth calls next() without returning it, so awaiting the
  // first handler doesn't cover an async handler further down the chain: collect
  // every handler's promise and wait for all of them.
  let i = 0;
  const pending = [];
  const next = (err) => {
    if (err) return Promise.reject(err);
    const h = route.handlers[i++];
    if (!h) return Promise.resolve();
    const p = (async () => h(req, res, next))();
    pending.push(p);
    return p;
  };
  next();
  for (let k = 0; k < pending.length; k++) await pending[k];
  return { req, res, status: res.statusCode, body: res.body };
}

/** Cookie jar helper: merge Set-Cookie results into a jar */
function absorb(jar, res) {
  for (const c of res.cleared) delete jar[c.name];
  for (const [k, v] of Object.entries(res.cookies)) jar[k] = v.value;
  return jar;
}

// Hashes with the legacy synchronous scrypt call the app used before hashing went
// async (same params/format), so every login in the suite also proves that hashes
// stored by older versions still verify. Keeps this helper synchronous.
function legacyHash(password, salt) {
  return require('crypto').scryptSync(password, salt, 64).toString('hex');
}

function createUser(username, password, { role = 'analyst', email = null, mustChange = false } = {}) {
  const salt = auth.generateSalt();
  const r = db.createUser(username, username, legacyHash(password, salt), salt, role, null, email || `${username}@example.test`);
  if (!r.success) throw new Error(r.error);
  db.createUserNotificationSettings(r.id);
  if (mustChange) db.setMustChangePassword(r.id, 1);
  return r.id;
}

async function login(username, password, ip) {
  const r = await request('POST', '/api/auth/login', { body: { username, password }, ip });
  if (!r.body || !r.body.success) throw new Error(`login failed: ${JSON.stringify(r.body)}`);
  return absorb({}, r.res);
}

module.exports = { db, auth, security, router, request, absorb, createUser, legacyHash, login, tmp };

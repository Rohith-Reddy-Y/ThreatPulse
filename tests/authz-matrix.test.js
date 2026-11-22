/**
 * Authorization matrix: every route (enumerated from the real routers and the
 * server.js app) x every actor, from unauthenticated up to admin.
 *
 * Requests go through the real server.js middleware stack in order (cookie
 * parser -> CSRF -> headers -> rate limits -> CORS -> routers), with the real
 * auth/requireAuth, real api.js + ai.js routers and a throwaway SQLite DB.
 * Only the feed aggregator and the network-facing deps are stubbed.
 *
 * Part 1 is the gate matrix (who gets past authn/authz for each route).
 * Part 2 checks object-level isolation (analyst A vs B, guest, admin).
 * Part 3 covers admin edge cases, id parsing, method/path confusion and CSRF.
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const crypto = require('crypto');

// AI quotas would otherwise 429 the matrix; no AI/Telegram keys (no network).
Object.assign(process.env, {
  AI_USER_PER_MIN: '100000', AI_GUEST_IP_PER_MIN: '100000',
  AI_GUEST_TOTAL_PER_MIN: '100000', AI_GUEST_TOTAL_PER_DAY: '100000',
});
for (const k of ['GROQ_API_KEY', 'TAVILY_API_KEY', 'TELEGRAM_BOT_TOKEN', 'TELEGRAM_CHAT_ID']) delete process.env[k];

const h = require('./helpers'); // stubbed npm deps, temp DB, quiet console
const { db, auth, createUser } = h;
const ROOT = path.join(__dirname, '..');

const stub = (rel, exportsObj) => {
  const file = require.resolve(path.join(ROOT, rel));
  require.cache[file] = { id: file, filename: file, loaded: true, exports: exportsObj };
};
const aggregatorCalls = [];
stub('src/feeds/aggregator', {
  setOnFetchComplete() {}, startScheduler() {},
  fetchAllSources: async () => { aggregatorCalls.push(Date.now()); return {}; },
  getStatus: () => ({ isRunning: false, lastFetchTime: null, total: 0, new: 0, errors: 0 }),
});
stub('src/feeds/default-sources', { seedDefaultSources() {} });

// ---------------------------------------------------------------------------
// Fixtures (created before server.js loads, so no first-run admin is made)
// ---------------------------------------------------------------------------
const PW = 'Correct-Horse-9';
const SECRET = process.env.JWT_SECRET;
let seq = 0;
const uniq = () => `${Date.now().toString(36)}${(++seq).toString(36)}`;

const ids = {
  admin: createUser('root_admin', PW, { role: 'admin' }),
  admin2: createUser('second_admin', PW, { role: 'admin' }),
  a: createUser('analyst_a', PW),
  b: createUser('analyst_b', PW),
  disabled: createUser('disabled_user', PW),
  mustChange: createUser('must_change', PW, { mustChange: true }),
  mustChangeAdmin: createUser('must_change_admin', PW, { role: 'admin', mustChange: true }),
};
db.updateUser(ids.disabled, { is_active: 0 });
const deletedId = createUser('deleted_user', PW);
db.deleteUser(deletedId);

function addSource(userId, extra = {}) {
  return db.addSource({ name: `src ${uniq()}`, url: `https://feeds.example.com/${uniq()}.xml`, added_by: 'user', user_id: userId, ...extra }).id;
}
function addArticle(sourceId, userId, title) {
  return db.insertArticle({
    title: title || `article ${uniq()}`, description: 'desc', url: `https://news.example.com/${uniq()}`,
    source_name: 'S', severity: 'high', category: 'news', published_date: new Date().toISOString(),
    source_id: sourceId, user_id: userId,
  }).id;
}

const sysSource = addSource(null, { added_by: 'system', name: 'System Feed' });
const sysArticle = addArticle(sysSource, null, 'System article quokka');
const data = {};
for (const who of ['a', 'b', 'admin']) {
  const src = addSource(ids[who], { name: `Private ${who} feed` });
  data[who] = { source: src, article: addArticle(src, ids[who], `Private ${who} article quokka`) };
}
db.escalateArticle(data.a.article, ids.a, 'A-secret-note');
db.updateNotificationSettings({ telegram_bot_token: '111111:AAAA-secret-token-of-a', telegram_chat_id: 'chat-a', email: 'alerts-a@example.test' }, ids.a);
db.updateNotificationSettings({ telegram_bot_token: '222222:BBBB-secret-token-of-b', telegram_chat_id: 'chat-b', email: 'alerts-b@example.test' }, ids.b);
data.a.thread = db.createThread(ids.a, 'A private thread');
db.addMessage(data.a.thread, 'user', 'A-secret-question');
data.b.thread = db.createThread(ids.b, 'B private thread');
data.admin.thread = db.createThread(ids.admin, 'Admin thread');

// Load the real server wiring (real api.js + ai.js routers)
require(path.join(ROOT, 'server.js'));
const app = require('express').lastApp;
const apiRouter = require(path.join(ROOT, 'src/routes/api'));
const aiRouter = require(path.join(ROOT, 'src/routes/ai'));

// ---------------------------------------------------------------------------
// Tokens
// ---------------------------------------------------------------------------
const b64 = (o) => Buffer.from(JSON.stringify(o)).toString('base64url');
function mint(payload, { secret = SECRET, header = { alg: 'HS256', typ: 'JWT' }, hash = 'sha256', expIn = 900 } = {}) {
  const now = Math.floor(Date.now() / 1000);
  const hd = b64(header);
  // jti keeps every token unique, so a logout in one case can't blacklist another
  const pl = b64({ iat: now, exp: now + expIn, jti: crypto.randomBytes(8).toString('hex'), ...payload });
  const sig = hash ? crypto.createHmac(hash, secret).update(`${hd}.${pl}`).digest('base64url') : '';
  return `${hd}.${pl}.${sig}`;
}
const tokenFor = (id, extra = {}) => {
  const u = db.getUserById(id);
  return mint({ userId: u.id, username: u.username, role: u.role, ...extra });
};

// ---------------------------------------------------------------------------
// Mini express: runs app.stack (as recorded by the express stub) in order
// ---------------------------------------------------------------------------
function matchPath(pattern, actual) {
  // express defaults: case-insensitive, non-strict (one trailing slash allowed)
  if (actual.length > 1 && actual.endsWith('/')) actual = actual.slice(0, -1);
  const p = pattern.split('/'), a = actual.split('/');
  if (p.length !== a.length) return null;
  const params = {};
  for (let i = 0; i < p.length; i++) {
    if (p[i].startsWith(':')) {
      if (!a[i]) return null;
      try { params[p[i].slice(1)] = decodeURIComponent(a[i]); } catch { return null; }
    } else if (p[i].toLowerCase() !== a[i].toLowerCase()) return null;
  }
  return params;
}
function mountMatch(mount, pathname) {
  const m = mount.toLowerCase(), pth = pathname.toLowerCase();
  return pth === m || pth.startsWith(m + '/');
}
function makeRes() {
  return {
    statusCode: 200, body: undefined, cookies: {}, cleared: [], headers: {}, done: false, file: null,
    _finish() { this.done = true; if (this._notify) this._notify(); return this; },
    status(c) { this.statusCode = c; return this; },
    json(b) { this.body = b; return this._finish(); },
    send(b) { this.body = b; return this._finish(); },
    end() { return this._finish(); },
    sendStatus(c) { this.statusCode = c; return this._finish(); },
    sendFile(f) { this.file = f; return this._finish(); },
    setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
    header(k, v) { this.headers[k.toLowerCase()] = v; },
    cookie(name, value, opts) { this.cookies[name] = { value, opts }; },
    clearCookie(name) { this.cleared.push(name); },
  };
}
function runFn(fn, req, res, err) {
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (v) => { if (!settled) { settled = true; resolve(v); } };
    res._notify = () => finish('done');
    const next = (e) => { if (e) { settled = true; reject(e); } else finish('next'); };
    let ret;
    try { ret = err ? fn(err, req, res, next) : fn(req, res, next); } catch (e) { reject(e); return; }
    if (ret && typeof ret.then === 'function') ret.then(() => finish('end'), reject);
    else finish(res.done ? 'done' : 'end');
  });
}
async function runRouter(router, req, res) {
  for (const r of router.routes) {
    if (!(r.method === req.method || (req.method === 'HEAD' && r.method === 'GET'))) continue;
    const params = matchPath(r.path, req.path);
    if (!params) continue;
    req.params = params;
    for (const fn of r.handlers) {
      if ((await runFn(fn, req, res)) !== 'next') return true;
    }
  }
  return false;
}
let ipSeq = 0;
async function dispatch(method, url, { cookies = {}, headers = {}, body, csrf = true, ip } = {}) {
  const [pathname, qs] = url.split('?');
  const jar = { ...cookies };
  const hdrs = { ...headers };
  if (csrf) {
    const t = crypto.randomBytes(32).toString('hex');
    jar.tp_csrf = t; hdrs['x-csrf-token'] = t;
  }
  const cookieStr = Object.entries(jar).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('; ');
  if (cookieStr) hdrs.cookie = cookieStr;
  ipSeq++;
  const req = {
    method, url, originalUrl: url, path: pathname, baseUrl: '', params: {},
    query: Object.fromEntries(new URLSearchParams(qs || '')),
    headers: hdrs, body: body || {}, ip: ip || `10.${(ipSeq >> 16) & 255}.${(ipSeq >> 8) & 255}.${ipSeq & 255}`,
    protocol: 'https', connection: {}, app,
    get: (k) => (k.toLowerCase() === 'host' ? 'tp.example.test' : hdrs[k.toLowerCase()]),
  };
  const res = makeRes();
  let stopped = false;
  try {
    for (const layer of app.stack) {
      const fns = layer.args.slice();
      let mount = typeof fns[0] === 'string' ? fns.shift() : null;
      if (fns.some(f => typeof f === 'function' && f.length === 4)) continue; // error handler
      if (layer.kind === 'get') {
        if (!['GET', 'HEAD'].includes(method) || !matchPath(mount, pathname)) continue;
        req.baseUrl = ''; req.path = pathname;
      } else if (mount && mount !== '/') {
        if (!mountMatch(mount, pathname)) continue;
        req.baseUrl = pathname.slice(0, mount.length); req.path = pathname.slice(mount.length) || '/';
      } else { req.baseUrl = ''; req.path = pathname; }
      for (const fn of fns) {
        const v = (fn && Array.isArray(fn.routes))
          ? ((await runRouter(fn, req, res)) ? 'done' : 'next')
          : await runFn(fn, req, res);
        if (v !== 'next') { stopped = true; break; }
      }
      req.baseUrl = ''; req.path = pathname;
      if (stopped) break;
    }
    if (!stopped) { res.statusCode = 404; res.body = { error: 'Cannot ' + method + ' ' + pathname }; }
  } catch (e) {
    const eh = app.stack.find(l => l.kind === 'use' && l.args.length && typeof l.args[l.args.length - 1] === 'function' && l.args[l.args.length - 1].length === 4);
    await runFn(eh.args[eh.args.length - 1], req, res, e);
  }
  return { status: res.statusCode, body: res.body, res, req };
}

// ---------------------------------------------------------------------------
// Actors, least -> most privileged
// ---------------------------------------------------------------------------
const GUEST_SID = 'ab'.repeat(16);
let guestId;
async function freshRefreshCookie(username) {
  const r = await dispatch('POST', '/api/auth/login', { body: { username, password: PW }, csrf: false });
  assert.ok(r.body && r.body.success, `login ${username}: ${JSON.stringify(r.body)}`);
  return r.res.cookies.tp_refresh.value;
}
const cookieActor = (fn) => async () => ({ cookies: { tp_access: await fn() } });
const ACTORS = [
  { name: 'anonymous (no cookies)', kind: 'anon', creds: async () => ({}) },
  { name: 'garbage token', kind: 'anon', creds: async () => ({ cookies: { tp_access: 'not.a.jwt' } }) },
  { name: 'garbage bearer', kind: 'anon', creds: async () => ({ headers: { authorization: 'Bearer abc.def.ghi' } }) },
  { name: 'forged signature (admin claims)', kind: 'anon', creds: cookieActor(() => mint({ userId: ids.admin, username: 'root_admin', role: 'admin' }, { secret: 'y'.repeat(48) })) },
  { name: 'alg:none (admin claims)', kind: 'anon', creds: cookieActor(() => mint({ userId: ids.admin, role: 'admin' }, { header: { alg: 'none', typ: 'JWT' }, hash: null })) },
  { name: 'alg:HS512 signed with the real secret', kind: 'anon', creds: cookieActor(() => mint({ userId: ids.admin, role: 'admin' }, { header: { alg: 'HS512', typ: 'JWT' }, hash: 'sha512' })) },
  { name: 'expired token', kind: 'anon', creds: cookieActor(() => mint({ userId: ids.admin, role: 'admin' }, { expIn: -60 })) },
  { name: 'token for a deleted user', kind: 'anon', creds: cookieActor(() => mint({ userId: deletedId, role: 'analyst' })) },
  { name: 'token for a non-existent user id', kind: 'anon', creds: cookieActor(() => mint({ userId: 987654, role: 'admin' })) },
  { name: 'refresh cookie only', kind: 'anon', creds: async () => ({ cookies: { tp_refresh: await freshRefreshCookie('analyst_a') } }) },
  { name: 'guest', kind: 'guest', creds: async () => ({ cookies: { tp_access: tokenFor(guestId), tp_ai_gsid: GUEST_SID } }), who: 'guest' },
  { name: 'analyst A', kind: 'analyst', creds: cookieActor(() => tokenFor(ids.a)), who: 'a' },
  { name: 'analyst A with forged role:admin claim', kind: 'analyst', creds: cookieActor(() => tokenFor(ids.a, { role: 'admin' })), who: 'a' },
  { name: 'analyst B', kind: 'analyst', creds: cookieActor(() => tokenFor(ids.b)), who: 'b' },
  { name: 'disabled user (valid token)', kind: 'disabled', creds: cookieActor(() => tokenFor(ids.disabled)) },
  { name: 'must_change_password analyst', kind: 'mustChange', creds: cookieActor(() => tokenFor(ids.mustChange)) },
  { name: 'must_change_password admin', kind: 'mustChange', creds: cookieActor(() => tokenFor(ids.mustChangeAdmin)) },
  { name: 'admin', kind: 'admin', creds: cookieActor(() => tokenFor(ids.admin)), who: 'admin' },
];

// ---------------------------------------------------------------------------
// Route policy table. Every route the app exposes must be listed here.
//   public  - no auth (pre-auth flows)       auth   - any signed-in user incl. guest
//   member  - signed-in, not the guest       admin  - admins only
// must_change_password users may only use routes marked mustChangeOk (plus public).
// allow   - statuses an allowed actor gets for the request built below.
// ---------------------------------------------------------------------------
const userIdOf = (actor) => (actor.who === 'guest' ? guestId : actor.who ? ids[actor.who] : null);
const ownSource = (actor) => (userIdOf(actor) && actor.who !== 'guest' ? addSource(userIdOf(actor)) : data.a.source);
const ownArticle = (actor) => {
  if (actor.who === 'guest') return sysArticle;
  if (!userIdOf(actor)) return data.a.article;
  return addArticle(addSource(userIdOf(actor)), userIdOf(actor));
};
async function newGuestThread() {
  const title = `guest quokka ${uniq()}`;
  const r = await dispatch('POST', '/api/ai/ask', {
    cookies: { tp_access: tokenFor(guestId), tp_ai_gsid: GUEST_SID }, body: { question: title, mode: 'web' },
  });
  // web mode creates the thread even without API keys (RAG now refuses up front)
  assert.ok([200, 503].includes(r.status), `ask -> ${r.status}`);
  return db.getThreads(guestId).find(t => t.title === title).id;
}
const ownThread = (actor) => (actor.who === 'guest' ? newGuestThread() : userIdOf(actor) ? db.createThread(userIdOf(actor), 't') : data.a.thread);
const throwawayUser = () => createUser(`victim_${uniq()}`, PW);

const ROUTES = {
  // server.js
  'GET /healthz': { policy: 'public', allow: [200] },
  'GET /admin': { policy: 'public', allow: [200] }, // static HTML shell; all data is behind /api/admin/*
  // auth (pre-auth)
  'GET /api/auth/config': { policy: 'public', allow: [200] },
  'POST /api/auth/login': { policy: 'public', allow: [200] },
  'POST /api/auth/register': { policy: 'public', allow: [200] },
  'POST /api/auth/forgot-password': { policy: 'public', allow: [200] },
  'POST /api/auth/reset-password': { policy: 'public', allow: [200] },
  'POST /api/auth/logout': { policy: 'public', allow: [200] },
  'POST /api/auth/guest': { policy: 'public', allow: [200] },
  'POST /api/auth/refresh': { policy: 'public', allow: [200, 401] }, // 401 = no/invalid refresh cookie
  // account
  'GET /api/auth/me': { policy: 'auth', mustChangeOk: true, allow: [200] },
  'PUT /api/auth/password': { policy: 'member', mustChangeOk: true, allow: [400] }, // empty body -> validation
  'PUT /api/auth/email': { policy: 'member', allow: [400] },
  'POST /api/auth/verify-change': { policy: 'member', allow: [400] },
  // articles / search
  'GET /api/articles': { policy: 'auth', allow: [200] },
  'GET /api/articles/stats': { policy: 'auth', allow: [200] },
  'GET /api/search': { policy: 'auth', allow: [200], query: '?q=quokka' },
  'POST /api/articles/:id/review': { policy: 'member', allow: [200], params: ownArticle },
  'PUT /api/articles/:id/review': { policy: 'member', allow: [200], params: ownArticle, body: () => ({ notes: 'n' }) },
  'POST /api/articles/:id/escalate': { policy: 'member', allow: [200], params: ownArticle, body: () => ({ notes: 'n' }) },
  // sources
  'GET /api/sources': { policy: 'auth', allow: [200] },
  'POST /api/sources': { policy: 'member', allow: [201], body: () => ({ name: 'New feed', url: `https://feeds.example.com/new-${uniq()}.xml` }) },
  'PUT /api/sources/:id': { policy: 'member', allow: [200], params: ownSource, body: () => ({ name: 'Renamed feed' }) },
  'DELETE /api/sources/:id': { policy: 'member', allow: [200], params: ownSource },
  // fetch / status
  'POST /api/fetch-now': { policy: 'member', allow: [200, 429] }, // 429 = non-admin cooldown
  'GET /api/status': { policy: 'auth', allow: [200] },
  // notifications
  'GET /api/notifications/settings': { policy: 'auth', allow: [200] },
  'PUT /api/notifications/settings': { policy: 'member', allow: [200], body: () => ({ severity_threshold: 'high' }) },
  'POST /api/notifications/test': { policy: 'member', allow: [400], body: () => ({ type: 'nope' }) },
  // admin
  'GET /api/admin/users': { policy: 'admin', allow: [200] },
  'PUT /api/admin/users/:id': { policy: 'admin', allow: [200], params: throwawayUser, body: () => ({ display_name: 'Renamed' }) },
  'DELETE /api/admin/users/:id': { policy: 'admin', allow: [200], params: throwawayUser },
  'POST /api/admin/invite-codes': { policy: 'admin', allow: [200] },
  'GET /api/admin/invite-codes': { policy: 'admin', allow: [200] },
  'GET /api/admin/articles': { policy: 'admin', allow: [200] },
  'GET /api/admin/sources': { policy: 'admin', allow: [200] },
  'GET /api/admin/stats': { policy: 'admin', allow: [200] },
  'GET /api/admin/audit-log': { policy: 'admin', allow: [200] },
  'GET /api/admin/reset-tokens': { policy: 'admin', allow: [200] },
  'GET /api/admin/ai-settings': { policy: 'admin', allow: [200] },
  'PUT /api/admin/ai-settings': { policy: 'admin', allow: [200] },
  // AI (no GROQ key in tests -> generation answers 503 once past the gates)
  'POST /api/ai/summarize': { policy: 'auth', allow: [503], body: (a) => ({ articleId: ownArticle(a) }) },
  'POST /api/ai/triage': { policy: 'auth', allow: [503], body: (a) => ({ articleId: ownArticle(a) }) },
  'POST /api/ai/ask': { policy: 'auth', allow: [503], body: () => ({ question: 'ransomware quokka', mode: 'rag' }) },
  'GET /api/ai/threads': { policy: 'auth', allow: [200] },
  'GET /api/ai/threads/:id': { policy: 'auth', allow: [200], params: ownThread },
  'DELETE /api/ai/threads/:id': { policy: 'auth', allow: [200], params: ownThread },
  'GET /api/ai/status': { policy: 'auth', allow: [200] },
};

function expectedGate(spec, actor) {
  if (spec.policy === 'public') return 'allow';
  if (actor.kind === 'anon' || actor.kind === 'disabled') return 401;
  if (actor.kind === 'mustChange') return spec.mustChangeOk ? 'allow' : 'mustChange';
  if (spec.policy === 'auth') return 'allow';
  if (spec.policy === 'member') return actor.kind === 'guest' ? 403 : 'allow';
  if (spec.policy === 'admin') return actor.kind === 'admin' ? 'allow' : 403;
  throw new Error('unknown policy ' + spec.policy);
}

function enumerateRoutes() {
  const out = [];
  for (const r of apiRouter.routes) out.push(`${r.method} /api${r.path}`);
  for (const r of aiRouter.routes) out.push(`${r.method} /api/ai${r.path}`);
  for (const l of app.stack) if (l.kind === 'get') out.push(`GET ${l.args[0]}`);
  return out;
}

async function buildRequest(key, spec, actor) {
  const [method, pattern] = key.split(' ');
  let url = pattern;
  if (pattern.includes(':id')) url = pattern.replace(':id', String(await spec.params(actor)));
  url += spec.query || '';
  const body = spec.body ? await spec.body(actor) : {};
  return { method, url, body };
}

test.before(async () => {
  const g = await auth.getOrCreateGuestUser();
  guestId = g.user.id;
  // A thread owned by this guest browser (per-visitor isolation via tp_ai_gsid)
  data.guestThread = await newGuestThread();
});

// ===========================================================================
// Part 1 — gate matrix
// ===========================================================================
test('every route exposed by the app has an entry in the policy table (and vice versa)', () => {
  const routes = enumerateRoutes();
  assert.strictEqual(new Set(routes).size, routes.length, 'duplicate route registration');
  assert.deepStrictEqual([...routes].sort(), Object.keys(ROUTES).sort(),
    'a route was added/removed: classify it in ROUTES (tests/authz-matrix.test.js)');
});

for (const [key, spec] of Object.entries(ROUTES)) {
  test(`gate matrix: ${key}`, async () => {
    const failures = [];
    for (const actor of ACTORS) {
      const { method, url, body } = await buildRequest(key, spec, actor);
      const r = await dispatch(method, url, { ...(await actor.creds()), body });
      const want = expectedGate(spec, actor);
      const got = `${r.status} ${JSON.stringify(r.body)}`.slice(0, 200);
      if (want === 'allow') {
        if (!spec.allow.includes(r.status)) failures.push(`${actor.name}: want ${spec.allow.join('|')}, got ${got}`);
      } else if (want === 'mustChange') {
        if (r.status !== 403 || !r.body || r.body.mustChangePassword !== true) failures.push(`${actor.name}: want 403 mustChangePassword, got ${got}`);
      } else if (r.status !== want) {
        failures.push(`${actor.name}: want ${want}, got ${got}`);
      }
    }
    assert.deepStrictEqual(failures, []);
  });
}

test('CSRF: every state-changing /api route except the token-issuing ones rejects a missing or mismatched token', async () => {
  const exempt = new Set(['/api/auth/login', '/api/auth/register', '/api/auth/forgot-password',
    '/api/auth/reset-password', '/api/auth/refresh', '/api/auth/guest']);
  const admin = ACTORS.find(a => a.name === 'admin');
  const failures = [];
  for (const [key, spec] of Object.entries(ROUTES)) {
    const [method, pattern] = key.split(' ');
    if (method === 'GET' || !pattern.startsWith('/api')) continue;
    const { url, body } = await buildRequest(key, spec, admin);
    const creds = await admin.creds();
    const none = await dispatch(method, url, { ...creds, body, csrf: false });
    const bad = await dispatch(method, url, {
      cookies: { ...creds.cookies, tp_csrf: 'a'.repeat(64) }, headers: { 'x-csrf-token': 'b'.repeat(64) }, body, csrf: false,
    });
    for (const [label, r] of [['missing', none], ['mismatched', bad]]) {
      const csrfBlocked = r.status === 403 && /CSRF/.test(r.body && r.body.error);
      if (exempt.has(pattern) === csrfBlocked) failures.push(`${key} (${label} token): got ${r.status} ${JSON.stringify(r.body)}`);
    }
  }
  assert.deepStrictEqual(failures, []);
});

test('CSRF is checked before auth and before the handler runs (no side effect)', async () => {
  const victim = throwawayUser();
  const r = await dispatch('DELETE', `/api/admin/users/${victim}`, { cookies: { tp_access: tokenFor(ids.admin) }, csrf: false });
  assert.strictEqual(r.status, 403);
  assert.ok(db.getUserById(victim), 'user deleted despite missing CSRF token');
});

// ===========================================================================
// Part 2 — object-level isolation
// ===========================================================================
const as = (who) => ({ cookies: { tp_access: tokenFor(who === 'guest' ? guestId : ids[who]), ...(who === 'guest' ? { tp_ai_gsid: GUEST_SID } : {}) } });
const call = (who, method, url, body) => dispatch(method, url, { ...as(who), body });

test('read scope: guest = system content only, analysts = own rows only, admin = everything', async () => {
  const titles = async (who) => (await call(who, 'GET', '/api/articles?limit=200')).body.articles.map(a => a.title);
  const has = (list, s) => list.some(t => t.includes(s));

  const g = await titles('guest');
  assert.ok(has(g, 'System article'));
  assert.ok(!has(g, 'Private'), `guest sees private articles: ${g}`);
  const a = await titles('a');
  assert.ok(has(a, 'Private a article') && !has(a, 'Private b') && !has(a, 'Private admin') && !has(a, 'System article'));
  const b = await titles('b');
  assert.ok(has(b, 'Private b article') && !has(b, 'Private a'));
  const ad = await titles('admin');
  for (const s of ['Private a', 'Private b', 'Private admin', 'System article']) assert.ok(has(ad, s), `admin misses ${s}`);

  const search = async (who) => JSON.stringify((await call(who, 'GET', '/api/search?q=quokka')).body);
  assert.ok(!/Private/.test(await search('guest')));
  assert.ok(/Private a/.test(await search('a')) && !/Private b|Private admin/.test(await search('a')));
  assert.ok(!/Private a|A-secret-note/.test(await search('b')));

  const srcNames = async (who) => (await call(who, 'GET', '/api/sources')).body.sources.map(s => s.name);
  assert.deepStrictEqual(await srcNames('guest'), ['System Feed']);
  assert.ok((await srcNames('a')).every(n => n !== 'Private b feed' && n !== 'System Feed' && n !== 'Private admin feed'));
  assert.ok((await srcNames('b')).every(n => n !== 'Private a feed'));
  assert.ok((await srcNames('admin')).includes('Private a feed'));

  const statsA = (await call('a', 'GET', '/api/articles/stats')).body;
  const statsAdmin = (await call('admin', 'GET', '/api/articles/stats')).body;
  assert.ok(statsA.totalArticles < statsAdmin.totalArticles);
  assert.strictEqual((await call('guest', 'GET', '/api/articles/stats')).body.totalArticles, 1);

  // B never sees A's review note anywhere
  assert.ok(!JSON.stringify((await call('b', 'GET', '/api/articles?limit=200')).body).includes('A-secret-note'));
  assert.ok(!JSON.stringify((await call('guest', 'GET', '/api/articles?limit=200')).body).includes('A-secret-note'));
});

test('analyst B cannot modify or delete analyst A\'s sources (or system sources); mass assignment is ignored', async () => {
  const src = addSource(ids.a);
  const before = db.getDb().prepare('SELECT * FROM sources WHERE id = ?').get(src);
  for (const [m, body] of [['PUT', { name: 'pwned', url: 'https://evil.example/x' }], ['DELETE', {}]]) {
    const r = await call('b', m, `/api/sources/${src}`, body);
    assert.strictEqual(r.status, 403, `${m}: ${JSON.stringify(r.body)}`);
  }
  assert.deepStrictEqual(db.getDb().prepare('SELECT * FROM sources WHERE id = ?').get(src), before);

  for (const m of ['PUT', 'DELETE']) {
    const r = await call('a', m, `/api/sources/${sysSource}`, { name: 'pwned' });
    assert.strictEqual(r.status, 403, `analyst ${m} system source`);
  }
  // Owner can't reassign ownership / provenance through the update body
  const own = addSource(ids.a);
  const r = await call('a', 'PUT', `/api/sources/${own}`, { name: 'ok', user_id: ids.b, added_by: 'system', id: 1 });
  assert.strictEqual(r.status, 200);
  const row = db.getDb().prepare('SELECT * FROM sources WHERE id = ?').get(own);
  assert.strictEqual(row.user_id, ids.a);
  assert.strictEqual(row.added_by, 'user');
  // ...nor through creation
  const c = await call('a', 'POST', '/api/sources', { name: 'x', url: `https://feeds.example.com/${uniq()}`, user_id: ids.b, added_by: 'system' });
  assert.strictEqual(c.status, 201);
  const created = db.getDb().prepare('SELECT * FROM sources WHERE id = ?').get(c.body.id);
  assert.strictEqual(created.user_id, ids.a);
  assert.strictEqual(created.added_by, 'user');
});

test('platform-only source types (headless browser, dark-web/abuse.ch) are reserved for admins', async () => {
  for (const type of ['browser', 'darkweb', 'Browser ']) {
    const r = await call('a', 'POST', '/api/sources', { name: 'x', url: `https://feeds.example.com/${uniq()}`, type });
    assert.strictEqual(r.status, 403, `analyst created a ${type} source`);
  }
  const own = addSource(ids.a);
  const u = await call('a', 'PUT', `/api/sources/${own}`, { type: 'browser' });
  assert.strictEqual(u.status, 403);
  assert.strictEqual(db.getDb().prepare('SELECT type FROM sources WHERE id = ?').get(own).type, 'rss');
  // ordinary types still work for analysts; admins may use any type
  assert.strictEqual((await call('a', 'POST', '/api/sources', { name: 'x', url: `https://feeds.example.com/${uniq()}`, type: 'api' })).status, 201);
  assert.strictEqual((await call('admin', 'POST', '/api/sources', { name: 'x', url: `https://feeds.example.com/${uniq()}`, type: 'browser' })).status, 201);
});

test('reviews: B cannot start/complete/escalate on A\'s article; analysts cannot review system articles; guest cannot review', async () => {
  for (const [m, p] of [['POST', 'review'], ['PUT', 'review'], ['POST', 'escalate']]) {
    assert.strictEqual((await call('b', m, `/api/articles/${data.a.article}/${p}`, { notes: 'B was here' })).status, 403);
    assert.strictEqual((await call('a', m, `/api/articles/${sysArticle}/${p}`, { notes: 'x' })).status, 403);
    assert.strictEqual((await call('guest', m, `/api/articles/${sysArticle}/${p}`, { notes: 'x' })).status, 403);
  }
  const n = db.getDb().prepare('SELECT COUNT(*) c FROM article_reviews WHERE article_id IN (?, ?) AND user_id IN (?, ?, ?)')
    .get(data.a.article, sysArticle, ids.b, guestId, guestId).c;
  assert.strictEqual(n, 0);
  // admin may review anyone's article
  assert.strictEqual((await call('admin', 'POST', `/api/articles/${data.a.article}/review`)).status, 200);
});

test('notification settings are per-user: B reads/writes only B\'s row, secrets are masked', async () => {
  const gb = (await call('b', 'GET', '/api/notifications/settings')).body;
  assert.strictEqual(gb.user_id, ids.b);
  assert.ok(!JSON.stringify(gb).includes('AAAA-secret') && !JSON.stringify(gb).includes('BBBB-secret'));
  const r = await call('b', 'PUT', '/api/notifications/settings', { email: 'b2@example.test', user_id: ids.a, id: 1 });
  assert.strictEqual(r.status, 200);
  assert.strictEqual(db.getNotificationSettings(ids.a).email, 'alerts-a@example.test', 'B overwrote A\'s settings');
  assert.strictEqual(db.getNotificationSettings(ids.b).email, 'b2@example.test');
  // guest gets the shared guest row but can never write it
  assert.strictEqual((await call('guest', 'PUT', '/api/notifications/settings', { email: 'x@example.test' })).status, 403);
});

test('telegram: only admins fall back to the operator\'s TELEGRAM_BOT_TOKEN / TELEGRAM_CHAT_ID', async () => {
  const axios = require('axios');
  const realPost = axios.post;
  const sent = [];
  axios.post = async (url, body) => { sent.push({ url, chat: body && body.chat_id }); return { data: { ok: true } }; };
  // helpers.js unrefs timers; the notifier's sleep() must still keep the loop alive
  const keepAlive = require('timers').setInterval(() => {}, 1000);
  process.env.TELEGRAM_BOT_TOKEN = '999999:OPERATOR-token';
  process.env.TELEGRAM_CHAT_ID = 'operator-chat';
  try {
    const u = createUser(`tg_${uniq()}`, PW);
    db.updateNotificationSettings({ telegram_chat_id: 'attacker-chat' }, u);
    const r = await dispatch('POST', '/api/notifications/test', { cookies: { tp_access: tokenFor(u) }, body: { type: 'telegram' } });
    assert.strictEqual(r.status, 400, `analyst used the operator bot: ${JSON.stringify(r.body)}`);
    const v = createUser(`tg_${uniq()}`, PW);
    const r2 = await dispatch('POST', '/api/notifications/test', { cookies: { tp_access: tokenFor(v) }, body: { type: 'telegram' } });
    assert.strictEqual(r2.status, 400, 'analyst test message went to the operator chat');
    assert.ok(!sent.some(s => s.url.includes('OPERATOR')), 'operator token used for a non-admin');

    // scheduled alerts: a non-admin's private articles never go out through the operator bot/chat
    db.updateNotificationSettings({ telegram_enabled: 1, severity_threshold: 'low' }, v);
    const src = addSource(v);
    const art = db.getArticleById(addArticle(src, v, 'v private alert'));
    await apiRouter.handleNotifications([art]);
    assert.ok(!sent.some(s => s.url.includes('OPERATOR') || s.chat === 'operator-chat'), JSON.stringify(sent));

    // admins keep the fallback
    sent.length = 0;
    const adm = createUser(`tgadm_${uniq()}`, PW, { role: 'admin' });
    const r3 = await dispatch('POST', '/api/notifications/test', { cookies: { tp_access: tokenFor(adm) }, body: { type: 'telegram' } });
    assert.notStrictEqual(r3.status, 400);
    assert.ok(sent.some(s => s.url.includes('OPERATOR') && s.chat === 'operator-chat'));
  } finally {
    axios.post = realPost;
    require('timers').clearInterval(keepAlive);
    delete process.env.TELEGRAM_BOT_TOKEN; delete process.env.TELEGRAM_CHAT_ID;
  }
});

test('AI: B cannot summarize/triage A\'s article, guest only system articles; threads are private', async () => {
  for (const ep of ['summarize', 'triage']) {
    assert.strictEqual((await call('b', 'POST', `/api/ai/${ep}`, { articleId: data.a.article })).status, 404);
    assert.strictEqual((await call('guest', 'POST', `/api/ai/${ep}`, { articleId: data.a.article })).status, 404);
    assert.strictEqual((await call('guest', 'POST', `/api/ai/${ep}`, { articleId: sysArticle })).status, 503);
    assert.strictEqual((await call('a', 'POST', `/api/ai/${ep}`, { articleId: sysArticle })).status, 404);
    assert.strictEqual((await call('admin', 'POST', `/api/ai/${ep}`, { articleId: data.a.article })).status, 503);
  }
  for (const who of ['b', 'admin', 'guest']) {
    assert.strictEqual((await call(who, 'GET', `/api/ai/threads/${data.a.thread}`)).status, 404, who);
    assert.strictEqual((await call(who, 'DELETE', `/api/ai/threads/${data.a.thread}`)).status, 404, who);
    assert.strictEqual((await call(who, 'POST', '/api/ai/ask', { question: 'q', threadId: data.a.thread })).status, 404, who);
    assert.ok(!JSON.stringify((await call(who, 'GET', '/api/ai/threads')).body).includes('A private thread'), who);
  }
  assert.ok(db.getThread(data.a.thread, ids.a), 'A\'s thread was deleted');
  assert.ok(!db.getThreadMessages(data.a.thread, ids.a, 50).some(m => m.content === 'q'), 'message appended to A\'s thread');

  // guest threads are per browser: another guest visitor (other/no tp_ai_gsid) can't see them
  const other = { cookies: { tp_access: tokenFor(guestId), tp_ai_gsid: 'cd'.repeat(16) } };
  assert.strictEqual((await dispatch('GET', `/api/ai/threads/${data.guestThread}`, other)).status, 404);
  assert.deepStrictEqual((await dispatch('GET', '/api/ai/threads', other)).body.threads, []);
  assert.deepStrictEqual((await dispatch('GET', '/api/ai/threads', { cookies: { tp_access: tokenFor(guestId) } })).body.threads, []);
  assert.strictEqual((await call('guest', 'GET', `/api/ai/threads/${data.guestThread}`)).status, 200);
});

test('verification codes are bound to their user: B cannot redeem A\'s pending code', async () => {
  db.createVerificationCode(ids.a, 'email_change', 'a-new@example.test', '424242', auth.sqliteDateTime(Date.now() + 600000));
  const r = await call('b', 'POST', '/api/auth/verify-change', { type: 'email_change', code: '424242' });
  assert.strictEqual(r.status, 400);
  assert.notStrictEqual(db.getUserById(ids.b).email, 'a-new@example.test');
  assert.notStrictEqual(db.getUserById(ids.a).email, 'a-new@example.test');
});

test('email change needs the current password (a session alone must not be able to move the account)', async () => {
  const u = createUser(`mover_${uniq()}`, PW);
  const creds = { cookies: { tp_access: tokenFor(u) } };
  for (const body of [{ email: 'evil@example.test' }, { email: 'evil@example.test', currentPassword: 'Wrong-Pass-1' }]) {
    const r = await dispatch('PUT', '/api/auth/email', { ...creds, body });
    assert.strictEqual(r.status, 400);
    assert.match(r.body.error, /password/i);
  }
  assert.strictEqual(db.getDb().prepare('SELECT COUNT(*) c FROM verification_codes WHERE user_id = ?').get(u).c, 0);
  const ok = await dispatch('PUT', '/api/auth/email', { ...creds, body: { email: 'mine@example.test', currentPassword: PW } });
  assert.strictEqual(ok.status, 200, JSON.stringify(ok.body));
  // No SMTP in tests: with the right password the change is applied directly
  // (a code could never arrive); with SMTP a code would be sent instead.
  assert.strictEqual(db.getUserById(u).email, 'mine@example.test');
});

test('invite codes, reset tokens, audit log and user list are admin-only', async () => {
  for (const who of ['guest', 'a', 'b']) {
    for (const p of ['/api/admin/invite-codes', '/api/admin/reset-tokens', '/api/admin/audit-log', '/api/admin/users', '/api/admin/ai-settings']) {
      const r = await call(who, 'GET', p);
      assert.strictEqual(r.status, 403, `${who} ${p}`);
      assert.ok(!('codes' in (r.body || {})) && !('tokens' in (r.body || {})));
    }
    const n = db.getValidInviteCodes().length;
    assert.strictEqual((await call(who, 'POST', '/api/admin/invite-codes')).status, 403);
    assert.strictEqual(db.getValidInviteCodes().length, n);
  }
});

test('disabled / deleted users: access and refresh tokens stop working at once', async () => {
  const u = createUser(`soon_off_${uniq()}`, PW);
  const rt = await freshRefreshCookie(db.getUserById(u).username);
  const at = tokenFor(u);
  assert.strictEqual((await dispatch('GET', '/api/auth/me', { cookies: { tp_access: at } })).status, 200);
  assert.strictEqual((await call('admin', 'PUT', `/api/admin/users/${u}`, { is_active: 0 })).status, 200);
  assert.strictEqual((await dispatch('GET', '/api/articles', { cookies: { tp_access: at } })).status, 401);
  assert.strictEqual((await dispatch('POST', '/api/auth/refresh', { cookies: { tp_refresh: rt } })).status, 401);
  const login = await dispatch('POST', '/api/auth/login', { body: { username: db.getUserById(u).username, password: PW }, csrf: false });
  assert.notStrictEqual(login.body.success, true);
  // re-enabled, then deleted
  await call('admin', 'PUT', `/api/admin/users/${u}`, { is_active: 1 });
  const rt2 = await freshRefreshCookie(db.getUserById(u).username);
  assert.strictEqual((await call('admin', 'DELETE', `/api/admin/users/${u}`)).status, 200);
  assert.strictEqual((await dispatch('GET', '/api/auth/me', { cookies: { tp_access: at } })).status, 401);
  assert.strictEqual((await dispatch('POST', '/api/auth/refresh', { cookies: { tp_refresh: rt2 } })).status, 401);
});

test('a demoted admin loses admin rights immediately (role comes from the DB, not the token)', async () => {
  const u = createUser(`demoted_${uniq()}`, PW, { role: 'admin' });
  const at = tokenFor(u); // carries role: 'admin'
  assert.strictEqual((await dispatch('GET', '/api/admin/users', { cookies: { tp_access: at } })).status, 200);
  assert.strictEqual((await call('admin', 'PUT', `/api/admin/users/${u}`, { role: 'analyst' })).status, 200);
  assert.strictEqual((await dispatch('GET', '/api/admin/users', { cookies: { tp_access: at } })).status, 403);
  assert.strictEqual((await dispatch('GET', '/api/articles?limit=200', { cookies: { tp_access: at } })).body.articles
    .some(a => a.title.includes('Private a')), false, 'demoted admin still has the god view');
});

test('guest: shared account cannot change shared state; disabling it switches guest access off', async () => {
  for (const [m, p, body] of [
    ['PUT', '/api/auth/password', { currentPassword: 'x', newPassword: 'Another-Pass-1' }],
    ['PUT', '/api/auth/email', { email: 'g@example.test' }],
    ['POST', '/api/auth/verify-change', { type: 'email_change', code: '000000' }],
    ['POST', '/api/sources', { name: 'g', url: 'https://feeds.example.com/g' }],
    ['PUT', `/api/sources/${sysSource}`, { name: 'g' }],
    ['DELETE', `/api/sources/${sysSource}`],
    ['POST', '/api/fetch-now'],
    ['PUT', '/api/notifications/settings', { email: 'g@example.test' }],
    ['POST', '/api/notifications/test', { type: 'email' }],
  ]) {
    assert.strictEqual((await call('guest', m, p, body)).status, 403, `${m} ${p}`);
  }
  assert.strictEqual(db.getDb().prepare('SELECT name FROM sources WHERE id = ?').get(sysSource).name, 'System Feed');

  assert.strictEqual((await call('admin', 'PUT', `/api/admin/users/${guestId}`, { is_active: 0 })).status, 200);
  try {
    assert.strictEqual((await dispatch('POST', '/api/auth/guest', { csrf: false })).status, 403);
    assert.strictEqual((await call('guest', 'GET', '/api/articles')).status, 401);
  } finally {
    await call('admin', 'PUT', `/api/admin/users/${guestId}`, { is_active: 1 });
  }
});

test('must_change_password: only /auth/me, /auth/password and /auth/logout work, in any path spelling', async () => {
  const creds = { cookies: { tp_access: tokenFor(ids.mustChange) } };
  for (const p of ['/api/auth/me', '/api/AUTH/ME', '/api/auth/me/']) {
    assert.strictEqual((await dispatch('GET', p, creds)).status, 200, p);
  }
  for (const [m, p] of [['GET', '/api/Articles'], ['GET', '/api/articles/'], ['GET', '/API/sources'], ['GET', '/api/ai/threads'],
    ['POST', '/api/ai/ask'], ['PUT', '/api/auth/email'], ['POST', '/api/auth/verify-change']]) {
    const r = await dispatch(m, p, { ...creds, body: { question: 'x' } });
    assert.strictEqual(r.status, 403, `${m} ${p}`);
    assert.strictEqual(r.body.mustChangePassword, true);
  }
  assert.strictEqual((await dispatch('POST', '/api/auth/logout', creds)).status, 200);
});

// ===========================================================================
// Part 3 — admin edge cases, id parsing, method/path confusion
// ===========================================================================
test('admin: cannot demote/disable/delete self, cannot promote guest; can manage other admins', async () => {
  for (const body of [{ role: 'analyst' }, { is_active: 0 }, { is_active: false }]) {
    assert.strictEqual((await call('admin', 'PUT', `/api/admin/users/${ids.admin}`, body)).status, 400);
  }
  assert.strictEqual((await call('admin', 'DELETE', `/api/admin/users/${ids.admin}`)).status, 400);
  assert.strictEqual((await call('admin', 'PUT', `/api/admin/users/${guestId}`, { role: 'admin' })).status, 400);
  const me = db.getUserById(ids.admin);
  assert.strictEqual(me.role, 'admin'); assert.strictEqual(me.is_active, 1);
  assert.strictEqual(db.getUserById(guestId).role, 'analyst');

  // another admin can be demoted and restored (the acting admin always remains)
  assert.strictEqual((await call('admin', 'PUT', `/api/admin/users/${ids.admin2}`, { role: 'analyst' })).status, 200);
  assert.strictEqual((await call('admin', 'PUT', `/api/admin/users/${ids.admin2}`, { role: 'admin' })).status, 200);
  // role escalation via unexpected values / fields is refused
  const t = throwawayUser();
  for (const body of [{ role: 'superadmin' }, { role: ['admin'] }, { must_change_password: 0, password_hash: 'x' }]) {
    const r = await call('admin', 'PUT', `/api/admin/users/${t}`, body);
    assert.strictEqual(r.status, 400, JSON.stringify(body));
  }
  assert.strictEqual(db.getUserById(t).role, 'analyst');
});

test('admin: the last active admin can never be removed', async () => {
  // simulate a lone admin: everybody else with role admin is disabled for the duration
  const others = db.getDb().prepare("SELECT id FROM users WHERE role = 'admin' AND is_active = 1 AND id != ?").all(ids.admin).map(r => r.id);
  for (const id of others) db.updateUser(id, { is_active: 0 });
  try {
    assert.strictEqual((await call('admin', 'DELETE', `/api/admin/users/${ids.admin}`)).status, 400);
    assert.strictEqual((await call('admin', 'PUT', `/api/admin/users/${ids.admin}`, { role: 'analyst' })).status, 400);
    assert.strictEqual(db.getDb().prepare("SELECT COUNT(*) c FROM users WHERE role = 'admin' AND is_active = 1").get().c, 1);
  } finally {
    for (const id of others) db.updateUser(id, { is_active: 1 });
  }
});

test('admin: non-existent ids are 404, malformed ids 400, and nothing else is touched', async () => {
  for (const m of ['PUT', 'DELETE']) {
    const r = await call('admin', m, '/api/admin/users/987654', { display_name: 'Ghost user' });
    assert.strictEqual(r.status, 404, `${m} missing user: ${r.status} ${JSON.stringify(r.body)}`);
    assert.strictEqual(r.body.success, false);
  }
  const victim = throwawayUser();
  for (const raw of [`${victim}abc`, `${victim}.0`, `${victim}e0`, `+${victim}`, `0${victim}`, '-1', '0', '1e3', '0x1', '99999999999999999999', ' ', 'NaN']) {
    for (const m of ['PUT', 'DELETE']) {
      const r = await call('admin', m, `/api/admin/users/${encodeURIComponent(raw)}`, { display_name: 'Changed name' });
      assert.strictEqual(r.status, 400, `${m} /admin/users/${raw}: ${r.status} ${JSON.stringify(r.body)}`);
    }
  }
  const v = db.getUserById(victim);
  assert.ok(v, `parseInt-style id parsing deleted user ${victim}`);
  assert.notStrictEqual(v.display_name, 'Changed name');
});

test('malformed ids never resolve to another record (sources, reviews, AI threads/articles)', async () => {
  const src = addSource(ids.a);
  const art = addArticle(src, ids.a);
  const thread = db.createThread(ids.a, 'mine');
  for (const suffix of ['abc', '.5', 'e0', '%20']) {
    assert.strictEqual((await call('a', 'PUT', `/api/sources/${src}${suffix}`, { name: 'changed' })).status, 404, `PUT source ${suffix}`);
    assert.strictEqual((await call('a', 'DELETE', `/api/sources/${src}${suffix}`)).status, 404, `DELETE source ${suffix}`);
    assert.strictEqual((await call('a', 'POST', `/api/articles/${art}${suffix}/review`)).status, 404, `review ${suffix}`);
    assert.strictEqual((await call('a', 'GET', `/api/ai/threads/${thread}${suffix}`)).status, 404, `thread ${suffix}`);
    assert.strictEqual((await call('a', 'DELETE', `/api/ai/threads/${thread}${suffix}`)).status, 404, `delete thread ${suffix}`);
    assert.strictEqual((await call('a', 'POST', '/api/ai/summarize', { articleId: `${art}${suffix}` })).status, 400, `summarize ${suffix}`);
    assert.strictEqual((await call('a', 'POST', '/api/ai/ask', { question: 'q', threadId: `${thread}${suffix}` })).status, 404, `ask ${suffix}`);
  }
  for (const id of ['-1', '0', '99999999999999999999']) {
    assert.strictEqual((await call('a', 'PUT', `/api/sources/${id}`, { name: 'changed' })).status, 404);
    assert.strictEqual((await call('a', 'POST', `/api/articles/${id}/escalate`)).status, 404);
  }
  assert.strictEqual(db.getDb().prepare('SELECT name FROM sources WHERE id = ?').get(src).name.startsWith('src '), true);
  assert.strictEqual(db.getDb().prepare('SELECT COUNT(*) c FROM article_reviews WHERE article_id = ?').get(art).c, 0);
  assert.ok(db.getThread(thread, ids.a));
});

test('method / route confusion: unregistered methods and look-alike paths do not reach handlers', async () => {
  const victim = throwawayUser();
  for (const [m, p] of [
    ['POST', `/api/admin/users/${victim}`], ['PATCH', `/api/admin/users/${victim}`], ['GET', `/api/admin/users/${victim}`],
    ['POST', `/api/sources/${data.a.source}`], ['GET', `/api/sources/${data.a.source}`], ['PATCH', '/api/notifications/settings'],
    ['POST', '/api/admin/ai-settings'], ['DELETE', '/api/articles'], ['PUT', '/api/ai/threads/1'],
  ]) {
    const r = await call('admin', m, p, { role: 'admin', display_name: 'X' });
    assert.strictEqual(r.status, 404, `${m} ${p}: ${r.status}`);
  }
  assert.ok(db.getUserById(victim));
  // case / trailing-slash variants still hit the same guards
  for (const p of ['/api/ADMIN/users', '/api/admin/users/', '/API/Admin/Users']) {
    assert.strictEqual((await call('a', 'GET', p)).status, 403, p);
    assert.strictEqual((await dispatch('GET', p)).status, 401, p);
  }
  // HEAD on a protected GET route is protected too
  assert.strictEqual((await dispatch('HEAD', '/api/admin/users', as('a'))).status, 403);
  // a case-variant of a CSRF-exempt route is NOT exempt (fails closed)
  assert.strictEqual((await dispatch('POST', '/api/AUTH/LOGIN', { body: { username: 'x', password: 'y' }, csrf: false })).status, 403);
});

test('token tampering: claims in the token never override the database', async () => {
  // payload says admin + another user's name; userId is what counts
  const at = mint({ userId: ids.a, username: 'root_admin', role: 'admin' });
  const me = await dispatch('GET', '/api/auth/me', { cookies: { tp_access: at } });
  assert.strictEqual(me.body.user.id, ids.a);
  assert.strictEqual(me.body.user.role, 'analyst');
  assert.strictEqual(me.body.user.username, 'analyst_a');
  // guest token with role admin is still a guest
  const g = mint({ userId: guestId, username: 'guest', role: 'admin' });
  assert.strictEqual((await dispatch('POST', '/api/sources', { cookies: { tp_access: g }, body: { name: 'x', url: 'https://feeds.example.com/q' } })).status, 403);
  // a payload signed for one user with a modified userId fails the signature
  const [hd, , sig] = tokenFor(ids.a).split('.');
  const swapped = `${hd}.${b64({ userId: ids.admin, exp: Math.floor(Date.now() / 1000) + 600 })}.${sig}`;
  assert.strictEqual((await dispatch('GET', '/api/auth/me', { cookies: { tp_access: swapped } })).status, 401);
  // logout blacklists the access token
  const t = tokenFor(ids.b);
  assert.strictEqual((await dispatch('POST', '/api/auth/logout', { cookies: { tp_access: t } })).status, 200);
  assert.strictEqual((await dispatch('GET', '/api/auth/me', { cookies: { tp_access: t } })).status, 401);
});

test('server.js: middleware order — cookies, CSRF and rate limits run before any router', () => {
  const idx = (pred) => app.stack.findIndex(pred);
  const isUseAt = (mount) => (l) => l.kind === 'use' && l.args[0] === mount;
  const apiRouterIdx = idx(l => l.kind === 'use' && l.args[0] === '/api' && l.args[1] === apiRouter);
  const aiRouterIdx = idx(l => l.kind === 'use' && l.args[0] === '/api/ai' && l.args[1] === aiRouter);
  const cookieIdx = idx(l => l.kind === 'use' && l.args[0] === require(path.join(ROOT, 'src/security')).cookieParser);
  const csrfIdx = idx(l => isUseAt('/api')(l) && l.args[1] !== apiRouter && /csrfMiddleware/.test(String(l.args[1])));
  const authLimitIdx = idx(isUseAt('/api/auth'));
  assert.ok(apiRouterIdx > 0 && aiRouterIdx > 0, 'routers mounted');
  assert.ok(cookieIdx === 0, 'cookie parser first');
  assert.ok(csrfIdx > cookieIdx && csrfIdx < apiRouterIdx && csrfIdx < aiRouterIdx, 'CSRF before routers');
  assert.ok(authLimitIdx > 0 && authLimitIdx < apiRouterIdx, 'auth limiter before routers');
});

test('reset links: an admin never sees another admin account\'s live reset token', async () => {
  const future = new Date(Date.now() + 3600e3).toISOString().replace('T', ' ').slice(0, 19);
  const victim = createUser(`plain_${uniq()}`, PW);
  db.createPasswordResetToken(ids.admin2, 'tok-admin2-' + uniq(), future);
  db.createPasswordResetToken(victim, 'tok-user-' + uniq(), future);
  const r = await call('admin', 'GET', '/api/admin/reset-tokens');
  assert.strictEqual(r.status, 200);
  const byUser = Object.fromEntries(r.body.tokens.map(t => [t.user_id, t]));
  assert.strictEqual(byUser[ids.admin2].token, null);
  assert.strictEqual(byUser[ids.admin2].withheld, 'admin_account');
  assert.match(byUser[victim].token, /^tok-user-/);   // no SMTP: manual recovery for normal users still works
});

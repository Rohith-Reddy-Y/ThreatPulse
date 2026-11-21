'use strict';
// Hostile / malformed input against the api.js routes and the notifiers.
// Runs in the data suite (tests/run.sh): shims for better-sqlite3 (which, like
// the real module, throws when asked to bind an object/array/boolean), axios
// and nodemailer. Every route must answer non-2xx-or-2xx cleanly, never 500.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const axios = require('axios');
const nodemailer = require('nodemailer');
const { load, makeUser, art, call } = require('./data-helpers');

const HUGE = 'A'.repeat(1024 * 1024);
const HOSTILE_VALUES = [
  ['a', 'b'], { x: 1 }, { __proto__: { polluted: 1 } }, 123, true, null,
  HUGE, 'nul\u0000byte', '‮evil‬', '​‍', '😀'.repeat(50), '1e309', '-1', 'NaN',
];

function assertNot500(res, label) {
  assert.notStrictEqual(res.statusCode, 500, `${label} -> 500 ${JSON.stringify(res.body)}`);
}

// ---------------- Query-string type confusion (qs gives arrays/objects) ----------------

test('GET /articles: array/object/odd query values never produce a 500', async () => {
  const env = load();
  const u = makeUser(env.db);
  const admin = makeUser(env.db, { role: 'admin' });
  env.db.insertArticle(art({ user_id: u.id }));
  const fields = ['page', 'limit', 'category', 'severity', 'search', 'source_type', 'start_date', 'end_date',
    'time_range', 'sector', 'threat_actor', 'has_poc', 'has_mitre', 'is_patched'];
  for (const user of [u, admin]) {
    for (const f of fields) {
      for (const v of HOSTILE_VALUES) {
        const res = await call(env, 'GET', '/articles', { user, query: { [f]: v } });
        assertNot500(res, `GET /articles ${f}=${JSON.stringify(v).slice(0, 40)}`);
      }
    }
  }
  // prototype keys used as a time_range shorthand used to hit Object.prototype
  for (const tr of ['constructor', '__proto__', 'toString', 'hasOwnProperty']) {
    const res = await call(env, 'GET', '/articles', { user: u, query: { time_range: tr } });
    assert.strictEqual(res.statusCode, 200, `time_range=${tr} -> ${res.statusCode}`);
  }
});

test('GET /articles: negative / huge page+limit stay clamped (no LIMIT -1 dump)', async () => {
  const env = load();
  const u = makeUser(env.db);
  for (let i = 0; i < 205; i++) env.db.insertArticle(art({ user_id: u.id }));
  for (const [page, limit] of [['-1', '-1'], ['1e309', '1e309'], ['0', '0'], ['NaN', 'Infinity'], ['99999999999', '5']]) {
    const res = await call(env, 'GET', '/articles', { user: u, query: { page, limit } });
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.articles.length <= 200, `page=${page} limit=${limit} returned ${res.body.articles.length}`);
  }
  const s = await call(env, 'GET', '/search', { user: u, query: { q: 'Generic', limit: '-1' } });
  assert.ok(s.body.length <= 200);
});

test('GET /admin/articles + /search: array/object query values never produce a 500', async () => {
  const env = load();
  const admin = makeUser(env.db, { role: 'admin' });
  for (const f of ['page', 'limit', 'category', 'severity', 'search']) {
    for (const v of HOSTILE_VALUES) {
      assertNot500(await call(env, 'GET', '/admin/articles', { user: admin, query: { [f]: v } }), `/admin/articles ${f}`);
    }
  }
  for (const v of HOSTILE_VALUES) {
    assertNot500(await call(env, 'GET', '/search', { user: admin, query: { q: v, limit: v } }), '/search');
  }
});

test('GET /admin/audit-log: limit=-1 does not dump the whole table', async () => {
  const env = load();
  const admin = makeUser(env.db, { role: 'admin' });
  for (let i = 0; i < 520; i++) env.db.logAudit(admin.id, 'x', `row ${i}`, '1.1.1.1');
  for (const limit of ['-1', '-100', '1e309', 'NaN', ['1', '2'], { a: 1 }]) {
    const res = await call(env, 'GET', '/admin/audit-log', { user: admin, query: { limit } });
    assert.strictEqual(res.statusCode, 200);
    assert.ok(res.body.log.length <= 500, `limit=${JSON.stringify(limit)} returned ${res.body.log.length} rows`);
  }
});

// ---------------- Body type confusion on every write route ----------------

test('auth routes: non-string / huge credentials get a clean 4xx or generic failure, never a 500', async () => {
  const env = load();
  const u = makeUser(env.db);
  const routes = [
    ['POST', '/auth/login', ['username', 'password']],
    ['POST', '/auth/register', ['username', 'displayName', 'password', 'inviteCode', 'email']],
    ['POST', '/auth/forgot-password', ['email']],
    ['POST', '/auth/reset-password', ['token', 'newPassword']],
  ];
  for (const [m, p, fields] of routes) {
    for (const f of fields) {
      for (const v of HOSTILE_VALUES) {
        const res = await call(env, m, p, { body: { [f]: v } });
        assertNot500(res, `${m} ${p} ${f}`);
      }
    }
  }
  for (const [m, p, fields] of [['PUT', '/auth/email', ['email']], ['PUT', '/auth/password', ['currentPassword', 'newPassword']]]) {
    for (const f of fields) {
      for (const v of HOSTILE_VALUES) {
        assertNot500(await call(env, m, p, { user: u, body: { [f]: v } }), `${m} ${p} ${f}`);
      }
    }
  }
});

test('POST /auth/verify-change: non-string type/code are a 400, not a 500', async () => {
  const env = load();
  const u = makeUser(env.db);
  for (const body of [{ type: 'email_change', code: ['123456'] }, { type: { a: 1 }, code: '123456' },
    { type: 'email_change', code: { $gt: '' } }, { type: ['password_change'], code: 123456 }, { type: 'email_change', code: true }]) {
    const res = await call(env, 'POST', '/auth/verify-change', { user: u, body });
    assert.strictEqual(res.statusCode, 400, `${JSON.stringify(body)} -> ${res.statusCode}`);
  }
});

test('reviews: hostile notes are stored as bounded plain strings, never a 500', async () => {
  const env = load();
  const u = makeUser(env.db);
  const { id } = env.db.insertArticle(art({ user_id: u.id }));
  for (const v of HOSTILE_VALUES) {
    for (const [m, p] of [['POST', '/articles/:id/review'], ['PUT', '/articles/:id/review'], ['POST', '/articles/:id/escalate']]) {
      assertNot500(await call(env, m, p, { user: u, params: { id: String(id) }, body: { notes: v } }), `${m} ${p}`);
    }
  }
  const notes = env.db.getDb().prepare('SELECT notes FROM article_reviews WHERE article_id = ?').get(id).notes;
  assert.ok(notes === null || notes.length <= 500);
  for (const badId of ['9'.repeat(400), '-1', 'NaN', '1e309', '__proto__']) {
    assertNot500(await call(env, 'POST', '/articles/:id/review', { user: u, params: { id: badId } }), `review id ${badId}`);
  }
});

test('POST /sources: non-string fields / unknown types are a 400 and nothing unbounded is stored', async () => {
  const env = load();
  const u = makeUser(env.db);
  for (const f of ['url', 'name', 'type', 'category']) {
    for (const v of HOSTILE_VALUES) {
      const body = { url: `https://feeds.example.com/${Math.random()}`, name: 'Feed', [f]: v };
      assertNot500(await call(env, 'POST', '/sources', { user: u, body }), `POST /sources ${f}`);
    }
  }
  const rows = env.db.getDb().prepare('SELECT type, category, name FROM sources WHERE user_id = ?').all(u.id);
  for (const r of rows) {
    assert.ok(r.type.length <= 20 && r.category.length <= 30 && r.name.length <= 128, JSON.stringify(r).slice(0, 80));
  }
});

test('sources: a regular user cannot pick the headless-browser / dark-web fetchers', async () => {
  const env = load();
  const u = makeUser(env.db);
  const admin = makeUser(env.db, { role: 'admin' });
  for (const type of ['browser', 'darkweb', 'nonsense', '']) {
    const res = await call(env, 'POST', '/sources', { user: u, body: { url: `https://x.example.com/${type}`, name: 'n', type } });
    if (type === '') { assert.strictEqual(res.statusCode, 201); continue; } // empty -> default 'rss'
    assert.strictEqual(res.statusCode, 400, `user type=${type} -> ${res.statusCode}`);
  }
  const ok = await call(env, 'POST', '/sources', { user: u, body: { url: 'https://x.example.com/rss', name: 'n', type: 'rss' } });
  assert.strictEqual(ok.statusCode, 201);
  const put = await call(env, 'PUT', '/sources/:id', { user: u, params: { id: String(ok.body.id) }, body: { type: 'browser' } });
  assert.strictEqual(put.statusCode, 400);
  assert.strictEqual(env.db.getDb().prepare('SELECT type FROM sources WHERE id = ?').get(ok.body.id).type, 'rss');
  // admins keep the special fetchers
  const a = await call(env, 'POST', '/sources', { user: admin, body: { url: 'https://cf.example.com/feed', name: 'cf', type: 'browser' } });
  assert.strictEqual(a.statusCode, 201);
});

test('PUT /sources/:id: hostile bodies are a 4xx, never a 500, and never store huge values', async () => {
  const env = load();
  const u = makeUser(env.db);
  const { id } = env.db.addSource({ name: 'mine', url: 'https://mine.example.com/rss', user_id: u.id });
  for (const f of ['url', 'name', 'type', 'category', 'enabled', '__proto__', 'constructor', 'user_id', 'id']) {
    for (const v of HOSTILE_VALUES) {
      const res = await call(env, 'PUT', '/sources/:id', { user: u, params: { id: String(id) }, body: { [f]: v } });
      assertNot500(res, `PUT /sources ${f}=${JSON.stringify(v).slice(0, 30)}`);
    }
  }
  // JSON.parse('{"__proto__": ...}') makes an own property; it must not reach the SQL builder
  const body = JSON.parse('{"__proto__": {"user_id": 999}, "name": "renamed"}');
  const res = await call(env, 'PUT', '/sources/:id', { user: u, params: { id: String(id) }, body });
  assert.strictEqual(res.statusCode, 200);
  const row = env.db.getDb().prepare('SELECT * FROM sources WHERE id = ?').get(id);
  assert.strictEqual(row.user_id, u.id);
  assert.ok(row.type.length <= 20 && row.category.length <= 30, 'unbounded type/category stored');
  assert.strictEqual({}.user_id, undefined);
});

test('POST /sources: regular accounts have a bounded source list (admins exempt)', async () => {
  const env = load();
  const u = makeUser(env.db);
  const admin = makeUser(env.db, { role: 'admin' });
  for (let i = 0; i < 100; i++) env.db.addSource({ name: `s${i}`, url: `https://s${i}.example.com/rss`, user_id: u.id });
  const res = await call(env, 'POST', '/sources', { user: u, body: { url: 'https://one-too-many.example.com/rss', name: 'x' } });
  assert.strictEqual(res.statusCode, 400, `101st source -> ${res.statusCode}`);
  for (let i = 0; i < 100; i++) env.db.addSource({ name: `a${i}`, url: `https://a${i}.example.com/rss`, user_id: admin.id });
  const a = await call(env, 'POST', '/sources', { user: admin, body: { url: 'https://admin-more.example.com/rss', name: 'x' } });
  assert.strictEqual(a.statusCode, 201);
});

// ---------------- Notification settings ----------------

test('PUT /notifications/settings: hostile values are a 400, never a 500', async () => {
  const env = load();
  const u = makeUser(env.db);
  const fields = ['email', 'telegram_chat_id', 'telegram_bot_token', 'email_enabled', 'telegram_enabled',
    'teams_webhook', 'teams_enabled', 'whatsapp_number', 'whatsapp_apikey', 'whatsapp_enabled',
    'severity_threshold', 'keywords_filter', 'digest_mode'];
  for (const f of fields) {
    for (const v of HOSTILE_VALUES) {
      const res = await call(env, 'PUT', '/notifications/settings', { user: u, body: { [f]: v } });
      assertNot500(res, `settings ${f}=${JSON.stringify(v).slice(0, 30)}`);
    }
  }
  const s = env.db.getNotificationSettings(u.id) || {};
  for (const [k, v] of Object.entries(s)) {
    if (typeof v === 'string') assert.ok(v.length <= 2048, `${k} stored ${v.length} chars`);
  }
});

test('PUT /notifications/settings: recipient lists, internal webhooks and bad enums are rejected', async () => {
  const env = load();
  const u = makeUser(env.db);
  const bad = [
    { email: 'me@example.com, victim1@example.org' },
    { email: 'me@example.com\r\nBcc: victim@example.org' },
    { email: 'not-an-email' },
    { teams_webhook: 'http://169.254.169.254/latest/meta-data/' },
    { teams_webhook: 'file:///etc/passwd' },
    { severity_threshold: 'bogus' },
    { telegram_bot_token: '123:abc/../../evil?x=' },
    { telegram_chat_id: '1 OR 1=1' },
    { whatsapp_number: '+1 555 0100&apikey=steal' },
    { email_enabled: 'yes' },
  ];
  for (const body of bad) {
    const res = await call(env, 'PUT', '/notifications/settings', { user: u, body });
    assert.strictEqual(res.statusCode, 400, `${JSON.stringify(body)} -> ${res.statusCode}`);
  }
  const s = env.db.getNotificationSettings(u.id) || {};
  assert.ok(!s.email && !s.teams_webhook && s.severity_threshold !== 'bogus');

  // The full form the dashboard sends (with masked secrets) still saves
  const good = {
    email: 'me@example.com', email_enabled: 1, telegram_chat_id: '-100123', telegram_bot_token: '12345678...ABCDEF',
    telegram_enabled: true, teams_webhook: 'https://example.webhook.office.com/webhookb2/abc', teams_enabled: 0,
    whatsapp_number: '+44 7700 900123', whatsapp_apikey: '...123', whatsapp_enabled: false,
    severity_threshold: 'high', keywords_filter: 'ransomware, CVE-2026',
  };
  const ok = await call(env, 'PUT', '/notifications/settings', { user: u, body: good });
  assert.strictEqual(ok.statusCode, 200, JSON.stringify(ok.body));
  const after = env.db.getNotificationSettings(u.id);
  assert.strictEqual(after.email, 'me@example.com');
  assert.strictEqual(after.telegram_enabled, 1);
  assert.strictEqual(after.telegram_bot_token, null, 'masked token must not be stored');
  // empty strings clear a channel
  const clear = await call(env, 'PUT', '/notifications/settings', { user: u, body: { email: '', teams_webhook: '' } });
  assert.strictEqual(clear.statusCode, 200);
});

test('POST /notifications/test is rate-limited per user (no unbounded email/webhook sends)', async () => {
  const env = load();
  const u = makeUser(env.db);
  env.db.updateNotificationSettings({ email: 'a@example.com' }, u.id);
  const codes = [];
  for (let i = 0; i < 15; i++) {
    codes.push((await call(env, 'POST', '/notifications/test', { user: u, body: { type: 'email' } })).statusCode);
  }
  assert.ok(codes.includes(429), `no throttle: ${codes.join(',')}`);
  assert.strictEqual(codes[0], 200);
  // another user is unaffected
  const other = makeUser(env.db);
  env.db.updateNotificationSettings({ email: 'b@example.com' }, other.id);
  assert.strictEqual((await call(env, 'POST', '/notifications/test', { user: other, body: { type: 'email' } })).statusCode, 200);
});

// ---------------- Admin inputs ----------------

test('admin: display names / AI keys are bounded and stripped of control characters', async () => {
  const env = load();
  const admin = makeUser(env.db, { role: 'admin' });
  const u = makeUser(env.db);
  for (const v of HOSTILE_VALUES) {
    assertNot500(await call(env, 'PUT', '/admin/users/:id', { user: admin, params: { id: String(u.id) }, body: { display_name: v, role: v, is_active: v } }), 'admin PUT user');
    assertNot500(await call(env, 'PUT', '/admin/ai-settings', { user: admin, body: { groq_api_key: v, tavily_api_key: v } }), 'ai-settings');
  }
  await call(env, 'PUT', '/admin/users/:id', { user: admin, params: { id: String(u.id) }, body: { display_name: 'Bob\u0000‮ nimda' } });
  assert.strictEqual(env.db.getUserById(u.id).display_name, 'Bob nimda');
  const k = env.db.getSetting('groq_api_key');
  assert.ok(!k || k.length <= 512, `stored a ${k && k.length}-char API key`);
});

test('register: display name control / bidi-override characters are stripped', async () => {
  const env = load();
  // data-helpers' call() has no res.cookie; drive the handler directly
  const route = env.api.routes.find(r => r.method === 'POST' && r.path === '/auth/register');
  const req = { body: { username: 'bidi_user', displayName: 'Ad\u0000min‮gpj.exe', password: 'Passw0rdOK', email: 'bidi@example.com' }, ip: '9.9.9.8' };
  const res = { status() { return this; }, json(b) { this.body = b; return this; }, cookie() {} };
  await route.handlers[0](req, res, () => {});
  assert.strictEqual(res.body.success, true, JSON.stringify(res.body));
  assert.strictEqual(env.db.getUserByUsername('bidi_user').display_name, 'Admingpj.exe');
});

// ---------------- Outbound messages built from user data ----------------

test('verification email escapes the (user-controlled) display name', async () => {
  load();
  const keep = { ...process.env };
  Object.assign(process.env, { SMTP_HOST: 'smtp.example.com', SMTP_USER: 'bot@example.com', SMTP_PASS: 'x' });
  try {
    const email = require(path.join(__dirname, '..', 'src', 'notifications', 'email-notifier.js'));
    nodemailer.sent.length = 0;
    await email.sendVerificationEmail('victim@example.org', '<a href="https://phish.example/">Secure your account</a>', 'email_change', '123456');
    const html = nodemailer.sent.at(-1).html;
    assert.ok(!html.includes('<a href="https://phish.example/">'), 'attacker HTML injected into a platform email');
    assert.ok(html.includes('&lt;a href='));
  } finally {
    for (const k of ['SMTP_HOST', 'SMTP_USER', 'SMTP_PASS']) { if (keep[k] === undefined) delete process.env[k]; else process.env[k] = keep[k]; }
  }
});

test('Teams: an error body from the (user-chosen) webhook is bounded before it reaches the client', async () => {
  load();
  const { sendTeamsAlert } = require(path.join(__dirname, '..', 'src', 'notifications', 'teams-notifier.js'));
  axios.calls.length = 0;
  axios.__handler = () => { const e = new Error('400'); e.response = { data: 'S'.repeat(500000) }; throw e; };
  try {
    const r = await sendTeamsAlert([art()], 'https://8.8.8.8/hook');
    assert.strictEqual(r.success, false);
    assert.ok(r.error.length <= 300, `reflected ${r.error.length} chars of webhook response`);
    const cfg = axios.calls.at(-1).config;
    assert.ok(cfg.maxContentLength > 0 && cfg.maxContentLength <= 1024 * 1024, 'unbounded webhook response size');
    assert.ok(cfg.signal instanceof AbortSignal, 'no overall deadline: a slow-drip webhook holds the request open');
  } finally { axios.__handler = null; }
});

test('password-reset links prefer the configured public URL over the Host header', async () => {
  const env = load();
  const u = makeUser(env.db, { email: 'reset-me@example.com' });
  const keep = { ...process.env };
  delete process.env.BASE_URL;
  Object.assign(process.env, { RENDER_EXTERNAL_URL: 'https://threatpulse.onrender.com', SMTP_HOST: 'smtp.example.com', SMTP_USER: 'bot@example.com', SMTP_PASS: 'x' });
  try {
    nodemailer.sent.length = 0;
    const route = env.api.routes.find(r => r.method === 'POST' && r.path === '/auth/forgot-password');
    const req = { body: { email: u.email }, ip: '9.9.9.9', protocol: 'https', headers: { host: 'evil.example' }, get: () => 'evil.example' };
    const res = { status() { return this; }, json(b) { this.body = b; return this; } };
    await route.handlers[0](req, res, () => {});
    const html = nodemailer.sent.map(m => m.html).join('\n');
    assert.ok(html.includes('https://threatpulse.onrender.com/?reset='), 'reset link not built from RENDER_EXTERNAL_URL');
    assert.ok(!html.includes('evil.example'), 'reset link built from attacker-controlled Host header');
  } finally {
    for (const k of ['RENDER_EXTERNAL_URL', 'SMTP_HOST', 'SMTP_USER', 'SMTP_PASS', 'BASE_URL']) {
      if (keep[k] === undefined) delete process.env[k]; else process.env[k] = keep[k];
    }
  }
});

test('Object.prototype is never polluted by any of the above', () => {
  assert.strictEqual({}.polluted, undefined);
  assert.strictEqual({}.user_id, undefined);
});

'use strict';
const test = require('node:test');
const assert = require('node:assert');
const axios = require('axios');
const { load, makeUser, art, call } = require('./data-helpers');

// ---------------- Reviews / escalation ----------------

test('a user cannot review/escalate another user\'s article', async () => {
  const env = load();
  const owner = makeUser(env.db), other = makeUser(env.db);
  const { id } = env.db.insertArticle(art({ user_id: owner.id }));
  for (const [m, p] of [['POST', '/articles/:id/review'], ['PUT', '/articles/:id/review'], ['POST', '/articles/:id/escalate']]) {
    const res = await call(env, m, p, { user: other, params: { id: String(id) }, body: { notes: 'injected note' } });
    assert.ok(res.statusCode === 403 || res.statusCode === 404, `${m} ${p} -> ${res.statusCode}`);
  }
  // the owner's view must not show another user's review/notes
  const a = env.db.getArticles({ userId: owner.id }).articles[0];
  assert.deepStrictEqual(JSON.parse(a.reviews), []);
});

test('reviewing a non-existent article returns 404 (not a 500 FK error)', async () => {
  const env = load();
  const u = makeUser(env.db);
  const res = await call(env, 'POST', '/articles/:id/review', { user: u, params: { id: '999999' } });
  assert.strictEqual(res.statusCode, 404);
  const res2 = await call(env, 'POST', '/articles/:id/escalate', { user: u, params: { id: 'abc' } });
  assert.strictEqual(res2.statusCode, 404);
});

test('the shared guest account cannot write reviews/escalations', async () => {
  const env = load();
  const owner = makeUser(env.db);
  const guest = makeUser(env.db, { username: 'guest' });
  const { id } = env.db.insertArticle(art({ user_id: owner.id }));
  const res = await call(env, 'POST', '/articles/:id/escalate', { user: guest, params: { id: String(id) }, body: { notes: 'x' } });
  assert.strictEqual(res.statusCode, 403);
});

test('owner and admin can review / complete / escalate', async () => {
  const env = load();
  const owner = makeUser(env.db), admin = makeUser(env.db, { role: 'admin' });
  const { id } = env.db.insertArticle(art({ user_id: owner.id }));
  const p = { id: String(id) };
  assert.strictEqual((await call(env, 'POST', '/articles/:id/review', { user: owner, params: p })).body.success, true);
  assert.strictEqual((await call(env, 'PUT', '/articles/:id/review', { user: owner, params: p, body: { notes: 'done' } })).body.success, true);
  assert.strictEqual((await call(env, 'POST', '/articles/:id/escalate', { user: admin, params: p, body: { notes: 'esc' } })).body.success, true);
  const reviews = JSON.parse(env.db.getArticles({ userId: owner.id }).articles[0].reviews);
  assert.deepStrictEqual(reviews.map(r => r.status).sort(), ['escalated', 'reviewed']);
});

// ---------------- Sources ----------------

test('sources: ownership enforced on update/delete', async () => {
  const env = load();
  const u1 = makeUser(env.db), u2 = makeUser(env.db);
  const { id } = env.db.addSource({ name: 'Mine', url: 'https://mine.example/feed', user_id: u1.id });
  const put = await call(env, 'PUT', '/sources/:id', { user: u2, params: { id: String(id) }, body: { name: 'pwned' } });
  assert.strictEqual(put.statusCode, 403);
  const del = await call(env, 'DELETE', '/sources/:id', { user: u2, params: { id: String(id) } });
  assert.strictEqual(del.statusCode, 403);
  const list = await call(env, 'GET', '/sources', { user: u2 });
  assert.strictEqual(list.body.sources.length, 0);
});

test('sources: duplicate URL per user -> 409, same URL for another user allowed', async () => {
  const env = load();
  const u1 = makeUser(env.db), u2 = makeUser(env.db);
  const body = { name: 'Feed', url: 'https://feed.example/rss' };
  assert.strictEqual((await call(env, 'POST', '/sources', { user: u1, body })).statusCode, 201);
  assert.strictEqual((await call(env, 'POST', '/sources', { user: u1, body })).statusCode, 409);
  assert.strictEqual((await call(env, 'POST', '/sources', { user: u2, body })).statusCode, 201);
});

test('sources: PUT changing url to one the user already has -> 409 (not 500)', async () => {
  const env = load();
  const u = makeUser(env.db);
  env.db.addSource({ name: 'A', url: 'https://a.example/rss', user_id: u.id });
  const { id } = env.db.addSource({ name: 'B', url: 'https://b.example/rss', user_id: u.id });
  const res = await call(env, 'PUT', '/sources/:id', { user: u, params: { id: String(id) }, body: { url: 'https://a.example/rss' } });
  assert.strictEqual(res.statusCode, 409);
});

test('sources: PUT validates url even when it is an empty string', async () => {
  const env = load();
  const u = makeUser(env.db);
  const { id } = env.db.addSource({ name: 'A', url: 'https://a.example/rss', user_id: u.id });
  const res = await call(env, 'PUT', '/sources/:id', { user: u, params: { id: String(id) }, body: { url: '' } });
  assert.strictEqual(res.statusCode, 400);
  assert.strictEqual(env.db.getDb().prepare('SELECT url FROM sources WHERE id = ?').get(id).url, 'https://a.example/rss');
});

test('sources: PUT with JSON boolean enabled works (better-sqlite3 cannot bind booleans)', async () => {
  const env = load();
  const u = makeUser(env.db);
  const { id } = env.db.addSource({ name: 'A', url: 'https://a.example/rss', user_id: u.id });
  const res = await call(env, 'PUT', '/sources/:id', { user: u, params: { id: String(id) }, body: { enabled: false } });
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(env.db.getDb().prepare('SELECT enabled FROM sources WHERE id = ?').get(id).enabled, 0);
});

test('sources: invalid / private URLs rejected on create', async () => {
  const env = load();
  const u = makeUser(env.db);
  for (const url of ['javascript:alert(1)', 'http://127.0.0.1/feed', 'http://169.254.169.254/latest']) {
    const res = await call(env, 'POST', '/sources', { user: u, body: { name: 'x', url } });
    assert.strictEqual(res.statusCode, 400, url);
  }
});

// ---------------- Notification settings ----------------

test('notification settings are per-user and secrets are masked', async () => {
  const env = load();
  const u1 = makeUser(env.db, { email: 'u1@example.com' }), u2 = makeUser(env.db);
  await call(env, 'PUT', '/notifications/settings', { user: u1, body: { email: 'u1@example.com', telegram_bot_token: '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ', email_enabled: 1 } });
  const s2 = await call(env, 'GET', '/notifications/settings', { user: u2 });
  assert.strictEqual(s2.body.email, undefined);
  const s1 = await call(env, 'GET', '/notifications/settings', { user: u1 });
  assert.strictEqual(s1.body.email, 'u1@example.com');
  assert.ok(s1.body.telegram_bot_token.includes('...'));
  // saving the masked token back must not overwrite the real one
  await call(env, 'PUT', '/notifications/settings', { user: u1, body: { telegram_bot_token: s1.body.telegram_bot_token } });
  assert.strictEqual(env.db.getNotificationSettings(u1.id).telegram_bot_token, '123456789:ABCDEFGHIJKLMNOPQRSTUVWXYZ');
});

test('notification settings accept JSON booleans for *_enabled', async () => {
  const env = load();
  const u = makeUser(env.db, { email: 'a@example.com' });
  const res = await call(env, 'PUT', '/notifications/settings', { user: u, body: { email: 'a@example.com', email_enabled: true, telegram_enabled: false } });
  assert.strictEqual(res.statusCode, 200);
  assert.strictEqual(env.db.getNotificationSettings(u.id).email_enabled, 1);
});

test('notification test: no SMTP / Telegram configured -> clean error, no throw', async () => {
  const env = load();
  const u = makeUser(env.db, { email: 'a@example.com' });
  env.db.createUserNotificationSettings(u.id);
  env.db.updateNotificationSettings({ email: 'a@example.com' }, u.id);
  const e = await call(env, 'POST', '/notifications/test', { user: u, body: { type: 'email' } });
  assert.strictEqual(e.statusCode, 200);
  assert.strictEqual(e.body.success, false);
  const t = await call(env, 'POST', '/notifications/test', { user: u, body: { type: 'telegram' } });
  assert.strictEqual(t.statusCode, 400);
  const none = await call(env, 'POST', '/notifications/test', { user: makeUser(env.db), body: { type: 'email' } });
  assert.strictEqual(none.statusCode, 400);
});

test('notification test: Teams webhook pointing at an internal address is not requested (SSRF)', async () => {
  const env = load();
  const u = makeUser(env.db, { email: 'a@example.com' });
  env.db.updateNotificationSettings({ teams_webhook: 'http://169.254.169.254/latest/meta-data/' }, u.id);
  axios.calls.length = 0;
  const res = await call(env, 'POST', '/notifications/test', { user: u, body: { type: 'teams' } });
  assert.strictEqual(axios.calls.length, 0, 'server made a request to an internal address');
  assert.strictEqual(res.body.success, false);
});

test('notification test: Telegram reports failure when every message failed', async () => {
  const env = load();
  const u = makeUser(env.db);
  env.db.updateNotificationSettings({ telegram_bot_token: 'bad-token', telegram_chat_id: '1' }, u.id);
  axios.__handler = () => { const e = new Error('401'); e.response = { data: { description: 'Unauthorized' } }; throw e; };
  try {
    const res = await call(env, 'POST', '/notifications/test', { user: u, body: { type: 'telegram' } });
    assert.strictEqual(res.body.success, false, 'frontend shows "Test sent" for a broken bot token');
  } finally { axios.__handler = null; }
});

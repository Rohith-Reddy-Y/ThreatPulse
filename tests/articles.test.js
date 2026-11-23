'use strict';
const test = require('node:test');
const assert = require('node:assert');
const { load, makeUser, art, call } = require('./data-helpers');

test('insertArticle rejects non-http(s) URLs and skips known urls', () => {
  const { db } = load();
  assert.strictEqual(db.insertArticle(art({ url: 'javascript:alert(1)' })).success, false);
  const a = art();
  assert.strictEqual(db.insertArticle({ ...a }).isNew, true);
  assert.strictEqual(db.insertArticle({ ...a }).isNew, false);
});

test('same story from two sources of one user is deduped; other users unaffected', () => {
  const { db } = load();
  const u1 = makeUser(db), u2 = makeUser(db);
  const title = 'Critical flaw in Example Router firmware exploited in the wild';
  assert.strictEqual(db.insertArticle(art({ title, user_id: u1.id })).isNew, true);
  assert.strictEqual(db.insertArticle(art({ title: title + ' - BleepingComputer', user_id: u1.id })).isNew, false);
  assert.strictEqual(db.insertArticle(art({ title, user_id: u2.id })).isNew, true);
});

test('two users subscribed to the same feed URL both receive the article', () => {
  const { db } = load();
  const u1 = makeUser(db), u2 = makeUser(db);
  const url = 'https://feeds.example.com/story-1';
  assert.strictEqual(db.insertArticle(art({ url, user_id: u1.id })).isNew, true);
  const r2 = db.insertArticle(art({ url, user_id: u2.id }));
  assert.strictEqual(r2.isNew, true, 'user 2 never gets articles already stored for user 1');
  assert.strictEqual(db.getArticles({ userId: u2.id }).total, 1);
  // but the same user re-reading the feed is still deduped
  assert.strictEqual(db.insertArticle(art({ url, user_id: u2.id })).isNew, false);
});

test('legacy rows stored with the plain url hash are still deduped for their owner', () => {
  const { db } = load();
  const u1 = makeUser(db);
  const url = 'https://feeds.example.com/legacy';
  db.getDb().prepare("INSERT INTO articles (url_hash, title, url, user_id) VALUES (?, 'legacy', ?, ?)").run(db.hashUrl(url), url, u1.id);
  assert.strictEqual(db.insertArticle(art({ url, user_id: u1.id })).isNew, false);
});

test('normalizeDate: RFC-822 and zone-less ISO become ISO UTC; future dates are clamped to now', () => {
  const { db } = load();
  const a = art({ published_date: 'Fri, 20 Nov 2026 10:00:00 GMT' });
  db.insertArticle(a);
  assert.strictEqual(a.published_date, '2026-11-20T10:00:00.000Z');
  const b = art({ published_date: '2026-11-20T15:15:10.123' });
  db.insertArticle(b);
  assert.strictEqual(b.published_date, '2026-11-20T15:15:10.123Z');
  // A feed that labels local time as GMT puts items hours in the future; those
  // used to be stored as-is (up to +24h), landing on "tomorrow" and missing
  // from "threats today" while pinned to the top of the feed.
  const before = Date.now();
  const c = art({ published_date: new Date(Date.now() + 12 * 3600 * 1000).toISOString() });
  db.insertArticle(c);
  assert.ok(new Date(c.published_date).getTime() <= Date.now(), 'future date stored');
  assert.ok(new Date(c.published_date).getTime() >= before - 1000);
});

test('getArticles is user-scoped', () => {
  const { db } = load();
  const u1 = makeUser(db), u2 = makeUser(db);
  db.insertArticle(art({ user_id: u1.id }));
  db.insertArticle(art({ user_id: u2.id }));
  db.insertArticle(art({ user_id: u2.id }));
  assert.strictEqual(db.getArticles({ userId: u1.id }).total, 1);
  assert.strictEqual(db.getArticles({ userId: u2.id }).total, 2);
  assert.strictEqual(db.getArticles({}).total, 3);
});

test('getArticles: negative / zero / huge limit and page are clamped', () => {
  const { db } = load();
  for (let i = 0; i < 5; i++) db.insertArticle(art());
  const neg = db.getArticles({ limit: -1 });
  assert.ok(neg.articles.length <= 200 && neg.articles.length >= 1);
  assert.ok(neg.totalPages >= 1, `totalPages ${neg.totalPages}`);
  const r = db.getArticles({ limit: 2, page: -3 });
  assert.strictEqual(r.page, 1);
  assert.strictEqual(r.articles.length, 2);
  const huge = db.getArticles({ limit: 1e9 });
  assert.ok(huge.articles.length <= 200);
  const bigPage = db.getArticles({ limit: 50, page: 1e20 });
  assert.strictEqual(bigPage.articles.length, 0);
});

test('GET /articles?limit=-1 does not return an unbounded result', async () => {
  const env = load();
  const u = makeUser(env.db);
  for (let i = 0; i < 205; i++) env.db.insertArticle(art({ user_id: u.id }));
  const res = await call(env, 'GET', '/articles', { user: u, query: { limit: '-1' } });
  assert.strictEqual(res.statusCode, 200);
  assert.ok(res.body.articles.length <= 200, `returned ${res.body.articles.length}`);
});

test('GET /search?limit=-1 does not return an unbounded result', async () => {
  const env = load();
  const u = makeUser(env.db);
  for (let i = 0; i < 205; i++) env.db.insertArticle(art({ user_id: u.id, title: `ransomware item ${i} long enough title` }));
  const res = await call(env, 'GET', '/search', { user: u, query: { q: 'ransomware', limit: '-1' } });
  assert.ok(res.body.length <= 200, `returned ${res.body.length}`);
});

test('search treats % and _ literally (LIKE wildcards escaped)', async () => {
  const env = load();
  const { db } = env;
  const u = makeUser(db);
  db.insertArticle(art({ user_id: u.id, title: 'Patch now: 100% of servers affected by bug' }));
  db.insertArticle(art({ user_id: u.id, title: 'Unrelated story about a vendor update' }));
  db.insertArticle(art({ user_id: u.id, title: 'Variable FOO_BAR leaked in build logs' }));
  db.insertArticle(art({ user_id: u.id, title: 'FOOXBAR is a different thing entirely' }));
  assert.strictEqual(db.getArticles({ userId: u.id, search: '%' }).total, 1);
  assert.strictEqual(db.getArticles({ userId: u.id, search: 'FOO_BAR' }).total, 1);
  assert.strictEqual(db.searchArticles('%', 50, u.id).length, 1);
  assert.strictEqual(db.searchArticles('FOO_BAR', 50, u.id).length, 1);
  assert.strictEqual(db.getArticles({ userId: u.id, threat_actor: '%' }).total, 0);
  // special chars / quotes don't break SQL
  assert.strictEqual(db.getArticles({ userId: u.id, search: "'; DROP TABLE articles; --" }).total, 0);
  assert.strictEqual(db.searchArticles('\\', 50, u.id).length, 0);
  // whitespace-only query returns nothing rather than everything
  const res = await call(env, 'GET', '/search', { user: u, query: { q: '   ' } });
  assert.deepStrictEqual(res.body, []);
});

test('search is user-scoped', () => {
  const { db } = load();
  const u1 = makeUser(db), u2 = makeUser(db);
  db.insertArticle(art({ user_id: u1.id, title: 'LockBit hits hospital network systems' }));
  assert.strictEqual(db.searchArticles('LockBit', 50, u2.id).length, 0);
  assert.strictEqual(db.searchArticles('LockBit', 50, u1.id).length, 1);
});

test('stats: today / yesterday / timeline use UTC ISO dates and are user-scoped', () => {
  const { db } = load();
  const u1 = makeUser(db), u2 = makeUser(db);
  const now = new Date();
  const yest = new Date(now.getTime() - 24 * 3600 * 1000);
  db.insertArticle(art({ user_id: u1.id, published_date: now.toUTCString() }));
  db.insertArticle(art({ user_id: u1.id, published_date: yest.toISOString() }));
  db.insertArticle(art({ user_id: u2.id }));
  const s = db.getArticleStats(u1.id);
  assert.strictEqual(s.threatsToday, 1);
  assert.strictEqual(s.threatsYesterday, 1);
  assert.strictEqual(s.totalArticles, 2);
  const today = now.toISOString().slice(0, 10);
  assert.strictEqual(s.timeline.find(t => t.day === today).count, 1);
  assert.strictEqual(db.getArticleStats().totalArticles, 3);
});

test('stats: criticalVulns counts distinct CVEs + critical vuln/advisory items only', () => {
  const { db } = load();
  const u = makeUser(db);
  db.insertArticle(art({ user_id: u.id, severity: 'critical', cve_id: 'CVE-2026-1111', category: 'news', title: 'Story one about CVE-2026-1111 long title' }));
  db.insertArticle(art({ user_id: u.id, severity: 'critical', cve_id: 'CVE-2026-1111', category: 'vulnerability', title: 'Story two about CVE-2026-1111 other angle' }));
  db.insertArticle(art({ user_id: u.id, severity: 'critical', category: 'advisory' }));
  db.insertArticle(art({ user_id: u.id, severity: 'critical', category: 'news' }));
  db.insertArticle(art({ user_id: u.id, severity: 'high', category: 'vulnerability' }));
  assert.strictEqual(db.getArticleStats(u.id).criticalVulns, 2);
});

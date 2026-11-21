'use strict';
// The shared anonymous 'guest' account may only see built-in (system) content:
// system sources and their articles — never another user's private sources
// (feed URLs), their articles, review notes or names. Admins see everything,
// regular users only their own rows.
const test = require('node:test');
const assert = require('node:assert');
const { load, makeUser, art, call, tmpDbPath } = require('./data-helpers');

const PRIVATE_FEED = 'https://private-intel.example/secret-feed.xml';

// Build a DB with: an admin, a regular user (alice) with a private source +
// article + review note, the admin's own private source + article, and system
// sources (RSS + API + dark-web style) with articles — stored the way
// seedDefaultSources and the fetchers store them (added_by 'system', the
// article carries the source's id and user_id).
function seed(env) {
  const { db } = env;
  const admin = makeUser(db, { username: 'admin', role: 'admin' });
  const alice = makeUser(db, { username: 'alice' });
  const guest = makeUser(db, { username: 'guest' });

  const sys = {};
  for (const [key, src] of Object.entries({
    rss: { name: 'Sys RSS', url: 'https://sys.example/rss', type: 'rss', category: 'news' },
    nvd: { name: 'NVD', url: 'https://services.nvd.nist.gov/rest/json/cves/2.0', type: 'api', category: 'vulnerability' },
    ransom: { name: 'RansomWatch', url: 'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json', type: 'darkweb', category: 'darkweb' },
  })) {
    sys[key] = db.addSource({ ...src, added_by: 'system' }).id;
  }
  const srcRow = (id) => db.getDb().prepare('SELECT * FROM sources WHERE id = ?').get(id);
  const sysArticles = {};
  for (const key of Object.keys(sys)) {
    const s = srcRow(sys[key]);
    sysArticles[key] = db.insertArticle(art({
      title: `System article ${key} zebracorn`, source_id: s.id, user_id: s.user_id || null,
      source_name: s.name, source_type: s.type,
    })).id;
  }

  const aliceSrc = db.addSource({ name: 'Alice Private', url: PRIVATE_FEED, added_by: 'user', user_id: alice.id }).id;
  const aliceArt = db.insertArticle(art({
    title: 'Alice private zebracorn article', source_id: aliceSrc, user_id: alice.id, source_name: 'Alice Private',
  })).id;
  db.escalateArticle(aliceArt, alice.id, 'alice secret review note');

  const adminSrc = db.addSource({ name: 'Admin Private', url: 'https://admin-only.example/feed', added_by: 'user', user_id: admin.id }).id;
  const adminArt = db.insertArticle(art({
    title: 'Admin private zebracorn article', source_id: adminSrc, user_id: admin.id, source_name: 'Admin Private',
  })).id;

  // An admin review note on a system article must not reach guests either.
  db.escalateArticle(sysArticles.rss, admin.id, 'admin note on system article');

  return { admin, alice, guest, sys, sysArticles, aliceSrc, aliceArt, adminSrc, adminArt };
}

async function guestView(env, guest) {
  const articles = (await call(env, 'GET', '/articles', { user: guest, query: { limit: '200' } })).body;
  const sources = (await call(env, 'GET', '/sources', { user: guest })).body.sources;
  const search = (await call(env, 'GET', '/search', { user: guest, query: { q: 'zebracorn' } })).body;
  const stats = (await call(env, 'GET', '/articles/stats', { user: guest })).body;
  return { articles, sources, search, stats };
}

function assertGuestSeesOnlySystem(env, s, v) {
  const ids = v.articles.articles.map(a => a.id).sort();
  assert.deepStrictEqual(ids, Object.values(s.sysArticles).sort(), 'guest article list = system articles only');
  assert.strictEqual(v.articles.total, 3);

  const json = JSON.stringify(v);
  for (const leak of [PRIVATE_FEED, 'Alice Private', 'alice secret review note', 'admin note on system article',
    'Admin Private', 'admin-only.example', 'ALICE', 'ADMIN']) {
    assert.ok(!json.includes(leak), `guest response leaks "${leak}"`);
  }

  // Same response shapes; reviews/owner/ownership redacted.
  for (const a of v.articles.articles) {
    assert.ok('owner_name' in a && 'reviews' in a && 'user_id' in a);
    assert.strictEqual(a.owner_name, null);
    assert.strictEqual(a.user_id, null);
    assert.deepStrictEqual(JSON.parse(a.reviews), []);
  }

  assert.deepStrictEqual(v.sources.map(x => x.id).sort(), Object.values(s.sys).sort(), 'guest sources = system sources');
  assert.ok(v.sources.every(x => x.added_by === 'system' && 'url' in x && 'user_id' in x));

  assert.deepStrictEqual(v.search.map(a => a.id).sort(), Object.values(s.sysArticles).sort(), 'guest search = system only');

  assert.strictEqual(v.stats.totalArticles, 3);
  assert.strictEqual(v.stats.threatsToday, 3);
  assert.strictEqual(v.stats.timeline.reduce((n, d) => n + d.count, 0), 3);
}

function markFetched(env, s) {
  const now = new Date().toISOString();
  for (const id of Object.values(s.sys)) env.db.updateSourceFetchStatus(id, { last_fetched: now });
  env.db.updateSourceFetchStatus(s.aliceSrc, { last_fetched: now });
  env.db.updateSourceFetchStatus(s.adminSrc, { last_fetched: now, last_error: 'boom' });
}

test('guest sees only system sources/articles on a fresh DB (system rows have user_id NULL)', async () => {
  const env = load();
  const s = seed(env);
  markFetched(env, s);
  const row = env.db.getDb().prepare('SELECT user_id FROM articles WHERE id = ?').get(s.sysArticles.nvd);
  assert.strictEqual(row.user_id, null, 'precondition: fresh DB system article is unowned');

  const v = await guestView(env, s.guest);
  assertGuestSeesOnlySystem(env, s, v);
  assert.strictEqual(v.stats.activeSources, 3, 'Sources Active counts system sources only');
  assert.strictEqual(v.stats.erroredSources, 0, 'errored count excludes private sources');
});

test('guest still sees only system content after the orphan -> admin migration (restart)', async () => {
  const p = tmpDbPath();
  let env = load(p);
  const s = seed(env);
  markFetched(env, s);
  env = load(p); // restart: initializeSchema reassigns system rows to the admin

  const d = env.db.getDb();
  assert.strictEqual(d.prepare('SELECT user_id FROM sources WHERE id = ?').get(s.sys.rss).user_id, s.admin.id,
    'precondition: migration assigned system sources to admin');
  assert.strictEqual(d.prepare('SELECT user_id FROM articles WHERE id = ?').get(s.sysArticles.ransom).user_id, s.admin.id,
    'precondition: migration assigned system articles to admin');

  // Articles fetched after the restart carry the (now admin-owned) system source's user_id.
  const nvd = d.prepare('SELECT * FROM sources WHERE id = ?').get(s.sys.nvd);
  const late = env.db.insertArticle(art({ title: 'CVE-2026-0001 zebracorn', source_id: nvd.id, user_id: nvd.user_id, source_type: 'api' })).id;

  const v = await guestView(env, s.guest);
  assert.strictEqual(v.articles.total, 4);
  assert.deepStrictEqual(v.articles.articles.map(a => a.id).sort(), [...Object.values(s.sysArticles), late].sort(),
    'admin/alice private articles hidden even though admin rows share user_id with system rows');
  const json = JSON.stringify(v);
  for (const leak of [PRIVATE_FEED, 'alice secret review note', 'admin note on system article', 'Admin Private', 'ADMIN']) {
    assert.ok(!json.includes(leak), `guest response leaks "${leak}"`);
  }
  assert.ok(v.articles.articles.every(a => a.owner_name === null && a.user_id === null && a.reviews === '[]'));
  assert.deepStrictEqual(v.sources.map(x => x.id).sort(), Object.values(s.sys).sort());
  assert.ok(v.sources.every(x => x.user_id === null));
  assert.strictEqual(v.search.length, 4);
  assert.strictEqual(v.stats.totalArticles, 4);
  assert.strictEqual(v.stats.activeSources, 3);
  assert.strictEqual(v.stats.erroredSources, 0);
});

test('admin sees everything; a regular user sees only their own', async () => {
  const env = load();
  const s = seed(env);
  markFetched(env, s);

  const adm = (await call(env, 'GET', '/articles', { user: s.admin, query: { limit: '200' } })).body;
  assert.strictEqual(adm.total, 5);
  const aliceRow = adm.articles.find(a => a.id === s.aliceArt);
  assert.strictEqual(aliceRow.owner_name, 'ALICE');
  assert.match(aliceRow.reviews, /alice secret review note/);
  assert.strictEqual((await call(env, 'GET', '/sources', { user: s.admin })).body.sources.length, 5);
  assert.strictEqual((await call(env, 'GET', '/search', { user: s.admin, query: { q: 'zebracorn' } })).body.length, 5);
  const admStats = (await call(env, 'GET', '/articles/stats', { user: s.admin })).body;
  assert.strictEqual(admStats.totalArticles, 5);
  assert.strictEqual(admStats.activeSources, 4);
  assert.strictEqual(admStats.erroredSources, 1);

  const own = (await call(env, 'GET', '/articles', { user: s.alice })).body;
  assert.deepStrictEqual(own.articles.map(a => a.id), [s.aliceArt]);
  const ownSrc = (await call(env, 'GET', '/sources', { user: s.alice })).body.sources;
  assert.deepStrictEqual(ownSrc.map(x => x.id), [s.aliceSrc]);
  assert.strictEqual(ownSrc[0].url, PRIVATE_FEED);
  const ownSearch = (await call(env, 'GET', '/search', { user: s.alice, query: { q: 'zebracorn' } })).body;
  assert.deepStrictEqual(ownSearch.map(a => a.id), [s.aliceArt]);
  const ownStats = (await call(env, 'GET', '/articles/stats', { user: s.alice })).body;
  assert.strictEqual(ownStats.totalArticles, 1);
  assert.strictEqual(ownStats.activeSources, 1);
});

test('guest article filters (search/category) stay inside the system scope', async () => {
  const env = load();
  const s = seed(env);
  const r = (await call(env, 'GET', '/articles', { user: s.guest, query: { search: 'Alice private' } })).body;
  assert.strictEqual(r.total, 0);
  assert.deepStrictEqual(r.articles, []);
});

test('db: isSystemArticle and RAG retrieval honour the system scope', async () => {
  const p = tmpDbPath();
  let env = load(p);
  const s = seed(env);
  env = load(p); // migrated
  const { db } = env;
  assert.strictEqual(db.isSystemArticle(db.getArticleById(s.sysArticles.rss)), true);
  assert.strictEqual(db.isSystemArticle(db.getArticleById(s.adminArt)), false);
  assert.strictEqual(db.isSystemArticle(db.getArticleById(s.aliceArt)), false);
  const rag = db.searchArticlesRag('zebracorn article', 20, db.SYSTEM_SCOPE).map(a => a.id).sort();
  assert.deepStrictEqual(rag, Object.values(s.sysArticles).sort());
  assert.strictEqual(db.searchArticlesRag('zebracorn article', 20, null).length, 5);
});

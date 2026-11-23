/**
 * /api/geo is scoped like the feed (each user sees only countries from their
 * own articles), and /api/admin/source-catalog shows each feed once with every
 * contributor.  Run with: sh tests/run-all.sh
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const h = require('./helpers');
const { db, request, createUser } = h;

const PW = 'Passw0rdA';
let n = 0;
const ip = () => `192.0.2.${++n}`;

function article(userId, sourceId, title, extra = {}) {
  const r = db.insertArticle({ url: `https://news.example/${userId}/${++n}`, title, description: extra.description || '', user_id: userId,
    source_id: sourceId, published_date: new Date().toISOString(), severity: extra.severity || 'high', threat_actors: extra.actors || '' });
  assert.ok(r.success && r.isNew, JSON.stringify(r));
}

test('geo: every user maps only their own articles', async () => {
  const a = createUser('geo_alice', PW), b = createUser('geo_bob', PW);
  const sa = db.addSource({ name: 'A feed', url: 'https://feeds.example/a', user_id: a }).id;
  const sb = db.addSource({ name: 'B feed', url: 'https://feeds.example/b', user_id: b }).id;
  article(a, sa, 'Russian APT28 phishing wave hits German ministries', { actors: 'APT28', severity: 'critical' });
  article(a, sa, 'German utility breached');
  article(b, sb, 'Japanese automaker hit by ransomware');

  const ja = await h.login('geo_alice', PW, ip());
  const ra = await request('GET', '/api/geo?days=7', { cookies: ja });
  assert.strictEqual(ra.status, 200, JSON.stringify(ra.body));
  const codesA = ra.body.countries.map((c) => c.code).sort();
  assert.deepStrictEqual(codesA, ['DE', 'RU']);
  assert.strictEqual(ra.body.countries.find((c) => c.code === 'DE').count, 2);
  assert.deepStrictEqual(ra.body.arcs.map((x) => `${x.from}>${x.to}`), ['RU>DE']);
  assert.ok(!JSON.stringify(ra.body).includes('Japanese'), "another user's headline leaked");

  const jb = await h.login('geo_bob', PW, ip());
  const rb = await request('GET', '/api/geo', { cookies: jb });
  assert.deepStrictEqual(rb.body.countries.map((c) => c.code), ['JP']);
  assert.ok(!JSON.stringify(rb.body).includes('German'));

  assert.strictEqual((await request('GET', '/api/geo')).status, 401, 'signed-out callers get nothing');
});

test('admin source catalog: one row per feed, built-in matches folded, contributor labels', async () => {
  const admin = createUser('cat_admin', PW, { role: 'admin' });
  const u1 = createUser('cat_user1', PW), u2 = createUser('cat_user2', PW);
  db.addSource({ name: 'Built-in Krebs', url: 'https://krebsonsecurity.com/feed/', added_by: 'system', user_id: admin });
  db.addSource({ name: 'krebs', url: 'http://www.krebsonsecurity.com/feed', user_id: u1 });
  db.addSource({ name: 'Brand new blog', url: 'https://brand-new.example/rss', user_id: u1 });
  db.addSource({ name: 'same new blog', url: 'https://www.brand-new.example/rss/?utm_source=x', user_id: u2 });

  const jar = await h.login('cat_admin', PW, ip());
  const r = await request('GET', '/api/admin/source-catalog', { cookies: jar });
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  const krebs = r.body.entries.filter((e) => e.key === 'krebsonsecurity.com/feed');
  assert.strictEqual(krebs.length, 1, 'built-in + user copy shown once');
  assert.strictEqual(krebs[0].builtIn, true);
  assert.deepStrictEqual(krebs[0].contributors.map((c) => c.username), ['cat_user1']);
  const fresh = r.body.entries.filter((e) => e.key === 'brand-new.example/rss');
  assert.strictEqual(fresh.length, 1, 'two users, one feed');
  assert.strictEqual(fresh[0].userSubmitted, true);
  assert.strictEqual(fresh[0].isNew, true);
  assert.deepStrictEqual(fresh[0].contributors.map((c) => c.username).sort(), ['cat_user1', 'cat_user2']);

  const plain = await h.login('cat_user1', PW, ip());
  assert.strictEqual((await request('GET', '/api/admin/source-catalog', { cookies: plain })).status, 403);
});

test('landscape: per-user scope, and the feed search finds ATT&CK IDs and sectors', async () => {
  const a = createUser('ls_alice', PW), b = createUser('ls_bob', PW);
  const sa = db.addSource({ name: 'A2', url: 'https://feeds.example/a2', user_id: a }).id;
  const sb = db.addSource({ name: 'B2', url: 'https://feeds.example/b2', user_id: b }).id;
  article(a, sa, 'Volt Typhoon password spraying against utilities', { actors: 'Volt Typhoon' });
  article(b, sb, 'Ransomware attack encrypts hospital systems', { actors: 'LockBit' });

  const ja = await h.login('ls_alice', PW, ip());
  const ra = await request('GET', '/api/landscape?days=7', { cookies: ja });
  assert.strictEqual(ra.status, 200, JSON.stringify(ra.body));
  assert.deepStrictEqual(ra.body.actors.map((x) => x.name), ['Volt Typhoon']);
  const techA = ra.body.attack.tactics.flatMap((t) => t.techniques).map((t) => t.id);
  assert.ok(techA.includes('T1110') && !techA.includes('T1486'), techA.join(','));
  assert.ok(!JSON.stringify(ra.body).includes('hospital'), "another user's report leaked");

  // search now covers mitre_ids
  const id = db.insertArticle({ url: 'https://news.example/ttp', title: 'Generic advisory', description: 'nothing', user_id: a, source_id: sa,
    published_date: new Date().toISOString(), mitre_ids: 'T1059.001', sector: 'financial' });
  assert.ok(id.success);
  const found = db.getArticles({ userId: a, search: 'T1059' });
  assert.ok(found.articles.some((x) => x.title === 'Generic advisory'), 'search by technique ID');
  assert.ok(db.getArticles({ userId: a, search: 'financial' }).articles.some((x) => x.title === 'Generic advisory'), 'search by sector');
});

test('articles API returns TTPs per report', async () => {
  const u = createUser('ttp_user', PW);
  const src = db.addSource({ name: 'T', url: 'https://feeds.example/ttp', user_id: u }).id;
  article(u, src, 'Infostealer campaign uses fake CAPTCHA lures', { description: 'Victims are shown a fake CAPTCHA that runs PowerShell.' });
  const jar = await h.login('ttp_user', PW, ip());
  const r = await request('GET', '/api/articles', { cookies: jar });
  assert.strictEqual(r.status, 200);
  const a = r.body.articles.find((x) => /Infostealer/.test(x.title));
  const ids = a.ttps.map((t) => t.id);
  assert.ok(ids.includes('T1555') && ids.includes('T1204') && ids.includes('T1059'), ids.join(','));
  assert.ok(a.ttps.every((t) => t.url.startsWith('https://attack.mitre.org/techniques/') && t.tacticName && t.how === 'inferred'));
});

test('articles carry patch priority from stored EPSS / CVSS and the CISA KEV catalog', async () => {
  const vulnIntel = require('../src/vuln-intel');
  const u = createUser('vi_user', PW);
  const s = db.addSource({ name: 'VI feed', url: 'https://feeds.example/vi', user_id: u }).id;
  db.insertArticle({ url: 'https://news.example/vi/1', title: 'Acme VPN CVE-2026-1111 exploited', description: '', user_id: u, source_id: s,
    source_name: 'VI feed', published_date: new Date().toISOString(), category: 'vulnerability', severity: 'high' });
  db.insertArticle({ url: 'https://news.example/vi/2', title: 'Foo CMS bug CVE-2026-2222', description: '', user_id: u, source_id: s,
    source_name: 'VI feed', published_date: new Date().toISOString(), category: 'vulnerability', severity: 'medium' });
  vulnIntel.lookup(['CVE-2026-0000']);   // creates the table
  db.getDb().prepare("INSERT INTO cve_intel (cve, epss, percentile, cvss, epss_at) VALUES ('CVE-2026-2222', 0.02, 0.4, 7.5, datetime('now'))").run();
  vulnIntel._setKevForTests(new Map([['CVE-2026-1111', { added: '2026-11-20', ransomware: true }]]));
  const jar = await h.login('vi_user', PW, ip());
  const r = await request('GET', '/api/articles?limit=50', { cookies: jar });
  const by = Object.fromEntries(r.body.articles.map((a) => [a.title.slice(0, 8), a.vuln]));
  assert.strictEqual(by['Acme VPN'][0].priority, 'now');
  assert.strictEqual(by['Acme VPN'][0].kev.ransomware, true);
  assert.strictEqual(by['Foo CMS '][0].priority, 'plan');
  assert.strictEqual(by['Foo CMS '][0].cvss, 7.5);
  vulnIntel._setKevForTests(new Map());
});

test('landscape trends: each technique and actor carries its count from the previous period', async () => {
  const u = createUser('tr_user', PW);
  const s = db.addSource({ name: 'TR feed', url: 'https://feeds.example/tr', user_id: u }).id;
  const add = (title, daysAgo) => db.insertArticle({ url: `https://news.example/tr/${++n}`, title, description: 'Attackers used password spraying against VPN accounts.',
    user_id: u, source_id: s, source_name: 'TR', published_date: new Date(Date.now() - daysAgo * 86400000).toISOString(), severity: 'high', threat_actors: 'APT28' });
  add('APT28 password spraying wave one', 1); add('APT28 password spraying wave two', 2); add('APT28 password spraying wave three', 3);
  add('APT28 password spraying last week', 9);
  const jar = await h.login('tr_user', PW, ip());
  const r = await request('GET', '/api/landscape?days=7', { cookies: jar });
  const t = r.body.attack.tactics.flatMap(x => x.techniques).find(x => x.id === 'T1110');
  assert.ok(t, 'brute force technique present');
  assert.strictEqual(t.total, 3);
  assert.strictEqual(t.prev, 1);
  assert.strictEqual(r.body.actors.find(a => a.name === 'APT28').prev, 1);
});

test('watchlist: per user, validated, highlights + filters the feed, guests cannot use it', async () => {
  const u = createUser('wl_user', PW), other = createUser('wl_other', PW);
  const s = db.addSource({ name: 'WL feed', url: 'https://feeds.example/wl', user_id: u }).id;
  const mk = (title) => db.insertArticle({ url: `https://news.example/wl/${++n}`, title, description: '', user_id: u, source_id: s,
    source_name: 'WL', published_date: new Date().toISOString(), severity: 'low' });
  mk('FortiOS SSL-VPN bug patched'); mk('Unrelated gardening story');
  const jar = await h.login('wl_user', PW, ip());
  const csrf = { 'X-CSRF-Token': jar.tp_csrf };
  assert.strictEqual((await request('POST', '/api/watchlist', { cookies: jar, headers: csrf, body: { term: ' ' } })).status, 400);
  const add = await request('POST', '/api/watchlist', { cookies: jar, headers: csrf, body: { term: 'fortios' } });
  assert.strictEqual(add.status, 201, JSON.stringify(add.body));
  assert.strictEqual((await request('POST', '/api/watchlist', { cookies: jar, headers: csrf, body: { term: 'FortiOS' } })).status, 400, 'duplicate (case-insensitive)');
  const feed = await request('GET', '/api/articles?limit=50', { cookies: jar });
  assert.deepStrictEqual(feed.body.articles.find((a) => a.title.startsWith('FortiOS')).watch, ['fortios']);
  const only = await request('GET', '/api/articles?limit=50&watchlist=1', { cookies: jar });
  assert.deepStrictEqual(only.body.articles.map((a) => a.title), ['FortiOS SSL-VPN bug patched']);
  // another user can't see or delete it
  const jo = await h.login('wl_other', PW, ip());
  assert.deepStrictEqual((await request('GET', '/api/watchlist', { cookies: jo })).body.terms, []);
  assert.strictEqual((await request('DELETE', `/api/watchlist/${add.body.id}`, { cookies: jo, headers: { 'X-CSRF-Token': jo.tp_csrf } })).status, 404);
  assert.strictEqual((await request('DELETE', `/api/watchlist/${add.body.id}`, { cookies: jar, headers: csrf })).status, 200);
});

test('actor profile: built only from the caller\'s reports, with techniques, weeks and recent list', async () => {
  const u = createUser('ap_user', PW), v = createUser('ap_other', PW);
  const s = db.addSource({ name: 'AP feed', url: 'https://feeds.example/ap', user_id: u }).id;
  const sv = db.addSource({ name: 'AP2 feed', url: 'https://feeds.example/ap2', user_id: v }).id;
  db.insertArticle({ url: 'https://news.example/ap/1', title: 'Fancy Bear password spraying against ministries', description: 'APT28 used password spraying.',
    user_id: u, source_id: s, source_name: 'AP', published_date: new Date().toISOString(), severity: 'high', threat_actors: 'APT28' });
  db.insertArticle({ url: 'https://news.example/ap/2', title: 'Other user APT28 report', description: 'APT28 phishing.',
    user_id: v, source_id: sv, source_name: 'AP2', published_date: new Date().toISOString(), severity: 'high', threat_actors: 'APT28' });
  const jar = await h.login('ap_user', PW, ip());
  const r = await request('GET', '/api/actors/profile?name=Fancy%20Bear', { cookies: jar });
  assert.strictEqual(r.status, 200, JSON.stringify(r.body));
  assert.strictEqual(r.body.found, true);
  assert.strictEqual(r.body.name, 'APT28', 'aliases fold to the canonical name');
  assert.strictEqual(r.body.reports, 1, 'only the caller\'s own reports');
  assert.ok(r.body.techniques.some((t) => t.id === 'T1110'));
  assert.strictEqual(r.body.weeks.length, 13);
  assert.strictEqual(r.body.recent[0].title, 'Fancy Bear password spraying against ministries');
});

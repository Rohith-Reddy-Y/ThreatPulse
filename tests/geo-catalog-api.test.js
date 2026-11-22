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

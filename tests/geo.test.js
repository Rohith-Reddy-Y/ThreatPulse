/**
 * Threat geography engine (src/geo.js) and source canonicalisation
 * (src/source-catalog.js) — pure functions.  Run with: sh tests/run-all.sh
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const geo = require('../src/geo');
const { canonicalUrl, buildCatalog } = require('../src/source-catalog');

test('countries: names, demonyms and codes — case-sensitive so ordinary words do not count', () => {
  const t = (s) => [...geo.countriesIn(s)].sort().join(',');
  assert.strictEqual(t('Russian APT28 targets Ukrainian grid and German ministries'), 'DE,RU,UA');
  assert.strictEqual(t('polish the report, turkey sandwich, chile sauce, tell us more'), '');
  assert.strictEqual(t('U.S. and UK agencies; the US Treasury; North Korean and South Korean firms'), 'GB,KP,KR,US');
  assert.strictEqual(t('US-CERT advisory; USB drives'), '', 'no partial-word matches');
});

test('actor attribution follows public naming (Bear/Panda/Kitten/Chollima) and skips unattributed crews', () => {
  const o = geo.originsOf(['Fancy Bear', 'LockBit', 'Volt Typhoon', 'Famous Chollima', 'Charming Kitten', 'Scattered Spider']);
  assert.deepStrictEqual([...o.keys()].sort(), ['CN', 'IR', 'KP', 'RU']);
});

test('buildGeo: counts, worst severity, ransomware Country: field, origin -> target arcs, search terms', () => {
  const g = geo.buildGeo([
    { id: 1, title: 'APT28 hits Ukrainian and Polish targets', description: '', severity: 'critical', threat_actors: 'APT28' },
    { id: 2, title: '[Dark Web] Ransomware Leak: x.com (Qilin)', description: 'Victim: x\nCountry: BR', severity: 'high', threat_actors: 'Qilin' },
    { id: 3, title: 'Leak b (Akira)', description: 'Country: BR', severity: 'low', threat_actors: '' },
    { id: 4, title: 'Patch Tuesday', description: 'no geography here', severity: 'medium', threat_actors: '' },
    { id: 5, title: 'Lazarus targets crypto firms', description: '', severity: 'high', threat_actors: 'Lazarus Group' },
  ], 7);
  assert.strictEqual(g.totalArticles, 5);
  assert.strictEqual(g.geolocated, 4);
  const by = Object.fromEntries(g.countries.map((c) => [c.code, c]));
  assert.strictEqual(by.BR.count, 2);
  assert.strictEqual(by.BR.worst, 'high');
  assert.strictEqual(by.BR.ransomware, 1);
  assert.strictEqual(by.BR.term, 'Country: BR', 'search term that matches those articles');
  assert.strictEqual(by.RU.origin, 1);
  assert.strictEqual(by.RU.term, 'APT28');
  assert.strictEqual(by.KP.count, 1, 'origin-only country still gets a beacon');
  assert.deepStrictEqual(g.arcs.map((a) => `${a.from}>${a.to}`).sort(), ['RU>PL', 'RU>UA']);
  assert.strictEqual(g.arcs[0].worst, 'critical');
  assert.ok(g.countries.every((c) => c.top.length <= 3 && c.lat !== undefined && c.lon !== undefined));
});

test('buildGeo stays fast on a full week of articles', () => {
  const rows = [];
  for (let i = 0; i < 4000; i++) rows.push({ id: i, title: `Chinese hackers target Taiwan and U.S. firms ${i}`, description: 'x '.repeat(600) + ' Germany France Japan', severity: 'high', threat_actors: 'Volt Typhoon' });
  const t0 = Date.now();
  geo.buildGeo(rows, 7);
  assert.ok(Date.now() - t0 < 1500, `took ${Date.now() - t0} ms`);
});

test('canonicalUrl treats www / scheme / trailing slash / tracking params / fragments as the same feed', () => {
  const same = [
    'https://www.Example.com/feed/', 'http://example.com/feed', 'https://example.com:443/feed#top',
    'https://example.com/feed?utm_source=x&utm_medium=y', 'https://example.com//feed',
  ];
  for (const u of same) assert.strictEqual(canonicalUrl(u), 'example.com/feed', u);
  assert.notStrictEqual(canonicalUrl('https://example.com/feed?cat=1'), canonicalUrl('https://example.com/feed?cat=2'));
  assert.notStrictEqual(canonicalUrl('https://blog.example.com/feed'), canonicalUrl('https://example.com/feed'));
});

test('buildCatalog folds duplicates, matches built-ins and labels every contributor', () => {
  const users = [{ id: 1, username: 'admin', display_name: 'Admin', role: 'admin' }, { id: 2, username: 'alice', display_name: 'Alice' }, { id: 3, username: 'bob', display_name: 'Bob' }];
  const now = new Date().toISOString().replace('T', ' ').slice(0, 19);
  const rows = [
    { id: 10, name: 'Krebs', url: 'https://krebsonsecurity.com/feed/', type: 'rss', added_by: 'system', user_id: 1, enabled: 1, created_at: '2026-01-01 00:00:00' },
    { id: 11, name: 'my krebs', url: 'http://www.krebsonsecurity.com/feed', type: 'rss', added_by: 'user', user_id: 2, enabled: 1, created_at: now },
    { id: 12, name: 'Niche blog', url: 'https://niche.example/rss?utm_source=a', type: 'rss', added_by: 'user', user_id: 2, enabled: 1, created_at: '2026-11-20 10:00:00' },
    { id: 13, name: 'niche', url: 'https://www.niche.example/rss/', type: 'rss', added_by: 'user', user_id: 3, enabled: 0, created_at: now },
  ];
  const { entries, totals } = buildCatalog(rows, users);
  assert.strictEqual(entries.length, 2, 'four rows, two feeds');
  assert.strictEqual(totals.duplicatesFolded, 2);
  const krebs = entries.find((e) => e.builtIn);
  assert.strictEqual(krebs.name, 'Krebs', 'built-in naming wins');
  assert.deepStrictEqual(krebs.contributors.map((c) => c.displayName), ['Alice']);
  const niche = entries.find((e) => e.userSubmitted);
  assert.strictEqual(niche.builtIn, false);
  assert.deepStrictEqual(niche.contributors.map((c) => c.displayName), ['Alice', 'Bob'], 'oldest contributor first');
  assert.strictEqual(niche.contributors[1].enabled, false);
  assert.strictEqual(entries[0], niche, 'user-submitted feeds are listed first');
  assert.strictEqual(totals.userSubmitted, 1);
});

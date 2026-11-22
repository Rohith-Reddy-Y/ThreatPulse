/**
 * Threat Landscape analytics (src/landscape.js).  Run with: sh tests/run-all.sh
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const L = require('../src/landscape');

const row = (o) => ({ id: 1, title: '', description: '', severity: 'medium', threat_actors: '', mitre_ids: null, sector: null,
  cve_id: null, has_poc: 0, is_patched: -1, tags: '', published_date: '2026-11-22T00:00:00Z', ...o });

test('ATT&CK: explicit IDs and inferred behaviour are counted separately, sub-techniques roll up', () => {
  const r = L.buildLandscape([
    row({ id: 1, title: 'APT28 password spraying', mitre_ids: 'T1110.003,T1566', severity: 'critical', threat_actors: 'APT28' }),
    row({ id: 2, title: 'Phishing wave delivers infostealer', severity: 'high' }),
    row({ id: 3, title: 'Patch Tuesday roundup' }),
  ], 7);
  const tech = Object.fromEntries(r.attack.tactics.flatMap((t) => t.techniques).map((t) => [t.id, t]));
  assert.deepStrictEqual([tech.T1110.explicit, tech.T1110.inferred], [1, 0], 'sub-technique counted under T1110, not re-inferred');
  assert.deepStrictEqual([tech.T1566.explicit, tech.T1566.inferred], [1, 1]);
  assert.strictEqual(tech.T1555.inferred, 1, 'infostealer -> Credentials from Password Stores');
  assert.strictEqual(tech.T1566.worst, 'critical');
  assert.strictEqual(r.attack.mappedArticles, 2);
  assert.strictEqual(r.attack.explicitArticles, 1);
  assert.strictEqual(r.attack.tactics.length, 14, 'every tactic column present');
  assert.strictEqual(r.attack.tactics.find((t) => t.id === 'TA0001').count, 2);
  assert.strictEqual(tech.T1566.term, 'phishing', 'search term reproduces the match');
});

test('inference stays conservative: ordinary words do not map to techniques', () => {
  const r = L.buildLandscape([row({ title: 'Vendor ships update to its cloud dashboard', description: 'New features for teams.' })], 7);
  assert.strictEqual(r.attack.mappedArticles, 0);
});

test('actors, CVEs and sectors', () => {
  const r = L.buildLandscape([
    row({ id: 1, title: 'Volt Typhoon targets utilities', description: 'exploiting CVE-2024-1111', threat_actors: 'Volt Typhoon', sector: 'government', severity: 'high' }),
    row({ id: 2, title: 'Citrix flaw actively exploited', description: 'CVE-2026-9999 web shells', cve_id: 'CVE-2026-9999', tags: 'cisa-kev,actively-exploited', has_poc: 1, is_patched: 0, severity: 'critical', sector: 'technology' }),
    row({ id: 3, title: 'More on CVE-2026-9999', cve_id: 'CVE-2026-9999', is_patched: 1, severity: 'high' }),
    row({ id: 4, title: 'LockBit hits hospital', threat_actors: 'LockBit', sector: 'healthcare', severity: 'critical' }),
  ], 7);
  const volt = r.actors.find((a) => a.name === 'Volt Typhoon');
  assert.strictEqual(volt.origin.code, 'CN');
  assert.deepStrictEqual(volt.cves, ['CVE-2024-1111']);
  assert.strictEqual(r.actors.find((a) => a.name === 'LockBit').origin, null, 'no attribution invented');
  const c = r.cves[0];
  assert.strictEqual(c.id, 'CVE-2026-9999', 'exploited CVEs rank first');
  assert.deepStrictEqual([c.count, c.kev, c.exploited, c.poc, c.patch, c.worst], [2, true, true, true, 'unpatched', 'critical']);
  assert.deepStrictEqual(r.sectors.map((s) => s.name).sort(), ['government', 'healthcare', 'technology']);
});

test('actor aliases fold into one row and are listed; one report counts once', () => {
  const r = L.buildLandscape([
    row({ id: 1, title: 'Lazarus hits exchange', threat_actors: 'Lazarus, Lazarus Group' }),
    row({ id: 2, title: 'Lazarus Group phishing', threat_actors: 'Lazarus Group' }),
    row({ id: 3, title: 'Fancy Bear campaign', threat_actors: 'Fancy Bear' }),
  ], 7);
  const laz = r.actors.find((a) => a.name === 'Lazarus');
  assert.strictEqual(laz.count, 2);
  assert.deepStrictEqual(laz.aliases, ['Lazarus Group']);
  assert.strictEqual(laz.origin.code, 'KP');
  assert.strictEqual(r.actors.filter((a) => /lazarus/i.test(a.name)).length, 1);
  const apt28 = r.actors.find((a) => a.name === 'APT28');
  assert.strictEqual(apt28.term, 'Fancy Bear', 'search by the spelling the reports use');
  assert.strictEqual(apt28.origin.code, 'RU');
});

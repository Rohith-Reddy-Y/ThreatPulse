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

const kb = require('../src/attack-kb');

test('analyzeTtps: tactic / technique / procedure, cited vs inferred, MITRE links, kill-chain order', () => {
  const ttps = kb.analyzeTtps({
    title: 'APT28 password spraying hits ministries',
    description: 'The group used password spraying against Outlook accounts. Later it deployed a web shell on Exchange. T1110.003 observed.',
    mitre_ids: 'T1110.003',
  });
  assert.deepStrictEqual(ttps.map((t) => `${t.tacticName}|${t.id}|${t.how}`), ['Persistence|T1505|inferred', 'Credential Access|T1110|cited']);
  const bf = ttps.find((t) => t.id === 'T1110');
  assert.strictEqual(bf.subId, 'T1110.003');
  assert.strictEqual(bf.url, 'https://attack.mitre.org/techniques/T1110/003/');
  assert.strictEqual(bf.procedure, 'The group used password spraying against Outlook accounts.', 'behaviour sentence beats the bare ID sentence');
  assert.strictEqual(ttps[0].procedure, 'Later it deployed a web shell on Exchange.');
  assert.strictEqual(kb.attackUrl('TA0006'), 'https://attack.mitre.org/tactics/TA0006/');
  assert.ok(Object.values(kb.TECHNIQUES).every((t) => t.name && t.tactic && t.desc), 'every catalogue entry has name, tactic and description');
});

test('landscape techniques carry MITRE link, description, procedures and actors; actors carry their techniques', () => {
  const r = L.buildLandscape([
    row({ id: 1, title: 'Fancy Bear password spraying', description: 'Fancy Bear ran password spraying against mail portals.', threat_actors: 'Fancy Bear', url: 'https://news.example/1' }),
    row({ id: 2, title: 'More spraying', description: 'Attackers used password spraying again.', url: 'https://news.example/2' }),
  ], 7);
  const t = r.attack.tactics.flatMap((x) => x.techniques).find((x) => x.id === 'T1110');
  assert.strictEqual(t.url, 'https://attack.mitre.org/techniques/T1110/');
  assert.ok(t.desc.length > 10);
  assert.strictEqual(t.procedures.length, 2);
  assert.strictEqual(t.procedures[0].url, 'https://news.example/1');
  assert.deepStrictEqual(t.actors, [{ name: 'APT28', count: 1 }]);
  assert.strictEqual(r.attack.tactics.find((x) => x.id === 'TA0006').url, 'https://attack.mitre.org/tactics/TA0006/');
  assert.deepStrictEqual(r.actors[0].techniques.map((x) => x.id), ['T1110']);
});

test('AI-mapped techniques (from "Map with AI") are counted in the landscape', () => {
  const { buildLandscape } = require('../src/landscape');
  const now = new Date().toISOString();
  const d = buildLandscape([
    { id: 1, title: 'Quiet report', description: 'Attackers extracted NTDS.dit from domain controllers.', severity: 'high', published_date: now,
      _aiTtps: [{ id: 'T1003', subId: 'T1003.003', name: 'OS Credential Dumping', tactic: 'TA0006', tacticName: 'Credential Access', how: 'ai', term: null, procedure: 'extracted NTDS.dit from domain controllers' }] },
  ], 7);
  const all = d.attack.tactics.flatMap(t => t.techniques);
  const t = all.find(x => x.id === 'T1003');
  assert.ok(t, 'AI technique present');
  assert.equal(t.procedures[0].how, 'ai');
});

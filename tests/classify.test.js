// Table-driven classifier tests: category / severity / has_poc / is_patched / cve
require('./helpers/stubs');
const test = require('node:test');
const assert = require('node:assert/strict');
const r = require('../src/feeds/rss-fetcher');

// [title, description, category, severity, has_poc, is_patched, cve]
// `null` in an expectation column = don't care.
const CASES = [
  // critical keyword followed by a product name (was: medium)
  ['Cisco patches critical IOS XE flaw exploited in attacks', '', 'vulnerability', 'critical', 0, 1, null],
  // CVSS score at a sentence end "9.6." (was: not extracted -> medium)
  ['Fortinet warns of critical FortiOS SSL-VPN vulnerability', 'The flaw, tracked as CVE-2024-21762, has a CVSS score of 9.6.', 'vulnerability', 'critical', 0, -1, 'CVE-2024-21762'],
  ['Apache Tomcat flaw', 'The issue has a CVSS score of 9.8.', 'vulnerability', 'critical', 0, -1, null],
  ['Atlassian Confluence bug rated CVSS 9.8.', '', 'vulnerability', 'critical', 0, -1, null],
  // CVSS vector string is not a 3.1 score (was: low); "bug" is a vulnerability word (was: news)
  ['Ivanti fixes high-severity bug in Connect Secure', 'CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H', 'vulnerability', 'high', 0, 1, null],
  // CVSS version is not a score (was: low)
  ['New flaw in OpenSSH', 'CVSS v3.1 base score unavailable; actively exploited in the wild.', 'vulnerability', 'critical', 0, -1, null],
  ['Sophos firewall bug with CVSS 4.0 score of 9.3', '', 'vulnerability', 'critical', 0, -1, null],
  ['Jenkins plugin flaw', 'CVSSv3.1 base score: 7.5', 'vulnerability', 'high', 0, -1, null],
  ['GitLab patches account takeover', 'CVSS 10.0', 'advisory', 'critical', 0, 1, null],
  ['WordPress plugin XSS (CVSS v3.1: 6.1)', '', 'vulnerability', 'medium', 0, -1, null],
  // PoC negation (was: has_poc=1)
  ['Microsoft: no public exploit for Exchange flaw', 'Microsoft is not aware of any public exploits. Patches are available.', 'vulnerability', null, 0, 1, null],
  ['Researcher drops PoC for Windows kernel bug', 'No patch is available yet.', 'vulnerability', 'high', 1, 0, null],
  ['Researchers publish proof-of-concept exploit for Fortinet bug', '', 'vulnerability', 'high', 1, -1, null],
  ['Exploit code released for VMware vCenter flaw', '', 'vulnerability', null, 1, -1, null],
  // patch negations (were: is_patched=1)
  ['Zero-day in Chrome exploited', 'Google says no fixes are available yet', 'vulnerability', 'critical', 0, 0, null],
  ['Vendor yet to patch critical router bug', 'The flaw remains unfixed; it will be patched next month.', 'vulnerability', 'critical', 0, 0, null],
  ['No patches available for WinRAR flaw', '', 'vulnerability', null, 0, 0, null],
  ['Patch now: Citrix Bleed 2 under active exploitation', '', 'vulnerability', 'critical', 0, 1, null],
  ['Patch Tuesday: Microsoft fixes 61 flaws, two zero-days', '', 'vulnerability', 'critical', 0, 1, null],
  ['Microsoft Patch Tuesday', 'Fixed in version 2.4.1', 'advisory', null, 0, 1, null],
  // "memory leak" is not a breach (was: breach)
  ['Linux kernel memory leak fixed in 6.8', '', 'news', 'low', 0, 1, null],
  // Unicode dashes in CVE IDs (was: no CVE)
  ['CVE‑2024‑3400 exploited in GlobalProtect', '', 'vulnerability', null, 0, -1, 'CVE-2024-3400'],
  ['cve-2023-4966 Citrix Bleed', '', 'vulnerability', null, 0, -1, 'CVE-2023-4966'],
  // Zero Day Initiative is not a zero-day (was: category vulnerability)
  ['Zero Day Initiative announces Pwn2Own Berlin', '', 'news', 'low', 0, -1, null],
  ['Bug bounty programs: are they worth it?', '', 'news', 'low', 0, -1, null],
  // unchanged behaviour (regression guard)
  ['New Android banking trojan steals credentials', '', 'malware', 'medium', 0, -1, null],
  ['LockBit ransomware gang claims attack on hospital', '', 'malware', 'medium', 0, -1, null],
  ['Data breach at Ticketmaster exposes 560M records', '', 'breach', 'high', 0, -1, null],
  ['CISA adds three flaws to KEV catalog', '', 'vulnerability', 'critical', 0, -1, null],
  ['How to adapt your SOC to AI', '', 'news', 'low', 0, -1, null],
  ['Monitoring resources for your laptop fleet', '', 'news', 'low', 0, -1, null],
  ['Police take down dark web marketplace', '', 'darkweb', 'medium', 0, -1, null],
  ['Chinese APT targets telecom firms in espionage campaign', '', 'threat_intel', 'medium', 0, -1, null],
  ['Phishing campaign abuses Google Docs', '', 'threat_intel', 'medium', 0, -1, null],
  ['Critical infrastructure operators warned about Volt Typhoon', '', 'news', 'low', 0, -1, null],
  ['Unauthenticated RCE in Jenkins plugin', '', 'vulnerability', 'critical', 0, -1, null],
  ['The Week in Security: AI agents and identity', '', 'news', 'low', 0, -1, null],
  ['Moderate-severity XSS in WordPress plugin', '', 'vulnerability', 'medium', 0, -1, null],
  ['DoS vulnerability in BIND', '', 'vulnerability', 'medium', 0, -1, null],
  ['Open source maintainers face burnout', '', 'news', 'low', 0, -1, null],
  ['Maximum-severity GitLab flaw lets attackers run pipelines as any user', '', 'vulnerability', 'critical', 0, -1, null],
];

for (const [title, desc, cat, sev, poc, patched, cve] of CASES) {
  test(`classify: ${title}`, () => {
    const c = r.detectCategory(title, desc);
    const got = {
      category: c,
      severity: r.detectSeverity(title, desc, c),
      has_poc: r.detectPOC(title, desc),
      is_patched: r.detectPatchStatus(title, desc),
      cve: r.extractCVE(`${title} ${desc}`),
    };
    const want = { category: cat, severity: sev, has_poc: poc, is_patched: patched, cve };
    for (const k of Object.keys(want)) if (want[k] === null && k !== 'cve') { delete want[k]; delete got[k]; }
    assert.deepEqual(got, want);
  });
}

test('generateTags: no cloud tag for "flaws", no crypto tag for "cryptographic", no ios for Cisco IOS', () => {
  const { generateTags } = r._internal;
  assert.equal(generateTags('Microsoft fixes 61 flaws', ''), 'windows');
  assert.equal(generateTags('Cryptographic library flaws allow key recovery', ''), null);
  assert.equal(generateTags('Cisco IOS XE flaw', ''), null);
  assert.equal(generateTags('Linux kernel memory leak', ''), 'linux');
  assert.equal(generateTags('AWS keys stolen in crypto heist', ''), 'cloud,cryptocurrency');
  assert.equal(generateTags('APT29 phishing', ''), 'phishing,apt');
});

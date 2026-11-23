// IOC extractor + enrichment false positives
require('./helpers/stubs');
const test = require('node:test');
const assert = require('node:assert/strict');
const { extractIOCs } = require('../src/feeds/ioc-extractor');
const { detectSector, detectThreatActors } = require('../src/enrich');

test('IOC: version numbers are not IPs', () => {
  const t = 'Linux kernel 5.15.0.91 fixed; upgrade to version 1.2.3.4 or v2.0.1.3; build 10.0.19041.1; release 6.1.0.12; 4.4.2.1.5 too.';
  assert.deepEqual(extractIOCs(t).ips, []);
});

test('IOC: documentation / special-purpose ranges are not IOCs; real C2 IPs are kept', () => {
  const t = 'C2 at 45.137.21.9; examples 192.0.2.10, 198.51.100.7, 203.0.113.5; CGNAT 100.64.1.1; benchmark 198.18.0.1. Traffic to 185.220.101.4.';
  assert.deepEqual(extractIOCs(t).ips, ['45.137.21.9', '185.220.101.4']);
});

test('IOC: code identifiers / file names are not domains; real domains kept', () => {
  const t = 'Payload uses System.IO and ASP.NET, plays sound.au, contacts evil-c2.ru and cdn.badguy.com; abuse.com.au mirror.';
  assert.deepEqual(extractIOCs(t).domains, ['evil-c2.ru', 'cdn.badguy.com', 'abuse.com.au']);
});

test('sector: the Swift programming language is not the SWIFT banking network', () => {
  assert.equal(detectSector('Swift package manager vulnerability allows code execution'), null);
  assert.equal(detectSector('Apple patches flaw in swift compiler toolchain'), null);
  assert.equal(detectSector('Hackers abused SWIFT to steal $81M from Bangladesh Bank'), 'financial');
  assert.equal(detectSector('Fraudulent SWIFT transfers'), 'financial');
});

test('threat actors: "snatch" as an English verb is not the Snatch ransomware group', () => {
  assert.equal(detectThreatActors('Infostealer snatches browser cookies'), null);
  assert.equal(detectThreatActors('Attackers snatch session tokens from Okta users'), null);
  assert.equal(detectThreatActors('Snatch ransomware gang leaks data'), 'Snatch');
  assert.equal(detectThreatActors('LockBit and Lazarus Group'), 'Lazarus Group,Lazarus,LockBit');
});

test('product version numbers after a product name are not IPs; real IOCs still are', () => {
  const { extractIOCs } = require('../src/feeds/ioc-extractor');
  const none = ['Upgrade FortiOS 7.4.2.1 now', 'PAN-OS 10.2.9.1 is affected', 'Chrome 13.0.6.85 fixed'];
  for (const t of none) assert.deepEqual(extractIOCs(t).ips, [], t);
  assert.deepEqual(extractIOCs('C2 server 45.9.148.108 observed').ips, ['45.9.148.108']);
  assert.deepEqual(extractIOCs('IP 5.8.18.7 used').ips, ['5.8.18.7']);
  assert.deepEqual(extractIOCs('beaconing from 23.4.5.6').ips, ['23.4.5.6']);
  assert.deepEqual(extractIOCs('IOCs: 8.9.10.11, 91.92.93.94').ips, ['8.9.10.11', '91.92.93.94']);
});

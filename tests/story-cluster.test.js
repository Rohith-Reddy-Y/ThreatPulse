'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { clusterArticles } = require('../src/story-cluster');
const d = '2026-11-22T10:00:00Z';
const A = (id, title, url, extra = {}) => ({ id, title, url, source_name: `S${id}`, published_date: d, ...extra });

test('same story from several outlets becomes one card listing the others', () => {
  const out = clusterArticles([
    A(1, 'Fortinet patches FortiOS SSL-VPN zero-day exploited in attacks (CVE-2026-1111)', 'https://a.com/1'),
    A(2, 'CVE-2026-1111: FortiOS flaw under active exploitation', 'https://b.com/2', { has_poc: 1 }),
    A(3, 'Fortinet FortiOS SSL-VPN zero-day exploited in attacks - SecurityWeek', 'https://c.com/3'),
    A(4, 'Microsoft Patch Tuesday fixes 63 flaws', 'https://d.com/4'),
    A(6, 'Google fixes Chrome zero-day exploited in attacks', 'https://e.com/6'),
  ]);
  assert.deepEqual(out.map((o) => o.id), [1, 4, 6]);
  assert.deepEqual(out[0].related.map((r) => r.id), [2, 3]);
  assert.equal(out[0].has_poc, 1, 'facts from folded copies are kept');
  assert.equal(out[1].related, undefined);
});

test('per-user copies of the very same URL collapse silently; old stories are not merged', () => {
  const out = clusterArticles([
    A(1, 'Acme VPN RCE exploited', 'https://a.com/x'),
    A(2, 'Acme VPN RCE exploited', 'https://www.a.com/x/'),
    A(3, 'Acme VPN RCE exploited again in new wave', 'https://b.com/y', { published_date: '2026-10-01T00:00:00Z' }),
  ]);
  assert.deepEqual(out.map((o) => o.id), [1, 3]);
  assert.equal(out[0].related, undefined, 'same article is not listed as another source');
});

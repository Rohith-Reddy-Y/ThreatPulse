/**
 * Analytics page data (src/analytics.js).  Run with: sh tests/run-all.sh
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const A = require('../src/analytics');

const NOW = Date.parse('2026-11-22T12:00:00Z');
const at = (daysAgo, hours = 1) => new Date(NOW - daysAgo * 86400000 - hours * 3600000).toISOString();
const row = (o) => ({ id: 1, title: 'x', description: '', severity: 'low', threat_actors: '', mitre_ids: null, cve_id: null,
  has_poc: 0, tags: '', source_name: 'S', category: 'news', published_date: at(0), ...o });

test('buckets follow the viewer time zone; 24h view is hourly', () => {
  const ist = A.bucketer(7, 330, NOW);
  assert.strictEqual(ist.n, 7);
  assert.strictEqual(ist.starts[6], '2026-11-21T18:30:00.000Z', 'today starts at local midnight (IST)');
  assert.strictEqual(ist.index(Date.parse('2026-11-21T18:29:00Z')), 5);
  assert.strictEqual(ist.index(Date.parse('2026-11-21T18:31:00Z')), 6);
  const h = A.bucketer(1, 0, NOW);
  assert.strictEqual(h.unit, 'hour');
  assert.strictEqual(h.n, 24);
  assert.strictEqual(h.index(NOW), 23);
});

test('severity series, KPIs vs previous period, sources, categories, top over time', async () => {
  const rows = [
    row({ id: 1, severity: 'critical', published_date: at(0), source_name: 'A', category: 'vulnerability', description: 'CVE-2026-12345 actively exploited', has_poc: 1 }),
    row({ id: 2, severity: 'high', published_date: at(1), source_name: 'A', title: 'Phishing wave', threat_actors: 'Lazarus Group' }),
    row({ id: 3, severity: 'low', published_date: at(2), source_name: 'B', threat_actors: 'Lazarus' }),
    row({ id: 4, severity: 'critical', published_date: at(9), source_name: 'A' }),       // previous period
    row({ id: 5, severity: 'medium', published_date: at(40), source_name: 'A' }),        // outside both windows
  ];
  const sources = [{ enabled: 1, last_fetched: 'x', last_error: null }, { enabled: 1, last_fetched: 'x', last_error: 'down' }, { enabled: 0 }];
  const r = await A.buildAnalytics(rows, sources, { days: 7, tz: 0, now: NOW });
  assert.strictEqual(r.severity.total.reduce((a, b) => a + b, 0), 3);
  assert.strictEqual(r.severity.series.find((s) => s.key === 'critical').values[6], 1);
  assert.deepStrictEqual([r.kpis.reports.value, r.kpis.reports.prev], [3, 1]);
  assert.deepStrictEqual([r.kpis.critical.value, r.kpis.critical.prev], [1, 1]);
  assert.strictEqual(r.kpis.exploitedCves.value, 1);
  assert.strictEqual(r.kpis.pocs.value, 1);
  assert.strictEqual(r.kpis.actors.value, 1, 'Lazarus + Lazarus Group = one actor');
  assert.deepStrictEqual(r.kpis.sources, { total: 2, healthy: 1, errors: 1 });
  assert.deepStrictEqual(r.sources.top, [{ name: 'A', count: 2 }, { name: 'B', count: 1 }]);
  assert.strictEqual(r.categories[0].name, 'news');
  assert.deepStrictEqual(r.sourcesOverTime.series.map((s) => s.name), ['A', 'B']);
  assert.strictEqual(r.techniquesOverTime.series[0].name, 'T1566 Phishing');
});

// NVD / CISA KEV / abuse.ch / RansomWatch fetchers + aggregator bookkeeping.
process.env.ABUSE_CH_API_KEY = 'test-abuse-key';
const { state, calls, reset, fakeDb } = require('./helpers/stubs');
const test = require('node:test');
const assert = require('node:assert/strict');
const { fetchCVEs } = require('../src/feeds/cve-fetcher');
const dw = require('../src/feeds/darkweb-fetcher');

const day = (offsetDays = 0) => new Date(Date.now() - offsetDays * 864e5);
const abuseTs = (d) => d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

test('RansomWatch (raw.githubusercontent.com) is not sent the abuse.ch Auth-Key', async () => {
  reset();
  state.axiosGet = async () => ({ data: [] });
  await dw.fetchRansomWatch({ id: 1 });
  const headers = calls.axiosGet[0].config.headers || {};
  assert.equal(headers['Auth-Key'], undefined);
});

test('abuse.ch requests do carry the Auth-Key', async () => {
  reset();
  state.axiosPost = async () => ({ data: { query_status: 'ok', data: [] } });
  state.axiosGet = async () => ({ data: { urls: [] } });
  await dw.fetchThreatFox({ id: 2 });
  await dw.fetchURLhaus({ id: 3 });
  await dw.fetchMalwareBazaar({ id: 4 });
  assert.equal(calls.axiosPost[0].config.headers['Auth-Key'], 'test-abuse-key');
  assert.equal(calls.axiosGet[0].config.headers['Auth-Key'], 'test-abuse-key');
  assert.equal(calls.axiosPost[1].config.headers['Auth-Key'], 'test-abuse-key');
});

test('RansomWatch: every leak post gets its own URL (DB dedupes on URL)', async () => {
  reset();
  state.axiosGet = async () => ({ data: [
    { post_title: 'Acme Corp', group_name: 'lockbit3', discovered: day(1).toISOString() },
    { post_title: 'Globex', group_name: 'play', discovered: day(1).toISOString() },
  ] });
  const { articles } = await dw.fetchRansomWatch({ id: 1 });
  assert.equal(articles.length, 2);
  assert.equal(new Set(articles.map(a => a.url.toLowerCase())).size, 2);
});

function threatFoxIoc(malware, printable, firstSeen) {
  // field names as documented at https://threatfox.abuse.ch/api/
  return { id: String(Math.random()), ioc: '1.2.3.4:443', threat_type: 'botnet_cc', ioc_type: 'ip:port',
    malware, malware_printable: printable, malware_malpedia: `https://malpedia.caad.fkie.fraunhofer.de/details/${malware}`,
    confidence_level: 100, first_seen: firstSeen, reporter: 'abuse_ch' };
}

test('ThreatFox: field mapping (first_seen, malware id in browse URL)', async () => {
  reset();
  const seen = abuseTs(day(0));
  state.axiosPost = async () => ({ data: { query_status: 'ok', data: [threatFoxIoc('win.cobalt_strike', 'Cobalt Strike', seen)] } });
  const { articles: [a] } = await dw.fetchThreatFox({ id: 2 });
  assert.equal(a.published_date, seen);
  assert.match(a.description, new RegExp(`First Seen: ${seen}`));
  assert.match(a.description, /IOC Types: ip:port/);
  assert.match(a.url, /^https:\/\/threatfox\.abuse\.ch\/browse\/malware\/win\.cobalt_strike\//);
});

test('ThreatFox: the same malware family on a later day is a new article (distinct URL)', async () => {
  reset();
  state.axiosPost = async () => ({ data: { query_status: 'ok', data: [threatFoxIoc('win.cobalt_strike', 'Cobalt Strike', abuseTs(day(2)))] } });
  const a1 = (await dw.fetchThreatFox({ id: 2 })).articles[0];
  state.axiosPost = async () => ({ data: { query_status: 'ok', data: [threatFoxIoc('win.cobalt_strike', 'Cobalt Strike', abuseTs(day(0)))] } });
  const a2 = (await dw.fetchThreatFox({ id: 2 })).articles[0];
  assert.notEqual(a1.url.toLowerCase(), a2.url.toLowerCase());
});

test('URLhaus: uses date_added (24h filter + published date) and per-day URLs', async () => {
  reset();
  const fresh = abuseTs(day(0)), stale = abuseTs(day(3));
  state.axiosGet = async () => ({ data: { query_status: 'ok', urls: [
    { id: '1', url: 'http://bad.example/a', url_status: 'online', date_added: fresh, threat: 'malware_download', tags: ['elf'], urlhaus_reference: 'https://urlhaus.abuse.ch/url/1/', reporter: 'r1' },
    { id: '2', url: 'http://bad.example/b', url_status: 'offline', date_added: stale, threat: 'malware_download', tags: ['exe'], urlhaus_reference: 'https://urlhaus.abuse.ch/url/2/', reporter: 'r2' },
  ] } });
  const { articles } = await dw.fetchURLhaus({ id: 3 });
  assert.equal(articles.length, 1);
  assert.match(articles[0].title, /^\[Malicious URLs\] 1 new malware download URLs/);
  assert.equal(articles[0].published_date, fresh);
  assert.notEqual(articles[0].url, 'https://urlhaus.abuse.ch/browse/');
});

test('fetchDarkWebIntel results carry the source id (names are not unique across users)', async () => {
  reset();
  state.axiosGet = async () => ({ data: [] });
  const { results } = await dw.fetchDarkWebIntel([
    { id: 11, name: 'RansomWatch', url: 'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json' },
    { id: 12, name: 'RansomWatch', url: 'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json', user_id: 5 },
  ]);
  assert.deepEqual(results.map(r => r.sourceId), [11, 12]);
});

function nvdVuln(id, metrics) {
  return { cve: { id, published: '2026-11-21T10:00:00.000', descriptions: [{ lang: 'en', value: `Description of ${id}` }], metrics, references: [] } };
}

test('NVD: CVSS v4.0-only CVEs get their real severity (was: medium, score 0)', async () => {
  reset();
  state.axiosGet = async () => ({ data: { totalResults: 1, vulnerabilities: [
    nvdVuln('CVE-2026-0001', { cvssMetricV40: [{ cvssData: { version: '4.0', baseScore: 9.3, baseSeverity: 'CRITICAL' } }] }),
  ] } });
  const { articles: [a] } = await fetchCVEs({ id: 7 }, null);
  assert.equal(a.severity, 'critical');
  assert.match(a.tags || '', /critical/);
});

test('NVD: all CVEs of the 24h window are fetched, not just the first page of 50', async () => {
  reset();
  const all = Array.from({ length: 140 }, (_, i) => nvdVuln(`CVE-2026-${String(1000 + i)}`, {}));
  // NVD paging semantics: at most resultsPerPage items starting at startIndex
  state.axiosGet = async (url, cfg) => {
    const start = cfg.params.startIndex || 0, per = cfg.params.resultsPerPage || 2000;
    return { data: { totalResults: all.length, startIndex: start, resultsPerPage: per, vulnerabilities: all.slice(start, start + per) } };
  };
  const { articles } = await fetchCVEs({ id: 7 }, 'k');
  assert.equal(articles.length, 140);
  assert.equal(calls.axiosGet[0].config.headers.apiKey, 'k');
});

test('trusted API fetchers also have a hard deadline (AbortSignal)', async () => {
  reset();
  state.axiosGet = async () => ({ data: { vulnerabilities: [], urls: [] } });
  state.axiosPost = async () => ({ data: { query_status: 'ok', data: [] } });
  await fetchCVEs({ id: 7 }, null);
  await dw.fetchThreatFox({ id: 2 });
  assert.ok(calls.axiosGet[0].config.signal, 'NVD request has no signal');
  assert.ok(calls.axiosPost[0].config.signal, 'ThreatFox request has no signal');
});

test('aggregator: failed API / custom / dark-web fetches are counted and mapped to the right source', async () => {
  reset();
  const statusUpdates = [];
  fakeDb.getEnabledSources = () => [
    { id: 21, name: 'NVD', type: 'api', url: 'https://services.nvd.nist.gov/rest/json/cves/2.0' },
    { id: 22, name: 'ThreatFox', type: 'darkweb', url: 'https://threatfox-api.abuse.ch/api/v1/' },
    { id: 23, name: 'ThreatFox', type: 'darkweb', url: 'https://threatfox-api.abuse.ch/api/v1/', user_id: 9 },
  ];
  fakeDb.updateSourceFetchStatus = (id, s) => statusUpdates.push({ id, err: s.last_error || null });
  state.axiosGet = async () => { const e = new Error('Request failed with status code 503'); e.response = { status: 503 }; throw e; };
  let tf = 0;
  state.axiosPost = async () => { if (tf++ === 0) return { data: { query_status: 'ok', data: [] } }; throw new Error('boom'); };
  const realSetTimeout = global.setTimeout;
  global.setTimeout = (fn, ms, ...a) => realSetTimeout(fn, Math.min(ms, 1), ...a);   // skip NVD rate-limit sleep
  try {
    const agg = require('../src/feeds/aggregator');
    const res = await agg.fetchAllSources();
    assert.equal(res.errors, 2);                                 // NVD 503 + second ThreatFox
    assert.deepEqual(statusUpdates.filter(u => u.id !== 21), [{ id: 22, err: null }, { id: 23, err: 'boom' }]);
    assert.equal(agg.getStatus().isRunning, false);
  } finally {
    global.setTimeout = realSetTimeout;
  }
});

test('ThreatFox: a multi-MB response is parsed off the main thread (event loop stays responsive)', async () => {
  reset();
  // ~6 MB of IOCs, like a busy day on ThreatFox
  const iocs = Array.from({ length: 12000 }, (_, i) => ({
    id: String(i), ioc: `198.51.${i % 250}.${i % 200}:443`, threat_type: 'botnet_cc', ioc_type: 'ip:port',
    malware: 'win.cobalt_strike', malware_printable: i % 2 ? 'Cobalt Strike' : 'AsyncRAT',
    first_seen: new Date().toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
    confidence_level: 75, tags: ['c2', 'x'.repeat(300)], reporter: 'test',
  }));
  const big = JSON.stringify({ query_status: 'ok', data: iocs });
  assert.ok(big.length > 5e6);
  state.axiosPost = async () => ({ data: big });           // raw text, as with responseType 'text'

  let maxGap = 0, last = Date.now();
  const tick = setInterval(() => { const n = Date.now(); maxGap = Math.max(maxGap, n - last); last = n; }, 10);
  const r = await dw.fetchThreatFox({ id: 2 });
  clearInterval(tick);

  assert.equal(r.success, true);
  assert.ok(r.articles.length > 0);
  assert.equal(calls.axiosPost[0].config.responseType, 'text');
  assert.ok(maxGap < 250, `event loop blocked for ${maxGap} ms`);
});

test('URLhaus and MalwareBazaar request bounded result sets', async () => {
  reset();
  state.axiosGet = async () => ({ data: { query_status: 'ok', urls: [] } });
  state.axiosPost = async () => ({ data: { query_status: 'ok', data: [] } });
  await dw.fetchURLhaus({ id: 3 });
  await dw.fetchMalwareBazaar({ id: 4 });
  assert.match(calls.axiosGet[0].url, /\/urls\/recent\/limit\/100\/$/);
  assert.equal(calls.axiosPost[0].body, 'query=get_recent&selector=100');
});

// Feed pipeline gaps: every source type the dashboard offers must actually be
// fetched, and the Add Source form's default category must not freeze articles
// into a category no filter matches.
const { fakeDb, FAKES } = require('./helpers/stubs');
const test = require('node:test');
console.log = () => {}; console.warn = () => {};
const assert = require('node:assert/strict');

const rss = require('../src/feeds/rss-fetcher');
const scraper = require('../src/feeds/web-scraper');
const cve = require('../src/feeds/cve-fetcher');

const seen = [];
rss.fetchRSSFeed = async (s) => { seen.push(['rss', s.id]); return { success: true, articles: [] }; };
scraper.scrapeSource = async (s) => { seen.push(['scrape', s.id]); return { success: true, articles: [] }; };
cve.fetchCVEs = async (s) => { seen.push(['nvd', s.id]); return { success: true, articles: [] }; };
cve.fetchCISAKEV = async (s) => { seen.push(['kev', s.id]); return { success: true, articles: [] }; };
const status = [];
fakeDb.updateSourceFetchStatus = (id, st) => status.push({ id, ...st });
void FAKES;
const aggregator = require('../src/feeds/aggregator');

// keep the NVD politeness sleep out of the test
const realSetTimeout = global.setTimeout;
global.setTimeout = (fn, ms, ...a) => realSetTimeout(fn, Math.min(ms || 0, 5), ...a);

test('every dashboard source type is fetched (blog / other / generic API used to be skipped forever)', async () => {
  seen.length = 0; status.length = 0;
  const sources = [
    { id: 1, type: 'rss', url: 'https://a.example/feed', enabled: 1 },
    { id: 2, type: 'blog', url: 'https://b.example/', enabled: 1 },
    { id: 3, type: 'other', url: 'https://c.example/', enabled: 1 },
    { id: 4, type: 'api', url: 'https://d.example/api/feed.xml', enabled: 1 },
    { id: 5, type: 'api', url: 'https://services.nvd.nist.gov/rest/json/cves/2.0', enabled: 1 },
    { id: 6, type: 'api', url: 'https://www.cisa.gov/known_exploited_vulnerabilities.json', enabled: 1 },
    { id: 7, type: 'website', url: 'https://e.example/', enabled: 1 },
    { id: 8, type: 'rss', url: 'https://f.example/feed', enabled: 0 },
  ];
  const r = await aggregator.fetchSources(sources);
  const byId = Object.fromEntries(seen.map(([how, id]) => [id, how]));
  assert.deepEqual(byId, { 1: 'rss', 2: 'scrape', 3: 'scrape', 4: 'rss', 5: 'nvd', 6: 'kev', 7: 'scrape' });
  assert.deepEqual([...new Set(status.map(s => s.id))].sort(), [1, 2, 3, 4, 5, 6, 7], 'each fetched source gets a status');
  assert.equal(r.errors, 0);
  assert.ok(Array.isArray(r.newArticles));
});

test('a targeted fetch does not touch the platform-wide run state', async () => {
  const before = aggregator.getStatus();
  await aggregator.fetchSources([{ id: 9, type: 'rss', url: 'https://g.example/feed', enabled: 1 }]);
  const after = aggregator.getStatus();
  assert.equal(after.isRunning, false);
  assert.equal(after.lastFetchTime, before.lastFetchTime);
});

test("Add Source's default category 'general' means auto-classify; explicit categories still win", () => {
  assert.equal(rss.articleCategory({ category: 'general' }, 'malware'), 'malware');
  assert.equal(rss.articleCategory({ category: 'news' }, 'breach'), 'breach');
  assert.equal(rss.articleCategory({}, 'vulnerability'), 'vulnerability');
  assert.equal(rss.articleCategory({ category: 'advisory' }, 'malware'), 'advisory');
});

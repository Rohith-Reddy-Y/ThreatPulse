'use strict';
// Data journeys: stat cards vs the feed they filter to, new sources being
// fetched for their owner only, "Fetch now" scope/feedback, export scope.
const test = require('node:test');
const assert = require('node:assert');
const { load, makeUser, art, call } = require('./data-helpers');

const HOUR = 3600 * 1000;

// What the dashboard does when "Threats today" is clicked, for a viewer whose
// clock is tz minutes east of UTC: [local midnight, next local midnight - 1ms].
function localTodayBounds(tz, now = Date.now()) {
  const shifted = new Date(now + tz * 60000);
  const midnightShifted = Date.UTC(shifted.getUTCFullYear(), shifted.getUTCMonth(), shifted.getUTCDate());
  const start = midnightShifted - tz * 60000;
  return { start: new Date(start).toISOString(), end: new Date(start + 24 * HOUR - 1).toISOString(),
    day: new Date(midnightShifted).toISOString().slice(0, 10) };
}

test('"threats today" equals the feed filtered to the viewer\'s local today, in every time zone', async () => {
  const env = load();
  const { db } = env;
  const u = makeUser(db);
  for (const hAgo of [0.5, 3, 7, 11, 15, 19, 23, 27, 35, 47]) {
    db.insertArticle(art({ user_id: u.id, published_date: new Date(Date.now() - hAgo * HOUR).toISOString() }));
  }
  for (const tz of [-600, -300, 0, 60, 330, 540, 780]) {
    const stats = await call(env, 'GET', '/articles/stats', { user: u, query: { tz: String(tz) } });
    const b = localTodayBounds(tz);
    const list = await call(env, 'GET', '/articles', { user: u, query: { start_date: b.start, end_date: b.end, time_range: 'custom', limit: '200' } });
    assert.strictEqual(stats.body.threatsToday, list.body.total, `tz ${tz}: stat ${stats.body.threatsToday} vs list ${list.body.total}`);
    const tl = stats.body.timeline.find(t => t.day === b.day);
    assert.strictEqual(tl ? tl.count : 0, list.body.total, `tz ${tz}: timeline day ${b.day}`);
    assert.strictEqual(stats.body.timeline.reduce((s, t) => s + t.count, 0), 10, 'timeline covers every article');
  }
});

test('PoC count uses the same 7-day window as the feed\'s "Last 7 Days" filter', async () => {
  const env = load();
  const { db } = env;
  const u = makeUser(db);
  db.insertArticle(art({ user_id: u.id, has_poc: 1, published_date: new Date(Date.now() - 2 * HOUR).toISOString() }));
  db.insertArticle(art({ user_id: u.id, has_poc: 1, published_date: new Date(Date.now() - (7 * 24 + 6) * HOUR).toISOString() }));
  const stats = await call(env, 'GET', '/articles/stats', { user: u, query: {} });
  const list = await call(env, 'GET', '/articles', { user: u, query: { has_poc: '1', time_range: '7d' } });
  assert.strictEqual(stats.body.pocsDetected, 1);
  assert.strictEqual(list.body.total, stats.body.pocsDetected);
});

test('a bogus tz parameter cannot break the stats', async () => {
  const env = load();
  const u = makeUser(env.db);
  for (const tz of ['abc', '99999', '']) {
    const r = await call(env, 'GET', '/articles/stats', { user: u, query: { tz } });
    assert.strictEqual(r.statusCode, 200, `tz=${tz}`);
    assert.strictEqual(typeof r.body.threatsToday, 'number');
  }
});

// A stand-in for the aggregator (server.js registers the real one on the app)
function fakeAggregator(env, { delayMs = 0 } = {}) {
  const calls = { some: [], all: 0 };
  return {
    calls,
    getStatus: () => ({ isRunning: false }),
    fetchAllSources: async () => { calls.all++; return { newArticles: [] }; },
    fetchSources: async (sources) => {
      calls.some.push(sources.map(s => s.id));
      if (delayMs) await new Promise(r => setTimeout(r, delayMs));
      // emulate the fetchers: one article per source, owned like the source
      const items = sources.map(s => art({ user_id: s.user_id, source_id: s.id, url: `https://ex.test/${s.id}/${Math.random()}` }));
      const r = env.db.insertArticles(items);
      return { total: items.length, new: r.newCount, errors: 0, newArticles: [] };
    },
  };
}

test('adding a source fetches it right away; its articles appear for that user only', async () => {
  const env = load();
  const { db } = env;
  const owner = makeUser(db), other = makeUser(db);
  const agg = fakeAggregator(env);
  const r = await call(env, 'POST', '/sources', { user: owner, app: { aggregator: agg },
    body: { url: 'https://feeds.example.org/rss', name: 'Mine', type: 'rss', category: 'general' } });
  assert.strictEqual(r.statusCode, 201, JSON.stringify(r.body));
  assert.strictEqual(r.body.fetching, true);
  await new Promise(res => setImmediate(res));
  assert.deepStrictEqual(agg.calls.some, [[r.body.id]], 'only the new source is fetched');
  assert.strictEqual(agg.calls.all, 0, 'no platform-wide fetch');
  const mine = await call(env, 'GET', '/articles', { user: owner, query: {} });
  const theirs = await call(env, 'GET', '/articles', { user: other, query: {} });
  assert.strictEqual(mine.body.total, 1);
  assert.strictEqual(theirs.body.total, 0);

  const dup = await call(env, 'POST', '/sources', { user: owner, app: { aggregator: agg },
    body: { url: 'https://feeds.example.org/rss', name: 'Again' } });
  assert.strictEqual(dup.statusCode, 409);
  const bad = await call(env, 'POST', '/sources', { user: owner, app: { aggregator: agg },
    body: { url: 'http://127.0.0.1/feed', name: 'Local' } });
  assert.strictEqual(bad.statusCode, 400);
});

test('Fetch now (user): only their own enabled sources, real result in the response, per-user cooldown', async () => {
  const env = load();
  const { db } = env;
  env.api._resetFetchThrottle();
  const a = makeUser(db), b = makeUser(db);
  const s1 = db.addSource({ name: 'A1', url: 'https://a.example/1', user_id: a.id }).id;
  const s2 = db.addSource({ name: 'A2', url: 'https://a.example/2', user_id: a.id }).id;
  const s3 = db.addSource({ name: 'A3', url: 'https://a.example/3', user_id: a.id }).id;
  db.updateSource(s3, { enabled: 0 });
  db.addSource({ name: 'B1', url: 'https://b.example/1', user_id: b.id });
  db.addSource({ name: 'SYS', url: 'https://sys.example/1', added_by: 'system' });
  const agg = fakeAggregator(env);

  const r = await call(env, 'POST', '/fetch-now', { user: a, app: { aggregator: agg } });
  assert.strictEqual(r.body.success, true, JSON.stringify(r.body));
  assert.strictEqual(r.body.completed, true);
  assert.strictEqual(r.body.scope, 'own');
  assert.strictEqual(r.body.newArticles, 2);
  assert.deepStrictEqual(agg.calls.some, [[s1, s2]]);
  assert.strictEqual(agg.calls.all, 0);

  // Someone else is not blocked by a's cooldown; a is (with a clear message)
  const rb = await call(env, 'POST', '/fetch-now', { user: b, app: { aggregator: agg } });
  assert.strictEqual(rb.body.completed, true);
  const again = await call(env, 'POST', '/fetch-now', { user: a, app: { aggregator: agg } });
  assert.strictEqual(again.statusCode, 429);
  assert.match(again.body.error, /Try again/);

  // No sources → told to add one instead of a fake "Feeds updated"
  const c = makeUser(db);
  const none = await call(env, 'POST', '/fetch-now', { user: c, app: { aggregator: agg } });
  assert.strictEqual(none.statusCode, 400);
  assert.match(none.body.error, /no enabled sources/);
});

test('Fetch now (admin): full background run, honest "started" response', async () => {
  const env = load();
  const admin = makeUser(env.db, { role: 'admin' });
  const agg = fakeAggregator(env);
  const r = await call(env, 'POST', '/fetch-now', { user: admin, app: { aggregator: agg } });
  assert.strictEqual(r.body.success, true);
  assert.strictEqual(r.body.scope, 'all');
  assert.strictEqual(r.body.completed, false);
  assert.match(r.body.message, /several minutes/);
  assert.strictEqual(agg.calls.all, 1);
  agg.getStatus = () => ({ isRunning: true });
  const busy = await call(env, 'POST', '/fetch-now', { user: admin, app: { aggregator: agg } });
  assert.strictEqual(busy.body.alreadyRunning, true);
  assert.strictEqual(agg.calls.all, 1);
});

test('export pages (limit 200) stay within the viewer\'s scope and match the filtered total', async () => {
  const env = load();
  const { db } = env;
  const u = makeUser(db), other = makeUser(db);
  for (let i = 0; i < 230; i++) db.insertArticle(art({ user_id: u.id, severity: i % 2 ? 'high' : 'low' }));
  for (let i = 0; i < 5; i++) db.insertArticle(art({ user_id: other.id, severity: 'high' }));
  // The export button walks the same endpoint page by page
  const seen = [];
  let page = 1, totalPages = 1, total = 0;
  do {
    const r = await call(env, 'GET', '/articles', { user: u, query: { severity: 'high', page: String(page), limit: '200' } });
    seen.push(...r.body.articles); totalPages = r.body.totalPages; total = r.body.total; page++;
  } while (page <= totalPages);
  assert.strictEqual(total, 115);
  assert.strictEqual(seen.length, 115);
  assert.strictEqual(new Set(seen.map(a => a.id)).size, 115);
  assert.ok(seen.every(a => a.user_id === u.id && a.severity === 'high'));
});

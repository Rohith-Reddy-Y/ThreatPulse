// Ransomware.live fetcher (replacement for the archived RansomWatch feed).
const { state, calls, reset } = require('./helpers/stubs');
const test = require('node:test');
const assert = require('node:assert/strict');

// Fresh module per test so the hourly cache starts empty.
function freshDarkweb() {
  delete require.cache[require.resolve('../src/feeds/darkweb-fetcher')];
  return require('../src/feeds/darkweb-fetcher');
}

const ago = (h) => new Date(Date.now() - h * 3600e3).toISOString();

const sample = [
  { victim: 'genica.com.ve', group: 'lockbit5', discovered: ago(2), attackdate: ago(5), country: 'VE',
    activity: 'Other', description: 'Pharma company', url: 'https://www.ransomware.live/id/Z2VuaWNh' },
  { victim: 'Acme Corp', group: 'play', discovered: ago(30), url: 'https://www.ransomware.live/id/QWNtZQ' },
  { victim: 'Old Victim', group: 'akira', discovered: ago(24 * 20), url: 'https://www.ransomware.live/id/T2xk' },
  { victim: '<img src=x>', group: 'qilin', discovered: ago(1), url: 'javascript:alert(1)' },
];

test('maps recent victims to articles, skips >7-day-old posts, no abuse.ch key sent', async () => {
  reset();
  process.env.ABUSE_CH_API_KEY = 'secret-key';
  const dw = freshDarkweb();
  state.axiosGet = async () => ({ data: sample });
  const r = await dw.fetchRansomwareLive({ id: 7, user_id: null });
  assert.equal(r.success, true);
  assert.equal(r.articles.length, 3);               // 20-day-old one dropped
  const a = r.articles[0];
  assert.match(a.title, /genica\.com\.ve \(lockbit5\)/);
  assert.equal(a.url, 'https://www.ransomware.live/id/Z2VuaWNh');
  assert.equal(a.category, 'darkweb');
  assert.equal(a.source_id, 7);
  assert.match(a.description, /Country: VE/);
  assert.equal((calls.axiosGet[0].config.headers || {})['Auth-Key'], undefined);
});

test('non-ransomware.live URLs from the API are not trusted as article links', async () => {
  reset();
  const dw = freshDarkweb();
  state.axiosGet = async () => ({ data: sample });
  const { articles } = await dw.fetchRansomwareLive({ id: 1 });
  const bad = articles.find(a => a.author === 'qilin');
  assert.match(bad.url, /^https:\/\/www\.ransomware\.live\/group\/qilin#/);
});

test('every victim gets its own URL (DB dedupes on URL)', async () => {
  reset();
  const dw = freshDarkweb();
  state.axiosGet = async () => ({ data: sample });
  const { articles } = await dw.fetchRansomwareLive({ id: 1 });
  assert.equal(new Set(articles.map(a => a.url)).size, articles.length);
});

test('API is called at most once per hour (rate-limited API)', async () => {
  reset();
  const dw = freshDarkweb();
  state.axiosGet = async () => ({ data: sample });
  await dw.fetchRansomwareLive({ id: 1 });
  await dw.fetchRansomwareLive({ id: 1 });
  await dw.fetchRansomwareLive({ id: 1 });
  assert.equal(calls.axiosGet.length, 1);
});

test('API errors and non-array payloads are handled without throwing', async () => {
  reset();
  let dw = freshDarkweb();
  state.axiosGet = async () => { throw new Error('429 Too Many Requests'); };
  const r1 = await dw.fetchRansomwareLive({ id: 1 });
  assert.equal(r1.success, false);
  assert.match(r1.error, /429/);

  reset();
  dw = freshDarkweb();
  state.axiosGet = async () => ({ data: { error: 'nope' } });
  const r2 = await dw.fetchRansomwareLive({ id: 1 });
  assert.equal(r2.success, true);
  assert.equal(r2.articles.length, 0);
});

test('dispatcher routes the default source URL to the ransomware.live fetcher', async () => {
  reset();
  const dw = freshDarkweb();
  state.axiosGet = async () => ({ data: sample });
  const { results } = await dw.fetchDarkWebIntel([
    { id: 9, name: 'Ransomware.live - Ransomware Leak Tracker', url: 'https://api.ransomware.live/v2/recentvictims' }
  ]);
  assert.equal(results[0].success, true);
  assert.equal(results[0].count, 3);
  assert.equal(calls.axiosGet[0].url, 'https://api.ransomware.live/v2/recentvictims');
});

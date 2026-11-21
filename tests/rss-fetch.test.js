// Feed parsing (sanitizeXml / lenientParse), Google News fallback and
// failure counting in rss-fetcher.js — network replaced by the axios stub.
const { state, calls, reset, defaultParseString } = require('./helpers/stubs');
const test = require('node:test');
const assert = require('node:assert/strict');
const dns = require('dns');
const r = require('../src/feeds/rss-fetcher');
const I = r._internal || {};

// safeGet resolves hosts through dns.lookup — answer with a public address.
dns.lookup = (host, opts, cb) => { if (typeof opts === 'function') cb = opts; cb(null, [{ address: '93.184.216.34', family: 4 }]); };

test('CVSS extraction edge cases', () => {
  const x = I.extractCvssScore;
  assert.equal(x('has a CVSS score of 9.8.'), 9.8);               // sentence end
  assert.equal(x('(CVSS 9.8)'), 9.8);
  assert.equal(x('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H'), null); // vector, no score
  assert.equal(x('CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N'), null);
  assert.equal(x('CVSS v3.1 base score unavailable'), null);       // version, no score
  assert.equal(x('CVSS v3.1 base score: 8.1'), 8.1);
  assert.equal(x('CVSS 3.1 base score 8.1'), 8.1);
  assert.equal(x('CVSSv3: 7.5'), 7.5);
  assert.equal(x('CVSS 4.0 score of 9.3'), 9.3);
  assert.equal(x('CVSS score: 10'), 10);
  assert.equal(x('CVSS 10.0/10'), 10);
  assert.equal(x('CVSS score: N/A'), null);
  assert.equal(x('rated CVSS 9.8/10'), 9.8);
  assert.equal(x('CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H (base score 9.8)'), null);
  assert.equal(x('CVSS v3.1 (9.8)'), 9.8);
});

test('sanitizeXml: bare & escaped, valid entity references untouched', () => {
  const s = I.sanitizeXml('<t>Q&A &amp; a=1&b=2 &#8217; &#x2019; Microsoft&rsquo;s</t>');
  assert.equal(s, '<t>Q&amp;A &amp; a=1&amp;b=2 &#8217; &#x2019; Microsoft&rsquo;s</t>');
});

test('lenientParse: CDATA, entities (incl. HTML named), RDF items', () => {
  const xml = `<?xml version="1.0"?><rdf:RDF><channel><items><rdf:Seq/></items></channel>
    <item rdf:about="https://ex.com/1"><title><![CDATA[Microsoft&rsquo;s fix & more]]></title>
      <link>https://ex.com/1?a=1&amp;b=2</link><dc:date>2026-11-20T10:00:00Z</dc:date>
      <description>&lt;p&gt;Hello&nbsp;world &mdash; ok&lt;/p&gt;</description></item></rdf:RDF>`;
  const items = I.lenientParse(xml);
  assert.equal(items.length, 1);
  assert.equal(items[0].title, 'Microsoft’s fix & more');
  assert.equal(items[0].link, 'https://ex.com/1?a=1&b=2');
  assert.equal(items[0].isoDate, '2026-11-20T10:00:00.000Z');
  assert.equal(I.stripHtml(items[0].content), 'Hello world — ok');
});

test('lenientParse: Atom entry picks rel="alternate", not the replies/edit link (Blogger order)', () => {
  const xml = `<feed><entry><title>Post</title>
    <link rel='replies' type='application/atom+xml' href='https://blog.ex.com/feeds/1/comments/default'/>
    <link rel='edit' href='https://www.blogger.com/feeds/1/posts/default/2'/>
    <link rel='alternate' type='text/html' href='https://blog.ex.com/2026/11/post.html'/>
    <updated>2026-11-20T10:00:00Z</updated></entry></feed>`;
  const [item] = I.lenientParse(xml);
  assert.equal(item.link, 'https://blog.ex.com/2026/11/post.html');
});

test('lenientParse: linear on unclosed <item> tags (was quadratic: ~1.5 s for 440 KB)', () => {
  const bad = '<rss>' + '<item><title>x</title>'.repeat(20000) + '</rss>';
  const t0 = Date.now();
  assert.deepEqual(I.lenientParse(bad), []);
  assert.ok(Date.now() - t0 < 200, `took ${Date.now() - t0} ms`);
});

test('stripHtml decodes numeric and named entities exactly once', () => {
  assert.equal(I.stripHtml('<p>It&#8217;s &amp;lt;b&amp;gt; &quot;x&quot;&nbsp;y</p>'), 'It’s &lt;b&gt; "x" y');
});

test('Google News title cleanup keeps hyphenated headlines, drops hyphenated publishers', () => {
  assert.equal(I.cleanGoogleNewsTitle('CVE-2024-1234 - Critical flaw in X - SecurityWeek'), 'CVE-2024-1234 - Critical flaw in X');
  assert.equal(I.cleanGoogleNewsTitle('New flaw in X - Security-Insider'), 'New flaw in X');
  assert.equal(I.cleanGoogleNewsTitle('No publisher suffix'), 'No publisher suffix');
});

function rss(items) {
  return `<rss><channel>${items.map(t => `<item><title>${t}</title><link>https://ex.com/${encodeURIComponent(t)}</link></item>`).join('')}</channel></rss>`;
}
function httpError(status) { const e = new Error(`Request failed with status code ${status}`); e.response = { status }; return e; }
function netError(code) { const e = new Error(`getaddrinfo ${code}`); e.code = code; return e; }

test('Google News fallback: never widens "ncsc.gov.uk" to "gov.uk"', async () => {
  reset(); I.fallbackCache.clear();
  state.axiosGet = async (url) => {
    if (url.startsWith('https://www.ncsc.gov.uk/')) throw httpError(403);
    const q = decodeURIComponent(new URL(url).searchParams.get('q'));
    if (q.startsWith('site:gov.uk')) return { data: rss(['Unrelated gov.uk story - GOV.UK']) };
    return { data: rss([]) };
  };
  const res = await r.fetchRSSFeed({ id: 9001, name: 'NCSC', url: 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml', category: 'advisory' });
  const queries = calls.axiosGet.map(c => c.url).filter(u => u.includes('news.google.com')).map(u => decodeURIComponent(new URL(u).searchParams.get('q')));
  assert.ok(!queries.some(q => q.startsWith('site:gov.uk')), `queried ${queries.join(' | ')}`);
  assert.equal(res.success, false);
});

test('Google News fallback: parent-domain retry still works for blog subdomains', async () => {
  reset(); I.fallbackCache.clear();
  state.axiosGet = async (url) => {
    if (url.startsWith('https://news.sophos.com/')) throw httpError(403);
    const q = decodeURIComponent(new URL(url).searchParams.get('q'));
    if (q === 'site:sophos.com when:30d') return { data: rss(['Sophos story - Sophos News']) };
    return { data: rss([]) };
  };
  const res = await r.fetchRSSFeed({ id: 9002, name: 'Sophos', url: 'https://news.sophos.com/en-us/feed/', category: 'news' });
  assert.equal(res.success, true);
  assert.equal(res.articles[0].title, 'Sophos story');
});

test('Google News fallback: an HTTP error from Google is cached (no re-query every cycle)', async () => {
  reset(); I.fallbackCache.clear();
  state.axiosGet = async (url) => { throw httpError(url.includes('news.google.com') ? 429 : 403); };
  const src = { id: 9003, name: 'Blocked', url: 'https://blocked.example.org/feed', category: 'news' };
  await r.fetchRSSFeed(src);
  await r.fetchRSSFeed(src);
  const gn = calls.axiosGet.filter(c => c.url.includes('news.google.com')).length;
  assert.equal(gn, 1);
});

test('outage: network down for 5+ cycles does not auto-disable sources', async () => {
  reset(); I.fallbackCache.clear(); I.failureTracker.clear();
  state.axiosGet = async () => { throw netError('EAI_AGAIN'); };
  const src = { id: 9004, name: 'Healthy feed', url: 'https://healthy.example.org/feed', category: 'news' };
  for (let i = 0; i < 6; i++) await r.fetchRSSFeed(src);
  assert.deepEqual(calls.updateSource, []);
});

test('dead source (Google reachable but nothing found) is still auto-disabled after 5 failures', async () => {
  reset(); I.fallbackCache.clear(); I.failureTracker.clear();
  state.axiosGet = async (url) => { if (url.includes('news.google.com')) return { data: rss([]) }; throw httpError(404); };
  const src = { id: 9005, name: 'Dead feed', url: 'https://dead.example.org/feed', category: 'news' };
  for (let i = 0; i < 5; i++) { I.fallbackCache.clear(); await r.fetchRSSFeed(src); }
  assert.deepEqual(calls.updateSource, [{ id: 9005, updates: { enabled: 0 } }]);
});

test('one malformed item (title as {_ , $}) does not fail the whole feed', async () => {
  reset(); I.fallbackCache.clear(); I.failureTracker.clear();
  state.parseString = async () => ({ items: [
    { title: { _: 'Attributed title', $: { type: 'html' } }, link: 'https://ex.com/a' },
    { title: 'Normal title', link: 'https://ex.com/b' },
  ] });
  state.axiosGet = async () => ({ data: rss(['ignored']) });
  try {
    const res = await r.fetchRSSFeed({ id: 9006, name: 'Odd feed', url: 'https://odd.example.org/feed', category: 'news' });
    assert.equal(res.success, true);
    assert.equal(res.via, undefined);
    assert.deepEqual(res.articles.map(a => a.title), ['Attributed title', 'Normal title']);
  } finally {
    state.parseString = defaultParseString;
  }
});

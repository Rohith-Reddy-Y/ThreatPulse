// web-scraper link resolution / category, browser-fetcher SSRF guard
const { state, FAKES, reset } = require('./helpers/stubs');
const test = require('node:test');
const assert = require('node:assert/strict');
const dns = require('dns');
dns.lookup = (host, opts, cb) => { if (typeof opts === 'function') cb = opts; cb(null, [{ address: '93.184.216.34', family: 4 }]); };

// Minimal cheerio stand-in: an index page whose only article links are `h2 a[href]`.
function fakeCheerio(links) {
  const wrap = (el) => ({ attr: (k) => el[k], text: () => el.text, first: () => wrap(el) });
  const $ = (sel) => {
    if (typeof sel === 'object') return wrap(sel);
    const els = sel === 'h2 a[href]' ? links : [];
    return { each: (fn) => els.forEach((el, i) => fn(i, el)), attr: () => undefined, text: () => '', first: () => ({ text: () => '' }) };
  };
  return $;
}

test('scraper: relative and protocol-relative links resolve correctly; category is detected', async () => {
  reset();
  FAKES.cheerio.load = () => fakeCheerio([
    { href: '/2026/11/critical-flaw', text: 'Critical Ivanti flaw exploited in attacks' },
    { href: '//cdn.other.example/post', text: 'Ransomware gang hits hospital' },
    { href: 'posts/123', text: 'Weekly webinar recap' },
  ]);
  state.axiosGet = async () => ({ data: '<html></html>' });
  const { scrapeSource } = require('../src/feeds/web-scraper');
  const res = await scrapeSource({ id: 1, name: 'Blog', url: 'https://blog.example.com/news/', category: 'news' });
  assert.equal(res.success, true);
  assert.deepEqual(res.articles.map(a => a.url), [
    'https://blog.example.com/2026/11/critical-flaw',
    'https://cdn.other.example/post',
    'https://blog.example.com/news/posts/123',
  ]);
  assert.deepEqual(res.articles.map(a => a.category), ['vulnerability', 'malware', 'news']);
  assert.equal(res.articles[0].severity, 'critical');
});

test('scraper: an explicit non-news source category still wins', async () => {
  FAKES.cheerio.load = () => fakeCheerio([{ href: '/a', text: 'Ransomware gang hits hospital' }]);
  state.axiosGet = async () => ({ data: '<html></html>' });
  const { scrapeSource } = require('../src/feeds/web-scraper');
  const res = await scrapeSource({ id: 2, name: 'Advisories', url: 'https://vendor.example.com/', category: 'advisory' });
  assert.equal(res.articles[0].category, 'advisory');
});

test('browser-fetcher: internal URLs are refused before Chrome navigates to them', async () => {
  let pages = 0;
  FAKES['puppeteer-core'] = {
    launch: async () => ({
      newPage: async () => { pages++; throw new Error('should not navigate'); },
      close: async () => {},
    }),
  };
  process.env.PUPPETEER_EXECUTABLE_PATH = process.execPath;   // any existing file
  delete process.env.DISABLE_BROWSER_FETCH;
  const bf = require('../src/feeds/browser-fetcher');
  assert.equal(bf.isAvailable(), true);
  const { results } = await bf.fetchViaBrowser([
    { id: 1, name: 'meta', url: 'http://169.254.169.254/latest/meta-data/' },
    { id: 2, name: 'local', url: 'http://localhost:8080/admin' },
  ]);
  assert.equal(pages, 0);
  assert.ok(results.every(r => !r.success && /blocked/i.test(r.error)), JSON.stringify(results));
});

// Fox-IT style index: none of the blog selectors match, only plain <a href> links.
function fakeCheerioPlainLinks(links) {
  const wrap = (el) => ({ attr: (k) => el[k], text: () => el.text, first: () => wrap(el) });
  const $ = (sel) => {
    if (typeof sel === 'object') return wrap(sel);
    const els = sel === 'a[href]' ? links : [];
    return { each: (fn) => els.forEach((el, i) => fn(i, el)), attr: () => undefined, text: () => '', first: () => ({ text: () => '' }) };
  };
  return $;
}

test('scraper: generic fallback picks slug links one level below the index path', async () => {
  reset();
  FAKES.cheerio.load = () => fakeCheerioPlainLinks([
    { href: '/nl/research/when-picos-attack-usb-exploit-engineering/', text: 'When Picos Attack' },
    { href: '/nl/research/releasing-the-cobalt-strike-beacon-corpus/', text: 'Cobalt Strike Beacon Corpus' },
    { href: '/nl/research/', text: 'Research' },                       // the index itself
    { href: '/nl/research/page/2/', text: 'Next' },                    // pagination
    { href: '/nl/contact/', text: 'Contact' },                         // outside the index path
    { href: 'https://evil.example/nl/research/fake-post-here/', text: 'x' }, // other host
    { href: '/nl/research/when-picos-attack-usb-exploit-engineering/#comments', text: 'dup' },
  ]);
  state.axiosGet = async () => ({ data: '<html></html>' });
  delete require.cache[require.resolve('../src/feeds/web-scraper')];
  const { scrapeSource } = require('../src/feeds/web-scraper');
  const res = await scrapeSource({ id: 2, name: 'Fox-IT', url: 'https://www.fox-it.com/nl/research/', category: 'threat_intel' });
  assert.equal(res.success, true);
  assert.deepEqual(res.articles.map(a => a.url), [
    'https://www.fox-it.com/nl/research/when-picos-attack-usb-exploit-engineering/',
    'https://www.fox-it.com/nl/research/releasing-the-cobalt-strike-beacon-corpus/',
  ]);
});

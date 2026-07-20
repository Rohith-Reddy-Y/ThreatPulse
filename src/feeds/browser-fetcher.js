/**
 * ThreatPulse — Headless-Browser Feed Fetcher
 *
 * Some worthy feeds sit behind Cloudflare/Akamai bot protection and return 403
 * to plain HTTP clients (even with a browser User-Agent). This fetcher drives a
 * real Chrome via puppeteer-core to pass the JS challenge, then reads the raw
 * feed XML from the page context (same-origin fetch → clean RSS/Atom).
 *
 * Fully optional & self-degrading:
 *   - puppeteer-core is an OPTIONAL dependency (require is wrapped in try/catch)
 *   - Chrome is auto-detected across OSes (or PUPPETEER_EXECUTABLE_PATH / CHROME_PATH)
 *   - if neither is present (e.g. a slim production container), isAvailable()
 *     returns false and the aggregator simply skips these sources.
 *   - set DISABLE_BROWSER_FETCH=1 to force it off.
 */

const fs = require('fs');
const RSSParser = require('rss-parser');
const { detectCategory, detectSeverity, extractCVE, detectPOC, detectPatchStatus } = require('./rss-fetcher');

const UA = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36';
const parser = new RSSParser({ timeout: 20000 });

let puppeteer = null;
try { puppeteer = require('puppeteer-core'); } catch (_) { puppeteer = null; }

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

function detectChromePath() {
  const envPaths = [process.env.PUPPETEER_EXECUTABLE_PATH, process.env.CHROME_PATH];
  for (const p of envPaths) { if (p && safeExists(p)) return p; }
  const candidates = [
    // Windows
    'C:/Program Files/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Google/Chrome/Application/chrome.exe',
    (process.env.LOCALAPPDATA || '') + '/Google/Chrome/Application/chrome.exe',
    'C:/Program Files (x86)/Microsoft/Edge/Application/msedge.exe',
    // macOS
    '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
    '/Applications/Chromium.app/Contents/MacOS/Chromium',
    // Linux
    '/usr/bin/google-chrome',
    '/usr/bin/google-chrome-stable',
    '/usr/bin/chromium',
    '/usr/bin/chromium-browser',
    '/snap/bin/chromium'
  ];
  for (const c of candidates) { if (c && safeExists(c)) return c; }
  return null;
}

function safeExists(p) { try { return fs.existsSync(p); } catch (_) { return false; } }

function isAvailable() {
  if (process.env.DISABLE_BROWSER_FETCH === '1') return false;
  return !!(puppeteer && detectChromePath());
}

function stripHtml(html) {
  if (!html) return '';
  return String(html)
    .replace(/<[^>]*>/g, '')
    .replace(/&nbsp;/g, ' ').replace(/&amp;/g, '&').replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'")
    .replace(/\s+/g, ' ').trim().substring(0, 1000);
}

function normalize(item, source) {
  const title = (item.title || 'Untitled').trim();
  const description = stripHtml(item.contentSnippet || item.content || item['content:encoded'] || item.summary || '');
  const category = detectCategory(title, description);
  return {
    title,
    description,
    url: item.link || item.guid || source.url,
    source_name: source.name,
    source_type: 'rss', // it IS an RSS/Atom feed — browser is only the transport
    source_id: source.id,
    user_id: source.user_id || null,
    author: item.creator || item.author || item['dc:creator'] || null,
    published_date: item.isoDate || item.pubDate || new Date().toISOString(),
    category: source.category && source.category !== 'news' ? source.category : category,
    severity: detectSeverity(title, description, category),
    cve_id: extractCVE(`${title} ${description}`),
    is_patched: detectPatchStatus(title, description),
    has_poc: detectPOC(title, description),
    tags: null
    // sector / threat_actors / mitre_ids are filled centrally in database.insertArticle
  };
}

async function fetchFeedText(browser, feedUrl) {
  const page = await browser.newPage();
  try {
    await page.setUserAgent(UA);
    await page.setExtraHTTPHeaders({ 'Accept-Language': 'en-US,en;q=0.9' });
    await page.evaluateOnNewDocument(() => {
      Object.defineProperty(navigator, 'webdriver', { get: () => undefined });
    });
    await page.goto(feedUrl, { waitUntil: 'domcontentloaded', timeout: 50000 });
    // Wait out a Cloudflare interstitial if one is shown.
    for (let i = 0; i < 6; i++) {
      const t = await page.title().catch(() => '');
      if (!/just a moment|attention required|checking your browser/i.test(t)) break;
      await sleep(3000);
    }
    await sleep(1200);
    // Same-origin fetch now carries the clearance cookie → raw feed XML.
    return await page.evaluate(async (u) => {
      try { const r = await fetch(u, { credentials: 'include' }); return { status: r.status, text: await r.text() }; }
      catch (e) { return { status: 0, text: '', err: String(e.message || e) }; }
    }, feedUrl);
  } finally {
    await page.close().catch(() => {});
  }
}

/**
 * Fetch an array of browser-type sources. Returns { articles, results } where
 * results is per-source { source, success, count|error } for status logging.
 */
async function fetchViaBrowser(sources) {
  if (!isAvailable()) {
    return {
      articles: [],
      results: sources.map((s) => ({ source: s, success: false, error: 'Headless browser not available on this host' }))
    };
  }

  let browser;
  try {
    browser = await puppeteer.launch({
      executablePath: detectChromePath(),
      headless: true,
      args: ['--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--disable-blink-features=AutomationControlled', '--window-size=1400,900']
    });
  } catch (e) {
    return {
      articles: [],
      results: sources.map((s) => ({ source: s, success: false, error: 'Browser launch failed: ' + e.message }))
    };
  }

  const articles = [];
  const results = [];
  try {
    for (const source of sources) {
      try {
        const res = await fetchFeedText(browser, source.url);
        const body = res.text || '';
        if (res.status !== 200 || !/<rss|<feed|<\?xml/i.test(body.slice(0, 1000))) {
          results.push({ source, success: false, error: `Browser fetch HTTP ${res.status}${res.err ? ' (' + res.err + ')' : ''}` });
          continue;
        }
        const feed = await parser.parseString(body);
        const arts = (feed.items || []).map((item) => normalize(item, source));
        articles.push(...arts);
        results.push({ source, success: true, count: arts.length });
      } catch (e) {
        results.push({ source, success: false, error: String(e.message || 'parse error').slice(0, 120) });
      }
    }
  } finally {
    await browser.close().catch(() => {});
  }
  return { articles, results };
}

module.exports = { fetchViaBrowser, isAvailable, detectChromePath };

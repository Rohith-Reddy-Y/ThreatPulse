/**
 * ThreatPulse — RSS Feed Fetcher
 * Fetches and parses RSS/Atom feeds from cybersecurity sources
 */

const RSSParser = require('rss-parser');
const { safeGet } = require('../net-guard');
// Shared, source-agnostic enrichment (sector / threat actors / MITRE IDs)
const { detectSector, detectThreatActors, extractMitreIds } = require('../enrich');

const FEED_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': 'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/html;q=0.8, */*;q=0.7',
    'Accept-Language': 'en-US,en;q=0.9',
    'Cache-Control': 'no-cache'
};

const parser = new RSSParser({
  timeout: 30000,
  headers: FEED_HEADERS,
  customFields: {
    item: [
      ['dc:creator', 'creator'],
      ['content:encoded', 'contentEncoded'],
      ['dc:date', 'dcDate']
    ]
  }
});

// Track consecutive failures to auto-disable dead sources
const failureTracker = new Map();
const MAX_CONSECUTIVE_FAILURES = 5;

// ============================================
// CLASSIFICATION (word-boundary aware)
// Earlier versions matched raw substrings, so "rce" hit "source"/"resource",
// "apt" hit "adapt"/"laptop", "tor " hit "monitor", "low" hit "follow" —
// which badly inflated "critical" counts and mis-categorised articles.
// ============================================

const CATEGORY_RULES = [
  ['vulnerability', [
    /\bCVE[-\u2010-\u2013]\d{4}[-\u2010-\u2013]\d{4,}\b/i, /\bvulnerabilit(y|ies)\b/i, /\bvulns?\b/i, /\bexploit(s|ed|ation|ing)?\b/i,
    /\bRCE\b/, /\bremote code execution\b/i, /\bXSS\b/, /\bcross[- ]site scripting\b/i,
    /\bSQL ?injection\b/i, /\bSQLi\b/, /\bbuffer overflow\b/i, /\b(zero|0)[- ]days?\b(?!\s+(protection|defen[cs]e|prevention|initiative|program))/i,
    /\bsecurity (flaw|bug|hole)s?\b/i, /\bflaws?\b/i, /\bbugs?\b(?![- ]bount)/i, /\bprivilege escalation\b/i, /\bauthentication bypass\b/i
  ]],
  ['malware', [
    /\b(malware|trojans?|ransomware|botnets?|backdoors?|rootkits?|spyware|infostealers?|stealers?|wipers?|worms?|loaders?|droppers?)\b/i,
    /\bRATs?\b/, /\bremote access trojan\b/i
  ]],
  ['breach', [
    /\bdata breach(es)?\b/i, /\bbreach(ed|es)?\b/i, /(?<!memory )\bleak(ed|s)?\b/i, /\bhack(ed|ers?|ing)?\b/i,
    /\bcompromised\b/i, /\bstolen (data|credentials|records)\b/i, /\bexposed (data|records|database|personal)\b/i
  ]],
  ['advisory', [
    /\badvisor(y|ies)\b/i, /\bsecurity (update|bulletin|notice|alert)s?\b/i, /\bpatch(es|ed)?\b/i,
    /\bPatch Tuesday\b/i, /\bbulletin\b/i
  ]],
  ['threat_intel', [
    /\bAPT ?-?\d*\b/, /\bthreat (actor|group)s?\b/i, /\bcampaigns?\b/i, /\bnation[- ]state\b/i,
    /\bstate[- ]sponsored\b/i, /\bespionage\b/i, /\bcyber ?-?attacks?\b/i, /\bTTPs?\b/
  ]],
  ['darkweb', [
    /\bdark ?web\b/i, /\bdarknet\b/i, /\bunderground (forum|market)s?\b/i, /\.onion\b/i,
    /\bTor (network|browser|hidden)\b/i, /\bleak sites?\b/i
  ]]
];

function classifyText(text) {
  for (const [category, patterns] of CATEGORY_RULES) {
    if (patterns.some(re => re.test(text))) return category;
  }
  return null;
}

/**
 * Detect category from content/title. The title is the strongest signal, so it
 * is classified on its own first; the body is only used when the title is generic.
 */
function detectCategory(title, description) {
  return classifyText(title || '') || classifyText(`${title || ''} ${description || ''}`) || 'news';
}

/**
 * Pull a CVSS base score out of text: "CVSS 9.8", "CVSS score of 9.8",
 * "CVSSv3.1: 7.5", "CVSS 3.1 base score 8.1".
 */
// group 1 = CVSS version ("v3.1"), group 2 = score. The score must not be
// followed by more digits, ".digit" (so "9.8." at a sentence end is fine) or
// "/letter" (vector strings such as "CVSS:3.1/AV:N/..." carry the version, not
// a score; "9.8/10" is still a score).
const CVSS_RE = /\bcvss(?:[\s:]*v?\s?([234](?:\.[01])?)(?!\d|\.\d))?[^0-9\n]{0,25}?(10(?:\.0)?|[0-9]\.[0-9]|[0-9])(?!\d|\.\d|\/[a-z])/gi;

function extractCvssScore(text) {
  const str = String(text || '');
  CVSS_RE.lastIndex = 0;
  let m;
  while ((m = CVSS_RE.exec(str)) !== null) {
    // If the version group was skipped, the engine may have backtracked onto the
    // version number itself ("CVSS v3.1 score unavailable" -> 3.1): reject that.
    const gap = m[0].slice(4, m[0].length - m[2].length);
    if (m[1] === undefined && /^[\s:]*v?\s?$/i.test(gap) && /^[234](\.[01])?$/.test(m[2])) continue;
    const v = parseFloat(m[2]);
    if (v >= 0 && v <= 10) return v;
  }
  return null;
}

const SEVERITY_RULES = {
  critical: [
    /\bactively[- ]exploited\b/i, /\bexploited in (the wild|attacks)\b/i, /\bunder active (exploitation|attack)\b/i,
    /\b(zero|0)[- ]days?\b(?!\s+(protection|defen[cs]e|prevention|initiative|program))/i,
    // "critical flaw" but also "critical IOS XE flaw" / "critical FortiOS SSL-VPN vulnerability"
    /\bcritical\b(?![- ]infrastructure)[^.!?\n]{0,30}?\b(severity|vulnerabilit(y|ies)|flaws?|bugs?|rce|remote code|security (flaw|bug|issue|update|patch|fix))/i,
    /\bmax(imum)?[- ]severity\b/i,
    /\b(severity|rated|rating)[:\s]+critical\b/i,
    /\bknown exploited vulnerabilit/i, /\bKEV\b/,
    /\bemergency (patch|update|directive|fix)/i,
    /\b(unauthenticated|pre-?auth(entication)?)\b[^.\n]{0,60}\b(remote code execution|RCE|code execution)\b/i,
    /\bwormable\b/i
  ],
  high: [
    /\bremote code execution\b/i, /\bRCE\b/, /\bhigh[- ]severity\b/i, /\b(severity|rated|rating)[:\s]+high\b/i,
    /\bprivilege escalation\b/i, /\bauth(entication)? bypass\b/i, /\bsandbox escape\b/i,
    /\bransomware attack/i, /\bdata breach\b/i, /\bsupply[- ]chain (attack|compromise)\b/i,
    /\bbackdoor(ed)?\b/i, /\bproof[- ]of[- ]concept\b/i, /\bPoC\b/,
    /\b(account|device|server|full|complete) takeover\b/i, /\btake (full )?(control|over)\b/i
  ],
  medium: [
    /\b(medium|moderate)[- ]severity\b/i, /\b(severity|rated|rating)[:\s]+(medium|moderate)\b/i,
    /\bcross[- ]site scripting\b/i, /\bXSS\b/, /\bdenial[- ]of[- ]service\b/i, /\bDoS\b/,
    /\binformation disclosure\b/i, /\bphishing\b/i
  ],
  low: [
    /\blow[- ]severity\b/i, /\b(severity|rated|rating)[:\s]+low\b/i, /\binformational\b/i
  ]
};

/**
 * Detect severity: a stated CVSS score wins; otherwise the strongest keyword
 * signal; otherwise a conservative default by category.
 */
function detectSeverity(title, description, category) {
  const text = `${title || ''} ${description || ''}`;
  const keywordText = text.replace(NEGATED_POC_RE, ' ');   // "no public PoC" is no signal

  const score = extractCvssScore(text);
  if (score !== null) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    return 'low';
  }

  for (const level of ['critical', 'high', 'medium', 'low']) {
    if (SEVERITY_RULES[level].some(re => re.test(keywordText))) return level;
  }

  // No explicit signal: security-relevant categories default to medium,
  // general news to low (so it doesn't drown out real issues).
  if (['vulnerability', 'malware', 'breach', 'advisory', 'threat_intel', 'darkweb'].includes(category)) return 'medium';
  return 'low';
}

/**
 * Extract CVE IDs from text
 */
function extractCVE(text) {
  if (!text) return null;
  // Some publishers use non-breaking / en dashes ("CVE\u20112024\u20113400")
  const match = text.match(/\bCVE[-\u2010-\u2013](\d{4})[-\u2010-\u2013](\d{4,})\b/i);
  return match ? `CVE-${match[1]}-${match[2]}` : null;
}

/**
 * Detect if a public exploit / PoC is mentioned
 */
// "no public exploit", "not aware of any public exploits", "no PoC is available"
const NEGATED_POC_RE = /\b(no|not aware of any|no known|nor any|without (a |any )?|lack of|absence of)\s+(publicly[- ]available |public |known |working |functional )*(proof[- ]of[- ]concept|PoC|exploit(s| code)?)\b/gi;

function detectPOC(title, description) {
  const text = `${title || ''} ${description || ''}`.replace(NEGATED_POC_RE, ' ');
  return /\bproof[- ]of[- ]concept\b|\bPoC\b|\bexploit[- ]code\b|\b(public|working|functional) exploits?\b|\bexploits? (is |are |has been |have been )?(now )?(available|released|published)\b|\bweaponi[sz]ed\b|\bexploit-db\b|\bmetasploit\b|github\.com\/\S*exploit/i.test(text) ? 1 : 0;
}

/**
 * Detect patch status: 1 = patched, 0 = unpatched, -1 = unknown
 */
function detectPatchStatus(title, description) {
  const text = `${title || ''} ${description || ''}`;
  if (/\bun(patched|fixed)\b|\bno (fix|patch)(es)?\b|\bnot (yet )?(been )?(patched|fixed)\b|\bwithout a (fix|patch)\b|\b(patch|fix)(es)? (is |are )?not (yet )?available\b|\byet to (be )?(patch|fix)|\b(will|to) be (patched|fixed)\b/i.test(text)) return 0;
  if (/\bpatch(ed|es)\b|\bfix(ed|es)\b|\b(fix|patch|update)s? (is |are )?(now )?(available|released)\b|\bsecurity updates? (released|available|address)|\bremediat(ed|ion)\b|\bupgrade to (version )?\d|\b(patch|update) now\b/i.test(text)) return 1;
  if (/\b(zero|0)[- ]days?\b(?!\s+(protection|defen[cs]e|prevention|initiative|program))/i.test(text)) return 0;
  return -1;
}

/**
 * Extract MITRE ATT&CK Tactic and Technique IDs from text
 * Matches patterns like T1059, T1059.001, TA0001
 */
/**
 * Strip HTML tags from text
 */
function stripHtml(html) {
  if (!html) return '';
  // decodeEntities decodes each entity exactly once (&amp; last), so "&amp;lt;"
  // stays "&lt;" and numeric references (&#8217;) are decoded too.
  return decodeEntities(String(html).replace(/<[^>]*>/g, ''))
    .replace(/\s+/g, ' ')
    .trim()
    .substring(0, 1000);
}

// ============================================
// ROBUST FEED FETCHING
// ============================================

// Repair the most common XML breakage: bare "&" (e.g. "Q&A", "?a=1&b=2").
function sanitizeXml(xml) {
  return xml.replace(/&(?!(?:[a-zA-Z][a-zA-Z0-9]*|#\d+|#x[0-9a-fA-F]+);)/g, '&amp;');
}

// HTML named entities that commonly appear in feed text (the lenient parser has
// no XML parser to decode them, so titles showed a literal "&rsquo;").
const HTML_ENTITIES = {
  nbsp: 160, ndash: 8211, mdash: 8212, lsquo: 8216, rsquo: 8217, sbquo: 8218, ldquo: 8220,
  rdquo: 8221, bdquo: 8222, hellip: 8230, bull: 8226, middot: 183, laquo: 171, raquo: 187,
  copy: 169, reg: 174, trade: 8482, deg: 176, euro: 8364, pound: 163, times: 215
};

function decodeEntities(str) {
  return String(str)
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'")
    .replace(/&#(\d+);/g, (m, n) => { try { return String.fromCodePoint(+n); } catch { return m; } })
    .replace(/&#x([0-9a-f]+);/gi, (m, n) => { try { return String.fromCodePoint(parseInt(n, 16)); } catch { return m; } })
    .replace(/&([a-z]+);/g, (m, n) => HTML_ENTITIES[n] ? String.fromCodePoint(HTML_ENTITIES[n]) : m)
    .replace(/&amp;/g, '&');
}

function firstTag(block, names) {
  for (const n of names) {
    const m = block.match(new RegExp(`<${n}(?:\\s[^>]*)?>([\\s\\S]*?)</${n}>`, 'i'));
    if (m && m[1].trim()) return decodeEntities(m[1]).trim();
  }
  return '';
}

// Linear-time <tag>...</tag> block extraction. (A lazy /<item[\s>][\s\S]*?<\/item>/
// regex is quadratic when closing tags are missing: a 440 KB truncated feed took
// ~1.5 s of synchronous CPU on a fast machine, far longer on a 0.1-CPU host.)
function extractBlocks(xml, tag) {
  const openRe = new RegExp(`<${tag}[\\s>]`, 'gi');
  const closeRe = new RegExp(`</${tag}>`, 'gi');
  const blocks = [];
  let open;
  while ((open = openRe.exec(xml)) !== null) {
    closeRe.lastIndex = open.index;
    const close = closeRe.exec(xml);
    if (!close) break;                      // no closing tag anywhere after this point
    blocks.push(xml.slice(open.index, close.index + close[0].length));
    openRe.lastIndex = close.index + close[0].length;
  }
  return blocks;
}

// Atom entries often carry several <link>s (replies, edit, self, alternate):
// the article is rel="alternate" (or a link with no rel at all).
function atomLink(block) {
  const links = block.match(/<link\b[^>]*>/gi) || [];
  let fallback = '';
  for (const tag of links) {
    const href = tag.match(/\bhref\s*=\s*["']([^"']+)["']/i);
    if (!href) continue;
    const rel = (tag.match(/\brel\s*=\s*["']([^"']+)["']/i) || [])[1];
    if (!rel || rel.toLowerCase() === 'alternate') return decodeEntities(href[1]);
    if (!fallback) fallback = decodeEntities(href[1]);
  }
  return fallback;
}

// Last-resort parser for feeds whose XML is too broken for a strict parser:
// pulls <item>/<entry> blocks out with regexes.
function lenientParse(xml) {
  let blocks = extractBlocks(xml, 'item');
  if (!blocks.length) blocks = extractBlocks(xml, 'entry');
  return blocks.map(b => {
    let link = firstTag(b, ['link']);
    if (!link || !/^https?:/i.test(link)) {
      const href = atomLink(b);
      if (href) link = href;
    }
    const date = firstTag(b, ['pubDate', 'published', 'updated', 'dc:date']);
    const d = new Date(date);
    return {
      title: firstTag(b, ['title']),
      link,
      pubDate: date || undefined,
      isoDate: isNaN(d) ? undefined : d.toISOString(),
      content: firstTag(b, ['description', 'summary', 'content:encoded', 'content']),
      creator: firstTag(b, ['dc:creator', 'author']) || undefined
    };
  }).filter(i => i.title && i.link);
}

function errorText(e) {
  if (!e) return 'unknown error';
  if (e.message) return e.message;
  if (e.code) return e.code;
  if (Array.isArray(e.errors) && e.errors.length) return e.errors.map(x => x.code || x.message).join(', ');
  return String(e);
}

async function fetchFeedItems(url) {
  const resp = await safeGet(url, { timeout: 30000, headers: FEED_HEADERS, responseType: 'text' });
  const raw = typeof resp.data === 'string' ? resp.data : String(resp.data);
  const xml = raw.replace(/^﻿/, '').trimStart();
  // Only reject obvious HTML pages (bot challenges, moved-feed landing pages).
  // Real feeds can have long preambles (stylesheets, comments) before <rss>.
  const looksLikeFeed = /<(rss|feed|rdf:RDF|channel)[\s>]/i.test(xml);
  if (!looksLikeFeed && /^(<!doctype html|<html)/i.test(xml)) {
    throw new Error('Response is an HTML page, not an RSS/Atom feed');
  }
  if (!looksLikeFeed && !/<(item|entry)[\s>]/i.test(xml)) {
    throw new Error('Response is not an RSS/Atom feed');
  }
  try {
    return (await parser.parseString(xml)).items || [];
  } catch (strictErr) {
    try {
      return (await parser.parseString(sanitizeXml(xml))).items || [];
    } catch {
      const items = lenientParse(xml);
      if (items.length) return items;
      throw strictErr;
    }
  }
}

// ── Google News fallback ─────────────────────────────────────────────
// Many sites block cloud-hosting IPs (403/520/timeouts), break their XML, or
// move their feed. Google News indexes these sites and serves RSS for a
// "site:" query, so a broken feed still yields that site's recent articles.
const NO_FALLBACK_HOSTS = /(^|\.)(github\.com|githubusercontent\.com|medium\.com|feedburner\.com)$/i;
const FALLBACK_TTL_MS = 60 * 60 * 1000;          // query Google News at most hourly per source
const fallbackCache = new Map();                  // sourceId → { at, items }

function fallbackSite(source) {
  try {
    const host = new URL(source.url).hostname.toLowerCase();
    if (NO_FALLBACK_HOSTS.test(host)) return null;
    return host.replace(/^www\./, '').replace(/^feeds?\./, '');
  } catch { return null; }
}

// "ncsc.gov.uk" must not fall back to "gov.uk" (every UK government site),
// nor "bbc.co.uk" to "co.uk".
const PUBLIC_SUFFIX_2LD = /^(co|com|net|org|gov|edu|ac|mil|or|ne|go|gv|govt|nic)\.[a-z]{2}$/i;

// Google News titles look like "Headline - Publisher" (the publisher may itself
// contain hyphens, e.g. "Security-Insider"): drop the last " - " segment.
function cleanGoogleNewsTitle(title) {
  const t = String(title || '');
  const i = t.lastIndexOf(' - ');
  return i > 0 ? t.slice(0, i).trim() : t;
}

async function fetchGoogleNewsFallback(source) {
  const site = fallbackSite(source);
  if (!site) return null;
  const cached = fallbackCache.get(source.id);
  if (cached && Date.now() - cached.at < FALLBACK_TTL_MS) {
    if (cached.error) throw cached.error;
    return cached.items;
  }
  try {
    return await queryGoogleNews(source, site);
  } catch (err) {
    // Google answered with an HTTP error (429/503...): don't re-query it every
    // 15-minute cycle for every broken source. Network-level errors aren't cached.
    if (err && err.response) fallbackCache.set(source.id, { at: Date.now(), items: [], error: err });
    throw err;
  }
}

async function queryGoogleNews(source, site) {

  // Last 30 days first; sites that post rarely get an unrestricted search.
  const gn = (query) => `https://news.google.com/rss/search?q=${encodeURIComponent(query)}&hl=en-US&gl=US&ceid=US:en`;
  let raw = await fetchFeedItems(gn(`site:${site} when:30d`));
  if (!raw.length) raw = await fetchFeedItems(gn(`site:${site}`));
  // Google News often indexes only the main domain (sophos.com, not news.sophos.com)
  const parts = site.split('.');
  if (!raw.length && parts.length > 2 && !PUBLIC_SUFFIX_2LD.test(parts.slice(-2).join('.'))) {
    raw = await fetchFeedItems(gn(`site:${parts.slice(-2).join('.')} when:30d`));
  }
  // Cap volume: fallback queries can return 100 items each, and processing
  // thousands of items per cycle is too heavy for a small free-tier CPU.
  const items = raw.slice(0, 30).map(i => ({ ...i, title: cleanGoogleNewsTitle(textOf(i.title)) }));
  fallbackCache.set(source.id, { at: Date.now(), items });
  return items;
}

// Feed parsers can yield { _: 'text', $: {...} } instead of a string for
// elements with attributes; one such item must not fail the whole feed.
function textOf(v) {
  if (v == null) return '';
  if (typeof v === 'string') return v;
  if (Array.isArray(v)) return textOf(v[0]);
  if (typeof v === 'object') return v._ != null ? textOf(v._) : '';
  return String(v);
}

function itemsToArticles(items, source) {
  const articles = [];
  for (const item of items) {
    if (!item) continue;
    const title = textOf(item.title).trim() || 'Untitled';
    const description = stripHtml(textOf(item.contentSnippet || item.content || item.contentEncoded || item.summary || ''));
    const category = detectCategory(title, description);

    articles.push({
      title: title.trim(),
      description,
      url: textOf(item.link || item.guid) || source.url,
      source_name: source.name,
      source_type: 'rss',
      source_id: source.id,
      user_id: source.user_id || null,
      author: textOf(item.creator || item.author || item['dc:creator']) || null,
      published_date: item.isoDate || item.pubDate || item.dcDate || new Date().toISOString(),
      category: source.category !== 'news' ? source.category : category,
      severity: detectSeverity(title, description, category),
      cve_id: extractCVE(`${title} ${description}`),
      is_patched: detectPatchStatus(title, description),
      has_poc: detectPOC(title, description),
      tags: generateTags(title, description),
      mitre_ids: extractMitreIds(`${title} ${description}`),
      sector: detectSector(`${title} ${description}`),
      threat_actors: detectThreatActors(`${title} ${description}`)
    });
  }
  return articles;
}

/**
 * Fetch a single RSS feed and normalize articles
 */
async function fetchRSSFeed(source) {
  let primaryError;
  try {
    // Fetched through the SSRF guard (blocks private IPs, re-checks redirects).
    const items = await fetchFeedItems(source.url);
    failureTracker.delete(source.id);
    const articles = itemsToArticles(items, source);
    return { success: true, articles, count: articles.length };
  } catch (error) {
    primaryError = error;
  }

  // Primary feed failed → try the Google News fallback for this site.
  let egressDown = false;
  try {
    const items = await fetchGoogleNewsFallback(source);
    if (items && items.length) {
      failureTracker.delete(source.id);
      console.warn(`[RSS] ${source.name}: feed failed (${errorText(primaryError)}) — using Google News fallback (${items.length} items)`);
      const articles = itemsToArticles(items, source);
      return { success: true, articles, count: articles.length, via: 'google-news' };
    }
    else if (items) console.warn(`[RSS] ${source.name}: Google News fallback found no articles for this site`);
  } catch (fbErr) {
    console.warn(`[RSS] ${source.name}: Google News fallback failed too (${errorText(fbErr)})`);
    // Couldn't even reach news.google.com (DNS/connect/timeout, no HTTP answer):
    // our own egress is down, so this failure says nothing about the source.
    egressDown = !!fbErr && !fbErr.response && fbErr.code !== 'EBLOCKED';
  }

  const msg = errorText(primaryError);
  console.error(`[RSS] Error fetching ${source.name}: ${msg}`);

  if (egressDown) {
    return { success: false, articles: [], error: `${msg} (network unavailable; not counted toward auto-disable)` };
  }

  // Track consecutive failures — auto-disable after threshold
  const fails = (failureTracker.get(source.id) || 0) + 1;
  failureTracker.set(source.id, fails);

  let autoDisabled = false;
  if (fails >= MAX_CONSECUTIVE_FAILURES) {
    try {
      const db = require('../database');
      db.updateSource(source.id, { enabled: 0 });
      console.log(`[RSS] Auto-disabled ${source.name} after ${fails} consecutive failures`);
      autoDisabled = true;
    } catch (e) {}
  }

  const errMsg = autoDisabled
    ? `Auto-disabled after ${fails} failures: ${msg}`
    : `(${fails}/${MAX_CONSECUTIVE_FAILURES}) ${msg}`;

  return { success: false, articles: [], error: errMsg };
}

/**
 * Generate tags from content
 */
function generateTags(title, description) {
  const text = `${title} ${description}`.toLowerCase();
  const tags = [];

  const tagPatterns = {
    'ransomware': /ransomware/i,
    'phishing': /phishing/i,
    'zero-day': /zero[- ]day|0[- ]day/i,
    'apt': /\bapt[- ]?\d+\b|advanced persistent threat/i,
    'supply-chain': /supply[- ]chain/i,
    'iot': /\biot\b|internet of things/i,
    'cloud': /\bcloud\b|\baws\b|\bazure\b|\bgcp\b/i,             // not "flaws" / "laws"
    'windows': /windows|microsoft/i,
    'linux': /linux|ubuntu|debian|centos/i,
    'android': /android/i,
    'ios': /(?<!cisco )\bios\b|iphone|apple/i,                    // not "Cisco IOS"
    'cryptocurrency': /\bcrypto\b|bitcoin|ethereum|cryptocurrenc/i, // not "cryptographic"
    'ddos': /ddos|denial of service/i,
    'data-breach': /data breach|(?<!memory )\bleak/i,
    'nation-state': /nation[- ]state|government/i
  };

  for (const [tag, pattern] of Object.entries(tagPatterns)) {
    if (pattern.test(text)) tags.push(tag);
  }

  return tags.length > 0 ? tags.join(',') : null;
}

module.exports = {
  fetchRSSFeed, detectCategory, detectSeverity, extractCVE, detectPOC, detectPatchStatus, extractMitreIds, detectSector, detectThreatActors,
  // internals, exported for tests only
  _internal: { extractCvssScore, sanitizeXml, decodeEntities, lenientParse, stripHtml, generateTags, cleanGoogleNewsTitle, fallbackCache, failureTracker }
};

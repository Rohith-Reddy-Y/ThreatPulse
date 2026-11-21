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
    /\bCVE-\d{4}-\d{4,}\b/i, /\bvulnerabilit(y|ies)\b/i, /\bvulns?\b/i, /\bexploit(s|ed|ation|ing)?\b/i,
    /\bRCE\b/, /\bremote code execution\b/i, /\bXSS\b/, /\bcross[- ]site scripting\b/i,
    /\bSQL ?injection\b/i, /\bSQLi\b/, /\bbuffer overflow\b/i, /\b(zero|0)[- ]days?\b/i,
    /\bsecurity (flaw|bug|hole)s?\b/i, /\bflaws?\b/i, /\bprivilege escalation\b/i, /\bauthentication bypass\b/i
  ]],
  ['malware', [
    /\b(malware|trojans?|ransomware|botnets?|backdoors?|rootkits?|spyware|infostealers?|stealers?|wipers?|worms?|loaders?|droppers?)\b/i,
    /\bRATs?\b/, /\bremote access trojan\b/i
  ]],
  ['breach', [
    /\bdata breach(es)?\b/i, /\bbreach(ed|es)?\b/i, /\bleak(ed|s)?\b/i, /\bhack(ed|ers?|ing)?\b/i,
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
function extractCvssScore(text) {
  const m = String(text || '').match(/\bcvss(?:\s?v?\s?[234](?:\.\d)?)?\b[^0-9\n]{0,25}?(10(?:\.0)?|[0-9]\.[0-9]|[0-9])(?![\d.])/i);
  if (!m) return null;
  const v = parseFloat(m[1]);
  return v >= 0 && v <= 10 ? v : null;
}

const SEVERITY_RULES = {
  critical: [
    /\bactively[- ]exploited\b/i, /\bexploited in the wild\b/i, /\bunder active (exploitation|attack)\b/i,
    /\b(zero|0)[- ]days?\b(?!\s+(protection|defen[cs]e|prevention|initiative|program))/i,
    /\bcritical[- ](severity|vulnerabilit(y|ies)|flaws?|bugs?|rce|remote code|security (flaw|bug|issue|update|patch|fix))/i,
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
    /\bbackdoor(ed)?\b/i, /\bproof[- ]of[- ]concept\b/i,
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

  const score = extractCvssScore(text);
  if (score !== null) {
    if (score >= 9) return 'critical';
    if (score >= 7) return 'high';
    if (score >= 4) return 'medium';
    return 'low';
  }

  for (const level of ['critical', 'high', 'medium', 'low']) {
    if (SEVERITY_RULES[level].some(re => re.test(text))) return level;
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
  const match = text.match(/\bCVE-\d{4}-\d{4,}\b/i);
  return match ? match[0].toUpperCase() : null;
}

/**
 * Detect if a public exploit / PoC is mentioned
 */
function detectPOC(title, description) {
  const text = `${title || ''} ${description || ''}`;
  return /\bproof[- ]of[- ]concept\b|\bPoC\b|\bexploit[- ]code\b|\b(public|working|functional) exploits?\b|\bexploits? (is |are |has been |have been )?(now )?(available|released|published)\b|\bweaponi[sz]ed\b|\bexploit-db\b|\bmetasploit\b|github\.com\/\S*exploit/i.test(text) ? 1 : 0;
}

/**
 * Detect patch status: 1 = patched, 0 = unpatched, -1 = unknown
 */
function detectPatchStatus(title, description) {
  const text = `${title || ''} ${description || ''}`;
  if (/\bunpatched\b|\bno (fix|patch)\b|\bnot (yet )?(been )?(patched|fixed)\b|\bwithout a (fix|patch)\b|\bpatch (is )?not (yet )?available\b/i.test(text)) return 0;
  if (/\bpatch(ed|es)\b|\bfix(ed|es)\b|\b(fix|patch|update)s? (is |are )?(now )?(available|released)\b|\bsecurity updates? (released|available|address)|\bremediat(ed|ion)\b|\bupgrade to (version )?\d/i.test(text)) return 1;
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
  return html
    .replace(/<[^>]*>/g, '')
    .replace(/&nbsp;/g, ' ')
    .replace(/&amp;/g, '&')
    .replace(/&lt;/g, '<')
    .replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"')
    .replace(/&#39;/g, "'")
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

function decodeEntities(str) {
  return str
    .replace(/<!\[CDATA\[([\s\S]*?)\]\]>/g, '$1')
    .replace(/&lt;/g, '<').replace(/&gt;/g, '>')
    .replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'")
    .replace(/&#(\d+);/g, (m, n) => { try { return String.fromCodePoint(+n); } catch { return m; } })
    .replace(/&#x([0-9a-f]+);/gi, (m, n) => { try { return String.fromCodePoint(parseInt(n, 16)); } catch { return m; } })
    .replace(/&amp;/g, '&');
}

function firstTag(block, names) {
  for (const n of names) {
    const m = block.match(new RegExp(`<${n}(?:\\s[^>]*)?>([\\s\\S]*?)</${n}>`, 'i'));
    if (m && m[1].trim()) return decodeEntities(m[1]).trim();
  }
  return '';
}

// Last-resort parser for feeds whose XML is too broken for a strict parser:
// pulls <item>/<entry> blocks out with regexes.
function lenientParse(xml) {
  const blocks = xml.match(/<item[\s>][\s\S]*?<\/item>/gi) || xml.match(/<entry[\s>][\s\S]*?<\/entry>/gi) || [];
  return blocks.map(b => {
    let link = firstTag(b, ['link']);
    if (!link || !/^https?:/i.test(link)) {
      const m = b.match(/<link[^>]*href=["']([^"']+)["'][^>]*>/i);
      if (m) link = decodeEntities(m[1]);
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

async function fetchGoogleNewsFallback(source) {
  const site = fallbackSite(source);
  if (!site) return null;
  const cached = fallbackCache.get(source.id);
  if (cached && Date.now() - cached.at < FALLBACK_TTL_MS) return cached.items;

  // Last 30 days first; sites that post rarely get an unrestricted search.
  const gn = (query) => `https://news.google.com/rss/search?q=${encodeURIComponent(query)}&hl=en-US&gl=US&ceid=US:en`;
  let raw = await fetchFeedItems(gn(`site:${site} when:30d`));
  if (!raw.length) raw = await fetchFeedItems(gn(`site:${site}`));
  // Google News often indexes only the main domain (sophos.com, not news.sophos.com)
  const parts = site.split('.');
  if (!raw.length && parts.length > 2) {
    raw = await fetchFeedItems(gn(`site:${parts.slice(-2).join('.')} when:30d`));
  }
  // Cap volume: fallback queries can return 100 items each, and processing
  // thousands of items per cycle is too heavy for a small free-tier CPU.
  const items = raw.slice(0, 30).map(i => ({
    ...i,
    // Google News titles look like "Headline - Publisher": drop the suffix
    title: (i.title || '').replace(/\s+-\s+[^-]{2,60}$/, '')
  }));
  fallbackCache.set(source.id, { at: Date.now(), items });
  return items;
}

function itemsToArticles(items, source) {
  const articles = [];
  for (const item of items) {
    const title = item.title || 'Untitled';
    const description = stripHtml(item.contentSnippet || item.content || item.contentEncoded || item.summary || '');
    const category = detectCategory(title, description);

    articles.push({
      title: title.trim(),
      description,
      url: item.link || item.guid || source.url,
      source_name: source.name,
      source_type: 'rss',
      source_id: source.id,
      user_id: source.user_id || null,
      author: item.creator || item.author || item['dc:creator'] || null,
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
  }

  const msg = errorText(primaryError);
  console.error(`[RSS] Error fetching ${source.name}: ${msg}`);

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
    'apt': /apt[- ]?\d+|advanced persistent threat/i,
    'supply-chain': /supply[- ]chain/i,
    'iot': /\biot\b|internet of things/i,
    'cloud': /\bcloud\b|aws|azure|gcp/i,
    'windows': /windows|microsoft/i,
    'linux': /linux|ubuntu|debian|centos/i,
    'android': /android/i,
    'ios': /\bios\b|iphone|apple/i,
    'cryptocurrency': /crypto|bitcoin|ethereum|cryptocurrency/i,
    'ddos': /ddos|denial of service/i,
    'data-breach': /data breach|leak/i,
    'nation-state': /nation[- ]state|government/i
  };

  for (const [tag, pattern] of Object.entries(tagPatterns)) {
    if (pattern.test(text)) tags.push(tag);
  }

  return tags.length > 0 ? tags.join(',') : null;
}

module.exports = { fetchRSSFeed, detectCategory, detectSeverity, extractCVE, detectPOC, detectPatchStatus, extractMitreIds, detectSector, detectThreatActors };

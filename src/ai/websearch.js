/**
 * ThreatPulse — Web Search (free tiers, no credit card required)
 * Priority: Tavily (1,000/mo free, no card) → Wikipedia (no key, no card).
 * The AI then synthesizes a cited answer from these results.
 */
const axios = require('axios');

const TAVILY_URL = 'https://api.tavily.com/search';
const WIKI_URL = 'https://en.wikipedia.org/w/api.php';
const UA = 'ThreatPulse/1.0 (cyber threat intelligence dashboard)';
// Keep each provider call short: web mode then still fits inside the AI deadline.
const TIMEOUT_MS = 8000;
const MAX_RESULTS = 10;
const MAX_QUERY = 400;

// Results are third-party data that is echoed into prompts and the UI: bound sizes
// and keep only http(s) URLs (the URL is only ever displayed, never fetched).
function str(v, max) {
  const s = v == null ? '' : String(v);
  return s.length > max ? s.slice(0, max) : s;
}
function safeUrl(u) {
  const s = str(u, 500);
  return /^https?:\/\//i.test(s) ? s : '';
}

// Tavily key can come from the environment OR admin-configured DB settings.
let db = null;
try { db = require('../database'); } catch (e) { db = null; }

function getTavilyKey() {
  if (process.env.TAVILY_API_KEY) return process.env.TAVILY_API_KEY;
  if (db) {
    try { return db.getSetting('tavily_api_key') || null; } catch (e) { return null; }
  }
  return null;
}

function hasTavily() {
  return !!getTavilyKey();
}

/**
 * Search the web, preferring Tavily when configured, else Wikipedia.
 * @param {string} query
 * @param {number} max
 * @returns {Promise<Array<{title, url, snippet}>>}
 */
async function search(query, max = 5) {
  query = str(query, MAX_QUERY);
  max = Math.max(1, Math.min(parseInt(max, 10) || 5, MAX_RESULTS));
  if (hasTavily()) {
    const results = await searchTavily(query, max);
    if (results.length > 0) return results;
  }
  return searchWikipedia(query, max);
}

async function searchTavily(query, max = 5) {
  try {
    const resp = await axios.post(TAVILY_URL, {
      api_key: getTavilyKey(),
      query,
      max_results: max,
      search_depth: 'basic',
      include_answer: false
    }, { headers: { 'Content-Type': 'application/json' }, timeout: TIMEOUT_MS });

    const results = Array.isArray(resp?.data?.results) ? resp.data.results : [];
    return results.slice(0, max).map(r => ({
      title: str(r && r.title, 200) || '(untitled)',
      url: safeUrl(r && r.url),
      snippet: str(r && r.content, 300)
    }));
  } catch (e) {
    console.error('[WebSearch] Tavily error:', e.message);
    return [];
  }
}

async function searchWikipedia(query, max = 5) {
  try {
    const resp = await axios.get(WIKI_URL, {
      params: {
        action: 'query',
        list: 'search',
        srsearch: query,
        format: 'json',
        srlimit: max,
        origin: '*'
      },
      headers: { 'User-Agent': UA },
      timeout: TIMEOUT_MS
    });

    const hits = Array.isArray(resp?.data?.query?.search) ? resp.data.query.search : [];
    return hits.filter(h => h && h.title).slice(0, max).map(h => {
      const title = str(h.title, 200);
      return {
        title,
        url: `https://en.wikipedia.org/wiki/${encodeURIComponent(title.replace(/ /g, '_'))}`,
        snippet: str(String(h.snippet || '').replace(/<[^>]+>/g, '').replace(/&quot;/g, '"').replace(/&amp;/g, '&').trim(), 300)
      };
    });
  } catch (e) {
    console.error('[WebSearch] Wikipedia error:', e.message);
    return [];
  }
}

module.exports = { search, hasTavily };

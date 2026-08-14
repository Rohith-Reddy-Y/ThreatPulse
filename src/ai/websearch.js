/**
 * ThreatPulse — Web Search (free tiers, no credit card required)
 * Priority: Brave Search API (2,000/mo free) → Tavily (1,000/mo free) → Wikipedia (no key).
 * The AI then synthesizes a cited answer from these results.
 */
const axios = require('axios');

const BRAVE_URL = 'https://api.search.brave.com/res/v1/web/search';
const TAVILY_URL = 'https://api.tavily.com/search';
const WIKI_URL = 'https://en.wikipedia.org/w/api.php';
const UA = 'ThreatPulse/1.0 (cyber threat intelligence dashboard)';

function hasBrave() {
  return !!process.env.BRAVE_API_KEY;
}

function hasTavily() {
  return !!process.env.TAVILY_API_KEY;
}

/**
 * Search the web, preferring the best configured free provider.
 * @param {string} query
 * @param {number} max
 * @returns {Promise<Array<{title, url, snippet}>>}
 */
async function search(query, max = 5) {
  if (hasBrave()) {
    const results = await searchBrave(query, max);
    if (results.length > 0) return results;
  }
  if (hasTavily()) {
    const results = await searchTavily(query, max);
    if (results.length > 0) return results;
  }
  return searchWikipedia(query, max);
}

async function searchBrave(query, max = 5) {
  try {
    const resp = await axios.get(BRAVE_URL, {
      params: { q: query, count: Math.min(max, 10) },
      headers: {
        'Accept': 'application/json',
        'X-Subscription-Token': process.env.BRAVE_API_KEY,
        'User-Agent': UA
      },
      timeout: 15000
    });

    const web = resp.data?.web?.results || [];
    return web.map(r => ({
      title: r.title,
      url: r.url,
      snippet: (r.description || '').substring(0, 300)
    }));
  } catch (e) {
    console.error('[WebSearch] Brave error:', e.message);
    return [];
  }
}

async function searchTavily(query, max = 5) {
  try {
    const resp = await axios.post(TAVILY_URL, {
      api_key: process.env.TAVILY_API_KEY,
      query,
      max_results: max,
      search_depth: 'basic',
      include_answer: false
    }, { headers: { 'Content-Type': 'application/json' }, timeout: 15000 });

    return (resp.data?.results || []).map(r => ({
      title: r.title,
      url: r.url,
      snippet: (r.content || '').substring(0, 300)
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
      timeout: 15000
    });

    const hits = (resp.data?.query?.search) || [];
    return hits.map(h => ({
      title: h.title,
      url: `https://en.wikipedia.org/wiki/${encodeURIComponent(h.title.replace(/ /g, '_'))}`,
      snippet: (h.snippet || '').replace(/<[^>]+>/g, '').replace(/&quot;/g, '"').replace(/&amp;/g, '&').trim()
    }));
  } catch (e) {
    console.error('[WebSearch] Wikipedia error:', e.message);
    return [];
  }
}

module.exports = { search, hasBrave, hasTavily };

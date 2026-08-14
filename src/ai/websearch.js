/**
 * ThreatPulse — Web Search (free tiers, no credit card required)
 * Priority: Tavily (1,000/mo free, no card) → Wikipedia (no key, no card).
 * The AI then synthesizes a cited answer from these results.
 */
const axios = require('axios');

const TAVILY_URL = 'https://api.tavily.com/search';
const WIKI_URL = 'https://en.wikipedia.org/w/api.php';
const UA = 'ThreatPulse/1.0 (cyber threat intelligence dashboard)';

function hasTavily() {
  return !!process.env.TAVILY_API_KEY;
}

/**
 * Search the web, preferring Tavily when configured, else Wikipedia.
 * @param {string} query
 * @param {number} max
 * @returns {Promise<Array<{title, url, snippet}>>}
 */
async function search(query, max = 5) {
  if (hasTavily()) {
    const results = await searchTavily(query, max);
    if (results.length > 0) return results;
  }
  return searchWikipedia(query, max);
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

module.exports = { search, hasTavily };

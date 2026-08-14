/**
 * ThreatPulse — Web Search (free, no API key, no billing)
 * Primary: Wikipedia API (reliable, free, no key).
 * The AI then synthesizes a cited answer from these results.
 */
const axios = require('axios');

const WIKI_URL = 'https://en.wikipedia.org/w/api.php';
const UA = 'ThreatPulse/1.0 (cyber threat intelligence dashboard)';

/**
 * Search Wikipedia and return { title, url, snippet } results.
 * @param {string} query
 * @param {number} max
 */
async function search(query, max = 5) {
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

module.exports = { search };

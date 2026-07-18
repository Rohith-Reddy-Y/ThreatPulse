/**
 * ThreatPulse — Dark Web Intel Fetcher (Clearnet APIs)
 * Fetches threat intelligence from dark web monitoring services
 * WITHOUT requiring Tor — uses clearnet APIs that aggregate dark web data
 */

const axios = require('axios');

// abuse.ch now requires a free account Auth-Key for ThreatFox / URLhaus / MalwareBazaar.
// Get one at https://auth.abuse.ch and set ABUSE_CH_API_KEY in your .env.
const ABUSE_KEY = process.env.ABUSE_CH_API_KEY || '';

const HTTP_CONFIG = {
  timeout: 30000,
  headers: {
    'User-Agent': 'ThreatPulse/1.0 (Threat Intelligence Aggregator)',
    ...(ABUSE_KEY ? { 'Auth-Key': ABUSE_KEY } : {})
  }
};

/**
 * Fetch RansomWatch — Tracks ransomware group leak site posts
 * Source: https://github.com/joshhighet/ransomwatch
 * This scrapes .onion sites and publishes data on GitHub (clearnet)
 */
async function fetchRansomWatch(source) {
  try {
    const response = await axios.get(
      'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json',
      { ...HTTP_CONFIG, timeout: 30000 }
    );

    const posts = response.data;
    const articles = [];

    // Get posts from the last 7 days
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);

    if (Array.isArray(posts)) {
      for (const post of posts) {
        const discoveredDate = post.discovered ? new Date(post.discovered) : null;
        if (discoveredDate && discoveredDate < sevenDaysAgo) continue;

        articles.push({
          title: `[Dark Web] Ransomware Leak: ${post.post_title || 'Unknown Victim'} (${post.group_name || 'Unknown Group'})`,
          description: `Ransomware group "${post.group_name}" posted a new victim on their dark web leak site.\n\nVictim: ${post.post_title || 'Unknown'}\nGroup: ${post.group_name || 'Unknown'}\nDiscovered: ${post.discovered || 'Unknown'}${post.post_url ? '\nLeak Site (Tor): ' + post.post_url : ''}`,
          url: `https://github.com/joshhighet/ransomwatch`,
          source_name: 'RansomWatch - Dark Web Tracker',
          source_type: 'darkweb',
          source_id: source?.id || null,
          user_id: source?.user_id || null,
          author: post.group_name || 'Unknown Ransomware Group',
          published_date: post.discovered || new Date().toISOString(),
          category: 'darkweb',
          severity: 'critical',
          cve_id: null,
          is_patched: -1,
          has_poc: 0,
          tags: `ransomware,dark-web,leak,${(post.group_name || '').toLowerCase()}`
        });
      }
    }

    console.log(`[DarkWeb] RansomWatch: ${articles.length} recent leak posts`);
    return { success: true, articles, count: articles.length };

  } catch (error) {
    console.error(`[DarkWeb] RansomWatch error: ${error.message}`);
    return { success: false, articles: [], error: error.message };
  }
}

/**
 * Fetch ThreatFox — Malware IOCs (many sourced from dark web)
 * Source: https://threatfox.abuse.ch
 */
async function fetchThreatFox(source) {
  try {
    const response = await axios.post(
      'https://threatfox-api.abuse.ch/api/v1/',
      { query: 'get_iocs', days: 1 },
      { ...HTTP_CONFIG }
    );

    const data = response.data;
    const articles = [];

    if (data.query_status === 'ok' && data.data && Array.isArray(data.data)) {
      // Group by malware to avoid flooding — take top 20
      const malwareGroups = {};
      for (const ioc of data.data.slice(0, 100)) {
        const malware = ioc.malware_printable || 'Unknown';
        if (!malwareGroups[malware]) {
          malwareGroups[malware] = [];
        }
        malwareGroups[malware].push(ioc);
      }

      for (const [malware, iocs] of Object.entries(malwareGroups).slice(0, 20)) {
        const firstIoc = iocs[0];
        const iocTypes = [...new Set(iocs.map(i => i.ioc_type_desc))].join(', ');

        articles.push({
          title: `[IOC] ${malware} — ${iocs.length} new indicators detected`,
          description: `ThreatFox detected ${iocs.length} new IOC(s) for "${malware}".\n\nIOC Types: ${iocTypes}\nThreat Type: ${firstIoc.threat_type_desc || 'Unknown'}\nConfidence: ${firstIoc.confidence_level || 'N/A'}%\nFirst Seen: ${firstIoc.first_seen_utc || 'Unknown'}\n\nSample IOC: ${firstIoc.ioc || 'N/A'}`,
          url: `https://threatfox.abuse.ch/browse/malware/${encodeURIComponent(firstIoc.malware_malpedia || malware)}/`,
          source_name: 'ThreatFox - Malware IOCs',
          source_type: 'darkweb',
          source_id: source?.id || null,
          user_id: source?.user_id || null,
          author: firstIoc.reporter || 'abuse.ch',
          published_date: firstIoc.first_seen_utc || new Date().toISOString(),
          category: 'darkweb',
          severity: (firstIoc.confidence_level || 0) >= 75 ? 'high' : 'medium',
          cve_id: null,
          is_patched: -1,
          has_poc: 0,
          tags: `malware,ioc,${malware.toLowerCase()},${firstIoc.threat_type || ''}`
        });
      }
    }

    console.log(`[DarkWeb] ThreatFox: ${articles.length} malware IOC groups`);
    return { success: true, articles, count: articles.length };

  } catch (error) {
    console.error(`[DarkWeb] ThreatFox error: ${error.message}`);
    return { success: false, articles: [], error: error.message };
  }
}

/**
 * Fetch URLhaus — Malicious URLs (malware distribution, often from dark web)
 * Source: https://urlhaus.abuse.ch
 */
async function fetchURLhaus(source) {
  try {
    const response = await axios.post(
      'https://urlhaus-api.abuse.ch/v1/',
      'urlhaus_recent',
      {
        ...HTTP_CONFIG,
        headers: { ...HTTP_CONFIG.headers, 'Content-Type': 'application/x-www-form-urlencoded' }
      }
    );

    const data = response.data;
    const articles = [];

    if (data.urls && Array.isArray(data.urls)) {
      // Group by threat type — take recent ones
      const threatGroups = {};
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

      for (const url of data.urls.slice(0, 50)) {
        const addedDate = new Date(url.dateadded);
        if (addedDate < oneDayAgo) continue;

        const threat = url.threat || 'malware_download';
        if (!threatGroups[threat]) {
          threatGroups[threat] = [];
        }
        threatGroups[threat].push(url);
      }

      for (const [threat, urls] of Object.entries(threatGroups)) {
        const statusCounts = {};
        urls.forEach(u => {
          const s = u.url_status || 'unknown';
          statusCounts[s] = (statusCounts[s] || 0) + 1;
        });

        articles.push({
          title: `[Malicious URLs] ${urls.length} new ${threat.replace('_', ' ')} URLs detected`,
          description: `URLhaus detected ${urls.length} new malicious URLs associated with "${threat}".\n\nStatuses: ${Object.entries(statusCounts).map(([k, v]) => `${k}: ${v}`).join(', ')}\nTags: ${[...new Set(urls.flatMap(u => u.tags || []))].slice(0, 10).join(', ')}\n\nSample: ${urls[0]?.url || 'N/A'}`,
          url: 'https://urlhaus.abuse.ch/browse/',
          source_name: 'URLhaus - Malicious URLs',
          source_type: 'darkweb',
          source_id: source?.id || null,
          user_id: source?.user_id || null,
          author: urls[0]?.reporter || 'abuse.ch',
          published_date: urls[0]?.dateadded || new Date().toISOString(),
          category: 'darkweb',
          severity: 'high',
          cve_id: null,
          is_patched: -1,
          has_poc: 0,
          tags: `malicious-url,${threat},dark-web`
        });
      }
    }

    console.log(`[DarkWeb] URLhaus: ${articles.length} threat groups`);
    return { success: true, articles, count: articles.length };

  } catch (error) {
    console.error(`[DarkWeb] URLhaus error: ${error.message}`);
    return { success: false, articles: [], error: error.message };
  }
}

/**
 * Fetch MalwareBazaar — Recent malware samples
 * Source: https://bazaar.abuse.ch
 */
async function fetchMalwareBazaar(source) {
  try {
    const response = await axios.post(
      'https://mb-api.abuse.ch/api/v1/',
      'query=get_recent&selector=time',
      {
        ...HTTP_CONFIG,
        headers: { ...HTTP_CONFIG.headers, 'Content-Type': 'application/x-www-form-urlencoded' }
      }
    );

    const data = response.data;
    const articles = [];

    if (data.query_status === 'ok' && data.data && Array.isArray(data.data)) {
      // Group by malware family
      const families = {};
      for (const sample of data.data.slice(0, 50)) {
        const family = sample.signature || 'Unknown';
        if (!families[family]) {
          families[family] = [];
        }
        families[family].push(sample);
      }

      for (const [family, samples] of Object.entries(families).slice(0, 15)) {
        const first = samples[0];

        articles.push({
          title: `[Malware] ${family} — ${samples.length} new sample(s) submitted`,
          description: `MalwareBazaar received ${samples.length} new sample(s) of "${family}".\n\nFile Type: ${first.file_type || 'Unknown'}\nFile Size: ${first.file_size ? Math.round(first.file_size / 1024) + ' KB' : 'Unknown'}\nDelivery Method: ${first.delivery_method || 'Unknown'}\nFirst Seen: ${first.first_seen || 'Unknown'}\nSHA256: ${first.sha256_hash || 'N/A'}\nTags: ${(first.tags || []).join(', ')}`,
          url: first.sha256_hash
            ? `https://bazaar.abuse.ch/sample/${first.sha256_hash}/`
            : 'https://bazaar.abuse.ch/browse/',
          source_name: 'MalwareBazaar - Malware Samples',
          source_type: 'darkweb',
          source_id: source?.id || null,
          user_id: source?.user_id || null,
          author: first.reporter || 'abuse.ch',
          published_date: first.first_seen || new Date().toISOString(),
          category: 'malware',
          severity: 'high',
          cve_id: null,
          is_patched: -1,
          has_poc: 1, // The sample itself is the POC
          tags: `malware,${family.toLowerCase()},${(first.tags || []).join(',')}`
        });
      }
    }

    console.log(`[DarkWeb] MalwareBazaar: ${articles.length} malware families`);
    return { success: true, articles, count: articles.length };

  } catch (error) {
    console.error(`[DarkWeb] MalwareBazaar error: ${error.message}`);
    return { success: false, articles: [], error: error.message };
  }
}

/**
 * Main dark web fetch orchestrator
 */
async function fetchDarkWebIntel(sources) {
  const allArticles = [];
  const results = [];

  // ThreatFox / URLhaus / MalwareBazaar all require an abuse.ch Auth-Key now.
  const needsAbuseKey = (url) => /threatfox|urlhaus|mb-api\.abuse\.ch|malwarebazaar/.test(url);

  for (const source of sources) {
    let result;

    if (needsAbuseKey(source.url) && !ABUSE_KEY) {
      result = { success: false, articles: [], count: 0, error: 'abuse.ch API key required — set ABUSE_CH_API_KEY (free at auth.abuse.ch)' };
    } else if (source.url.includes('ransomwatch')) {
      result = await fetchRansomWatch(source);
    } else if (source.url.includes('threatfox')) {
      result = await fetchThreatFox(source);
    } else if (source.url.includes('urlhaus')) {
      result = await fetchURLhaus(source);
    } else if (source.url.includes('mb-api.abuse.ch') || source.url.includes('malwarebazaar')) {
      result = await fetchMalwareBazaar(source);
    } else if (source.url.includes('feodotracker')) {
      // Skip Feodo for now — it's a blocklist, not article-style data
      result = { success: true, articles: [], count: 0 };
    } else {
      result = { success: true, articles: [], count: 0 };
    }

    allArticles.push(...result.articles);
    results.push({ source: source.name, ...result });
  }

  return { articles: allArticles, results };
}

module.exports = { fetchDarkWebIntel, fetchRansomWatch, fetchThreatFox, fetchURLhaus, fetchMalwareBazaar };

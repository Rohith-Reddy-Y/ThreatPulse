/**
 * ThreatPulse — Dark Web Intel Fetcher (Clearnet APIs)
 * Fetches threat intelligence from dark web monitoring services
 * WITHOUT requiring Tor — uses clearnet APIs that aggregate dark web data
 */

const axios = require('axios');

// abuse.ch now requires a free account Auth-Key for ThreatFox / URLhaus / MalwareBazaar.
// Get one at https://auth.abuse.ch and set ABUSE_CH_API_KEY in your .env.
const ABUSE_KEY = process.env.ABUSE_CH_API_KEY || '';

const USER_AGENT = 'ThreatPulse/1.0 (Threat Intelligence Aggregator)';
const HTTP_CONFIG = {
  timeout: 30000,
  headers: {
    'User-Agent': USER_AGENT,
    ...(ABUSE_KEY ? { 'Auth-Key': ABUSE_KEY } : {})
  }
};

// Per-request config. The abuse.ch Auth-Key is only sent to abuse.ch (it used
// to go to raw.githubusercontent.com with the RansomWatch request too), and
// every request gets a hard deadline: axios' `timeout` is only a socket-idle timer.
function requestConfig({ abuse = true, extraHeaders = {} } = {}) {
  return {
    timeout: HTTP_CONFIG.timeout,
    headers: { ...(abuse ? HTTP_CONFIG.headers : { 'User-Agent': USER_AGENT }), ...extraHeaders },
    signal: AbortSignal.timeout(60000)
  };
}

// "2026-11-20 13:36:27 UTC" -> "2026-11-20"; used to give daily summary
// articles a distinct URL per day (articles are de-duplicated on URL).
function dayOf(value) {
  const d = new Date(value || Date.now());
  return (isNaN(d) ? new Date() : d).toISOString().slice(0, 10);
}

// ── Large JSON off the main thread ──────────────────────────────────
// ThreatFox `get_iocs` returns every IOC of the last day (several MB). Parsing
// that with JSON.parse on the main thread blocked the event loop long enough on
// a ~0.1-CPU instance to fail the 5 s health check. Parse it in a worker and
// hand back only the first `limit` rows.
const { Worker } = require('worker_threads');
const PARSE_WORKER_SRC = `
const { parentPort, workerData } = require('worker_threads');
try {
  const d = JSON.parse(workerData.text);
  const n = workerData.limit;
  let out = d;
  if (Array.isArray(d)) out = d.slice(0, n);
  else if (d && typeof d === 'object') {
    out = Object.assign({}, d);
    if (Array.isArray(d.data)) out.data = d.data.slice(0, n);
    if (Array.isArray(d.urls)) out.urls = d.urls.slice(0, n);
  }
  parentPort.postMessage({ ok: true, out });
} catch (e) {
  parentPort.postMessage({ ok: false, error: e.message });
}`;

function parseJsonOffThread(payload, limit) {
  // Already parsed (small responses / test stubs) → just trim.
  if (typeof payload !== 'string') {
    if (payload && Array.isArray(payload.data)) return Promise.resolve({ ...payload, data: payload.data.slice(0, limit) });
    if (payload && Array.isArray(payload.urls)) return Promise.resolve({ ...payload, urls: payload.urls.slice(0, limit) });
    return Promise.resolve(payload);
  }
  return new Promise((resolve, reject) => {
    const w = new Worker(PARSE_WORKER_SRC, { eval: true, workerData: { text: payload, limit } });
    const timer = setTimeout(() => { w.terminate(); reject(new Error('JSON parse timed out')); }, 30000);
    w.once('message', (m) => { clearTimeout(timer); w.terminate(); m.ok ? resolve(m.out) : reject(new Error(m.error)); });
    w.once('error', (e) => { clearTimeout(timer); reject(e); });
  });
}

/**
 * Fetch RansomWatch — Tracks ransomware group leak site posts
 * Source: https://github.com/joshhighet/ransomwatch
 * This scrapes .onion sites and publishes data on GitHub (clearnet)
 */
async function fetchRansomWatch(source) {
  try {
    const response = await axios.get(
      'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json',
      requestConfig({ abuse: false })
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
          // One URL per post: a shared URL made the DB keep only the first post ever.
          url: `https://github.com/joshhighet/ransomwatch#${encodeURIComponent(post.group_name || 'unknown')}/${encodeURIComponent(post.post_title || 'unknown')}`,
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

// ── Ransomware.live (maintained successor of the archived RansomWatch) ──
// Free, no key, but rate-limited with a daily call cap → fetch at most hourly
// and reuse the last result in between (the aggregator runs every 15 min).
const RANSOMWARE_LIVE_URL = 'https://api.ransomware.live/v2/recentvictims';
const RANSOMWARE_LIVE_TTL_MS = 60 * 60 * 1000;
let ransomwareLiveCache = { at: 0, posts: null };

async function fetchRansomwareLive(source) {
  try {
    let posts = ransomwareLiveCache.posts;
    if (!posts || Date.now() - ransomwareLiveCache.at > RANSOMWARE_LIVE_TTL_MS) {
      const response = await axios.get(RANSOMWARE_LIVE_URL, {
        ...requestConfig({ abuse: false }),
        maxContentLength: 5 * 1024 * 1024
      });
      posts = Array.isArray(response.data) ? response.data : [];
      ransomwareLiveCache = { at: Date.now(), posts };
    }

    const sevenDaysAgo = Date.now() - 7 * 24 * 60 * 60 * 1000;
    const articles = [];
    for (const post of posts.slice(0, 200)) {
      if (!post || typeof post !== 'object') continue;
      const discovered = post.discovered || post.attackdate;
      const t = discovered ? new Date(discovered).getTime() : NaN;
      if (!isNaN(t) && t < sevenDaysAgo) continue;

      const victim = String(post.victim || post.domain || 'Unknown Victim').slice(0, 200);
      const group = String(post.group || 'Unknown Group').slice(0, 80);
      const pageUrl = /^https:\/\/(www\.)?ransomware\.live\//.test(post.url || '')
        ? post.url
        : `https://www.ransomware.live/group/${encodeURIComponent(group)}#${encodeURIComponent(victim)}`;

      const lines = [
        `Ransomware group "${group}" listed a new victim on its leak site.`,
        '',
        `Victim: ${victim}`,
        `Group: ${group}`,
        post.country ? `Country: ${post.country}` : null,
        post.activity ? `Sector: ${post.activity}` : null,
        post.attackdate ? `Attack date: ${post.attackdate}` : null,
        `Discovered: ${discovered || 'Unknown'}`,
        post.description ? `\n${String(post.description).slice(0, 600)}` : null
      ].filter(Boolean);

      articles.push({
        title: `[Dark Web] Ransomware Leak: ${victim} (${group})`,
        description: lines.join('\n'),
        url: pageUrl,                       // unique per victim page
        source_name: 'Ransomware.live',
        source_type: 'darkweb',
        source_id: source?.id || null,
        user_id: source?.user_id || null,
        author: group,
        published_date: discovered || new Date().toISOString(),
        category: 'darkweb',
        severity: 'high',
        cve_id: null,
        is_patched: -1,
        has_poc: 0,
        tags: `ransomware,dark-web,leak,${group.toLowerCase().replace(/[^a-z0-9-]/g, '')}`
      });
    }

    console.log(`[DarkWeb] Ransomware.live: ${articles.length} recent leak posts`);
    return { success: true, articles, count: articles.length };
  } catch (error) {
    console.error(`[DarkWeb] Ransomware.live error: ${error.message}`);
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
      { ...requestConfig(), responseType: 'text', maxContentLength: 50 * 1024 * 1024 }
    );

    const data = (await parseJsonOffThread(response.data, 100)) || {};
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
        const iocTypes = [...new Set(iocs.map(i => i.ioc_type_desc || i.ioc_type))].join(', ');
        const firstSeen = firstIoc.first_seen || firstIoc.first_seen_utc;

        articles.push({
          title: `[IOC] ${malware} — ${iocs.length} new indicators detected`,
          description: `ThreatFox detected ${iocs.length} new IOC(s) for "${malware}".\n\nIOC Types: ${iocTypes}\nThreat Type: ${firstIoc.threat_type_desc || firstIoc.threat_type || 'Unknown'}\nConfidence: ${firstIoc.confidence_level || 'N/A'}%\nFirst Seen: ${firstSeen || 'Unknown'}\n\nSample IOC: ${firstIoc.ioc || 'N/A'}`,
          // `malware` is the Malpedia id ("win.cobalt_strike"); `malware_malpedia` is a full URL.
          // The #day fragment makes each day's summary a new article (DB de-dupes on URL).
          url: `https://threatfox.abuse.ch/browse/malware/${encodeURIComponent(firstIoc.malware || malware)}/#${dayOf(firstSeen)}`,
          source_name: 'ThreatFox - Malware IOCs',
          source_type: 'darkweb',
          source_id: source?.id || null,
          user_id: source?.user_id || null,
          author: firstIoc.reporter || 'abuse.ch',
          published_date: firstSeen || new Date().toISOString(),
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
    // URLhaus moved to a path-based endpoint (the old `urlhaus_recent` body 404s now).
    const response = await axios.get(
      // /limit/<n>/ caps the response (default is up to 1000 URLs)
      'https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/',
      requestConfig()
    );

    const data = response.data;
    const articles = [];

    if (data.urls && Array.isArray(data.urls)) {
      // Group by threat type — take recent ones
      const threatGroups = {};
      const oneDayAgo = new Date(Date.now() - 24 * 60 * 60 * 1000);

      for (const url of data.urls.slice(0, 50)) {
        // The API field is `date_added` ("2026-11-20 13:36:27 UTC"); `dateadded`
        // never existed, so the 24h filter let everything through.
        const addedDate = new Date(url.date_added || url.dateadded);
        if (!(addedDate >= oneDayAgo)) continue;

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
          url: `https://urlhaus.abuse.ch/browse/#${encodeURIComponent(threat)}-${dayOf(urls[0]?.date_added)}`,
          source_name: 'URLhaus - Malicious URLs',
          source_type: 'darkweb',
          source_id: source?.id || null,
          user_id: source?.user_id || null,
          author: urls[0]?.reporter || 'abuse.ch',
          published_date: urls[0]?.date_added || urls[0]?.dateadded || new Date().toISOString(),
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
      'query=get_recent&selector=100',   // latest 100 samples (bounded)
      requestConfig({ extraHeaders: { 'Content-Type': 'application/x-www-form-urlencoded' } })
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
          has_poc: 0, // a malware sample is not a proof-of-concept exploit
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
    } else if (source.url.includes('ransomware.live')) {
      result = await fetchRansomwareLive(source);
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
    results.push({ source: source.name, sourceId: source.id, ...result });
  }

  return { articles: allArticles, results };
}

module.exports = { fetchDarkWebIntel, fetchRansomwareLive, fetchRansomWatch, fetchThreatFox, fetchURLhaus, fetchMalwareBazaar };

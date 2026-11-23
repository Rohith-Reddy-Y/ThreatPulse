/**
 * ThreatPulse — Feed Aggregation Engine
 * Orchestrates all fetchers on a cron schedule
 */

const cron = require('node-cron');
const db = require('../database');
const { fetchRSSFeed } = require('./rss-fetcher');
const { fetchCVEs, fetchCISAKEV } = require('./cve-fetcher');
const { fetchDarkWebIntel } = require('./darkweb-fetcher');
const { scrapeSource } = require('./web-scraper');


// Insert in small chunks and yield to the event loop between them. Each insert
// runs synchronous enrichment (IOCs, actors, MITRE); a few hundred new items in
// one transaction (e.g. NVD after a fresh boot) could block the event loop for
// seconds on a ~0.1-CPU instance and fail the platform health check.
const INSERT_CHUNK = 25;
async function insertArticlesChunked(articles) {
  let newCount = 0;
  const newArticles = [];
  for (let i = 0; i < articles.length; i += INSERT_CHUNK) {
    const r = db.insertArticles(articles.slice(i, i + INSERT_CHUNK));
    newCount += r.newCount;
    newArticles.push(...r.newArticles);
    await new Promise(resolve => setImmediate(resolve));
  }
  return { newCount, newArticles };
}

let isRunning = false;
let lastFetchTime = null;
let fetchStats = { total: 0, new: 0, errors: 0 };
let onFetchComplete = null;

/**
 * Register a callback to run after each scheduled fetch completes with new articles
 */
function setOnFetchComplete(callback) {
  onFetchComplete = callback;
}

/**
 * Fetch all enabled sources
 */
async function fetchAllSources() {
  if (isRunning) {
    console.log('[Aggregator] Fetch already in progress, skipping...');
    return fetchStats;
  }

  isRunning = true;
  let result;
  try {
    result = await fetchSourceList(db.getEnabledSources());
  } finally {
    isRunning = false;
  }
  lastFetchTime = new Date().toISOString();
  const { newArticles, ...stats } = result;
  fetchStats = stats;
  return result;
}

/**
 * Fetch just the given sources (e.g. one user's own feeds, or a source that was
 * just added) without waiting for — or blocking — the platform-wide run.
 * Returns { total, new, errors, duration, newArticles }.
 */
async function fetchSources(sources) {
  return fetchSourceList((sources || []).filter(s => s && s.enabled !== 0 && s.enabled !== false));
}

async function fetchSourceList(sources) {
  const startTime = Date.now();
  let totalNew = 0;
  let totalErrors = 0;
  let totalFetched = 0;
  const newArticles = [];

  console.log('\n' + '='.repeat(60));
  console.log(`[Aggregator] Starting feed fetch at ${new Date().toISOString()}`);
  console.log('='.repeat(60));

  try {
    console.log(`[Aggregator] Fetching from ${sources.length} enabled sources`);

    // Group sources by type for efficient processing. Every type must land in
    // exactly one group: the dashboard used to offer "Blog/Website" (blog) and
    // "Other" (other), which matched no group, so those sources were never
    // fetched and sat at "Not yet fetched" forever. Generic "API" URLs other than
    // NVD / CISA KEV are read as feeds (most such endpoints serve RSS/Atom).
    const isKnownApi = s => s.url.includes('nvd.nist.gov') || s.url.includes('known_exploited_vulnerabilities');
    const rssSources = sources.filter(s => s.type === 'rss' || (s.type === 'api' && !isKnownApi(s)));
    const apiSources = sources.filter(s => s.type === 'api' && isKnownApi(s));
    const darkwebSources = sources.filter(s => s.type === 'darkweb');
    const browserSources = sources.filter(s => s.type === 'browser');
    const customSources = sources.filter(s =>
      !['rss', 'api', 'darkweb', 'browser'].includes(s.type));   // custom, website, blog, other, ...

    // --- 1. Fetch RSS Feeds (parallel, batched) ---
    console.log(`\n[RSS] Fetching ${rssSources.length} RSS feeds...`);
    const RSS_BATCH_SIZE = 5;
    for (let i = 0; i < rssSources.length; i += RSS_BATCH_SIZE) {
      const batch = rssSources.slice(i, i + RSS_BATCH_SIZE);
      const results = await Promise.allSettled(
        batch.map(source => fetchRSSFeed(source))
      );

      for (let j = 0; j < results.length; j++) {
        const source = batch[j];
        const result = results[j];

        if (result.status === 'fulfilled' && result.value.success) {
          const { articles } = result.value;
          if (articles.length > 0) {
            const inserted = await insertArticlesChunked(articles);
            totalNew += inserted.newCount;
            totalFetched += articles.length;
            newArticles.push(...inserted.newArticles);
          }
          db.updateSourceFetchStatus(source.id, {
            last_fetched: new Date().toISOString()
          });
        } else {
          totalErrors++;
          const errorMsg = result.status === 'rejected'
            ? result.reason?.message
            : result.value?.error;
          db.updateSourceFetchStatus(source.id, {
            last_fetched: new Date().toISOString(),
            last_error: errorMsg
          });
        }
      }

      // Small delay between batches to be polite
      if (i + RSS_BATCH_SIZE < rssSources.length) {
        await sleep(1000);
      }
    }

    // --- 2. Fetch CVE/API Sources ---
    console.log(`\n[API] Fetching ${apiSources.length} API sources...`);
    const apiSeen = new Set();
    for (const source of apiSources) {
      try {
        let result;

        // The NVD / CISA KEV fetchers use the server's own API key and rate-limit
        // budget, so only the built-in (system) sources may trigger them, and
        // each one at most once per cycle — a user-added "api" source pointing at
        // NVD used to cost a full extra NVD call + 6.5 s pause each.
        const kind = source.url.includes('nvd.nist.gov') ? 'nvd'
          : source.url.includes('known_exploited_vulnerabilities') ? 'kev' : null;
        if (kind && (source.added_by !== 'system' || apiSeen.has(kind))) {
          db.updateSourceFetchStatus(source.id, {
            last_fetched: new Date().toISOString(),
            last_error: source.added_by !== 'system'
              ? 'Built-in API feeds (NVD / CISA KEV) are provided by the platform sources'
              : null
          });
          continue;
        }
        if (kind) apiSeen.add(kind);

        if (source.url.includes('nvd.nist.gov')) {
          const apiKey = process.env.NVD_API_KEY || null;
          result = await fetchCVEs(source, apiKey);
        } else if (source.url.includes('known_exploited_vulnerabilities')) {
          result = await fetchCISAKEV(source);
        } else {
          continue;
        }

        if (result.success && result.articles.length > 0) {
          const inserted = await insertArticlesChunked(result.articles);
          totalNew += inserted.newCount;
          totalFetched += result.articles.length;
          newArticles.push(...inserted.newArticles);
        }
        if (!result.success) totalErrors++;   // fetchers report failure, they don't throw

        db.updateSourceFetchStatus(source.id, {
          last_fetched: new Date().toISOString(),
          last_error: result.success ? null : result.error
        });

        // NVD rate limit compliance
        if (source.url.includes('nvd.nist.gov')) {
          await sleep(process.env.NVD_API_KEY ? 1000 : 6500);
        }

      } catch (error) {
        totalErrors++;
        db.updateSourceFetchStatus(source.id, {
          last_fetched: new Date().toISOString(),
          last_error: error.message
        });
      }
    }

    // --- 3. Fetch Dark Web Intel ---
    if (darkwebSources.length > 0) {
      console.log(`\n[DarkWeb] Fetching ${darkwebSources.length} dark web intel sources...`);
      try {
        const dwResult = await fetchDarkWebIntel(darkwebSources);
        if (dwResult.articles.length > 0) {
          const inserted = await insertArticlesChunked(dwResult.articles);
          totalNew += inserted.newCount;
          totalFetched += dwResult.articles.length;
          newArticles.push(...inserted.newArticles);
        }

        // Update source statuses (by id: names are not unique across users)
        for (const r of dwResult.results) {
          if (!r.success) totalErrors++;
          const source = darkwebSources.find(s => s.id === r.sourceId);
          if (source) {
            db.updateSourceFetchStatus(source.id, {
              last_fetched: new Date().toISOString(),
              last_error: r.success ? null : r.error
            });
          }
        }
      } catch (error) {
        totalErrors++;
        console.error(`[DarkWeb] Overall error: ${error.message}`);
      }
    }

    // --- 4. Fetch Custom/Scraped Sources ---
    if (customSources.length > 0) {
      console.log(`\n[Custom] Scraping ${customSources.length} custom sources...`);
      for (const source of customSources) {
        try {
          const result = await scrapeSource(source);
          if (result.success && result.articles.length > 0) {
            const inserted = await insertArticlesChunked(result.articles);
            totalNew += inserted.newCount;
            totalFetched += result.articles.length;
            newArticles.push(...inserted.newArticles);
          }
          if (!result.success) totalErrors++;
          db.updateSourceFetchStatus(source.id, {
            last_fetched: new Date().toISOString(),
            last_error: result.success ? null : result.error
          });
        } catch (error) {
          totalErrors++;
          db.updateSourceFetchStatus(source.id, {
            last_fetched: new Date().toISOString(),
            last_error: error.message
          });
        }
        await sleep(2000); // Be polite with scraping
      }
    }

    // --- 5. Fetch Cloudflare/Akamai-protected feeds via a headless browser ---
    if (browserSources.length > 0) {
      const browserFetcher = require('./browser-fetcher');
      if (browserFetcher.isAvailable()) {
        console.log(`\n[Browser] Fetching ${browserSources.length} protected feeds via headless browser...`);
        try {
          const { articles, results } = await browserFetcher.fetchViaBrowser(browserSources);
          if (articles.length > 0) {
            const inserted = await insertArticlesChunked(articles);
            totalNew += inserted.newCount;
            totalFetched += articles.length;
            newArticles.push(...inserted.newArticles);
          }
          for (const r of results) {
            if (!r.success) totalErrors++;
            db.updateSourceFetchStatus(r.source.id, {
              last_fetched: new Date().toISOString(),
              last_error: r.success ? null : r.error
            });
          }
        } catch (error) {
          totalErrors++;
          console.error(`[Browser] Overall error: ${error.message}`);
        }
      } else {
        // No headless Chrome here (e.g. Render free tier): fetch them like normal
        // feeds instead — the RSS fetcher falls back to Google News if blocked.
        console.log(`[Browser] No headless Chrome — fetching ${browserSources.length} browser-type source(s) as plain RSS (with fallback).`);
        for (const source of browserSources) {
          try {
            const result = await fetchRSSFeed(source);
            if (result.success && result.articles.length > 0) {
              const inserted = await insertArticlesChunked(result.articles);
              totalNew += inserted.newCount;
              totalFetched += result.articles.length;
              newArticles.push(...inserted.newArticles);
            }
            if (!result.success) totalErrors++;
            db.updateSourceFetchStatus(source.id, {
              last_fetched: new Date().toISOString(),
              last_error: result.success ? null : result.error
            });
          } catch (error) {
            totalErrors++;
            db.updateSourceFetchStatus(source.id, { last_fetched: new Date().toISOString(), last_error: error.message });
          }
        }
      }
    }

  } catch (error) {
    console.error(`[Aggregator] Fatal error: ${error.message}`);
    totalErrors++;
  }

  const duration = ((Date.now() - startTime) / 1000).toFixed(1);

  console.log('\n' + '='.repeat(60));
  console.log(`[Aggregator] Fetch complete in ${duration}s`);
  console.log(`[Aggregator] Total fetched: ${totalFetched} | New: ${totalNew} | Errors: ${totalErrors}`);
  console.log('='.repeat(60) + '\n');

  return { total: totalFetched, new: totalNew, errors: totalErrors, duration, newArticles };
}

/**
 * Start the cron scheduler
 */
function startScheduler(cronExpression) {
  const expr = cronExpression || process.env.FETCH_CRON || '*/15 * * * *';

  if (!cron.validate(expr)) {
    console.error(`[Scheduler] Invalid cron expression: ${expr}`);
    return null;
  }

  console.log(`[Scheduler] Starting feed scheduler with cron: ${expr}`);

  const task = cron.schedule(expr, async () => {
    console.log(`[Scheduler] Cron triggered at ${new Date().toISOString()}`);
    const result = await fetchAllSources();
    if (onFetchComplete && result.newArticles && result.newArticles.length > 0) {
      await onFetchComplete(result.newArticles);
    }
  });

  return task;
}

function getStatus() {
  return {
    isRunning,
    lastFetchTime,
    ...fetchStats
  };
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

module.exports = { fetchAllSources, fetchSources, startScheduler, getStatus, setOnFetchComplete, getOnFetchComplete: () => onFetchComplete };

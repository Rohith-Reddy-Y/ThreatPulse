/**
 * ThreatPulse — Generic Web Scraper
 * Scrapes article metadata from custom URLs that don't have RSS feeds
 */

const axios = require('axios');
const cheerio = require('cheerio');
const { detectCategory, detectSeverity, extractCVE, detectPOC, detectPatchStatus } = require('./rss-fetcher');

const HTTP_CONFIG = {
  timeout: 15000,
  headers: {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5'
  },
  maxRedirects: 5
};

/**
 * Extract metadata from an HTML page
 */
function extractMetadata($, url) {
  // Title
  const title =
    $('meta[property="og:title"]').attr('content') ||
    $('meta[name="twitter:title"]').attr('content') ||
    $('h1').first().text().trim() ||
    $('title').text().trim() ||
    'Untitled';

  // Description
  const description =
    $('meta[property="og:description"]').attr('content') ||
    $('meta[name="description"]').attr('content') ||
    $('meta[name="twitter:description"]').attr('content') ||
    $('article p').first().text().trim().substring(0, 500) ||
    $('main p').first().text().trim().substring(0, 500) ||
    $('p').first().text().trim().substring(0, 500) ||
    '';

  // Author
  const author =
    $('meta[name="author"]').attr('content') ||
    $('meta[property="article:author"]').attr('content') ||
    $('[rel="author"]').text().trim() ||
    $('[class*="author"]').first().text().trim() ||
    null;

  // Published Date
  const publishedDate =
    $('meta[property="article:published_time"]').attr('content') ||
    $('meta[name="date"]').attr('content') ||
    $('time[datetime]').attr('datetime') ||
    $('meta[property="og:updated_time"]').attr('content') ||
    null;

  // Image
  const image =
    $('meta[property="og:image"]').attr('content') ||
    $('meta[name="twitter:image"]').attr('content') ||
    null;

  return { title, description, author, publishedDate, image };
}

/**
 * Try to find article links on a page (for blog/news sites)
 */
function extractArticleLinks($, baseUrl) {
  const links = [];
  const seen = new Set();

  // Look for article links in common containers
  const selectors = [
    'article a[href]',
    '.post a[href]',
    '.entry a[href]',
    'h2 a[href]',
    'h3 a[href]',
    '.article-title a[href]',
    '.post-title a[href]',
    '[class*="headline"] a[href]',
    '[class*="story"] a[href]'
  ];

  for (const selector of selectors) {
    $(selector).each((_, el) => {
      let href = $(el).attr('href');
      if (!href) return;

      // Make absolute URL
      if (href.startsWith('/')) {
        try {
          const base = new URL(baseUrl);
          href = `${base.protocol}//${base.host}${href}`;
        } catch { return; }
      }
      if (!href.startsWith('http')) return;

      // Skip non-article URLs
      if (href.includes('#') || href.includes('javascript:') || href.includes('/tag/') ||
          href.includes('/category/') || href.includes('/author/') || href.includes('/page/')) return;

      if (!seen.has(href)) {
        seen.add(href);
        links.push({
          url: href,
          title: $(el).text().trim() || null
        });
      }
    });
  }

  return links.slice(0, 20); // Max 20 articles per source
}

/**
 * Scrape a single URL for article content
 */
async function scrapeUrl(url) {
  try {
    const response = await axios.get(url, HTTP_CONFIG);
    const $ = cheerio.load(response.data);
    const metadata = extractMetadata($, url);

    return {
      success: true,
      ...metadata,
      url
    };
  } catch (error) {
    return {
      success: false,
      error: error.message,
      url
    };
  }
}

/**
 * Scrape a source — either a single article or a blog/news index page
 */
async function scrapeSource(source) {
  try {
    const response = await axios.get(source.url, HTTP_CONFIG);
    const $ = cheerio.load(response.data);
    const articles = [];

    // First check if this is a single article or an index page
    const articleLinks = extractArticleLinks($, source.url);

    if (articleLinks.length > 0) {
      // It's an index page — scrape each article link
      for (const link of articleLinks.slice(0, 10)) { // Limit to 10 per fetch
        const title = link.title || '';
        const category = detectCategory(title, '');

        articles.push({
          title: title || 'Untitled',
          description: '', // Would need to fetch each page for full description
          url: link.url,
          source_name: source.name,
          source_type: 'custom',
          source_id: source.id,
          user_id: source.user_id || null,
          author: null,
          published_date: new Date().toISOString(),
          category: source.category || category,
          severity: detectSeverity(title, '', category),
          cve_id: extractCVE(title),
          is_patched: detectPatchStatus(title, ''),
          has_poc: detectPOC(title, ''),
          tags: null
        });
      }
    } else {
      // It's a single article page — extract metadata
      const metadata = extractMetadata($, source.url);
      const fullText = `${metadata.title} ${metadata.description}`;
      const category = detectCategory(metadata.title, metadata.description);

      articles.push({
        title: metadata.title,
        description: metadata.description,
        url: source.url,
        source_name: source.name,
        source_type: 'custom',
        source_id: source.id,
          user_id: source.user_id || null,
        author: metadata.author,
        published_date: metadata.publishedDate || new Date().toISOString(),
        category: source.category || category,
        severity: detectSeverity(metadata.title, metadata.description, category),
        cve_id: extractCVE(fullText),
        is_patched: detectPatchStatus(metadata.title, metadata.description),
        has_poc: detectPOC(metadata.title, metadata.description),
        tags: null
      });
    }

    console.log(`[Scraper] ${source.name}: ${articles.length} articles found`);
    return { success: true, articles, count: articles.length };

  } catch (error) {
    console.error(`[Scraper] Error scraping ${source.name}: ${error.message}`);
    return { success: false, articles: [], error: error.message };
  }
}

module.exports = { scrapeSource, scrapeUrl, extractMetadata };

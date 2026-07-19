/**
 * ThreatPulse — RSS Feed Fetcher
 * Fetches and parses RSS/Atom feeds from cybersecurity sources
 */

const RSSParser = require('rss-parser');
// Shared, source-agnostic enrichment (sector / threat actors / MITRE IDs)
const { detectSector, detectThreatActors, extractMitreIds } = require('../enrich');

const parser = new RSSParser({
  timeout: 20000,
  headers: {
    // Present as a real browser — many worthy feeds (Cloudflare/Akamai fronted)
    // return 403 to non-browser User-Agents.
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36',
    'Accept': 'application/rss+xml, application/atom+xml, application/xml;q=0.9, text/html;q=0.8, */*;q=0.7',
    'Accept-Language': 'en-US,en;q=0.9'
  },
  customFields: {
    item: [
      ['dc:creator', 'creator'],
      ['content:encoded', 'contentEncoded'],
      ['dc:date', 'dcDate']
    ]
  }
});

/**
 * Detect category from content/title
 */
function detectCategory(title, description) {
  const text = `${title} ${description}`.toLowerCase();

  if (/cve-\d{4}-\d+|vulnerability|vuln|exploit|rce|xss|sqli|buffer overflow|zero[- ]day/i.test(text)) {
    return 'vulnerability';
  }
  if (/malware|trojan|ransomware|botnet|backdoor|rootkit|spyware|worm|rat /i.test(text)) {
    return 'malware';
  }
  if (/breach|leak|data (loss|exposure|stolen)|hack|compromised|credential/i.test(text)) {
    return 'breach';
  }
  if (/advisory|alert|patch|update|bulletin|security notice/i.test(text)) {
    return 'advisory';
  }
  if (/apt|threat actor|campaign|nation[- ]state|espionage|cyber[- ]attack/i.test(text)) {
    return 'threat_intel';
  }
  if (/dark ?web|underground|tor |onion|leaked|darknet/i.test(text)) {
    return 'darkweb';
  }
  return 'news';
}

/**
 * Detect severity from content
 */
function detectSeverity(title, description, category) {
  const text = `${title} ${description}`.toLowerCase();

  if (/critical|cvss[:\s]*(?:9|10)|emergency|actively exploited|zero[- ]day|remote code execution|rce/i.test(text)) {
    return 'critical';
  }
  if (/high|severe|important|cvss[:\s]*(?:7|8)|privilege escalation/i.test(text)) {
    return 'high';
  }
  if (/medium|moderate|cvss[:\s]*(?:4|5|6)/i.test(text)) {
    return 'medium';
  }
  if (/low|informational|cvss[:\s]*(?:0|1|2|3)/i.test(text)) {
    return 'low';
  }

  // Default by category
  if (category === 'vulnerability' || category === 'breach') return 'high';
  if (category === 'advisory') return 'medium';
  return 'medium';
}

/**
 * Extract CVE IDs from text
 */
function extractCVE(text) {
  if (!text) return null;
  const match = text.match(/CVE-\d{4}-\d{4,}/i);
  return match ? match[0].toUpperCase() : null;
}

/**
 * Detect if PoC is mentioned
 */
function detectPOC(title, description) {
  const text = `${title} ${description}`.toLowerCase();
  return /proof[- ]of[- ]concept|poc |exploit[- ]code|exploit available|weaponized|exploit-db|github\.com.*exploit|metasploit/i.test(text) ? 1 : 0;
}

/**
 * Detect patch status
 */
function detectPatchStatus(title, description) {
  const text = `${title} ${description}`.toLowerCase();
  if (/patched|fix available|fixed|update released|patch released|remediat/i.test(text)) return 1;
  if (/unpatched|no fix|no patch|zero[- ]day|0[- ]day/i.test(text)) return 0;
  return -1; // unknown
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

/**
 * Fetch a single RSS feed and normalize articles
 */
async function fetchRSSFeed(source) {
  try {
    const feed = await parser.parseURL(source.url);
    const articles = [];

    for (const item of (feed.items || [])) {
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

    return { success: true, articles, count: articles.length };
  } catch (error) {
    console.error(`[RSS] Error fetching ${source.name}: ${error.message}`);
    return { success: false, articles: [], error: error.message };
  }
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

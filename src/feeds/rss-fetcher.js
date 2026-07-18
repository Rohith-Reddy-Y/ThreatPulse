/**
 * ThreatPulse — RSS Feed Fetcher
 * Fetches and parses RSS/Atom feeds from cybersecurity sources
 */

const RSSParser = require('rss-parser');

const parser = new RSSParser({
  timeout: 15000,
  headers: {
    'User-Agent': 'ThreatPulse/1.0 (Threat Intelligence Aggregator)',
    'Accept': 'application/rss+xml, application/xml, text/xml, */*'
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
function extractMitreIds(title, description) {
  const text = `${title} ${description}`;
  const matches = text.match(/\b(T[1-9]\d{3}(\.\d{3})?|TA00\d{2})\b/g);
  if (!matches || matches.length === 0) return null;
  const unique = [...new Set(matches.map(m => m.toUpperCase()))];
  return unique.join(',');
}

/**
 * Detect industry sector from content
 */
function detectSector(title, description) {
  const text = `${title} ${description}`.toLowerCase();
  if (/\bbank\b|\bfinancial\b|\bpayment\b|\bcredit card\b|\bswift\b|\bfintech\b|\batm\b|\bpci\b|fs-isac|banking|\bfin\d|wire transfer|monetary/i.test(text)) return 'financial';
  if (/\bhospital\b|\bhipaa\b|\bpatient\b|\bmedical\b|\bpharma\b|\bhealthcare\b|\bclinic\b|\behr\b|health data/i.test(text)) return 'healthcare';
  if (/\bgovernment\b|\bfederal\b|\belection\b|state-sponsored|\bmilitary\b|\bdefense\b|\bintelligence agency|national security/i.test(text)) return 'government';
  if (/\bcloud\b|\bsaas\b|\bdevops\b|\bkubernetes\b|\bdocker\b|\bci\/cd\b|software supply chain/i.test(text)) return 'technology';
  return null;
}

/**
 * Detect known threat actors from content
 */
const KNOWN_THREAT_ACTORS = [
  'Scattered Spider', 'Lazarus Group', 'APT28', 'APT29', 'APT41', 'APT27', 'APT33', 'APT34', 'APT35', 'APT38', 'APT40',
  'Fancy Bear', 'Cozy Bear', 'BlackCat', 'ALPHV', 'LockBit', 'Cl0p', 'Clop',
  'Volt Typhoon', 'Salt Typhoon', 'Flax Typhoon', 'Sandworm', 'FIN7', 'FIN11', 'FIN12',
  'REvil', 'Conti', 'DarkSide', 'Black Basta', 'Rhysida', 'Play', 'Akira', 'Medusa', 'Royal',
  'Turla', 'Kimsuky', 'Charming Kitten', 'MuddyWater', 'OilRig', 'Hafnium',
  'UNC2452', 'UNC3886', 'Star Blizzard', 'Midnight Blizzard', 'Forest Blizzard',
  'BlackTech', 'Mustang Panda', 'Gamaredon', 'Lapsus', 'Vice Society',
  'BianLian', 'NoEscape', 'Hunters International', 'INC Ransom', 'RansomHub',
  'Qilin', 'DragonForce', 'Embargo'
];

function detectThreatActors(title, description) {
  const text = `${title} ${description}`;
  const found = [];
  for (const actor of KNOWN_THREAT_ACTORS) {
    if (text.toLowerCase().includes(actor.toLowerCase())) {
      found.push(actor);
    }
  }
  return found.length > 0 ? found.join(',') : null;
}

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
        mitre_ids: extractMitreIds(title, description),
        sector: detectSector(title, description),
        threat_actors: detectThreatActors(title, description)
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

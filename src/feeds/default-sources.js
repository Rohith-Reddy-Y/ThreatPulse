/**
 * ThreatPulse — Default Threat Intelligence Sources
 * 30+ pre-configured feeds from around the world
 */

const DEFAULT_SOURCES = [
  // ============================================
  // 🔴 VULNERABILITY DATABASES & ADVISORIES
  // ============================================
  {
    name: 'NVD - National Vulnerability Database',
    url: 'https://services.nvd.nist.gov/rest/json/cves/2.0',
    type: 'api',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'CISA Known Exploited Vulnerabilities',
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    type: 'api',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Exploit-DB',
    url: 'https://www.exploit-db.com/rss.xml',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },

  // ============================================
  // 📰 CYBERSECURITY NEWS & BLOGS
  // ============================================
  {
    name: 'The Hacker News',
    url: 'https://feeds.feedburner.com/TheHackersNews',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'GBHackers Security',
    url: 'https://gbhackers.com/feed/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'BleepingComputer',
    url: 'https://www.bleepingcomputer.com/feed/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Krebs on Security',
    url: 'https://krebsonsecurity.com/feed/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Dark Reading',
    url: 'https://www.darkreading.com/rss.xml',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'SecurityWeek',
    url: 'https://www.securityweek.com/feed/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'The Record by Recorded Future',
    url: 'https://therecord.media/feed',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },
  {
    name: 'Infosecurity Magazine',
    url: 'https://www.infosecurity-magazine.com/rss/news/',
    type: 'rss',
    category: 'news',
    added_by: 'system'
  },

  // ============================================
  // 🏢 VENDOR THREAT INTELLIGENCE
  // ============================================
  {
    name: 'Cisco Talos Blog',
    url: 'https://blog.talosintelligence.com/rss/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Microsoft Security Blog',
    url: 'https://www.microsoft.com/en-us/security/blog/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'CrowdStrike Blog',
    url: 'https://www.crowdstrike.com/blog/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Palo Alto Unit 42',
    url: 'https://unit42.paloaltonetworks.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'SentinelOne Labs',
    url: 'https://www.sentinelone.com/labs/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Kaspersky Securelist',
    url: 'https://securelist.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Zero Day Initiative (Published Advisories)',
    url: 'https://www.zerodayinitiative.com/rss/published/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },

  // ============================================
  // 🛠️ DETECTION ENGINEERING (TTPs · PoCs · MITRE-mapped)
  // ============================================
  {
    name: 'The DFIR Report',
    url: 'https://thedfirreport.com/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Red Canary',
    url: 'https://redcanary.com/blog/feed/',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Elastic Security Labs',
    url: 'https://www.elastic.co/security-labs/rss/feed.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },
  {
    name: 'Rapid7 Blog',
    url: 'https://www.rapid7.com/blog/rss/',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Google Project Zero',
    url: 'https://googleprojectzero.blogspot.com/feeds/posts/default',
    type: 'rss',
    category: 'vulnerability',
    added_by: 'system'
  },
  {
    name: 'Huntress Blog',
    url: 'https://www.huntress.com/blog/rss.xml',
    type: 'rss',
    category: 'threat_intel',
    added_by: 'system'
  },

  // ============================================
  // 🌑 DARK WEB & UNDERGROUND INTEL (Clearnet APIs)
  // ============================================
  {
    name: 'RansomWatch - Ransomware Leak Tracker',
    url: 'https://raw.githubusercontent.com/joshhighet/ransomwatch/main/posts.json',
    type: 'darkweb',
    category: 'darkweb',
    added_by: 'system'
  },
  {
    name: 'URLhaus - Malicious URLs',
    url: 'https://urlhaus-api.abuse.ch/v1/',
    type: 'darkweb',
    category: 'darkweb',
    added_by: 'system'
  },
  {
    name: 'ThreatFox - Malware IOCs',
    url: 'https://threatfox-api.abuse.ch/api/v1/',
    type: 'darkweb',
    category: 'darkweb',
    added_by: 'system'
  },
  {
    name: 'MalwareBazaar - Malware Samples',
    url: 'https://mb-api.abuse.ch/api/v1/',
    type: 'darkweb',
    category: 'darkweb',
    added_by: 'system'
  },
  {
    name: 'Feodo Tracker - Botnet C2s',
    url: 'https://feodotracker.abuse.ch/downloads/ipblocklist_recommended.json',
    type: 'darkweb',
    category: 'darkweb',
    added_by: 'system'
  },

  // ============================================
  // 🐦 COMMUNITY & SOCIAL
  // ============================================
  {
    name: 'SANS Internet Storm Center',
    url: 'https://isc.sans.edu/rssfeed.xml',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },

  // ============================================
  // 🏛️ GOVERNMENT & CERT ADVISORIES (Worldwide)
  // ============================================
  {
    name: 'CISA Alerts (USA)',
    url: 'https://www.cisa.gov/news.xml',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'CERT-EU (European Union)',
    url: 'https://cert.europa.eu/publications/security-advisories-rss',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'CERT-FR ANSSI Alerts (France)',
    url: 'https://www.cert.ssi.gouv.fr/alerte/feed/',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'JPCERT/CC (Japan)',
    url: 'https://www.jpcert.or.jp/english/rss/jpcert-en.rdf',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'JPCERT Blog (Japan)',
    url: 'https://blogs.jpcert.or.jp/en/atom.xml',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  },
  {
    name: 'CIS/MS-ISAC Advisories (USA)',
    url: 'https://www.cisecurity.org/feed/advisories',
    type: 'rss',
    category: 'advisory',
    added_by: 'system'
  }
];

// System sources that were removed because their feeds are permanently broken.
// These are cleaned up from existing installs on startup.
const OBSOLETE_SOURCES = [
  'CCCS (Canada)',
  'BSI (Germany)',
  'Google/Mandiant Threat Intel',
  'Trend Micro Research', // replaced by the correctly-labelled ZDI entry
  // Legacy feeds that are permanently dead (404 / bot-blocked / rate-limited)
  'HackerOne Blog',
  'Reddit r/netsec',
  'Reddit r/malware',
  'SC Magazine',
  'Sophos News', // nakedsecurity retired; news.sophos feed returns 404
];

function seedDefaultSources(db) {
  const database = typeof db.addSource === 'function' ? db : require('../database');
  let added = 0, updated = 0, skipped = 0, removed = 0;

  // 1. Remove obsolete/broken system sources FIRST, so renamed replacements
  //    (which may reuse the same feed URL) can be added cleanly afterwards.
  for (const s of database.getAllSources()) {
    if (OBSOLETE_SOURCES.includes(s.name) && (s.added_by === 'system' || !s.user_id)) {
      const res = database.deleteSource(s.id);
      if (res.success) removed++;
    }
  }

  // 2. Add new defaults / fix relocated URLs on existing system sources
  const allSources = database.getAllSources();
  for (const source of DEFAULT_SOURCES) {
    const byName = allSources.find(s => s.name === source.name);
    const byUrl = allSources.find(s => s.url === source.url);

    if (byName) {
      // Same source, but the feed URL moved — repair it in place
      if (byName.url !== source.url && (byName.added_by === 'system' || !byName.user_id)) {
        database.updateSource(byName.id, { url: source.url, type: source.type, category: source.category });
        updated++;
      } else {
        skipped++;
      }
      continue;
    }
    if (byUrl) { skipped++; continue; }

    const result = database.addSource(source);
    if (result.success) added++; else skipped++;
  }

  // 3. De-duplicate system sources that share a name (legacy installs sometimes
  //    accumulated duplicates with slightly different/stale URLs). Keep the row whose
  //    URL matches a current default (else the lowest id); delete the rest.
  const defaultUrls = new Set(DEFAULT_SOURCES.map(s => s.url));
  const byName = {};
  for (const s of database.getAllSources()) {
    if (!(s.added_by === 'system' || !s.user_id)) continue;
    const key = s.name.trim().toLowerCase();
    (byName[key] = byName[key] || []).push(s);
  }
  for (const key of Object.keys(byName)) {
    const rows = byName[key].sort((a, b) => a.id - b.id);
    if (rows.length < 2) continue;
    const keep = rows.find(r => defaultUrls.has(r.url)) || rows[0];
    for (const r of rows) {
      if (r.id !== keep.id) {
        const res = database.deleteSource(r.id);
        if (res.success) removed++;
      }
    }
  }

  console.log(`[Sources] Seeded ${added} new, fixed ${updated}, removed ${removed} obsolete/dupe, ${skipped} unchanged`);
  return { added, updated, removed, skipped, total: DEFAULT_SOURCES.length };
}

module.exports = { DEFAULT_SOURCES, seedDefaultSources };

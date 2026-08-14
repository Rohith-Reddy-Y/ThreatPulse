/**
 * ThreatPulse — Article Enrichment
 * Shared, source-agnostic tagging of industry sector, known threat actors, and
 * MITRE ATT&CK IDs from article text. Applied centrally at insert time so every
 * feed (RSS, NVD/CVE, CISA KEV, dark web, scraped) is enriched uniformly.
 */

// ── Industry sector ──────────────────────────────────────────
// Only the four sectors exposed in the dashboard filter dropdown.
const SECTOR_PATTERNS = [
  ['financial', /\b(bank|banking|financial|finance|fintech|payment|credit[- ]card|swift|atm|pci[- ]dss|pci|wire transfer|monetary|insurer|insurance|stock exchange|brokerage|trading platform|crypto(currency)?[- ]exchange|fs-isac)\b/i],
  ['healthcare', /\b(hospital|hipaa|patient|medical|pharma(ceutical)?|healthcare|health[- ]care|clinic|ehr|health data|medicare|medicaid|biotech|life sciences|medtech)\b/i],
  ['government', /\b(government|federal|election|state[- ]sponsored|military|defense|ministry|municipal|public sector|national security|pentagon|nation[- ]state|city council|\.gov|cisa|nsa|fbi)\b/i],
  ['technology', /\b(cloud|saas|paas|devops|kubernetes|docker|ci\/cd|software supply chain|open[- ]source|data center|semiconductor|microservice|npm|pypi|github|gitlab|api gateway|tech giant|software vendor)\b/i],
];

function detectSector(text) {
  const t = String(text || '');
  for (const [sector, re] of SECTOR_PATTERNS) {
    if (re.test(t)) return sector;
  }
  return null;
}

// ── Known threat actors ──────────────────────────────────────
// Distinctive names — safe to match on a plain word boundary.
// Includes the full Synchrony Tracked Threat Actor Library (127 actors across
// A-Critical, B-High, C-Medium, D-Low, E-Legacy) plus common public aliases.
const DISTINCTIVE_ACTORS = [
  // A — Critical
  'Scattered Spider', 'Nimble Spider',
  // B — High
  'Arcane Kitten', 'Bitwise Spider', 'Brain Spider', 'Carbon Spider', 'Cozy Bear',
  'Donut Spider', 'Famous Chollima', 'Frozen Spider', 'Honey Spider', 'Indrik Spider',
  'Knockout Spider', 'Labyrinth Chollima', 'Lunar Spider', 'Mallard Spider',
  'Mangled Spider', 'Masked Spider', 'Merchant Spider', 'Monarch Spider',
  'Prophet Spider', 'Punk Spider', 'Recess Spider', 'Scully Spider', 'Silent Chollima',
  'Stardust Chollima', 'Traveling Spider', 'Veto Spider', 'Wandering Spider',
  'Wicked Panda', 'Royal Spider', 'Graceful Spider', 'Butler Spider', 'Hook Spider',
  'Rice Spider', 'Lightning Spider', 'Nitro Spider', 'Murky Panda',
  'Lightbasin Activity Cluster', 'Comrade Saiga',
  // C — Medium
  'Aquatic Panda', 'Banished Kitten', 'Cascade Panda', 'Chariot Spider', 'Chef Spider',
  'Clockwork Spider', 'Cookie Spider', 'Demon Spider', 'Distant Spider', 'Fancy Bear',
  'Hazard Spider', 'Hermit Spider', 'Highground Activity Cluster', 'Jackpot Panda',
  'Nemesis Kitten', 'Ocean Buffalo', 'Odyssey Spider', 'Outrider Tiger', 'Phantom Panda',
  'Ricochet Chollima', 'Salty Spider', 'Shining Spider', 'Smoky Spider', 'Solar Spider',
  'Spectral Kitten', 'Squab Spider', 'Static Kitten', 'Tunnel Spider', 'Vampire Spider',
  'Velvet Chollima', 'Vengeful Kitten', 'Vice Spider', 'Viking Spider', 'Alpha Spider',
  'Helix Kitten', 'Emissary Panda', 'Apothecary Spider', 'Percussion Spider',
  'Renaissance Spider', 'Samba Spider', 'Scion Spider', 'Sly Spider', 'Sinful Spider',
  'Curly Spider', 'Imperial Kitten', 'Vault Panda', 'Radiant Spider', 'Plump Spider',
  // D — Low
  'Pulsar Kitten', 'Chaotic Spider', 'Holiday Spider', 'Chatty Spider', 'Haywire Kitten',
  // E — Legacy
  'Anthropoid Spider', 'Aviator Spider', 'Black Basta', 'Blind Spider', 'Charming Kitten',
  'Circuit Panda', 'Circus Spider', 'Cobalt Spider', 'Compass Spider', 'Cyborg Spider',
  'Doppel Spider', 'Ember Bear', 'Feral Spider', 'Judgement Panda', 'Keyhole Panda',
  'Monty Spider', 'Narwhal Spider', 'Night Spider', 'Octane Panda', 'Outlaw Spider',
  'Pioneer Kitten', 'Refined Kitten', 'Remix Kitten', 'Riddle Spider', 'Skeleton Spider',
  'TA 511', 'TA 551', 'Tiny Spider', 'Twisted Spider', 'Venom Spider', 'Voodoo Bear',
  'Wet Panda', 'Whisper Spider', 'Wizard Spider',
  // Common public aliases (kept for broader matching)
  'Lazarus Group', 'Lazarus', 'APT28', 'APT29', 'APT41', 'APT27', 'APT33', 'APT34', 'APT35', 'APT38', 'APT40',
  'BlackCat', 'ALPHV', 'LockBit', 'Cl0p', 'Clop',
  'Volt Typhoon', 'Salt Typhoon', 'Flax Typhoon', 'Sandworm', 'FIN7', 'FIN11', 'FIN12',
  'REvil', 'Conti', 'DarkSide', 'Rhysida',
  'Turla', 'Kimsuky', 'MuddyWater', 'OilRig', 'Hafnium',
  'UNC2452', 'UNC3886', 'Star Blizzard', 'Midnight Blizzard', 'Forest Blizzard',
  'BlackTech', 'Mustang Panda', 'Gamaredon', 'Lapsus', 'Vice Society',
  'BianLian', 'NoEscape', 'Hunters International', 'INC Ransom', 'RansomHub',
  'Qilin', 'DragonForce', 'BlackByte', 'Snatch',
];

// Ambiguous names that are also ordinary English words — only tag these when the
// text also mentions a threat context, to avoid false positives ("Play Store",
// "Royal Mail", "display", etc.).
const AMBIGUOUS_ACTORS = ['Play', 'Akira', 'Medusa', 'Royal', 'Embargo', 'Hive', 'Cuba', 'Maze'];
const THREAT_CONTEXT = /\b(ransomware|ransom|threat actor|threat group|apt|gang|extortion|leak site|data breach|cybercrime|affiliate|encryptor)\b/i;

function escapeRegExp(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

function detectThreatActors(text) {
  const t = String(text || '');
  const found = new Set();

  for (const actor of DISTINCTIVE_ACTORS) {
    const re = new RegExp(`\\b${escapeRegExp(actor)}\\b`, 'i');
    if (re.test(t)) found.add(actor);
  }

  if (THREAT_CONTEXT.test(t)) {
    for (const actor of AMBIGUOUS_ACTORS) {
      const re = new RegExp(`\\b${escapeRegExp(actor)}\\b`, 'i');
      if (re.test(t)) found.add(actor);
    }
  }

  return found.size > 0 ? [...found].join(',') : null;
}

// ── MITRE ATT&CK technique / tactic IDs ──────────────────────
function extractMitreIds(text) {
  const matches = String(text || '').match(/\b(T[1-9]\d{3}(\.\d{3})?|TA00\d{2})\b/g);
  if (!matches || matches.length === 0) return null;
  return [...new Set(matches.map(m => m.toUpperCase()))].join(',');
}

// ── IOC Extraction ──────────────────────────────────────────
const { extractIOCs, formatIOCsForDB } = require('./feeds/ioc-extractor');

/**
 * Fill in sector / threat_actors / mitre_ids / iocs on an article when the fetcher
 * didn't already provide them. Mutates and returns the article.
 */
function enrichArticle(article) {
  if (!article) return article;
  const text = `${article.title || ''} ${article.description || ''} ${article.tags || ''}`;
  if (article.sector == null) article.sector = detectSector(text);
  if (article.threat_actors == null) article.threat_actors = detectThreatActors(text);
  if (article.mitre_ids == null) article.mitre_ids = extractMitreIds(text);
  // Always extract IOCs (overwrites on every enrich — cheap, no side effects)
  const iocs = extractIOCs(text);
  article.iocs = formatIOCsForDB(iocs);
  return article;
}

module.exports = { detectSector, detectThreatActors, extractMitreIds, enrichArticle, extractIOCs, formatIOCsForDB };

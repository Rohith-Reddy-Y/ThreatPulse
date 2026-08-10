/**
 * ThreatPulse — IOC Extractor
 * Extracts structured indicators from article descriptions:
 *   IPv4, domains, MD5/SHA1/SHA256 hashes, email addresses
 */

/**
 * Extract all IOCs from text, returning categorized results
 * @param {string} text - Article title + description
 * @returns {{ ips: string[], domains: string[], hashes: {md5:string[],sha1:string[],sha256:string[]}, emails: string[] }}
 */
function extractIOCs(text) {
  if (!text) return { ips: [], domains: [], hashes: { md5: [], sha1: [], sha256: [] }, emails: [] };

  const results = {
    ips: [],
    domains: [],
    hashes: { md5: [], sha1: [], sha256: [] },
    emails: []
  };

  // ── IPv4 ──
  const ipv4Re = /\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b/g;
  const ipMatches = text.match(ipv4Re) || [];
  results.ips = [...new Set(ipMatches.filter(ip => {
    // Exclude common non-routable/placeholder IPs
    const octets = ip.split('.').map(Number);
    return !(
      octets[0] === 0 || octets[0] === 127 ||
      (octets[0] === 10) ||
      (octets[0] === 172 && octets[1] >= 16 && octets[1] <= 31) ||
      (octets[0] === 192 && octets[1] === 168) ||
      (octets[0] === 169 && octets[1] === 254) ||
      octets[0] >= 224
    );
  }))];

  // ── Domains (no IPs, no TLD-only) ──
  const domainRe = /\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}\b/g;
  const domainMatches = text.match(domainRe) || [];
  results.domains = [...new Set(domainMatches.filter(d => {
    // Exclude IPs, common false positives, very short domains
    if (/^\d+\.\d+\.\d+\.\d+$/.test(d)) return false;
    // Exclude common TLDs that appear as sentence endings / filenames
    const fakeTlds = /\.(com|org|net|io|gov|edu|mil|info|biz|co|uk|de|jp|fr|ru|cn|br|in|au|ca|it|es|nl|se|ch|pl|kr|tw)$/i;
    return d.length > 7 && fakeTlds.test(d);
  }))].slice(0, 50); // cap at 50

  // ── Hashes ──
  results.hashes.md5 = [...new Set((text.match(/\b[a-fA-F0-9]{32}\b/g) || []))].slice(0, 20);
  results.hashes.sha1 = [...new Set((text.match(/\b[a-fA-F0-9]{40}\b/g) || []))].slice(0, 20);
  results.hashes.sha256 = [...new Set((text.match(/\b[a-fA-F0-9]{64}\b/g) || []))].slice(0, 20);

  // Deduplicate: remove hashes that are actually domain/hex tokens
  results.hashes.md5 = results.hashes.md5.filter(h => !/^[0-9]+$/.test(h) && !/^0+$/.test(h));
  results.hashes.sha1 = results.hashes.sha1.filter(h => !/^[0-9]+$/.test(h) && !/^0+$/.test(h));
  results.hashes.sha256 = results.hashes.sha256.filter(h => !/^[0-9]+$/.test(h) && !/^0+$/.test(h));

  // ── Emails (limited) ──
  const emailRe = /\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b/g;
  results.emails = [...new Set(text.match(emailRe) || [])].slice(0, 10);

  return results;
}

/**
 * Format IOCs as a compact tag string for DB storage
 */
function formatIOCsForDB(iocs) {
  const parts = [];
  if (iocs.ips.length) parts.push('ip:' + iocs.ips.slice(0, 10).join(','));
  if (iocs.domains.length) parts.push('domain:' + iocs.domains.slice(0, 10).join(','));
  const allHashes = [...iocs.hashes.md5.slice(0, 5), ...iocs.hashes.sha1.slice(0, 5), ...iocs.hashes.sha256.slice(0, 5)];
  if (allHashes.length) parts.push('hash:' + allHashes.join(','));
  if (iocs.emails.length) parts.push('email:' + iocs.emails.slice(0, 5).join(','));
  return parts.join('|') || null;
}

module.exports = { extractIOCs, formatIOCsForDB };

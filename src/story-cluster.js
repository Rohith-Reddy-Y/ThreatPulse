/**
 * ThreatPulse — merge duplicate stories
 *
 * The same news arrives from several outlets with different headlines
 * ("Fortinet patches FortiOS zero-day CVE-2026-1111" / "CVE-2026-1111: FortiOS
 * flaw exploited"). Within a page of results, articles about the same story are
 * folded into the first (newest) one, which lists the others as `related`.
 *
 * Same story when published within MAX_GAP_DAYS of each other and:
 *   - same canonical URL (the admin sees every user's copy), or
 *   - they share a CVE ID and some headline words, or
 *   - their headlines share most of their key words.
 */
const MAX_GAP_DAYS = 4;
const STOP = new Set(('a an the and or of to in on for with by from at as is are was were be been it its this that these those ' +
  'new now how why what who after over under into via vs amid about more than just your you our their his her they them we ' +
  'says said report reports reported warns warning update updates latest week today news first could would should may can will ' +
  'attack attacks attackers hackers hacker threat threats security cyber flaw flaws vulnerability vulnerabilities bug bugs ' +
  'zero day days patch patches patched fix fixes fixed exploit exploits exploited exploitation active actively critical high ' +
  'severe released release warns urges issues issued').split(' '));

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;

function canonicalUrl(u) {
  return String(u || '').toLowerCase().replace(/^https?:\/\/(www\.)?/, '').replace(/[?#].*$/, '').replace(/\/+$/, '');
}

function keyWords(title) {
  const t = String(title || '')
    .replace(/\s+[-|–—]\s+[^-|–—]{2,60}$/, '')           // trailing " - Publisher"
    .toLowerCase().replace(CVE_RE, ' ');
  return new Set(t.split(/[^a-z0-9]+/).filter((w) => w.length >= 3 && !STOP.has(w) && !/^\d+$/.test(w)));
}

function cvesOf(a) {
  return new Set([...(`${a.cve_id || ''} ${a.title || ''}`.match(CVE_RE) || [])].map((c) => c.toUpperCase()));
}

function similar(x, y) {
  if (x.url && x.url === y.url) return true;
  const t1 = Date.parse(x.date), t2 = Date.parse(y.date);
  if (!Number.isNaN(t1) && !Number.isNaN(t2) && Math.abs(t1 - t2) > MAX_GAP_DAYS * 86400000) return false;
  let shared = 0;
  for (const w of x.words) if (y.words.has(w)) shared++;
  const union = x.words.size + y.words.size - shared;
  const jac = union ? shared / union : 0;
  const sharedCve = [...x.cves].some((c) => y.cves.has(c));
  if (sharedCve && shared >= 1) return true;            // a CVE ID is specific: one more shared word is enough
  // headlines alone: the distinctive words must overlap strongly
  return (shared >= 3 && jac >= 0.75) || (shared >= 4 && jac >= 0.5);
}

/**
 * @param {object[]} articles newest first
 * @returns {object[]} one entry per story; duplicates folded into `related`
 */
function clusterArticles(articles) {
  const groups = [];
  for (const a of articles || []) {
    const sig = { url: canonicalUrl(a.url), date: a.published_date, words: keyWords(a.title), cves: cvesOf(a) };
    const g = groups.find((gr) => gr.sigs.some((s) => similar(s, sig)));
    if (!g) { groups.push({ lead: { ...a }, sigs: [sig], related: [], urls: new Set([sig.url]) }); continue; }
    g.sigs.push(sig);
    const lead = g.lead;
    // fold useful facts into the lead so nothing is lost by hiding the copy
    if (a.has_poc && !lead.has_poc) lead.has_poc = a.has_poc;
    if (a.cve_id && !lead.cve_id) lead.cve_id = a.cve_id;
    if (g.urls.has(sig.url)) continue;          // another user's copy of the very same article
    g.urls.add(sig.url);
    if (g.related.length < 10) {
      g.related.push({ id: a.id, title: a.title, url: a.url, source_name: a.source_name, published_date: a.published_date });
    }
  }
  return groups.map((g) => (g.related.length ? { ...g.lead, related: g.related } : g.lead));
}

module.exports = { clusterArticles, keyWords, canonicalUrl };

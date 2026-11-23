/**
 * ThreatPulse — vulnerability priority intel (per CVE)
 *
 *   EPSS  (FIRST.org, free, no key): probability the CVE is exploited in the next 30 days
 *   KEV   (CISA catalog, free):      the CVE is known to be exploited in the wild
 *   CVSS  (NVD 2.0, NVD_API_KEY):    base severity score
 *
 * Stored in the cve_intel table and refreshed in the background for CVEs seen
 * in recent articles. `priorityOf` turns the three into one plain label.
 */
const db = require('./database');
const { safeGet } = require('./net-guard');

const KEV_URL = 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';
const EPSS_URL = 'https://api.first.org/data/v1/epss';
const NVD_URL = 'https://services.nvd.nist.gov/rest/json/cves/2.0';
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;

let kev = new Map();          // CVE -> { added, due, ransomware, vendor, product, name }
let kevLoadedAt = 0;

function ensureTable() {
  db.getDb().exec(`CREATE TABLE IF NOT EXISTS cve_intel (
    cve TEXT PRIMARY KEY, epss REAL, percentile REAL, cvss REAL, cvss_vector TEXT,
    epss_at TEXT, cvss_at TEXT
  )`);
}

function cvesInText(...parts) {
  return [...new Set(parts.join(' ').match(CVE_RE) || [])].map((c) => c.toUpperCase());
}

async function loadKev(force = false) {
  if (!force && kev.size && Date.now() - kevLoadedAt < 12 * 3600 * 1000) return kev;
  try {
    const r = await safeGet(KEV_URL, { timeout: 30000, responseType: 'json' });
    const list = r && r.data && Array.isArray(r.data.vulnerabilities) ? r.data.vulnerabilities : [];
    if (list.length) {
      const next = new Map();
      for (const v of list) {
        if (!v || !v.cveID) continue;
        next.set(String(v.cveID).toUpperCase(), {
          added: v.dateAdded || null, due: v.dueDate || null,
          ransomware: String(v.knownRansomwareCampaignUse || '').toLowerCase() === 'known',
          vendor: v.vendorProject || null, product: v.product || null, name: v.vulnerabilityName || null,
        });
      }
      kev = next;
      kevLoadedAt = Date.now();
    }
  } catch (e) {
    console.error('[VulnIntel] KEV load failed:', e.message);
  }
  return kev;
}

async function refreshEpss(cves) {
  ensureTable();
  const upsert = db.getDb().prepare(`INSERT INTO cve_intel (cve, epss, percentile, epss_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(cve) DO UPDATE SET epss = excluded.epss, percentile = excluded.percentile, epss_at = excluded.epss_at`);
  let n = 0;
  for (let i = 0; i < cves.length; i += 80) {
    const batch = cves.slice(i, i + 80);
    try {
      const r = await safeGet(`${EPSS_URL}?cve=${batch.join(',')}`, { timeout: 20000, responseType: 'json' });
      const rows = r && r.data && Array.isArray(r.data.data) ? r.data.data : [];
      const seen = new Set();
      for (const row of rows) {
        const cve = String(row.cve || '').toUpperCase();
        if (!/^CVE-\d{4}-\d{4,7}$/.test(cve)) continue;
        const e = parseFloat(row.epss), p = parseFloat(row.percentile);
        upsert.run(cve, Number.isFinite(e) ? e : null, Number.isFinite(p) ? p : null);
        seen.add(cve); n++;
      }
      // CVEs EPSS doesn't know yet (too new): remember we asked, so we don't hammer the API
      for (const cve of batch) if (!seen.has(cve)) upsert.run(cve, null, null);
    } catch (e) {
      console.error('[VulnIntel] EPSS batch failed:', e.message);
    }
  }
  return n;
}

async function refreshCvss(cves) {
  ensureTable();
  const upsert = db.getDb().prepare(`INSERT INTO cve_intel (cve, cvss, cvss_vector, cvss_at) VALUES (?, ?, ?, datetime('now'))
    ON CONFLICT(cve) DO UPDATE SET cvss = excluded.cvss, cvss_vector = excluded.cvss_vector, cvss_at = excluded.cvss_at`);
  const headers = process.env.NVD_API_KEY ? { apiKey: process.env.NVD_API_KEY } : {};
  let n = 0;
  for (const cve of cves) {
    try {
      const r = await safeGet(`${NVD_URL}?cveId=${cve}`, { timeout: 20000, responseType: 'json', headers });
      const m = r && r.data && r.data.vulnerabilities && r.data.vulnerabilities[0] && r.data.vulnerabilities[0].cve && r.data.vulnerabilities[0].cve.metrics;
      const pick = m && (m.cvssMetricV40 || m.cvssMetricV31 || m.cvssMetricV30 || m.cvssMetricV2);
      const data = pick && pick[0] && pick[0].cvssData;
      const score = data && Number.isFinite(parseFloat(data.baseScore)) ? parseFloat(data.baseScore) : null;
      upsert.run(cve, score, data ? String(data.vectorString || '').slice(0, 200) : null);
      if (score !== null) n++;
    } catch (e) {
      if (e && e.response && (e.response.status === 403 || e.response.status === 429)) break;   // rate limited: stop this round
    }
    // stay well inside NVD's limits (50/30s with a key, 5/30s without)
    await new Promise((res) => setTimeout(res, process.env.NVD_API_KEY ? 700 : 6500));
  }
  return n;
}

/** Background refresh for CVEs mentioned in the last `days` of articles. */
async function refresh({ days = 30, maxCvss = 25 } = {}) {
  ensureTable();
  await loadKev();
  const rows = db.getDb().prepare(
    `SELECT cve_id, title FROM articles WHERE published_date >= datetime('now', ?) AND (cve_id IS NOT NULL OR title LIKE '%CVE-%')
      ORDER BY published_date DESC LIMIT 3000`
  ).all(`-${days} days`);
  const all = [...new Set(rows.flatMap((r) => cvesInText(r.cve_id || '', r.title || '')))].slice(0, 1500);
  if (!all.length) return { cves: 0 };
  const have = new Map(db.getDb().prepare(
    `SELECT cve, epss_at, cvss_at FROM cve_intel WHERE cve IN (${all.map(() => '?').join(',')})`
  ).all(...all).map((r) => [r.cve, r]));
  const dayAgo = Date.now() - 24 * 3600 * 1000;
  const staleEpss = all.filter((c) => { const h = have.get(c); return !h || !h.epss_at || Date.parse(h.epss_at + 'Z') < dayAgo; });
  const needCvss = all.filter((c) => { const h = have.get(c); return !h || !h.cvss_at; }).slice(0, maxCvss);
  const epss = await refreshEpss(staleEpss);
  const cvss = await refreshCvss(needCvss);
  return { cves: all.length, epss, cvss, kev: kev.size };
}

function priorityOf({ kev: k, epss, cvss }) {
  if (k || (epss !== null && epss >= 0.5) || (cvss !== null && cvss >= 9 && epss !== null && epss >= 0.1)) return 'now';
  if ((epss !== null && epss >= 0.1) || (cvss !== null && cvss >= 9)) return 'soon';
  if (cvss !== null && cvss >= 7) return 'plan';
  return 'monitor';
}

/** Intel for a list of CVE IDs (one query). */
function lookup(cves) {
  const list = [...new Set((cves || []).map((c) => String(c).toUpperCase()))].filter((c) => /^CVE-\d{4}-\d{4,7}$/.test(c)).slice(0, 500);
  if (!list.length) return new Map();
  let rows = [];
  try {
    ensureTable();
    rows = db.getDb().prepare(`SELECT cve, epss, percentile, cvss FROM cve_intel WHERE cve IN (${list.map(() => '?').join(',')})`).all(...list);
  } catch { rows = []; }
  const byCve = new Map(rows.map((r) => [r.cve, r]));
  const out = new Map();
  for (const cve of list) {
    const r = byCve.get(cve) || {};
    const k = kev.get(cve) || null;
    const item = {
      cve, epss: r.epss ?? null, percentile: r.percentile ?? null, cvss: r.cvss ?? null,
      kev: k ? { added: k.added, due: k.due, ransomware: k.ransomware } : null,
    };
    if (item.epss === null && item.cvss === null && !item.kev) continue;   // nothing known yet
    item.priority = priorityOf({ kev: !!k, epss: item.epss, cvss: item.cvss });
    out.set(cve, item);
  }
  return out;
}

/** Attach `vuln: [...]` to articles (most urgent CVE first). */
function attach(articles) {
  const per = articles.map((a) => cvesInText(a.cve_id || '', a.title || ''));
  const intel = lookup(per.flat());
  const rank = { now: 0, soon: 1, plan: 2, monitor: 3 };
  return articles.map((a, i) => {
    const v = per[i].map((c) => intel.get(c)).filter(Boolean).sort((x, y) => (rank[x.priority] - rank[y.priority]) || ((y.epss || 0) - (x.epss || 0)));
    return v.length ? { ...a, vuln: v.slice(0, 3) } : a;
  });
}

function _setKevForTests(map) { kev = map; kevLoadedAt = Date.now(); }

module.exports = { refresh, lookup, attach, priorityOf, loadKev, cvesInText, _setKevForTests };

/**
 * ThreatPulse — Analytics page data (/api/analytics).
 *
 * Time-bucketed views of the caller's OWN reports (same scope as their feed):
 * severity composition over time, KPI tiles with change vs the previous period,
 * reports by category and by source (top N), and top sources / top ATT&CK
 * techniques over time.
 *
 * Work is done in chunks with setImmediate between them so a 30-day window on a
 * small CPU share never blocks the event loop (health checks keep answering).
 */

const { analyzeTtps, canonicalActor, TECHNIQUES } = require('./attack-kb');

const SEVERITIES = ['critical', 'high', 'medium', 'low'];
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const EXPLOITED_RE = /\b(actively exploited|exploited in the wild|under active exploitation|zero-day)\b/i;
const CHUNK = 400;
const tick = () => new Promise((r) => setImmediate(r));

function bucketer(days, tzMinutes, now) {
  const tz = (Number.isFinite(tzMinutes) ? Math.max(-840, Math.min(840, tzMinutes)) : 0) * 60000;
  if (days <= 1) {
    const HOUR = 3600000;
    const end = Math.floor(now / HOUR);
    const n = 24;
    const starts = Array.from({ length: n }, (_, i) => new Date((end - n + 1 + i) * HOUR).toISOString());
    return { unit: 'hour', n, starts, index: (t) => { const i = Math.floor(t / HOUR) - (end - n + 1); return i >= 0 && i < n ? i : -1; } };
  }
  const DAY = 86400000;
  const today = Math.floor((now + tz) / DAY);
  const n = days;
  const starts = Array.from({ length: n }, (_, i) => new Date((today - n + 1 + i) * DAY - tz).toISOString());
  return { unit: 'day', n, starts, index: (t) => { const i = Math.floor((t + tz) / DAY) - (today - n + 1); return i >= 0 && i < n ? i : -1; } };
}

const zeros = (n) => new Array(n).fill(0);
const ts = (v) => { const t = Date.parse(v); return Number.isFinite(t) ? t : NaN; };

/**
 * @param {Array} rows    articles from the last 2×days (current + previous window)
 * @param {Array} sources the caller's sources (for the health tile)
 * @param {{days:number, tz:number, now?:number}} opts
 */
async function buildAnalytics(rows, sources, { days, tz, now = Date.now() }) {
  const B = bucketer(days, tz, now);
  const windowStart = now - days * 86400000;
  const prevStart = now - 2 * days * 86400000;

  const sev = Object.fromEntries(SEVERITIES.map((s) => [s, zeros(B.n)]));
  const total = zeros(B.n);
  const cur = { reports: 0, critical: 0, high: 0, poc: 0, cves: new Set(), exploited: new Set(), actors: new Set(), techniques: new Set() };
  const prev = { reports: 0, critical: 0, high: 0, poc: 0, exploited: new Set(), actors: new Set() };
  const categories = new Map();
  const sourceTotals = new Map();
  const sourceByBucket = new Map();     // name -> counts[]
  const techTotals = new Map();
  const techByBucket = new Map();       // id -> counts[]

  for (let i = 0; i < rows.length; i++) {
    if (i % CHUNK === CHUNK - 1) await tick();
    const a = rows[i];
    const t = ts(a.published_date);
    if (!Number.isFinite(t) || t < prevStart || t > now + 3600000) continue;
    const text = `${a.title || ''}\n${a.description || ''}`;
    const tags = String(a.tags || '').toLowerCase();
    const exploited = /cisa-kev|actively-exploited/.test(tags) || EXPLOITED_RE.test(text);
    const cves = new Set([...(text.match(CVE_RE) || []), ...(a.cve_id ? [a.cve_id] : [])].map((c) => c.toUpperCase()));
    const actorNames = String(a.threat_actors || '').split(',').map((s) => s.trim()).filter(Boolean).map(canonicalActor);
    const s = SEVERITIES.includes(a.severity) ? a.severity : 'low';

    if (t < windowStart) {               // previous period: cheap counts only
      prev.reports++;
      if (s === 'critical') prev.critical++;
      if (s === 'high') prev.high++;
      if (a.has_poc) prev.poc++;
      if (exploited) cves.forEach((c) => prev.exploited.add(c));
      actorNames.forEach((n) => prev.actors.add(n.toLowerCase()));
      continue;
    }

    cur.reports++;
    if (s === 'critical') cur.critical++;
    if (s === 'high') cur.high++;
    if (a.has_poc) cur.poc++;
    cves.forEach((c) => cur.cves.add(c));
    if (exploited) cves.forEach((c) => cur.exploited.add(c));
    actorNames.forEach((n) => cur.actors.add(n.toLowerCase()));

    const cat = a.category || 'other';
    categories.set(cat, (categories.get(cat) || 0) + 1);
    const src = a.source_name || 'Unknown';
    sourceTotals.set(src, (sourceTotals.get(src) || 0) + 1);

    const bi = B.index(t);
    const ttps = analyzeTtps(a);
    for (const tp of ttps) {
      cur.techniques.add(tp.id);
      techTotals.set(tp.id, (techTotals.get(tp.id) || 0) + 1);
    }
    if (bi < 0) continue;
    sev[s][bi]++;
    total[bi]++;
    if (!sourceByBucket.has(src)) sourceByBucket.set(src, zeros(B.n));
    sourceByBucket.get(src)[bi]++;
    for (const tp of ttps) {
      if (!techByBucket.has(tp.id)) techByBucket.set(tp.id, zeros(B.n));
      techByBucket.get(tp.id)[bi]++;
    }
  }

  const ranked = (m) => [...m.entries()].sort((x, y) => y[1] - x[1]);

  // Top N + "Other" over time (stacked columns read best with <= 6 parts)
  function overTime(totals, byBucket, label, n = 5) {
    const top = ranked(totals).slice(0, n).map(([k]) => k);
    const other = zeros(B.n);
    for (const [k, arr] of byBucket) if (!top.includes(k)) arr.forEach((v, i) => { other[i] += v; });
    return {
      series: top.map((k) => ({ key: k, name: label(k), values: byBucket.get(k) || zeros(B.n) })),
      other: other.some(Boolean) ? other : null,
    };
  }

  const srcRanked = ranked(sourceTotals);
  const healthy = sources.filter((x) => x.enabled && x.last_fetched && !x.last_error).length;
  const errors = sources.filter((x) => x.enabled && x.last_error).length;
  const delta = (c, p) => ({ value: c, prev: p });

  return {
    days,
    unit: B.unit,
    buckets: B.starts,
    severity: { series: SEVERITIES.map((k) => ({ key: k, values: sev[k] })), total },
    kpis: {
      reports: { ...delta(cur.reports, prev.reports), spark: total },
      critical: { ...delta(cur.critical, prev.critical), spark: sev.critical },
      high: delta(cur.high, prev.high),
      exploitedCves: delta(cur.exploited.size, prev.exploited.size),
      pocs: delta(cur.poc, prev.poc),
      actors: delta(cur.actors.size, prev.actors.size),
      techniques: { value: cur.techniques.size, prev: null },
      cves: { value: cur.cves.size, prev: null },
      sources: { total: sources.filter((x) => x.enabled).length, healthy, errors },
    },
    categories: ranked(categories).map(([name, count]) => ({ name, count })),
    sources: {
      total: cur.reports,
      distinct: srcRanked.length,
      top: srcRanked.slice(0, 10).map(([name, count]) => ({ name, count })),
      otherCount: srcRanked.slice(10).reduce((s2, [, c]) => s2 + c, 0),
    },
    sourcesOverTime: overTime(sourceTotals, sourceByBucket, (k) => k),
    techniquesOverTime: overTime(techTotals, techByBucket, (k) => `${k} ${TECHNIQUES[k] ? TECHNIQUES[k].name : ''}`.trim()),
    generatedAt: new Date(now).toISOString(),
  };
}

module.exports = { buildAnalytics, bucketer };

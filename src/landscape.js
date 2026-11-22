/**
 * ThreatPulse — Threat Landscape analytics.
 *
 * Summarises the caller's OWN articles (same scope as their feed) into the
 * views enterprise CTI platforms lead with:
 *   - MITRE ATT&CK: techniques by tactic. A technique counts as EXPLICIT when the
 *     report cites its ID, INFERRED when the report describes the behaviour
 *     (e.g. "password spraying" -> T1110). The two are always reported separately.
 *   - Threat actors: who appears most, attributed origin, sectors, CVEs, last seen
 *   - Vulnerabilities: most-reported CVEs with exploitation / PoC / patch signals
 *   - Targeting: sectors and countries named in the reports
 *
 * Pure computation over text the user can already see. Nothing is fetched.
 */

const geo = require('./geo');

const { TACTICS, TECHNIQUES, canonicalActor, attackUrl, analyzeTtps } = require('./attack-kb');

const SEV_RANK = { critical: 4, high: 3, medium: 2, low: 1 };
const worse = (a, b) => ((SEV_RANK[a] || 0) >= (SEV_RANK[b] || 0) ? a : b);
const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const EXPLOITED_RE = /\b(actively exploited|exploited in the wild|under active exploitation|zero-day)\b/i;


/**
 * @param {Array} articles rows with id,title,description,severity,threat_actors,
 *   mitre_ids,sector,cve_id,has_poc,is_patched,tags,published_date
 * @param {number} days
 */
function buildLandscape(articles, days) {
  const tech = new Map();      // id -> {explicit, inferred, worst, samples}
  const tacticCounts = new Map();
  const actors = new Map();
  const cves = new Map();
  const sectors = new Map();
  let mapped = 0, explicitArticles = 0;

  const sample = (list, a) => { if (list.length < 3) list.push({ id: a.id, title: String(a.title || '').slice(0, 140) }); };

  for (const a of articles) {
    const text = `${a.title || ''}\n${a.description || ''}`;
    const sev = a.severity || 'low';

    // ── Actors in this report (canonical names) ──
    const names = String(a.threat_actors || '').split(',').map((x) => x.trim()).filter(Boolean);
    const actorKeys = [...new Set(names.map((n) => canonicalActor(n)))];

    // ── ATT&CK (Tactic / Technique / Procedure) ──
    const ttps = analyzeTtps(a);
    if (ttps.some((t) => t.how === 'cited')) explicitArticles++;
    if (ttps.length) mapped++;
    const tacticsHit = new Set();
    for (const tp of ttps) {
      let t = tech.get(tp.id);
      if (!t) { t = { id: tp.id, explicit: 0, inferred: 0, worst: 'low', samples: [], terms: new Map(), procedures: [], actors: new Map() }; tech.set(tp.id, t); }
      t[tp.how === 'cited' ? 'explicit' : 'inferred']++;
      const key = tp.how === 'cited' ? tp.id : tp.term.toLowerCase();
      t.terms.set(key, (t.terms.get(key) || 0) + 1);
      t.worst = worse(sev, t.worst);
      sample(t.samples, a);
      if (tp.procedure && t.procedures.length < 6 && !t.procedures.some((p) => p.text === tp.procedure)) {
        t.procedures.push({ text: tp.procedure, how: tp.how, articleId: a.id, title: String(a.title || '').slice(0, 140), url: a.url || null, published: a.published_date, severity: sev });
      }
      for (const name of actorKeys) t.actors.set(name, (t.actors.get(name) || 0) + 1);
      if (tp.tactic) tacticsHit.add(tp.tactic);
    }
    for (const ta of tacticsHit) tacticCounts.set(ta, (tacticCounts.get(ta) || 0) + 1);

    // ── Threat actors ──
    const origins = geo.originsOf(names);
    const articleCves = new Set([...(text.match(CVE_RE) || []), ...(a.cve_id ? [a.cve_id] : [])].map((c) => c.toUpperCase()));
    const seen = new Set();
    for (const raw of names) {
      const name = canonicalActor(raw);
      const key = name.toLowerCase();
      if (seen.has(key)) continue;   // "Lazarus" + "Lazarus Group" in one report count once
      seen.add(key);
      let r = actors.get(key);
      if (!r) { r = { name, count: 0, worst: 'low', lastSeen: null, origin: null, sectors: new Map(), cves: new Set(), samples: [], aliases: new Map(), techniques: new Map() }; actors.set(key, r); }
      r.count++;
      for (const n of names) if (canonicalActor(n).toLowerCase() === key) r.aliases.set(n, (r.aliases.get(n) || 0) + 1);
      r.worst = worse(sev, r.worst);
      if (!r.lastSeen || String(a.published_date) > r.lastSeen) r.lastSeen = a.published_date;
      for (const [code, actor] of origins) if (canonicalActor(actor).toLowerCase() === key) r.origin = code;
      if (a.sector) r.sectors.set(a.sector, (r.sectors.get(a.sector) || 0) + 1);
      articleCves.forEach((c) => r.cves.add(c));
      for (const tp of ttps) r.techniques.set(tp.id, (r.techniques.get(tp.id) || 0) + 1);
      sample(r.samples, a);
    }

    // ── Vulnerabilities ──
    const tags = String(a.tags || '').toLowerCase();
    const exploited = /cisa-kev|actively-exploited/.test(tags) || EXPLOITED_RE.test(text);
    for (const id of articleCves) {
      let c = cves.get(id);
      if (!c) { c = { id, count: 0, worst: 'low', kev: false, exploited: false, poc: false, patched: 0, unpatched: 0, lastSeen: null, title: '' }; cves.set(id, c); }
      c.count++;
      c.worst = worse(sev, c.worst);
      if (/cisa-kev/.test(tags)) c.kev = true;
      if (exploited) c.exploited = true;
      if (a.has_poc) c.poc = true;
      if (a.is_patched === 1) c.patched++;
      if (a.is_patched === 0) c.unpatched++;
      if (!c.lastSeen || String(a.published_date) > c.lastSeen) { c.lastSeen = a.published_date; c.title = String(a.title || '').slice(0, 140); }
    }

    // ── Sectors ──
    if (a.sector) {
      let s = sectors.get(a.sector);
      if (!s) { s = { name: a.sector, count: 0, critical: 0, high: 0 }; sectors.set(a.sector, s); }
      s.count++;
      if (sev === 'critical') s.critical++;
      if (sev === 'high') s.high++;
    }
  }

  // Matrix: every tactic column, techniques sorted by total
  const techList = [...tech.values()].map(({ terms, actors: acts, ...t }) => {
    const meta = TECHNIQUES[t.id];
    const isId = (k) => /^T\d{4}/.test(k);
    const term = [...terms.entries()].sort((x, y) => y[1] - x[1] || isId(x[0]) - isId(y[0]))[0][0];
    return {
      ...t, name: meta ? meta.name : t.id, tactic: meta ? meta.tactic : null, desc: meta ? meta.desc : null,
      url: attackUrl(t.id), total: t.explicit + t.inferred, term,
      actors: [...acts.entries()].sort((x, y) => y[1] - x[1]).slice(0, 6).map(([name, count]) => ({ name, count })),
    };
  }).sort((x, y) => y.total - x.total || y.explicit - x.explicit);
  const tactics = TACTICS.map(([id, name]) => ({
    id, name, url: attackUrl(id), count: tacticCounts.get(id) || 0,
    techniques: techList.filter((t) => t.tactic === id).slice(0, 8),
  }));
  const unmapped = techList.filter((t) => !t.tactic).slice(0, 12); // explicit IDs outside the catalogue

  const actorList = [...actors.values()]
    .sort((x, y) => y.count - x.count)
    .slice(0, 15)
    .map((r) => ({
      name: r.name, count: r.count, worst: r.worst, lastSeen: r.lastSeen,
      aliases: [...r.aliases.keys()].filter((a) => a.toLowerCase() !== r.name.toLowerCase()),
      // most frequent spelling in the reports = the feed search term
      term: [...r.aliases.entries()].sort((x, y) => y[1] - x[1])[0]?.[0] || r.name,
      origin: r.origin ? { code: r.origin, name: (geo.COUNTRIES.find((c) => c[0] === r.origin) || [])[1] || r.origin } : null,
      sectors: [...r.sectors.entries()].sort((x, y) => y[1] - x[1]).map(([s]) => s).slice(0, 3),
      cves: [...r.cves].slice(0, 3),
      techniques: [...r.techniques.entries()].sort((x, y) => y[1] - x[1]).slice(0, 5)
        .map(([id, count]) => ({ id, count, name: TECHNIQUES[id] ? TECHNIQUES[id].name : id, url: attackUrl(id) })),
      samples: r.samples,
    }));

  const cveList = [...cves.values()]
    .sort((x, y) => (y.exploited - x.exploited) || (SEV_RANK[y.worst] - SEV_RANK[x.worst]) || (y.count - x.count))
    .slice(0, 15)
    .map((c) => ({ ...c, patch: c.patched && !c.unpatched ? 'patched' : c.unpatched ? 'unpatched' : 'unknown' }));

  const g = geo.buildGeo(articles, days);

  return {
    days,
    totalArticles: articles.length,
    attack: { tactics, unmapped, mappedArticles: mapped, explicitArticles, techniqueCount: techList.length },
    actors: actorList,
    cves: cveList,
    sectors: [...sectors.values()].sort((x, y) => y.count - x.count),
    countries: g.countries.slice(0, 12).map(({ code, name, count, critical, high, term }) => ({ code, name, count, critical, high, term })),
    geolocated: g.geolocated,
    generatedAt: new Date().toISOString(),
  };
}

module.exports = { buildLandscape, TACTICS, TECHNIQUES };

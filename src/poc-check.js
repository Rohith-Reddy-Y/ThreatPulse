/**
 * ThreatPulse — PoC checker
 *
 * "has_poc" from the feeds is only a keyword guess ("PoC", "exploit released").
 * This module answers the real questions for one article:
 *   1. Is there an actual proof-of-concept link?  (links on the article page,
 *      plus a GitHub search for the article's CVE IDs)
 *   2. Is each link real and usable?  (exists, not archived/disabled, contains
 *      source code, mentions the CVE)
 *   3. Does it look like a fake "PoC" lure?  (binary-only repos, README that
 *      sends you to a file host / password-protected archive)
 *
 * It only reads metadata and file listings through public APIs; it never
 * downloads or runs exploit code. All requests go through net-guard (SSRF-safe).
 * Set GITHUB_TOKEN (a free token, no scopes needed) for 5,000 GitHub API
 * requests/hour instead of 60.
 */
const { safeGet } = require('./net-guard');

const CVE_RE = /\bCVE-\d{4}-\d{4,7}\b/gi;
const GH_RESERVED = new Set(['topics', 'features', 'about', 'pricing', 'advisories', 'security', 'orgs', 'sponsors', 'marketplace',
  'login', 'join', 'settings', 'explore', 'collections', 'enterprise', 'readme', 'customer-stories', 'solutions', 'resources',
  'site', 'contact', 'trending', 'notifications', 'issues', 'pulls', 'apps', 'events', 'search', 'new', 'codespaces', 'team',
  'premium-support', 'github-copilot', 'sessions', 'signup', 'logout', 'users', 'organizations']);
const SKIP_REPOS = new Set(['github/advisory-database', 'cisagov/kev-data', 'mitre/cti', 'cveproject/cvelistv5']);
const CODE_EXT = /\.(py|go|c|cc|cpp|h|rs|rb|js|ts|mjs|php|java|kt|cs|ps1|psm1|sh|bash|pl|lua|swift|m|nse|yaml|yml|json|html|xml|asm|s|vbs|bat|cmd|sol|ino|scala|groovy|r|sql|txt|md)$/i;
const SOURCE_EXT = /\.(py|go|c|cc|cpp|h|rs|rb|js|ts|mjs|php|java|kt|cs|ps1|psm1|sh|bash|pl|lua|swift|m|nse|yaml|yml|asm|s|vbs|sol|scala|groovy)$/i;
const BINARY_EXT = /\.(exe|dll|scr|msi|com|pif|zip|rar|7z|tar|gz|tgz|bz2|xz|iso|img|vhd|lnk|jar|apk|dmg|pkg|bin)$/i;
const FILE_HOST_RE = /\b(mega\.nz|mega\.co\.nz|mediafire\.com|anonfiles|gofile\.io|dropbox\.com\/s|drive\.google\.com|1drv\.ms|sendspace|transfer\.sh|pixeldrain|file\.io|catbox\.moe|t\.me\/)/i;
const PASSWORD_LURE_RE = /\b(password|pass|pwd)\s*[:=]\s*\S+|\bdownload (the )?(exploit|poc|tool)\b.*\b(here|link|release)\b/i;

const MAX_CANDIDATES = 5;

function ghHeaders() {
  const h = { Accept: 'application/vnd.github+json', 'User-Agent': 'ThreatPulse-PoC-Checker', 'X-GitHub-Api-Version': '2022-11-28' };
  if (process.env.GITHUB_TOKEN) h.Authorization = `Bearer ${process.env.GITHUB_TOKEN}`;
  return h;
}

// ── candidate extraction ──
function cvesOf(article) {
  const text = `${article.cve_id || ''} ${article.title || ''} ${article.description || ''}`;
  return [...new Set((text.match(CVE_RE) || []).map((c) => c.toUpperCase()))].slice(0, 3);
}

function extractLinks(html) {
  const out = [];
  const seen = new Set();
  const add = (kind, url, key, extra = {}) => {
    const k = `${kind}:${key.toLowerCase()}`;
    if (seen.has(k)) return;
    seen.add(k);
    out.push({ kind, url, key, ...extra });
  };
  const text = String(html || '').slice(0, 2_000_000);
  const urlRe = /https?:\/\/[^\s"'<>()\\]+/gi;
  let m;
  while ((m = urlRe.exec(text)) !== null) {
    const raw = m[0].replace(/&amp;/g, '&').replace(/[.,;:!?]+$/, '');
    let u;
    try { u = new URL(raw); } catch { continue; }
    const host = u.hostname.toLowerCase().replace(/^www\./, '');
    const parts = u.pathname.split('/').filter(Boolean);
    if (host === 'github.com' && parts.length >= 2) {
      const [owner, repoRaw] = parts;
      const repo = repoRaw.replace(/\.git$/, '');
      if (GH_RESERVED.has(owner.toLowerCase()) || !/^[\w.-]{1,100}$/.test(repo) || !/^[A-Za-z0-9-]{1,39}$/.test(owner)) continue;
      if (SKIP_REPOS.has(`${owner}/${repo}`.toLowerCase())) continue;
      // keep the file path for template collections (e.g. nuclei-templates/.../CVE-x.yaml)
      const deep = parts.length > 4 && (parts[2] === 'blob' || parts[2] === 'tree') ? u.href : null;
      add('github', `https://github.com/${owner}/${repo}`, `${owner}/${repo}${deep ? '#' + parts.slice(4).join('/') : ''}`, { owner, repo, deep });
    } else if (host === 'gist.github.com' && parts.length >= 1) {
      const id = parts[parts.length - 1];
      if (/^[0-9a-f]{20,40}$/i.test(id)) add('gist', `https://gist.github.com/${parts.join('/')}`, id, { id });
    } else if (host === 'exploit-db.com' && parts[0] === 'exploits' && /^\d+$/.test(parts[1] || '')) {
      add('exploitdb', `https://www.exploit-db.com/exploits/${parts[1]}`, parts[1], { id: parts[1] });
    } else if (host === 'packetstormsecurity.com' && parts[0] === 'files' && /^\d+$/.test(parts[1] || '')) {
      add('packetstorm', `https://packetstormsecurity.com/files/${parts[1]}/`, parts[1], { id: parts[1] });
    } else if (host === 'gitlab.com' && parts.length >= 2 && !['explore', 'users', 'help', '-'].includes(parts[0])) {
      add('gitlab', `https://gitlab.com/${parts[0]}/${parts[1]}`, `${parts[0]}/${parts[1]}`);
    }
  }
  return out;
}

// ── validation ──
async function getJson(url) {
  try {
    const r = await safeGet(url, { headers: ghHeaders(), timeout: 12000, validateStatus: () => true, responseType: 'json' });
    if (r.status === 403 || r.status === 429) {
      const rl = r.headers && (r.headers['x-ratelimit-remaining'] === '0' || r.status === 429);
      return { status: r.status, rateLimited: !!rl, data: null };
    }
    return { status: r.status, data: r.status >= 200 && r.status < 300 ? r.data : null };
  } catch (e) {
    return { status: 0, error: e.message, data: null };
  }
}

function daysSince(iso) {
  const t = Date.parse(iso || '');
  return Number.isNaN(t) ? null : Math.floor((Date.now() - t) / 86400000);
}

async function validateGithub(c, cves, ctx) {
  const res = { ...c, status: 'unverified', reasons: [] };
  const repo = await getJson(`https://api.github.com/repos/${c.owner}/${c.repo}`);
  if (repo.rateLimited) { ctx.rateLimited = true; res.reasons.push('GitHub API rate limit reached, try again later'); return res; }
  if (repo.status === 404 || repo.status === 451) { res.status = 'dead'; res.reasons.push('Repository not found (deleted or private)'); return res; }
  if (!repo.data) { res.reasons.push('Could not reach GitHub'); return res; }
  const d = repo.data;
  res.stars = d.stargazers_count || 0;
  res.updated = d.pushed_at || null;
  res.created = d.created_at || null;
  res.description = String(d.description || '').slice(0, 200);
  if (d.disabled) { res.status = 'dead'; res.reasons.push('Repository disabled by GitHub'); return res; }
  if (d.archived) res.reasons.push('Archived (read-only)');
  if (d.fork) res.reasons.push('Fork of another repository');

  const list = await getJson(`https://api.github.com/repos/${c.owner}/${c.repo}/contents`);
  if (list.rateLimited) ctx.rateLimited = true;
  const files = Array.isArray(list.data) ? list.data : [];
  const names = files.map((f) => String(f.name || ''));
  const dirs = files.filter((f) => f.type === 'dir').length;
  const source = names.filter((n) => SOURCE_EXT.test(n));
  const binaries = names.filter((n) => BINARY_EXT.test(n));
  res.files = names.slice(0, 12);

  // README: lure check + CVE relevance
  let readme = '';
  const rd = await getJson(`https://api.github.com/repos/${c.owner}/${c.repo}/readme`);
  if (rd.data && rd.data.content) {
    try { readme = Buffer.from(String(rd.data.content), 'base64').toString('utf8').slice(0, 40000); } catch { readme = ''; }
  }
  const hay = `${c.repo} ${d.description || ''} ${readme} ${c.deep || ''}`.toUpperCase();
  const matched = cves.filter((cv) => hay.includes(cv));
  res.cveMatch = matched;

  const binaryOnly = binaries.length > 0 && source.length === 0 && dirs === 0;
  // A file-host link alone isn't damning (demo videos); it is when there's no code to read
  const lure = (FILE_HOST_RE.test(readme) && source.length === 0) || (binaries.length > 0 && PASSWORD_LURE_RE.test(readme));
  const age = daysSince(d.created_at);

  if (binaryOnly) res.reasons.push(`Only binaries/archives, no source code (${binaries.slice(0, 3).join(', ')})`);
  if (lure) res.reasons.push('README sends you to a file host or password-protected download');
  if (age !== null && age <= 3 && res.stars === 0) res.reasons.push(`Created ${age === 0 ? 'today' : age + ' day(s) ago'} with no stars: unvetted`);

  if (binaryOnly || lure) {
    res.status = 'suspicious';
    res.reasons.unshift('Possible fake PoC / malware lure: do not run');
  } else if (source.length || dirs) {
    if (matched.length || c.source === 'article') {
      res.status = 'verified';
      res.reasons.unshift(source.length ? `Source code present (${source.slice(0, 3).join(', ')}${source.length > 3 ? '…' : ''})` : 'Code folders present');
      if (matched.length) res.reasons.push(`Mentions ${matched.join(', ')}`);
      if (c.source === 'article') res.reasons.push('Linked from the article');
    } else {
      res.reasons.unshift('Has code, but no mention of this article\'s CVE');
    }
  } else {
    res.reasons.unshift('No source code found in the repository root');
  }
  return res;
}

async function validateGist(c, cves, ctx) {
  const res = { ...c, status: 'unverified', reasons: [] };
  const g = await getJson(`https://api.github.com/gists/${c.id}`);
  if (g.rateLimited) { ctx.rateLimited = true; res.reasons.push('GitHub API rate limit reached'); return res; }
  if (g.status === 404) { res.status = 'dead'; res.reasons.push('Gist not found'); return res; }
  if (!g.data) { res.reasons.push('Could not reach GitHub'); return res; }
  const files = Object.keys(g.data.files || {});
  res.files = files.slice(0, 12);
  const code = files.filter((n) => CODE_EXT.test(n));
  const hay = `${g.data.description || ''} ${files.join(' ')}`.toUpperCase();
  res.cveMatch = cves.filter((cv) => hay.includes(cv));
  if (code.length && (res.cveMatch.length || c.source === 'article')) {
    res.status = 'verified';
    res.reasons.push(`Code present (${code.slice(0, 3).join(', ')})`);
  } else res.reasons.push(code.length ? 'Has code, but no mention of this article\'s CVE' : 'No code files');
  return res;
}

async function validatePage(c, label) {
  const res = { ...c, status: 'unverified', reasons: [] };
  try {
    const r = await safeGet(c.url, { timeout: 12000, validateStatus: () => true, responseType: 'text',
      headers: { 'User-Agent': 'Mozilla/5.0 (ThreatPulse PoC checker)' } });
    if (r.status === 404 || r.status === 410) { res.status = 'dead'; res.reasons.push(`${label} entry not found`); }
    else if (r.status >= 200 && r.status < 300) { res.status = 'verified'; res.reasons.push(`Listed on ${label} (curated exploit archive)`); }
    else res.reasons.push(`${label} returned HTTP ${r.status} (bot protection?), open it manually`);
  } catch (e) {
    res.reasons.push(`Could not reach ${label}`);
  }
  return res;
}

async function searchGithubForCve(cve, ctx) {
  const q = encodeURIComponent(`${cve} in:name,description,readme`);
  const r = await getJson(`https://api.github.com/search/repositories?q=${q}&sort=stars&order=desc&per_page=5`);
  if (r.rateLimited) { ctx.rateLimited = true; return []; }
  const items = (r.data && Array.isArray(r.data.items)) ? r.data.items : [];
  return items
    .filter((it) => it && it.full_name && !SKIP_REPOS.has(String(it.full_name).toLowerCase()))
    .map((it) => {
      const [owner, repo] = String(it.full_name).split('/');
      return { kind: 'github', url: `https://github.com/${owner}/${repo}`, key: `${owner}/${repo}`, owner, repo, source: 'cve-search', via: cve };
    });
}

/**
 * Check one article. Returns
 * { verdict: verified|suspicious|unverified|none, links: [...], cves, mentionsPoc, notes, rateLimited, checkedAt }
 */
async function checkArticle(article) {
  const ctx = { rateLimited: false };
  const cves = cvesOf(article);
  const notes = [];
  let candidates = extractLinks(`${article.title || ''} ${article.description || ''}`).map((c) => ({ ...c, source: 'article' }));

  // Links on the article page itself
  if (/^https?:\/\//i.test(article.url || '')) {
    try {
      const page = await safeGet(article.url, { timeout: 15000, responseType: 'text', validateStatus: () => true,
        maxContentLength: 3 * 1024 * 1024, headers: { 'User-Agent': 'Mozilla/5.0 (ThreatPulse PoC checker)' } });
      if (page.status >= 200 && page.status < 300) {
        const host = (() => { try { return new URL(article.url).hostname.replace(/^www\./, ''); } catch { return ''; } })();
        for (const c of extractLinks(page.data)) {
          if (host === 'github.com' && article.url.toLowerCase().includes(c.key.toLowerCase())) continue;
          candidates.push({ ...c, source: 'article' });
        }
      } else notes.push(`Article page returned HTTP ${page.status}; only the feed text was scanned`);
    } catch (e) {
      notes.push('Article page could not be fetched; only the feed text was scanned');
    }
  }

  // GitHub search by CVE when the article links nothing usable
  if (cves.length) {
    for (const cve of cves.slice(0, 2)) candidates.push(...(await searchGithubForCve(cve, ctx)));
  } else notes.push('No CVE ID in the article, so GitHub was not searched');

  // De-duplicate (article links win over search hits), cap the work
  const byKey = new Map();
  for (const c of candidates) {
    const k = `${c.kind}:${String(c.key).toLowerCase().split('#')[0]}`;
    if (!byKey.has(k)) byKey.set(k, c);
  }
  const picked = [...byKey.values()]
    .sort((a, b) => (a.source === 'article' ? 0 : 1) - (b.source === 'article' ? 0 : 1))
    .slice(0, MAX_CANDIDATES);

  const links = [];
  for (const c of picked) {
    if (ctx.rateLimited && (c.kind === 'github' || c.kind === 'gist')) { links.push({ ...c, status: 'unverified', reasons: ['Not checked: GitHub API rate limit'] }); continue; }
    if (c.kind === 'github') links.push(await validateGithub(c, cves, ctx));
    else if (c.kind === 'gist') links.push(await validateGist(c, cves, ctx));
    else if (c.kind === 'exploitdb') links.push(await validatePage(c, 'Exploit-DB'));
    else if (c.kind === 'packetstorm') links.push(await validatePage(c, 'Packet Storm'));
    else links.push({ ...c, status: 'unverified', reasons: ['Link found; not validated automatically'] });
  }

  // Search hits that turned out irrelevant are noise: keep only useful ones
  const shown = links.filter((l) => l.source === 'article' || l.status === 'verified' || l.status === 'suspicious');
  const rank = { verified: 0, suspicious: 1, unverified: 2, dead: 3 };
  shown.sort((a, b) => (rank[a.status] - rank[b.status]) || ((b.stars || 0) - (a.stars || 0)));

  const verdict = shown.some((l) => l.status === 'verified') ? 'verified'
    : shown.some((l) => l.status === 'suspicious') ? 'suspicious'
      : shown.some((l) => l.status === 'unverified') ? 'unverified' : 'none';
  if (ctx.rateLimited) notes.push(process.env.GITHUB_TOKEN ? 'GitHub rate limit reached; re-check later' : 'GitHub rate limit reached (60/hour without a token). Add GITHUB_TOKEN in Render for 5,000/hour');

  return {
    verdict,
    links: shown.map((l) => ({
      url: l.deep || l.url, kind: l.kind, source: l.source, via: l.via || null, status: l.status,
      reasons: (l.reasons || []).slice(0, 5), stars: l.stars ?? null, updated: l.updated || null,
      cveMatch: l.cveMatch || [], files: (l.files || []).slice(0, 8),
    })),
    cves,
    mentionsPoc: !!article.has_poc,
    notes,
    rateLimited: ctx.rateLimited,
    checkedAt: new Date().toISOString(),
  };
}

module.exports = { checkArticle, extractLinks, cvesOf };

/**
 * ThreatPulse — platform-wide source catalog for the admin panel.
 *
 * Every user keeps their own private source rows; this view folds them into
 * one entry per *feed*: the same feed added by ten people (or matching a
 * built-in source) shows once, with everyone who added it listed as labels.
 * Feeds that no built-in source covers are flagged "user-submitted" so the
 * admin sees new sources the moment someone adds them.
 *
 * Read-only: nothing here changes anyone's sources.
 */

const TRACKING_PARAMS = /^(utm_[a-z]+|fbclid|gclid|mc_cid|mc_eid|ref|ref_src|source)$/i;

/**
 * Canonical form used to decide "same feed":
 * scheme-less, lower-case host without "www.", no default port, no fragment,
 * no tracking params, remaining params sorted, no trailing slash.
 */
function canonicalUrl(raw) {
  if (typeof raw !== 'string' || !raw.trim()) return '';
  let u;
  try { u = new URL(raw.trim()); } catch { return raw.trim().toLowerCase(); }
  const host = u.hostname.toLowerCase().replace(/^www\./, '').replace(/\.$/, '');
  const port = u.port && !['80', '443'].includes(u.port) ? `:${u.port}` : '';
  let decoded;
  try { decoded = decodeURI(u.pathname); } catch { decoded = u.pathname; } // malformed %-escapes
  let path = decoded.replace(/\/{2,}/g, '/').replace(/\/+$/, '');
  if (/\/index\.(html?|php|xml)$/i.test(path)) path = path.replace(/\/index\.(html?|php|xml)$/i, '');
  const params = [...u.searchParams.entries()]
    .filter(([k]) => !TRACKING_PARAMS.test(k))
    .sort(([a], [b]) => a.localeCompare(b));
  const query = params.length ? `?${params.map(([k, v]) => `${k}=${v}`).join('&')}` : '';
  return `${host}${port}${path.toLowerCase()}${query}`;
}

function hostOf(raw) {
  try { return new URL(raw).hostname.toLowerCase().replace(/^www\./, ''); } catch { return ''; }
}

/**
 * @param {Array} sources  every row from the sources table
 * @param {Array} users    every user (id, username, display_name)
 * @returns {{ entries: Array, totals: object }}
 */
function buildCatalog(sources, users) {
  const userById = new Map(users.map((u) => [u.id, u]));
  const groups = new Map();
  const NEW_MS = 48 * 3600 * 1000;
  const now = Date.now();
  const ts = (s) => { const t = Date.parse(String(s || '').replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(String(s || '')) ? '' : 'Z')); return Number.isFinite(t) ? t : 0; };

  for (const s of sources) {
    const key = canonicalUrl(s.url);
    if (!key) continue;
    let g = groups.get(key);
    if (!g) {
      g = { key, url: s.url, name: s.name, type: s.type, category: s.category, host: hostOf(s.url),
            builtIn: false, builtInId: null, contributors: [], firstAddedAt: null, lastFetched: null,
            lastError: null, enabledCount: 0 };
      groups.set(key, g);
    }
    if (s.added_by === 'system') {
      g.builtIn = true;
      g.builtInId = s.id;
      g.url = s.url; g.name = s.name; g.type = s.type; g.category = s.category; // built-in naming wins
    } else {
      const u = userById.get(s.user_id);
      g.contributors.push({
        sourceId: s.id,
        userId: s.user_id,
        username: u ? u.username : 'deleted user',
        displayName: u ? (u.display_name || u.username) : 'Deleted user',
        role: u ? u.role : null,
        nameGiven: s.name,
        addedAt: s.created_at,
        enabled: !!s.enabled,
      });
    }
    if (s.enabled) g.enabledCount++;
    if (s.last_fetched && (!g.lastFetched || ts(s.last_fetched) > ts(g.lastFetched))) {
      g.lastFetched = s.last_fetched;
      g.lastError = s.last_error || null;
    }
    if (s.added_by !== 'system' && (!g.firstAddedAt || ts(s.created_at) < ts(g.firstAddedAt))) g.firstAddedAt = s.created_at;
  }

  const entries = [...groups.values()].map((g) => {
    g.contributors.sort((a, b) => ts(a.addedAt) - ts(b.addedAt));
    const userSubmitted = !g.builtIn && g.contributors.length > 0;
    return {
      ...g,
      status: !g.lastFetched ? 'pending' : g.lastError ? 'error' : 'ok',
      userSubmitted,
      isNew: userSubmitted && g.firstAddedAt ? now - ts(g.firstAddedAt) < NEW_MS : false,
      contributorCount: g.contributors.length,
    };
  });

  // User-submitted first (newest first), then built-in feeds that users also added, then the rest
  entries.sort((a, b) =>
    (b.userSubmitted - a.userSubmitted) ||
    (a.userSubmitted ? ts(b.firstAddedAt) - ts(a.firstAddedAt) : 0) ||
    (b.contributorCount - a.contributorCount) ||
    String(a.name).localeCompare(String(b.name)));

  const totals = {
    feeds: entries.length,
    builtIn: entries.filter((e) => e.builtIn).length,
    userSubmitted: entries.filter((e) => e.userSubmitted).length,
    newUserSubmitted: entries.filter((e) => e.isNew).length,
    userRows: sources.filter((s) => s.added_by !== 'system').length,
    duplicatesFolded: sources.length - entries.length,
  };
  return { entries, totals };
}

module.exports = { canonicalUrl, buildCatalog };

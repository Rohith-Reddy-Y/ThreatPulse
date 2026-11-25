/**
 * ThreatPulse — Jira Cloud integration (PoC tracker "Approve")
 *
 * Approving a PoC tracker item creates one issue in the Jira project's backlog
 * (in a Scrum project, an issue that is in no sprint sits in the backlog).
 * The description follows the team's research template:
 *   Ideation (summary, blog/article link, PoC link) · References · Hypothesis · Summary · Outcome
 *
 * Settings (Render → Environment):
 *   JIRA_BASE_URL     https://<site>.atlassian.net
 *   JIRA_EMAIL        the Atlassian account email that owns the API token
 *   JIRA_API_TOKEN    from https://id.atlassian.com/manage-profile/security/api-tokens
 *   JIRA_PROJECT_KEY  e.g. SCRUM
 *   JIRA_ISSUE_TYPE   optional, default "Task"
 */
const crypto = require('crypto');
const axios = require('axios');
const { isSafeUrl } = require('./net-guard');

function config() {
  const base = String(process.env.JIRA_BASE_URL || '').trim().replace(/\/+$/, '');
  const email = String(process.env.JIRA_EMAIL || '').trim();
  const token = String(process.env.JIRA_API_TOKEN || '').trim();
  const project = String(process.env.JIRA_PROJECT_KEY || '').trim().toUpperCase();
  const issueType = String(process.env.JIRA_ISSUE_TYPE || 'Task').trim() || 'Task';
  const missing = [];
  if (!base) missing.push('JIRA_BASE_URL');
  if (!email) missing.push('JIRA_EMAIL');
  if (!token) missing.push('JIRA_API_TOKEN');
  if (!project) missing.push('JIRA_PROJECT_KEY');
  let baseOk = false;
  try { const u = new URL(base); baseOk = u.protocol === 'https:' && !u.username && !u.password && isSafeUrl(base); } catch { baseOk = false; }
  if (base && !baseOk) missing.push('JIRA_BASE_URL (must be https://<site>.atlassian.net)');
  if (project && !/^[A-Z][A-Z0-9_]{1,19}$/.test(project)) missing.push('JIRA_PROJECT_KEY (letters/digits, e.g. SCRUM)');
  return { base, email, token, project, issueType, missing, ok: missing.length === 0 };
}

function status() {
  const c = config();
  return { configured: c.ok, missing: c.missing, project: c.project || null, site: c.ok ? c.base : null };
}

function headers(c) {
  return {
    Authorization: `Basic ${Buffer.from(`${c.email}:${c.token}`).toString('base64')}`,
    Accept: 'application/json',
    'Content-Type': 'application/json',
  };
}

// A label unique to the story, so a second approval (or a wiped database) never files it twice
function storyLabel(storyKey) {
  return `tp-poc-${crypto.createHash('sha1').update(String(storyKey)).digest('hex').slice(0, 12)}`;
}

// ── Atlassian Document Format helpers ──
const txt = (text, marks) => (marks ? { type: 'text', text: String(text), marks } : { type: 'text', text: String(text) });
const link = (text, href) => txt(text, [{ type: 'link', attrs: { href } }]);
const para = (...content) => ({ type: 'paragraph', content: content.filter(Boolean).filter((n) => n.text !== '') });
const heading = (text, level = 2) => ({ type: 'heading', attrs: { level }, content: [txt(text)] });
const bullets = (items) => ({ type: 'bulletList', content: items.map((c) => ({ type: 'listItem', content: [Array.isArray(c) ? para(...c) : c] })) });
const strong = (t) => txt(t, [{ type: 'strong' }]);
const em = (t) => txt(t, [{ type: 'em' }]);
const safeHref = (u) => (/^https?:\/\/[^\s]+$/i.test(String(u || '')) ? String(u).slice(0, 2000) : null);
const clip = (s, n) => { const v = String(s || '').replace(/\s+/g, ' ').trim(); return v.length > n ? v.slice(0, n - 1) + '…' : v; };

function cvesOf(item) {
  const text = `${item.cve_id || ''} ${item.title || ''} ${item.description || ''}`;
  return [...new Set((text.match(/\bCVE-\d{4}-\d{4,7}\b/gi) || []).map((c) => c.toUpperCase()))].slice(0, 5);
}

function pocLinks(item) {
  const links = ((item.poc && item.poc.links) || []).filter((l) => safeHref(l.url) && l.status !== 'dead');
  const rank = { verified: 0, unverified: 1, suspicious: 2 };
  return links.sort((a, b) => (rank[a.status] ?? 3) - (rank[b.status] ?? 3)).slice(0, 5);
}

function plainSummary(item) {
  const s = item.aiSummary || String(item.description || '').replace(/<[^>]+>/g, ' ');
  return clip(s, 900) || 'No summary available.';
}

/** Template hypothesis when AI is unavailable. */
function templateHypothesis(item) {
  const cves = cvesOf(item);
  const ttps = (item.ttps || []).slice(0, 4);
  const subject = cves.length ? cves.join(', ') : clip(item.title, 120);
  const tech = ttps.length ? ttps.map((t) => `${t.subId || t.id} ${t.name}`).join('; ') : 'T1190 Exploit Public-Facing Application';
  return `If an attacker runs the public proof-of-concept for ${subject} against a vulnerable system in our lab, ` +
    `we expect to see the behaviour mapped to ${tech} in endpoint, network and application logs, ` +
    'and our current detections either alert on it or show a gap we can close with a new rule.';
}

// The article title alone: no "[CISA KEV]"-style tags, no " | Site name" / " - Site name" suffix
function cleanTitle(item) {
  let t = String(item.title || '').replace(/\s+/g, ' ').trim();
  t = t.replace(/^(\[[^\]]{1,40}\]\s*)+/, '');
  const m = t.match(/^(.{20,}?)\s+[|–—-]\s+([^|–—-]{2,50})$/);
  if (m) {
    const site = m[2].toLowerCase().replace(/[^a-z0-9]/g, '');
    const src = String(item.source_name || '').toLowerCase().replace(/[^a-z0-9]/g, '');
    if (site && (src.includes(site) || site.includes(src.slice(0, 6)) || / \|/.test(t))) t = m[1];
  }
  return t || 'Untitled';
}

/** Build the Jira issue fields for an approved PoC tracker item. */
function buildIssue(item, { hypothesis, storyKey, approvedBy, project, issueType }) {
  const articleUrl = safeHref(item.url);
  const pocs = pocLinks(item);
  const cves = cvesOf(item);
  const ttps = (item.ttps || []).filter((t) => t && t.id).slice(0, 8);
  const vuln = (item.vuln || [])[0] || null;
  const shortSummary = clip(item.aiSummary || item.description, 400) || clip(item.title, 200);

  const content = [];
  // Ideation
  content.push(heading('Ideation'));
  content.push(para(txt(shortSummary)));
  content.push(bullets([
    [strong('Blog / article: '), articleUrl ? link(clip(item.title, 140), articleUrl) : txt('n/a')],
    ...(pocs.length
      ? pocs.map((l) => [strong('PoC: '), link(l.url, l.url), txt(` (${l.status}${l.source === 'nvd-reference' ? ', from NVD' : ''})`)])
      : [[strong('PoC: '), txt('no link found yet. The article says: '), em(clip(((item.poc && item.poc.wording) || [])[0] || 'a PoC is available', 240))]]),
  ]));

  // References
  content.push(heading('References'));
  const refs = [];
  if (articleUrl) refs.push([link(`${item.source_name || 'Article'}: ${clip(item.title, 120)}`, articleUrl)]);
  for (const l of pocs) refs.push([link(l.url, l.url)]);
  for (const c of cves) refs.push([link(`NVD ${c}`, `https://nvd.nist.gov/vuln/detail/${c}`)]);
  for (const t of ttps) {
    const href = safeHref(t.url) || `https://attack.mitre.org/techniques/${t.id}/`;
    refs.push([link(`MITRE ATT&CK ${t.subId || t.id} ${t.name}${t.tacticName ? ` (${t.tacticName})` : ''}`, href)]);
  }
  content.push(refs.length ? bullets(refs) : para(txt('None')));

  // Hypothesis
  content.push(heading('Hypothesis'));
  for (const p of String(hypothesis || templateHypothesis(item)).split(/\n{2,}/).slice(0, 4)) content.push(para(txt(clip(p, 1500))));

  // Summary
  content.push(heading('Summary'));
  content.push(para(txt(plainSummary(item))));
  const facts = [];
  if (item.severity) facts.push([strong('Severity: '), txt(item.severity)]);
  if (cves.length) facts.push([strong('CVE: '), txt(cves.join(', '))]);
  if (vuln) {
    const v = [];
    if (vuln.cvss !== null && vuln.cvss !== undefined) v.push(`CVSS ${vuln.cvss}`);
    if (vuln.epss !== null && vuln.epss !== undefined) v.push(`EPSS ${(vuln.epss * 100).toFixed(1)}%`);
    if (vuln.kev) v.push('in CISA KEV');
    if (v.length) facts.push([strong('Exploit risk: '), txt(v.join(' · '))]);
  }
  if (item.threat_actors) facts.push([strong('Threat actor: '), txt(clip(item.threat_actors, 200))]);
  if (ttps.length) facts.push([strong('Techniques: '), txt(ttps.map((t) => t.subId || t.id).join(', '))]);
  if (item.poc && item.poc.verdict) facts.push([strong('PoC check: '), txt(item.poc.verdict)]);
  if (facts.length) content.push(bullets(facts));

  // Outcome (filled in by the team after the experiment)
  content.push(heading('Outcome'));
  content.push(bullets([
    [strong('Result: '), em('to be filled in after the lab run')],
    [strong('Detections created / updated: '), em('…')],
    [strong('Gaps and follow-ups: '), em('…')],
  ]));
  content.push(para(em(`Created from the ThreatPulse PoC tracker${approvedBy ? ` by ${approvedBy}` : ''}.`)));

  return {
    fields: {
      project: { key: project },
      issuetype: { name: issueType },
      summary: clip(`Research - ${cleanTitle(item)}`, 250),
      labels: ['threatpulse', 'poc-research', storyLabel(storyKey)],
      description: { type: 'doc', version: 1, content },
    },
  };
}

function jiraError(err) {
  const r = err && err.response;
  if (!r) return err && err.code === 'ECONNABORTED' ? 'Jira did not answer in time' : 'Could not reach Jira';
  if (r.status === 401) return 'Jira rejected the login: check JIRA_EMAIL and JIRA_API_TOKEN';
  if (r.status === 403) return 'This Jira account may not create issues in that project';
  if (r.status === 404) return 'Jira project not found: check JIRA_PROJECT_KEY and JIRA_BASE_URL';
  const d = r.data || {};
  const msgs = [...(d.errorMessages || []), ...Object.entries(d.errors || {}).map(([k, v]) => `${k}: ${v}`)];
  return clip(`Jira error ${r.status}${msgs.length ? `: ${msgs.join('; ')}` : ''}`, 300);
}

/** Find an issue already filed for this story (by its label). */
async function findExisting(c, label) {
  try {
    const jql = `project = "${c.project}" AND labels = "${label}" ORDER BY created DESC`;
    const r = await axios.get(`${c.base}/rest/api/3/search/jql`, {
      params: { jql, fields: 'key', maxResults: 1 }, headers: headers(c), timeout: 15000,
    });
    const issue = r && r.data && Array.isArray(r.data.issues) ? r.data.issues[0] : null;
    return issue && issue.key ? issue.key : null;
  } catch {
    return null;   // search is a best-effort duplicate guard
  }
}

/**
 * Create the backlog issue. Returns { ok, key, url, existing } or { ok:false, error }.
 */
async function createPocIssue(item, { hypothesis, storyKey, approvedBy } = {}) {
  const c = config();
  if (!c.ok) return { ok: false, notConfigured: true, error: `Jira is not connected. Set ${c.missing.join(', ')} in Render → Environment.` };
  const label = storyLabel(storyKey || item.url || item.id);
  const existing = await findExisting(c, label);
  if (existing) return { ok: true, key: existing, url: `${c.base}/browse/${existing}`, existing: true };
  const body = buildIssue(item, { hypothesis, storyKey: storyKey || item.url || item.id, approvedBy, project: c.project, issueType: c.issueType });
  try {
    const r = await axios.post(`${c.base}/rest/api/3/issue`, body, { headers: headers(c), timeout: 20000 });
    const key = r && r.data && r.data.key;
    if (!key || !/^[A-Z][A-Z0-9_]+-\d+$/.test(key)) return { ok: false, error: 'Jira did not return an issue key' };
    return { ok: true, key, url: `${c.base}/browse/${key}`, existing: false };
  } catch (err) {
    return { ok: false, error: jiraError(err) };
  }
}

module.exports = { config, status, cleanTitle, buildIssue, createPocIssue, templateHypothesis, storyLabel };

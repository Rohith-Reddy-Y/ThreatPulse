'use strict';
// PoC tracker review: approve → one Jira backlog issue (Ideation, References,
// Hypothesis, Summary, Outcome), decline / undo, no duplicates, tracker filtering.
const test = require('node:test');
const assert = require('node:assert');
const axios = require('axios');
const { load, makeUser, art, call } = require('./data-helpers');

const JIRA_ENV = {
  JIRA_BASE_URL: 'https://example-team.atlassian.net', JIRA_EMAIL: 'me@example.test',
  JIRA_API_TOKEN: 'test-token', JIRA_PROJECT_KEY: 'SCRUM',
};
function withJira(on) {
  for (const [k, v] of Object.entries(JIRA_ENV)) { if (on) process.env[k] = v; else delete process.env[k]; }
  delete process.env.GROQ_API_KEY;
}
function fakeJira() {
  const created = [];
  axios.calls.length = 0;
  axios.__handler = async ({ method, url, data }) => {
    if (method === 'GET' && url.endsWith('/rest/api/3/search/jql')) return { status: 200, data: { issues: [] } };
    if (method === 'POST' && url.endsWith('/rest/api/3/issue')) {
      created.push(data);
      return { status: 201, data: { key: `SCRUM-${created.length}` } };
    }
    return { status: 404, data: {} };
  };
  return created;
}
const docText = (node) => (node.text || '') + (node.content || []).map(docText).join(' ');
const headings = (doc) => doc.content.filter((n) => n.type === 'heading').map((n) => n.content[0].text);

test('approve creates one Jira backlog issue in the agreed format', async () => {
  const env = load();
  withJira(true);
  const created = fakeJira();
  const admin = makeUser(env.db, { role: 'admin' });
  const { id } = env.db.insertArticle(art({
    title: 'Researchers release proof-of-concept for CVE-2026-4242 in Acme Gateway',
    description: 'A proof-of-concept exploit for CVE-2026-4242 was published on GitHub. Attackers can gain remote code execution.',
    url: 'https://blog.example/acme-poc', cve_id: 'CVE-2026-4242', has_poc: 1,
  }));
  env.db.savePocCheck(id, { verdict: 'verified', links: [{ url: 'https://github.com/res/acme-poc', kind: 'github', source: 'article', status: 'verified', reasons: [] }], wording: [], cves: ['CVE-2026-4242'] });

  const r = await call(env, 'POST', '/admin/poc-decision', { user: admin, body: { articleId: id, action: 'approve' } });
  assert.strictEqual(r.statusCode, 200, JSON.stringify(r.body));
  assert.strictEqual(r.body.decision.status, 'approved');
  assert.strictEqual(r.body.decision.jiraKey, 'SCRUM-1');
  assert.strictEqual(r.body.decision.jiraUrl, 'https://example-team.atlassian.net/browse/SCRUM-1');
  assert.strictEqual(created.length, 1);

  const f = created[0].fields;
  assert.strictEqual(f.project.key, 'SCRUM');
  assert.strictEqual(f.issuetype.name, 'Task');
  assert.strictEqual(f.summary, 'Research - Researchers release proof-of-concept for CVE-2026-4242 in Acme Gateway');
  assert.ok(f.labels.includes('threatpulse') && f.labels.some((l) => /^tp-poc-[0-9a-f]{12}$/.test(l)));
  assert.deepStrictEqual(headings(f.description), ['Ideation', 'References', 'Hypothesis', 'Summary', 'Outcome']);
  const all = docText(f.description);
  assert.match(all, /https:\/\/github\.com\/res\/acme-poc/);          // PoC link
  assert.match(all, /If an attacker runs the public proof-of-concept for CVE-2026-4242/); // template hypothesis (no AI key)
  const json = JSON.stringify(f.description);
  assert.ok(json.includes('"href":"https://blog.example/acme-poc"'), 'blog link');
  assert.ok(json.includes('"href":"https://nvd.nist.gov/vuln/detail/CVE-2026-4242"'), 'NVD reference');

  // A second click never files a duplicate
  const again = await call(env, 'POST', '/admin/poc-decision', { user: admin, body: { articleId: id, action: 'approve' } });
  assert.strictEqual(again.statusCode, 200);
  assert.strictEqual(again.body.decision.jiraKey, 'SCRUM-1');
  assert.strictEqual(created.length, 1);
  // ...and an approved item can't be declined
  const dec = await call(env, 'POST', '/admin/poc-decision', { user: admin, body: { articleId: id, action: 'decline' } });
  assert.strictEqual(dec.statusCode, 409);
  axios.__handler = null;
});

test('approve reuses an issue already in Jira for the same story (wiped database)', async () => {
  const env = load();
  withJira(true);
  const created = fakeJira();
  axios.__handler = async ({ method, url }) => {
    if (method === 'GET' && url.endsWith('/rest/api/3/search/jql')) return { status: 200, data: { issues: [{ key: 'SCRUM-77' }] } };
    created.push(1);
    return { status: 201, data: { key: 'SCRUM-99' } };
  };
  const admin = makeUser(env.db, { role: 'admin' });
  const { id } = env.db.insertArticle(art({ title: 'PoC out for Foo', description: 'A PoC was released.', has_poc: 1 }));
  const r = await call(env, 'POST', '/admin/poc-decision', { user: admin, body: { articleId: id, action: 'approve' } });
  assert.strictEqual(r.body.decision.jiraKey, 'SCRUM-77');
  assert.strictEqual(r.body.existing, true);
  assert.strictEqual(created.length, 0);
  axios.__handler = null;
});

test('approve without Jira settings explains what to set, and stores nothing', async () => {
  const env = load();
  withJira(false);
  const admin = makeUser(env.db, { role: 'admin' });
  const { id } = env.db.insertArticle(art({ title: 'PoC out', has_poc: 1 }));
  const r = await call(env, 'POST', '/admin/poc-decision', { user: admin, body: { articleId: id, action: 'approve' } });
  assert.strictEqual(r.statusCode, 503);
  assert.match(r.body.error, /JIRA_API_TOKEN/);
  assert.strictEqual(env.db.getPocDecisions(['blog.example']).size, 0);
});

test('Jira errors are reported without saving an approval', async () => {
  const env = load();
  withJira(true);
  axios.__handler = async ({ method }) => {
    if (method === 'GET') return { status: 200, data: { issues: [] } };
    const e = new Error('401'); e.response = { status: 401, data: {} }; throw e;
  };
  const admin = makeUser(env.db, { role: 'admin' });
  const { id } = env.db.insertArticle(art({ title: 'PoC out', has_poc: 1, url: 'https://x.example/a' }));
  const r = await call(env, 'POST', '/admin/poc-decision', { user: admin, body: { articleId: id, action: 'approve' } });
  assert.strictEqual(r.statusCode, 502);
  assert.match(r.body.error, /JIRA_EMAIL and JIRA_API_TOKEN/);
  assert.strictEqual(env.db.getPocDecision('x.example/a'), null);
  axios.__handler = null;
});

test('decline, undo, bad input; tracker hides malware samples and shows decisions', async () => {
  const env = load();
  withJira(false);
  const admin = makeUser(env.db, { role: 'admin' });
  const { id } = env.db.insertArticle(art({ title: 'Exploit code published for Bar', description: 'Exploit code is now available.', has_poc: 1, url: 'https://news.example/bar' }));
  env.db.insertArticle(art({ title: '[Malware] AgentTesla — 3 new samples submitted', source_name: 'MalwareBazaar - Malware Samples', has_poc: 1 }));

  const bad = await call(env, 'POST', '/admin/poc-decision', { user: admin, body: { articleId: id, action: 'delete' } });
  assert.strictEqual(bad.statusCode, 400);
  const missing = await call(env, 'POST', '/admin/poc-decision', { user: admin, body: { articleId: 999999, action: 'decline' } });
  assert.strictEqual(missing.statusCode, 404);

  const d = await call(env, 'POST', '/admin/poc-decision', { user: admin, body: { articleId: id, action: 'decline' } });
  assert.strictEqual(d.body.decision.status, 'declined');

  let t = await call(env, 'GET', '/admin/poc-tracker', { user: admin, query: { days: '30' } });
  assert.strictEqual(t.statusCode, 200);
  assert.ok(!t.body.items.some((x) => /MalwareBazaar/.test(x.source_name)), 'malware samples are not PoCs');
  const item = t.body.items.find((x) => x.id === id);
  assert.strictEqual(item.decision.status, 'declined');
  assert.strictEqual(item.kind, 'article');
  assert.ok(item.wording.some((q) => /Exploit code is now available/.test(q)), JSON.stringify(item.wording));
  assert.strictEqual(t.body.jira.configured, false);

  const u = await call(env, 'POST', '/admin/poc-decision', { user: admin, body: { articleId: id, action: 'undo' } });
  assert.strictEqual(u.body.decision, null);
  t = await call(env, 'GET', '/admin/poc-tracker', { user: admin, query: { days: '30' } });
  assert.strictEqual(t.body.items.find((x) => x.id === id).decision, null);
});

test('existing MalwareBazaar rows lose their PoC flag on startup', () => {
  const env = load();
  const { id } = env.db.insertArticle(art({ title: '[Malware] Lumma — 1 new sample', source_name: 'MalwareBazaar - Malware Samples', has_poc: 1 }));
  env.db.getDb().prepare('UPDATE articles SET has_poc = 1 WHERE id = ?').run(id);
  const again = load(env.dbPath);
  assert.strictEqual(again.db.getDb().prepare('SELECT has_poc FROM articles WHERE id = ?').get(id).has_poc, 0);
});

test('background page scan: flags technique posts, keeps manual checks, shows them as no-CVE research', async () => {
  const env = load();
  withJira(false);
  const admin = makeUser(env.db, { role: 'admin' });
  const url = 'https://research.example/new-injection-technique';
  const a1 = env.db.insertArticle(art({ title: 'A new process injection technique', description: 'Research.', url, has_poc: 0 })).id;
  const todo = env.db.getArticlesToScanForPoc(50);
  assert.ok(todo.some((t) => t.url === url));
  env.db.savePocScan(url, { quotes: ['We released the tool on GitHub.'], denied: [], links: [{ url: 'https://github.com/r/inject', kind: 'github', key: 'r/inject' }] });
  assert.ok(!env.db.getArticlesToScanForPoc(50).some((t) => t.url === url), 'scanned once');
  const t = await call(env, 'GET', '/admin/poc-tracker', { user: admin, query: { days: '30' } });
  const item = t.body.items.find((x) => x.id === a1);
  assert.ok(item, 'technique post is in the tracker');
  assert.strictEqual(item.noCve, true);
  assert.strictEqual(item.poc.verdict, 'mentioned');
  assert.strictEqual(item.poc.auto, true);
  assert.strictEqual(item.poc.links[0].url, 'https://github.com/r/inject');
  assert.deepStrictEqual(item.wording, ['We released the tool on GitHub.']);

  // A scan never overwrites a real (manual) check
  const url2 = 'https://research.example/other';
  const a2 = env.db.insertArticle(art({ title: 'Other research', url: url2 })).id;
  env.db.savePocCheck(a2, { verdict: 'verified', links: [], wording: [] });
  env.db.savePocScan(url2, { quotes: ['PoC is out.'], denied: [], links: [] });
  assert.strictEqual(env.db.getPocCheck(a2).verdict, 'verified');
});

test('Jira title is only "Research - <article title>"', () => {
  require('./data-helpers');
  const { cleanTitle, buildIssue } = require('../src/jira');
  assert.strictEqual(cleanTitle({ title: 'Ruby2Shell (CVE-2026-1): Detection, Hunting, and Fixes | Corelight', source_name: 'Corelight Blog' }), 'Ruby2Shell (CVE-2026-1): Detection, Hunting, and Fixes');
  assert.strictEqual(cleanTitle({ title: '[CISA KEV] CVE-2026-1 — Acme RCE' }), 'CVE-2026-1 — Acme RCE');
  const f = buildIssue({ title: 'New EDR bypass technique - The Hacker News', source_name: 'The Hacker News', url: 'https://x.example/a' },
    { storyKey: 'k', project: 'SCRUM', issueType: 'Task' }).fields;
  assert.strictEqual(f.summary, 'Research - New EDR bypass technique');
});

test('scan-rule update: automatic flags are cleared and recomputed once', () => {
  const env = load();
  const url = 'https://blog.example/aws-forensics';
  const a = env.db.insertArticle(art({ title: 'AWS forensics guide', description: 'Tools we used.', url })).id;
  const b = env.db.insertArticle(art({ title: 'PoC released for Foo', description: 'A proof-of-concept was released.', url: 'https://blog.example/foo' })).id;
  env.db.savePocScan(url, { quotes: [], denied: [], links: [{ url: 'https://github.com/x/y', kind: 'github', key: 'x/y' }] });
  env.db.savePocScan('https://blog.example/foo', { quotes: ['A proof-of-concept was released.'], denied: [], links: [] });
  env.db.getDb().prepare("DELETE FROM app_settings WHERE key = 'poc_scan_version'").run();
  const detect = (t, d) => /proof-of-concept|PoC/i.test(`${t} ${d}`);
  assert.strictEqual(env.db.resetAutoPocScans(detect), 2);
  const flag = (id) => env.db.getDb().prepare('SELECT has_poc FROM articles WHERE id = ?').get(id).has_poc;
  assert.strictEqual(flag(a), 0, 'false positive cleared');
  assert.strictEqual(flag(b), 1, 'real PoC wording kept');
  assert.strictEqual(env.db.getPocCheck(a), null);
  assert.ok(env.db.getArticlesToScanForPoc(50).some((r) => r.url === url), 'rescanned with the new rules');
  assert.strictEqual(env.db.resetAutoPocScans(detect), 0, 'runs once');
});

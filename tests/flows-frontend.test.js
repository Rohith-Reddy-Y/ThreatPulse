/**
 * Frontend journeys: drives the real public/js/app.js / admin.js in a vm with a
 * stub DOM (tests/helpers/browser.js) and checks what each screen sends to the
 * API and what it shows for every response — especially messages that used to
 * be wrong or misleading.
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert/strict');
const { createBrowser } = require('./helpers/browser');

const GUEST = { id: 99, username: 'guest', displayName: 'Guest', role: 'analyst', email: null };
const ADMIN = { id: 1, username: 'admin', displayName: 'Administrator', role: 'admin', email: null };
const ALICE = { id: 2, username: 'alice', displayName: 'Alice', role: 'analyst', email: 'alice@example.test', mustChangePassword: false };

const EMPTY_STATS = { threatsToday: 0, threatsYesterday: 0, criticalVulns: 0, pocsDetected: 0, activeSources: 0, erroredSources: 0, timeline: [] };

// Routes every dashboard load needs; tests override what they exercise.
function baseRoutes(over = {}) {
  return {
    'GET /api/auth/config': { requireInvite: false, emailEnabled: false, dbCreatedAt: null },
    'GET /api/auth/me': { status: 401, body: { error: 'Authentication required' } },
    'POST /api/auth/refresh': { status: 401, body: { success: false } },
    'POST /api/auth/guest': { success: true, user: GUEST },
    'GET /api/articles/stats': EMPTY_STATS,
    'GET /api/articles': { articles: [], total: 0, page: 1, totalPages: 0 },
    'GET /api/sources': { sources: [] },
    'GET /api/notifications/settings': {},
    'POST /api/auth/logout': { success: true },
    ...over,
  };
}

async function signIn(b, username, password) {
  b.el('login-username').value = username;
  b.el('login-password').value = password;
  await b.el('login-form').fire('submit');
  await b.settle();
}

// ---------------------------------------------------------------------------
// Password change: no forced modal, change goes through an emailed link
// ---------------------------------------------------------------------------
test('signing in never pops a forced "change your password" modal', async () => {
  const b = createBrowser({ routes: baseRoutes({
    'POST /api/auth/login': { success: true, user: { ...ADMIN, mustChangePassword: true } },
  }) });
  await b.settle();
  await signIn(b, 'admin', 'Init1al Pw!');
  assert.ok(!b.visible('password-modal'), 'no forced modal');
});

test('Change Password emails a link and says where it went; errors show the server message', async () => {
  const b = createBrowser({ routes: baseRoutes({
    'GET /api/auth/me': { success: true, user: ALICE },
    'POST /api/auth/password/request-link': { success: true, emailSent: true, email: 'al***e@example.test' },
  }) });
  await b.settle();
  await b.el('change-password-btn').fire('click');
  assert.ok(b.visible('password-modal'));
  assert.equal(b.el('password-link-email').textContent, 'alice@example.test');
  await b.el('password-form').fire('submit');
  await b.settle();
  const post = b.req('POST', '/api/auth/password/request-link');
  assert.equal(post.length, 1);
  assert.ok(post[0].headers['X-CSRF-Token'], 'CSRF header sent');
  assert.equal(b.req('PUT', '/api/auth/password').length, 0, 'never changes the password in-app');
  assert.match(b.el('password-success').textContent, /al\*\*\*e@example\.test/);

  b.routes['POST /api/auth/password/request-link'] = { status: 400, body: { success: false, needsEmail: true, error: 'Add an email address to your account first' } };
  await b.el('password-form').fire('submit');
  await b.settle();
  assert.equal(b.el('password-error').textContent, 'Add an email address to your account first');
});

// ---------------------------------------------------------------------------
// Sign-in errors: explain a wiped (ephemeral) database
// ---------------------------------------------------------------------------
test('failed sign-in on a freshly reset database explains why an old password no longer works', async () => {
  const resetAt = new Date(Date.now() - 10 * 60000).toISOString();
  const b = createBrowser({ routes: baseRoutes({
    'GET /api/auth/config': { requireInvite: false, emailEnabled: false, dbCreatedAt: resetAt },
    'POST /api/auth/login': { success: false, error: 'Invalid username/email or password' },
  }) });
  await b.settle();
  await signIn(b, 'admin', 'MyChangedPassw0rd');
  const msg = b.el('login-error').textContent;
  assert.match(msg, /^Invalid username\/email or password/);
  assert.match(msg, /database was reset/);
  assert.ok(b.visible('login-error'));

  b.routes['POST /api/auth/login'] = { success: false, locked: true, error: 'Too many failed login attempts. Try again in 15 minute(s).' };
  await signIn(b, 'admin', 'x');
  assert.equal(b.el('login-error').textContent, 'Too many failed login attempts. Try again in 15 minute(s).');
});

test('no reset notice on a server whose database survived the restart', async () => {
  const b = createBrowser({ routes: baseRoutes({ 'POST /api/auth/login': { success: false, error: 'Invalid username/email or password' } }) });
  await b.settle();
  await signIn(b, 'alice', 'nope');
  assert.equal(b.el('login-error').textContent, 'Invalid username/email or password');
});

// ---------------------------------------------------------------------------
// Registration with REQUIRE_INVITE_CODE
// ---------------------------------------------------------------------------
test('invite-only server: the invite field is shown, required, and sent upper-cased', async () => {
  const b = createBrowser({ routes: baseRoutes({
    'GET /api/auth/config': { requireInvite: true, emailEnabled: false, dbCreatedAt: null },
    'POST /api/auth/register': { success: true, user: { ...ALICE } },
  }) });
  await b.settle();
  assert.equal(b.el('reg-invite-group').style.display, '', 'field visible');
  const fill = () => {
    b.el('reg-username').value = 'alice'; b.el('reg-display').value = 'Alice'; b.el('reg-email').value = 'alice@example.test';
    b.el('reg-password').value = 'Passw0rdA'; b.el('reg-confirm').value = 'Passw0rdA';
  };
  fill(); b.el('reg-invite').value = '';
  await b.el('register-form').fire('submit'); await b.settle();
  assert.match(b.el('register-error').textContent, /invite code is required/i);
  assert.equal(b.req('POST', '/api/auth/register').length, 0);

  fill(); b.el('reg-invite').value = ' abcd1234 ';
  await b.el('register-form').fire('submit'); await b.settle();
  assert.equal(b.req('POST', '/api/auth/register')[0].body.inviteCode, 'ABCD1234');
});

test('open registration keeps the invite field hidden', async () => {
  const b = createBrowser({ routes: baseRoutes() });
  await b.settle();
  assert.equal(b.el('reg-invite-group').style.display, 'none');
});

// ---------------------------------------------------------------------------
// Account changes / notifications
// ---------------------------------------------------------------------------
test('email change applied without verification (no SMTP) is a success, not "Failed to update email"', async () => {
  const b = createBrowser({ routes: baseRoutes({
    'GET /api/auth/me': { success: true, user: ALICE },
    'PUT /api/auth/email': { success: true, verificationRequired: false, email: 'new@example.test', message: 'Email address updated' },
  }) });
  await b.settle();
  await b.el('change-email-btn').fire('click');
  b.el('account-email').value = 'new@example.test';
  await b.el('email-form').fire('submit'); await b.settle();
  assert.ok(!b.visible('email-modal'));
  assert.ok(!b.visible('verification-modal'));
  assert.ok(b.el('email-error').classList.contains('hidden'));
  assert.ok(b.toastTexts().some(t => /Email updated/.test(t)));
  // the next open shows the new address
  await b.el('change-email-btn').fire('click');
  assert.equal(b.el('account-email').value, 'new@example.test');
});

test('notification test / save without SMTP never shows a false success', async () => {
  const b = createBrowser({ routes: baseRoutes({
    'GET /api/auth/me': { success: true, user: ALICE },
    'PUT /api/notifications/settings': { success: true },
    'POST /api/notifications/test': (r) => (r.body.type === 'email'
      ? { success: false, error: 'SMTP not configured' }
      : { status: 400, body: { error: 'Telegram not configured' } }),
  }), groups: { '.notif-test': [{ test: 'email' }, { test: 'telegram' }] } });
  await b.settle();
  b.el('notif-email-enabled').checked = true;
  const [emailBtn, tgBtn] = b.sandbox.document.querySelectorAll('.notif-test');
  await emailBtn.fire('click'); await b.settle();
  await tgBtn.fire('click'); await b.settle();
  const texts = b.toastTexts();
  assert.ok(texts.some(t => /email alerts unavailable/.test(t)), texts.join(' | '));
  assert.ok(texts.some(t => /Test failed SMTP not configured/.test(t)), texts.join(' | '));
  assert.ok(texts.some(t => /Error Telegram not configured/.test(t)), texts.join(' | '));
  assert.ok(!texts.some(t => /Test sent/.test(t)));
});

// ---------------------------------------------------------------------------
// Feed: fetch-now feedback, stat cards, stats time zone, export
// ---------------------------------------------------------------------------
test('Fetch now does not announce "Feeds updated" while the fetch is still running', async () => {
  const b = createBrowser({ routes: baseRoutes({
    'GET /api/auth/me': { success: true, user: ALICE },
    'POST /api/fetch-now': { success: true, scope: 'own', completed: false, message: 'Fetching your 3 source(s) — still running; new articles will appear shortly.' },
  }) });
  await b.settle();
  await b.el('fetch-now-btn').fire('click'); await b.settle();
  const texts = b.toastTexts();
  assert.ok(texts.some(t => /still running/.test(t)), texts.join(' | '));
  assert.ok(!texts.some(t => /Feeds updated|Complete/.test(t)));

  const b2 = createBrowser({ routes: baseRoutes({
    'GET /api/auth/me': { success: true, user: ALICE },
    'POST /api/fetch-now': { success: true, scope: 'own', completed: true, newArticles: 4, errors: 0, message: 'Fetched 2 source(s): 4 new article(s).' },
  }) });
  await b2.settle();
  await b2.el('fetch-now-btn').fire('click'); await b2.settle();
  assert.ok(b2.toastTexts().some(t => /Fetch complete Fetched 2 source\(s\): 4 new article\(s\)\./.test(t)));
});

test('stats are requested for the viewer\'s time zone; "Threats today" filters to the local day', async () => {
  const b = createBrowser({ routes: baseRoutes({ 'GET /api/auth/me': { success: true, user: ALICE } }),
    groups: { '.stat-card': [{ stat: 'threats' }, { stat: 'critical' }, { stat: 'pocs' }] } });
  await b.settle();
  const statsReq = b.requests.find(r => r.url.startsWith('/api/articles/stats'));
  assert.equal(statsReq.url, `/api/articles/stats?tz=${-new Date().getTimezoneOffset()}`);

  const [threats, critical, pocs] = b.sandbox.document.querySelectorAll('.stat-card');
  await threats.fire('click'); await b.settle();
  const last = () => new URL('http://x' + b.requests.filter(r => r.url.startsWith('/api/articles?')).pop().url).searchParams;
  const start = new Date(); start.setHours(0, 0, 0, 0);
  const end = new Date(start); end.setDate(end.getDate() + 1);
  assert.equal(last().get('start_date'), start.toISOString());
  assert.equal(last().get('end_date'), new Date(end.getTime() - 1).toISOString());
  assert.equal(b.el('time-range-filter').value, 'custom');

  await critical.fire('click'); await b.settle();
  assert.equal(last().get('severity'), 'critical');
  assert.equal(last().get('time_range'), '7d', 'same window as the count');
  await pocs.fire('click'); await b.settle();
  assert.equal(last().get('has_poc'), '1');
  assert.equal(last().get('time_range'), '7d');
});

test('export downloads every article matching the filters (all pages), not just the 50 on screen', async () => {
  const mk = (n) => Array.from({ length: n }, (_, i) => ({ id: i + 1, title: `T${i}`, url: `https://e/${i}`, severity: 'high',
    category: 'malware', is_patched: -1, has_poc: 0, reviews: '[{"user_id":null}]', url_hash: 'h', title_key: 'k', notified: 0 }));
  const all = mk(250);
  const b = createBrowser({ routes: baseRoutes({
    'GET /api/auth/me': { success: true, user: ALICE },
    'GET /api/articles': (r) => {
      const q = new URL('http://x' + r.url).searchParams;
      const limit = +q.get('limit'), page = +q.get('page');
      return { articles: all.slice((page - 1) * limit, page * limit), total: all.length, page, totalPages: Math.ceil(all.length / limit) };
    },
  }) });
  await b.settle();
  await b.el('export-btn').fire('click'); await b.settle();
  const pages = b.requests.filter(r => r.url.startsWith('/api/articles?') && r.url.includes('limit=200'));
  assert.equal(pages.length, 2);
  const payload = JSON.parse(b.sandbox._lastBlob.parts[0]);
  assert.equal(payload.count, 250);
  assert.equal(payload.total_matching, 250);
  assert.equal(payload.articles.length, 250);
  assert.ok(!('url_hash' in payload.articles[0]), 'internal fields dropped');
  assert.deepEqual(payload.articles[0].reviews, []);
  assert.equal(b.downloads().length, 1);
});

test('adding a source tells the user it is being fetched now', async () => {
  const b = createBrowser({ routes: baseRoutes({
    'GET /api/auth/me': { success: true, user: ALICE },
    'POST /api/sources': { status: 201, body: { success: true, id: 7, fetching: true } },
  }) });
  await b.settle();
  b.el('source-url').value = 'https://feeds.example.org/rss';
  b.el('source-name').value = 'Mine';
  b.el('source-type').value = 'website';
  b.el('source-category').value = 'general';
  await b.el('add-source-form').fire('submit'); await b.settle();
  assert.deepEqual(b.req('POST', '/api/sources')[0].body, { url: 'https://feeds.example.org/rss', name: 'Mine', type: 'website', category: 'general' });
  assert.ok(b.toastTexts().some(t => /being fetched now/.test(t)));
});

// ---------------------------------------------------------------------------
// Guest
// ---------------------------------------------------------------------------
test('guest UI: account-only controls hidden; sign in from guest switches to the user', async () => {
  const b = createBrowser({ routes: baseRoutes({ 'POST /api/auth/login': { success: true, user: ALICE } }) });
  await b.settle();
  assert.equal(b.sandbox.document.body.classList.contains('guest-mode'), true);
  for (const id of ['change-email-btn', 'change-password-btn', 'logout-btn']) assert.ok(b.el(id).classList.contains('hidden'), id);
  assert.ok(!b.el('sign-in-btn').classList.contains('hidden'));
  await b.el('sign-in-btn').fire('click');
  assert.ok(b.visible('auth-overlay'));
  await signIn(b, 'alice', 'Passw0rdA');
  assert.equal(b.sandbox.document.body.classList.contains('guest-mode'), false);
  assert.ok(!b.visible('auth-overlay'));
  assert.ok(!b.el('logout-btn').classList.contains('hidden'));
});

// ---------------------------------------------------------------------------
// Admin panel: password resets tab
// ---------------------------------------------------------------------------
test('admin panel lists pending password resets with a copyable link', async () => {
  const b = createBrowser({ html: 'admin.html', script: 'js/admin.js', routes: {
    'GET /api/auth/me': { success: true, user: ADMIN },
    'GET /api/admin/stats': { totalUsers: 2, totalSourcesAll: 3, totalArticles: 4, errorsToday: 0 },
    'GET /api/admin/users': { users: [] },
    'GET /api/admin/invite-codes': { codes: [] },
    'GET /api/admin/sources': { sources: [] },
    'GET /api/admin/audit-log': { log: [] },
    'GET /api/admin/ai-settings': { groq_set: false, tavily_set: false },
    'GET /api/admin/reset-tokens': { tokens: [{ id: 1, user_id: 5, username: 'erin', email: 'erin@example.test', token: 'abc123',
      created_at: '2026-11-22 10:00:00', expires_at: '2026-11-22 11:00:00' }] },
  } });
  await b.settle();
  const html = b.el('resets-tbody').innerHTML;
  assert.match(html, /erin@example\.test/);
  assert.match(html, /data-copy="https:\/\/tp\.test\/\?reset=abc123"/);
});

// ---------------------------------------------------------------------------
// Article cards: threat actor + each MITRE ID tied to its tactic and procedure
// ---------------------------------------------------------------------------
test('cards show the threat actor and every MITRE ID linked to its TTP, with a 3D attack path button', async () => {
  const art = {
    id: 42, title: 'APT28 phishing <b>x</b>', url: 'https://news.example/a', source_name: 'Src', severity: 'high', category: 'threat_intel',
    published_date: new Date().toISOString(), threat_actors: 'APT28',
    ttps: [
      { id: 'T1566', subId: null, name: 'Phishing', tactic: 'TA0001', tacticName: 'Initial Access', how: 'cited', procedure: 'Emails with <script>alert(1)</script> lures.', url: 'https://attack.mitre.org/techniques/T1566/' },
      { id: 'T1059', subId: null, name: 'Command and Scripting Interpreter', tactic: 'TA0002', tacticName: 'Execution', how: 'inferred', procedure: 'PowerShell ran.' },
    ],
  };
  const b = createBrowser({ routes: baseRoutes({
    'GET /api/auth/me': { success: true, user: ALICE },
    'GET /api/articles': { articles: [art], total: 1, page: 1, totalPages: 1 },
  }) });
  await b.settle();
  const html = b.el('articles-container').innerHTML;
  assert.match(html, /class="ti-panel"/);
  assert.match(html, /data-filter-actor="APT28"/);
  assert.match(html, /<span class="ti-tactic">Initial Access<\/span><a class="ti-id" href="https:\/\/attack\.mitre\.org\/techniques\/T1566\/?"/);
  assert.match(html, /ti-cited/);
  assert.match(html, /ti-inferred/);
  assert.match(html, /data-attack-path="42"/);
  assert.match(html, /2 TTPs · 2\/14 tactics/);
  assert.ok(!html.includes('<script>alert(1)'), 'procedure text is escaped');
});

test('one "AI analysis" button: shows progress, then summary/priority, and merges ATT&CK into the box (not listed twice)', async () => {
  const art = { id: 9, title: 'Clinic breach', url: 'https://news.example/c', source_name: 'Src', severity: 'high', category: 'threat_intel',
    published_date: new Date().toISOString(), ttps: [] };
  const b = createBrowser({ routes: baseRoutes({
    'GET /api/auth/me': { success: true, user: ALICE },
    'GET /api/articles': { articles: [art], total: 1, page: 1, totalPages: 1 },
    'POST /api/ai/analyze': { success: true, summary: { summary: 'Staff were phished.', keyTakeaway: 'Block ISO.', affectedTech: [] },
      triage: { priority: 'high', relevance: 80, reason: 'Active.' }, aiMapped: true, addedTtps: ['T1566.001'], actors: [],
      ttps: [{ id: 'T1566', subId: 'T1566.001', name: 'Spearphishing Attachment', tactic: 'TA0001', tacticName: 'Initial Access', how: 'ai', procedure: 'sent spearphishing emails' }] },
  }) });
  await b.settle();
  let html = b.el('articles-container').innerHTML;
  assert.ok(!html.includes('ti-panel'), 'no empty ATT&CK box');
  assert.equal((html.match(/data-ai-analyze=/g) || []).length, 1, 'exactly one AI button');
  assert.ok(!html.includes('data-ai-summarize') && !html.includes('data-ai-ttps'));
  await b.fireDoc('click', { id: '', classList: { contains: () => false }, closest: (sel) => sel.includes('data-ai-analyze') ? { dataset: { aiAnalyze: '9' } } : null });
  await b.settle();
  html = b.el('articles-container').innerHTML;
  assert.match(html, /Staff were phished\./);
  assert.match(html, /ai-an-pri-high/);
  assert.match(html, /class="ti-panel"/, 'ATT&CK box now present');
  assert.equal((html.match(/T1566\.001/g) || []).length >= 2, true);
  assert.equal((html.match(/Spearphishing Attachment/g) || []).length, 1, 'technique name shown once (in the box only)');
});

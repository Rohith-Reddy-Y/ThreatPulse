/**
 * Email delivery and account emails: Brevo HTTPS transport (Render's free tier
 * blocks SMTP), invite-only registration by default, and the reset / change /
 * notice emails every account gets.  Run with: sh tests/run-all.sh
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const h = require('./helpers');
const { db, auth, request, createUser } = h;
const axios = require('axios');           // tests/stubs/modules/axios
const mailer = require('../src/notifications/mailer');
const templates = require('../src/notifications/account-emails');

const PW = 'Passw0rdA';
const PW2 = 'Passw0rdB';
let ipSeq = 0;
const ip = () => `203.0.113.${++ipSeq}`;
const csrf = (jar) => ({ 'x-csrf-token': jar.tp_csrf });
const tick = () => new Promise((r) => setImmediate(r));
const settle = async () => { for (let i = 0; i < 5; i++) await tick(); };

// Route every Brevo call into `sent`; `fail` makes the API answer with an error.
function withBrevo(fn, { fail } = {}) {
  const keep = { BREVO_API_KEY: process.env.BREVO_API_KEY, MAIL_FROM: process.env.MAIL_FROM, BASE_URL: process.env.BASE_URL };
  Object.assign(process.env, { BREVO_API_KEY: 'xkeysib-test', MAIL_FROM: 'alerts@example.test', BASE_URL: 'https://tp.example.test' });
  const realPost = axios.post;
  const sent = [];
  axios.post = async (url, body, opts) => {
    if (fail) { const e = new Error('Request failed'); e.response = fail; throw e; }
    sent.push({ url, body, headers: (opts || {}).headers || {} });
    return { data: { messageId: `<m${sent.length}@brevo>` } };
  };
  const restore = () => {
    axios.post = realPost;
    for (const [k, v] of Object.entries(keep)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  };
  return Promise.resolve().then(() => fn(sent)).finally(restore);
}

test('mailer: Brevo is used when BREVO_API_KEY + MAIL_FROM are set; nothing is configured otherwise', async () => {
  assert.strictEqual(mailer.isConfigured(), false);
  const none = await mailer.sendMail({ to: 'a@example.test', subject: 's', html: '<p>x</p>' });
  assert.strictEqual(none.success, false);

  await withBrevo(async (sent) => {
    assert.strictEqual(mailer.provider(), 'brevo');
    const r = await mailer.sendMail({ to: ' user@example.test ', subject: 'Hi\r\nBcc: evil@x.test', html: '<p>x</p>', text: 'x' });
    assert.strictEqual(r.success, true, JSON.stringify(r));
    assert.strictEqual(sent.length, 1);
    const m = sent[0];
    assert.strictEqual(m.url, 'https://api.brevo.com/v3/smtp/email');
    assert.strictEqual(m.headers['api-key'], 'xkeysib-test');
    assert.deepStrictEqual(m.body.sender, { name: 'ThreatPulse', email: 'alerts@example.test' });
    assert.deepStrictEqual(m.body.to, [{ email: 'user@example.test' }]);
    assert.ok(!/[\r\n]/.test(m.body.subject), 'header injection through the subject');
    assert.strictEqual(m.body.textContent, 'x');
    // one recipient only — lists / header tricks are refused
    assert.strictEqual((await mailer.sendMail({ to: 'a@x.test, b@x.test', subject: 's', html: 'x' })).success, false);
    assert.strictEqual(sent.length, 1);
  });

  // MAIL_FROM missing or invalid -> not configured, and the admin is told why
  process.env.BREVO_API_KEY = 'k';
  try {
    assert.strictEqual(mailer.isConfigured(), false);
    assert.match(mailer.describe().problem, /MAIL_FROM/);
  } finally { delete process.env.BREVO_API_KEY; }
});

test('mailer: Brevo errors become actionable messages and never throw', async () => {
  await withBrevo(async () => {
    const r = await mailer.sendMail({ to: 'u@example.test', subject: 's', html: 'x' });
    assert.strictEqual(r.success, false);
    assert.match(r.error, /401/);
    assert.match(r.error, /Authorised IPs/);
  }, { fail: { status: 401, data: { code: 'unauthorized', message: 'We have detected you are using an unrecognised IP address' } } });
  await withBrevo(async () => {
    const r = await mailer.sendMail({ to: 'u@example.test', subject: 's', html: 'x' });
    assert.match(r.error, /MAIL_FROM must be a sender verified/);
  }, { fail: { status: 400, data: { code: 'invalid_parameter', message: 'sender is not valid' } } });
});

test('registration is invite-only unless REQUIRE_INVITE_CODE=false', async () => {
  const keep = process.env.REQUIRE_INVITE_CODE;
  delete process.env.REQUIRE_INVITE_CODE;           // the production default
  try {
    assert.strictEqual(auth.inviteRequired(), true);
    assert.strictEqual((await request('GET', '/api/auth/config')).body.requireInvite, true);
    const base = { displayName: 'New Person', password: PW };
    const none = await request('POST', '/api/auth/register', { ip: ip(), body: { ...base, username: 'noinvite', email: 'noinvite@example.test' } });
    assert.strictEqual(none.body.success, false);
    assert.strictEqual(db.getUserByUsername('noinvite'), undefined);
    const bogus = await request('POST', '/api/auth/register', { ip: ip(), body: { ...base, username: 'bogus', email: 'bogus@example.test', inviteCode: 'NOTREAL1' } });
    assert.strictEqual(bogus.body.success, false);

    const admin = db.getUserByUsername('admin') || db.getUserById(createUser('admin_for_invites', PW, { role: 'admin' }));
    db.createInviteCode(admin.id, 'EMAIL123');
    const ok = await request('POST', '/api/auth/register', { ip: ip(), body: { ...base, username: 'invited', email: 'invited@example.test', inviteCode: 'email123' } });
    assert.strictEqual(ok.body.success, true, JSON.stringify(ok.body));
    for (const v of ['TRUE', 'yes', '1', '']) { process.env.REQUIRE_INVITE_CODE = v; assert.strictEqual(auth.inviteRequired(), true, v); }
    process.env.REQUIRE_INVITE_CODE = ' False ';
    assert.strictEqual(auth.inviteRequired(), false);
  } finally { process.env.REQUIRE_INVITE_CODE = keep; }
});

test('forgot password emails a one-time reset link built from BASE_URL; unknown addresses get the same answer', async () => {
  createUser('forgetful', PW, { email: 'forgetful@example.test' });
  await withBrevo(async (sent) => {
    const r = await request('POST', '/api/auth/forgot-password', { ip: ip(), headers: { host: 'evil.example' }, body: { email: 'FORGETFUL@example.test' } });
    const unknown = await request('POST', '/api/auth/forgot-password', { ip: ip(), body: { email: 'nobody@example.test' } });
    await settle();
    assert.strictEqual(r.body.success, true);
    assert.strictEqual(r.body.message, unknown.body.message, 'no account enumeration');
    assert.strictEqual(r.body.emailDelivery, true);
    assert.ok(!JSON.stringify(r.body).includes('reset='), 'link never in the response');
    assert.strictEqual(sent.length, 1, 'only the real account gets mail');
    const mail = sent[0].body;
    assert.deepStrictEqual(mail.to, [{ email: 'forgetful@example.test' }]);
    assert.match(mail.subject, /Reset your ThreatPulse password/);
    const link = mail.htmlContent.match(/https:\/\/tp\.example\.test\/\?reset=([0-9a-f]{64})/);
    assert.ok(link, 'link uses BASE_URL, not the Host header');
    assert.ok(!mail.htmlContent.includes('evil.example'));
    assert.ok(mail.textContent.includes(link[0]), 'plain-text part carries the link too');

    // Using the link changes the password and sends a "password changed" notice
    const reset = await request('POST', '/api/auth/reset-password', { ip: ip(), body: { token: link[1], newPassword: PW2 } });
    await settle();
    assert.strictEqual(reset.body.success, true, JSON.stringify(reset.body));
    assert.ok(!('_userId' in reset.body), 'internal fields stay internal');
    assert.strictEqual(sent.length, 2);
    assert.match(sent[1].body.subject, /password was changed/);
    assert.match(sent[1].body.htmlContent, /password reset link/);
    // single use
    const again = await request('POST', '/api/auth/reset-password', { ip: ip(), body: { token: link[1], newPassword: 'Passw0rdC' } });
    assert.strictEqual(again.body.success, false);
  });
});

test('password change: code by email, then a "password changed" notice; forced first change sends only the notice', async () => {
  createUser('changer', PW, { email: 'changer@example.test' });
  let jar = await h.login('changer', PW, ip());
  await withBrevo(async (sent) => {
    const start = await request('PUT', '/api/auth/password', { cookies: jar, headers: csrf(jar), body: { currentPassword: PW, newPassword: PW2 } });
    assert.strictEqual(start.body.verificationRequired, true, JSON.stringify(start.body));
    assert.strictEqual(sent.length, 1);
    const code = sent[0].body.subject.match(/^(\d{6}) is your ThreatPulse password change code$/);
    assert.ok(code, sent[0].body.subject);
    assert.ok(sent[0].body.htmlContent.includes(code[1]));
    const done = await request('POST', '/api/auth/verify-change', { cookies: jar, headers: csrf(jar), body: { type: 'password_change', code: code[1] } });
    await settle();
    assert.strictEqual(done.body.success, true, JSON.stringify(done.body));
    assert.strictEqual(sent.length, 2);
    assert.match(sent[1].body.subject, /password was changed/);
    assert.deepStrictEqual(sent[1].body.to, [{ email: 'changer@example.test' }]);
  });

  createUser('firsttimer', PW, { email: 'first@example.test', mustChange: true });
  jar = await h.login('firsttimer', PW, ip());
  await withBrevo(async (sent) => {
    const r = await request('PUT', '/api/auth/password', { cookies: jar, headers: csrf(jar), body: { currentPassword: PW, newPassword: PW2 } });
    await settle();
    assert.strictEqual(r.body.verificationRequired, false);
    assert.strictEqual(sent.length, 1);
    assert.match(sent[0].body.htmlContent, /during first sign-in/);
  });
});

test('email change: code to the new address, then confirmation to the new one and a warning to the old one', async () => {
  createUser('mover2', PW, { email: 'old@example.test' });
  const jar = await h.login('mover2', PW, ip());
  await withBrevo(async (sent) => {
    const r = await request('PUT', '/api/auth/email', { cookies: jar, headers: csrf(jar), body: { email: 'new@example.test', currentPassword: PW } });
    assert.strictEqual(r.body.verificationRequired, true, JSON.stringify(r.body));
    assert.deepStrictEqual(sent[0].body.to, [{ email: 'new@example.test' }]);
    const code = sent[0].body.subject.match(/^(\d{6}) /)[1];
    const v = await request('POST', '/api/auth/verify-change', { cookies: jar, headers: csrf(jar), body: { type: 'email_change', code } });
    await settle();
    assert.strictEqual(v.body.success, true);
    const to = sent.slice(1).map((m) => m.body.to[0].email).sort();
    assert.deepStrictEqual(to, ['new@example.test', 'old@example.test']);
    const warn = sent.find((m) => m.body.to[0].email === 'old@example.test').body;
    assert.match(warn.subject, /was changed/);
    assert.match(warn.htmlContent, /If this wasn&#39;t you|If this wasn't you/);
  });
});

test('new accounts get a welcome email when delivery is configured', async () => {
  await withBrevo(async (sent) => {
    const r = await request('POST', '/api/auth/register', { ip: ip(), body: { username: 'welcomed', displayName: 'Wel Come', email: 'welcome@example.test', password: PW } });
    await settle();
    assert.strictEqual(r.body.success, true, JSON.stringify(r.body));
    assert.strictEqual(sent.length, 1);
    assert.match(sent[0].body.subject, /Welcome to ThreatPulse/);
  });
});

test('templates escape user-controlled names everywhere', () => {
  const evil = '<img src=x onerror=alert(1)>"\'';
  for (const t of [
    templates.passwordReset({ name: evil, link: 'https://tp.example/?reset=ab', ip: '1.2.3.4' }),
    templates.verificationCode({ name: evil, type: 'email_change', code: '123456' }),
    templates.passwordChanged({ name: evil, method: 'change', ip: '<b>', link: 'https://tp.example' }),
    templates.emailChanged({ name: evil, oldEmail: 'a@x.test', newEmail: '<x>@y.test', toOld: true }),
    templates.welcome({ name: evil, username: '<u>', link: 'https://tp.example' }),
  ]) {
    assert.ok(!t.html.includes('<img src=x'), t.subject);
    assert.ok(!t.html.includes('<b>') && !t.html.includes('<u>') && !t.html.includes('<x>'), t.subject);
    assert.ok(!t.text.includes('<img'), t.subject);
    assert.ok(t.subject && t.text.length > 20);
  }
});

test('admin email panel: status shows the provider without secrets; test goes only to the admin\'s own address', async () => {
  const adminId = createUser(`mailadmin_${Date.now()}`, PW, { role: 'admin', email: 'boss@example.test' });
  const jar = await h.login(db.getUserById(adminId).username, PW, ip());
  const off = await request('GET', '/api/admin/email-status', { cookies: jar });
  assert.strictEqual(off.body.configured, false);
  const noCfg = await request('POST', '/api/admin/email-test', { cookies: jar, headers: csrf(jar), body: { to: 'victim@example.test' } });
  assert.strictEqual(noCfg.status, 400);
  await withBrevo(async (sent) => {
    const st = await request('GET', '/api/admin/email-status', { cookies: jar });
    assert.strictEqual(st.body.provider, 'brevo');
    assert.strictEqual(st.body.from, 'alerts@example.test');
    assert.ok(!JSON.stringify(st.body).includes('xkeysib'), 'API key never leaves the server');
    const r = await request('POST', '/api/admin/email-test', { cookies: jar, headers: csrf(jar), body: { to: 'victim@example.test' } });
    assert.strictEqual(r.body.success, true, JSON.stringify(r.body));
    assert.deepStrictEqual(sent.map((m) => m.body.to[0].email), ['boss@example.test'], 'body.to is ignored');
  });
  const analyst = await h.login((() => { const id = createUser(`plainuser_${Date.now()}`, PW); return db.getUserById(id).username; })(), PW, ip());
  assert.strictEqual((await request('GET', '/api/admin/email-status', { cookies: analyst })).status, 403);
});

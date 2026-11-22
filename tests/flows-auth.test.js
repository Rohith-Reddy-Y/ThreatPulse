/**
 * End-to-end account journeys at the API level (real handlers, real SQLite):
 * first run + forced password change, sign-in by username / email in any case,
 * invite-only registration, forgot/reset without SMTP, email and password
 * changes with and without SMTP.  Run with: sh tests/run-all.sh
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const h = require('./helpers');
const { db, auth, request, absorb, createUser } = h;
const nodemailer = require('nodemailer'); // the stub in tests/stubs/modules

const PW = 'Passw0rdA';
const PW2 = 'Passw0rdB';
let ipSeq = 0;
const ip = () => `198.51.100.${++ipSeq}`;
const csrf = (jar) => ({ 'x-csrf-token': jar.tp_csrf });

async function loginRaw(username, password, from = ip()) {
  return request('POST', '/api/auth/login', { body: { username, password }, ip: from });
}

function withSmtp(fn, { failSend = false } = {}) {
  const env = { SMTP_HOST: process.env.SMTP_HOST, SMTP_USER: process.env.SMTP_USER, SMTP_PASS: process.env.SMTP_PASS };
  // a fresh user name forces email-notifier to build a new transporter
  Object.assign(process.env, { SMTP_HOST: 'smtp.example.test', SMTP_USER: `u${Math.random()}`, SMTP_PASS: 'p' });
  const realCreate = nodemailer.createTransport;
  const sent = [];
  nodemailer.createTransport = () => ({
    sendMail: async (m) => { if (failSend) throw new Error('550 mailbox unavailable'); sent.push(m); return { messageId: 'x' }; },
  });
  const restore = () => {
    nodemailer.createTransport = realCreate;
    for (const [k, v] of Object.entries(env)) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
  };
  return Promise.resolve().then(() => fn(sent)).finally(restore);
}

// ---------------------------------------------------------------------------
// First run: admin creation → forced change → re-login → logout → login
// ---------------------------------------------------------------------------
test('first run: initial admin password, forced change with the sign-in password, re-login with the new one', async () => {
  process.env.ADMIN_INITIAL_PASSWORD = 'Init1alPassw0rd';
  await auth.ensureAdminExists();
  const admin = db.getUserByUsername('admin');
  assert.ok(admin, 'admin created');
  assert.strictEqual(admin.must_change_password, 1);

  // Sign in: the UI keeps this password (forcedChangeSecret) for the change
  const r = await loginRaw('admin', 'Init1alPassw0rd');
  assert.strictEqual(r.body.success, true, JSON.stringify(r.body));
  assert.strictEqual(r.body.user.mustChangePassword, true);
  const jar = absorb({}, r.res);

  // Everything except me/password/logout is blocked until the change
  const blocked = await request('GET', '/api/articles/stats', { cookies: jar });
  assert.strictEqual(blocked.status, 403);
  assert.strictEqual(blocked.body.mustChangePassword, true);

  // Token refresh mid-change keeps the flag (the UI re-shows the modal)
  const ref = await request('POST', '/api/auth/refresh', { cookies: jar });
  assert.strictEqual(ref.body.user.mustChangePassword, true);
  absorb(jar, ref.res);

  // Page reload mid-change: /auth/me still reports the flag
  const me = await request('GET', '/api/auth/me', { cookies: jar });
  assert.strictEqual(me.body.user.mustChangePassword, true);

  // Same password as new → refused with a clear message
  const same = await request('PUT', '/api/auth/password', { cookies: jar, headers: csrf(jar),
    body: { currentPassword: 'Init1alPassw0rd', newPassword: 'Init1alPassw0rd' } });
  assert.strictEqual(same.status, 400);
  assert.match(same.body.error, /different/);

  const change = await request('PUT', '/api/auth/password', { cookies: jar, headers: csrf(jar),
    body: { currentPassword: 'Init1alPassw0rd', newPassword: PW } });
  assert.strictEqual(change.body.success, true, JSON.stringify(change.body));
  assert.strictEqual(change.body.verificationRequired, false);
  assert.strictEqual((await request('GET', '/api/articles/stats', { cookies: jar })).status, 200);

  // Logout, then the old password fails and the new one works
  const out = await request('POST', '/api/auth/logout', { cookies: jar });
  assert.strictEqual(out.body.success, true);
  assert.strictEqual((await loginRaw('admin', 'Init1alPassw0rd')).body.success, false);
  const again = await loginRaw('admin', PW);
  assert.strictEqual(again.body.success, true);
  assert.strictEqual(again.body.user.mustChangePassword, false);
});

test('ADMIN_FORCE_PASSWORD_CHANGE=false keeps a chosen initial password without a forced change', async () => {
  db.getDb().prepare("DELETE FROM invite_codes").run();
  db.getDb().prepare("DELETE FROM notification_settings").run();
  db.getDb().prepare("DELETE FROM audit_log").run();
  db.getDb().prepare("DELETE FROM users").run();
  process.env.ADMIN_INITIAL_PASSWORD = 'Ch0senAdminPw';
  process.env.ADMIN_FORCE_PASSWORD_CHANGE = 'false';
  try {
    await auth.ensureAdminExists();
  } finally { delete process.env.ADMIN_FORCE_PASSWORD_CHANGE; }
  const r = await loginRaw('admin', 'Ch0senAdminPw');
  assert.strictEqual(r.body.success, true);
  assert.strictEqual(r.body.user.mustChangePassword, false);
});

// ---------------------------------------------------------------------------
// "Correct password shows wrong": case of the username / email
// ---------------------------------------------------------------------------
test('sign-in by username is case-insensitive (the password stays case-sensitive)', async () => {
  createUser('Alice', PW, { email: 'alice@example.test' });
  for (const name of ['Alice', 'alice', 'ALICE', '  alice  ']) {
    const r = await loginRaw(name, PW);
    assert.strictEqual(r.body.success, true, `login as ${JSON.stringify(name)}: ${JSON.stringify(r.body)}`);
    assert.strictEqual(r.body.user.username, 'Alice');
  }
  assert.strictEqual((await loginRaw('alice', PW.toLowerCase())).body.success, false);
});

test('sign-in by email is case-insensitive', async () => {
  const id = createUser('bob', PW, { email: 'Bob.Smith@Example.test' });
  for (const e of ['Bob.Smith@Example.test', 'bob.smith@example.test', 'BOB.SMITH@EXAMPLE.TEST']) {
    const r = await loginRaw(e, PW);
    assert.strictEqual(r.body.success, true, `login as ${e}: ${JSON.stringify(r.body)}`);
    assert.strictEqual(r.body.user.id, id);
  }
});

test('registration refuses usernames / emails that differ only by case', async () => {
  createUser('Carol', PW, { email: 'carol@example.test' });
  const dupName = await request('POST', '/api/auth/register', { ip: ip(),
    body: { username: 'carol', displayName: 'Carol 2', password: PW, email: 'other@example.test' } });
  assert.strictEqual(dupName.body.success, false);
  assert.match(dupName.body.error, /taken/);
  const dupMail = await request('POST', '/api/auth/register', { ip: ip(),
    body: { username: 'carol2', displayName: 'Carol 2', password: PW, email: 'CAROL@example.test' } });
  assert.strictEqual(dupMail.body.success, false);
  assert.match(dupMail.body.error, /Email already registered/);
});

test('wrong password and lockout messages; another IP is not locked', async () => {
  createUser('dave', PW);
  const from = ip();
  for (let i = 0; i < 4; i++) {
    const r = await loginRaw('dave', 'Wrong1234', from);
    assert.strictEqual(r.body.error, 'Invalid username/email or password');
  }
  const locked = await loginRaw('dave', 'Wrong1234', from);
  assert.strictEqual(locked.body.locked, true);
  assert.match(locked.body.error, /Too many failed login attempts/);
  // Even the right password is refused from the locked IP (with the lockout text, not "wrong password")
  const right = await loginRaw('DAVE', PW, from);
  assert.strictEqual(right.body.success, false);
  assert.strictEqual(right.body.locked, true);
  assert.strictEqual((await loginRaw('dave', PW, ip())).body.success, true);
});

// ---------------------------------------------------------------------------
// Public config: invite field, email capability, fresh-DB notice
// ---------------------------------------------------------------------------
test('/auth/config tells the sign-in page about invites, email and a freshly created DB', async () => {
  const c = await request('GET', '/api/auth/config');
  assert.strictEqual(c.status, 200);
  assert.strictEqual(c.body.requireInvite, false);
  assert.strictEqual(c.body.emailEnabled, false);
  assert.ok(c.body.dbCreatedAt && !isNaN(new Date(c.body.dbCreatedAt)), 'test DB was created by this process');
  process.env.REQUIRE_INVITE_CODE = 'true';
  try {
    assert.strictEqual((await request('GET', '/api/auth/config')).body.requireInvite, true);
  } finally { delete process.env.REQUIRE_INVITE_CODE; }
});

test('invite-only registration: code required, accepted in lower case, single use', async () => {
  const admin = db.getUserByUsername('admin');
  db.createInviteCode(admin.id, 'ABCD1234');
  process.env.REQUIRE_INVITE_CODE = 'true';
  try {
    const base = { displayName: 'Invitee', password: PW };
    const none = await request('POST', '/api/auth/register', { ip: ip(), body: { ...base, username: 'inv0', email: 'inv0@example.test' } });
    assert.strictEqual(none.body.success, false);
    assert.match(none.body.error, /Invite code is required/);
    const ok = await request('POST', '/api/auth/register', { ip: ip(),
      body: { ...base, username: 'inv1', email: 'inv1@example.test', inviteCode: ' abcd1234 ' } });
    assert.strictEqual(ok.body.success, true, JSON.stringify(ok.body));
    const reuse = await request('POST', '/api/auth/register', { ip: ip(),
      body: { ...base, username: 'inv2', email: 'inv2@example.test', inviteCode: 'ABCD1234' } });
    assert.strictEqual(reuse.body.success, false);
    assert.match(reuse.body.error, /already used/);
  } finally { delete process.env.REQUIRE_INVITE_CODE; }
  // Open registration ignores the code entirely
  const open = await request('POST', '/api/auth/register', { ip: ip(),
    body: { username: 'open1', displayName: 'Open', password: PW, email: 'open1@example.test', inviteCode: 'whatever' } });
  assert.strictEqual(open.body.success, true);
});

// ---------------------------------------------------------------------------
// Forgot / reset password without SMTP
// ---------------------------------------------------------------------------
test('forgot password without SMTP says so (same text for unknown emails); admin sees the link; reset works', async () => {
  const id = createUser('erin', PW, { email: 'Erin@example.test' });
  const known = await request('POST', '/api/auth/forgot-password', { ip: ip(), body: { email: 'erin@EXAMPLE.test' } });
  const unknown = await request('POST', '/api/auth/forgot-password', { ip: ip(), body: { email: 'nobody@example.test' } });
  assert.strictEqual(known.body.success, true);
  assert.strictEqual(known.body.message, unknown.body.message, 'no account enumeration');
  assert.match(known.body.message, /cannot send email/);
  assert.strictEqual(known.body.emailDelivery, false);
  assert.ok(!JSON.stringify(known.body).includes('reset='), 'link never in the response');

  const adminJar = await h.login('admin', 'Ch0senAdminPw', ip());
  const tokens = await request('GET', '/api/admin/reset-tokens', { cookies: adminJar });
  const row = tokens.body.tokens.find(t => t.user_id === id);
  assert.ok(row, 'case-insensitive email lookup created the token; admin can see it');

  const reset = await request('POST', '/api/auth/reset-password', { ip: ip(), body: { token: row.token, newPassword: PW2 } });
  assert.strictEqual(reset.body.success, true);
  assert.strictEqual((await loginRaw('erin', PW2)).body.success, true);
});

test('forgot password with SMTP keeps the "link has been sent" message', async () => {
  createUser('frank', PW, { email: 'frank@example.test' });
  await withSmtp(async (sent) => {
    const r = await request('POST', '/api/auth/forgot-password', { ip: ip(), body: { email: 'frank@example.test' } });
    assert.match(r.body.message, /reset link has been sent/);
    assert.strictEqual(r.body.emailDelivery, true);
    assert.strictEqual(sent.length, 1);
  });
});

// ---------------------------------------------------------------------------
// Email change / password change with and without SMTP
// ---------------------------------------------------------------------------
test('email change without SMTP is applied directly (a code could never arrive)', async () => {
  const id = createUser('gina', PW, { email: 'gina@example.test' });
  const jar = await h.login('gina', PW, ip());
  const r = await request('PUT', '/api/auth/email', { cookies: jar, headers: csrf(jar), body: { email: 'gina.new@example.test' } });
  assert.strictEqual(r.body.success, true, JSON.stringify(r.body));
  assert.strictEqual(r.body.verificationRequired, false);
  assert.strictEqual(db.getUserById(id).email, 'gina.new@example.test');
  const taken = await request('PUT', '/api/auth/email', { cookies: jar, headers: csrf(jar), body: { email: 'ERIN@example.test' } });
  assert.strictEqual(taken.status, 409, 'duplicate check is case-insensitive');
});

test('email change with SMTP sends a code; a failed send is reported instead of a phantom code', async () => {
  const id = createUser('hank', PW, { email: 'hank@example.test' });
  const jar = await h.login('hank', PW, ip());
  await withSmtp(async (sent) => {
    const r = await request('PUT', '/api/auth/email', { cookies: jar, headers: csrf(jar), body: { email: 'hank2@example.test' } });
    assert.strictEqual(r.body.verificationRequired, true);
    assert.strictEqual(sent.length, 1);
    const code = db.getDb().prepare("SELECT code FROM verification_codes WHERE user_id = ? AND type = 'email_change'").get(id).code;
    const v = await request('POST', '/api/auth/verify-change', { cookies: jar, headers: csrf(jar), body: { type: 'email_change', code } });
    assert.strictEqual(v.body.success, true);
    assert.strictEqual(db.getUserById(id).email, 'hank2@example.test');
  });
  await withSmtp(async () => {
    const r = await request('PUT', '/api/auth/email', { cookies: jar, headers: csrf(jar), body: { email: 'hank3@example.test' } });
    assert.strictEqual(r.status, 502);
    assert.strictEqual(r.body.success, false);
    assert.match(r.body.error, /Could not send/);
    assert.strictEqual(db.getDb().prepare('SELECT COUNT(*) c FROM verification_codes WHERE user_id = ?').get(id).c, 0);
  }, { failSend: true });
});

test('normal password change: direct without SMTP, code with SMTP, clear error when the code email fails', async () => {
  createUser('ivy', PW, { email: 'ivy@example.test' });
  let jar = await h.login('ivy', PW, ip());
  const wrong = await request('PUT', '/api/auth/password', { cookies: jar, headers: csrf(jar), body: { currentPassword: 'Nope12345', newPassword: PW2 } });
  assert.strictEqual(wrong.status, 400);
  assert.strictEqual(wrong.body.error, 'Current password is incorrect');

  const direct = await request('PUT', '/api/auth/password', { cookies: jar, headers: csrf(jar), body: { currentPassword: PW, newPassword: PW2 } });
  assert.strictEqual(direct.body.success, true);
  assert.strictEqual(direct.body.verificationRequired, false);

  await withSmtp(async (sent) => {
    const r = await request('PUT', '/api/auth/password', { cookies: jar, headers: csrf(jar), body: { currentPassword: PW2, newPassword: PW } });
    assert.strictEqual(r.body.verificationRequired, true);
    assert.strictEqual(sent.length, 1);
    const code = db.getDb().prepare("SELECT code FROM verification_codes WHERE type = 'password_change' ORDER BY id DESC").get().code;
    const v = await request('POST', '/api/auth/verify-change', { cookies: jar, headers: csrf(jar), body: { type: 'password_change', code } });
    assert.strictEqual(v.body.success, true);
  });
  assert.strictEqual((await loginRaw('ivy', PW)).body.success, true);

  await withSmtp(async () => {
    const r = await request('PUT', '/api/auth/password', { cookies: jar, headers: csrf(jar), body: { currentPassword: PW, newPassword: PW2 } });
    assert.strictEqual(r.status, 502);
    assert.match(r.body.error, /Could not send/);
  }, { failSend: true });
  assert.strictEqual((await loginRaw('ivy', PW)).body.success, true, 'password unchanged after the failed send');
});

// ---------------------------------------------------------------------------
// Guest → register keeps working; guests can't change account state
// ---------------------------------------------------------------------------
test('guest session, then register from it; guest cannot change password/email/sources', async () => {
  const g = await request('POST', '/api/auth/guest', { ip: ip() });
  assert.strictEqual(g.body.success, true);
  const gjar = absorb({}, g.res);
  for (const [m, u, body] of [['PUT', '/api/auth/password', { currentPassword: 'x', newPassword: PW }],
    ['PUT', '/api/auth/email', { email: 'g@example.test' }], ['POST', '/api/sources', { url: 'https://ex.com/f', name: 'F' }]]) {
    const r = await request(m, u, { cookies: gjar, body });
    assert.strictEqual(r.status, 403, `${m} ${u}`);
  }
  const reg = await request('POST', '/api/auth/register', { cookies: gjar, ip: ip(),
    body: { username: 'fromguest', displayName: 'From Guest', password: PW, email: 'fromguest@example.test' } });
  assert.strictEqual(reg.body.success, true);
  const jar = absorb(gjar, reg.res);
  const me = await request('GET', '/api/auth/me', { cookies: jar });
  assert.strictEqual(me.body.user.username, 'fromguest');
});

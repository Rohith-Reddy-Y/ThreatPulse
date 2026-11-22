/**
 * Auth / admin regression tests.  Run:  node --test tests/
 * (no npm deps needed — see tests/helpers.js)
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const h = require('./helpers');
const { db, auth, request, absorb, createUser, login } = h;

const PW = 'Passw0rdA';
const PW2 = 'Passw0rdB';

function csrf(jar) { return { 'x-csrf-token': jar.tp_csrf }; }

function withClock(offsetMs, fn) {
  const real = Date.now;
  Date.now = () => real() + offsetMs;
  try { return fn(); } finally { Date.now = real; }
}

// ---------------------------------------------------------------------------
// must_change_password is enforced server-side, not just by the UI modal
// ---------------------------------------------------------------------------
test('user with mustChangePassword cannot use other APIs until they change it', async () => {
  createUser('forced1', PW, { mustChange: true });
  const jar = await login('forced1', PW);

  const blocked = await request('GET', '/api/articles', { cookies: jar });
  assert.strictEqual(blocked.status, 403, 'other APIs must be refused');
  assert.strictEqual(blocked.body.mustChangePassword, true);

  const me = await request('GET', '/api/auth/me', { cookies: jar });
  assert.strictEqual(me.status, 200);
  assert.strictEqual(me.body.user.mustChangePassword, true);

  const change = await request('PUT', '/api/auth/password', {
    cookies: jar, body: { currentPassword: PW, newPassword: PW2 },
  });
  assert.strictEqual(change.body.success, true, JSON.stringify(change.body));

  const after = await request('GET', '/api/articles', { cookies: jar });
  assert.strictEqual(after.status, 200);
});

test('refresh response keeps the mustChangePassword flag', async () => {
  createUser('forced2', PW, { mustChange: true });
  const jar = await login('forced2', PW);
  const r = await request('POST', '/api/auth/refresh', { cookies: jar });
  assert.strictEqual(r.body.success, true);
  assert.strictEqual(r.body.user.mustChangePassword, true);
});

// ---------------------------------------------------------------------------
// Refresh rotation
// ---------------------------------------------------------------------------
test('concurrent refreshes with the same token do not log the user out', async () => {
  createUser('racer', PW);
  const jar = await login('racer', PW);
  // Two parallel 401-retries from the dashboard both send the same refresh cookie
  const a = await request('POST', '/api/auth/refresh', { cookies: { ...jar } });
  const b = await request('POST', '/api/auth/refresh', { cookies: { ...jar } });
  assert.strictEqual(a.body.success, true);
  assert.strictEqual(b.body.success, true, 'second concurrent refresh must not fail');
  assert.strictEqual(b.res.cleared.length, 0, 'must not clear the fresh cookies');
  // Both responses hand back the same successor token, which keeps working
  assert.strictEqual(a.res.cookies.tp_refresh.value, b.res.cookies.tp_refresh.value);
  const c = await request('POST', '/api/auth/refresh', { cookies: { tp_refresh: a.res.cookies.tp_refresh.value } });
  assert.strictEqual(c.body.success, true);
});

test('a rotated refresh token is rejected once the grace window has passed', async () => {
  createUser('replayer', PW);
  const jar = await login('replayer', PW);
  const a = await request('POST', '/api/auth/refresh', { cookies: { ...jar } });
  assert.strictEqual(a.body.success, true);
  const real = Date.now;
  Date.now = () => real() + 5 * 60 * 1000;
  try {
    const late = await request('POST', '/api/auth/refresh', { cookies: { ...jar } });
    assert.strictEqual(late.status, 401);
  } finally { Date.now = real; }
});

test('logout revokes the refresh token even when the access token has expired', async () => {
  createUser('sleepy', PW);
  const jar = await login('sleepy', PW);
  const expiredJar = { ...jar, tp_access: 'expired.or.garbage' };
  const out = await request('POST', '/api/auth/logout', { cookies: expiredJar, headers: csrf(jar) });
  assert.strictEqual(out.status, 200);
  assert.ok(out.res.cleared.some(c => c.name === 'tp_refresh'), 'cookies must be cleared');
  const r = await request('POST', '/api/auth/refresh', { cookies: { tp_refresh: jar.tp_refresh } });
  assert.strictEqual(r.status, 401, 'refresh token must be revoked by logout');
});

test('logout also kills the grace-period predecessor of the refresh token', async () => {
  createUser('sleepy2', PW);
  const jar = await login('sleepy2', PW);
  const rot = await request('POST', '/api/auth/refresh', { cookies: { ...jar } });
  const jar2 = absorb({ ...jar }, rot.res);
  await request('POST', '/api/auth/logout', { cookies: jar2, headers: csrf(jar2) });
  const r = await request('POST', '/api/auth/refresh', { cookies: { tp_refresh: jar.tp_refresh } });
  assert.strictEqual(r.status, 401);
});

test('changing the password revokes the other sessions but keeps the current one', async () => {
  createUser('multi', PW, { email: null });
  // no SMTP configured → password is applied directly
  const s1 = await login('multi', PW);
  const s2 = await login('multi', PW);
  const ch = await request('PUT', '/api/auth/password', {
    cookies: s1, body: { currentPassword: PW, newPassword: PW2 },
  });
  assert.strictEqual(ch.body.success, true, JSON.stringify(ch.body));
  const other = await request('POST', '/api/auth/refresh', { cookies: { tp_refresh: s2.tp_refresh } });
  assert.strictEqual(other.status, 401, 'other session must be revoked');
  const mine = await request('POST', '/api/auth/refresh', { cookies: { tp_refresh: s1.tp_refresh } });
  assert.strictEqual(mine.body.success, true, 'current session must survive');
});

// ---------------------------------------------------------------------------
// Expiry timestamps compared against SQLite datetime('now')
// ---------------------------------------------------------------------------
test('password reset tokens actually expire after one hour', async () => {
  createUser('forgetful', PW, { email: 'forgetful@example.test' });
  // Token issued 61 minutes ago → expired 1 minute ago
  const r = withClock(-61 * 60 * 1000, () => auth.forgotPassword('forgetful@example.test'));
  assert.ok(r._token);
  const reset = await auth.resetPassword(r._token, PW2);
  assert.strictEqual(reset.success, false, 'expired token must be rejected');
});

test('email verification codes actually expire after 15 minutes', async () => {
  createUser('mover', PW, { email: 'mover@example.test' });
  const jar = await login('mover', PW);
  const real = Date.now;
  Date.now = () => real() - 16 * 60 * 1000;
  // Codes are only issued when SMTP can deliver them (stub transport here);
  // without SMTP the change is applied directly (see flows-account tests).
  Object.assign(process.env, { SMTP_HOST: 'smtp.example.test', SMTP_USER: 'u', SMTP_PASS: 'p' });
  try {
    const r = await request('PUT', '/api/auth/email', { cookies: jar, body: { email: 'moved@example.test', currentPassword: PW } });
    assert.strictEqual(r.body.success, true, JSON.stringify(r.body));
    assert.strictEqual(r.body.verificationRequired, true);
  } finally { Date.now = real; delete process.env.SMTP_HOST; delete process.env.SMTP_USER; delete process.env.SMTP_PASS; }
  const row = db.getDb().prepare("SELECT code FROM verification_codes WHERE type = 'email_change'").get();
  const v = await request('POST', '/api/auth/verify-change', { cookies: jar, body: { type: 'email_change', code: row.code } });
  assert.strictEqual(v.body.success, false, 'expired code must be rejected');
});

// ---------------------------------------------------------------------------
// Input validation should give a 4xx-style error, not a 500
// ---------------------------------------------------------------------------
test('register without a password is a validation error, not a 500', async () => {
  const r = await request('POST', '/api/auth/register', {
    body: { username: 'nopass', displayName: 'No Pass', email: 'nopass@example.test' },
  });
  assert.notStrictEqual(r.status, 500);
  assert.strictEqual(r.body.success, false);
  assert.match(r.body.error, /password/i);
});

test('reset-password without newPassword is a validation error, not a 500', async () => {
  const r = await request('POST', '/api/auth/reset-password', { body: { token: 'abc' } });
  assert.notStrictEqual(r.status, 500);
  assert.strictEqual(r.body.success, false);
});

test('login with a non-string password is rejected cleanly', async () => {
  createUser('typed', PW);
  const r = await request('POST', '/api/auth/login', { body: { username: 'typed', password: { a: 1 } } });
  assert.notStrictEqual(r.status, 500);
  assert.strictEqual(r.body.success, false);
});

test('disabled-account message is only shown after a correct password', async () => {
  const id = createUser('ghost', PW);
  db.updateUser(id, { is_active: 0 });
  const wrong = await request('POST', '/api/auth/login', { body: { username: 'ghost', password: 'nope' } });
  assert.doesNotMatch(wrong.body.error, /disabled/i);
  const right = await request('POST', '/api/auth/login', { body: { username: 'ghost', password: PW } });
  assert.match(right.body.error, /disabled/i);
});

// ---------------------------------------------------------------------------
// Guest account
// ---------------------------------------------------------------------------
test('nobody can register the reserved "guest" username', async () => {
  for (const username of ['guest', 'Guest']) {
    const r = await request('POST', '/api/auth/register', {
      body: { username, displayName: 'Squatter', email: `${username}sq@example.test`, password: PW },
    });
    assert.strictEqual(r.body.success, false, `${username} must be reserved`);
  }
});

test('guest sessions are refused while the guest account is disabled', async () => {
  const g = await request('POST', '/api/auth/guest');
  assert.strictEqual(g.body.success, true);
  const guest = db.getUserByUsername('guest');
  db.updateUser(guest.id, { is_active: 0 });
  try {
    const r = await request('POST', '/api/auth/guest');
    assert.strictEqual(r.body.success, false);
    assert.ok(!r.res.cookies.tp_access, 'no session cookie for a disabled guest');
  } finally { db.updateUser(guest.id, { is_active: 1 }); }
});

test('a flood of guest sessions is bounded and does not evict real sessions', async () => {
  createUser('survivor', PW);
  const jar = await login('survivor', PW);
  const before = auth._refreshTokenCount();
  for (let i = 0; i < auth.MAX_GUEST_REFRESH_TOKENS + 50; i++) await auth.getOrCreateGuestUser();
  assert.ok(auth._guestRefreshTokenCount() <= auth.MAX_GUEST_REFRESH_TOKENS);
  assert.ok(auth._refreshTokenCount() <= before + auth.MAX_GUEST_REFRESH_TOKENS, `store grew to ${auth._refreshTokenCount()}`);
  const r = await request('POST', '/api/auth/refresh', { cookies: { tp_refresh: jar.tp_refresh } });
  assert.strictEqual(r.body.success, true, 'registered session must survive the flood');
});

// ---------------------------------------------------------------------------
// Admin endpoints
// ---------------------------------------------------------------------------
async function adminJar(name) {
  createUser(name, PW, { role: 'admin' });
  return login(name, PW);
}

test('admin cannot demote or disable themselves', async () => {
  const jar = await adminJar('admin_self');
  const me = db.getUserByUsername('admin_self');
  const demote = await request('PUT', `/api/admin/users/${me.id}`, { cookies: jar, body: { role: 'analyst' } });
  assert.strictEqual(demote.status, 400);
  const disable = await request('PUT', `/api/admin/users/${me.id}`, { cookies: jar, body: { is_active: 0 } });
  assert.strictEqual(disable.status, 400);
  const fresh = db.getUserById(me.id);
  assert.strictEqual(fresh.role, 'admin');
  assert.strictEqual(fresh.is_active, 1);
  // Renaming yourself is still fine
  const rename = await request('PUT', `/api/admin/users/${me.id}`, { cookies: jar, body: { display_name: 'Boss' } });
  assert.strictEqual(rename.body.success, true);
});

test('admin cannot promote the shared guest account', async () => {
  const jar = await adminJar('admin_guest');
  await request('POST', '/api/auth/guest');
  const guest = db.getUserByUsername('guest');
  const r = await request('PUT', `/api/admin/users/${guest.id}`, { cookies: jar, body: { role: 'admin' } });
  assert.strictEqual(r.status, 400);
  assert.strictEqual(db.getUserById(guest.id).role, 'analyst');
});

test('admin user update validates role / is_active / display_name values', async () => {
  const jar = await adminJar('admin_val');
  const target = createUser('target_val', PW);
  for (const body of [{ role: 'superuser' }, { is_active: 'false' }, { is_active: 2 }, { display_name: '' }, { display_name: { x: 1 } }]) {
    const r = await request('PUT', `/api/admin/users/${target}`, { cookies: jar, body });
    assert.strictEqual(r.status, 400, `should reject ${JSON.stringify(body)}`);
  }
  const ok = await request('PUT', `/api/admin/users/${target}`, { cookies: jar, body: { role: 'admin', is_active: 1 } });
  assert.strictEqual(ok.body.success, true);
  const u = db.getUserById(target);
  assert.strictEqual(u.role, 'admin');
});

test('non-admin cannot reach admin endpoints', async () => {
  createUser('plain', PW);
  const jar = await login('plain', PW);
  const r = await request('GET', '/api/admin/users', { cookies: jar });
  assert.strictEqual(r.status, 403);
});

test('admin can delete a user who created invite codes, atomically', async () => {
  const jar = await adminJar('admin_del');
  const victim = createUser('inviter', PW, { role: 'admin' });
  db.createInviteCode(victim, 'DEL0CODE');
  db.addSource({ name: 'v', url: 'https://example.test/feed', user_id: victim });
  const r = await request('DELETE', `/api/admin/users/${victim}`, { cookies: jar });
  assert.strictEqual(r.body.success, true, JSON.stringify(r.body));
  assert.strictEqual(db.getUserById(victim), undefined);
  const code = db.getDb().prepare("SELECT created_by FROM invite_codes WHERE code = 'DEL0CODE'").get();
  assert.strictEqual(code.created_by, db.getUserByUsername('admin_del').id);
});

test('a delete that fails part-way is rolled back', async () => {
  const jar = await adminJar('admin_del2');
  const target = createUser('half_deleted', PW);
  db.addSource({ name: 't', url: 'https://example.test/t', user_id: target });
  const realDelete = db.deleteUser;
  db.deleteUser = (id) => {
    db.getDb().prepare('DELETE FROM sources WHERE user_id = ?').run(id);
    throw new Error('simulated failure after the first DELETE');
  };
  try {
    const r = await request('DELETE', `/api/admin/users/${target}`, { cookies: jar });
    assert.strictEqual(r.status, 500);
  } finally { db.deleteUser = realDelete; }
  assert.ok(db.getUserById(target), 'user must still exist');
  const n = db.getDb().prepare('SELECT COUNT(*) AS c FROM sources WHERE user_id = ?').get(target).c;
  assert.strictEqual(n, 1, 'their sources must not be half-deleted');
});

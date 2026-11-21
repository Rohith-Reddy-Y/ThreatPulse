/**
 * Async password hashing + per-(account, IP) login lockout.
 * Run:  node --test tests/auth-hardening.test.js   (no npm deps — see tests/helpers.js)
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const crypto = require('crypto');
const h = require('./helpers');
const { db, auth, request, createUser, legacyHash } = h;
const throttle = auth._loginThrottle;

const PW = 'Passw0rdA';
const PW2 = 'Passw0rdB';

function loginReq(username, password, ip) {
  return request('POST', '/api/auth/login', { body: { username, password }, ip });
}

function withClock(offsetMs, fn) {
  const real = Date.now;
  Date.now = () => real() + offsetMs;
  const restore = () => { Date.now = real; };
  try {
    const r = fn();
    if (r && typeof r.then === 'function') return r.finally(restore);
    restore();
    return r;
  } catch (e) { restore(); throw e; }
}

// ---------------------------------------------------------------------------
// Async hashing
// ---------------------------------------------------------------------------
test('hashPassword/verifyPassword are async and round-trip', async () => {
  const salt = auth.generateSalt();
  const p = auth.hashPassword(PW, salt);
  assert.ok(p instanceof Promise, 'hashPassword must return a promise');
  const hash = await p;
  assert.match(hash, /^[0-9a-f]{128}$/, 'same 64-byte hex format as before');
  const v = auth.verifyPassword(PW, salt, hash);
  assert.ok(v instanceof Promise, 'verifyPassword must return a promise');
  assert.strictEqual(await v, true);
  assert.strictEqual(await auth.verifyPassword(PW2, salt, hash), false);
  assert.strictEqual(await auth.verifyPassword(PW, auth.generateSalt(), hash), false);
});

test('a hash produced by the old scryptSync code path still verifies (and matches)', async () => {
  const salt = auth.generateSalt();
  const old = crypto.scryptSync(PW, salt, 64).toString('hex'); // the pre-async implementation
  assert.strictEqual(await auth.verifyPassword(PW, salt, old), true);
  assert.strictEqual(await auth.verifyPassword(PW2, salt, old), false);
  assert.strictEqual(await auth.hashPassword(PW, salt), old, 'new hashes are byte-identical');
});

test('verifyPassword fails closed on malformed input instead of throwing', async () => {
  const salt = auth.generateSalt();
  const hash = await auth.hashPassword(PW, salt);
  assert.strictEqual(await auth.verifyPassword(PW, salt, 'not-hex'), false);
  assert.strictEqual(await auth.verifyPassword(PW, salt, hash.slice(0, 64)), false);
  assert.strictEqual(await auth.verifyPassword(PW, null, hash), false);
  assert.strictEqual(await auth.verifyPassword(PW, salt, null), false);
  assert.strictEqual(await auth.verifyPassword({ a: 1 }, salt, hash), false);
});

test('hashing does not block the event loop', async () => {
  let ticks = 0;
  const iv = setInterval(() => { ticks++; }, 0);
  const salt = auth.generateSalt();
  await Promise.all(Array.from({ length: 4 }, () => auth.hashPassword(PW, salt)));
  clearInterval(iv);
  assert.ok(ticks > 0, 'timers must keep running while scrypt works');
});

test('register / login / password change / reset all work with async hashing', async () => {
  const reg = await request('POST', '/api/auth/register', {
    body: { username: 'asyncer', displayName: 'Async User', email: 'asyncer@example.test', password: PW },
  });
  assert.strictEqual(reg.body.success, true, JSON.stringify(reg.body));
  const row = db.getUserByUsername('asyncer');
  assert.match(row.password_hash, /^[0-9a-f]{128}$/);
  assert.strictEqual(row.password_hash, legacyHash(PW, row.salt), 'stored format unchanged');

  const ok = await loginReq('asyncer', PW, '10.9.0.1');
  assert.strictEqual(ok.body.success, true);

  // Password change route (no SMTP → applied directly)
  const jar = h.absorb({}, ok.res);
  const ch = await request('PUT', '/api/auth/password', { cookies: jar, body: { currentPassword: PW, newPassword: PW2 } });
  assert.strictEqual(ch.body.success, true, JSON.stringify(ch.body));
  const wrongCur = await request('PUT', '/api/auth/password', { cookies: jar, body: { currentPassword: PW, newPassword: 'Passw0rdC' } });
  assert.strictEqual(wrongCur.status, 400);
  const same = await request('PUT', '/api/auth/password', { cookies: jar, body: { currentPassword: PW2, newPassword: PW2 } });
  assert.strictEqual(same.status, 400);
  assert.strictEqual((await loginReq('asyncer', PW2, '10.9.0.1')).body.success, true);

  // Email-token reset
  const f = auth.forgotPassword('asyncer@example.test');
  const r = await request('POST', '/api/auth/reset-password', { body: { token: f._token, newPassword: 'Passw0rdC' } });
  assert.strictEqual(r.body.success, true, JSON.stringify(r.body));
  assert.strictEqual((await loginReq('asyncer', 'Passw0rdC', '10.9.0.1')).body.success, true);
});

test('a reset token can only be used once, even by concurrent requests', async () => {
  createUser('racer_reset', PW, { email: 'racer_reset@example.test' });
  const f = auth.forgotPassword('racer_reset@example.test');
  const results = await Promise.all([
    auth.resetPassword(f._token, 'Passw0rdX'),
    auth.resetPassword(f._token, 'Passw0rdY'),
  ]);
  assert.strictEqual(results.filter(r => r.success).length, 1, JSON.stringify(results));
});

test('concurrent first guest visits create a single guest account', async () => {
  const before = db.getUserByUsername('guest');
  if (before) db.getDb().prepare('DELETE FROM users WHERE id = ?').run(before.id);
  const rs = await Promise.all([auth.getOrCreateGuestUser(), auth.getOrCreateGuestUser(), auth.getOrCreateGuestUser()]);
  assert.ok(rs.every(r => r.success), JSON.stringify(rs.map(r => r.error)));
  assert.strictEqual(new Set(rs.map(r => r.user.id)).size, 1);
  assert.strictEqual(db.getDb().prepare("SELECT COUNT(*) c FROM users WHERE username = 'guest'").get().c, 1);
});

test('a failing hash makes the route return a clean 500', async () => {
  createUser('boom', PW);
  // The route calls auth.verifyPassword through the module object, so patch it there
  const realVerify = auth.verifyPassword;
  auth.verifyPassword = async () => { throw new Error('threadpool exploded'); };
  try {
    const jar = await h.login('boom', PW, '10.9.9.9');
    const r = await request('PUT', '/api/auth/password', { cookies: jar, body: { currentPassword: PW, newPassword: PW2 } });
    assert.strictEqual(r.status, 500);
    assert.doesNotMatch(JSON.stringify(r.body), /exploded/);
  } finally { auth.verifyPassword = realVerify; }
});

// ---------------------------------------------------------------------------
// Lockout: per (account, IP) pair + short per-account cap
// ---------------------------------------------------------------------------
test('5 failures from one IP lock that IP out; the owner on another IP still logs in', async () => {
  createUser('victim', PW);
  const attacker = '203.0.113.7';
  for (let i = 1; i < throttle.PAIR_MAX_FAILURES; i++) {
    const r = await loginReq('victim', 'wrong' + i, attacker);
    assert.strictEqual(r.body.success, false);
    assert.match(r.body.error, /invalid username\/email or password/i);
  }
  const fifth = await loginReq('victim', 'wrong5', attacker);
  assert.match(fifth.body.error, /too many failed login attempts/i);

  // Even the right password is refused from the locked IP
  const right = await loginReq('victim', PW, attacker);
  assert.strictEqual(right.body.success, false);
  assert.match(right.body.error, /too many failed login attempts/i);

  // The owner, elsewhere, is unaffected
  const owner = await loginReq('victim', PW, '198.51.100.20');
  assert.strictEqual(owner.body.success, true, JSON.stringify(owner.body));

  // The DB lock columns are no longer used for locking
  const row = db.getUserByUsername('victim');
  assert.ok(!row.locked_until, 'account row must not be locked');
});

test('the IP lock expires after 15 minutes', async () => {
  createUser('patient', PW);
  const ip = '203.0.113.8';
  for (let i = 0; i < throttle.PAIR_MAX_FAILURES; i++) await loginReq('patient', 'nope', ip);
  assert.match((await loginReq('patient', PW, ip)).body.error, /too many/i);
  await withClock(throttle.PAIR_LOCK_MS + 1000, async () => {
    const r = await loginReq('patient', PW, ip);
    assert.strictEqual(r.body.success, true, JSON.stringify(r.body));
  });
});

test('a successful login resets that pair\'s failure counter', async () => {
  createUser('forgetter', PW);
  const ip = '203.0.113.9';
  for (let i = 0; i < throttle.PAIR_MAX_FAILURES - 1; i++) await loginReq('forgetter', 'nope', ip);
  assert.strictEqual((await loginReq('forgetter', PW, ip)).body.success, true);
  // Counter was cleared: another 4 failures still don't lock
  for (let i = 0; i < throttle.PAIR_MAX_FAILURES - 1; i++) {
    const r = await loginReq('forgetter', 'nope', ip);
    assert.doesNotMatch(r.body.error, /too many/i);
  }
  assert.strictEqual((await loginReq('forgetter', PW, ip)).body.success, true);
});

test('IPv4-mapped and same-/64 IPv6 addresses share a bucket', async () => {
  assert.strictEqual(throttle.normalizeIp('::ffff:203.0.113.5'), '203.0.113.5');
  assert.strictEqual(throttle.normalizeIp('2001:db8:1:2::1'), throttle.normalizeIp('2001:db8:1:2:ffff:ee:dd:cc'));
  assert.notStrictEqual(throttle.normalizeIp('2001:db8:1:2::1'), throttle.normalizeIp('2001:db8:1:3::1'));
  assert.strictEqual(throttle.normalizeIp(undefined), 'unknown');

  createUser('v6victim', PW);
  for (let i = 0; i < throttle.PAIR_MAX_FAILURES; i++) await loginReq('v6victim', 'nope', `2001:db8:aa:bb::${i + 1}`);
  const r = await loginReq('v6victim', PW, '2001:db8:aa:bb::99');
  assert.match(r.body.error, /too many/i, 'rotating within one /64 must not reset the lock');
  assert.strictEqual((await loginReq('v6victim', PW, '2001:db8:aa:cc::1')).body.success, true);
});

test('distributed guessing hits the per-account cap: short global lock that then resets', async () => {
  createUser('popular', PW);
  // ACCOUNT_MAX_FAILURES failures, each from a different IP (none hits the pair limit)
  for (let i = 0; i < throttle.ACCOUNT_MAX_FAILURES; i++) {
    await loginReq('popular', 'nope', `192.0.2.${i + 1}`);
  }
  const blocked = await loginReq('popular', PW, '198.51.100.77');
  assert.strictEqual(blocked.body.success, false, 'global cap applies to every IP');
  assert.match(blocked.body.error, /too many failed login attempts/i);
  assert.match(blocked.body.error, /2 minute/);

  await withClock(throttle.ACCOUNT_LOCK_MS + 1000, async () => {
    const r = await loginReq('popular', PW, '198.51.100.77');
    assert.strictEqual(r.body.success, true, 'global lock is short and lifts by itself');
    // Counter restarted: a single new failure doesn't re-lock
    await loginReq('popular', 'nope', '192.0.2.250');
    assert.strictEqual((await loginReq('popular', PW, '198.51.100.78')).body.success, true);
  });
});

test('failures outside the 15-minute window do not add up to the global cap', async () => {
  createUser('slowburn', PW);
  const half = Math.floor(throttle.ACCOUNT_MAX_FAILURES / 2) + 1;
  for (let i = 0; i < half; i++) await loginReq('slowburn', 'nope', `192.0.3.${i + 1}`);
  await withClock(throttle.ACCOUNT_WINDOW_MS + 1000, async () => {
    for (let i = 0; i < half; i++) await loginReq('slowburn', 'nope', `192.0.4.${i + 1}`);
    assert.strictEqual((await loginReq('slowburn', PW, '198.51.100.90')).body.success, true);
  });
});

test('lockout responses do not reveal whether the account exists', async () => {
  createUser('realone', PW);
  const ip = '203.0.113.50';
  const real = [], fake = [];
  for (let i = 0; i < throttle.PAIR_MAX_FAILURES + 1; i++) {
    real.push((await loginReq('realone', 'nope', ip)).body.error);
    fake.push((await loginReq('nosuchuser_zz', 'nope', ip)).body.error);
  }
  assert.deepStrictEqual(fake, real);
});

test('loginUser stays backward compatible without an ip argument', async () => {
  createUser('noip', PW);
  const r = await auth.loginUser('noip', PW);
  assert.strictEqual(r.success, true);
  for (let i = 0; i < throttle.PAIR_MAX_FAILURES; i++) await auth.loginUser('noip', 'nope');
  assert.match((await auth.loginUser('noip', PW)).error, /too many/i);
  // a real IP is a separate bucket
  assert.strictEqual((await auth.loginUser('noip', PW, '198.51.100.5')).success, true);
});

test('a password reset clears the account\'s lockouts', async () => {
  createUser('lockedout', PW, { email: 'lockedout@example.test' });
  const ip = '203.0.113.60';
  for (let i = 0; i < throttle.PAIR_MAX_FAILURES; i++) await loginReq('lockedout', 'nope', ip);
  assert.match((await loginReq('lockedout', PW, ip)).body.error, /too many/i);
  const f = auth.forgotPassword('lockedout@example.test');
  assert.strictEqual((await auth.resetPassword(f._token, PW2)).success, true);
  assert.strictEqual((await loginReq('lockedout', PW2, ip)).body.success, true);
});

test('throttle state is bounded', () => {
  throttle._reset();
  for (let i = 0; i < throttle.MAX_KEYS + 500; i++) throttle.recordFailure(`n:flood${i}`, `10.${(i >> 16) & 255}.${(i >> 8) & 255}.${i & 255}`);
  const s = throttle._sizes();
  assert.ok(s.pairs <= throttle.MAX_KEYS, `pairs=${s.pairs}`);
  assert.ok(s.accounts <= throttle.MAX_KEYS, `accounts=${s.accounts}`);
  throttle._reset();
});

test('legacy locked_until in the DB no longer blocks a login', async () => {
  const id = createUser('legacylock', PW);
  db.lockAccount(id, new Date(Date.now() + 60 * 60 * 1000).toISOString());
  const r = await loginReq('legacylock', PW, '198.51.100.123');
  assert.strictEqual(r.body.success, true, JSON.stringify(r.body));
});

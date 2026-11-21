/**
 * ThreatPulse — Login failure throttling (in memory, single instance)
 *
 * Two independent limits:
 *  - per (account, client IP) pair: PAIR_MAX_FAILURES wrong passwords from one IP
 *    against one account lock THAT IP out of THAT account for PAIR_LOCK_MS. The
 *    owner logging in from another address is unaffected, so knowing a username
 *    is no longer enough to lock its owner out.
 *  - per account, across all IPs: ACCOUNT_MAX_FAILURES failures within
 *    ACCOUNT_WINDOW_MS impose a short ACCOUNT_LOCK_MS lock, which slows
 *    distributed guessing without letting anyone lock the account for long.
 *
 * The account key is chosen by the caller (a user id for real accounts, the
 * typed identifier for unknown ones) so unknown names get identical treatment
 * and the responses don't reveal whether an account exists.
 *
 * State lives in bounded Maps (oldest entries evicted first), so a flood of
 * random usernames/IPs cannot grow memory without limit. It resets on restart.
 */
'use strict';

const PAIR_MAX_FAILURES = 5;
const PAIR_WINDOW_MS = 15 * 60 * 1000;   // failures older than this are forgotten
const PAIR_LOCK_MS = 15 * 60 * 1000;
const ACCOUNT_MAX_FAILURES = 50;
const ACCOUNT_WINDOW_MS = 15 * 60 * 1000;
const ACCOUNT_LOCK_MS = 2 * 60 * 1000;
const MAX_KEYS = 20000;
const SWEEP_MIN_INTERVAL_MS = 10 * 1000;

// pair key "<account>|<ip>"  → { count, firstAt, lockedUntil }
const pairs = new Map();
// account key               → { count, windowStart, lockedUntil }
const accounts = new Map();
const lastSweep = new WeakMap();

function pairIdle(e, now) {
  return e.lockedUntil <= now && now - e.firstAt > PAIR_WINDOW_MS;
}
function accountIdle(e, now) {
  return e.lockedUntil <= now && now - e.windowStart > ACCOUNT_WINDOW_MS;
}

function sweep(map, isIdle, now) {
  for (const [k, e] of map) if (isIdle(e, now)) map.delete(k);
  lastSweep.set(map, now);
}

// Re-insert so Map order tracks recency, then enforce the size cap: first drop
// idle entries (at most once per SWEEP_MIN_INTERVAL_MS, so a flood doesn't make
// every insert an O(n) scan), then the least recently touched ones.
function put(map, key, value, isIdle, now) {
  map.delete(key);
  map.set(key, value);
  if (map.size > MAX_KEYS) {
    if (now - (lastSweep.get(map) || 0) >= SWEEP_MIN_INTERVAL_MS) sweep(map, isIdle, now);
    while (map.size > MAX_KEYS) map.delete(map.keys().next().value);
  }
}

// IPv4-mapped IPv6 → plain IPv4; IPv6 → its /64 (one host usually controls a
// whole /64, so per-address keys would be trivial to rotate).
function normalizeIp(ip) {
  if (typeof ip !== 'string' || !ip.trim()) return 'unknown';
  let s = ip.trim().toLowerCase();
  if (s.startsWith('[') && s.endsWith(']')) s = s.slice(1, -1);
  const mapped = s.match(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/);
  if (mapped) return mapped[1];
  if (!s.includes(':')) return s;
  s = s.split('%')[0];
  const halves = s.split('::');
  if (halves.length > 2) return s;
  const toGroups = (part) => {
    if (!part) return [];
    const out = [];
    for (const g of part.split(':')) {
      if (g.includes('.')) out.push('0', '0'); // trailing embedded IPv4 = two (host-part) groups
      else out.push(g);
    }
    return out;
  };
  const head = toGroups(halves[0]);
  const tail = halves.length === 2 ? toGroups(halves[1]) : [];
  const fill = halves.length === 2 ? 8 - head.length - tail.length : 0;
  if (fill < 0) return s;
  const groups = [...head, ...Array(fill).fill('0'), ...tail];
  if (groups.length !== 8 || groups.some(g => !/^[0-9a-f]{1,4}$/.test(g))) return s;
  return `${groups.slice(0, 4).map(g => g.replace(/^0+(?=.)/, '')).join(':')}::/64`;
}

function pairKey(accountKey, ip) {
  return `${accountKey}|${normalizeIp(ip)}`;
}

/**
 * Is this (account, ip) currently allowed to attempt a login?
 * Returns { locked: false } or { locked: true, scope: 'ip'|'account', retryAfterMs }.
 */
function check(accountKey, ip) {
  const now = Date.now();
  const pk = pairKey(accountKey, ip);
  const p = pairs.get(pk);
  if (p) {
    if (p.lockedUntil > now) return { locked: true, scope: 'ip', retryAfterMs: p.lockedUntil - now };
    if (p.lockedUntil && p.lockedUntil <= now) pairs.delete(pk); // lock served → fresh start
  }
  const a = accounts.get(accountKey);
  if (a && a.lockedUntil > now) return { locked: true, scope: 'account', retryAfterMs: a.lockedUntil - now };
  return { locked: false };
}

/** Record a failed attempt. Returns the same shape as check(), reflecting any lock it triggered. */
function recordFailure(accountKey, ip) {
  const now = Date.now();
  const pk = pairKey(accountKey, ip);

  let p = pairs.get(pk);
  if (!p || (p.lockedUntil <= now && (p.lockedUntil || now - p.firstAt > PAIR_WINDOW_MS))) {
    p = { count: 0, firstAt: now, lockedUntil: 0 };
  }
  p.count++;
  if (p.count >= PAIR_MAX_FAILURES && p.lockedUntil <= now) p.lockedUntil = now + PAIR_LOCK_MS;
  put(pairs, pk, p, pairIdle, now);

  let a = accounts.get(accountKey);
  if (!a || (a.lockedUntil <= now && now - a.windowStart > ACCOUNT_WINDOW_MS)) {
    a = { count: 0, windowStart: now, lockedUntil: 0 };
  }
  a.count++;
  if (a.count >= ACCOUNT_MAX_FAILURES) {
    // Short global lock, then the counter starts over
    a.lockedUntil = now + ACCOUNT_LOCK_MS;
    a.count = 0;
    a.windowStart = now;
  }
  put(accounts, accountKey, a, accountIdle, now);

  if (p.lockedUntil > now) return { locked: true, scope: 'ip', retryAfterMs: p.lockedUntil - now };
  if (a.lockedUntil > now) return { locked: true, scope: 'account', retryAfterMs: a.lockedUntil - now };
  return { locked: false };
}

/** A successful login clears that (account, ip) pair's counter. */
function recordSuccess(accountKey, ip) {
  pairs.delete(pairKey(accountKey, ip));
}

/** Clear every lock/counter for an account (e.g. after an admin password reset). */
function clearAccount(accountKey) {
  accounts.delete(accountKey);
  const prefix = `${accountKey}|`;
  for (const k of pairs.keys()) if (k.startsWith(prefix)) pairs.delete(k);
}

// Periodic housekeeping so idle entries don't linger until the cap is reached
setInterval(() => {
  const now = Date.now();
  sweep(pairs, pairIdle, now);
  sweep(accounts, accountIdle, now);
}, 5 * 60 * 1000).unref?.();

module.exports = {
  check,
  recordFailure,
  recordSuccess,
  clearAccount,
  normalizeIp,
  PAIR_MAX_FAILURES,
  PAIR_LOCK_MS,
  ACCOUNT_MAX_FAILURES,
  ACCOUNT_WINDOW_MS,
  ACCOUNT_LOCK_MS,
  MAX_KEYS,
  _reset: () => { pairs.clear(); accounts.clear(); },
  _sizes: () => ({ pairs: pairs.size, accounts: accounts.size }),
};

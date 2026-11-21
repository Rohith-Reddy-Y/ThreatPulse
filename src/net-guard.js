/**
 * ThreatPulse — Outbound network guard (SSRF protection)
 *
 * User-supplied feed URLs are fetched server-side, so every outbound request to
 * such a URL must be prevented from reaching internal/private addresses:
 *   - literal IPs in the URL are checked up front
 *   - hostnames are checked AFTER DNS resolution (custom agent lookup), which
 *     also covers DNS rebinding and names like 127.0.0.1.nip.io
 *   - every redirect hop is re-validated
 */

const dns = require('dns');
const net = require('net');
const http = require('http');
const https = require('https');
const axios = require('axios');

function isPrivateIPv4(ip) {
  const p = ip.split('.').map(n => parseInt(n, 10));
  if (p.length !== 4 || p.some(n => Number.isNaN(n) || n < 0 || n > 255)) return true;
  const [a, b] = p;
  return (
    a === 0 || a === 10 || a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||   // CGNAT
    (a === 169 && b === 254) ||             // link-local / cloud metadata
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 168) ||
    (a === 192 && b === 0 && (p[2] === 0 || p[2] === 2)) ||   // 192.0.0.0/24, 192.0.2.0/24 only
                                                              // (NOT all of 192.0/16 — WordPress.com is 192.0.78.x)
    (a === 198 && b === 51 && p[2] === 100) ||                // TEST-NET-2
    (a === 203 && b === 0 && p[2] === 113) ||                 // TEST-NET-3
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224                                // multicast + reserved
  );
}

/** Expand an IPv6 address (any spelling, optional dotted-IPv4 tail) to 8 hextets. */
function ipv6Hextets(ip) {
  let v = ip.toLowerCase().replace(/%.*$/, '');
  const tail = v.match(/^(.*:)(\d+)\.(\d+)\.(\d+)\.(\d+)$/);
  if (tail) {
    const [a, b, c, d] = tail.slice(2).map(Number);
    v = `${tail[1]}${((a << 8) | b).toString(16)}:${((c << 8) | d).toString(16)}`;
  }
  const halves = v.split('::');
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(':') : [];
  const rest = halves.length === 2 && halves[1] ? halves[1].split(':') : [];
  const fill = halves.length === 2 ? 8 - head.length - rest.length : 0;
  const parts = [...head, ...Array(Math.max(fill, 0)).fill('0'), ...rest];
  if (parts.length !== 8) return null;
  return parts.map(h => parseInt(h, 16));
}

const v4From = (hi, lo) => `${hi >> 8}.${hi & 255}.${lo >> 8}.${lo & 255}`;

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip);
  if (net.isIPv6(ip)) {
    const h = ipv6Hextets(ip);
    if (!h) return true;
    const zero = (from, to) => h.slice(from, to).every(x => x === 0);
    // ::/96 — unspecified, loopback and deprecated IPv4-compatible (::127.0.0.1)
    if (zero(0, 6)) return true;
    // IPv4-mapped ::ffff:a.b.c.d (any spelling) and IPv4-translated ::ffff:0:a.b.c.d
    if (zero(0, 5) && h[5] === 0xffff) return isPrivateIPv4(v4From(h[6], h[7]));
    if (zero(0, 4) && h[4] === 0xffff && h[5] === 0) return isPrivateIPv4(v4From(h[6], h[7]));
    // NAT64 64:ff9b::/96 and 6to4 2002::/16 embed an IPv4 destination
    if (h[0] === 0x64 && h[1] === 0xff9b && zero(2, 6)) return isPrivateIPv4(v4From(h[6], h[7]));
    if (h[0] === 0x2002) return isPrivateIPv4(v4From(h[1], h[2]));
    if ((h[0] & 0xffc0) === 0xfe80) return true;          // fe80::/10 link-local
    if ((h[0] & 0xffc0) === 0xfec0) return true;          // fec0::/10 site-local (deprecated)
    if ((h[0] & 0xfe00) === 0xfc00) return true;          // fc00::/7 unique-local
    if ((h[0] & 0xff00) === 0xff00) return true;          // multicast
    return false;
  }
  return true; // not an IP at all → treat as unsafe
}

/** Quick static check of a URL (protocol, obvious internal names, literal IPs). */
function isSafeUrl(urlStr) {
  let u;
  try { u = new URL(urlStr); } catch { return false; }
  if (!['http:', 'https:'].includes(u.protocol)) return false;
  let host = u.hostname.toLowerCase();
  if (host.startsWith('[') && host.endsWith(']')) host = host.slice(1, -1);
  if (!host) return false;
  if (host === 'localhost' || host.endsWith('.localhost') ||
      host.endsWith('.internal') || host.endsWith('.local')) return false;
  if (net.isIP(host)) return !isPrivateIp(host);
  return true;
}

/** dns.lookup replacement that refuses to connect to private addresses. */
function safeLookup(hostname, options, callback) {
  if (typeof options === 'function') { callback = options; options = {}; }
  if (typeof options === 'number') options = { family: options };
  options = options || {};
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    // Prefer IPv4: many hosting platforms have no IPv6 egress, and Node's
    // happy-eyeballs then fails with an empty-message AggregateError.
    const v4 = addresses.filter(a => a.family === 4);
    const usable = v4.length ? v4 : addresses;
    const bad = usable.find(a => isPrivateIp(a.address));
    if (bad || usable.length === 0) {
      const e = new Error(`Blocked outbound request: ${hostname} resolves to a private/internal address${bad ? ` (${bad.address})` : ''}`);
      e.code = 'EBLOCKED';
      return callback(e);
    }
    if (options.all) return callback(null, usable);
    return callback(null, usable[0].address, usable[0].family);
  });
}

const safeHttpAgent = new http.Agent({ lookup: safeLookup, autoSelectFamily: false });
const safeHttpsAgent = new https.Agent({ lookup: safeLookup, autoSelectFamily: false });

/**
 * axios.get for UNTRUSTED (user-supplied) URLs.
 */
async function safeGet(url, config = {}) {
  if (!isSafeUrl(url)) {
    const e = new Error('Blocked outbound request: URL is not a public http(s) address');
    e.code = 'EBLOCKED';
    throw e;
  }
  // axios' `timeout` is a socket-idle timer: a server that drips a byte every
  // few seconds keeps the request (and the whole fetch cycle, which waits for
  // it) alive forever. Enforce a hard overall deadline as well.
  const deadlineMs = (config.timeout || 30000) * 2;
  const signal = config.signal || AbortSignal.timeout(deadlineMs);
  try {
    return await axios.get(url, {
      maxRedirects: 5,
      maxContentLength: 10 * 1024 * 1024,
      ...config,
      signal,
      httpAgent: safeHttpAgent,
      httpsAgent: safeHttpsAgent,
      proxy: false,
      beforeRedirect: (opts) => {
        const href = opts.href || `${opts.protocol}//${opts.hostname}${opts.port ? ':' + opts.port : ''}${opts.path || ''}`;
        if (!isSafeUrl(href)) {
          const e = new Error('Blocked redirect to a non-public address');
          e.code = 'EBLOCKED';
          throw e;
        }
      }
    });
  } catch (err) {
    if (!config.signal && signal.aborted && !(err && err.response)) {
      const e = new Error(`Request exceeded the ${Math.round(deadlineMs / 1000)}s deadline`);
      e.code = 'ETIMEDOUT';
      throw e;
    }
    throw err;
  }
}

module.exports = { isPrivateIp, isSafeUrl, safeLookup, safeGet };

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

function isPrivateIp(ip) {
  if (net.isIPv4(ip)) return isPrivateIPv4(ip);
  if (net.isIPv6(ip)) {
    const v = ip.toLowerCase();
    if (v === '::' || v === '::1') return true;
    const mapped = v.match(/^::ffff:(\d+\.\d+\.\d+\.\d+)$/);
    if (mapped) return isPrivateIPv4(mapped[1]);
    if (v.startsWith('::ffff:')) return true;            // hex-form mapped — refuse
    if (/^fe[89ab]/.test(v)) return true;                 // fe80::/10 link-local
    if (/^f[cd]/.test(v)) return true;                    // fc00::/7 unique-local
    if (v.startsWith('ff')) return true;                  // multicast
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
  return axios.get(url, {
    maxRedirects: 5,
    maxContentLength: 10 * 1024 * 1024,
    ...config,
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
}

module.exports = { isPrivateIp, isSafeUrl, safeLookup, safeGet };

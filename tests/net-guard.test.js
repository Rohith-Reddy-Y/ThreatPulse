// SSRF guard: bypass forms, false positives on public hosts, DNS answers,
// redirect re-validation and the hard request deadline.
const { state, calls, reset } = require('./helpers/stubs');
const test = require('node:test');
const assert = require('node:assert/strict');
const dns = require('dns');
const { isPrivateIp, isSafeUrl, safeLookup, safeGet } = require('../src/net-guard');

test('blocks loopback/private/metadata in every URL spelling', () => {
  for (const u of [
    'http://127.0.0.1/', 'http://2130706433/', 'http://0x7f.1/', 'http://017700000001/', 'http://127.1/',
    'http://0/', 'http://[::1]/', 'http://[::]/', 'http://[::ffff:127.0.0.1]/', 'http://[0:0:0:0:0:ffff:7f00:1]/',
    'http://169.254.169.254/latest/meta-data/', 'http://[::ffff:a9fe:a9fe]/', 'http://10.0.0.1/', 'http://192.168.1.1/',
    'http://100.64.0.1/', 'http://[fd00::1]/', 'http://[fe80::1]/', 'http://localhost/', 'http://foo.localhost/',
    'http://metadata.google.internal/', 'file:///etc/passwd', 'gopher://example.com/',
    // IPv4 embedded in IPv6 transition prefixes (IPv4-compatible, NAT64, 6to4)
    'http://[::127.0.0.1]/', 'http://[::a9fe:a9fe]/', 'http://[64:ff9b::169.254.169.254]/', 'http://[64:ff9b::a00:1]/',
    'http://[2002:7f00:1::1]/', 'http://[2002:a9fe:a9fe::]/',
  ]) assert.equal(isSafeUrl(u), false, u);
});

test('allows legitimate public hosts (no false positives)', () => {
  for (const u of [
    'https://example.com/feed', 'https://192.0.78.12/', 'http://8.8.8.8/', 'https://[2606:4700:4700::1111]/',
    'https://[2a00:1450:4001:82a::200e]/', 'https://[64:ff9b::808:808]/', 'https://[2002:808:808::1]/',
    'https://news.sophos.com/en-us/feed/', 'https://www.ncsc.gov.uk/api/1/services/v1/all-rss-feed.xml',
  ]) assert.equal(isSafeUrl(u), true, u);
});

function withDns(answers, fn) {
  const orig = dns.lookup;
  dns.lookup = (host, opts, cb) => cb(null, answers);
  return new Promise((resolve) => fn(resolve)).finally(() => { dns.lookup = orig; });
}

test('safeLookup: IPv6-only answer pointing into ::/96 is blocked', async () => {
  const err = await withDns([{ address: '::7f00:1', family: 6 }], (done) => safeLookup('rebind.example', {}, (e) => done(e)));
  assert.ok(err && err.code === 'EBLOCKED', 'expected EBLOCKED');
});

test('safeLookup: prefers public IPv4, blocks private IPv4 answers', async () => {
  const ok = await withDns([{ address: '2606:4700::1', family: 6 }, { address: '93.184.216.34', family: 4 }],
    (done) => safeLookup('example.com', {}, (e, addr, fam) => done({ e, addr, fam })));
  assert.deepEqual(ok, { e: null, addr: '93.184.216.34', fam: 4 });
  const bad = await withDns([{ address: '93.184.216.34', family: 4 }, { address: '10.0.0.5', family: 4 }],
    (done) => safeLookup('mixed.example', {}, (e) => done(e)));
  assert.equal(bad && bad.code, 'EBLOCKED');
});

test('safeGet: redirects to internal targets are rejected', async () => {
  reset();
  state.axiosGet = async () => ({ data: '' });
  await safeGet('https://example.com/feed');
  const { beforeRedirect } = calls.axiosGet[0].config;
  assert.throws(() => beforeRedirect({ href: 'http://169.254.169.254/latest/meta-data/' }), /Blocked redirect/);
  assert.throws(() => beforeRedirect({ href: 'http://[::127.0.0.1]/' }), /Blocked redirect/);
  assert.doesNotThrow(() => beforeRedirect({ href: 'https://www.example.com/feed.xml' }));
});

test('safeGet: has a hard overall deadline (axios `timeout` is only a socket-idle timer)', async () => {
  reset();
  state.axiosGet = async () => ({ data: '' });
  await safeGet('https://example.com/feed', { timeout: 50 });
  const { signal } = calls.axiosGet[0].config;
  assert.ok(signal, 'no AbortSignal passed to axios');
  await new Promise((r) => setTimeout(r, 400));
  assert.equal(signal.aborted, true);
});

// Real-axios proof of the problem (skipped when axios isn't installed locally).
let realAxios = null;
try { realAxios = require(require.resolve('axios', { paths: ['/opt/node-tools/node_modules', process.cwd()] })); } catch { /* not installed */ }
test('axios timeout does not abort a slowly-dripping response (why the deadline is needed)', { skip: !realAxios || realAxios === require('axios') }, async () => {
  const http = require('http');
  const srv = http.createServer((req, res) => {
    res.writeHead(200);
    const iv = setInterval(() => res.write('.'), 100);
    req.on('close', () => clearInterval(iv));
  });
  await new Promise((r) => srv.listen(0, r));
  const url = `http://127.0.0.1:${srv.address().port}/`;
  const ctl = new AbortController();
  const p = realAxios.get(url, { timeout: 300, signal: ctl.signal }).then(() => 'resolved', (e) => e.code);
  const winner = await Promise.race([p, new Promise((r) => setTimeout(() => r('still pending'), 1200))]);
  ctl.abort(); await p; srv.close();
  assert.equal(winner, 'still pending');
});

test('safeGet: a request that never finishes is aborted with ETIMEDOUT', async () => {
  reset();
  state.axiosGet = (url, cfg) => new Promise((_, rej) => cfg.signal.addEventListener('abort', () => {
    const e = new Error('canceled'); e.code = 'ERR_CANCELED'; rej(e);
  }));
  const keepAlive = setTimeout(() => {}, 1000);   // AbortSignal.timeout timers are unref'd
  await assert.rejects(safeGet('https://example.com/feed', { timeout: 50 }), (e) => e.code === 'ETIMEDOUT' && /deadline/.test(e.message));
  clearTimeout(keepAlive);
});

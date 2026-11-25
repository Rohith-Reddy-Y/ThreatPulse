'use strict';
// PoC checker: finds PoC links (article page + GitHub CVE search) and validates them.
const { state, calls, reset } = require('./helpers/stubs');
const test = require('node:test');
const assert = require('node:assert/strict');
const { checkArticle, extractLinks, scanPage, findPocWording } = require('../src/poc-check');

const b64 = (s) => Buffer.from(s).toString('base64');
const now = new Date().toISOString();
const old = new Date(Date.now() - 200 * 86400000).toISOString();

// Fake web + GitHub API keyed by URL prefix
function web(routes) {
  state.axiosGet = async (url) => {
    for (const [prefix, out] of Object.entries(routes)) {
      if (url.startsWith(prefix)) {
        const o = typeof out === 'function' ? out(url) : out;
        return { status: o.status || 200, data: o.data !== undefined ? o.data : o, headers: o.headers || {} };
      }
    }
    return { status: 404, data: null, headers: {} };
  };
}
const repo = (over = {}) => ({ status: 200, data: { stargazers_count: 120, pushed_at: now, created_at: old, description: 'PoC for CVE-2026-1111', archived: false, disabled: false, fork: false, ...over } });
const contents = (names) => ({ status: 200, data: names.map((n) => ({ name: n, type: n.endsWith('/') ? 'dir' : 'file' })) });
const readme = (txt) => ({ status: 200, data: { content: b64(txt) } });
const article = (over = {}) => ({ id: 1, title: 'Exploit released for CVE-2026-1111 in Acme VPN', description: 'A proof-of-concept is now public.', url: 'https://news.example/acme', cve_id: 'CVE-2026-1111', has_poc: 1, ...over });

test('extractLinks finds repos, gists, Exploit-DB and Packet Storm, and ignores GitHub site pages', () => {
  const html = `<a href="https://github.com/alice/CVE-2026-1111-poc">x</a> <a href="https://github.com/topics/exploit">t</a>
    https://github.com/advisories/GHSA-xxxx https://gist.github.com/bob/0123456789abcdef0123
    https://www.exploit-db.com/exploits/51234 https://packetstormsecurity.com/files/180000/x.html
    https://github.com/projectdiscovery/nuclei-templates/blob/main/http/cves/2026/CVE-2026-1111.yaml`;
  const kinds = extractLinks(html).map((l) => `${l.kind}:${l.key}`);
  assert.ok(kinds.includes('github:alice/CVE-2026-1111-poc'));
  assert.ok(kinds.includes('gist:0123456789abcdef0123'));
  assert.ok(kinds.includes('exploitdb:51234'));
  assert.ok(kinds.includes('packetstorm:180000'));
  assert.ok(kinds.some((k) => k.startsWith('github:projectdiscovery/nuclei-templates#')));
  assert.ok(!kinds.some((k) => k.includes('topics') || k.includes('advisories')));
});

test('a real PoC repo linked from the article is verified (code present, CVE mentioned)', async () => {
  reset();
  web({
    'https://news.example/acme': { data: '<p>PoC: <a href="https://github.com/alice/acme-vpn-rce">repo</a></p>' },
    'https://api.github.com/repos/alice/acme-vpn-rce/contents': contents(['exploit.py', 'README.md', 'requirements.txt']),
    'https://api.github.com/repos/alice/acme-vpn-rce/readme': readme('# CVE-2026-1111 Acme VPN pre-auth RCE\nUsage: python exploit.py target'),
    'https://api.github.com/repos/alice/acme-vpn-rce': repo(),
    'https://api.github.com/search/repositories': { data: { items: [] } },
  });
  const r = await checkArticle(article());
  assert.equal(r.verdict, 'verified');
  assert.equal(r.links[0].url, 'https://github.com/alice/acme-vpn-rce');
  assert.equal(r.links[0].source, 'article');
  assert.deepEqual(r.links[0].cveMatch, ['CVE-2026-1111']);
  assert.match(r.links[0].reasons[0], /Source code present/);
});

test('a binary-only repo that sends you to a password-protected download is flagged suspicious', async () => {
  reset();
  web({
    'https://news.example/acme': { data: 'no links here' },
    'https://api.github.com/search/repositories': { data: { items: [{ full_name: 'evil/CVE-2026-1111' }] } },
    'https://api.github.com/repos/evil/CVE-2026-1111/contents': contents(['Exploit.zip', 'README.md']),
    'https://api.github.com/repos/evil/CVE-2026-1111/readme': readme('CVE-2026-1111 exploit. Download: https://mega.nz/file/abc  password: infected'),
    'https://api.github.com/repos/evil/CVE-2026-1111': repo({ stargazers_count: 0, created_at: now }),
  });
  const r = await checkArticle(article());
  assert.equal(r.verdict, 'suspicious');
  assert.equal(r.links[0].source, 'cve-search');
  assert.match(r.links[0].reasons.join(' '), /fake PoC|binaries|file host/);
});

test('search hits that do not mention the CVE are dropped; no links means verdict none', async () => {
  reset();
  web({
    'https://news.example/acme': { data: 'nothing' },
    'https://api.github.com/search/repositories': { data: { items: [{ full_name: 'random/scanner' }] } },
    'https://api.github.com/repos/random/scanner/contents': contents(['scan.py']),
    'https://api.github.com/repos/random/scanner/readme': readme('A generic scanner'),
    'https://api.github.com/repos/random/scanner': repo({ description: 'generic' }),
  });
  const r = await checkArticle(article({ title: 'Acme VPN flaw CVE-2026-1111 patched', description: 'Update to 9.2.' }));
  assert.equal(r.verdict, 'none');
  assert.equal(r.links.length, 0);
});

test('article wording alone gives verdict "mentioned" with the quoted sentence', async () => {
  reset();
  web({
    'https://news.example/acme': { data: '<html><nav>menu</nav><p>Researchers at Foo published a proof-of-concept exploit for the flaw on Tuesday.</p></html>' },
    'https://api.github.com/search/repositories': { data: { items: [] } },
  });
  const r = await checkArticle(article({ title: 'Acme VPN flaw CVE-2026-1111', description: 'Patch now.' }));
  assert.equal(r.verdict, 'mentioned');
  assert.equal(r.mentionsPoc, true);
  assert.match(r.wording[0], /published a proof-of-concept exploit/);
});

test('"no public PoC" is not counted as a PoC', async () => {
  reset();
  web({
    'https://news.example/acme': { data: '<p>The vendor said it is not aware of any public exploit. There is no PoC yet.</p>' },
    'https://api.github.com/search/repositories': { data: { items: [] } },
  });
  const r = await checkArticle(article({ title: 'Acme VPN flaw CVE-2026-1111', description: 'Patch now.' }));
  assert.equal(r.verdict, 'none');
  assert.equal(r.mentionsPoc, false);
  assert.ok(r.notes.some((n) => /no public PoC/.test(n)));
});

test('exploit links stored from NVD references are checked', async () => {
  reset();
  web({
    'https://nvd.nist.gov/vuln/detail/CVE-2026-1111': { data: 'nvd page' },
    'https://api.github.com/search/repositories': { data: { items: [] } },
    'https://api.github.com/repos/bob/acme-rce/contents': contents(['exploit.py']),
    'https://api.github.com/repos/bob/acme-rce/readme': readme('Acme RCE'),
    'https://api.github.com/repos/bob/acme-rce': repo({ description: 'Acme RCE' }),
  });
  const r = await checkArticle(article({ url: 'https://nvd.nist.gov/vuln/detail/CVE-2026-1111', title: 'CVE-2026-1111', description: 'RCE in Acme VPN.',
    poc_refs: JSON.stringify(['https://github.com/bob/acme-rce', 'https://seclists.org/fulldisclosure/2026/Nov/1']) }));
  assert.equal(r.verdict, 'verified');
  const gh = r.links.find((l) => l.kind === 'github');
  assert.equal(gh.source, 'nvd-reference');
  assert.ok(r.links.some((l) => l.kind === 'reference' && /seclists/.test(l.url)));
});

test('an unrelated GitHub link in a blog footer is not a PoC', async () => {
  reset();
  web({
    'https://news.example/acme': { data: `<p>Acme fixed a bug.</p>${'x'.repeat(3000)}<footer><a href="https://github.com/newsco/site">GitHub</a></footer>` },
    'https://api.github.com/repos/newsco/site/contents': contents(['index.js']),
    'https://api.github.com/repos/newsco/site/readme': readme('Our website'),
    'https://api.github.com/repos/newsco/site': repo({ description: 'Website source' }),
    'https://api.github.com/search/repositories': { data: { items: [] } },
  });
  const r = await checkArticle(article({ title: 'Acme update', description: 'Bug fixes.', cve_id: null }));
  assert.equal(r.verdict, 'none');
  assert.equal(r.links.length, 0);
});

test('dead links and Exploit-DB entries are classified', async () => {
  reset();
  web({
    'https://news.example/acme': { data: 'https://github.com/gone/poc https://www.exploit-db.com/exploits/51234' },
    'https://api.github.com/repos/gone/poc': { status: 404, data: null },
    'https://www.exploit-db.com/exploits/51234': { data: '<html>EDB-ID: 51234</html>' },
    'https://api.github.com/search/repositories': { data: { items: [] } },
  });
  const r = await checkArticle(article());
  assert.equal(r.verdict, 'verified', 'Exploit-DB counts as verified');
  const byKind = Object.fromEntries(r.links.map((l) => [l.kind, l.status]));
  assert.equal(byKind.exploitdb, 'verified');
  assert.equal(byKind.github, 'dead');
});

test('GitHub rate limit: stops calling GitHub, reports it, does not crash', async () => {
  reset();
  web({
    'https://news.example/acme': { data: 'https://github.com/alice/poc' },
    'https://api.github.com/search/repositories': { status: 403, data: null, headers: { 'x-ratelimit-remaining': '0' } },
  });
  const r = await checkArticle(article());
  assert.equal(r.rateLimited, true);
  assert.ok(r.notes.some((n) => /rate limit/.test(n)));
  assert.match(r.links[0].reasons[0], /rate limit/);
  assert.ok(!calls.axiosGet.some((c) => c.url.startsWith('https://api.github.com/repos/')), 'no further GitHub calls');
});

test('the checker only talks to public URLs (private article URL is not fetched)', async () => {
  reset();
  web({});
  const r = await checkArticle(article({ url: 'http://127.0.0.1/admin', cve_id: null, title: 'x', description: 'y' }));
  assert.ok(!calls.axiosGet.some((c) => c.url.startsWith('http://127.0.0.1')));
  assert.equal(r.verdict, 'none');
});

test('page scan finds technique research with no CVE: tool released on GitHub', async () => {
  reset();
  web({
    'https://blog.example/edr-bypass': { data: `<article><p>We found a new way to blind EDR by abusing kernel callbacks.</p>
      <p>We released the tool on GitHub so defenders can test the technique: <a href="https://github.com/labs/callback-blind">callback-blind</a>.</p></article>
      ${'x'.repeat(3000)}<footer><a href="https://github.com/bloglabs">GitHub</a></footer>` },
  });
  const r = await scanPage({ url: 'https://blog.example/edr-bypass', title: 'Blinding EDR with kernel callbacks', description: 'New research.' });
  assert.equal(r.fetched, true);
  assert.match(r.quotes[0], /released the tool on GitHub/);
  assert.deepEqual(r.links.map((l) => l.key), ['labs/callback-blind']);
  assert.equal(calls.axiosGet.filter((c) => c.url.includes('api.github.com')).length, 0, 'no GitHub API use');
});

test('wording: negations and tool-release phrasing', () => {
  assert.equal(findPocWording('Microsoft has not released a PoC.').quotes.length, 0);
  assert.equal(findPocWording('Follow us on GitHub for updates.').quotes.length, 0);
  assert.equal(findPocWording('The code is now available on GitHub.').quotes.length, 1);
  assert.equal(findPocWording('We published a GitHub repository with the bypass tool.').quotes.length, 1);
});

test('page scan: listing other people\'s tools, sidebars and blog-index URLs are not PoCs', async () => {
  reset();
  web({
    'https://www.synacktiv.example/aws-forensics': { data: `<nav><a href="https://github.com/Synacktiv">Github</a></nav>
      <article><p>Several tools help with enumeration. The Stratus-red-team tool covers attack techniques:
      <a href="https://github.com/DataDog/stratus-red-team">stratus</a>. We also used <a href="https://github.com/nccgroup/scoutsuite">ScoutSuite</a>.</p></article>
      <aside class="related"><p>Rikugan: free, open-source, 678 stars on GitHub. A PoC is available.</p></aside>` },
  });
  const r = await scanPage({ url: 'https://www.synacktiv.example/aws-forensics', title: 'AWS Forensics: what you need to know', description: 'Cloud forensics.' });
  assert.equal(r.fetched, true);
  assert.deepEqual(r.quotes, []);
  assert.deepEqual(r.links, []);
  reset();
  const f = await scanPage({ url: 'https://objective-see.example/blog.html#blogEntry9', title: 'Monitoring process creation', description: 'Kernel.' });
  assert.equal(f.fetched, false, 'list page with #fragment: feed text only');
  assert.equal(calls.axiosGet.length, 0);
});

/**
 * Hostile / malformed input against /api/ai/* (auth/AI suite, see run-all.sh).
 * No network: Groq/Tavily/Wikipedia go through the axios stub in tests/helpers/harness.js.
 */
process.env.AI_TIMEOUT_MS = '300';
process.env.AI_DEADLINE_MS = '1500';

const test = require('node:test');
const assert = require('node:assert/strict');
const H = require('./helpers/harness');
const { db, axiosStub, makeUser, call, groqReply } = H;

const HOSTILE = [
  ['a', 'b'], { x: 1 }, 123, -1, 1e309, true, false, null, '', ' ', 'NaN', '1e309', '-1', '0x10',
  '9'.repeat(400), 'A'.repeat(1024 * 1024), 'nul\u0000byte', '‮evil', '😀'.repeat(100), '__proto__', 'constructor',
];

let n = 0;
let ipN = 0;
const freshIp = () => `10.9.${Math.floor(++ipN / 250)}.${ipN % 250}`;

test.beforeEach(() => {
  process.env.GROQ_API_KEY = 'test-key';
  axiosStub.post = async () => groqReply('{"answer":"ok","citations":[1],"summary":"s","priority":"high","relevance":50}');
  axiosStub.get = async () => ({ data: { query: { search: [] } } });
});

test('AI routes: hostile body/param values never produce a 500 or an unhandled rejection', async () => {
  const users = [makeUser(`fuzz_a${++n}_${Date.now()}`), makeUser(`fuzz_admin${n}_${Date.now()}`, 'admin'), makeUser('guest')];
  for (const user of users) {
    for (const v of HOSTILE) {
      for (const [m, p, req] of [
        ['POST', '/summarize', { body: { articleId: v } }],
        ['POST', '/triage', { body: { articleId: v } }],
        ['POST', '/ask', { body: { question: v } }],
        ['POST', '/ask', { body: { question: 'zebracorn?', threadId: v, mode: v } }],
        ['GET', '/threads/:id', { params: { id: v } }],
        ['DELETE', '/threads/:id', { params: { id: v } }],
        ['GET', '/threads', { cookies: { tp_ai_gsid: v } }],
      ]) {
        const r = await call(m, p, { user, ip: freshIp(), ...req });
        assert.notEqual(r.statusCode, 500, `${user.username} ${m} ${p} ${JSON.stringify(req).slice(0, 80)} -> 500`);
      }
    }
  }
});

test('AI /ask: an oversized question is refused before any thread or model call', async () => {
  const u = makeUser(`fuzz_big${++n}_${Date.now()}`);
  let posts = 0;
  axiosStub.post = async () => { posts++; return groqReply('{"answer":"x"}'); };
  const before = db.getThreads(u.id).length;
  const r = await call('POST', '/ask', { user: u, ip: freshIp(), body: { question: 'q'.repeat(2 * 1024 * 1024) } });
  assert.equal(r.statusCode, 400);
  assert.equal(posts, 0);
  assert.equal(db.getThreads(u.id).length, before);
});

test('AI thread titles keep HTML as inert text (rendered via escapeHtml)', async () => {
  const u = makeUser(`fuzz_xss${++n}_${Date.now()}`);
  const r = await call('POST', '/ask', { user: u, ip: freshIp(), body: { question: '<img src=x onerror=alert(1)> zebracorn' } });
  assert.equal(r.statusCode, 200);
  const t = (await call('GET', '/threads', { user: u, ip: freshIp() })).body.threads[0];
  // Stored verbatim (the server does not HTML-encode); the client escapes on render.
  assert.equal(t.title, '<img src=x onerror=alert(1)> zebracorn'.slice(0, 60));
  assert.ok(t.title.length <= 60);
});

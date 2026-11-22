/**
 * AI assistant journeys: missing Groq key, thread create / continue / delete.
 */
const test = require('node:test');
const assert = require('node:assert/strict');
const H = require('./helpers/harness');
const { db, axiosStub, makeUser, call, groqReply } = H;

let n = 0;
const ip = () => `10.9.0.${++n}`;
const threadCount = (uid) => db.getThreads(uid).length;

test('no Groq key: RAG ask is refused up front — no orphan "question-only" chats pile up', async () => {
  delete process.env.GROQ_API_KEY;
  const u = makeUser('ai-nokey');
  for (let i = 0; i < 3; i++) {
    const r = await call('POST', '/ask', { user: u, ip: ip(), body: { question: `what about zebracorn ${i}?` } });
    assert.equal(r.statusCode, 503);
    assert.equal(r.body.success, false);
    assert.match(r.body.error, /not configured/i);
    assert.match(r.body.error, /AI Settings/);
  }
  assert.equal(threadCount(u.id), 0, 'failed asks must not leave threads behind');
});

test('thread create → continue → list → delete, with a key configured', async () => {
  process.env.GROQ_API_KEY = 'test-key';
  axiosStub.post = async () => groqReply(JSON.stringify({ answer: 'Zebracorn is a ransomware family.', citations: [], insufficientData: false }));
  const u = makeUser('ai-user');
  const first = await call('POST', '/ask', { user: u, ip: ip(), body: { question: 'what is zebracorn?' } });
  assert.equal(first.statusCode, 200);
  const tid = first.body.threadId;
  assert.ok(tid);
  const second = await call('POST', '/ask', { user: u, ip: ip(), body: { question: 'who does it target?', threadId: tid } });
  assert.equal(second.body.threadId, tid, 'follow-up stays in the same thread');
  const list = await call('GET', '/threads', { user: u });
  assert.deepEqual(list.body.threads.map(t => t.id), [tid]);
  const one = await call('GET', '/threads/:id', { user: u, params: { id: String(tid) } });
  assert.equal(one.body.thread.messages.length, 4);
  const del = await call('DELETE', '/threads/:id', { user: u, params: { id: String(tid) } });
  assert.equal(del.body.success, true);
  assert.equal(threadCount(u.id), 0);
  const gone = await call('POST', '/ask', { user: u, ip: ip(), body: { question: 'again?', threadId: tid } });
  assert.equal(gone.statusCode, 404);
});

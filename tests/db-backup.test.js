'use strict';
// SigV4 signing (checked against AWS's published S3 example) + snapshot/restore round trip
const test = require('node:test');
const assert = require('node:assert/strict');
const { sign } = require('../src/db-backup');

test('SigV4 matches the AWS S3 documentation example (GET Object with Range)', () => {
  // https://docs.aws.amazon.com/AmazonS3/latest/API/sig-v4-header-based-auth.html  "Example: GET Object"
  const h = sign({
    method: 'GET', host: 'examplebucket.s3.amazonaws.com', canonicalPath: '/test.txt',
    headers: { range: 'bytes=0-9' },
    payloadHash: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',
    region: 'us-east-1', keyId: 'AKIAIOSFODNN7EXAMPLE', secret: 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY',
    now: new Date('2013-05-24T00:00:00Z'),
  });
  assert.equal(h.authorization,
    'AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20130524/us-east-1/s3/aws4_request, ' +
    'SignedHeaders=host;range;x-amz-content-sha256;x-amz-date, ' +
    'Signature=f0e8bdb87c964420e857bd35b5d6ed310bd44f0170aba48dd91039c6036bdb41');
});

test('snapshot -> restore round trip through an S3-style endpoint (only when data changed)', async () => {
  const https = require('https');
  const { EventEmitter } = require('events');
  const fs = require('fs'), os = require('os'), path = require('path');
  const { DatabaseSync } = require('node:sqlite');
  const store = new Map();
  const seen = [];
  const realRequest = https.request;
  https.request = (opts, cb) => {
    const req = new EventEmitter();
    const chunks = [];
    req.write = (b) => chunks.push(Buffer.from(b));
    req.destroy = () => {};
    req.end = () => {
      seen.push({ method: opts.method, path: opts.path, auth: opts.headers.authorization });
      const res = new EventEmitter();
      res.statusCode = 200;
      if (opts.method === 'PUT') store.set(opts.path, Buffer.concat(chunks));
      else if (!store.has(opts.path)) res.statusCode = 404;
      cb(res);
      if (opts.method === 'GET' && store.has(opts.path)) res.emit('data', store.get(opts.path));
      res.emit('end');
    };
    return req;
  };
  Object.assign(process.env, { BACKUP_S3_ENDPOINT: 'https://s3.us-east-005.backblazeb2.com', BACKUP_S3_BUCKET: 'tp-test',
    BACKUP_S3_KEY_ID: 'kid', BACKUP_S3_SECRET: 'secret' });
  try {
    const backup = require('../src/db-backup');
    assert.equal(backup.config().region, 'us-east-005', 'region read from the endpoint');
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tpb-'));
    const src = new DatabaseSync(path.join(dir, 'a.db'));
    src.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT); INSERT INTO users (name) VALUES ('alice')");
    const db = { getDb: () => src };

    const r1 = await backup.snapshot(db);
    assert.equal(r1.uploaded, true, JSON.stringify(r1));
    assert.equal(seen[0].method, 'GET', 'first checks the store is empty (no restore ran)');
    const put = seen.find((x) => x.method === 'PUT');
    assert.equal(put.path, '/tp-test/threatpulse/threatpulse.sqlite.gz');
    assert.match(put.auth, /^AWS4-HMAC-SHA256 Credential=kid\/\d{8}\/us-east-005\/s3\/aws4_request/);
    assert.equal((await backup.snapshot(db)).uploaded, false, 'nothing changed: no upload');

    const target = path.join(dir, 'restored.db');
    const r = await backup.restore(target);
    assert.equal(r.restored, true);
    const back = new DatabaseSync(target);
    assert.equal(back.prepare('SELECT name FROM users').get().name, 'alice');
    back.close(); src.close();

    store.clear();
    assert.equal((await backup.restore(path.join(dir, 'none.db'))).restored, false, '404: fresh database');
  } finally {
    https.request = realRequest;
    for (const k of ['BACKUP_S3_ENDPOINT', 'BACKUP_S3_BUCKET', 'BACKUP_S3_KEY_ID', 'BACKUP_S3_SECRET']) delete process.env[k];
  }
});

// Fake GitHub API for the release-asset backend
function fakeGithub({ privateRepo = true, hasCommit = true } = {}) {
  const https = require('https');
  const { EventEmitter } = require('events');
  const st = { release: null, assets: new Map(), nextId: 1, log: [] };
  const real = https.request;
  https.request = (opts, cb) => {
    const req = new EventEmitter();
    const chunks = [];
    req.write = (b) => chunks.push(Buffer.from(b));
    req.destroy = () => {};
    req.end = () => {
      const body = Buffer.concat(chunks);
      const url = new URL(`https://${opts.hostname}${opts.path}`);
      st.log.push({ method: opts.method, host: opts.hostname, path: url.pathname, auth: opts.headers.Authorization });
      const res = new EventEmitter();
      res.headers = {};
      let out = null;
      const p = url.pathname;
      const rel = () => ({ id: 7, tag_name: 'threatpulse-db-backup', assets: [...st.assets.values()].map(({ id, name }) => ({ id, name })) });
      if (opts.hostname === 'objects.example' ) { res.statusCode = 200; out = st.assets.get(Number(url.searchParams.get('id'))).data; }
      else if (p === '/repos/me/tp-backup/releases/tags/threatpulse-db-backup') { if (st.release) { res.statusCode = 200; out = rel(); } else { res.statusCode = 404; out = { message: 'Not Found' }; } }
      else if (p === '/repos/me/tp-backup' ) { res.statusCode = 200; out = { private: privateRepo }; }
      else if (p === '/repos/me/tp-backup/releases' && opts.method === 'POST') { if (hasCommit) { st.release = true; res.statusCode = 201; out = rel(); } else { res.statusCode = 422; out = { message: 'Validation Failed' }; } }
      else if (p === '/repos/me/tp-backup/releases/7/assets' && opts.method === 'POST') {
        const id = st.nextId++; st.assets.set(id, { id, name: url.searchParams.get('name'), data: body }); res.statusCode = 201; out = { id };
      } else if (p.startsWith('/repos/me/tp-backup/releases/assets/')) {
        const id = Number(p.split('/').pop());
        if (opts.method === 'DELETE') { st.assets.delete(id); res.statusCode = 204; out = ''; }
        else { res.statusCode = 302; res.headers.location = `https://objects.example/x?id=${id}`; out = ''; }
      } else { res.statusCode = 404; out = { message: 'nope' }; }
      res.resume = () => {};
      cb(res);
      const buf = Buffer.isBuffer(out) ? out : Buffer.from(typeof out === 'string' ? out : JSON.stringify(out));
      if (buf.length) res.emit('data', buf);
      res.emit('end');
    };
    return req;
  };
  return { st, restore: () => { https.request = real; } };
}

test('GitHub private repo backend: snapshot to a release asset, restore it, keep only the newest 3', async () => {
  const fs = require('fs'), os = require('os'), path = require('path');
  const { DatabaseSync } = require('node:sqlite');
  const gh = fakeGithub();
  Object.assign(process.env, { BACKUP_GITHUB_REPO: 'me/tp-backup', GITHUB_TOKEN: 'ghp_test' });
  try {
    const backup = require('../src/db-backup');
    backup._reset();
    const c = backup.config();
    assert.equal(c.store, 'github');
    assert.equal(c.enabled, true);
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tpg-'));
    const src = new DatabaseSync(path.join(dir, 'a.db'));
    src.exec("CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT); INSERT INTO users (name) VALUES ('alice')");
    const db = { getDb: () => src };
    assert.equal((await backup.restore(path.join(dir, 'empty.db'))).restored, false, 'no release yet');
    for (let i = 0; i < 5; i++) {
      src.exec(`INSERT INTO users (name) VALUES ('u${i}')`);
      const r = await backup.snapshot(db);
      assert.equal(r.uploaded, true, JSON.stringify(r));
      await new Promise((ok) => setTimeout(ok, 1100));    // asset names are per-second timestamps
    }
    assert.equal(gh.st.assets.size, 3, 'old snapshots deleted');
    const target = path.join(dir, 'restored.db');
    assert.equal((await backup.restore(target)).restored, true);
    const back = new DatabaseSync(target);
    assert.equal(back.prepare('SELECT COUNT(*) AS n FROM users').get().n, 6, 'newest snapshot restored');
    back.close(); src.close();
    // the token is never sent to the redirect (download) host
    assert.ok(gh.st.log.filter((l) => l.host === 'objects.example').every((l) => !l.auth));
    assert.ok(gh.st.log.filter((l) => l.host === 'api.github.com').every((l) => l.auth === 'Bearer ghp_test'));
  } finally {
    gh.restore();
    delete process.env.BACKUP_GITHUB_REPO; delete process.env.GITHUB_TOKEN;
  }
});

test('GitHub backend refuses a public repo, and never overwrites a snapshot it could not restore', async () => {
  const fs = require('fs'), os = require('os'), path = require('path');
  const { DatabaseSync } = require('node:sqlite');
  Object.assign(process.env, { BACKUP_GITHUB_REPO: 'me/tp-backup', GITHUB_TOKEN: 'ghp_test' });
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'tpg2-'));
  const src = new DatabaseSync(path.join(dir, 'a.db'));
  src.exec('CREATE TABLE t (x)');
  const db = { getDb: () => src };
  const backup = require('../src/db-backup');
  let gh = fakeGithub({ privateRepo: false });
  try {
    backup._reset();
    const r = await backup.snapshot(db);
    assert.equal(r.uploaded, false);
  } finally { gh.restore(); }

  gh = fakeGithub();
  try {
    gh.st.release = true;
    gh.st.assets.set(99, { id: 99, name: 'threatpulse-20260101T000000Z.sqlite.gz', data: Buffer.from('good backup') });
    backup._reset();   // as if the restore at startup had failed
    const r = await backup.snapshot(db, { force: true });
    assert.equal(r.blocked, true);
    assert.equal(gh.st.assets.size, 1, 'existing snapshot untouched');
  } finally {
    gh.restore(); src.close();
    delete process.env.BACKUP_GITHUB_REPO; delete process.env.GITHUB_TOKEN;
  }
});

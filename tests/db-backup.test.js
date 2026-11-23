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
    assert.equal(seen[0].method, 'PUT');
    assert.equal(seen[0].path, '/tp-test/threatpulse/threatpulse.sqlite.gz');
    assert.match(seen[0].auth, /^AWS4-HMAC-SHA256 Credential=kid\/\d{8}\/us-east-005\/s3\/aws4_request/);
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

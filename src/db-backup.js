/**
 * ThreatPulse — keep the SQLite database across restarts (free-tier hosting)
 *
 * Render's free plan has no persistent disk: every deploy / restart starts with
 * an empty /tmp. This module stores a compressed snapshot of the database in any
 * S3-compatible bucket (Backblaze B2's free 10 GB works) and:
 *   - restores the latest snapshot on start, before the database is opened
 *   - uploads a new snapshot every BACKUP_INTERVAL_MIN minutes when data changed
 *   - uploads a final snapshot on SIGTERM (Render sends it before stopping)
 *
 * Env: BACKUP_S3_ENDPOINT (e.g. https://s3.us-east-005.backblazeb2.com),
 *      BACKUP_S3_REGION (e.g. us-east-005), BACKUP_S3_BUCKET,
 *      BACKUP_S3_KEY_ID, BACKUP_S3_SECRET, optional BACKUP_S3_PREFIX, BACKUP_INTERVAL_MIN.
 * No extra packages: requests are signed with AWS Signature V4 here.
 */
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');
const zlib = require('zlib');
const https = require('https');

const EMPTY_SHA = crypto.createHash('sha256').update('').digest('hex');

function config() {
  const c = {
    endpoint: (process.env.BACKUP_S3_ENDPOINT || '').replace(/\/+$/, ''),
    region: process.env.BACKUP_S3_REGION || '',
    bucket: process.env.BACKUP_S3_BUCKET || '',
    keyId: process.env.BACKUP_S3_KEY_ID || '',
    secret: process.env.BACKUP_S3_SECRET || '',
    prefix: (process.env.BACKUP_S3_PREFIX || 'threatpulse').replace(/^\/+|\/+$/g, ''),
    intervalMin: Math.max(2, parseInt(process.env.BACKUP_INTERVAL_MIN, 10) || 10),
  };
  if (!c.region) { const m = /s3\.([a-z0-9-]+)\./.exec(c.endpoint); if (m) c.region = m[1]; }
  c.enabled = !!(/^https:\/\//.test(c.endpoint) && c.bucket && c.keyId && c.secret && c.region);
  return c;
}

// ── AWS Signature Version 4 (path-style URLs) ──
const hmac = (key, data) => crypto.createHmac('sha256', key).update(data).digest();
const sha256hex = (data) => crypto.createHash('sha256').update(data).digest('hex');
const encodeKey = (k) => k.split('/').map((p) => encodeURIComponent(p).replace(/[!'()*]/g, (ch) => '%' + ch.charCodeAt(0).toString(16).toUpperCase())).join('/');

/**
 * Sign a request. Returns the headers to send (including Authorization).
 * `host` and `canonicalPath` describe the URL; headers are lower-cased.
 */
function sign({ method, host, canonicalPath, query = '', headers = {}, payloadHash, region, keyId, secret, service = 's3', now = new Date() }) {
  const amzDate = now.toISOString().replace(/[:-]|\.\d{3}/g, '');           // YYYYMMDDTHHMMSSZ
  const date = amzDate.slice(0, 8);
  const h = { ...headers, host, 'x-amz-date': amzDate, 'x-amz-content-sha256': payloadHash };
  const names = Object.keys(h).map((k) => k.toLowerCase()).sort();
  const lower = Object.fromEntries(Object.entries(h).map(([k, v]) => [k.toLowerCase(), String(v).trim().replace(/\s+/g, ' ')]));
  const canonicalHeaders = names.map((n) => `${n}:${lower[n]}\n`).join('');
  const signedHeaders = names.join(';');
  const canonicalRequest = [method, canonicalPath, query, canonicalHeaders, signedHeaders, payloadHash].join('\n');
  const scope = `${date}/${region}/${service}/aws4_request`;
  const stringToSign = ['AWS4-HMAC-SHA256', amzDate, scope, sha256hex(canonicalRequest)].join('\n');
  const kDate = hmac(`AWS4${secret}`, date);
  const kSigning = hmac(hmac(hmac(kDate, region), service), 'aws4_request');
  const signature = crypto.createHmac('sha256', kSigning).update(stringToSign).digest('hex');
  return { ...lower, authorization: `AWS4-HMAC-SHA256 Credential=${keyId}/${scope}, SignedHeaders=${signedHeaders}, Signature=${signature}` };
}

function request(c, method, key, body) {
  const url = new URL(c.endpoint);
  const canonicalPath = `/${encodeURIComponent(c.bucket)}/${encodeKey(key)}`;
  const payloadHash = body ? sha256hex(body) : EMPTY_SHA;
  const extra = body ? { 'content-type': 'application/octet-stream', 'content-length': String(body.length) } : {};
  const headers = sign({ method, host: url.host, canonicalPath, headers: extra, payloadHash, region: c.region, keyId: c.keyId, secret: c.secret });
  delete headers.host;
  return new Promise((resolve, reject) => {
    const req = https.request({ method, hostname: url.hostname, port: url.port || 443, path: canonicalPath, headers, timeout: 60000 }, (res) => {
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => resolve({ status: res.statusCode, body: Buffer.concat(chunks) }));
    });
    req.on('timeout', () => req.destroy(new Error('backup request timed out')));
    req.on('error', reject);
    if (body) req.write(body);
    req.end();
  });
}

const objectKey = (c) => `${c.prefix}/threatpulse.sqlite.gz`;

/** Restore the latest snapshot into dbPath (call before the database is opened). */
async function restore(dbPath) {
  const c = config();
  if (!c.enabled) { console.log('[Backup] Not configured: database starts empty on every restart (set BACKUP_S3_* to keep data)'); return { restored: false }; }
  if (dbPath === ':memory:') return { restored: false };
  try {
    const r = await request(c, 'GET', objectKey(c));
    if (r.status === 404) { console.log('[Backup] No snapshot yet: starting a new database'); return { restored: false }; }
    if (r.status !== 200) { console.error(`[Backup] Restore failed: HTTP ${r.status} ${r.body.toString('utf8').slice(0, 200)}`); return { restored: false, error: r.status }; }
    const raw = zlib.gunzipSync(r.body);
    if (raw.subarray(0, 16).toString('latin1') !== 'SQLite format 3\u0000') throw new Error('snapshot is not an SQLite file');
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    for (const ext of ['', '-wal', '-shm']) { try { fs.unlinkSync(dbPath + ext); } catch { /* none */ } }
    fs.writeFileSync(dbPath, raw);
    console.log(`[Backup] Restored database snapshot (${(raw.length / 1048576).toFixed(1)} MB) ✓`);
    return { restored: true, bytes: raw.length };
  } catch (e) {
    console.error('[Backup] Restore error:', e.message);
    return { restored: false, error: e.message };
  }
}

let lastChanges = -1;
let running = false;

/** Upload a snapshot if the data changed since the last one (force = always). */
async function snapshot(db, { force = false } = {}) {
  const c = config();
  if (!c.enabled || running) return { uploaded: false };
  running = true;
  const tmp = path.join(os.tmpdir(), `tp-snapshot-${process.pid}.db`);
  try {
    const d = db.getDb();
    const changes = d.prepare('SELECT total_changes() AS n').get().n;
    if (!force && changes === lastChanges) return { uploaded: false, unchanged: true };
    try { fs.unlinkSync(tmp); } catch { /* none */ }
    d.exec(`VACUUM INTO '${tmp.replace(/'/g, "''")}'`);              // consistent copy, no lock held for long
    const gz = zlib.gzipSync(fs.readFileSync(tmp), { level: 6 });
    const r = await request(c, 'PUT', objectKey(c), gz);
    if (r.status !== 200) throw new Error(`HTTP ${r.status} ${r.body.toString('utf8').slice(0, 200)}`);
    lastChanges = changes;
    return { uploaded: true, bytes: gz.length };
  } catch (e) {
    console.error('[Backup] Snapshot failed:', e.message);
    return { uploaded: false, error: e.message };
  } finally {
    running = false;
    try { fs.unlinkSync(tmp); } catch { /* none */ }
  }
}

/** Periodic snapshots + a final one on SIGTERM. */
function schedule(db) {
  const c = config();
  if (!c.enabled) return false;
  setInterval(() => { snapshot(db).then((r) => { if (r.uploaded) console.log(`[Backup] Snapshot saved (${(r.bytes / 1048576).toFixed(1)} MB gz)`); }); }, c.intervalMin * 60 * 1000).unref();
  let stopping = false;
  process.on('SIGTERM', async () => {
    if (stopping) return;
    stopping = true;
    console.log('[Backup] SIGTERM: saving a final snapshot…');
    const t = setTimeout(() => process.exit(0), 25000);                 // Render allows ~30 s
    const r = await snapshot(db, { force: true });
    console.log(r.uploaded ? '[Backup] Final snapshot saved ✓' : '[Backup] Final snapshot not saved');
    clearTimeout(t);
    process.exit(0);
  });
  console.log(`[Backup] Snapshots every ${c.intervalMin} min (when data changed) and on shutdown ✓`);
  return true;
}

module.exports = { restore, snapshot, schedule, sign, config, _encodeKey: encodeKey };

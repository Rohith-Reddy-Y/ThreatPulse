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
 * Two places to keep it (no extra packages either way):
 *  - a PRIVATE GitHub repo (free, no card): the snapshot is a release asset.
 *      Env: BACKUP_GITHUB_REPO (owner/repo), token from BACKUP_GITHUB_TOKEN or GITHUB_TOKEN
 *      (fine-grained token, that repo only, Contents: Read and write).
 *  - any S3-compatible bucket (Backblaze B2, Cloudflare R2, ...), signed with AWS SigV4 here.
 *      Env: BACKUP_S3_ENDPOINT (e.g. https://s3.us-east-005.backblazeb2.com),
 *      BACKUP_S3_REGION (e.g. us-east-005), BACKUP_S3_BUCKET,
 *      BACKUP_S3_KEY_ID, BACKUP_S3_SECRET, optional BACKUP_S3_PREFIX.
 * Optional: BACKUP_INTERVAL_MIN (default 10).
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
  const repo = String(process.env.BACKUP_GITHUB_REPO || '').trim().replace(/^https:\/\/github\.com\//i, '').replace(/\.git$/, '').replace(/\/+$/, '');
  const ghToken = String(process.env.BACKUP_GITHUB_TOKEN || process.env.GITHUB_TOKEN || '').trim();
  if (/^[A-Za-z0-9-]{1,39}\/[\w.-]{1,100}$/.test(repo) && ghToken) {
    c.store = 'github';
    c.repo = repo;
    c.ghToken = ghToken;
    c.enabled = true;
  } else {
    c.store = 's3';
    c.enabled = !!(/^https:\/\//.test(c.endpoint) && c.bucket && c.keyId && c.secret && c.region);
  }
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

// ── GitHub backend: snapshots are assets of one release in a private repo ──
const GH_TAG = 'threatpulse-db-backup';
const GH_ASSET_RE = /^threatpulse-\d{8}T\d{6}Z\.sqlite\.gz$/;
const KEEP_ASSETS = 3;

// https request with JSON / buffer bodies; follows redirects (dropping auth on another host)
function ghFetch(c, method, url, { body = null, headers = {}, raw = false, redirects = 3 } = {}) {
  const u = new URL(url);
  const sameHost = /(^|\.)github\.com$/i.test(u.hostname);
  const h = { 'User-Agent': 'ThreatPulse-Backup', 'X-GitHub-Api-Version': '2022-11-28', Accept: 'application/vnd.github+json', ...headers };
  if (sameHost) h.Authorization = `Bearer ${c.ghToken}`;
  let payload = null;
  if (body !== null) {
    payload = Buffer.isBuffer(body) ? body : Buffer.from(JSON.stringify(body));
    if (!Buffer.isBuffer(body)) h['Content-Type'] = 'application/json';
    h['Content-Length'] = String(payload.length);
  }
  return new Promise((resolve, reject) => {
    const req = https.request({ method, hostname: u.hostname, port: u.port || 443, path: u.pathname + u.search, headers: h, timeout: 120000 }, (res) => {
      if ([301, 302, 303, 307, 308].includes(res.statusCode) && res.headers.location && redirects > 0) {
        res.resume();
        const next = new URL(res.headers.location, url).href;
        resolve(ghFetch(c, 'GET', next, { headers: { Accept: headers.Accept || 'application/octet-stream' }, raw, redirects: redirects - 1 }));
        return;
      }
      const chunks = [];
      res.on('data', (d) => chunks.push(d));
      res.on('end', () => {
        const buf = Buffer.concat(chunks);
        let json = null;
        if (!raw) { try { json = JSON.parse(buf.toString('utf8') || 'null'); } catch { json = null; } }
        resolve({ status: res.statusCode, body: buf, json });
      });
    });
    req.on('timeout', () => req.destroy(new Error('backup request timed out')));
    req.on('error', reject);
    if (payload) req.write(payload);
    req.end();
  });
}
const ghApi = (c, p) => `https://api.github.com/repos/${c.repo}${p}`;
const ghErr = (r, what) => {
  const msg = (r.json && r.json.message) || r.body.toString('utf8').slice(0, 160);
  if (r.status === 401) return `${what}: GitHub rejected the token (check BACKUP_GITHUB_TOKEN / GITHUB_TOKEN)`;
  if (r.status === 403 || r.status === 404) return `${what}: no access to the backup repo (the token needs Contents: Read and write on it) [${r.status} ${msg}]`;
  return `${what}: HTTP ${r.status} ${msg}`;
};

async function ghRelease(c, create) {
  const r = await ghFetch(c, 'GET', ghApi(c, `/releases/tags/${GH_TAG}`));
  if (r.status === 200 && r.json) return r.json;
  if (r.status !== 404) throw new Error(ghErr(r, 'Read backup release'));
  const repo = await ghFetch(c, 'GET', ghApi(c, ''));
  if (repo.status !== 200) throw new Error(ghErr(repo, 'Open repo'));
  if (repo.json && repo.json.private === false) throw new Error(`${c.repo} is public: use a PRIVATE repo for database backups`);
  if (!create) return null;
  const cr = await ghFetch(c, 'POST', ghApi(c, '/releases'), { body: {
    tag_name: GH_TAG, name: 'ThreatPulse database backup', draft: false, prerelease: true,
    body: 'Automatic SQLite snapshots from ThreatPulse. Do not delete this release.' } });
  if (cr.status === 201 && cr.json) return cr.json;
  if (cr.status === 422) throw new Error('Could not create the backup release: the repo needs at least one commit (create it with "Add a README")');
  throw new Error(ghErr(cr, 'Create backup release'));
}

async function getBlob(c) {
  if (c.store !== 'github') {
    const r = await request(c, 'GET', objectKey(c));
    if (r.status === 404) return null;
    if (r.status !== 200) throw new Error(`HTTP ${r.status} ${r.body.toString('utf8').slice(0, 200)}`);
    return r.body;
  }
  const rel = await ghRelease(c, false);
  if (!rel) return null;
  const assets = (rel.assets || []).filter((a) => GH_ASSET_RE.test(a.name)).sort((a, b) => b.name.localeCompare(a.name));
  for (const a of assets) {                         // newest first; fall back to an older one if a download fails
    const r = await ghFetch(c, 'GET', ghApi(c, `/releases/assets/${a.id}`), { headers: { Accept: 'application/octet-stream' }, raw: true });
    if (r.status === 200 && r.body.length) return r.body;
    console.error(`[Backup] Could not download ${a.name}: HTTP ${r.status}`);
  }
  return null;
}

async function putBlob(c, gz) {
  if (c.store !== 'github') {
    const r = await request(c, 'PUT', objectKey(c), gz);
    if (r.status !== 200) throw new Error(`HTTP ${r.status} ${r.body.toString('utf8').slice(0, 200)}`);
    return;
  }
  const rel = await ghRelease(c, true);
  const name = `threatpulse-${new Date().toISOString().replace(/[:-]|\.\d{3}/g, '')}.sqlite.gz`;
  const up = await ghFetch(c, 'POST', `https://uploads.github.com/repos/${c.repo}/releases/${rel.id}/assets?name=${encodeURIComponent(name)}`,
    { body: gz, headers: { 'Content-Type': 'application/gzip' } });
  if (up.status !== 201) throw new Error(ghErr(up, 'Upload snapshot'));
  // keep the newest few snapshots, delete the rest
  const old = (rel.assets || []).filter((a) => GH_ASSET_RE.test(a.name) && a.name !== name).sort((a, b) => b.name.localeCompare(a.name)).slice(KEEP_ASSETS - 1);
  for (const a of old) {
    try { await ghFetch(c, 'DELETE', ghApi(c, `/releases/assets/${a.id}`)); } catch { /* next time */ }
  }
}

// Uploads are allowed once we know we won't overwrite a good snapshot with an
// empty database (i.e. the restore worked, or the store really has no snapshot).
let safeToUpload = false;

/** Restore the latest snapshot into dbPath (call before the database is opened). */
async function restore(dbPath) {
  const c = config();
  if (!c.enabled) { console.log('[Backup] Not configured: database starts empty on every restart (set BACKUP_GITHUB_REPO or BACKUP_S3_* to keep data)'); return { restored: false }; }
  if (dbPath === ':memory:') return { restored: false };
  try {
    const blob = await getBlob(c);
    if (!blob) { safeToUpload = true; console.log(`[Backup] No snapshot yet in ${c.store === 'github' ? c.repo : c.bucket}: starting a new database`); return { restored: false }; }
    const raw = zlib.gunzipSync(blob);
    if (raw.subarray(0, 16).toString('latin1') !== 'SQLite format 3\u0000') throw new Error('snapshot is not an SQLite file');
    fs.mkdirSync(path.dirname(dbPath), { recursive: true });
    for (const ext of ['', '-wal', '-shm']) { try { fs.unlinkSync(dbPath + ext); } catch { /* none */ } }
    fs.writeFileSync(dbPath, raw);
    safeToUpload = true;
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
    if (!safeToUpload) {
      // The restore failed (network, bad token...). Only upload if the store is really empty.
      let existing = null;
      try { existing = await getBlob(c); } catch (e) { return { uploaded: false, error: `store not reachable: ${e.message}` }; }
      if (existing) {
        console.error('[Backup] A snapshot exists but was not restored at startup; not overwriting it. Restart the service to restore it.');
        return { uploaded: false, blocked: true };
      }
      safeToUpload = true;
    }
    try { fs.unlinkSync(tmp); } catch { /* none */ }
    d.exec(`VACUUM INTO '${tmp.replace(/'/g, "''")}'`);              // consistent copy, no lock held for long
    const gz = zlib.gzipSync(fs.readFileSync(tmp), { level: 6 });
    await putBlob(c, gz);
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
  console.log(`[Backup] Snapshots to ${c.store === 'github' ? `GitHub repo ${c.repo}` : `bucket ${c.bucket}`} every ${c.intervalMin} min (when data changed) and on shutdown ✓`);
  return true;
}

module.exports = { restore, snapshot, schedule, sign, config, _encodeKey: encodeKey, _reset() { safeToUpload = false; lastChanges = -1; } };

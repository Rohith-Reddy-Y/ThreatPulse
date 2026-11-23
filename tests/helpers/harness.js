/**
 * Test harness for the AI routes — runs with no node_modules and no network.
 *  - better-sqlite3 -> thin shim over Node 22's built-in node:sqlite
 *  - axios          -> programmable stub (tests set axiosStub.post / axiosStub.get)
 *  - express        -> minimal Router that records handlers
 *  - src/auth.js    -> stub (route handlers are invoked directly with req.user set)
 * Uses the REAL src/database.js against a temp DB file.
 */
const Module = require('module');
const path = require('path');
const fs = require('fs');
const os = require('os');

const ROOT = path.resolve(__dirname, '..', '..');

// ---- better-sqlite3 shim ----
const { DatabaseSync } = require('node:sqlite');
class Database {
  constructor(file) { this._d = new DatabaseSync(file); }
  prepare(sql) {
    const st = this._d.prepare(sql);
    const norm = a => a.map(v => (typeof v === 'boolean' ? (v ? 1 : 0) : v === undefined ? null : v));
    return {
      get: (...a) => st.get(...norm(a)),
      all: (...a) => st.all(...norm(a)),
      run: (...a) => {
        const r = st.run(...norm(a));
        return { changes: Number(r.changes), lastInsertRowid: Number(r.lastInsertRowid) };
      }
    };
  }
  exec(s) { this._d.exec(s); return this; }
  pragma(s) { try { this._d.exec('PRAGMA ' + s); } catch (e) { /* ignore */ } }
  transaction(fn) {
    return (...a) => {
      this._d.exec('BEGIN');
      try { const r = fn(...a); this._d.exec('COMMIT'); return r; } catch (e) { this._d.exec('ROLLBACK'); throw e; }
    };
  }
  close() { this._d.close(); }
}

// ---- axios stub ----
const axiosStub = {
  calls: [],
  post: async () => { throw new Error('axios.post not stubbed'); },
  get: async () => { throw new Error('axios.get not stubbed'); }
};
const axiosModule = {
  post: (...a) => { axiosStub.calls.push(['post', ...a]); return axiosStub.post(...a); },
  get: (...a) => { axiosStub.calls.push(['get', ...a]); return axiosStub.get(...a); }
};

// ---- express stub ----
function Router() {
  const routes = [];
  const r = {};
  for (const m of ['get', 'post', 'put', 'delete', 'use']) {
    r[m] = (p, ...handlers) => { routes.push({ method: m.toUpperCase(), path: p, handlers }); return r; };
  }
  r._routes = routes;
  return r;
}
const expressModule = Object.assign(() => ({}), { Router });

const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (request === 'better-sqlite3') return Database;
  if (request === 'axios') return axiosModule;
  if (request === 'express') return expressModule;
  return origLoad.apply(this, arguments);
};

// ---- temp DB ----
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'tp-ai-test-'));
process.env.DB_PATH = path.join(tmp, 'test.db');
delete process.env.GROQ_API_KEY;
delete process.env.TAVILY_API_KEY;

// ---- auth stub (handlers are called directly) ----
const authPath = require.resolve(path.join(ROOT, 'src', 'auth.js'));
require.cache[authPath] = {
  id: authPath, filename: authPath, loaded: true,
  exports: { requireAuth: (req, res, next) => next(), requireAdmin: (req, res, next) => next() }
};

// Silence noisy logs from the code under test.
console.warn = () => {};
console.log = () => {};
const origError = console.error;
console.error = (...a) => { if (process.env.TEST_VERBOSE) origError(...a); };

const db = require(path.join(ROOT, 'src', 'database.js'));
db.getDb();

function makeUser(username, role = 'analyst') {
  const existing = db.getUserByUsername(username);
  if (existing) return { id: existing.id, username, role: existing.role };
  const r = db.createUser(username, username, 'x', 'y', role, null, null);
  if (!r.success) throw new Error('createUser failed: ' + r.error);
  return { id: r.id, username, role };
}

let router = null;
function loadRouter() {
  if (!router) router = require(path.join(ROOT, 'src', 'routes', 'ai.js'));
  return router;
}

/**
 * Invoke a route like Express would (runs the whole middleware chain).
 */
function call(method, routePath, { user, body = {}, params = {}, ip = '10.0.0.1', cookies = {}, headers = {} } = {}) {
  const r = loadRouter();
  const route = r._routes.find(x => x.method === method && x.path === routePath);
  if (!route) throw new Error(`no route ${method} ${routePath}`);
  return new Promise((resolve, reject) => {
    const res = {
      statusCode: 200, body: undefined, headers: {}, cookies: {},
      status(c) { this.statusCode = c; return this; },
      setHeader(k, v) { this.headers[k.toLowerCase()] = v; },
      cookie(name, val, opts) { this.cookies[name] = { val, opts }; return this; },
      json(b) { this.body = b; resolve(this); return this; },
      send(b) { this.body = b; resolve(this); return this; }
    };
    const req = { method, user, body, params, ip, cookies, headers, secure: false };
    const chain = route.handlers.slice();
    const next = (err) => {
      if (err) return reject(err);
      const h = chain.shift();
      if (!h) return reject(new Error('chain ended without response'));
      try {
        const p = h(req, res, next);
        if (p && p.catch) p.catch(reject);
      } catch (e) { reject(e); }
    };
    next();
  });
}

function groqReply(content) {
  return { data: { choices: [{ message: { content } }] } };
}

function httpError(status, message) {
  const e = new Error(`Request failed with status code ${status}`);
  e.response = { status, data: { error: { message: message || '' } } };
  return e;
}

module.exports = { db, axiosStub, makeUser, call, loadRouter, groqReply, httpError, ROOT };

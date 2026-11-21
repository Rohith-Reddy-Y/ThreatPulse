'use strict';
// Test-only shim: mimics the subset of the better-sqlite3 API ThreatPulse uses,
// backed by Node's built-in node:sqlite (no native module / network needed).
const { DatabaseSync } = require('node:sqlite');

// Count positional "?" parameters outside string literals / identifiers / comments.
function countParams(sql) {
  let n = 0;
  for (let i = 0; i < sql.length; i++) {
    const c = sql[i];
    if (c === "'" || c === '"' || c === '`') {
      const q = c; i++;
      while (i < sql.length && !(sql[i] === q && sql[i + 1] !== q)) { if (sql[i] === q) i++; i++; }
    } else if (c === '-' && sql[i + 1] === '-') {
      while (i < sql.length && sql[i] !== '\n') i++;
    } else if (c === '?') n++;
  }
  return n;
}

function convert(v, i) {
  // better-sqlite3: undefined/null -> NULL; numbers, strings, bigints, buffers ok; anything else throws
  if (v === undefined || v === null) return null;
  if (typeof v === 'number' || typeof v === 'string' || typeof v === 'bigint' || Buffer.isBuffer(v)) return v;
  throw new TypeError('SQLite3 can only bind numbers, strings, bigints, buffers, and null');
}

class Statement {
  constructor(db, sql) {
    this.sql = sql;
    this._stmt = db.prepare(sql);
    this._n = countParams(sql);
  }
  _bind(params) {
    if (params.length > this._n) throw new RangeError('Too many parameter values were provided');
    if (params.length < this._n) throw new RangeError('Too few parameter values were provided');
    return params.map(convert);
  }
  run(...p) {
    const r = this._stmt.run(...this._bind(p));
    return { changes: Number(r.changes), lastInsertRowid: Number(r.lastInsertRowid) };
  }
  get(...p) { const r = this._stmt.get(...this._bind(p)); return r ? { ...r } : undefined; }
  all(...p) { return this._stmt.all(...this._bind(p)).map(r => ({ ...r })); }
}

class Database {
  constructor(path) {
    this._db = new DatabaseSync(path);
    this._depth = 0;
    this.open = true;
  }
  prepare(sql) { return new Statement(this._db, sql); }
  exec(sql) { this._db.exec(sql); return this; }
  pragma(str) {
    const rows = this._db.prepare('PRAGMA ' + str).all();
    return rows.map(r => ({ ...r }));
  }
  transaction(fn) {
    const self = this;
    return function (...args) {
      const sp = 'sp' + self._depth;
      const outer = self._depth === 0;
      self._db.exec(outer ? 'BEGIN' : `SAVEPOINT ${sp}`);
      self._depth++;
      try {
        const r = fn.apply(this, args);
        self._depth--;
        self._db.exec(outer ? 'COMMIT' : `RELEASE ${sp}`);
        return r;
      } catch (e) {
        self._depth--;
        self._db.exec(outer ? 'ROLLBACK' : `ROLLBACK TO ${sp}; RELEASE ${sp}`);
        throw e;
      }
    };
  }
  close() { this._db.close(); this.open = false; }
}

module.exports = Database;

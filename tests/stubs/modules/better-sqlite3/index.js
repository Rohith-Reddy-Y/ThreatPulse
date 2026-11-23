// Test-only stand-in for better-sqlite3, built on Node 22's node:sqlite.
'use strict';
const { DatabaseSync } = require('node:sqlite');

function norm(args) {
  return args.map(a => (typeof a === 'boolean' ? (() => { throw new TypeError('SQLite3 can only bind numbers, strings, bigints, buffers, and null'); })() : a));
}

class Statement {
  constructor(stmt) { this.stmt = stmt; }
  run(...a) { const r = this.stmt.run(...norm(a)); return { changes: Number(r.changes), lastInsertRowid: Number(r.lastInsertRowid) }; }
  get(...a) { const r = this.stmt.get(...norm(a)); return r === undefined ? undefined : { ...r }; }
  all(...a) { return this.stmt.all(...norm(a)).map(r => ({ ...r })); }
}

class Database {
  constructor(file) { this.db = new DatabaseSync(file); }
  prepare(sql) { return new Statement(this.db.prepare(sql)); }
  exec(sql) { this.db.exec(sql); return this; }
  pragma(p) { try { return this.db.prepare(`PRAGMA ${p}`).all(); } catch { this.db.exec(`PRAGMA ${p}`); return []; } }
  transaction(fn) {
    const self = this;
    return function (...args) {
      self.db.exec('BEGIN');
      try { const r = fn.apply(this, args); self.db.exec('COMMIT'); return r; }
      catch (e) { self.db.exec('ROLLBACK'); throw e; }
    };
  }
  close() { this.db.close(); }
}
module.exports = Database;

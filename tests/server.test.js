/**
 * server.js wiring tests — loads server.js against stubbed express / feeds.
 */
'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
require('./helpers'); // sets NODE_PATH stubs, temp DB, quiet console

const ROOT = path.join(__dirname, '..');
// Keep the feed machinery out of it
const stub = (rel, exportsObj) => {
  const file = require.resolve(path.join(ROOT, rel));
  require.cache[file] = { id: file, filename: file, loaded: true, exports: exportsObj };
};
stub('src/feeds/aggregator', { setOnFetchComplete() {}, fetchAllSources: async () => ({}), startScheduler() {}, getStatus: () => ({}) });
stub('src/feeds/default-sources', { seedDefaultSources() {} });
stub('src/routes/ai', require('express').Router());

require(path.join(ROOT, 'server.js'));
const app = require('express').lastApp;

function errorHandler() {
  const e = app.stack.find(m => m.kind === 'use' && typeof m.args[m.args.length - 1] === 'function' && m.args[m.args.length - 1].length === 4);
  return e.args[e.args.length - 1];
}
function fakeRes() {
  return { statusCode: 200, status(c) { this.statusCode = c; return this; }, json(b) { this.body = b; return this; } };
}

test('malformed JSON bodies get a 400, not a 500', () => {
  const err = Object.assign(new SyntaxError('Unexpected token } in JSON'), { status: 400, statusCode: 400, type: 'entity.parse.failed', expose: true });
  const res = fakeRes();
  errorHandler()(err, {}, res, () => {});
  assert.strictEqual(res.statusCode, 400);
});

test('oversized bodies get a 413, not a 500', () => {
  const err = Object.assign(new Error('request entity too large'), { status: 413, statusCode: 413, type: 'entity.too.large', expose: true });
  const res = fakeRes();
  errorHandler()(err, {}, res, () => {});
  assert.strictEqual(res.statusCode, 413);
});

test('genuine server errors still return a generic 500', () => {
  const res = fakeRes();
  errorHandler()(new Error('db exploded: secret detail'), {}, res, () => {});
  assert.strictEqual(res.statusCode, 500);
  assert.doesNotMatch(JSON.stringify(res.body), /secret/);
});

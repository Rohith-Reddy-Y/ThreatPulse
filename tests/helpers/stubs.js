/**
 * Test helper: lets src/feeds/* and src/net-guard.js load without node_modules.
 * Missing third-party packages (axios, rss-parser, cheerio, node-cron, ../database)
 * are replaced by small controllable fakes. Require this file FIRST in a test.
 */
const Module = require('module');
const path = require('path');

async function defaultParseString(xml) {
  if (/<(rss|feed)[\s>]/i.test(xml) && !/<(item|entry)[\s>]/i.test(xml)) return { items: [] };
  throw new Error('strict parser unavailable in tests');
}

const calls = { axiosGet: [], axiosPost: [], updateSource: [] };
const state = {
  // (url, config) => Promise<{data}>; tests overwrite this
  axiosGet: async () => { throw new Error('axios.get not stubbed'); },
  axiosPost: async () => { throw new Error('axios.post not stubbed'); },
  // rss-parser parseString implementation. Default: a valid feed with no items
  // parses to []; anything else throws, which exercises lenientParse.
  parseString: defaultParseString,
};

const fakeAxios = {
  get: (url, config) => { calls.axiosGet.push({ url, config }); return state.axiosGet(url, config); },
  post: (url, body, config) => { calls.axiosPost.push({ url, body, config }); return state.axiosPost(url, body, config); },
};

class FakeRSSParser {
  constructor(opts) { this.opts = opts; }
  parseString(xml) { return state.parseString(xml); }
}

const fakeDb = {
  updateSource: (id, updates) => { calls.updateSource.push({ id, updates }); return { success: true }; },
  getEnabledSources: () => [],
  insertArticles: (a) => ({ newCount: a.length, newArticles: a }),
  updateSourceFetchStatus: () => {},
};

const FAKES = {
  axios: fakeAxios,
  'rss-parser': FakeRSSParser,
  cheerio: { load: () => { throw new Error('cheerio not stubbed'); } },
  'node-cron': { validate: () => true, schedule: () => ({}) },
};

const DB_PATH = path.resolve(__dirname, '../../src/database.js');
const origResolve = Module._resolveFilename;
const origLoad = Module._load;
Module._load = function (request, parent, isMain) {
  if (Object.prototype.hasOwnProperty.call(FAKES, request)) return FAKES[request];
  if (parent && /\.\.?\/(\.\.\/)?database$/.test(request)) {
    const resolved = path.resolve(path.dirname(parent.filename), request + '.js');
    if (resolved === DB_PATH) return fakeDb;
  }
  return origLoad.apply(this, arguments);
};
void origResolve;

function reset() {
  calls.axiosGet.length = 0; calls.axiosPost.length = 0; calls.updateSource.length = 0;
}

module.exports = { state, calls, reset, fakeDb, FAKES, defaultParseString };

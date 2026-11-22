/**
 * Tiny browser stand-in for driving the real public/js/app.js (or admin.js) in a
 * vm context: elements are created on demand by id (initial class / style taken
 * from the HTML file), fetch is answered by a per-test route table, and toasts /
 * requests are recorded. Enough to walk UI flows end to end without a browser.
 */
'use strict';
const fs = require('fs');
const path = require('path');
const vm = require('vm');

const ROOT = path.join(__dirname, '..', '..');

function initialAttrs(htmlFile) {
  const html = fs.readFileSync(path.join(ROOT, 'public', htmlFile), 'utf8');
  const out = {};
  const tagRe = /<[a-zA-Z][^>]*\bid="([^"]+)"[^>]*>/g;
  let m;
  while ((m = tagRe.exec(html))) {
    const tag = m[0];
    const cls = (tag.match(/\bclass="([^"]*)"/) || [])[1] || '';
    const style = (tag.match(/\bstyle="([^"]*)"/) || [])[1] || '';
    out[m[1]] = { classes: cls.split(/\s+/).filter(Boolean), display: /display:\s*none/.test(style) ? 'none' : undefined,
      required: /\brequired\b/.test(tag) };
  }
  return out;
}

function deepProxy() {
  const fn = function () { return deepProxy(); };
  return new Proxy(fn, { get: (t, k) => (k === Symbol.toPrimitive ? () => 0 : deepProxy()), set: () => true, apply: () => deepProxy() });
}

function createBrowser({ html = 'index.html', script = 'js/app.js', routes = {}, search = '', cookie = 'tp_csrf=' + 'c'.repeat(64), groups: groupSpec = {} } = {}) {
  const attrs = initialAttrs(html);
  const els = new Map();
  const groups = new Map();       // class selector -> [elements]
  const toasts = [];
  const requests = [];
  const listeners = {};
  let downloads = [];

  function makeEl(id, init = {}) {
    const classes = new Set(init.classes || []);
    const handlers = {};
    const el = {
      id, tagName: 'DIV', value: '', textContent: '', innerHTML: '', disabled: false, checked: false,
      required: !!init.required, type: 'text', style: { display: init.display }, dataset: {}, options: [], selectedIndex: 0,
      children: [], href: '', download: '',
      classList: {
        add: (...c) => c.forEach(x => classes.add(x)),
        remove: (...c) => c.forEach(x => classes.delete(x)),
        toggle(c, force) { const on = force === undefined ? !classes.has(c) : !!force; if (on) classes.add(c); else classes.delete(c); return on; },
        contains: (c) => classes.has(c),
      },
      get className() { return [...classes].join(' '); },
      set className(v) { classes.clear(); String(v).split(/\s+/).filter(Boolean).forEach(c => classes.add(c)); },
      addEventListener(t, fn) { (handlers[t] = handlers[t] || []).push(fn); },
      removeEventListener() {},
      async fire(t, extra = {}) {
        const ev = { type: t, target: el, preventDefault() {}, stopPropagation() {}, ...extra };
        for (const fn of handlers[t] || []) await fn(ev);
      },
      closest(sel) {
        if (!el._parents) el._parents = {};
        if (!el._parents[sel]) el._parents[sel] = makeEl(`${id}::closest(${sel})`);
        return el._parents[sel];
      },
      focus() {}, blur() {}, select() {},
      reset() { el._resetCount = (el._resetCount || 0) + 1; },
      click() { if (el.download) downloads.push({ name: el.download, href: el.href }); return el.fire('click'); },
      remove() {}, prepend() {}, setAttribute() {}, getAttribute() { return null; },
      appendChild(c) { el.children.push(c); if (id === 'toast-container') toasts.push(c); return c; },
      insertAdjacentHTML(pos, h) { el.innerHTML += h; },
      querySelector() { return makeEl(`${id}::child`); },
      querySelectorAll() { return []; },
      getBoundingClientRect() { return { width: 800, height: 200, left: 0, top: 0, right: 800, bottom: 200 }; },
      getContext() { return deepProxy(); },
      get parentElement() { return el.closest('parent'); },
      parentNode: { insertBefore() {} },
    };
    return el;
  }

  function getEl(id) {
    if (!els.has(id)) els.set(id, makeEl(id, attrs[id] || {}));
    return els.get(id);
  }

  let cookieJar = cookie;
  const document = {
    readyState: 'complete',
    get cookie() { return cookieJar; },
    set cookie(v) { cookieJar = v; },
    title: '',
    body: makeEl('body'),
    documentElement: makeEl('html'),
    querySelector(sel) {
      const m = /^#([\w-]+)$/.exec(sel);
      if (m) return getEl(m[1]);
      return null;
    },
    querySelectorAll(sel) { return groups.get(sel) || []; },
    getElementById(id) { return getEl(id); },
    createElement(tag) { const e = makeEl(`<${tag}>`); e.tagName = String(tag).toUpperCase(); return e; },
    addEventListener(t, fn) { (listeners[t] = listeners[t] || []).push(fn); },
  };

  async function fetchStub(url, opts = {}) {
    const method = (opts.method || 'GET').toUpperCase();
    let body;
    try { body = opts.body ? JSON.parse(opts.body) : undefined; } catch { body = opts.body; }
    const rec = { method, url, body, headers: opts.headers || {} };
    requests.push(rec);
    const pathOnly = url.split('?')[0];
    const handler = routes[`${method} ${url}`] || routes[`${method} ${pathOnly}`];
    let out = typeof handler === 'function' ? await handler(rec) : handler !== undefined ? handler : { status: 404, body: { error: 'not mocked' } };
    if (!out || typeof out !== 'object' || !('status' in out)) out = { status: 200, body: out };
    return { ok: out.status >= 200 && out.status < 300, status: out.status, json: async () => {
      if (out.body === undefined) throw new Error('no json');
      return JSON.parse(JSON.stringify(out.body));
    } };
  }

  const realSetTimeout = setTimeout;
  const sandbox = {
    document,
    fetch: fetchStub,
    atob: (s) => Buffer.from(s, 'base64').toString('binary'),
    console: { log() {}, warn() {}, error() {}, info() {} },
    setTimeout: (fn, ms, ...a) => { const t = realSetTimeout(fn, ms, ...a); if (t.unref) t.unref(); return t; },
    clearTimeout,
    setInterval: () => 0,
    clearInterval: () => {},
    requestAnimationFrame: () => 0,
    performance: { now: () => Date.now() },
    localStorage: { _s: {}, getItem(k) { return this._s[k] ?? null; }, setItem(k, v) { this._s[k] = String(v); } },
    location: { search, href: '/', origin: 'https://tp.test' },
    navigator: {},
    isSecureContext: true,
    devicePixelRatio: 1,
    innerWidth: 1200,
    addEventListener() {},
    URLSearchParams, Intl, Date, Math, JSON, Promise, Object, Array, String, Number, Boolean, Error, Set, Map, RegExp, Symbol,
    Blob: class { constructor(parts, o) { this.parts = parts; this.type = o && o.type; } },
    URL: Object.assign(function (u, b) { return new URL(u, b); }, { createObjectURL: (b) => { sandbox._lastBlob = b; return 'blob:x'; }, revokeObjectURL() {} }),
    MutationObserver: class { observe() {} disconnect() {} },
    Event: class { constructor(t) { this.type = t; } },
    alert() {}, confirm: () => true, prompt: () => '',
  };
  sandbox.window = sandbox;
  // elements matched by class selectors (e.g. '.stat-card'), bound at start-up
  for (const [sel, list] of Object.entries(groupSpec)) {
    groups.set(sel, list.map((data, i) => Object.assign(makeEl(`${sel}#${i}`), { dataset: { ...data } })));
  }
  vm.createContext(sandbox);
  const src = fs.readFileSync(path.join(ROOT, 'public', script), 'utf8');
  vm.runInContext(src, sandbox, { filename: script });

  const settle = async (n = 20) => { for (let i = 0; i < n; i++) await new Promise(r => setImmediate(r)); };

  return {
    el: getEl,
    sandbox,
    requests,
    toasts,
    downloads: () => downloads,
    routes,
    settle,
    registerAll(sel, list) { groups.set(sel, list); },
    makeEl,
    toastTexts: () => toasts.map(t => t.innerHTML.replace(/&times;/g, '').replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim()),
    visible: (id) => !getEl(id).classList.contains('hidden'),
    req: (method, prefix) => requests.filter(r => r.method === method && r.url.startsWith(prefix)),
  };
}

module.exports = { createBrowser };

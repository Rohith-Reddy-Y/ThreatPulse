/*
 * ThreatPulse — Analytics page.
 * Reads /api/analytics (the signed-in user's own reports; guests: built-in feeds)
 * and draws plain SVG charts. All data-derived text goes in via textContent.
 */
(function () {
  'use strict';

  const SVGNS = 'http://www.w3.org/2000/svg';
  const $ = (s) => document.querySelector(s);
  const state = { days: 7, topN: 10, tables: false, data: null };
  const tz = -new Date().getTimezoneOffset();

  // ── DOM helpers ──
  function el(tag, props, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(props || {})) {
      if (v == null || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k === 'style') Object.assign(n.style, v);
      else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? '' : v);
    }
    for (const c of kids.flat()) if (c != null && c !== false) n.append(c.nodeType ? c : document.createTextNode(String(c)));
    return n;
  }
  function sv(tag, attrs) {
    const n = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) if (v != null) n.setAttribute(k, v);
    return n;
  }
  const css = (name) => getComputedStyle(document.documentElement).getPropertyValue(name).trim();
  const fmt = (n) => Number(n || 0).toLocaleString();
  function compact(n) {
    n = Number(n || 0);
    if (Math.abs(n) >= 1e6) return `${(n / 1e6).toFixed(n >= 1e7 ? 0 : 1)}M`;
    if (Math.abs(n) >= 1e4) return `${(n / 1e3).toFixed(0)}K`;
    if (Math.abs(n) >= 1e3) return `${(n / 1e3).toFixed(1)}K`;
    return String(n);
  }
  function bucketLabel(iso, unit, long) {
    const d = new Date(iso);
    if (unit === 'hour') return d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' });
    return d.toLocaleDateString([], long ? { weekday: 'short', month: 'short', day: 'numeric' } : { month: 'short', day: 'numeric' });
  }
  function niceMax(v) {
    if (v <= 4) return Math.max(1, v);
    const p = Math.pow(10, Math.floor(Math.log10(v)));
    for (const m of [1, 1.5, 2, 2.5, 3, 4, 5, 6, 8, 10]) if (m * p >= v) return m * p;
    return 10 * p;
  }

  // ── Tooltip ──
  const tip = $('#an-tip');
  function showTip(x, y, build) {
    tip.textContent = '';
    build(tip);
    tip.classList.add('show');
    const w = tip.offsetWidth, h = tip.offsetHeight;
    let left = x + 14, top = y - h - 12;
    if (left + w > window.innerWidth - 8) left = x - w - 14;
    if (top < 8) top = y + 16;
    tip.style.left = `${Math.max(8, left)}px`;
    tip.style.top = `${top}px`;
  }
  const hideTip = () => tip.classList.remove('show');
  const tipRow = (color, value, label) => el('div', { class: 'an-tip-row' },
    el('i', { style: { background: color } }), el('b', null, value), el('span', null, label));

  // ── Legend + table view ──
  const legend = (series) => el('div', { class: 'an-legend', 'aria-hidden': 'true' },
    ...series.map((s) => el('span', null, el('i', { style: { background: s.color } }), s.name)));
  function dataTable(caption, headers, rows) {
    return el('div', { class: `an-table-wrap${state.tables ? '' : ' hidden'}` },
      el('table', { class: 'an-table' }, el('caption', { class: 'sr-only' }, caption),
        el('thead', null, el('tr', null, ...headers.map((h, i) => el('th', { scope: 'col', class: i ? 'num' : null }, h)))),
        el('tbody', null, ...rows.map((r) => el('tr', null, ...r.map((c, i) => el(i ? 'td' : 'th', { scope: i ? null : 'row', class: i ? 'num' : null }, c)))))));
  }

  // ── Stacked columns (time on x) ──
  function stackedColumns(host, { buckets, unit, series, height = 240, caption }) {
    host.textContent = '';
    if (!buckets.length || !series.length) { host.append(el('div', { class: 'an-empty' }, 'No data in this period.')); return; }
    host.append(legend(series));
    const box = el('div', { class: 'an-chart' });
    host.append(box);
    const W = Math.max(320, box.clientWidth || host.clientWidth || 600);
    const H = height, ml = 40, mr = 8, mt = 10, mb = 26;
    const cw = W - ml - mr, ch = H - mt - mb;
    const n = buckets.length;
    const totals = buckets.map((_, i) => series.reduce((s, x) => s + (x.values[i] || 0), 0));
    const yMax = niceMax(Math.max(1, ...totals));
    const y = (v) => mt + ch - (v / yMax) * ch;
    const slot = cw / n;
    const bw = Math.max(3, Math.min(24, slot * 0.62));
    const svg = sv('svg', { viewBox: `0 0 ${W} ${H}`, width: '100%', height: H, role: 'img', 'aria-label': caption });
    const grid = css('--an-grid'), axis = css('--an-axis'), ink = css('--text-muted'), surface = css('--bg-card');

    for (let k = 0; k <= 4; k++) {
      const v = (yMax / 4) * k, yy = Math.round(y(v)) + 0.5;
      svg.append(sv('line', { x1: ml, x2: W - mr, y1: yy, y2: yy, stroke: k ? grid : axis, 'stroke-width': 1 }));
      const t = sv('text', { x: ml - 8, y: yy + 3.5, 'text-anchor': 'end', class: 'an-tick', fill: ink });
      t.textContent = compact(Math.round(v));
      svg.append(t);
    }
    const every = Math.ceil(n / Math.max(2, Math.floor(cw / 70)));
    buckets.forEach((b, i) => {
      if (i % every && i !== n - 1) return;
      const t = sv('text', { x: ml + slot * i + slot / 2, y: H - 8, 'text-anchor': 'middle', class: 'an-tick', fill: ink });
      t.textContent = bucketLabel(b, unit);
      svg.append(t);
    });

    const cols = [];
    for (let i = 0; i < n; i++) {
      const g = sv('g', { class: 'an-col' });
      const x = ml + slot * i + (slot - bw) / 2;
      let acc = 0;
      const parts = series.map((s) => ({ s, v: s.values[i] || 0 })).filter((p) => p.v > 0);
      parts.forEach((p, j) => {
        const y0 = y(acc), y1 = y(acc + p.v);
        acc += p.v;
        const gapTop = j < parts.length - 1 ? 1 : 0, gapBottom = j > 0 ? 1 : 0;   // 2px surface gap between segments
        const top = y1 + gapTop, h = Math.max(0, y0 - gapBottom - top);
        if (h <= 0) return;
        if (j === parts.length - 1) {   // 4px rounded data-end, square at the baseline
          const r = Math.min(4, bw / 2, h);
          g.append(sv('path', { d: `M${x},${top + h}V${top + r}Q${x},${top} ${x + r},${top}H${x + bw - r}Q${x + bw},${top} ${x + bw},${top + r}V${top + h}Z`, fill: p.s.color }));
        } else g.append(sv('rect', { x, y: top, width: bw, height: h, fill: p.s.color }));
      });
      // hit target: the whole slot, taller than the mark
      const hit = sv('rect', { x: ml + slot * i, y: mt, width: slot, height: ch, fill: 'transparent', tabindex: '0', class: 'an-hit',
        'aria-label': `${bucketLabel(buckets[i], unit, true)}: ${totals[i]} reports. ${series.map((s) => `${s.name} ${s.values[i] || 0}`).join(', ')}` });
      const show = (cx, cy) => {
        cols.forEach((c, k) => c.classList.toggle('dim', k !== i));
        showTip(cx, cy, (t) => {
          t.append(el('div', { class: 'an-tip-head' }, el('b', null, fmt(totals[i])), ` reports · ${bucketLabel(buckets[i], unit, true)}`));
          [...series].reverse().forEach((s) => t.append(tipRow(s.color, fmt(s.values[i] || 0), s.name)));
        });
      };
      hit.addEventListener('pointermove', (e) => show(e.clientX, e.clientY));
      hit.addEventListener('focus', () => { const r = hit.getBoundingClientRect(); show(r.left + r.width / 2, r.top + 20); });
      const reset = () => { cols.forEach((c) => c.classList.remove('dim')); hideTip(); };
      hit.addEventListener('pointerleave', reset);
      hit.addEventListener('blur', reset);
      cols.push(g);
      svg.append(g);
      svg.append(hit);
    }
    box.append(svg);
    host.append(dataTable(caption, [unit === 'hour' ? 'Hour' : 'Day', ...series.map((s) => s.name), 'Total'],
      buckets.map((b, i) => [bucketLabel(b, unit, true), ...series.map((s) => fmt(s.values[i] || 0)), fmt(totals[i])])));
  }

  // ── KPI tiles ──
  function sparkline(values) {
    const w = 96, h = 26, max = Math.max(1, ...values), n = values.length;
    const s = sv('svg', { viewBox: `0 0 ${w} ${h}`, width: w, height: h, 'aria-hidden': 'true', class: 'an-spark' });
    const pts = values.map((v, i) => [n > 1 ? (i / (n - 1)) * (w - 4) + 2 : w / 2, h - 3 - (v / max) * (h - 6)]);
    s.append(sv('polyline', { points: pts.map((p) => p.join(',')).join(' '), fill: 'none', stroke: css('--an-spark'), 'stroke-width': 1.5, 'stroke-linejoin': 'round', 'stroke-linecap': 'round' }));
    const last = pts[pts.length - 1];
    if (last) s.append(sv('circle', { cx: last[0], cy: last[1], r: 2.5, fill: css('--accent-solid') }));
    return s;
  }
  function kpiTile(label, k, { upIsBad = true, spark, suffix, sub } = {}) {
    let delta = null;
    if (k && k.prev != null) {
      const d = k.value - k.prev;
      const pct = k.prev ? Math.round((d / k.prev) * 100) : null;
      const dir = d > 0 ? 'up' : d < 0 ? 'down' : 'flat';
      const tone = dir === 'flat' ? 'flat' : (dir === 'up') === upIsBad ? 'bad' : 'good';
      const range = state.days === 1 ? '24h' : `${state.days}d`;
      delta = el('span', { class: `an-delta an-delta-${tone}`, title: `Previous ${range}: ${fmt(k.prev)}` },
        el('i', { 'aria-hidden': 'true' }, dir === 'up' ? '▲' : dir === 'down' ? '▼' : '–'),
        dir === 'flat' ? 'no change' : `${d > 0 ? '+' : ''}${fmt(d)}${pct != null ? ` (${pct > 0 ? '+' : ''}${pct}%)` : ''}`,
        el('span', { class: 'an-delta-ctx' }, ` vs prev ${range}`));
    }
    return el('div', { class: 'an-kpi' },
      el('div', { class: 'an-kpi-label' }, label),
      el('div', { class: 'an-kpi-row' }, el('div', { class: 'an-kpi-value' }, k ? compact(k.value) : '—', suffix || ''), spark ? sparkline(spark) : null),
      delta || (sub ? el('div', { class: 'an-kpi-sub' }, sub) : el('div', { class: 'an-kpi-sub' }, ' ')));
  }

  // ── Ranked bars (part-to-whole read as a ranking: one hue, one baseline) ──
  function rankedBars(host, { rows, total, otherCount, unitLabel, caption, footer }) {
    host.textContent = '';
    if (!rows.length) { host.append(el('div', { class: 'an-empty' }, 'No data in this period.')); return; }
    const max = Math.max(1, ...rows.map((r) => r.count));
    host.append(el('div', { class: 'an-total' }, el('b', null, fmt(total)), el('span', null, unitLabel)));
    const list = el('ol', { class: 'an-rank' });
    rows.forEach((r) => {
      const share = total ? Math.round((r.count / total) * 1000) / 10 : 0;
      list.append(el('li', { tabindex: '0', 'aria-label': `${r.name}: ${r.count} (${share}%)` },
        el('span', { class: 'an-rank-name', title: r.name }, r.name),
        el('span', { class: 'an-rank-track' }, el('span', { class: 'an-rank-fill', style: { width: `${Math.max(2, (r.count / max) * 100)}%` } })),
        el('span', { class: 'an-rank-n' }, fmt(r.count)),
        el('span', { class: 'an-rank-pct' }, `${share}%`)));
    });
    host.append(list);
    if (otherCount) host.append(el('div', { class: 'an-foot' }, `+ ${fmt(otherCount)} more from other ${footer || 'items'}`));
    host.append(dataTable(caption, ['Name', 'Reports', 'Share'], rows.map((r) => [r.name, fmt(r.count), `${total ? ((r.count / total) * 100).toFixed(1) : 0}%`])));
  }

  // ── Render ──
  const CAT_VARS = ['--an-c1', '--an-c2', '--an-c3', '--an-c4', '--an-c5'];
  const SEV = [['critical', 'Critical', '--sev-critical'], ['high', 'High', '--sev-high'], ['medium', 'Medium', '--sev-medium'], ['low', 'Low', '--sev-low']];
  const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1).replace(/_/g, ' ');

  function render() {
    const d = state.data;
    if (!d) return;
    const range = state.days === 1 ? 'last 24 hours, hourly' : `last ${state.days} days, daily`;
    $('#an-sev-sub').textContent = `${range} · your time zone`;
    stackedColumns($('#an-sev'), {
      buckets: d.buckets, unit: d.unit, height: 250, caption: 'Report volume by severity',
      series: SEV.map(([k, name, v]) => ({ name, color: css(v), values: (d.severity.series.find((s) => s.key === k) || { values: [] }).values })),
    });

    const k = d.kpis;
    const srcSub = `${fmt(k.sources.healthy)} healthy · ${fmt(k.sources.errors)} with errors`;
    const kp = $('#an-kpis');
    kp.textContent = '';
    kp.append(
      kpiTile('Reports', k.reports, { spark: k.reports.spark }),
      kpiTile('Critical', k.critical, { spark: k.critical.spark }),
      kpiTile('High', k.high),
      kpiTile('Exploited CVEs', k.exploitedCves),
      kpiTile('Public PoCs', k.pocs),
      kpiTile('Threat actors', k.actors),
      kpiTile('ATT&CK techniques', k.techniques, { sub: `${fmt(k.cves.value)} distinct CVEs` }),
      kpiTile('Sources enabled', { value: k.sources.total, prev: null }, { sub: srcSub }));

    const n = state.topN;
    rankedBars($('#an-src'), {
      rows: d.sources.top.slice(0, n), total: d.sources.total, otherCount: d.sources.otherCount + d.sources.top.slice(n).reduce((s, r) => s + r.count, 0),
      unitLabel: `reports from ${fmt(d.sources.distinct)} sources`, caption: 'Top sources by reports', footer: 'sources',
    });
    const cats = d.categories.map((c) => ({ name: cap(c.name), count: c.count }));
    rankedBars($('#an-cat'), {
      rows: cats.slice(0, n), total: d.sources.total, otherCount: cats.slice(n).reduce((s, r) => s + r.count, 0),
      unitLabel: `reports in ${fmt(cats.length)} categories`, caption: 'Reports by category', footer: 'categories',
    });

    const withOther = (ot) => {
      const series = ot.series.map((s, i) => ({ name: s.name, color: css(CAT_VARS[i]), values: s.values }));
      if (ot.other) series.push({ name: 'Other', color: css('--an-other'), values: ot.other });
      return series;
    };
    stackedColumns($('#an-srct'), { buckets: d.buckets, unit: d.unit, series: withOther(d.sourcesOverTime), caption: 'Top sources over time' });
    stackedColumns($('#an-tech'), { buckets: d.buckets, unit: d.unit, series: withOther(d.techniquesOverTime), caption: 'Top ATT&CK techniques over time' });

    $('#an-updated').textContent = `Updated ${new Date(d.generatedAt).toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })} · refreshes every 3 min`;
  }

  // ── Data ──
  function csrf() { const m = document.cookie.match(/(?:^|;\s*)tp_csrf=([^;]+)/); return m ? decodeURIComponent(m[1]) : ''; }
  async function get(url) {
    let r = await fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
    if (r.status === 401) {
      const ok = await fetch('/api/auth/refresh', { method: 'POST', credentials: 'same-origin', headers: { 'X-CSRF-Token': csrf() } }).then((x) => x.ok).catch(() => false);
      if (ok) r = await fetch(url, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
    }
    return r;
  }
  function message(text, link) {
    const m = $('#an-message');
    m.textContent = text;
    if (link) m.append(' ', el('a', { href: '/' }, link));
    m.classList.remove('hidden');
  }
  let loadSeq = 0;
  async function load() {
    const main = $('#an-main');
    main.setAttribute('aria-busy', 'true');
    const seq = ++loadSeq;   // only the latest range click may update the page
    try {
      const r = await get(`/api/analytics?days=${state.days}&tz=${tz}`);
      if (seq !== loadSeq) return;
      if (r.status === 401) { message('Your session has ended.', 'Open the dashboard to sign in or browse as a guest, then come back.'); return; }
      if (!r.ok) { message('Analytics are unavailable right now. Try again in a minute.'); return; }
      const data = await r.json();
      if (seq !== loadSeq) return;
      state.data = data;
      $('#an-message').classList.add('hidden');
      render();
    } catch (_) {
      message('Could not reach the server.');
    } finally { if (seq === loadSeq) main.removeAttribute('aria-busy'); }
  }
  async function scope() {
    try {
      const r = await get('/api/auth/me');
      if (!r.ok) return;
      const u = (await r.json()).user || {};
      $('#an-scope').textContent = u.role === 'admin' ? 'Scope: all users (admin)' : u.username === 'guest' ? 'Scope: built-in feeds (guest)' : `Scope: your feeds · ${u.username}`;
    } catch (_) { /* label only */ }
  }

  // ── Wiring ──
  document.querySelectorAll('[data-an-days]').forEach((b) => b.addEventListener('click', () => {
    document.querySelectorAll('[data-an-days]').forEach((x) => x.classList.toggle('active', x === b));
    state.days = parseInt(b.dataset.anDays, 10) || 7;
    load();
  }));
  $('#an-topn').addEventListener('change', (e) => { state.topN = parseInt(e.target.value, 10) || 10; render(); });
  $('#an-tables').addEventListener('change', (e) => {
    state.tables = e.target.checked;
    document.querySelectorAll('.an-table-wrap').forEach((t) => t.classList.toggle('hidden', !state.tables));
  });
  $('#an-theme').addEventListener('click', () => {
    const next = document.documentElement.getAttribute('data-theme') === 'light' ? 'dark' : 'light';
    document.documentElement.setAttribute('data-theme', next);
    try { localStorage.setItem('tp_theme', next); } catch (_) { /* private mode */ }
    render();
  });
  let rz = 0;
  window.addEventListener('resize', () => { clearTimeout(rz); rz = setTimeout(render, 150); });
  window.addEventListener('scroll', hideTip, { passive: true });

  scope();
  load();
  setInterval(() => { if (!document.hidden) load(); }, 180000);
})();

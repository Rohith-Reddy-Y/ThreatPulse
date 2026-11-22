/*
 * ThreatPulse — Threat Landscape panel.
 *
 * Reads /api/landscape (the signed-in user's own articles; guests: built-in
 * feeds) and renders four analyst views: an ATT&CK technique heatmap, threat
 * actors, vulnerabilities, and targeting (sectors / countries). Every cell and
 * row filters the feed through the existing search box — no app logic changes.
 *
 * All feed-derived text is inserted with textContent (never innerHTML).
 */
(function () {
  'use strict';

  const root = document.getElementById('landscape');
  if (!root) return;

  const $ = (sel, el = root) => el.querySelector(sel);
  const state = { days: 7, tab: 'attack', data: null, attackView: 'matrix', loading: false };

  // Severity is a status: colour + text label, never colour alone
  const SEV_LABEL = { critical: 'Critical', high: 'High', medium: 'Medium', low: 'Low' };

  function el(tag, props, ...children) {
    const n = document.createElement(tag);
    if (props) {
      for (const [k, v] of Object.entries(props)) {
        if (v == null || v === false) continue;
        if (k === 'class') n.className = v;
        else if (k === 'text') n.textContent = v;
        else if (k === 'style') Object.assign(n.style, v);
        else if (k.startsWith('on')) n.addEventListener(k.slice(2), v);
        else n.setAttribute(k, v === true ? '' : v);
      }
    }
    for (const c of children.flat()) if (c != null && c !== false) n.append(c.nodeType ? c : document.createTextNode(String(c)));
    return n;
  }
  const sevChip = (s) => el('span', { class: `lp-sev lp-sev-${s || 'low'}` }, el('i', { 'aria-hidden': 'true' }), SEV_LABEL[s] || 'Low');
  const fmt = (n) => Number(n || 0).toLocaleString();
  function ago(iso) {
    const t = Date.parse(iso);
    if (!Number.isFinite(t)) return '—';
    const m = Math.round((Date.now() - t) / 60000);
    if (m < 60) return `${Math.max(1, m)}m ago`;
    if (m < 1440) return `${Math.round(m / 60)}h ago`;
    return `${Math.round(m / 1440)}d ago`;
  }

  // ── Feed filtering (drives the existing search box) ──
  function filterFeed(term, label) {
    const input = document.getElementById('search-input');
    if (!input || !term) return;
    input.value = term;
    input.dispatchEvent(new Event('input', { bubbles: true }));
    announce(`Feed filtered by ${label || term}`);
    const feed = document.getElementById('feed');
    if (feed) feed.scrollIntoView({ behavior: window.matchMedia('(prefers-reduced-motion: reduce)').matches ? 'auto' : 'smooth', block: 'start' });
  }
  function announce(msg) { const live = $('#landscape-live'); if (live) live.textContent = msg; }

  // ── Tooltip (shared) ──
  let tip;
  function showTip(target, build) {
    if (!tip) { tip = el('div', { class: 'lp-tip', role: 'tooltip', id: 'lp-tip' }); document.body.append(tip); }
    tip.textContent = '';
    build(tip);
    tip.classList.add('show');
    const r = target.getBoundingClientRect();
    const w = tip.offsetWidth, h = tip.offsetHeight;
    let x = r.left + r.width / 2 - w / 2, y = r.top - h - 8;
    if (y < 8) y = r.bottom + 8;
    x = Math.max(8, Math.min(window.innerWidth - w - 8, x));
    tip.style.left = `${x + window.scrollX}px`;
    tip.style.top = `${y + window.scrollY}px`;
  }
  function hideTip() { if (tip) tip.classList.remove('show'); }
  function bindTip(node, build) {
    node.addEventListener('mouseenter', () => showTip(node, build));
    node.addEventListener('mouseleave', hideTip);
    node.addEventListener('focus', () => showTip(node, build));
    node.addEventListener('blur', hideTip);
  }

  // ── Data ──
  async function load() {
    if (state.loading) return;
    state.loading = true;
    root.setAttribute('aria-busy', 'true');
    try {
      const r = await fetch(`/api/landscape?days=${state.days}`, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
      state.data = r.ok ? await r.json() : null;
    } catch (_) { state.data = null; }
    state.loading = false;
    root.removeAttribute('aria-busy');
    render();
  }

  // ── Header / tabs ──
  function renderHeader() {
    const d = state.data;
    const sub = $('#landscape-sub');
    const range = state.days === 1 ? '24 hours' : `${state.days} days`;
    if (!d) { sub.textContent = 'Sign in to analyse your feeds'; return; }
    const a = d.attack;
    sub.textContent = `${fmt(d.totalArticles)} reports from your feeds · last ${range} · ${fmt(a.mappedArticles)} mapped to ATT&CK (${fmt(a.explicitArticles)} cite technique IDs)`;
    const counts = { attack: a.techniqueCount, actors: d.actors.length, cves: d.cves.length, targeting: d.sectors.length + d.countries.length };
    for (const [k, v] of Object.entries(counts)) { const c = $(`#lt-count-${k}`); if (c) c.textContent = v ? String(v) : ''; }
  }

  function setTab(name, focus) {
    state.tab = name;
    root.querySelectorAll('[data-landscape-tab]').forEach((b) => {
      const on = b.dataset.landscapeTab === name;
      b.setAttribute('aria-selected', String(on));
      b.tabIndex = on ? 0 : -1;
      if (on && focus) b.focus();
    });
    root.querySelectorAll('.landscape-panel').forEach((p) => p.classList.toggle('hidden', p.id !== `lp-${name}`));
    hideTip();
  }

  function empty(panel, text) { panel.append(el('div', { class: 'lp-empty' }, text)); }

  // ── ATT&CK matrix ──
  function heatStep(total, max) {
    if (!total) return 0;
    return Math.max(1, Math.min(5, Math.ceil((Math.log(total + 1) / Math.log(max + 1)) * 5)));
  }
  function renderAttack() {
    const panel = $('#lp-attack');
    panel.textContent = '';
    const d = state.data;
    if (!d) return empty(panel, 'No data — sign in or add sources.');
    const a = d.attack;
    const all = a.tactics.flatMap((t) => t.techniques);
    const toolbar = el('div', { class: 'lp-toolbar' },
      el('div', { class: 'lp-seg', role: 'group', 'aria-label': 'View' },
        el('button', { type: 'button', class: state.attackView === 'matrix' ? 'active' : null, 'aria-pressed': String(state.attackView === 'matrix'), onclick: () => { state.attackView = 'matrix'; renderAttack(); } }, 'Matrix'),
        el('button', { type: 'button', class: state.attackView === 'list' ? 'active' : null, 'aria-pressed': String(state.attackView === 'list'), onclick: () => { state.attackView = 'list'; renderAttack(); } }, 'List')),
      el('div', { class: 'lp-legend', 'aria-hidden': 'true' },
        el('span', { class: 'lp-legend-ramp' }, 'Fewer', ...[1, 2, 3, 4, 5].map((i) => el('i', { class: `lp-heat-${i}` })), 'More reports'),
        el('span', null, el('b', { class: 'lp-id-mark' }, 'ID'), 'cited by technique ID'),
        el('span', { class: 'lp-legend-note' }, 'Other counts are inferred from described behaviour, e.g. “password spraying” → T1110')));
    panel.append(toolbar);
    if (!all.length) return empty(panel, 'No ATT&CK techniques in this period yet.');

    const max = Math.max(...all.map((t) => t.total));
    if (state.attackView === 'list') {
      const tacticName = Object.fromEntries(a.tactics.map((t) => [t.id, t.name]));
      const rows = [...all].sort((x, y) => y.total - x.total);
      panel.append(table(['Technique', 'Tactic', 'Reports', 'Cited by ID', 'Inferred', 'Highest severity'], rows.map((t) => ({
        cells: [el('span', null, el('code', { class: 'lp-code' }, t.id), ' ', t.name), tacticName[t.tactic] || '—', bar(t.total, max), fmt(t.explicit), fmt(t.inferred), sevChip(t.worst)],
        onclick: () => filterFeed(t.term, `${t.id} ${t.name}`),
        label: `Filter the feed by ${t.id} ${t.name}`,
      })), [2, 3, 4]));
      return;
    }

    const grid = el('div', { class: 'lp-matrix', role: 'grid', 'aria-label': 'ATT&CK techniques by tactic' });
    for (const ta of a.tactics) {
      const col = el('div', { class: 'lp-col', role: 'row' },
        el('div', { class: 'lp-col-head', role: 'columnheader' },
          el('span', { class: 'lp-col-name' }, ta.name),
          el('span', { class: 'lp-col-count' }, ta.count ? `${fmt(ta.count)} report${ta.count === 1 ? '' : 's'}` : '—')));
      if (!ta.techniques.length) col.append(el('div', { class: 'lp-cell lp-cell-empty', role: 'gridcell' }, 'No activity'));
      for (const t of ta.techniques) {
        const step = heatStep(t.total, max);
        const cell = el('button', {
          type: 'button', role: 'gridcell', class: `lp-cell lp-heat-${step}`,
          'aria-label': `${t.id} ${t.name}: ${t.total} reports (${t.explicit} cite the ID, ${t.inferred} inferred). Filter the feed.`,
          onclick: () => filterFeed(t.term, `${t.id} ${t.name}`),
        },
        el('span', { class: 'lp-cell-name' }, t.name),
        el('span', { class: 'lp-cell-meta' },
          el('code', null, t.id),
          t.explicit ? el('b', { class: 'lp-id-mark', title: 'Cited by ID' }, 'ID') : null,
          el('span', { class: 'lp-cell-n' }, fmt(t.total))));
        bindTip(cell, (tp) => {
          tp.append(el('div', { class: 'lp-tip-head' }, el('code', null, t.id), el('b', null, t.name)));
          tp.append(el('div', { class: 'lp-tip-row' }, `${fmt(t.total)} report${t.total === 1 ? '' : 's'} · ${fmt(t.explicit)} cite the ID · ${fmt(t.inferred)} inferred`));
          tp.append(el('div', { class: 'lp-tip-row' }, 'Highest severity: ', sevChip(t.worst)));
          for (const s of t.samples.slice(0, 2)) tp.append(el('div', { class: 'lp-tip-item' }, s.title));
          tp.append(el('div', { class: 'lp-tip-hint' }, 'Click to filter the feed'));
        });
        col.append(cell);
      }
      grid.append(col);
    }
    panel.append(el('div', { class: 'lp-scroll' }, grid));
    if (a.unmapped.length) {
      panel.append(el('div', { class: 'lp-unmapped' }, 'Also cited: ',
        ...a.unmapped.map((t) => el('button', { type: 'button', class: 'lp-chip', onclick: () => filterFeed(t.id, t.id) }, `${t.id} (${t.total})`))));
    }
  }

  // ── Shared table + inline bar ──
  function bar(n, max) {
    return el('span', { class: 'lp-bar' }, el('span', { class: 'lp-bar-track' }, el('span', { class: 'lp-bar-fill', style: { width: `${Math.max(4, (n / Math.max(1, max)) * 100)}%` } })), el('span', { class: 'lp-bar-n' }, fmt(n)));
  }
  function table(headers, rows, numericCols = []) {
    const t = el('table', { class: 'lp-table' },
      el('thead', null, el('tr', null, ...headers.map((h, i) => el('th', { scope: 'col', class: numericCols.includes(i) ? 'num' : null }, h)))));
    const body = el('tbody');
    for (const r of rows) {
      const tr = el('tr', { tabindex: '0', title: r.label, 'aria-label': r.label },
        ...r.cells.map((c, i) => el('td', { class: numericCols.includes(i) ? 'num' : null }, c)));
      tr.addEventListener('click', r.onclick);
      tr.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); r.onclick(); } });
      body.append(tr);
    }
    t.append(body);
    return el('div', { class: 'lp-table-wrap' }, t);
  }

  // ── Threat actors ──
  function renderActors() {
    const panel = $('#lp-actors');
    panel.textContent = '';
    const d = state.data;
    if (!d || !d.actors.length) return empty(panel, 'No named threat actors in this period.');
    const max = Math.max(...d.actors.map((x) => x.count));
    panel.append(el('p', { class: 'lp-note' }, 'Attribution follows public vendor naming and is shown only where it is consistently reported.'));
    panel.append(table(['Actor', 'Attributed to', 'Reports', 'Highest severity', 'Sectors', 'CVEs', 'Last seen'], d.actors.map((x) => ({
      cells: [
        el('span', null, el('b', null, x.name), x.aliases && x.aliases.length ? el('span', { class: 'lp-aka' }, `aka ${x.aliases.join(', ')}`) : null),
        x.origin ? x.origin.name : el('span', { class: 'lp-muted' }, 'Unattributed'),
        bar(x.count, max), sevChip(x.worst),
        x.sectors.length ? x.sectors.join(', ') : el('span', { class: 'lp-muted' }, '—'),
        x.cves.length ? el('span', null, ...x.cves.map((c) => el('code', { class: 'lp-code' }, c))) : el('span', { class: 'lp-muted' }, '—'),
        ago(x.lastSeen),
      ],
      onclick: () => filterFeed(x.term || x.name, x.name),
      label: `Filter the feed by ${x.name}`,
    })), [2]));
  }

  // ── Vulnerabilities ──
  function renderCves() {
    const panel = $('#lp-cves');
    panel.textContent = '';
    const d = state.data;
    if (!d || !d.cves.length) return empty(panel, 'No CVEs reported in this period.');
    const max = Math.max(...d.cves.map((x) => x.count));
    const yes = (on, label) => (on ? el('span', { class: 'lp-flag' }, el('i', { 'aria-hidden': 'true' }), label) : el('span', { class: 'lp-muted' }, '—'));
    panel.append(el('p', { class: 'lp-note' }, 'Exploited first, then by severity. “KEV” = listed in CISA’s Known Exploited Vulnerabilities catalog.'));
    panel.append(table(['CVE', 'Reports', 'Severity', 'Exploitation', 'Public PoC', 'Patch', 'Latest report', 'Last seen'], d.cves.map((c) => ({
      cells: [
        el('code', { class: 'lp-code lp-code-strong' }, c.id), bar(c.count, max), sevChip(c.worst),
        c.kev ? el('span', { class: 'lp-flag lp-flag-kev' }, el('i', { 'aria-hidden': 'true' }), 'KEV') : yes(c.exploited, 'Exploited'),
        yes(c.poc, 'PoC'),
        c.patch === 'patched' ? 'Available' : c.patch === 'unpatched' ? el('span', { class: 'lp-flag lp-flag-warn' }, el('i', { 'aria-hidden': 'true' }), 'Not yet') : el('span', { class: 'lp-muted' }, 'Unknown'),
        el('span', { class: 'lp-ellipsis', title: c.title }, c.title),
        ago(c.lastSeen),
      ],
      onclick: () => filterFeed(c.id, c.id),
      label: `Filter the feed by ${c.id}`,
    })), [1]));
  }

  // ── Targeting ──
  function rankList(title, rows, labelOf, termOf, note) {
    const max = Math.max(1, ...rows.map((r) => r.count));
    const list = el('ol', { class: 'lp-rank' });
    for (const r of rows) {
      const label = labelOf(r);
      list.append(el('li', null, el('button', { type: 'button', onclick: () => filterFeed(termOf(r), label), 'aria-label': `${label}: ${r.count} reports. Filter the feed.` },
        el('span', { class: 'lp-rank-name' }, label),
        el('span', { class: 'lp-bar-track' }, el('span', { class: 'lp-bar-fill', style: { width: `${Math.max(3, (r.count / max) * 100)}%` } })),
        el('span', { class: 'lp-rank-n' }, fmt(r.count)),
        r.critical ? el('span', { class: 'lp-rank-crit', title: `${r.critical} critical` }, `${r.critical} crit`) : el('span', { class: 'lp-rank-crit' }))));
    }
    return el('div', { class: 'lp-rank-block' }, el('h4', null, title), note ? el('p', { class: 'lp-note' }, note) : null,
      rows.length ? list : el('div', { class: 'lp-empty' }, 'Nothing named in this period.'));
  }
  function renderTargeting() {
    const panel = $('#lp-targeting');
    panel.textContent = '';
    const d = state.data;
    if (!d) return empty(panel, 'No data — sign in or add sources.');
    const cap = (s) => s.charAt(0).toUpperCase() + s.slice(1);
    panel.append(el('div', { class: 'lp-two' },
      rankList('Sectors', d.sectors, (s) => cap(s.name), (s) => s.name, 'Victim sector detected in the report.'),
      rankList('Countries', d.countries, (c) => c.name, (c) => c.term || c.name, `Countries named in ${fmt(d.geolocated)} reports, including ransomware leak-site victims.`)));
  }

  function render() {
    renderHeader();
    renderAttack();
    renderActors();
    renderCves();
    renderTargeting();
  }

  // ── Wiring ──
  root.querySelectorAll('[data-landscape-days]').forEach((b) => b.addEventListener('click', () => {
    root.querySelectorAll('[data-landscape-days]').forEach((x) => x.classList.toggle('active', x === b));
    state.days = parseInt(b.dataset.landscapeDays, 10) || 7;
    load();
  }));
  const tabs = [...root.querySelectorAll('[data-landscape-tab]')];
  tabs.forEach((b, i) => {
    b.addEventListener('click', () => setTab(b.dataset.landscapeTab));
    b.addEventListener('keydown', (e) => {
      const k = { ArrowRight: 1, ArrowLeft: -1 }[e.key];
      if (!k) return;
      e.preventDefault();
      setTab(tabs[(i + k + tabs.length) % tabs.length].dataset.landscapeTab, true);
    });
  });
  window.addEventListener('scroll', hideTip, { passive: true });

  setTab('attack');
  load();
  setInterval(() => { if (!document.hidden) load(); }, 180000);
  // Sign-in / sign-out / guest switch changes whose data we show
  let pending = 0;
  new MutationObserver(() => { clearTimeout(pending); pending = setTimeout(load, 900); })
    .observe(document.body, { attributes: true, attributeFilter: ['class'] });
  const overlay = document.getElementById('auth-overlay');
  if (overlay) new MutationObserver(() => { clearTimeout(pending); pending = setTimeout(load, 900); }).observe(overlay, { attributes: true, attributeFilter: ['class'] });
})();

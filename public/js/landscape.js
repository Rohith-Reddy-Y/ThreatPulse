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
  const state = { days: 7, tab: 'attack', data: null, attackView: 'matrix', loading: false, selected: null };

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
  const httpUrl = (u) => { try { const x = new URL(u, location.href); return /^https?:$/.test(x.protocol) ? x.href : null; } catch (_) { return null; } };
  const ext = (href, text, cls, title) => el('a', { href, target: '_blank', rel: 'noopener noreferrer', class: cls || null, title: title || null, onclick: (e) => e.stopPropagation() }, text);
  const MITRE_ARROW = '\u2197';
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
    // A newer request (day switch, sign-in) during a load runs right after it
    if (state.loading) { state.pending = true; return; }
    state.loading = true;
    state.pending = false;
    root.setAttribute('aria-busy', 'true');
    try {
      const r = await fetch(`/api/landscape?days=${state.days}`, { credentials: 'same-origin', headers: { Accept: 'application/json' } });
      const body = r.ok ? await r.json() : null;
      state.data = body && body.attack && Array.isArray(body.attack.tactics) ? body : null;   // ignore malformed responses
    } catch (_) { state.data = null; }
    state.loading = false;
    root.removeAttribute('aria-busy');
    if (state.pending) { state.pending = false; return load(); }
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
        el('span', { class: 'lp-legend-note' }, 'Other counts are inferred from described behaviour, e.g. “password spraying” → T1110')),
      el('div', { class: 'lp-actions' },
        el('button', { type: 'button', class: 'lp-btn', onclick: exportLayer, title: 'Download an ATT&CK Navigator layer (v4.5 JSON) of these techniques' }, 'Export Navigator layer'),
        ext('https://mitre-attack.github.io/attack-navigator/', `Open ATT&CK Navigator ${MITRE_ARROW}`, 'lp-link')));
    panel.append(toolbar);
    if (!all.length) return empty(panel, 'No ATT&CK techniques in this period yet.');

    const max = Math.max(...all.map((t) => t.total));
    if (state.attackView === 'list') {
      const tacticName = Object.fromEntries(a.tactics.map((t) => [t.id, t.name]));
      const rows = [...all].sort((x, y) => y.total - x.total);
      panel.append(table(['Technique', 'Tactic', 'Reports', 'Trend', 'Cited by ID', 'Inferred', 'Highest severity'], rows.map((t) => ({
        cells: [el('span', null, el('code', { class: 'lp-code' }, t.id), ' ', t.name), tacticName[t.tactic] || '—', bar(t.total, max), trend(t.total, t.prev) || el('span', { class: 'lp-muted' }, '—'), fmt(t.explicit), fmt(t.inferred), sevChip(t.worst)],
        onclick: () => select(t.id),
        label: `Inspect ${t.id} ${t.name}`,
      })), [2, 3, 4, 5]));
      renderInspector(panel);
      return;
    }

    const grid = el('div', { class: 'lp-matrix', role: 'grid', 'aria-label': 'ATT&CK techniques by tactic' });
    for (const ta of a.tactics) {
      const col = el('div', { class: 'lp-col', role: 'row' },
        el('div', { class: 'lp-col-head', role: 'columnheader' },
          ext(ta.url, ta.name, 'lp-col-name'),
          el('span', { class: 'lp-col-count' }, ta.count ? `${fmt(ta.count)} report${ta.count === 1 ? '' : 's'}` : '—')));
      if (!ta.techniques.length) col.append(el('div', { class: 'lp-cell lp-cell-empty', role: 'gridcell' }, 'No activity'));
      for (const t of ta.techniques) {
        const step = heatStep(t.total, max);
        const cell = el('button', {
          type: 'button', role: 'gridcell', class: `lp-cell lp-heat-${step}${state.selected === t.id ? ' selected' : ''}`,
          'aria-pressed': String(state.selected === t.id),
          'aria-label': `${t.id} ${t.name}: ${t.total} reports (${t.explicit} cite the ID, ${t.inferred} inferred). Open details.`,
          onclick: () => select(t.id),
        },
        el('span', { class: 'lp-cell-name' }, t.name),
        el('span', { class: 'lp-cell-meta' },
          el('code', null, t.id),
          t.explicit ? el('b', { class: 'lp-id-mark', title: 'Cited by ID' }, 'ID') : null,
          trend(t.total, t.prev, true),
          el('span', { class: 'lp-cell-n' }, fmt(t.total))));
        bindTip(cell, (tp) => {
          tp.append(el('div', { class: 'lp-tip-head' }, el('code', null, t.id), el('b', null, t.name)));
          tp.append(el('div', { class: 'lp-tip-row' }, `${fmt(t.total)} report${t.total === 1 ? '' : 's'} · ${fmt(t.explicit)} cite the ID · ${fmt(t.inferred)} inferred`));
          tp.append(el('div', { class: 'lp-tip-row' }, 'Highest severity: ', sevChip(t.worst)));
          if (t.prev !== undefined) tp.append(el('div', { class: 'lp-tip-row' }, `Previous period: ${fmt(t.prev)} report${t.prev === 1 ? '' : 's'}`));
          for (const s of t.samples.slice(0, 2)) tp.append(el('div', { class: 'lp-tip-item' }, s.title));
          tp.append(el('div', { class: 'lp-tip-hint' }, 'Click for procedures, actors and the MITRE page'));
        });
        col.append(cell);
      }
      grid.append(col);
    }
    panel.append(el('div', { class: 'lp-scroll' }, grid));
    renderInspector(panel);
    if (a.unmapped.length) {
      panel.append(el('div', { class: 'lp-unmapped' }, 'Also cited: ',
        ...a.unmapped.map((t) => el('button', { type: 'button', class: 'lp-chip', onclick: () => filterFeed(t.id, t.id) }, `${t.id} (${t.total})`))));
    }
  }

  // ── Technique inspector: TTP detail with procedures, actors and MITRE link ──
  function allTechniques() {
    const a = state.data && state.data.attack;
    return a ? [...a.tactics.flatMap((t) => t.techniques), ...a.unmapped] : [];
  }
  function select(id) {
    state.selected = state.selected === id ? null : id;
    renderAttack();
    const insp = $('.lp-inspector');
    if (insp) insp.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
  }
  function renderInspector(panel) {
    const t = allTechniques().find((x) => x.id === state.selected);
    if (!t) return;
    const tactic = state.data.attack.tactics.find((x) => x.id === t.tactic);
    const insp = el('section', { class: 'lp-inspector', 'aria-label': `${t.id} ${t.name} details` });
    insp.append(el('div', { class: 'lp-insp-head' },
      el('div', null,
        el('div', { class: 'lp-insp-crumb' }, tactic ? ext(tactic.url, `${tactic.id} · ${tactic.name}`) : 'Technique', ' › ', el('code', null, t.id)),
        el('h4', null, t.name)),
      el('div', { class: 'lp-insp-actions' },
        el('button', { type: 'button', class: 'lp-btn lp-btn-primary', onclick: () => filterFeed(t.term, `${t.id} ${t.name}`) }, 'Filter feed'),
        ext(t.url || `https://attack.mitre.org/techniques/${t.id}/`, `View on MITRE ATT&CK ${MITRE_ARROW}`, 'lp-btn'),
        el('button', { type: 'button', class: 'lp-close', 'aria-label': 'Close details', onclick: () => select(t.id) }, '\u00d7'))));
    if (t.desc) insp.append(el('p', { class: 'lp-insp-desc' }, t.desc, el('span', { class: 'lp-muted' }, ' Summary — see MITRE for the full definition.')));
    insp.append(el('div', { class: 'lp-insp-stats' },
      el('div', null, el('b', null, fmt(t.total)), el('span', null, 'reports')),
      el('div', null, el('b', null, fmt(t.explicit)), el('span', null, 'cite the ID')),
      el('div', null, el('b', null, fmt(t.inferred)), el('span', null, 'inferred from behaviour')),
      el('div', null, sevChip(t.worst), el('span', null, 'highest severity'))));

    const procs = el('div', { class: 'lp-insp-col' }, el('h5', null, 'Procedures observed'));
    if (t.procedures && t.procedures.length) {
      const ul = el('ul', { class: 'lp-procs' });
      for (const p of t.procedures) {
        const link = httpUrl(p.url);
        ul.append(el('li', null,
          el('q', null, p.text),
          el('div', { class: 'lp-proc-src' },
            el('span', { class: `lp-how lp-how-${p.how}` }, p.how === 'cited' ? 'ID cited' : p.how === 'ai' ? 'AI-mapped' : 'inferred'),
            link ? ext(link, p.title) : el('span', null, p.title),
            el('span', { class: 'lp-muted' }, ` · ${ago(p.published)}`))));
      }
      procs.append(ul);
    } else procs.append(el('p', { class: 'lp-muted' }, 'No procedure text captured.'));

    const who = el('div', { class: 'lp-insp-col lp-insp-side' }, el('h5', null, 'Threat actors in these reports'));
    if (t.actors && t.actors.length) {
      who.append(el('div', { class: 'lp-chips' }, ...t.actors.map((a) =>
        el('button', { type: 'button', class: 'lp-chip', onclick: () => (window.ThreatPulseActor ? window.ThreatPulseActor.open(a.name) : filterFeed(actorTerm(a.name), a.name)), title: `Open the ${a.name} profile` }, `${a.name} (${a.count})`))));
    } else who.append(el('p', { class: 'lp-muted' }, 'No named actor in these reports.'));
    const det = window.ThreatPulseAttackPath && window.ThreatPulseAttackPath.detectionLinks ? window.ThreatPulseAttackPath.detectionLinks(t.id) : [];
    if (det.length) {
      who.append(el('h5', { style: { marginTop: '14px' } }, 'Detect & test'));
      who.append(el('div', { class: 'lp-det' }, ...det.map((l) => ext(l.url, `${l.label} ${MITRE_ARROW}`, 'lp-btn', l.title))));
    }
    who.append(el('p', { class: 'lp-note', style: { marginTop: '12px' } },
      'TTP = Tactic › Technique › Procedure. A procedure is the reported behaviour in the source’s own words.'));
    insp.append(el('div', { class: 'lp-insp-body' }, procs, who));
    panel.append(insp);
  }

  // Reports store the original spelling ("Fancy Bear"), the inspector shows the
  // canonical name ("APT28"): search with the spelling the feed actually uses.
  function actorTerm(name) {
    const hit = state.data && Array.isArray(state.data.actors) && state.data.actors.find((x) => x.name === name);
    return (hit && hit.term) || name;
  }

  // ── ATT&CK Navigator layer (v4.5) export ──
  function exportLayer() {
    const d = state.data;
    if (!d) return;
    const techs = allTechniques();
    const max = Math.max(1, ...techs.map((t) => t.total));
    const range = state.days === 1 ? '24 hours' : `${state.days} days`;
    const layer = {
      name: `ThreatPulse — last ${range}`,
      versions: { navigator: '5.1.0', layer: '4.5' },
      domain: 'enterprise-attack',
      description: `Techniques seen in ${d.totalArticles} ThreatPulse reports (last ${range}, generated ${d.generatedAt}). Score = number of reports. Comments show how many cite the technique ID vs. describe the behaviour (inferred).`,
      sorting: 3,
      layout: { layout: 'side', showID: true, showName: true, expandedSubtechniques: 'none' },
      hideDisabled: false,
      techniques: techs.map((t) => ({
        techniqueID: t.id, score: t.total, enabled: true, showSubtechniques: false,
        comment: `${t.total} report(s): ${t.explicit} cite the ID, ${t.inferred} inferred. Highest severity: ${t.worst}.` +
          (t.actors && t.actors.length ? ` Actors: ${t.actors.map((a) => a.name).join(', ')}.` : ''),
      })),
      gradient: { colors: ['#cde2fb', '#2a78d6', '#0d366b'], minValue: 0, maxValue: max },
      legendItems: [],
      metadata: [{ name: 'source', value: 'ThreatPulse' }, { name: 'window', value: range }],
      showTacticRowBackground: false,
      selectTechniquesAcrossTactics: true,
    };
    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
    const a = el('a', { href: URL.createObjectURL(blob), download: `threatpulse-attack-layer-${state.days}d.json` });
    document.body.append(a);
    a.click();
    setTimeout(() => { URL.revokeObjectURL(a.href); a.remove(); }, 1000);
    announce('ATT&CK Navigator layer downloaded. Open it in the Navigator: Open Existing Layer → Upload from local.');
  }

  // ── Shared table + inline bar ──
  function bar(n, max) {
    return el('span', { class: 'lp-bar' }, el('span', { class: 'lp-bar-track' }, el('span', { class: 'lp-bar-fill', style: { width: `${Math.max(4, (n / Math.max(1, max)) * 100)}%` } })), el('span', { class: 'lp-bar-n' }, fmt(n)));
  }
  // Change vs the previous period of the same length (▲ rising, ▼ falling, NEW)
  function trend(cur, prev, compact) {
    if (prev === undefined || prev === null) return null;
    const d = cur - prev;
    const range = state.days === 1 ? 'previous 24h' : `previous ${state.days} days`;
    if (prev === 0 && cur > 0) return el('span', { class: 'lp-trend lp-trend-new', title: `New: not seen in the ${range}` }, 'NEW');
    if (d === 0) return compact ? null : el('span', { class: 'lp-trend lp-trend-flat', title: `Same as the ${range}` }, '=');
    return el('span', { class: `lp-trend ${d > 0 ? 'lp-trend-up' : 'lp-trend-down'}`, title: `${d > 0 ? '+' : ''}${d} vs the ${range} (${prev})` },
      `${d > 0 ? '▲' : '▼'}${compact ? '' : ' '}${Math.abs(d)}`);
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
    panel.append(table(['Actor', 'Attributed to', 'Reports', 'Trend', 'Highest severity', 'Top techniques', 'Sectors', 'CVEs', 'Last seen'], d.actors.map((x) => ({
      cells: [
        el('span', null, el('b', null, x.name), x.aliases && x.aliases.length ? el('span', { class: 'lp-aka' }, `aka ${x.aliases.join(', ')}`) : null),
        x.origin ? x.origin.name : el('span', { class: 'lp-muted' }, 'Unattributed'),
        bar(x.count, max), trend(x.count, x.prev) || el('span', { class: 'lp-muted' }, '—'), sevChip(x.worst),
        x.techniques && x.techniques.length
          ? el('span', { class: 'lp-ttp-chips' }, ...x.techniques.slice(0, 4).map((t) => ext(t.url, t.id, 'lp-code-link', `${t.id} ${t.name} — ${t.count} report(s). Opens MITRE ATT&CK.`)))
          : el('span', { class: 'lp-muted' }, '—'),
        x.sectors.length ? x.sectors.join(', ') : el('span', { class: 'lp-muted' }, '—'),
        x.cves.length ? el('span', null, ...x.cves.map((c) => el('code', { class: 'lp-code' }, c))) : el('span', { class: 'lp-muted' }, '—'),
        ago(x.lastSeen),
      ],
      onclick: () => (window.ThreatPulseActor ? window.ThreatPulseActor.open(x.name) : filterFeed(x.term || x.name, x.name)),
      label: `Open the ${x.name} profile`,
    })), [2, 3]));
  }

  // ── Vulnerabilities ──
  function renderCves() {
    const panel = $('#lp-cves');
    panel.textContent = '';
    const d = state.data;
    if (!d || !d.cves.length) return empty(panel, 'No CVEs reported in this period.');
    const max = Math.max(...d.cves.map((x) => x.count));
    const yes = (on, label) => (on ? el('span', { class: 'lp-flag' }, el('i', { 'aria-hidden': 'true' }), label) : el('span', { class: 'lp-muted' }, '—'));
    panel.append(el('p', { class: 'lp-note' }, 'Most urgent first. Priority combines CISA KEV (known exploited), EPSS (chance of exploitation in the next 30 days, FIRST.org) and CVSS.'));
    const PRI = { now: ['Patch now', 0], soon: ['Patch soon', 1], plan: ['Plan', 2], monitor: ['Monitor', 3] };
    const rows = d.cves.slice().sort((x, y) => ((PRI[x.priority] || [0, 4])[1] - (PRI[y.priority] || [0, 4])[1]) || ((y.epss || 0) - (x.epss || 0)) || (y.count - x.count));
    const pct = (v) => (v === null || v === undefined ? el('span', { class: 'lp-muted' }, '—') : `${(v * 100).toFixed(v < 0.1 ? 1 : 0)}%`);
    panel.append(table(['CVE', 'Priority', 'EPSS', 'CVSS', 'Reports', 'Exploitation', 'Public PoC', 'Patch', 'Latest report'], rows.map((c) => ({
      cells: [
        el('code', { class: 'lp-code lp-code-strong' }, c.id),
        c.priority ? el('span', { class: `vuln-pri vuln-pri-${c.priority}` }, PRI[c.priority][0]) : el('span', { class: 'lp-muted' }, 'Pending'),
        pct(c.epss),
        c.cvss !== null && c.cvss !== undefined ? String(c.cvss.toFixed(1)) : sevChip(c.worst),
        bar(c.count, max),
        c.kev ? el('span', { class: 'lp-flag lp-flag-kev' }, el('i', { 'aria-hidden': 'true' }), 'KEV') : yes(c.exploited, 'Exploited'),
        yes(c.poc, 'PoC'),
        c.patch === 'patched' ? 'Available' : c.patch === 'unpatched' ? el('span', { class: 'lp-flag lp-flag-warn' }, el('i', { 'aria-hidden': 'true' }), 'Not yet') : el('span', { class: 'lp-muted' }, 'Unknown'),
        el('span', { class: 'lp-ellipsis', title: c.title }, c.title),
      ],
      onclick: () => filterFeed(c.id, c.id),
      label: `Filter the feed by ${c.id}`,
    })), [2, 3, 4]));
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

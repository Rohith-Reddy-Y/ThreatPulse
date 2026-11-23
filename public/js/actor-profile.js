/*
 * ThreatPulse — threat actor profile (from the user's own reports, last 90 days)
 *
 * Opens from an actor chip on a card or a row in Threat Landscape › Threat actors.
 * Shows who they are (aliases, attributed origin), how active they are (13-week
 * bars + first/last seen), how they operate (techniques in kill-chain order, with
 * a 3D attack path across all their reports), what they exploit (CVEs with patch
 * priority), whom they target (sectors / countries) and the latest reports.
 */
(function () {
  'use strict';
  let overlay = null, opener = null;

  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') n.className = v;
      else if (k === 'text') n.textContent = v;
      else if (k === 'style') Object.assign(n.style, v);
      else if (k.startsWith('on') && typeof v === 'function') n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? '' : String(v));
    }
    for (const k of kids.flat()) if (k !== null && k !== undefined && k !== false) n.append(k.nodeType ? k : document.createTextNode(String(k)));
    return n;
  }
  const http = (u) => (/^https?:\/\//i.test(String(u || '')) ? u : null);
  const ago = (iso) => {
    const t = Date.parse(iso || '');
    if (Number.isNaN(t)) return '';
    const d = Math.floor((Date.now() - t) / 86400000);
    return d <= 0 ? 'today' : d === 1 ? 'yesterday' : d < 30 ? `${d} days ago` : `${Math.floor(d / 30)} mo ago`;
  };
  const PRI = { now: 'Patch now', soon: 'Patch soon', plan: 'Plan', monitor: 'Monitor' };

  function section(title, ...body) {
    return el('section', { class: 'ac-sec' }, el('h5', { text: title }), ...body);
  }

  function weeksChart(weeks) {
    const max = Math.max(1, ...weeks.map((w) => w.count));
    const W = 13 * 18, H = 46;
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('viewBox', `0 0 ${W} ${H + 14}`);
    svg.setAttribute('class', 'ac-weeks');
    svg.setAttribute('role', 'img');
    svg.setAttribute('aria-label', `Reports per week, last 13 weeks: ${weeks.map((w) => w.count).join(', ')}`);
    weeks.forEach((w, i) => {
      const h = w.count ? Math.max(3, Math.round((w.count / max) * H)) : 1;
      const r = document.createElementNS(ns, 'rect');
      r.setAttribute('x', i * 18 + 2); r.setAttribute('y', H - h); r.setAttribute('width', 14); r.setAttribute('height', h); r.setAttribute('rx', 2);
      r.setAttribute('class', w.count ? 'ac-bar' : 'ac-bar ac-bar-zero');
      const tt = document.createElementNS(ns, 'title');
      tt.textContent = `Week of ${new Date(w.start).toLocaleDateString()}: ${w.count} report${w.count === 1 ? '' : 's'}`;
      r.append(tt);
      svg.append(r);
    });
    const lab = (x, txt, anchor) => { const t = document.createElementNS(ns, 'text'); t.setAttribute('x', x); t.setAttribute('y', H + 12); t.setAttribute('text-anchor', anchor); t.setAttribute('class', 'ac-axis'); t.textContent = txt; svg.append(t); };
    lab(2, '13 weeks ago', 'start'); lab(W - 2, 'this week', 'end');
    return svg;
  }

  function filterFeedBy(name) {
    close();
    const sel = document.getElementById('threat-actor-filter');
    const opt = sel && [...sel.options].find((o) => o.value.toLowerCase() === name.toLowerCase());
    if (opt) { sel.value = opt.value; sel.dispatchEvent(new Event('change', { bubbles: true })); }
    else {
      const si = document.getElementById('search-input');
      if (si) { si.value = name; si.dispatchEvent(new Event('input', { bubbles: true })); }
    }
    document.querySelector('.filter-bar')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  function render(dialog, d) {
    const body = dialog.querySelector('.ac-body');
    body.textContent = '';
    if (!d.found) {
      body.append(el('p', { class: 'ac-empty', text: `No reports about ${d.name} in your feeds in the last ${d.days} days.` }));
      return;
    }
    dialog.querySelector('.ac-sub').textContent =
      `${d.aliases.length ? 'aka ' + d.aliases.join(', ') + ' · ' : ''}${d.origin ? 'Attributed to ' + d.origin.name : 'Origin not attributed'}`;

    const stats = el('div', { class: 'ac-stats' },
      el('div', {}, el('b', { text: String(d.reports) }), el('span', { text: `reports (${d.days} days)` })),
      el('div', {}, el('b', { text: String(d.techniques.length) }), el('span', { text: 'ATT&CK techniques' })),
      el('div', {}, el('b', { text: ago(d.lastSeen) || '—' }), el('span', { text: 'last seen' })),
      el('div', {}, el('b', { text: ago(d.firstSeen) || '—' }), el('span', { text: 'first seen (in window)' })));

    // How they operate: techniques in kill-chain order + 3D path across all reports
    const techList = el('ol', { class: 'ac-techs' }, d.techniques.map((t) => el('li', {},
      el('span', { class: 'ac-tac', text: t.tacticName }),
      el('a', { href: http(t.url) || '#', target: '_blank', rel: 'noopener', class: 'ac-tid', text: t.id }),
      el('span', { class: 'ac-tname', text: t.name }),
      el('span', { class: 'ac-n', title: `${t.count} report(s)`, text: `×${t.count}` }))));
    const pathBtn = d.techniques.length && window.ThreatPulseAttackPath
      ? el('button', { type: 'button', class: 'ap-btn ap-btn-primary', onclick: () => {
        const art = { id: `actor-${d.name}`, title: `${d.name}: techniques across ${d.reports} reports (last ${d.days} days)`, url: '', source_name: 'ThreatPulse actor profile', threat_actors: d.name,
          ttps: d.techniques.map((t) => ({ id: t.id, subId: null, name: t.name, tactic: t.tactic, tacticName: t.tacticName, how: t.how, procedure: t.procedure, url: t.url })) };
        close();
        window.ThreatPulseAttackPath.open(art);
      } }, '3D attack path (all reports)') : null;

    const cves = d.cves.length ? el('ul', { class: 'ac-cves' }, d.cves.map((c) => el('li', {},
      c.priority ? el('span', { class: `vuln-pri vuln-pri-${c.priority}`, text: PRI[c.priority] }) : null,
      el('a', { href: `https://nvd.nist.gov/vuln/detail/${encodeURIComponent(c.id)}`, target: '_blank', rel: 'noopener', class: 'ac-cve', text: c.id }),
      c.kev ? el('span', { class: 'vuln-kev', text: 'KEV' }) : null,
      c.epss !== null && c.epss !== undefined ? el('span', { class: 'ac-muted', text: `EPSS ${(c.epss * 100).toFixed(c.epss < 0.1 ? 1 : 0)}%` }) : null,
      c.poc ? el('span', { class: 'ac-muted', text: 'PoC' }) : null))) : el('p', { class: 'ac-muted', text: 'No CVEs named in these reports.' });

    const chips = (list) => list.length ? el('div', { class: 'ac-chips' }, list.map((x) => el('span', { class: 'ac-chip', text: `${x.name} (${x.count})` }))) : el('p', { class: 'ac-muted', text: 'Not stated in these reports.' });

    const recent = el('ul', { class: 'ac-recent' }, d.recent.map((r) => el('li', {},
      http(r.url) ? el('a', { href: r.url, target: '_blank', rel: 'noopener', text: r.title }) : el('span', { text: r.title }),
      el('span', { class: 'ac-muted', text: `${r.source_name || ''} · ${ago(r.published_date)}` }))));

    body.append(
      stats,
      section('Activity', weeksChart(d.weeks)),
      el('div', { class: 'ac-grid' },
        section('How they operate', d.techniques.length ? techList : el('p', { class: 'ac-muted', text: 'No techniques mapped yet. Try “AI analysis” on their reports.' }), pathBtn),
        el('div', {},
          section('What they exploit', cves),
          section('Sectors targeted', chips(d.sectors)),
          section('Countries named', chips(d.countries)))),
      section('Latest reports', recent));
  }

  async function open(name, from) {
    close();
    opener = from || document.activeElement;
    const dialog = el('div', { class: 'ap-dialog ac-dialog', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': 'ac-title' },
      el('header', { class: 'ap-head' },
        el('div', { class: 'ap-head-text' },
          el('p', { class: 'ap-eyebrow', text: 'Threat actor profile · your feeds, last 90 days' }),
          el('h3', { id: 'ac-title', text: name }),
          el('p', { class: 'ap-meta ac-sub', text: 'Loading…' })),
        el('button', { type: 'button', class: 'ap-btn', onclick: () => filterFeedBy(name) }, 'Show all reports in feed'),
        el('button', { type: 'button', class: 'ap-close', 'aria-label': 'Close', onclick: close }, '×')),
      el('div', { class: 'ac-body' }, el('p', { class: 'ac-muted', text: 'Building profile…' })));
    overlay = el('div', { class: 'ap-overlay', onclick: (e) => { if (e.target === overlay) close(); } }, dialog);
    overlay.addEventListener('keydown', (e) => { if (e.key === 'Escape') { e.preventDefault(); close(); } });
    document.body.append(overlay);
    document.body.classList.add('ap-open');
    dialog.querySelector('.ap-close').focus();
    try {
      const r = await fetch(`/api/actors/profile?name=${encodeURIComponent(name)}`, { credentials: 'same-origin' });
      const d = await r.json();
      if (!overlay) return;
      if (!r.ok) throw new Error(d.error || 'Could not load the profile');
      dialog.querySelector('#ac-title').textContent = d.name || name;
      render(dialog, d);
    } catch (err) {
      if (!overlay) return;
      dialog.querySelector('.ac-sub').textContent = '';
      dialog.querySelector('.ac-body').replaceChildren(el('p', { class: 'ac-empty', text: err.message || 'Could not load the profile' }));
    }
  }

  function close() {
    if (!overlay) return;
    overlay.remove();
    overlay = null;
    document.body.classList.remove('ap-open');
    if (opener && typeof opener.focus === 'function') opener.focus();
    opener = null;
  }

  window.ThreatPulseActor = { open, close };
})();

/*
 * ThreatPulse — 3D attack path for one report.
 *
 * Purpose (not decoration): lay a report's threat actor and its ATT&CK
 * techniques out along the 14 tactics of the kill chain, so an analyst sees
 * at a glance where the attack starts, how far it got, which stages the
 * report says nothing about (what to hunt for next), and can open each step's
 * procedure + MITRE page. Exports a per-report ATT&CK Navigator layer.
 *
 * Plain DOM + CSS 3D transforms (no WebGL, no libraries): crisp text, real
 * buttons, keyboard accessible, two fixed camera presets (no drag-to-rotate).
 */
(function () {
  'use strict';

  const TACTICS = [
    ['TA0043', 'Reconnaissance', 'Recon'], ['TA0042', 'Resource Development', 'Resource Dev'],
    ['TA0001', 'Initial Access', 'Initial Access'], ['TA0002', 'Execution', 'Execution'],
    ['TA0003', 'Persistence', 'Persistence'], ['TA0004', 'Privilege Escalation', 'Priv. Escalation'],
    ['TA0005', 'Defense Evasion', 'Defense Evasion'], ['TA0006', 'Credential Access', 'Credential Access'],
    ['TA0007', 'Discovery', 'Discovery'], ['TA0008', 'Lateral Movement', 'Lateral Movement'],
    ['TA0009', 'Collection', 'Collection'], ['TA0011', 'Command and Control', 'Command & Control'],
    ['TA0010', 'Exfiltration', 'Exfiltration'], ['TA0040', 'Impact', 'Impact'],
  ];
  const TACTIC_INDEX = Object.fromEntries(TACTICS.map(([id], i) => [id, i]));

  // Board geometry (px, before scaling)
  const ACTOR_W = 112, LANE_W = 56, LANE_GAP = 4, BOARD_H = 330, FOOT = 34;
  // blocks live in the upper zone; vertical tactic names sit in the lower part of each lane
  const ZONE_TOP = 16, ZONE_H = BOARD_H - 136, ZONE_MID = ZONE_TOP + ZONE_H / 2;
  const BOARD_W = ACTOR_W + TACTICS.length * (LANE_W + LANE_GAP);
  const H_CITED = 66, H_INFERRED = 40, H_ACTOR = 86;
  const VIEWS = { '3d': { rx: 56, rz: -32 }, top: { rx: 0, rz: 0 } };

  let overlay = null, opener = null, current = null;

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
  const safeHttp = (u) => (/^https:\/\/attack\.mitre\.org\//.test(String(u || '')) ? u : null);
  const mitreUrl = (id) => {
    const m = /^(T\d{4})(?:\.(\d{3}))?$/.exec(String(id || ''));
    return m ? `https://attack.mitre.org/techniques/${m[1]}/${m[2] ? m[2] + '/' : ''}` : null;
  };
  const reduceMotion = () => window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ── Model: ordered steps along the kill chain ──
  function buildModel(article) {
    const ttps = (Array.isArray(article.ttps) ? article.ttps : []).filter((t) => t && t.id);
    const actors = String(article.threat_actors || '').split(',').map((s) => s.trim()).filter(Boolean);
    const steps = ttps
      .map((t, i) => ({ ...t, lane: TACTIC_INDEX[t.tactic] ?? -1, order: i }))
      .filter((t) => t.lane >= 0)
      .sort((a, b) => (a.lane - b.lane) || (a.order - b.order));
    const unmapped = ttps.filter((t) => (TACTIC_INDEX[t.tactic] ?? -1) < 0);
    const lanesUsed = [...new Set(steps.map((s) => s.lane))];
    const first = lanesUsed.length ? Math.min(...lanesUsed) : -1;
    const last = lanesUsed.length ? Math.max(...lanesUsed) : -1;
    const gaps = [];
    for (let i = first + 1; i < last; i++) if (!lanesUsed.includes(i)) gaps.push(i);
    // place blocks: stack within a lane
    const perLane = {};
    steps.forEach((s) => { (perLane[s.lane] = perLane[s.lane] || []).push(s); });
    for (const [lane, list] of Object.entries(perLane)) {
      const n = list.length;
      const step = n > 1 ? Math.min(62, (ZONE_H - FOOT) / (n - 1)) : 0;
      const top = ZONE_MID - ((n - 1) * step) / 2 - FOOT / 2;
      list.forEach((s, k) => {
        s.x = ACTOR_W + Number(lane) * (LANE_W + LANE_GAP) + (LANE_W - FOOT) / 2;
        s.y = top + k * step;
        s.h = s.how === 'cited' ? H_CITED : H_INFERRED;
      });
    }
    return { article, actors, steps, unmapped, lanesUsed, first, last, gaps };
  }

  // ── 3D pieces ──
  function box(cls, x, y, w, d, h, label) {
    const faces = ['top', 'n', 's', 'e', 'w'].map((f) => el('span', { class: `ap-face ap-${f}`, 'aria-hidden': 'true' }));
    const b = el('div', { class: `ap-box ${cls}`, role: 'button', tabindex: '0', 'aria-label': label,
      style: { left: x + 'px', top: y + 'px', width: w + 'px', height: d + 'px' } }, faces);
    b.style.setProperty('--h', h + 'px');
    return b;
  }
  function billboard(x, y, z, cls, ...kids) {
    const l = el('div', { class: `ap-tag ${cls || ''}`, 'aria-hidden': 'true', style: { left: x + 'px', top: y + 'px' } }, ...kids);
    l.style.setProperty('--z', z + 'px');
    return l;
  }

  function renderBoard(model, onSelect) {
    const board = el('div', { class: 'ap-board', style: { width: BOARD_W + 'px', height: BOARD_H + 'px' } });

    // tactic lanes (flat on the board), observed ones lit, gaps marked
    TACTICS.forEach(([id, name, short], i) => {
      const used = model.lanesUsed.includes(i);
      const gap = model.gaps.includes(i);
      board.append(el('div', {
        class: `ap-lane${used ? ' used' : ''}${gap ? ' gap' : ''}`,
        style: { left: ACTOR_W + i * (LANE_W + LANE_GAP) + 'px', width: LANE_W + 'px', height: BOARD_H + 'px' },
        title: `${name}${used ? ' — seen in this report' : gap ? ' — not described (hunt here)' : ''}`,
      }, el('span', { class: 'ap-lane-name', text: short }), el('span', { class: 'ap-lane-no', text: String(i + 1) })));
    });

    // actor zone
    board.append(el('div', { class: 'ap-actor-zone', style: { width: ACTOR_W - 8 + 'px', height: BOARD_H + 'px' } },
      el('span', { class: 'ap-lane-name', text: 'Threat actor' })));

    // kill-chain path on the board plane
    const ns = 'http://www.w3.org/2000/svg';
    const svg = document.createElementNS(ns, 'svg');
    svg.setAttribute('class', 'ap-path');
    svg.setAttribute('width', BOARD_W); svg.setAttribute('height', BOARD_H);
    svg.setAttribute('viewBox', `0 0 ${BOARD_W} ${BOARD_H}`);
    svg.setAttribute('aria-hidden', 'true');
    const defs = document.createElementNS(ns, 'defs');
    const marker = document.createElementNS(ns, 'marker');
    marker.setAttribute('id', 'ap-arrow'); marker.setAttribute('viewBox', '0 0 10 10');
    marker.setAttribute('refX', '8'); marker.setAttribute('refY', '5');
    marker.setAttribute('markerWidth', '6'); marker.setAttribute('markerHeight', '6'); marker.setAttribute('orient', 'auto-start-reverse');
    const tip = document.createElementNS(ns, 'path'); tip.setAttribute('d', 'M0,0 L10,5 L0,10 z'); tip.setAttribute('class', 'ap-arrow');
    marker.append(tip); defs.append(marker); svg.append(defs);
    const ax = ACTOR_W / 2 - 4, ay = ZONE_MID;
    const pts = [[ax, ay], ...model.steps.map((s) => [s.x + FOOT / 2, s.y + FOOT / 2])];
    for (let i = 1; i < pts.length; i++) {
      const seg = document.createElementNS(ns, 'line');
      const [x1, y1] = pts[i - 1], [x2, y2] = pts[i];
      const len = Math.hypot(x2 - x1, y2 - y1) || 1;
      const pad = i === 1 ? 32 : FOOT / 2 + 2;
      seg.setAttribute('x1', x1 + ((x2 - x1) / len) * pad); seg.setAttribute('y1', y1 + ((y2 - y1) / len) * pad);
      seg.setAttribute('x2', x2 - ((x2 - x1) / len) * (FOOT / 2 + 4)); seg.setAttribute('y2', y2 - ((y2 - y1) / len) * (FOOT / 2 + 4));
      seg.setAttribute('class', 'ap-seg');
      seg.setAttribute('marker-end', 'url(#ap-arrow)');
      svg.append(seg);
    }
    board.append(svg);

    // actor block
    const actorLabel = model.actors.length ? model.actors.join(', ') : 'Unattributed';
    const actorBox = box(`ap-actor${model.actors.length ? '' : ' ap-unknown'}`, ACTOR_W / 2 - 4 - 28, ZONE_MID - 28, 56, 56, H_ACTOR,
      `Threat actor: ${actorLabel}. Step 0.`);
    actorBox.dataset.step = '-1';
    board.append(actorBox);
    board.append(billboard(ACTOR_W / 2 - 4, ZONE_MID, H_ACTOR + 10, 'ap-tag-actor',
      el('b', { text: model.actors[0] || 'Unattributed' }),
      model.actors.length > 1 ? el('small', { text: `+${model.actors.length - 1} more` }) : el('small', { text: model.actors.length ? 'threat actor' : 'no actor named' })));

    // technique blocks
    model.steps.forEach((s, i) => {
      const shown = s.subId || s.id;
      const b = box(`ap-tech ${s.how === 'cited' ? 'ap-cited' : 'ap-inferred'}`, s.x, s.y, FOOT, FOOT, s.h,
        `Step ${i + 1}: ${s.tacticName} — ${shown} ${s.name} (${s.how === 'cited' ? 'cited in the report' : 'inferred'})`);
      b.dataset.step = String(i);
      board.append(b);
      // alternate label heights along the path so neighbouring labels don't collide
      board.append(billboard(s.x + FOOT / 2, s.y + FOOT / 2, s.h + 8, `ap-tag-tech ap-tag-l${i % 3}`,
        el('b', { text: shown }), el('small', { text: s.name.length > 18 ? s.name.slice(0, 17) + '…' : s.name })));
    });

    board.addEventListener('click', (e) => {
      const b = e.target.closest('.ap-box');
      if (b) onSelect(parseInt(b.dataset.step, 10));
    });
    board.addEventListener('keydown', (e) => {
      const b = e.target.closest('.ap-box');
      if (b && (e.key === 'Enter' || e.key === ' ')) { e.preventDefault(); onSelect(parseInt(b.dataset.step, 10)); }
    });
    return board;
  }

  // ── Side panel ──
  function detail(model, idx) {
    const wrap = el('div', { class: 'ap-detail' });
    if (idx < 0) {
      wrap.append(
        el('p', { class: 'ap-eyebrow', text: 'Start of the path' }),
        el('h4', { text: model.actors.length ? model.actors.join(', ') : 'Unattributed activity' }),
        el('p', { class: 'ap-desc', text: model.actors.length
          ? 'Threat actor named in this report. Every technique on the path is attributed to this actor for this report.'
          : 'The report does not name a threat actor. The techniques on the path describe the activity itself.' }),
        model.actors.length ? el('div', { class: 'ap-actions' }, model.actors.map((a) =>
          el('button', { type: 'button', class: 'ap-btn', onclick: () => findInFeed(a, 'actor') }, `Show all reports about ${a}`))) : null,
      );
      return wrap;
    }
    const s = model.steps[idx];
    const shown = s.subId || s.id;
    const url = safeHttp(s.url) || mitreUrl(shown);
    wrap.append(
      el('p', { class: 'ap-eyebrow' }, `Step ${idx + 1} of ${model.steps.length} · `,
        el('a', { href: `https://attack.mitre.org/tactics/${s.tactic}/`, target: '_blank', rel: 'noopener', text: s.tacticName })),
      el('h4', {}, el('code', { text: shown }), ' ', s.name),
      s.desc ? el('p', { class: 'ap-desc', text: s.desc }) : null,
      el('p', { class: 'ap-sub', text: 'In this report' }),
      s.procedure ? el('blockquote', { class: 'ap-proc', text: s.procedure }) : el('p', { class: 'ap-desc', text: 'No sentence quoted.' }),
      el('p', { class: `ap-evidence ${s.how === 'cited' ? 'cited' : 'inferred'}` },
        s.how === 'cited' ? 'Cited: the report names this technique ID.'
          : `Inferred: the report describes this behaviour${s.term ? ` (“${s.term}”)` : ''}. Verify before relying on it.`),
      el('div', { class: 'ap-actions' },
        url ? el('a', { class: 'ap-btn ap-btn-primary', href: url, target: '_blank', rel: 'noopener' }, `Open ${shown} on MITRE ATT&CK ↗`) : null,
        el('button', { type: 'button', class: 'ap-btn', onclick: () => findInFeed(s.how === 'cited' ? shown : (s.term || s.name), 'search') },
          s.how === 'cited' ? `Other reports citing ${shown}` : `Other reports mentioning “${s.term || s.name}”`)),
    );
    return wrap;
  }

  function findInFeed(term, kind) {
    close();
    if (kind === 'actor') {
      const btn = document.querySelector(`[data-filter-actor="${CSS.escape(term)}"]`);
      if (btn) { btn.click(); return; }
    }
    const si = document.getElementById('search-input');
    if (si) { si.value = term; si.dispatchEvent(new Event('input', { bubbles: true })); si.scrollIntoView({ behavior: reduceMotion() ? 'auto' : 'smooth', block: 'center' }); }
  }

  // ATT&CK Navigator layer (v4.5) for this one report
  function exportLayer(model) {
    const a = model.article;
    const layer = {
      name: `ThreatPulse – ${String(a.title || 'report').slice(0, 80)}`,
      versions: { attack: '16', navigator: '5.1.0', layer: '4.5' },
      domain: 'enterprise-attack',
      description: `Techniques from "${a.title}" (${a.url}). Cited = ID named in the report; inferred = behaviour described.`,
      techniques: model.steps.concat(model.unmapped).map((s) => ({
        techniqueID: s.subId || s.id,
        score: s.how === 'cited' ? 2 : 1,
        color: s.how === 'cited' ? '#3987e5' : '#9cc3f0',
        comment: `${s.how}${s.procedure ? ': ' + s.procedure : ''}`.slice(0, 500),
        enabled: true,
      })),
      gradient: { colors: ['#9cc3f0', '#3987e5'], minValue: 1, maxValue: 2 },
      legendItems: [{ label: 'Cited in report', color: '#3987e5' }, { label: 'Inferred from behaviour', color: '#9cc3f0' }],
    };
    const blob = new Blob([JSON.stringify(layer, null, 2)], { type: 'application/json' });
    const link = el('a', { href: URL.createObjectURL(blob), download: `attack-path-${a.id}.json` });
    document.body.append(link); link.click(); link.remove();
    setTimeout(() => URL.revokeObjectURL(link.href), 2000);
  }

  // ── Dialog ──
  function open(article, from) {
    close();
    opener = from || document.activeElement;
    const model = buildModel(article);
    current = { model, view: reduceMotion() ? 'top' : '3d', sel: model.steps.length ? 0 : -1 };

    const side = el('aside', { class: 'ap-side', 'aria-live': 'polite' });
    const stepsList = el('ol', { class: 'ap-steps' });
    const select = (i) => {
      current.sel = i;
      overlay.querySelectorAll('.ap-box').forEach((b) => b.classList.toggle('sel', b.dataset.step === String(i)));
      stepsList.querySelectorAll('li').forEach((li) => li.classList.toggle('sel', li.dataset.step === String(i)));
      side.replaceChildren(detail(model, i));
    };

    const board = renderBoard(model, select);
    const scene = el('div', { class: 'ap-scene' }, board);
    const stage = el('div', { class: 'ap-stage' }, scene);

    const viewBtns = Object.keys(VIEWS).map((v) => el('button', {
      type: 'button', class: 'ap-seg-btn', 'data-view': v, 'aria-pressed': String(v === current.view),
      onclick: () => setView(v),
    }, v === '3d' ? '3D view' : 'Top-down'));
    function setView(v) {
      current.view = v;
      viewBtns.forEach((b) => b.setAttribute('aria-pressed', String(b.dataset.view === v)));
      stage.classList.toggle('is-top', v === 'top');
      board.style.setProperty('--rx', VIEWS[v].rx + 'deg');
      board.style.setProperty('--rz', VIEWS[v].rz + 'deg');
      fit();
    }
    function fit() {
      const w = stage.clientWidth || 800;
      const sc = Math.max(0.38, Math.min(1, (w - 24) / (BOARD_W * (current.view === 'top' ? 1.1 : 1.2))));
      board.style.setProperty('--sc', sc.toFixed(3));
      stage.style.height = Math.round(current.view === "top" ? BOARD_H * sc + 120 : Math.max(320, 610 * sc + 40)) + 'px';
    }

    // ordered step list (text twin of the 3D view) + hunting gaps
    stepsList.append(el('li', { 'data-step': '-1', tabindex: '0', onclick: () => select(-1), onkeydown: (e) => { if (e.key === 'Enter') select(-1); } },
      el('span', { class: 'ap-step-tac', text: 'Actor' }), el('span', { class: 'ap-step-name', text: model.actors.join(', ') || 'Unattributed' })));
    model.steps.forEach((s, i) => stepsList.append(el('li', {
      'data-step': String(i), tabindex: '0', class: s.how === 'cited' ? 'cited' : 'inferred',
      onclick: () => select(i), onkeydown: (e) => { if (e.key === 'Enter') select(i); },
    }, el('span', { class: 'ap-step-tac', text: s.tacticName }), el('code', { text: s.subId || s.id }), el('span', { class: 'ap-step-name', text: s.name }))));

    const coverage = model.steps.length
      ? `${model.lanesUsed.length} of 14 tactics · ${TACTICS[model.first][1]} → ${TACTICS[model.last][1]}`
      : 'No techniques mapped';
    const gapsNote = model.gaps.length
      ? el('p', { class: 'ap-gaps' }, el('b', { text: 'Not described between those stages: ' }),
        model.gaps.map((g) => TACTICS[g][1]).join(', '),
        '. The report is silent here: check your own telemetry for these stages.')
      : (model.steps.length > 1 ? el('p', { class: 'ap-gaps ok', text: 'No gaps between the first and last stage the report describes.' }) : null);

    const a = article;
    const titleId = 'ap-title';
    const dialog = el('div', { class: 'ap-dialog', role: 'dialog', 'aria-modal': 'true', 'aria-labelledby': titleId },
      el('header', { class: 'ap-head' },
        el('div', { class: 'ap-head-text' },
          el('p', { class: 'ap-eyebrow', text: '3D attack path · MITRE ATT&CK' }),
          el('h3', { id: titleId }, /^https?:\/\//i.test(a.url || '') ? el('a', { href: a.url, target: '_blank', rel: 'noopener', text: a.title }) : a.title),
          el('p', { class: 'ap-meta', text: `${a.source_name || ''}${a.source_name ? ' · ' : ''}${coverage}` })),
        el('button', { type: 'button', class: 'ap-close', 'aria-label': 'Close', onclick: close }, '×')),
      el('div', { class: 'ap-toolbar' },
        el('div', { class: 'ap-seg', role: 'group', 'aria-label': 'Camera' }, viewBtns),
        el('div', { class: 'ap-legend' },
          el('span', {}, el('i', { class: 'lg-actor' }), 'Threat actor'),
          el('span', {}, el('i', { class: 'lg-cited' }), 'Cited in report (tall)'),
          el('span', {}, el('i', { class: 'lg-inferred' }), 'Inferred (short)'),
          el('span', {}, el('i', { class: 'lg-gap' }), 'Stage not described')),
        el('button', { type: 'button', class: 'ap-btn ap-export', onclick: () => exportLayer(model), title: 'Download an ATT&CK Navigator layer for this report' }, 'Navigator layer ↓')),
      el('div', { class: 'ap-body' },
        el('div', { class: 'ap-main' }, stage, gapsNote,
          model.unmapped.length ? el('p', { class: 'ap-gaps' }, el('b', { text: 'Also cited (no tactic mapping): ' }), model.unmapped.map((u) => u.subId || u.id).join(', ')) : null,
          el('h5', { class: 'ap-sub', text: 'Path, step by step' }), stepsList),
        side));

    overlay = el('div', { class: 'ap-overlay', onclick: (e) => { if (e.target === overlay) close(); } }, dialog);
    overlay.addEventListener('keydown', onKey);
    document.body.append(overlay);
    document.body.classList.add('ap-open');
    setView(current.view);
    select(current.sel);
    window.addEventListener('resize', fit);
    current.fit = fit;
    overlay.querySelector('.ap-close').focus();
  }

  function onKey(e) {
    if (!overlay) return;
    if (e.key === 'Escape') { e.preventDefault(); close(); return; }
    if ((e.key === 'ArrowRight' || e.key === 'ArrowLeft') && !/INPUT|TEXTAREA/.test(e.target.tagName)) {
      const n = current.model.steps.length;
      const next = Math.max(-1, Math.min(n - 1, current.sel + (e.key === 'ArrowRight' ? 1 : -1)));
      const target = overlay.querySelector(`.ap-box[data-step="${next}"]`);
      if (target) { target.focus(); target.click(); }
      e.preventDefault();
      return;
    }
    if (e.key === 'Tab') {   // keep focus inside the dialog
      const f = [...overlay.querySelectorAll('button, a[href], [tabindex="0"]')].filter((x) => x.offsetParent !== null || x.closest('.ap-board'));
      if (!f.length) return;
      const i = f.indexOf(document.activeElement);
      if (e.shiftKey && i <= 0) { e.preventDefault(); f[f.length - 1].focus(); }
      else if (!e.shiftKey && i === f.length - 1) { e.preventDefault(); f[0].focus(); }
    }
  }

  function close() {
    if (!overlay) return;
    window.removeEventListener('resize', current && current.fit);
    overlay.remove();
    overlay = null;
    document.body.classList.remove('ap-open');
    if (opener && typeof opener.focus === 'function') opener.focus();
    opener = null; current = null;
  }

  window.ThreatPulseAttackPath = { open, close, _buildModel: buildModel };
})();

/**
 * ThreatPulse v2 — Frontend Application
 * Multi-user dashboard with auth, reviews, sector/adversary filters
 */
'use strict';

(function () {
  //
  //  AUTH STATE (cookie-based httpOnly JWT — no localStorage)
  //
  let currentUser = null;
  // Access token lifetime is 15 min; refresh proactively at 13 min
  const REFRESH_MARGIN = 13 * 60 * 1000; // refresh 2 min before expiry
  let refreshTimer = null;

  //
  //  STATE
  //
  const state = {
    articles: [],
    sources: [],
    currentPage: 1,
    totalPages: 1,
    totalArticles: 0,
    filters: { category: '', severity: '', source_type: '', search: '', sector: '', threat_actor: '', has_poc: '', has_mitre: '', is_patched: '', time_range: '', start_date: '', end_date: '' },
    refreshCountdown: 60,
    refreshTimer: null,
    countdownTimer: null,
    isLoading: false,
    isFetching: false
  };

  //
  //  DOM REFS
  //
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  //
  //  INLINE ICONS (clean SVGs — no emoji)
  //
  const ICONS = {
    eye: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z"/><circle cx="12" cy="12" r="3"/></svg>',
    eyeOff: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M9.9 4.2A9.5 9.5 0 0 1 12 4c6.5 0 10 7 10 7a13.6 13.6 0 0 1-2.2 3M6.1 6.1A13.5 13.5 0 0 0 2 11s3.5 7 10 7a9.3 9.3 0 0 0 3.9-.8"/><path d="M3 3l18 18"/></svg>',
    sun: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M6.3 17.7l-1.4 1.4M19.1 4.9l-1.4 1.4"/></svg>',
    moon: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>'
  };

  //
  //  API HELPERS (cookie-based auth + CSRF)
  //

  // Decode obfuscated API paths (base64)
  function d(b64) { return atob(b64); }

  // Read CSRF token from the readable cookie set by the server
  function getCsrfToken() {
    const match = document.cookie.match(/(?:^|;\s*)tp_csrf=([^;]*)/);
    return match ? match[1] : null;
  }

  async function api(method, endpoint, body = null) {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' }
    };

    // Add CSRF token for state-changing requests
    if (method !== 'GET') {
      const csrf = getCsrfToken();
      if (csrf) opts.headers['X-CSRF-Token'] = csrf;
    }

    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(endpoint, opts);
    if (res.status === 401) {
      // Try refreshing the token once, then retry
      const refreshed = await refreshAccessToken();
      if (refreshed) {
        // Update CSRF token from the refresh response cookie
        const newCsrf = getCsrfToken();
        if (newCsrf && method !== 'GET') opts.headers['X-CSRF-Token'] = newCsrf;
        const retryRes = await fetch(endpoint, opts);
        if (retryRes.status === 401) {
          logout();
          throw new Error('Session expired');
        }
        const retryData = await retryRes.json();
        if (!retryRes.ok) throw new Error(retryData?.error || `Request failed (${retryRes.status})`);
        return retryData;
      }
      logout();
      throw new Error('Session expired');
    }
    const data = await res.json();
    if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
    return data;
  }

  async function refreshAccessToken() {
    try {
      const csrf = getCsrfToken();
      const res = await fetch(d('L2FwaS9hdXRoL3JlZnJlc2g='), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf || '' }
      });
      if (!res.ok) return false;
      const data = await res.json();
      if (data.success && data.user) {
        currentUser = data.user;
        updateUserMenu();
        scheduleAutoRefresh();
        return true;
      }
      return false;
    } catch { return false; }
  }

  function scheduleAutoRefresh() {
    if (refreshTimer) clearTimeout(refreshTimer);
    refreshTimer = setTimeout(async () => {
      await refreshAccessToken();
    }, REFRESH_MARGIN);
  }

  //
  //  AUTH FLOW
  //
  function showAuth() {
    $('#auth-overlay').classList.remove('hidden');
    $('#app-container').classList.add('hidden');
  }

  function hideAuth() {
    $('#auth-overlay').classList.add('hidden');
    $('#app-container').classList.remove('hidden');
  }

  function setUser(user) {
    currentUser = user;
    updateUserMenu();
    scheduleAutoRefresh();
    hideAuth();
  }

  function logout() {
    // Call server to clear cookies + blacklist tokens
    fetch(d('L2FwaS9hdXRoL2xvZ291dA=='), { method: 'POST', headers: { 'X-CSRF-Token': getCsrfToken() || '' } }).catch(() => {});

    currentUser = null;
    if (refreshTimer) clearTimeout(refreshTimer);
    refreshTimer = null;
    if (state.refreshTimer) clearInterval(state.refreshTimer);
    if (state.countdownTimer) clearInterval(state.countdownTimer);
    showAuth();
  }

  function updateUserMenu() {
    if (!currentUser) return;
    const avatar = currentUser.displayName ? currentUser.displayName.charAt(0).toUpperCase() : 'U';
    $('#user-avatar').textContent = avatar;
    $('#user-display-name').textContent = currentUser.displayName || currentUser.username;
    $('#dropdown-name').textContent = currentUser.displayName || currentUser.username;
    $('#dropdown-role').textContent = currentUser.role;
    if (currentUser.role === 'admin') {
      $('#admin-link').classList.remove('hidden');
    } else {
      $('#admin-link').classList.add('hidden');
    }
  }

  //
  //  UTILITIES
  //
  function debounce(fn, ms) {
    let timer;
    return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
  }

  function escapeHtml(str) {
    if (!str) return '';
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
  }

  function relativeTime(dateStr) {
    if (!dateStr) return '';
    const now = new Date(), date = new Date(dateStr);
    if (isNaN(date.getTime())) return '';               // guard: malformed date
    const diff = Math.floor((now - date) / 1000);
    if (diff < 0) return 'Just now';                     // guard: future/clock skew
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 172800) return 'Yesterday';
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  }

  // Format a Date as YYYY-MM-DDTHH:MM for datetime-local inputs
  function toLocalDatetime(date) {
    const offset = date.getTimezoneOffset();
    const local = new Date(date.getTime() - offset * 60000);
    return local.toISOString().slice(0, 16);
  }

  // Show a tag indicating the custom date range
  function showSelectedRangeTag(startVal, endVal) {
    // Remove any existing tag
    const existing = document.querySelector('.selected-range-tag');
    if (existing) existing.remove();

    const start = new Date(startVal);
    const end = new Date(endVal);
    const fmt = (d) => d.toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });

    const tag = document.createElement('span');
    tag.className = 'selected-range-tag';
    tag.innerHTML = `${fmt(start)} — ${fmt(end)} <span class="remove-range">&times;</span>`;
    const filterActions = document.querySelector('.filter-actions');
    if (filterActions) filterActions.prepend(tag);
  }

  function dateKey(dateStr) {
    if (!dateStr) return 'Undated';
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return 'Undated';            // guard: malformed date
    const today = new Date(); today.setHours(0,0,0,0);
    const yesterday = new Date(today); yesterday.setDate(yesterday.getDate() - 1);
    const articleDate = new Date(d); articleDate.setHours(0,0,0,0);
    if (articleDate.getTime() === today.getTime()) return 'Today';
    if (articleDate.getTime() === yesterday.getTime()) return 'Yesterday';
    return d.toLocaleDateString('en-US', { weekday: 'long', month: 'long', day: 'numeric', year: 'numeric' });
  }

  function showToast(title, message, type = 'info') {
    const container = $('#toast-container');
    const toast = document.createElement('div');
    toast.className = `toast toast-${type}`;
    toast.innerHTML = `<div class="toast-header"><strong>${escapeHtml(title)}</strong><button class="toast-close">&times;</button></div><div class="toast-body">${escapeHtml(message)}</div>`;
    container.appendChild(toast);
    toast.querySelector('.toast-close').addEventListener('click', () => toast.remove());
    setTimeout(() => toast.classList.add('show'), 10);
    setTimeout(() => { toast.classList.remove('show'); setTimeout(() => toast.remove(), 300); }, 5000);
  }

  function updateClock() {
    const now = new Date();
    const el = $('#clock-time');
    if (el) el.textContent = now.toLocaleTimeString('en-US', { hour12: true });
    // Also refresh the relative "Last Updated" display every tick
    updateLastUpdatedDisplay();
  }

  // Dynamic favicon — badge showing today's threat count, resets daily
  let _todayCount = 0;
  function updateFavicon() {
    const count = _todayCount;
    const color = count > 50 ? '#ff5c7a' : count > 10 ? '#ffab5c' : '#22d3ee';
    const digits = count > 999 ? '1k' : String(count);
    const fontSize = digits.length > 2 ? '7' : '8';

    const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
      + '<rect width="16" height="16" rx="3" fill="#0d0f1a"/>'
      + '<rect width="16" height="16" rx="3" fill="none" stroke="' + color + '" stroke-width="0.8" opacity="0.8"/>'
      + '<text x="8" y="' + (digits.length > 2 ? '11.5' : '12') + '" text-anchor="middle" fill="' + color + '" font-family="Inter,sans-serif" font-weight="700" font-size="' + fontSize + '">' + digits + '</text>'
      + '</svg>';

    const icon = document.querySelector('link[rel=icon]');
    if (icon) icon.href = 'data:image/svg+xml,' + encodeURIComponent(svg);
  }

  function updateFaviconCount(count) {
    _todayCount = count;
    updateFavicon();
  }

  function animateValue(el, target) {
    const start = parseInt(el.textContent) || 0;
    if (start === target) return;
    const duration = 600, startTime = performance.now();
    function tick(currentTime) {
      const elapsed = currentTime - startTime;
      const progress = Math.min(elapsed / duration, 1);
      const ease = 1 - Math.pow(1 - progress, 3);
      el.textContent = Math.floor(start + (target - start) * ease);
      if (progress < 1) requestAnimationFrame(tick);
    }
    requestAnimationFrame(tick);
  }

  //
  //  DATA FETCHING
  //
  // Cache the raw last-updated timestamp so relativeTime can be re-evaluated live
  let _statsLastUpdatedRaw = null;
  let _lastFetchCheckTime = null;
  let _chartTimeline = [];
  let _chartRange = 7;  // default 7 days

  // Chart date constants for longer ranges ──
  const CHART_PRESETS = {
    7:  { label: '7d', days: 7, buckets: 'day' },
    14: { label: '14d', days: 14, buckets: 'day' },
    30: { label: '30d', days: 30, buckets: 'day' },
    180: { label: '6mo', days: 180, buckets: 'week' },
    365: { label: '1yr', days: 365, buckets: 'month' },
    0:  { label: 'All', days: 9999, buckets: 'month' }
  };

  // Loading bar — thin indeterminate progress bar at top of page
  function showLoader() {
    let bar = document.getElementById('loading-bar');
    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'loading-bar';
      bar.className = 'loading-bar';
      document.body.prepend(bar);
    }
    bar.classList.add('active');
  }

  function hideLoader() {
    const bar = document.getElementById('loading-bar');
    if (bar) bar.classList.remove('active');
  }

  async function fetchStats() {
    try {
      const stats = await api('GET', d('L2FwaS9hcnRpY2xlcy9zdGF0cw=='));
      animateValue($('#stat-threats'), stats.threatsToday || 0);
      animateValue($('#stat-critical'), stats.criticalVulns || 0);
      animateValue($('#stat-pocs'), stats.pocsDetected || 0);
      animateValue($('#stat-sources'), stats.activeSources || 0);

      _statsLastUpdatedRaw = stats.lastUpdated || null;
      _lastFetchCheckTime = Date.now();
      // Update trend values (real data from server)
      updateStatTrends(stats);

      // Chart data
      _chartTimeline = stats.timeline || [];
      renderChart(_chartTimeline, _chartRange);

      // Update dynamic favicon with today's count
      updateFaviconCount(stats.threatsToday || 0);

      $('#total-sources-count').textContent = stats.activeSources || 0;
      updateLastUpdatedDisplay();
    } catch (e) { console.error('Stats error:', e); }
  }

  function updateLastUpdatedDisplay() {
    const el = $('#last-updated-time');
    if (!el) return;
    let timeToShow = _statsLastUpdatedRaw;
    // If DB time is older than 2 min, prefer our last check time
    if (_statsLastUpdatedRaw) {
      const dbTime = new Date(_statsLastUpdatedRaw).getTime();
      const checkTime = _lastFetchCheckTime || Date.now();
      if (Date.now() - dbTime > 120000 && checkTime > dbTime) {
        timeToShow = new Date(checkTime).toISOString();
      }
    }
    if (timeToShow) {
      el.textContent = relativeTime(timeToShow);
    } else {
      el.textContent = '--';
    }
  }

  function updateStatTrends(stats) {
    // Threats Today trend: % change vs yesterday
    const threatsTrend = $('#stat-threats-trend');
    if (threatsTrend) {
      const today = stats.threatsToday || 0;
      const yesterday = stats.threatsYesterday || 0;
      if (yesterday === 0 && today === 0) {
        threatsTrend.textContent = '--';
        threatsTrend.className = 'stat-trend neutral';
      } else if (yesterday === 0) {
        threatsTrend.textContent = `↑ ${today} new`;
        threatsTrend.className = 'stat-trend up';
      } else {
        const pct = Math.round(((today - yesterday) / yesterday) * 100);
        const arrow = pct >= 0 ? '↑' : '↓';
        threatsTrend.textContent = `${arrow} ${Math.abs(pct)}%`;
        threatsTrend.className = pct >= 0 ? 'stat-trend up' : 'stat-trend down';
      }
    }

    // Critical Vulns
    const critTrend = $('#stat-critical-trend');
    if (critTrend) {
      const crit = stats.criticalVulns || 0;
      critTrend.textContent = crit > 0 ? `${crit} this week` : 'none';
      critTrend.className = crit > 0 ? 'stat-trend danger' : 'stat-trend neutral';
    }

    // POCs Detected
    const pocsTrend = $('#stat-pocs-trend');
    if (pocsTrend) {
      const pocs = stats.pocsDetected || 0;
      pocsTrend.textContent = pocs > 0 ? `${pocs} live` : 'none';
      pocsTrend.className = pocs > 0 ? 'stat-trend warning' : 'stat-trend neutral';
    }

    // Active Sources
    const srcTrend = $('#stat-sources-trend');
    if (srcTrend) {
      const src = stats.activeSources || 0;
      const err = stats.erroredSources || 0;
      if (err > 0) {
        srcTrend.textContent = `${src} OK · ${err} err`;
        srcTrend.className = 'stat-trend warning';
      } else if (src > 0) {
        srcTrend.textContent = '● Online';
        srcTrend.className = 'stat-trend neutral';
      } else {
        srcTrend.textContent = '● Offline';
        srcTrend.className = 'stat-trend danger';
      }
    }

    // Header: show healthy count + errored
    const totalEl = $('#total-sources-count');
    if (totalEl) {
      const err = stats.erroredSources || 0;
      if (err > 0) {
        totalEl.textContent = stats.activeSources || 0;
        totalEl.style.color = 'var(--orange)';
        totalEl.title = `${err} source(s) have errors`;
      } else {
        totalEl.textContent = stats.activeSources || 0;
        totalEl.style.color = '';
        totalEl.title = '';
      }
    }
  }

  //
  //  CHART RENDERING — Stock-style area/line chart
  //

  function renderChart(timeline, days) {
    const canvas = $('#threat-chart');
    const empty = $('#chart-empty');
    if (!canvas) return;

    const preset = CHART_PRESETS[days] || CHART_PRESETS[7];
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - preset.days);
    const cutoffStr = cutoff.toISOString().split('T')[0];

    // Filter out null days and apply date range
    let data = (timeline || []).filter(d => d.day && d.day >= cutoffStr);
    if (preset.buckets === 'week') {
      data = bucketTimeline(timeline, cutoffStr, 'week');
    } else if (preset.buckets === 'month') {
      data = bucketTimeline(timeline, cutoffStr, 'month');
    }

    if (data.length === 0) {
      canvas.style.display = 'none';
      if (empty) empty.classList.remove('hidden');
      return;
    }

    canvas.style.display = 'block';
    if (empty) empty.classList.add('hidden');

    const dpr = window.devicePixelRatio || 1;
    const rect = canvas.parentElement.getBoundingClientRect();
    const w = rect.width - 32;
    const h = 190;
    canvas.width = w * dpr;
    canvas.height = h * dpr;
    canvas.style.width = w + 'px';
    canvas.style.height = h + 'px';

    const ctx = canvas.getContext('2d');
    ctx.scale(dpr, dpr);
    ctx.clearRect(0, 0, w, h);

    const ml = 44, mr = 12, mt = 14, mb = 32;
    const cw = w - ml - mr;
    const ch = h - mt - mb;

    // Y-axis scale ──
    let maxVal = Math.max(1, ...data.map(d => d.count));
    maxVal = Math.ceil(maxVal * 1.15);

    // Grid + Y labels ──
    const gridLines = 4;
    for (let i = 0; i <= gridLines; i++) {
      const y = mt + (ch / gridLines) * i;
      ctx.strokeStyle = 'rgba(255,255,255,0.04)';
      ctx.setLineDash([1, 8]);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(ml, y);
      ctx.lineTo(w - mr, y);
      ctx.stroke();
      ctx.setLineDash([]);

      const val = Math.round(maxVal - (maxVal / gridLines) * i);
      ctx.fillStyle = 'rgba(255,255,255,0.28)';
      ctx.font = '9px "JetBrains Mono", monospace';
      ctx.textAlign = 'right';
      ctx.fillText(val, ml - 6, y + 3);
    }

    // Build point coordinates ──
    const points = data.map((d, i) => ({
      x: ml + (i / Math.max(1, data.length - 1)) * cw,
      y: mt + ch - (d.count / maxVal) * ch,
      count: d.count,
      critical: d.critical,
      high: d.high,
      medium: d.medium,
      low: d.low,
      day: d.day
    }));

    // Area fill gradient ──
    const grad = ctx.createLinearGradient(0, mt, 0, mt + ch);
    grad.addColorStop(0, 'rgba(34, 211, 238, 0.28)');
    grad.addColorStop(0.5, 'rgba(124, 92, 255, 0.12)');
    grad.addColorStop(1, 'rgba(124, 92, 255, 0.02)');

    ctx.beginPath();
    ctx.moveTo(ml, mt + ch);
    points.forEach(p => ctx.lineTo(p.x, p.y));
    ctx.lineTo(w - mr, mt + ch);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Line ──
    ctx.beginPath();
    points.forEach((p, i) => {
      if (i === 0) ctx.moveTo(p.x, p.y);
      else ctx.lineTo(p.x, p.y);
    });
    ctx.strokeStyle = '#22d3ee';
    ctx.lineWidth = 2;
    ctx.shadowColor = 'rgba(34, 211, 238, 0.6)';
    ctx.shadowBlur = 8;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Dots on data points ──
    points.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
      ctx.fillStyle = '#0d0f1a';
      ctx.fill();
      ctx.strokeStyle = '#22d3ee';
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });

    // X-axis labels ──
    const labelStep = Math.max(1, Math.floor(data.length / 7));
    ctx.fillStyle = 'rgba(255,255,255,0.35)';
    ctx.font = '8px "Inter", sans-serif';
    ctx.textAlign = 'center';
    data.forEach((d, i) => {
      if (i % labelStep === 0 || i === data.length - 1) {
        const x = ml + (i / Math.max(1, data.length - 1)) * cw;
        ctx.fillText(formatChartLabel(d.day, preset.buckets), x, mt + ch + 16);
      }
    });

    // Store for tooltip + click
    canvas._chartData = { points, ml, mt, ch, cw, mr, mb };
    canvas.style.cursor = 'pointer';
    if (!canvas._tooltipBound) {
      canvas._tooltipBound = true;
      canvas.addEventListener('mousemove', chartTooltip);
      canvas.addEventListener('mouseleave', () => {
        const tip = document.getElementById('chart-tooltip');
        if (tip) tip.classList.add('hidden');
      });
      // Click on chart dot → filter feed to that date
      canvas.addEventListener('click', (e) => {
        const cd = canvas._chartData;
        if (!cd) return;
        const rect = canvas.getBoundingClientRect();
        const mx = e.clientX - rect.left;
        let closest = cd.points[0], minDist = Infinity;
        for (const p of cd.points) {
          const dist = Math.abs(p.x - mx);
          if (dist < minDist) { minDist = dist; closest = p; }
        }
        if (minDist > 30) return;
        // Set date filter to that specific day
        state.filters.start_date = closest.day + 'T00:00:00.000Z';
        state.filters.end_date = closest.day + 'T23:59:59.999Z';
        state.filters.time_range = 'custom';
        state.currentPage = 1;
        const timeFilter = $('#time-range-filter');
        if (timeFilter) timeFilter.value = 'custom';
        updateClearAllButton();
        fetchArticles();
        showToast('Filtered', `Showing threats from ${closest.day}`, 'info');
      });
    }
  }

  // Bucket daily timeline into weeks or months
  function bucketTimeline(timeline, cutoff, bucketType) {
    const grouped = {};
    (timeline || []).forEach(d => {
      if (d.day < cutoff) return;
      const date = new Date(d.day + 'T00:00:00');
      let key;
      if (bucketType === 'week') {
        // Monday of the week
        const dayOfWeek = date.getDay();
        const monday = new Date(date);
        monday.setDate(date.getDate() - ((dayOfWeek + 6) % 7));
        key = monday.toISOString().split('T')[0];
      } else {
        key = date.getFullYear() + '-' + String(date.getMonth() + 1).padStart(2, '0');
      }
      if (!grouped[key]) grouped[key] = { day: key, count: 0, critical: 0, high: 0, medium: 0, low: 0 };
      grouped[key].count += d.count;
      grouped[key].critical += d.critical || 0;
      grouped[key].high += d.high || 0;
      grouped[key].medium += d.medium || 0;
      grouped[key].low += d.low || 0;
    });
    return Object.values(grouped).sort((a, b) => a.day.localeCompare(b.day));
  }

  function formatChartLabel(dayStr, buckets) {
    if (buckets === 'month') {
      const [y, m] = dayStr.split('-');
      return new Date(parseInt(y), parseInt(m) - 1, 1).toLocaleDateString('en-US', { month: 'short' });
    }
    const d = new Date(dayStr + 'T00:00:00');
    return d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' });
  }

  function chartTooltip(e) {
    const canvas = e.target;
    const cd = canvas._chartData;
    if (!cd) return;

    let tip = document.getElementById('chart-tooltip');
    if (!tip) {
      tip = document.createElement('div');
      tip.id = 'chart-tooltip';
      tip.style.cssText = 'position:absolute;pointer-events:none;background:var(--bg-elevated);border:1px solid var(--border-accent);border-radius:8px;padding:6px 10px;font-size:0.72rem;color:var(--text-primary);z-index:50;white-space:nowrap;box-shadow:0 4px 16px rgba(0,0,0,0.4);';
      canvas.parentElement.appendChild(tip);
    }

    const rect = canvas.getBoundingClientRect();
    const mx = e.clientX - rect.left;

    const { points, ml, mt, ch, cw } = cd;
    // Find closest point
    let closest = points[0];
    let minDist = Infinity;
    for (const p of points) {
      const dist = Math.abs(p.x - mx);
      if (dist < minDist) { minDist = dist; closest = p; }
    }
    if (minDist > 30) { tip.classList.add('hidden'); return; }

    tip.innerHTML = `<strong>${closest.day}</strong><br>Total: ${closest.count} | Crit: ${closest.critical} | High: ${closest.high} | Med: ${closest.medium} | Low: ${closest.low}`;
    tip.classList.remove('hidden');

    const tipRect = tip.getBoundingClientRect();
    let tx = rect.left + closest.x - tipRect.width / 2;
    let ty = rect.top + mt - tipRect.height - 8;
    if (tx < 0) tx = 4;
    if (tx + tipRect.width > window.innerWidth) tx = window.innerWidth - tipRect.width - 4;
    if (ty < 0) ty = rect.bottom + 4;
    tip.style.left = tx + 'px';
    tip.style.top = ty + 'px';
  }

  async function fetchArticles(page = 1, append = false) {
    if (state.isLoading) return;
    state.isLoading = true;
    showLoader();
    try {
      const params = new URLSearchParams({ page, limit: 50 });
      if (state.filters.category) params.set('category', state.filters.category);
      if (state.filters.severity) params.set('severity', state.filters.severity);
      if (state.filters.source_type) params.set('source_type', state.filters.source_type);
      if (state.filters.search) params.set('search', state.filters.search);
      if (state.filters.sector) params.set('sector', state.filters.sector);
      if (state.filters.threat_actor) params.set('threat_actor', state.filters.threat_actor);
      if (state.filters.has_poc) params.set('has_poc', state.filters.has_poc);
      if (state.filters.has_mitre) params.set('has_mitre', state.filters.has_mitre);
      if (state.filters.is_patched !== '') params.set('is_patched', state.filters.is_patched);
      if (state.filters.time_range) params.set('time_range', state.filters.time_range);
      if (state.filters.start_date) params.set('start_date', state.filters.start_date);
      if (state.filters.end_date) params.set('end_date', state.filters.end_date);

      const data = await api('GET', `${d('L2FwaS9hcnRpY2xlcw==')}?${params}`);
      state.currentPage = data.page;
      state.totalPages = data.totalPages;
      state.totalArticles = data.total;

      if (append) {
        state.articles = [...state.articles, ...data.articles];
      } else {
        state.articles = data.articles;
      }
      renderArticles();
    } catch (e) { console.error('Articles error:', e); }
    finally { state.isLoading = false; hideLoader(); }
  }

  async function fetchSources() {
    try {
      const data = await api('GET', d('L2FwaS9zb3VyY2Vz'));
      const sources = Array.isArray(data) ? data : (data.sources || []);
      state.sources = sources.map(s => ({
        ...s,
        is_user_added: s.added_by === 'user',
        enabled: !!s.enabled
      }));
      renderSources();
    } catch (e) { console.error('Sources error:', e); }
  }

  async function fetchNotificationSettings() {
    try {
      const s = await api('GET', d('L2FwaS9ub3RpZmljYXRpb25zL3NldHRpbmdz'));
      if (!s) return;
      if (s.email) $('#notif-email').value = s.email;
      $('#notif-email-enabled').checked = !!s.email_enabled;
      if (s.telegram_chat_id) $('#notif-telegram').value = s.telegram_chat_id;
      if (s.telegram_bot_token) $('#notif-telegram-token').value = s.telegram_bot_token;
      $('#notif-telegram-enabled').checked = !!s.telegram_enabled;
      if (s.teams_webhook) $('#notif-teams-webhook').value = s.teams_webhook;
      $('#notif-teams-enabled').checked = !!s.teams_enabled;
      if (s.whatsapp_number) $('#notif-whatsapp-number').value = s.whatsapp_number;
      if (s.whatsapp_apikey) $('#notif-whatsapp-apikey').value = s.whatsapp_apikey;
      $('#notif-whatsapp-enabled').checked = !!s.whatsapp_enabled;
      if (s.severity_threshold) $('#notif-severity').value = s.severity_threshold;
      if (s.keywords_filter) $('#notif-keywords').value = s.keywords_filter;
    } catch (e) { console.error('Notification settings error:', e); }
  }

  //
  //  RENDERING
  //
  function renderArticles() {
    const container = $('#articles-container');
    const skeletons = $('#loading-skeletons');
    const empty = $('#empty-state');
    const loadMore = $('#load-more-container');

    skeletons.classList.add('hidden');

    // Split: articles resolved (reviewed/escalated by anyone) go to sidebar
    const resolved = [];
    const active = [];
    state.articles.forEach(a => {
      let reviews = [];
      try { reviews = a.reviews ? JSON.parse(a.reviews) : []; } catch(e) {}
      const isResolved = reviews.some(r => r.status === 'reviewed' || r.status === 'escalated');
      if (isResolved) resolved.push(a);
      else active.push(a);
    });

    // Render sidebar escalated/reviewed items
    renderEscalatedSidebar(resolved);

    if (active.length === 0) {
      container.innerHTML = '';
      empty.classList.remove('hidden');
      loadMore.classList.add('hidden');
      const hasFilters = hasActiveFilters();
      $('#empty-title').textContent = hasFilters ? 'No threats match your filters' : 'No Threats Yet';
      $('#empty-message').textContent = hasFilters
        ? 'Your current filters returned nothing. Try widening them or clear all.'
        : 'Your dashboard is empty. Add threat intelligence sources from the sidebar to start tracking threats, or click Fetch Now.';
      const clearBtn = $('#clear-filters-btn-empty');
      if (clearBtn) {
        clearBtn.style.display = hasFilters ? '' : 'none';
        if (hasFilters && !clearBtn._bound) {
          clearBtn._bound = true;
          clearBtn.addEventListener('click', clearFilters);
        }
      }
      $('#fetch-now-empty').style.display = hasFilters ? 'none' : '';
      updateClearAllButton();
      return;
    }

    empty.classList.add('hidden');

    // Group by date
    const groups = {};
    active.forEach(a => {
      const key = dateKey(a.published_date);
      if (!groups[key]) groups[key] = [];
      groups[key].push(a);
    });

    let html = '';
    for (const [date, articles] of Object.entries(groups)) {
      const cards = articles.map(a => createArticleCard(a)).join('');
      html += `<section class="date-section">
        <div class="date-header" role="button" tabindex="0" aria-expanded="true">
          <span class="date-header-icon"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round"><polyline points="6 9 12 15 18 9"/></svg></span>
          <span class="date-header-text">${escapeHtml(date)}</span>
          <span class="date-header-count">${articles.length} item${articles.length === 1 ? '' : 's'}</span>
        </div>
        <div class="date-articles">${cards}</div>
      </section>`;
    }
    container.innerHTML = html;
    loadMore.classList.toggle('hidden', state.currentPage >= state.totalPages);
  }

  // Render escalated/reviewed items in the sidebar
  function renderEscalatedSidebar(items) {
    const list = $('#escalated-sidebar-list');
    if (!list) return;
    if (items.length === 0) {
      list.innerHTML = '<p class="empty-sources">No escalated or reviewed items.</p>';
      return;
    }
    list.innerHTML = items.map(a => {
      let reviews = [];
      try { reviews = a.reviews ? JSON.parse(a.reviews) : []; } catch(e) {}
      const escalated = reviews.find(r => r.status === 'escalated');
      const reviewed = reviews.find(r => r.status === 'reviewed');
      const who = escalated || reviewed;
      const statusTag = escalated
        ? '<span class="badge badge-severity-critical">Escalated</span>'
        : '<span class="badge badge-patched">Reviewed</span>';
      const noteSnippet = who && who.notes ? `<span class="sidebar-item-note">${escapeHtml(who.notes.substring(0, 50))}</span>` : '';
      return `<div class="sidebar-article-item">
        <a href="${escapeHtml(a.url)}" target="_blank" rel="noopener" class="sidebar-article-link" title="${escapeHtml(a.title)}">${escapeHtml(a.title.substring(0, 60))}${a.title.length > 60 ? '...' : ''}</a>
        <div class="sidebar-article-meta">${statusTag} ${who ? escapeHtml(who.username) : ''} ${noteSnippet}</div>
      </div>`;
    }).join('');
  }

  function mitreLink(id) {
    id = id.trim().toUpperCase();
    if (/^TA\d{4}$/.test(id)) return `https://attack.mitre.org/tactics/${id}/`;
    const m = id.match(/^T(\d{4})(?:\.(\d{3}))?$/);
    if (m) return m[2]
      ? `https://attack.mitre.org/techniques/T${m[1]}/${m[2]}/`
      : `https://attack.mitre.org/techniques/T${m[1]}/`;
    return 'https://attack.mitre.org/';
  }

  function createArticleCard(article) {
    const catBadge = `<span class="badge badge-${article.category}">${escapeHtml(article.category)}</span>`;
    const sevBadge = `<span class="badge badge-severity-${article.severity}">${article.severity}</span>`;
    const sectorBadge = article.sector ? `<span class="badge badge-sector">${escapeHtml(article.sector)}</span>` : '';
    const actorBadge = article.threat_actors ? article.threat_actors.split(',').map(a => `<span class="badge badge-actor">${escapeHtml(a.trim())}</span>`).join('') : '';
    const cveLink = article.cve_id ? `<a href="https://nvd.nist.gov/vuln/detail/${article.cve_id}" target="_blank" rel="noopener" class="cve-link">${article.cve_id}</a>` : '';
    const pocBadge = article.has_poc ? '<span class="badge badge-poc">PoC Available</span>' : '';

    // MITRE ATT&CK technique/tactic IDs — key signal for detection engineering
    const mitreIds = article.mitre_ids ? article.mitre_ids.split(',').map(s => s.trim()).filter(Boolean) : [];
    const mitreBadges = mitreIds.map(id =>
      `<a href="${mitreLink(id)}" target="_blank" rel="noopener" class="badge badge-mitre" title="MITRE ATT&CK ${escapeHtml(id)}">${escapeHtml(id)}</a>`
    ).join('');
    const ttpBadge = mitreIds.length ? '<span class="badge badge-ttp">TTP</span>' : '';

    // Patch status — 1 = patched, 0 = unpatched, -1 = unknown
    const patchBadge = article.is_patched === 1
      ? '<span class="badge badge-patched">Patched</span>'
      : article.is_patched === 0
        ? '<span class="badge badge-unpatched">Unpatched</span>'
        : '';

    // Owner label — shows which user's source each article came from
    const ownerBadge = article.owner_name
      ? `<span class="badge badge-owner">${escapeHtml(article.owner_name)}</span>`
      : '';

    // IOCs — extracted indicators
    let iocHtml = '';
    if (article.iocs) {
      const parts = article.iocs.split('|');
      const items = [];
      parts.forEach(p => {
        const [type, values] = p.split(':');
        if (values) {
          values.split(',').slice(0, 3).forEach(v => {
            items.push(`<span class="ioc-tag ioc-${type}" title="${type}: ${escapeHtml(v)}">${escapeHtml(v.length > 30 ? v.substring(0,28)+'..' : v)}</span>`);
          });
        }
      });
      if (items.length) iocHtml = `<div class="article-iocs">${items.join('')}</div>`;
    }

    const desc = article.description ? escapeHtml(article.description.substring(0, 300)) : '';

    // Reviews
    let reviewHtml = '';
    let myReviewStatus = null;
    let reviews = [];
    try { reviews = article.reviews ? JSON.parse(article.reviews) : []; } catch(e) {}
    reviews = reviews.filter(r => r.user_id); // filter out nulls

    // Determine current user's review state for button states
    if (currentUser && currentUser.id) {
      const myReview = reviews.find(r => r.user_id === currentUser.id);
      if (myReview) myReviewStatus = myReview.status;
    }

    // Check if ANY user has escalated this article (for dashboard visibility)
    const escalatedByAnyone = reviews.some(r => r.status === 'escalated');
    const escalatedReview = reviews.find(r => r.status === 'escalated');

    if (reviews.length > 0) {
      reviewHtml = '<div class="article-reviews">';
      reviews.forEach(r => {
        let label;
        if (r.status === 'reviewing') {
          label = `${escapeHtml(r.username)} · reviewing`;
        } else if (r.status === 'escalated') {
          const noteSnippet = r.notes ? ` — ${escapeHtml(r.notes.substring(0, 60))}` : '';
          label = `${escapeHtml(r.username)} · escalated${noteSnippet}`;
        } else {
          label = `${escapeHtml(r.username)} · reviewed`;
        }
        reviewHtml += `<span class="review-tag review-${r.status}">${label}</span>`;
      });
      reviewHtml += '</div>';
    }

    // Button states based on my review status
    let reviewBtnCls = 'btn-review';
    let reviewBtnTxt = 'Review';
    let reviewBtnDisabled = '';
    let doneBtnDisabled = 'disabled';     // ⬅ DEFAULT: only enable when actively reviewing
    let escalateBtnCls = 'btn-escalate';
    let escalateBtnTxt = 'Escalate';
    let escalateBtnDisabled = '';

    if (myReviewStatus === 'reviewing') {
      reviewBtnCls = 'btn-review reviewing';
      reviewBtnTxt = 'In Review';
      doneBtnDisabled = '';               // ⬅ enable Done when reviewing
    } else if (myReviewStatus === 'reviewed') {
      reviewBtnTxt = 'Reviewed ✓';
      reviewBtnCls = 'btn-review reviewing';
      reviewBtnDisabled = 'disabled';
    } else if (myReviewStatus === 'escalated') {
      escalateBtnCls = 'btn-escalate escalated';
      escalateBtnTxt = 'Escalated';
      escalateBtnDisabled = 'disabled';
      reviewBtnTxt = 'N/A';
      reviewBtnDisabled = 'disabled';
      doneBtnDisabled = 'disabled';
    }

    // Card CSS class for review state
    let cardExtraCls = '';
    if (myReviewStatus === 'reviewed') cardExtraCls = ' reviewed-by-me';
    else if (escalatedByAnyone) cardExtraCls = ' escalated-by-me';

    return `
      <article class="article-card ${article.severity === 'critical' ? 'critical' : ''} ${mitreIds.length ? 'has-ttp' : ''}${cardExtraCls}" data-article-id="${article.id}">
        <div class="article-header">
          <div class="article-badges">${catBadge}${sevBadge}${ownerBadge}${ttpBadge}${pocBadge}${patchBadge}${sectorBadge}${actorBadge}${mitreBadges}${cveLink}</div>
        </div>
        <h3 class="article-title"><a href="${escapeHtml(article.url)}" target="_blank" rel="noopener">${escapeHtml(article.title)}</a></h3>
        <div class="article-meta">
          <span>${escapeHtml(article.source_name)}</span>
          ${article.author ? `<span>by ${escapeHtml(article.author)}</span>` : ''}
          <span>${relativeTime(article.published_date)}</span>
        </div>
        ${desc ? `<p class="article-desc">${desc}</p>` : ''}
        ${article.tags ? `<div class="article-tags">${article.tags.split(',').map(t => `<span class="tag">${t.trim()}</span>`).join('')}</div>` : ''}
        ${iocHtml}
        ${reviewHtml}
        <div class="article-actions">
          <button class="${reviewBtnCls}" data-review-article="${article.id}" title="Start reviewing"${reviewBtnDisabled}>${reviewBtnTxt}</button>
          <button class="btn-review-done" data-review-done="${article.id}" title="Mark as reviewed"${doneBtnDisabled}>Done</button>
          <button class="${escalateBtnCls}" data-escalate="${article.id}" title="Escalate"${escalateBtnDisabled}>${escalateBtnTxt}</button>
        </div>
      </article>`;
  }

  // Unified source health status — same logic used by the admin panel
  function sourceStatus(source) {
    if (!source.enabled) return { cls: 'disabled', label: 'Disabled', color: 'var(--text-muted)' };
    if (source.last_error) return { cls: 'error', label: 'Error', color: 'var(--red)' };
    if (source.last_fetched) return { cls: 'active', label: 'OK', color: 'var(--green)' };
    return { cls: 'idle', label: 'Not yet fetched', color: 'var(--text-muted)' };
  }

  function renderSources() {
    const list = $('#my-sources-list');
    const totalEl = $('#dash-sources-total');
    if (totalEl) totalEl.textContent = state.sources.length ? `${state.sources.length} source${state.sources.length > 1 ? 's' : ''}` : '';
    if (state.sources.length === 0) {
      list.innerHTML = '<p class="empty-sources">No sources yet. Add your first source above to start tracking threats!</p>';
      const sa = $('#dash-select-all'); if (sa) sa.checked = false;
      updateDashBulkBar();
      return;
    }
    list.innerHTML = state.sources.map(s => renderSourceItem(s)).join('');
  }

  function renderSourceItem(source) {
    const st = sourceStatus(source);
    const lastFetched = source.last_fetched ? relativeTime(source.last_fetched) : 'Never';

    return `
      <div class="source-item" data-source-id="${source.id}">
        <input type="checkbox" class="dash-source-cb" data-src-id="${source.id}" data-src-url="${escapeHtml(source.url)}" data-src-name="${escapeHtml(source.name)}" style="margin-right:6px;cursor:pointer;">
        <span class="source-status-dot ${st.cls}" title="${st.label}"></span>
        <div class="source-info">
          <div class="source-info-name" title="${escapeHtml(source.name)}"><a href="${escapeHtml(source.url || '#')}" target="_blank" rel="noopener" style="color:inherit;text-decoration:none;" onmouseover="this.style.color='var(--cyan)'" onmouseout="this.style.color='inherit'">${escapeHtml(source.name)}</a></div>
          <div class="source-info-meta">Fetched: ${lastFetched} <span style="color:${st.color};font-size:10px;" title="${source.last_error ? escapeHtml(source.last_error) : st.label}">${st.label}</span></div>
        </div>
        <div class="source-actions">
          <label class="toggle-switch source-toggle">
            <input type="checkbox" ${source.enabled ? 'checked' : ''} data-toggle-source="${source.id}">
            <span class="toggle-slider"></span>
          </label>
        </div>
      </div>`;
  }

  function updateDashBulkBar() {
    const checked = document.querySelectorAll('.dash-source-cb:checked');
    const bar = $('#dashboard-bulk-bar');
    if (checked.length > 0) {
      bar.classList.remove('hidden');
      $('#dash-selected-count').textContent = checked.length + ' selected';
    } else {
      bar.classList.add('hidden');
    }
  }

  //
  //  SOURCE & NOTIFICATION ACTIONS
  //
  async function addSource(formData) {
    try {
      await api('POST', d('L2FwaS9zb3VyY2Vz'), formData);
      showToast('Source Added', `${formData.name} has been added.`, 'success');
      fetchSources();
      $('#add-source-form').reset();
    } catch (e) { showToast('Error', e.message, 'error'); }
  }

  async function toggleSource(id, enabled) {
    try {
      await api('PUT', `${d('L2FwaS9zb3VyY2Vz')}/${id}`, { enabled: enabled ? 1 : 0 });
    } catch (e) { showToast('Error', e.message, 'error'); fetchSources(); }
  }

  async function deleteSource(id) {
    try {
      await api('DELETE', `${d('L2FwaS9zb3VyY2Vz')}/${id}`);
      showToast('Source Removed', 'Source has been deleted.', 'success');
      fetchSources();
    } catch (e) { showToast('Error', e.message, 'error'); }
  }

  async function saveNotificationSettings() {
    try {
      await api('PUT', d('L2FwaS9ub3RpZmljYXRpb25zL3NldHRpbmdz'), {
        email: $('#notif-email').value.trim(),
        email_enabled: $('#notif-email-enabled').checked ? 1 : 0,
        telegram_chat_id: $('#notif-telegram').value.trim(),
        telegram_bot_token: $('#notif-telegram-token').value.trim(),
        telegram_enabled: $('#notif-telegram-enabled').checked ? 1 : 0,
        teams_webhook: $('#notif-teams-webhook').value.trim(),
        teams_enabled: $('#notif-teams-enabled').checked ? 1 : 0,
        whatsapp_number: $('#notif-whatsapp-number').value.trim(),
        whatsapp_apikey: $('#notif-whatsapp-apikey').value.trim(),
        whatsapp_enabled: $('#notif-whatsapp-enabled').checked ? 1 : 0,
        severity_threshold: $('#notif-severity').value,
        keywords_filter: $('#notif-keywords').value.trim()
      });
      showToast('Saved', 'Notification settings updated.', 'success');
    } catch (e) { showToast('Error', e.message, 'error'); }
  }

  async function testNotification(type) {
    try {
      const r = await api('POST', d('L2FwaS9ub3RpZmljYXRpb25zL3Rlc3Q='), { type });
      if (r && r.success === false) {
        showToast('Test failed', r.error || 'Channel not configured', 'error');
      } else {
        showToast('Test sent', `Check your ${type}.`, 'success');
      }
    } catch (e) { showToast('Error', e.message, 'error'); }
  }

  async function fetchNow() {
    if (state.isFetching) return;
    state.isFetching = true;
    $('#fetch-now-btn').disabled = true;
    showToast('Fetching', 'Fetching latest threats...', 'info');
    try {
      await api('POST', d('L2FwaS9mZXRjaC1ub3c='));
      setTimeout(async () => {
        await Promise.allSettled([fetchStats(), fetchArticles(), fetchSources()]);
        showToast('Complete', 'Feeds updated.', 'success');
        state.isFetching = false;
        $('#fetch-now-btn').disabled = false;
      }, 5000);
    } catch (e) {
      showToast('Error', e.message, 'error');
      state.isFetching = false;
      $('#fetch-now-btn').disabled = false;
    }
  }

  function clearFilters() {
    state.filters = { category: '', severity: '', source_type: '', search: '', sector: '', threat_actor: '', has_poc: '', has_mitre: '', is_patched: '', time_range: '', start_date: '', end_date: '' };
    state.currentPage = 1;
    const si = $('#search-input'); if (si) si.value = '';
    ['#severity-filter', '#source-type-filter', '#sector-filter', '#threat-actor-filter', '#patch-filter', '#time-range-filter'].forEach(sel => {
      const el = $(sel); if (el) { el.value = ''; el.classList.remove('has-value'); }
    });
    $$('.toggle-pill').forEach(b => b.classList.remove('active'));
    $$('#category-filters .pill').forEach(p => p.classList.remove('active'));
    const allPill = document.querySelector('#category-filters .pill[data-category=""]');
    if (allPill) allPill.classList.add('active');
    // Remove custom date picker and range tag
    const picker = $('#custom-date-picker');
    if (picker) picker.remove();
    const tag = document.querySelector('.selected-range-tag');
    if (tag) tag.remove();
    updateClearAllButton();
    fetchArticles();
  }

  function hasActiveFilters() {
    const f = state.filters;
    return !!(f.category || f.severity || f.source_type || f.search ||
              f.sector || f.threat_actor || f.has_poc || f.has_mitre ||
              (f.is_patched !== '') || f.time_range ||
              f.start_date || f.end_date);
  }

  function updateClearAllButton() {
    const btn = $('#clear-all-filters-btn');
    if (btn) {
      btn.classList.toggle('visible', hasActiveFilters());
    }
  }

  function exportArticles() {
    const blob = new Blob([JSON.stringify(state.articles, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `threatpulse-export-${new Date().toISOString().split('T')[0]}.json`;
    a.click(); URL.revokeObjectURL(url);
  }

  //
  //  AUTO-REFRESH
  //
  function startAutoRefresh() {
    state.refreshCountdown = 60;
    if (state.countdownTimer) clearInterval(state.countdownTimer);
    if (state.refreshTimer) clearInterval(state.refreshTimer);

    state.countdownTimer = setInterval(() => {
      state.refreshCountdown--;
      const el = $('#refresh-countdown');
      if (el) el.textContent = state.refreshCountdown;
      if (state.refreshCountdown <= 0) state.refreshCountdown = 60;
    }, 1000);

    state.refreshTimer = setInterval(async () => {
      state.refreshCountdown = 60;
      await Promise.allSettled([fetchStats(), fetchArticles()]);
    }, 60000);
  }

  //
  //  EVENT BINDING
  //
  function bindEvents() {
    // Auth: Login
    $('#login-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = $('#login-error');
      errEl.classList.add('hidden');
      errEl.textContent = '';

      const username = $('#login-username').value.trim();
      const password = $('#login-password').value;

      // Client-side validation
      if (!username) {
        errEl.textContent = 'Please enter your username or email';
        errEl.classList.remove('hidden');
        return;
      }
      if (!password) {
        errEl.textContent = 'Please enter your password';
        errEl.classList.remove('hidden');
        return;
      }

      $('#login-btn').disabled = true;
      $('#login-btn').textContent = 'Signing in…';

      try {
        const result = await fetch(d('L2FwaS9hdXRoL2xvZ2lu'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, password })
        }).then(r => r.json());

        if (result.success) {
          setUser(result.user);
          initDashboard();
        } else {
          errEl.textContent = (result.error || 'Invalid username/email or password');
          errEl.classList.remove('hidden');
          $('#login-password').value = '';
          $('#login-password').focus();
        }
      } catch (err) {
        errEl.textContent = 'Connection error — could not reach the server';
        errEl.classList.remove('hidden');
      } finally {
        $('#login-btn').disabled = false;
        $('#login-btn').textContent = 'Sign In';
      }
    });

    // Clear login error on input
    $('#login-username').addEventListener('input', () => { $('#login-error').classList.add('hidden'); });
    $('#login-password').addEventListener('input', () => { $('#login-error').classList.add('hidden'); });

    // Auth: Register — password strength + confirm match (real-time)
    $('#reg-password').addEventListener('input', () => {
      const pw = $('#reg-password').value;
      const meter = $('#password-strength');
      if (!pw) { meter.classList.add('hidden'); meter.className = 'password-strength hidden'; return; }
      meter.classList.remove('hidden');
      let score = 0;
      if (pw.length >= 8) score++;
      if (pw.length >= 12) score++;
      if (/[A-Z]/.test(pw)) score++;
      if (/[a-z]/.test(pw)) score++;
      if (/[0-9]/.test(pw)) score++;
      if (/[^A-Za-z0-9]/.test(pw)) score++;
      const levels = ['weak','weak','fair','good','strong','strong','strong'];
      const labels = ['Very Weak','Weak','Fair','Good','Strong','Very Strong','Excellent'];
      const cls = levels[Math.min(score, 6)];
      $('#strength-text').textContent = labels[Math.min(score, 6)];
      meter.className = 'password-strength strength-' + cls;
    });
    $('#reg-confirm').addEventListener('input', () => {
      const match = $('#reg-password').value === $('#reg-confirm').value;
      const hint = $('#confirm-match');
      if ($('#reg-confirm').value) {
        hint.classList.toggle('hidden', match);
      } else {
        hint.classList.add('hidden');
      }
    });

    // Auth: Register
    $('#register-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = $('#register-error');
      errEl.classList.add('hidden');
      errEl.textContent = '';

      // Gather values
      const username = $('#reg-username').value.trim();
      const displayName = $('#reg-display').value.trim();
      const email = $('#reg-email').value.trim();
      const pw = $('#reg-password').value;
      const confirmPw = $('#reg-confirm').value;
      const inviteCode = $('#reg-invite').value.trim();

      // Client-side validation — check each field
      if (!username || username.length < 3) {
        errEl.textContent = 'Username must be at least 3 characters';
        errEl.classList.remove('hidden');
        return;
      }
      if (!/^[a-zA-Z0-9_.-]+$/.test(username)) {
        errEl.textContent = 'Username can only contain letters, numbers, dots, hyphens, and underscores';
        errEl.classList.remove('hidden');
        return;
      }
      if (!displayName || displayName.length < 2) {
        errEl.textContent = 'Display name must be at least 2 characters';
        errEl.classList.remove('hidden');
        return;
      }
      if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        errEl.textContent = 'Please enter a valid email address';
        errEl.classList.remove('hidden');
        return;
      }
      if (!pw || pw.length < 8) {
        errEl.textContent = 'Password must be at least 8 characters';
        errEl.classList.remove('hidden');
        return;
      }
      if (!/[A-Z]/.test(pw)) {
        errEl.textContent = 'Password must contain at least one uppercase letter';
        errEl.classList.remove('hidden');
        return;
      }
      if (!/[a-z]/.test(pw)) {
        errEl.textContent = 'Password must contain at least one lowercase letter';
        errEl.classList.remove('hidden');
        return;
      }
      if (!/[0-9]/.test(pw)) {
        errEl.textContent = 'Password must contain at least one number';
        errEl.classList.remove('hidden');
        return;
      }
      if (pw !== confirmPw) {
        errEl.textContent = 'Passwords do not match';
        errEl.classList.remove('hidden');
        return;
      }
      if (!inviteCode) {
        errEl.textContent = 'Please enter your invite code';
        errEl.classList.remove('hidden');
        return;
      }

      $('#register-btn').disabled = true;
      $('#register-btn').textContent = 'Creating account…';

      try {
        const result = await fetch(d('L2FwaS9hdXRoL3JlZ2lzdGVy'), {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ username, displayName, password: pw, email, inviteCode })
        }).then(r => r.json());

        if (result.success) {
          setUser(result.user);
          initDashboard();
        } else {
          errEl.textContent = result.error || 'Registration failed';
          errEl.classList.remove('hidden');
        }
      } catch (err) {
        errEl.textContent = 'Connection error — could not reach the server';
        errEl.classList.remove('hidden');
      } finally {
        $('#register-btn').disabled = false;
        $('#register-btn').textContent = 'Create Account';
      }
    });

    // Clear register error on input
    ['#reg-username','#reg-display','#reg-email','#reg-password','#reg-confirm','#reg-invite'].forEach(sel => {
      $(sel)?.addEventListener('input', () => { $('#register-error').classList.add('hidden'); });
    });

    // Auth: Forgot password — show the request form
    $('#forgot-password-btn')?.addEventListener('click', () => {
      $('#login-form').classList.add('hidden');
      $('#forgot-password-form').classList.remove('hidden');
      $('#forgot-error').classList.add('hidden');
      $('#forgot-success').classList.add('hidden');
    });
    $('#back-to-login-btn')?.addEventListener('click', () => {
      $('#forgot-password-form').classList.add('hidden');
      $('#login-form').classList.remove('hidden');
    });
    $('#forgot-password-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = $('#forgot-error'), okEl = $('#forgot-success');
      errEl.classList.add('hidden'); okEl.classList.add('hidden');
      errEl.textContent = ''; okEl.textContent = '';

      const email = $('#forgot-email').value.trim();

      // Client-side validation
      if (!email) {
        errEl.textContent = 'Please enter your email address';
        errEl.classList.remove('hidden');
        return;
      }
      if (!/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
        errEl.textContent = 'Please enter a valid email address';
        errEl.classList.remove('hidden');
        return;
      }

      $('#forgot-btn').disabled = true;
      $('#forgot-btn').textContent = 'Sending…';

      try {
        const result = await fetch(d('L2FwaS9hdXRoL2ZvcmdvdC1wYXNzd29yZA=='), {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ email })
        }).then(r => r.json());
        if (result.success) {
          let msg = result.message || 'If that email exists, a reset link has been sent.';
          if (result._devResetLink) {
            msg += '\n\n⚠️ SMTP not configured. Copy this link to reset:\n' + result._devResetLink;
          }
          okEl.textContent = msg;
          okEl.classList.remove('hidden');
        } else {
          errEl.textContent = (result.error || 'Request failed');
          errEl.classList.remove('hidden');
        }
      } catch (err) {
        errEl.textContent = 'Connection error — could not reach the server';
        errEl.classList.remove('hidden');
      } finally {
        $('#forgot-btn').disabled = false;
        $('#forgot-btn').textContent = 'Send Reset Link';
      }
    });

    // Auth: Reset password (token comes from the ?reset= link in the email)
    $('#reset-password-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = $('#reset-error'), okEl = $('#reset-success');
      errEl.classList.add('hidden'); okEl.classList.add('hidden');
      errEl.textContent = ''; okEl.textContent = '';

      const pw = $('#reset-password').value, confirmPw = $('#reset-confirm').value;

      // Client-side validation
      if (!pw || pw.length < 8) {
        errEl.textContent = 'Password must be at least 8 characters';
        errEl.classList.remove('hidden');
        return;
      }
      if (!/[A-Z]/.test(pw)) {
        errEl.textContent = 'Password must contain at least one uppercase letter';
        errEl.classList.remove('hidden');
        return;
      }
      if (!/[a-z]/.test(pw)) {
        errEl.textContent = 'Password must contain at least one lowercase letter';
        errEl.classList.remove('hidden');
        return;
      }
      if (!/[0-9]/.test(pw)) {
        errEl.textContent = 'Password must contain at least one number';
        errEl.classList.remove('hidden');
        return;
      }
      if (pw !== confirmPw) {
        errEl.textContent = 'Passwords do not match';
        errEl.classList.remove('hidden');
        return;
      }

      const token = new URLSearchParams(window.location.search).get('reset');
      if (!token) {
        errEl.textContent = 'Missing reset token. Please use the link from your email.';
        errEl.classList.remove('hidden');
        return;
      }

      $('#reset-btn').disabled = true;
      $('#reset-btn').textContent = 'Resetting…';

      try {
        const result = await fetch(d('L2FwaS9hdXRoL3Jlc2V0LXBhc3N3b3Jk'), {
          method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token, newPassword: pw })
        }).then(r => r.json());
        if (result.success) {
          okEl.textContent = 'Password reset! Redirecting to sign in…';
          okEl.classList.remove('hidden');
          setTimeout(() => { window.location.href = '/'; }, 1600);
        } else {
          errEl.textContent = (result.error || 'Reset failed');
          errEl.classList.remove('hidden');
        }
      } catch (err) {
        errEl.textContent = 'Connection error — could not reach the server';
        errEl.classList.remove('hidden');
      } finally {
        $('#reset-btn').disabled = false;
        $('#reset-btn').textContent = 'Reset Password';
      }
    });

    // Auth: Toggle login/register
    $('#auth-toggle-btn').addEventListener('click', () => {
      const loginForm = $('#login-form');
      const regForm = $('#register-form');
      const toggleText = $('#auth-toggle-text');
      const toggleBtn = $('#auth-toggle-btn');
      if (loginForm.classList.contains('hidden')) {
        loginForm.classList.remove('hidden');
        regForm.classList.add('hidden');
        toggleText.textContent = "Don't have an account?";
        toggleBtn.textContent = 'Register';
      } else {
        loginForm.classList.add('hidden');
        regForm.classList.remove('hidden');
        toggleText.textContent = 'Already have an account?';
        toggleBtn.textContent = 'Sign In';
      }
    });

    // User menu toggle
    $('#user-menu-btn').addEventListener('click', (e) => {
      e.stopPropagation();
      $('#user-dropdown').classList.toggle('hidden');
    });
    document.addEventListener('click', () => {
      $('#user-dropdown').classList.add('hidden');
    });

    // Logout
    $('#logout-btn').addEventListener('click', logout);

    // Change email
    $('#change-email-btn').addEventListener('click', () => {
      $('#email-error').classList.add('hidden');
      $('#account-email').value = (currentUser && currentUser.email) || '';
      $('#email-modal').classList.remove('hidden');
    });
    $('#cancel-email-btn').addEventListener('click', () => {
      $('#email-modal').classList.add('hidden');
    });
    $('#email-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = $('#email-error');
      errEl.classList.add('hidden');
      try {
        const result = await api('PUT', d('L2FwaS9hdXRoL2VtYWls'), { email: $('#account-email').value.trim() });
        if (result.success && result.verificationRequired) {
          $('#email-modal').classList.add('hidden');
          $('#verification-code').value = '';
          $('#verification-error').classList.add('hidden');
          $('#verification-notice').textContent = `We sent a 6-digit verification code to your new email: ${result.email}. Please enter it below to confirm.`;
          state.pendingVerificationType = 'email_change';
          $('#verification-modal').classList.remove('hidden');
        } else {
          errEl.textContent = result.error || 'Failed to update email'; errEl.classList.remove('hidden');
        }
      } catch (err) {
        errEl.textContent = err.message; errEl.classList.remove('hidden');
      }
    });

    // Change password
    $('#change-password-btn').addEventListener('click', () => {
      $('#password-modal').classList.remove('hidden');
    });
    $('#cancel-password-btn').addEventListener('click', () => {
      $('#password-modal').classList.add('hidden');
    });
    $('#password-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = $('#password-error');
      errEl.classList.add('hidden');
      try {
        const result = await api('PUT', d('L2FwaS9hdXRoL3Bhc3N3b3Jk'), {
          currentPassword: $('#current-password').value,
          newPassword: $('#new-password').value
        });
        if (result.success && result.verificationRequired) {
          $('#password-modal').classList.add('hidden');
          $('#verification-code').value = '';
          $('#verification-error').classList.add('hidden');
          $('#verification-notice').textContent = `We sent a 6-digit verification code to your registered email: ${result.email}. Please enter it below to confirm.`;
          state.pendingVerificationType = 'password_change';
          $('#verification-modal').classList.remove('hidden');
        } else {
          errEl.textContent = result.error || 'Failed to change password';
          errEl.classList.remove('hidden');
        }
      } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.remove('hidden');
      }
    });

    // Verification Form submit
    $('#cancel-verification-btn')?.addEventListener('click', () => {
      $('#verification-modal').classList.add('hidden');
      state.pendingVerificationType = null;
    });
    $('#verification-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = $('#verification-error');
      errEl.classList.add('hidden');
      try {
        const code = $('#verification-code').value.trim();
        const type = state.pendingVerificationType;
        if (!code || !type) return;

        const result = await api('POST', d('L2FwaS9hdXRoL3ZlcmlmeS1jaGFuZ2U='), { type, code });
        if (result.success) {
          if (type === 'email_change') {
            if (currentUser) {
              currentUser.email = result.email;
            }
            showToast('Success', 'Email updated successfully.', 'success');
          } else if (type === 'password_change') {
            if (currentUser) {
              currentUser.mustChangePassword = false;
            }
            showToast('Success', 'Password changed successfully.', 'success');
            const notice = $('#password-forced-notice');
            if (notice) notice.classList.add('hidden');
            const cancelBtn = $('#cancel-password-btn');
            if (cancelBtn) cancelBtn.classList.remove('hidden');
          }
          $('#verification-modal').classList.add('hidden');
          $('#password-form').reset();
          state.pendingVerificationType = null;
        } else {
          errEl.textContent = result.error || 'Verification failed';
          errEl.classList.remove('hidden');
        }
      } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.remove('hidden');
      }
    });

    // Search
    const searchInput = $('#search-input');
    searchInput.addEventListener('input', debounce(() => {
      state.filters.search = searchInput.value;
      state.currentPage = 1;
      updateClearAllButton();
      fetchArticles();
    }, 400));

    // Category pills
    $$('#category-filters .pill').forEach(pill => {
      pill.addEventListener('click', () => {
        const clickedCategory = pill.dataset.category;
        // If clicking the already-active pill (and it's not 'All'), deselect it
        if (pill.classList.contains('active') && clickedCategory !== '') {
          pill.classList.remove('active');
          state.filters.category = '';
          const allPill = document.querySelector('#category-filters .pill[data-category=""]');
          if (allPill) allPill.classList.add('active');
        } else {
          $$('#category-filters .pill').forEach(p => p.classList.remove('active'));
          pill.classList.add('active');
          state.filters.category = clickedCategory;
        }
        state.currentPage = 1;
        updateClearAllButton();
        fetchArticles();
      });
    });

    // Severity filter
    // Dropdown filters — shared handler that adds/removes .has-value class
    ['#severity-filter', '#source-type-filter', '#sector-filter', '#threat-actor-filter', '#patch-filter', '#time-range-filter'].forEach(sel => {
      const el = $(sel);
      if (!el) return;
      el.addEventListener('change', (e) => {
        const filterMap = {
          '#severity-filter': 'severity',
          '#source-type-filter': 'source_type',
          '#sector-filter': 'sector',
          '#threat-actor-filter': 'threat_actor',
          '#patch-filter': 'is_patched',
          '#time-range-filter': 'time_range'
        };
        state.filters[filterMap[sel]] = e.target.value;
        e.target.classList.toggle('has-value', e.target.value !== '');
        state.currentPage = 1;
        updateClearAllButton();
        fetchArticles();
      });
    });

    // Detection-engineering toggle pills (PoC / MITRE)
    $$('.toggle-pill').forEach(btn => {
      btn.addEventListener('click', () => {
        const key = btn.dataset.filter; // has_poc | has_mitre
        const active = btn.classList.toggle('active');
        state.filters[key] = active ? '1' : '';
        state.currentPage = 1;
        updateClearAllButton();
        fetchArticles();
      });
    });

    // Chart time range pills
    document.addEventListener('click', (e) => {
      const chartPill = e.target.closest('#chart-time-pills .pill');
      if (chartPill) {
        $$('#chart-time-pills .pill').forEach(p => p.classList.remove('active'));
        chartPill.classList.add('active');
        _chartRange = parseInt(chartPill.dataset.chartRange);
        renderChart(_chartTimeline, _chartRange);
      }
    });

    // Custom date range picker (Task 5)
    $('#time-range-filter').addEventListener('change', (e) => {
      const picker = $('#custom-date-picker');
      if (e.target.value === 'custom') {
        if (!picker) {
          // Create the picker dynamically
          const pickerEl = document.createElement('div');
          pickerEl.id = 'custom-date-picker';
          pickerEl.className = 'custom-date-picker visible';
          const tz = Intl.DateTimeFormat().resolvedOptions().timeZone;
          pickerEl.innerHTML = `
            <label>From</label>
            <input type="datetime-local" id="custom-date-start">
            <label>To</label>
            <input type="datetime-local" id="custom-date-end">
            <span class="tz-label">${tz}</span>
            <button class="date-apply-btn" id="custom-date-apply">Apply</button>
          `;
          e.target.parentElement.appendChild(pickerEl);
          // Set defaults: last 7 days
          const now = new Date();
          const weekAgo = new Date(now.getTime() - 7*24*60*60*1000);
          document.getElementById('custom-date-start').value = toLocalDatetime(weekAgo);
          document.getElementById('custom-date-end').value = toLocalDatetime(now);
        } else {
          picker.classList.add('visible');
        }
      } else if (picker) {
        picker.classList.remove('visible');
      }
    });

    // Custom date apply
    document.addEventListener('click', (e) => {
      if (e.target.id === 'custom-date-apply') {
        const startEl = $('#custom-date-start');
        const endEl = $('#custom-date-end');
        if (startEl && endEl) {
          state.filters.start_date = new Date(startEl.value).toISOString();
          state.filters.end_date = new Date(endEl.value).toISOString();
          state.currentPage = 1;
          updateClearAllButton();
          showSelectedRangeTag(startEl.value, endEl.value);
          fetchArticles();
        }
      }
      // Remove custom range tag
      if (e.target.classList.contains('remove-range')) {
        const tag = e.target.closest('.selected-range-tag');
        if (tag) tag.remove();
        state.filters.start_date = '';
        state.filters.end_date = '';
        $('#time-range-filter').value = '';
        updateClearAllButton();
        fetchArticles();
      }
    });

    // Review buttons — improved UX (Task 7)
    document.addEventListener('click', (e) => {
      const reviewBtn = e.target.closest('[data-review-article]');
      if (reviewBtn) {
        const articleId = parseInt(reviewBtn.dataset.reviewArticle);
        reviewBtn.textContent = 'Starting...';
        reviewBtn.disabled = true;
        api('POST', `${d('L2FwaS9hcnRpY2xlcw==')}/${articleId}/review`).then(() => {
          showToast('Reviewing', 'You are now reviewing this article.', 'info');
          fetchArticles();
        }).catch(err => {
          showToast('Error', err.message, 'error');
          reviewBtn.textContent = 'Review';
          reviewBtn.disabled = false;
        });
      }

      const doneBtn = e.target.closest('[data-review-done]');
      if (doneBtn) {
        const articleId = parseInt(doneBtn.dataset.reviewDone);
        doneBtn.textContent = 'Saving...';
        doneBtn.disabled = true;
        const notes = prompt('Add review notes (optional):') || '';
        api('PUT', `${d('L2FwaS9hcnRpY2xlcw==')}/${articleId}/review`, { notes }).then(() => {
          showToast('Reviewed', 'Article marked as reviewed.', 'success');
          fetchArticles();
        }).catch(err => {
          showToast('Error', err.message, 'error');
          doneBtn.textContent = 'Done';
          doneBtn.disabled = false;
        });
      }

      const escalateBtn = e.target.closest('[data-escalate]');
      if (escalateBtn) {
        const articleId = parseInt(escalateBtn.dataset.escalate);
        escalateBtn.textContent = 'Escalating...';
        escalateBtn.disabled = true;
        const notes = prompt('Why are you escalating this? Provide context:') || '';
        api('POST', `${d('L2FwaS9hcnRpY2xlcw==')}/${articleId}/escalate`, { notes }).then(() => {
          showToast('Escalated', 'Article has been escalated.', 'warning');
          fetchArticles();
        }).catch(err => {
          showToast('Error', err.message, 'error');
          escalateBtn.textContent = 'Escalate';
          escalateBtn.disabled = false;
        });
      }
    });

    // Fetch now
    $('#fetch-now-btn').addEventListener('click', fetchNow);
    $('#fetch-now-empty').addEventListener('click', fetchNow);

    // Auth: Login
    $('#clear-filters-btn')?.addEventListener('click', clearFilters);
    $('#clear-all-filters-btn')?.addEventListener('click', clearFilters);

    // Export
    $('#export-btn').addEventListener('click', exportArticles);

    // Stat cards clickable — filter feed on click
    $$('.stat-card').forEach(card => {
      card.addEventListener('click', () => {
        const stat = card.dataset.stat;
        clearFilters();
        if (stat === 'threats') {
          const today = new Date().toISOString().split('T')[0];
          state.filters.start_date = today + 'T00:00:00.000Z';
          state.filters.end_date = today + 'T23:59:59.999Z';
          state.filters.time_range = 'custom';
        } else if (stat === 'critical') {
          state.filters.severity = 'critical';
          $('#severity-filter').value = 'critical';
        } else if (stat === 'pocs') {
          state.filters.has_poc = '1';
          $('#filter-poc').classList.add('active');
        }
        state.currentPage = 1;
        updateClearAllButton();
        fetchArticles();
      });
    });

    // Load more
    $('#load-more-btn').addEventListener('click', () => {
      fetchArticles(state.currentPage + 1, true);
    });

    // Add source
    $('#add-source-form').addEventListener('submit', (e) => {
      e.preventDefault();
      addSource({
        url: $('#source-url').value.trim(),
        name: $('#source-name').value.trim(),
        type: $('#source-type').value,
        category: $('#source-category').value
      });
    });

    // Source toggle & delete (delegated)
    document.addEventListener('change', (e) => {
      const toggle = e.target.closest('[data-toggle-source]');
      if (toggle) toggleSource(parseInt(toggle.dataset.toggleSource), toggle.checked);
    });

    document.addEventListener('click', (e) => {
      // Collapse / expand a date section (ignore clicks on links/buttons inside)
      const dateHeader = e.target.closest('.date-header');
      if (dateHeader) {
        const section = dateHeader.closest('.date-section');
        const body = section && section.querySelector('.date-articles');
        const icon = dateHeader.querySelector('.date-header-icon');
        if (body) {
          const collapsed = body.classList.toggle('collapsed');
          if (icon) icon.classList.toggle('collapsed', collapsed);
          dateHeader.setAttribute('aria-expanded', String(!collapsed));
        }
        return;
      }

      // Edit source URL
      const editBtn = e.target.closest('[data-edit-source]');
      if (editBtn) {
        const id = parseInt(editBtn.dataset.editSource);
        const currentUrl = editBtn.dataset.editUrl;
        const newUrl = prompt('Enter new URL for this source:', currentUrl);
        if (newUrl && newUrl.trim() !== currentUrl) {
          api('PUT', `${d('L2FwaS9zb3VyY2Vz')}/${id}`, { url: newUrl.trim() }).then(() => {
            showToast('Updated', 'Source URL updated.', 'success');
            fetchSources();
          }).catch(err => showToast('Error', err.message, 'error'));
        }
      }

      // Delete source
      const deleteBtn = e.target.closest('[data-delete-source]');
      if (deleteBtn) {
        if (confirm('Remove this source?')) {
          deleteSource(parseInt(deleteBtn.dataset.deleteSource));
        }
      }
    });

    // Notification form
    $('#notification-form').addEventListener('submit', (e) => {
      e.preventDefault();
      saveNotificationSettings();
    });
    // Per-channel test buttons — save first so the test uses current values
    $$('.notif-test').forEach(btn => {
      btn.addEventListener('click', async () => {
        await saveNotificationSettings();
        testNotification(btn.dataset.test);
      });
    });

    // Eye toggle for password visibility
    document.addEventListener('click', (eClick) => {
      const eyeBtn = eClick.target.closest('.eye-toggle');
      if (eyeBtn) {
        const targetId = eyeBtn.dataset.target;
        const input = document.getElementById(targetId);
        if (input) {
          input.type = input.type === 'password' ? 'text' : 'password';
          eyeBtn.innerHTML = input.type === 'password' ? ICONS.eye : ICONS.eyeOff;
        }
      }
    });

    // Dashboard source checkboxes
    document.addEventListener('change', (eChg) => {
      if (eChg.target.classList.contains('dash-source-cb')) {
        updateDashBulkBar();
      }
    });

    // Select-all sources
    $('#dash-select-all').addEventListener('change', (e) => {
      document.querySelectorAll('.dash-source-cb').forEach(cb => { cb.checked = e.target.checked; });
      updateDashBulkBar();
    });

    // Dashboard bulk edit
    $('#dash-edit-btn').addEventListener('click', async () => {
      const checked = document.querySelectorAll('.dash-source-cb:checked');
      if (checked.length === 0) return;
      if (checked.length === 1) {
        const cb = checked[0];
        const newUrl = prompt(`Edit URL for "${cb.dataset.srcName}":`, cb.dataset.srcUrl);
        if (newUrl && newUrl.trim() !== cb.dataset.srcUrl) {
          try {
            await api('PUT', `${d('L2FwaS9zb3VyY2Vz')}/${cb.dataset.srcId}`, { url: newUrl.trim() });
            showToast('Updated', 'Source URL updated.', 'success');
            fetchSources();
          } catch(err) { showToast('Error', err.message, 'error'); }
        }
      } else {
        showToast('Select one source', 'Select only one source to edit URL.', 'error');
      }
    });

    // Dashboard bulk delete
    $('#dash-delete-btn').addEventListener('click', async () => {
      const checked = document.querySelectorAll('.dash-source-cb:checked');
      if (checked.length === 0) return;
      if (confirm(`Delete ${checked.length} selected source(s)?`)) {
        for (const cb of checked) {
          try { await api('DELETE', `${d('L2FwaS9zb3VyY2Vz')}/${cb.dataset.srcId}`); } catch(e) {}
        }
        showToast('Deleted', `${checked.length} source(s) removed.`, 'success');
        fetchSources(); fetchStats();
      }
    });

    // Keyboard shortcut
    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        searchInput.focus();
      }
    });
  }

  //
  //  INITIALIZATION
  //
  function enforcePasswordChange() {
    if (!currentUser || !currentUser.mustChangePassword) return;
    const modal = $('#password-modal');
    modal.classList.remove('hidden');
    const cancelBtn = $('#cancel-password-btn');
    if (cancelBtn) cancelBtn.classList.add('hidden');
    const notice = $('#password-forced-notice');
    if (notice) notice.classList.remove('hidden');
  }

  async function initDashboard() {
    updateClock();
    setInterval(updateClock, 1000);
    // Dynamic favicon — updated via fetchStats
    updateFavicon();
    enforcePasswordChange();
    await Promise.allSettled([fetchStats(), fetchArticles(), fetchSources(), fetchNotificationSettings()]);
    startAutoRefresh();
  }

  function initTheme() {
    const btn = $('#theme-toggle');
    const apply = (t) => {
      document.documentElement.setAttribute('data-theme', t);
      try { localStorage.setItem('tp_theme', t); } catch (e) {}
      if (btn) btn.innerHTML = t === 'light' ? ICONS.sun : ICONS.moon;
    };
    apply(localStorage.getItem('tp_theme') || 'dark');
    if (btn) {
      btn.addEventListener('click', () => {
        const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
        apply(cur === 'light' ? 'dark' : 'light');
      });
    }
  }

  function init() {
    // Wrap so a single binding error can never leave the login button dead.
    try { bindEvents(); } catch (e) { console.error('[init] bindEvents error:', e); }
    try { initTheme(); } catch (e) { console.error('[init] theme error:', e); }

    // Arriving from a password-reset email link? Show the reset form.
    const resetToken = new URLSearchParams(window.location.search).get('reset');
    if (resetToken) {
      showAuth();
      $('#login-form')?.classList.add('hidden');
      $('#reset-password-form')?.classList.remove('hidden');
      return;
    }

    // Check if we have an httpOnly session cookie by hitting the auth endpoint
    // (the cookie is sent automatically, no JS involved)
    fetch(d('L2FwaS9hdXRoL21l'))
      .then(r => {
        if (!r.ok) throw new Error('Not authenticated');
        return r.json();
      })
      .then(data => {
        if (data.success && data.user) {
          currentUser = data.user;
          updateUserMenu();
          scheduleAutoRefresh();
          hideAuth();
          initDashboard();
        } else {
          showAuth();
        }
      })
      .catch(() => showAuth());
  }

  // Start
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

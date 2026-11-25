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
  const aiAnalysis = new Map(); // articleId -> { open, loading, error, data }: AI card analysis kept across re-renders
  let forcedChangeSecret = null; // sign-in password, held only until a forced change completes
  // Access token lifetime is 15 min; refresh proactively at 13 min
  const REFRESH_MARGIN = 13 * 60 * 1000; // refresh 2 min before expiry
  let refreshTimer = null;
  let refreshPromise = null;   // single-flight: concurrent 401s share one refresh
  let sessionEpoch = 0;        // bumped on logout so late refresh results are ignored
  let clockInterval = null;
  let faviconInterval = null;
  let resetAiPanel = () => {}; // assigned in bindEvents (AI panel state lives there)
  // Public server facts from /api/auth/config (invite codes, SMTP, DB reset time)
  let emailNudged = false;
  let serverConfig = { requireInvite: true, emailEnabled: false, dbCreatedAt: null };

  //
  //  STATE
  //
  const state = {
    articles: [],
    sources: [],
    currentPage: 1,
    totalPages: 1,
    totalArticles: 0,
    filters: { category: '', severity: '', source_type: '', search: '', sector: '', threat_actor: '', has_poc: '', has_mitre: '', watchlist: '', is_patched: '', time_range: '', start_date: '', end_date: '' },
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

  // Parse a JSON body without throwing on empty/HTML error pages (e.g. proxy 502s)
  async function readJson(res) {
    try { return await res.json(); } catch { return {}; }
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
        const retryData = await readJson(retryRes);
        if (!retryRes.ok) throw new Error(retryData?.error || `Request failed (${retryRes.status})`);
        return retryData;
      }
      logout();
      throw new Error('Session expired');
    }
    const data = await readJson(res);
    if (!res.ok) throw new Error(data?.error || `Request failed (${res.status})`);
    return data;
  }

  // The server rotates (revokes) the refresh token on every use, so two parallel
  // refreshes would make the second one fail and log the user out. Share one.
  function refreshAccessToken() {
    if (!refreshPromise) {
      refreshPromise = doRefreshAccessToken().finally(() => { refreshPromise = null; });
    }
    return refreshPromise;
  }

  async function doRefreshAccessToken() {
    const epoch = sessionEpoch;
    try {
      const csrf = getCsrfToken();
      const res = await fetch(d('L2FwaS9hdXRoL3JlZnJlc2g='), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf || '' }
      });
      if (!res.ok) return false;
      const data = await res.json();
      if (epoch !== sessionEpoch) return false; // logged out while refreshing
      if (data.success && data.user) {
        // Older servers omitted mustChangePassword from the refresh payload: keep
        // the flag we have only then (a server "false" means the change is done).
        if (data.user.mustChangePassword === undefined && currentUser &&
            currentUser.id === data.user.id && currentUser.mustChangePassword) {
          data.user.mustChangePassword = true;
        }
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
    // Switching account (e.g. guest -> signed in): drop the previous user's AI chat
    if (!currentUser || currentUser.id !== user.id) { resetAiPanel(); aiAnalysis.clear(); }
    currentUser = user;
    updateUserMenu();
    scheduleAutoRefresh();
    hideAuth();
    loadPocTracker();
    loadWatchlist();
  }

  // Wipe everything the previous user could leave behind in the DOM
  function resetSessionUi() {
    ['#email-modal', '#password-modal', '#verification-modal'].forEach(sel => $(sel)?.classList.add('hidden'));
    ['#password-form', '#email-form', '#verification-form', '#notification-form', '#login-form'].forEach(sel => $(sel)?.reset());
    forcedChangeSecret = null;
    setCurrentPasswordFieldVisible(true);   // the next user must be asked for theirs
    setForcedPasswordMode(false);
    $('#password-forced-notice')?.classList.add('hidden');
    $('#user-dropdown')?.classList.add('hidden');
    state.pendingVerificationType = null;
    state.articles = [];
    state.sources = [];
    state.currentPage = 1;
    articlesReqSeq++;            // discard any in-flight article response from the old session
    state.isLoading = false;
    hideLoader();
    const ac = $('#articles-container'); if (ac) ac.innerHTML = '';
    renderSources();
    renderEscalatedSidebar([]);
    resetAiPanel();
    aiAnalysis.clear();
    pocState.items = []; pocState.seq++;
    watchTerms = []; renderWatchlist();
    $('#poc-tracker-card')?.classList.add('hidden');
  }

  function logout() {
    // Call server to clear cookies + blacklist tokens
    fetch(d('L2FwaS9hdXRoL2xvZ291dA=='), { method: 'POST', headers: { 'X-CSRF-Token': getCsrfToken() || '' } }).catch(() => {});

    sessionEpoch++;
    currentUser = null;
    if (refreshTimer) clearTimeout(refreshTimer);
    refreshTimer = null;
    if (state.refreshTimer) clearInterval(state.refreshTimer);
    if (state.countdownTimer) clearInterval(state.countdownTimer);
    state.refreshTimer = state.countdownTimer = null;
    resetSessionUi();
    // Offer "Continue as Guest" (starts a fresh guest session — see guest-back-btn)
    const gb = $('#guest-back'); if (gb) gb.style.display = '';
    showAuth();
  }

  function updateUserMenu() {
    if (!currentUser) return;
    const isGuest = currentUser.username === 'guest';
    const avatar = currentUser.displayName ? currentUser.displayName.charAt(0).toUpperCase() : 'U';
    $('#user-avatar').textContent = avatar;
    $('#user-display-name').textContent = isGuest ? 'Guest' : (currentUser.displayName || currentUser.username);
    $('#dropdown-name').textContent = isGuest ? 'Guest' : (currentUser.displayName || currentUser.username);
    $('#dropdown-role').textContent = isGuest ? 'visitor' : currentUser.role;
    if (currentUser.role === 'admin') {
      $('#admin-link').classList.remove('hidden');
    } else {
      $('#admin-link').classList.add('hidden');
    }
    // Guests get 403 on sources / notifications / fetch-now — hide those controls
    document.body.classList.toggle('guest-mode', isGuest);
    // Guests see a "Sign In / Register" entry; hide account-only options
    if (isGuest) {
      $('#sign-in-btn').classList.remove('hidden');
      $('#change-email-btn').classList.add('hidden');
      $('#change-password-btn').classList.add('hidden');
      $('#logout-btn').classList.add('hidden');
    } else {
      $('#sign-in-btn').classList.add('hidden');
      $('#change-email-btn').classList.remove('hidden');
      $('#change-password-btn').classList.remove('hidden');
      $('#logout-btn').classList.remove('hidden');
    }
    // Accounts without an email can't receive reset links or security notices
    if (!isGuest && !currentUser.email && !currentUser.mustChangePassword && !emailNudged) {
      emailNudged = true;
      setTimeout(() => showToast('Add your email address',
        'Your account has no email, so password-reset links and security alerts cannot reach you. Open your user menu → Change Email.', 'warning'), 1500);
    }
  }

  //
  //  UTILITIES
  //
  function debounce(fn, ms) {
    let timer;
    return (...args) => { clearTimeout(timer); timer = setTimeout(() => fn(...args), ms); };
  }

  // Defence in depth: never render non-http(s) links (e.g. javascript:) as hrefs.
  function safeUrl(u) {
    try { return ['http:', 'https:'].includes(new URL(u, location.href).protocol) ? u : '#'; }
    catch { return '#'; }
  }

  // Must also escape quotes: the result is interpolated into attribute values
  // (title="...", href="...", data-*="..."). textContent->innerHTML does not.
  function escapeHtml(str) {
    if (str === null || str === undefined || str === '') return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  // Set a <select> programmatically and keep its custom dropdown label in sync
  function setSelectValue(el, value) {
    if (!el) return;
    el.value = value;
    el.classList.toggle('has-value', value !== '');
    if (el._syncDisplay) el._syncDisplay();
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

  // Local calendar day of a Date as YYYY-MM-DD (the stats API groups by the
  // viewer's local day when given ?tz=)
  function localDayKey(date) {
    const dt = date instanceof Date ? date : new Date(date);
    return `${dt.getFullYear()}-${String(dt.getMonth() + 1).padStart(2, '0')}-${String(dt.getDate()).padStart(2, '0')}`;
  }

  // ISO start/end instants of a local calendar day ('YYYY-MM-DD' or a Date)
  function localDayBounds(day) {
    const start = typeof day === 'string' ? new Date(day + 'T00:00:00') : new Date(day);
    start.setHours(0, 0, 0, 0);
    const next = new Date(start);
    next.setDate(next.getDate() + 1);
    return { start: start.toISOString(), end: new Date(next.getTime() - 1).toISOString() };
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

  // Dynamic favicon — shield + pulse, with page title badge showing today's count
  let _todayCount = 0;
  let _faviconFrame = 0;
  
  function updateFavicon() {
    const count = _todayCount;
    _faviconFrame++;
    const cycle = 60;
    const f = _faviconFrame % cycle;

    function ringAlpha(offset) {
      const phase = (f + offset) % cycle;
      const progress = phase / cycle;
      if (progress < 0.1) return 0;
      if (progress < 0.7) return 0.8;
      return 0.8 * (1 - (progress - 0.7) / 0.3);
    }

    function ringRadius(offset) {
      const phase = (f + offset) % cycle;
      const progress = phase / cycle;
      return 1.2 + progress * 2.5;
    }

    const color = count > 50 ? '#ff5c7a' : count > 10 ? '#ffab5c' : '#22d3ee';

    // Shield + pulse rings favicon
    const svg = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 16 16">'
      + '<path d="M8 1L3 4v4c0 4 5 7 5 7s5-3 5-7V4L8 1z" fill="none" stroke="' + color + '" stroke-width="0.9" opacity="0.85"/>'
      + '<circle cx="8" cy="7" r="' + ringRadius(0).toFixed(2) + '" fill="none" stroke="' + color + '" stroke-width="0.4" opacity="' + ringAlpha(0).toFixed(2) + '"/>'
      + '<circle cx="8" cy="7" r="' + ringRadius(20).toFixed(2) + '" fill="none" stroke="' + color + '" stroke-width="0.4" opacity="' + ringAlpha(20).toFixed(2) + '"/>'
      + '<circle cx="8" cy="7" r="' + ringRadius(40).toFixed(2) + '" fill="none" stroke="' + color + '" stroke-width="0.4" opacity="' + ringAlpha(40).toFixed(2) + '"/>'
      + '<circle cx="8" cy="7" r="0.8" fill="' + color + '" opacity="0.9"/>'
      + '</svg>';

    const icon = document.querySelector('link[rel=icon]');
    if (icon) icon.href = 'data:image/svg+xml,' + encodeURIComponent(svg);

    // Update page title with count badge
    const baseTitle = 'ThreatPulse';
    document.title = count > 0 ? baseTitle + ' (' + count + ')' : baseTitle;
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
      // tz: minutes east of UTC, so "today" / the chart days are the viewer's own
      const stats = await api('GET', `${d('L2FwaS9hcnRpY2xlcy9zdGF0cw==')}?tz=${-new Date().getTimezoneOffset()}`);
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

  function getChartColors() {
    const isLight = document.documentElement.getAttribute('data-theme') === 'light';
    return {
      grid: isLight ? 'rgba(0,0,0,0.06)' : 'rgba(255,255,255,0.04)',
      axisLabel: isLight ? 'rgba(0,0,0,0.55)' : 'rgba(255,255,255,0.35)',
      xLabel: isLight ? 'rgba(0,0,0,0.6)' : 'rgba(255,255,255,0.42)',
      dotFill: isLight ? '#ffffff' : '#1a1a19',
      // One series, one hue: 2px line + ~10% area wash, no glow
      areaTop: isLight ? 'rgba(42,120,214,0.14)' : 'rgba(57,135,229,0.16)',
      areaMid: isLight ? 'rgba(42,120,214,0.08)' : 'rgba(57,135,229,0.08)',
      areaBot: isLight ? 'rgba(42,120,214,0.01)' : 'rgba(57,135,229,0.01)',
      line: isLight ? '#2a78d6' : '#3987e5',
      glow: 'rgba(0,0,0,0)'
    };
  }

  function renderChart(timeline, days) {
    const canvas = $('#threat-chart');
    const empty = $('#chart-empty');
    if (!canvas) return;

    const colors = getChartColors();

    const preset = CHART_PRESETS[days] || CHART_PRESETS[7];
    const cutoff = new Date();
    cutoff.setDate(cutoff.getDate() - preset.days);
    const cutoffStr = localDayKey(cutoff);   // timeline days are local (see fetchStats)

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
      ctx.strokeStyle = colors.grid;
      ctx.setLineDash([1, 8]);
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(ml, y);
      ctx.lineTo(w - mr, y);
      ctx.stroke();
      ctx.setLineDash([]);

      const val = Math.round(maxVal - (maxVal / gridLines) * i);
      ctx.fillStyle = colors.axisLabel;
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
    grad.addColorStop(0, colors.areaTop);
    grad.addColorStop(0.5, colors.areaMid);
    grad.addColorStop(1, colors.areaBot);

    ctx.beginPath();
    ctx.moveTo(ml, mt + ch);
    points.forEach(p => ctx.lineTo(p.x, p.y));
    ctx.lineTo(w - mr, mt + ch);
    ctx.closePath();
    ctx.fillStyle = grad;
    ctx.fill();

    // Line
    ctx.beginPath();
    points.forEach((p, i) => {
      if (i === 0) ctx.moveTo(p.x, p.y);
      else ctx.lineTo(p.x, p.y);
    });
    ctx.strokeStyle = colors.line;
    ctx.lineWidth = 2;
    ctx.shadowColor = colors.glow;
    ctx.shadowBlur = 8;
    ctx.stroke();
    ctx.shadowBlur = 0;

    // Dots on data points
    points.forEach(p => {
      ctx.beginPath();
      ctx.arc(p.x, p.y, 3, 0, Math.PI * 2);
      ctx.fillStyle = colors.dotFill;
      ctx.fill();
      ctx.strokeStyle = colors.line;
      ctx.lineWidth = 1.5;
      ctx.stroke();
    });

    // X-axis labels
    const labelStep = Math.max(1, Math.floor(data.length / 7));
    ctx.fillStyle = colors.xLabel;
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
        // Set date filter to that (local) day — the timeline counts local days
        const b = localDayBounds(closest.day);
        state.filters.start_date = b.start;
        state.filters.end_date = b.end;
        state.filters.time_range = 'custom';
        showSelectedRangeTag(b.start, b.end);
        state.currentPage = 1;
        setSelectValue($('#time-range-filter'), 'custom');
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
        key = localDayKey(monday);   // toISOString() shifted east-of-UTC weeks a day back
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

    const n = (v) => Number(v) || 0;
    tip.innerHTML = `<strong>${escapeHtml(closest.day)}</strong><br>Total: ${n(closest.count)} | Crit: ${n(closest.critical)} | High: ${n(closest.high)} | Med: ${n(closest.medium)} | Low: ${n(closest.low)}`;
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

  // Latest request wins. Previously a fetch issued while another was in flight
  // (filter change during auto-refresh, stat-card click right after clearFilters)
  // was silently dropped, leaving the feed out of sync with the filters shown.
  let articlesReqSeq = 0;
  async function fetchArticles(page = 1, append = false) {
    if (append && state.isLoading) return;   // don't stack "Load more" on a pending load
    const seq = ++articlesReqSeq;
    state.isLoading = true;
    showLoader();
    try {
      const params = filterParams(page, 50);

      const data = await api('GET', `${d('L2FwaS9hcnRpY2xlcw==')}?${params}`);
      if (seq !== articlesReqSeq) return;     // superseded by a newer request
      state.currentPage = data.page;
      state.totalPages = data.totalPages;
      state.totalArticles = data.total;

      const articles = Array.isArray(data.articles) ? data.articles : [];
      if (append) {
        state.articles = [...state.articles, ...articles];
      } else {
        state.articles = articles;
      }
      renderArticles();
    } catch (e) { console.error('Articles error:', e); }
    finally {
      if (seq === articlesReqSeq) { state.isLoading = false; hideLoader(); }
    }
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
      // Assign unconditionally so a previous user's values never linger in the form
      // Alerts can only go to the account's own address
      $('#notif-email').value = s.email || (currentUser && currentUser.email) || '';
      $('#notif-email-enabled').checked = !!s.email_enabled;
      $('#notif-telegram').value = s.telegram_chat_id || '';
      $('#notif-telegram-token').value = s.telegram_bot_token || '';
      $('#notif-telegram-enabled').checked = !!s.telegram_enabled;
      $('#notif-teams-webhook').value = s.teams_webhook || '';
      $('#notif-teams-enabled').checked = !!s.teams_enabled;
      $('#notif-whatsapp-number').value = s.whatsapp_number || '';
      $('#notif-whatsapp-apikey').value = s.whatsapp_apikey || '';
      $('#notif-whatsapp-enabled').checked = !!s.whatsapp_enabled;
      setSelectValue($('#notif-severity'), s.severity_threshold || 'critical');
      $('#notif-keywords').value = s.keywords_filter || '';
      updateNotifSummary();
    } catch (e) { console.error('Notification settings error:', e); }
  }

  // "2 on" / "Off" chip on the collapsed Notifications header
  function updateNotifSummary() {
    const el = $('#notif-summary');
    if (!el) return;
    const on = [...$$('.notif-channel .toggle-switch input')].filter(i => i.checked).length;
    el.textContent = on ? `${on} on` : 'Off';
    el.classList.toggle('on', on > 0);
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

    if (active.length === 0 && state.currentPage < (state.totalPages || 1)) {
      // Everything on this page was reviewed/escalated (moved to the sidebar) but
      // more pages exist: keep "Load more" reachable instead of an empty dashboard.
      container.innerHTML = '<p class="empty-sources" style="padding:16px;">Everything on this page has been reviewed. Load more to see older threats.</p>';
      empty.classList.add('hidden');
      loadMore.classList.remove('hidden');
      return;
    }
    if (active.length === 0) {
      container.innerHTML = '';
      empty.classList.remove('hidden');
      loadMore.classList.add('hidden');
      const hasFilters = hasActiveFilters();
      $('#empty-title').textContent = hasFilters ? 'No threats match your filters' : 'No Threats Yet';
      const isGuest = currentUser && currentUser.username === 'guest';
      $('#empty-message').textContent = hasFilters
        ? 'Your current filters returned nothing. Try widening them or clear all.'
        : isGuest
          ? 'No threats yet. Sign in or register to add your own sources.'
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
      const noteSnippet = who && who.notes ? `<span class="sidebar-item-note">${escapeHtml(String(who.notes).substring(0, 50))}</span>` : '';
      const title = String(a.title || '');
      return `<div class="sidebar-article-item">
        <a href="${escapeHtml(safeUrl(a.url))}" target="_blank" rel="noopener" class="sidebar-article-link" title="${escapeHtml(title)}">${escapeHtml(title.substring(0, 60))}${title.length > 60 ? '...' : ''}</a>
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

  // Synchrony threat actor classification map (class letter → color/priority)
  const THREAT_ACTOR_CLASSES = {
    // A — Critical
    'Scattered Spider': 'A', 'Nimble Spider': 'A',
    // B — High
    'Arcane Kitten': 'B', 'Bitwise Spider': 'B', 'Brain Spider': 'B', 'Carbon Spider': 'B',
    'Cozy Bear': 'B', 'Donut Spider': 'B', 'Famous Chollima': 'B', 'Frozen Spider': 'B',
    'Honey Spider': 'B', 'Indrik Spider': 'B', 'Knockout Spider': 'B', 'Labyrinth Chollima': 'B',
    'Lunar Spider': 'B', 'Mallard Spider': 'B', 'Mangled Spider': 'B', 'Masked Spider': 'B',
    'Merchant Spider': 'B', 'Monarch Spider': 'B', 'Prophet Spider': 'B', 'Punk Spider': 'B',
    'Recess Spider': 'B', 'Scully Spider': 'B', 'Silent Chollima': 'B', 'Stardust Chollima': 'B',
    'Traveling Spider': 'B', 'Veto Spider': 'B', 'Wandering Spider': 'B', 'Wicked Panda': 'B',
    'Royal Spider': 'B', 'Graceful Spider': 'B', 'Butler Spider': 'B', 'Hook Spider': 'B',
    'Rice Spider': 'B', 'Lightning Spider': 'B', 'Nitro Spider': 'B', 'Murky Panda': 'B',
    'Lightbasin Activity Cluster': 'B', 'Comrade Saiga': 'B',
    // C — Medium
    'Aquatic Panda': 'C', 'Banished Kitten': 'C', 'Cascade Panda': 'C', 'Chariot Spider': 'C',
    'Chef Spider': 'C', 'Clockwork Spider': 'C', 'Cookie Spider': 'C', 'Demon Spider': 'C',
    'Distant Spider': 'C', 'Fancy Bear': 'C', 'Hazard Spider': 'C', 'Hermit Spider': 'C',
    'Highground Activity Cluster': 'C', 'Jackpot Panda': 'C', 'Nemesis Kitten': 'C', 'Ocean Buffalo': 'C',
    'Odyssey Spider': 'C', 'Outrider Tiger': 'C', 'Phantom Panda': 'C', 'Ricochet Chollima': 'C',
    'Salty Spider': 'C', 'Shining Spider': 'C', 'Smoky Spider': 'C', 'Solar Spider': 'C',
    'Spectral Kitten': 'C', 'Squab Spider': 'C', 'Static Kitten': 'C', 'Tunnel Spider': 'C',
    'Vampire Spider': 'C', 'Velvet Chollima': 'C', 'Vengeful Kitten': 'C', 'Vice Spider': 'C',
    'Viking Spider': 'C', 'Alpha Spider': 'C', 'Helix Kitten': 'C', 'Emissary Panda': 'C',
    'Apothecary Spider': 'C', 'Percussion Spider': 'C', 'Renaissance Spider': 'C', 'Samba Spider': 'C',
    'Scion Spider': 'C', 'Sly Spider': 'C', 'Sinful Spider': 'C', 'Curly Spider': 'C',
    'Imperial Kitten': 'C', 'Vault Panda': 'C', 'Radiant Spider': 'C', 'Plump Spider': 'C',
    // D — Low
    'Pulsar Kitten': 'D', 'Chaotic Spider': 'D', 'Holiday Spider': 'D', 'Chatty Spider': 'D', 'Haywire Kitten': 'D',
    // E — Legacy
    'Anthropoid Spider': 'E', 'Aviator Spider': 'E', 'Black Basta': 'E', 'Blind Spider': 'E',
    'Charming Kitten': 'E', 'Circuit Panda': 'E', 'Circus Spider': 'E', 'Cobalt Spider': 'E',
    'Compass Spider': 'E', 'Cyborg Spider': 'E', 'Doppel Spider': 'E', 'Ember Bear': 'E',
    'Feral Spider': 'E', 'Judgement Panda': 'E', 'Keyhole Panda': 'E', 'Monty Spider': 'E',
    'Narwhal Spider': 'E', 'Night Spider': 'E', 'Octane Panda': 'E', 'Outlaw Spider': 'E',
    'Pioneer Kitten': 'E', 'Refined Kitten': 'E', 'Remix Kitten': 'E', 'Riddle Spider': 'E',
    'Skeleton Spider': 'E', 'TA 511': 'E', 'TA 551': 'E', 'Tiny Spider': 'E', 'Twisted Spider': 'E',
    'Venom Spider': 'E', 'Voodoo Bear': 'E', 'Wet Panda': 'E', 'Whisper Spider': 'E', 'Wizard Spider': 'E',
  };

  function actorClass(name) {
    return THREAT_ACTOR_CLASSES[name] || null;
  }

  function createArticleCard(article) {
    const catBadge = categoryBadge(article);
    const sevBadge = severityBadge(article);
    const sectorBadge = article.sector ? `<span class="badge badge-sector">${escapeHtml(article.sector)}</span>` : '';
    // Threat actors render as a distinct label with their Synchrony class badge (A/B/C/D/E)
    const actorBadge = article.threat_actors ? article.threat_actors.split(',').map(a => {
      const name = a.trim();
      const cls = actorClass(name);
      const clsTag = cls ? `<span class="ta-class ta-class-${cls.toLowerCase()}">${cls}</span>` : '';
      return `<span class="badge badge-actor" title="${cls ? 'Class ' + cls : 'Threat actor'}">${clsTag}${escapeHtml(name)}</span>`;
    }).join('') : '';
    const cveLink = article.cve_id ? `<a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(encodeURIComponent(article.cve_id))}" target="_blank" rel="noopener" class="cve-link">${escapeHtml(article.cve_id)}</a>` : '';
    const pocBadge = article.has_poc ? '<span class="badge badge-poc">PoC Available</span>' : '';
    const watchBadge = Array.isArray(article.watch) && article.watch.length
      ? `<span class="badge badge-watch" title="On your watchlist: ${escapeHtml(article.watch.join(', '))}">Watchlist: ${escapeHtml(article.watch.slice(0, 2).join(', '))}${article.watch.length > 2 ? '…' : ''}</span>` : '';

    // MITRE ATT&CK technique/tactic IDs — key signal for detection engineering
    const mitreIds = article.mitre_ids ? article.mitre_ids.split(',').map(s => s.trim()).filter(Boolean) : [];
    const mitreBadges = mitreIds.map(id =>
      `<a href="${mitreLink(id)}" target="_blank" rel="noopener" class="badge badge-mitre" title="MITRE ATT&CK ${escapeHtml(id)}">${escapeHtml(id)}</a>`
    ).join('');
    const ttpBadge = mitreIds.length ? '<span class="badge badge-ttp">TTP</span>' : '';

    // Threat-intel panel: who (threat actor) → how (each MITRE technique ID tied
    // to its tactic and to the sentence in the report that shows it = the TTP).
    // "cited" = the report names the ID; "inferred" = it describes the behaviour.
    const ttps = Array.isArray(article.ttps) ? article.ttps : null;
    const actorNames = [...new Set([
      ...(article.threat_actors ? article.threat_actors.split(',').map(a => a.trim()).filter(Boolean) : []),
      ...(Array.isArray(article.aiActors) ? article.aiActors : []),
    ])];
    const actorChips = actorNames.map(name => {
      const cls = actorClass(name);
      const clsTag = cls ? `<span class="ta-class ta-class-${cls.toLowerCase()}">${cls}</span>` : '';
      return `<button type="button" class="ti-actor" data-filter-actor="${escapeHtml(name)}" title="${cls ? 'Class ' + cls + ' threat actor' : 'Threat actor'}: open the ${escapeHtml(name)} profile">${clsTag}${escapeHtml(name)}</button>`;
    }).join('');
    // Don't repeat text the card already shows: skip a quote that is just the
    // title, and show each distinct sentence only once across the steps.
    const normTxt = (x) => String(x || '').toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim();
    const titleNorm = normTxt(article.title);
    const shownDescNorm = normTxt(String(article.description || '').substring(0, 300));   // what the card prints
    const quoted = new Set();
    const quoteFor = (p) => {
      const n = normTxt(p);
      if (!n || n === titleNorm || titleNorm.includes(n) || shownDescNorm.includes(n) || quoted.has(n)) return '';
      quoted.add(n);
      return p;
    };
    const ttpItem = (t) => {
      const shown = t.subId || t.id;
      const proc = quoteFor(t.procedure);
      const cited = t.how === 'cited';
      const how = cited ? 'cited' : t.how === 'ai' ? 'AI' : 'inferred';
      const howTip = cited ? 'Technique ID cited in the report' : t.how === 'ai' ? 'Mapped by AI from the quoted sentence — verify' : 'Inferred from the behaviour the report describes';
      return `<li class="ti-step ${cited ? 'ti-cited' : t.how === 'ai' ? 'ti-ai' : 'ti-inferred'}">` +
        `<span class="ti-tactic">${escapeHtml(t.tacticName || 'Unmapped')}</span>` +
        `<a class="ti-id" href="${escapeHtml(mitreLink(shown))}" target="_blank" rel="noopener" title="Open ${escapeHtml(shown)} on attack.mitre.org">${escapeHtml(shown)}</a>` +
        `<span class="ti-tech">${escapeHtml(t.name)}</span>` +
        `<span class="ti-how" title="${howTip}">${how}</span>` +
        (proc ? `<q class="ti-proc">${escapeHtml(proc)}</q>` : '') +
        `</li>`;
    };
    const tacticCount = ttps ? new Set(ttps.map(t => t.tactic).filter(Boolean)).size : 0;
    const ttpHtml = ttps && (ttps.length || actorNames.length) ? `<div class="ti-panel" aria-label="Threat actor and MITRE ATT&CK TTPs">` +
      `<div class="ti-head"><span class="ti-title">MITRE ATT&amp;CK</span>` +
      (ttps.length ? `<span class="ti-count">${ttps.length} TTP${ttps.length === 1 ? '' : 's'} · ${tacticCount}/14 tactics</span>` : '') +
      (ttps.length ? `<span class="ti-head-actions"><button type="button" class="ti-3d-btn" data-attack-path="${article.id}" title="See this attack step by step in 3D">3D attack path</button></span>` : '') +
      `</div>` +
      (actorNames.length ? `<div class="ti-actor-row"><span class="ti-label">Threat actor</span>${actorChips}</div>` : '') +
      (ttps.length ? `<ol class="ti-steps">${ttps.slice(0, 3).map(ttpItem).join('')}</ol>` +
        (ttps.length > 3 ? `<details class="ti-more"><summary>+${ttps.length - 3} more TTP${ttps.length - 3 === 1 ? '' : 's'}</summary><ol class="ti-steps" start="4">${ttps.slice(3).map(ttpItem).join('')}</ol></details>` : '')
        : '') +
      `</div>` : '';

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
    const iocList = parseIocs(article.iocs);
    if (iocList.length) {
      const shownIocs = iocList.slice(0, 6).map(i => `<span class="ioc-tag ioc-${escapeHtml(i.type)}" title="${escapeHtml(i.label)}: ${escapeHtml(i.value)}">${escapeHtml(i.value.length > 30 ? i.value.substring(0, 28) + '..' : i.value)}</span>`).join('');
      iocHtml = `<div class="article-iocs">${shownIocs}${iocList.length > 6 ? `<span class="ioc-more">+${iocList.length - 6}</span>` : ''}` +
        `<span class="ioc-export" role="group" aria-label="Export IOCs">` +
        `<button type="button" data-ioc-export="copy" data-ioc-article="${article.id}" title="Copy all ${iocList.length} IOCs (one per line)">Copy</button>` +
        `<button type="button" data-ioc-export="csv" data-ioc-article="${article.id}" title="Download IOCs as CSV">CSV</button>` +
        `<button type="button" data-ioc-export="stix" data-ioc-article="${article.id}" title="Download a STIX 2.1 bundle (for MISP, OpenCTI, SIEMs)">STIX</button>` +
        `</span></div>`;
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
        reviewHtml += `<span class="review-tag review-${escapeHtml(r.status)}">${label}</span>`;
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
      <article class="article-card ${article.severity === 'critical' ? 'critical' : ''} ${(ttps && ttps.length) || mitreIds.length ? 'has-ttp' : ''}${watchBadge ? ' on-watchlist' : ''}${cardExtraCls}" data-article-id="${article.id}">
        <div class="article-header">
          <div class="article-badges">${watchBadge}${catBadge}${sevBadge}${ownerBadge}${ttps ? '' : ttpBadge}${pocBadge}${patchBadge}${sectorBadge}${ttpHtml ? '' : actorBadge}${ttps ? '' : mitreBadges}${cveLink}</div>
        </div>
        <h3 class="article-title"><a href="${escapeHtml(safeUrl(article.url))}" target="_blank" rel="noopener">${escapeHtml(article.title)}</a></h3>
        <div class="article-meta">
          <span>${escapeHtml(article.source_name)}</span>
          ${article.author ? `<span>by ${escapeHtml(article.author)}</span>` : ''}
          <span>${relativeTime(article.published_date)}</span>
        </div>
        ${vulnRowHtml(article)}
        ${Array.isArray(article.related) && article.related.length ? `<details class="also-reported"><summary>Also reported by ${article.related.length} more source${article.related.length === 1 ? '' : 's'}</summary><ul>${
          article.related.map(r => `<li><a href="${escapeHtml(safeUrl(r.url))}" target="_blank" rel="noopener">${escapeHtml(r.source_name || 'Source')}</a><span>${escapeHtml(r.title)}</span></li>`).join('')
        }</ul></details>` : ''}
        ${desc ? `<p class="article-desc">${desc}</p>` : ''}
        ${article.tags ? `<div class="article-tags">${String(article.tags).split(',').map(t => t.trim()).filter(Boolean).map(t => `<span class="tag">${escapeHtml(t)}</span>`).join('')}</div>` : ''}
        ${ttpHtml}
        ${iocHtml}
        ${reviewHtml}
        <div class="article-actions">
          <button class="${reviewBtnCls} guest-hidden" data-review-article="${article.id}" title="Start reviewing"${reviewBtnDisabled}>${reviewBtnTxt}</button>
          <button class="btn-review-done guest-hidden" data-review-done="${article.id}" title="Mark as reviewed"${doneBtnDisabled}>Done</button>
          <button class="${escalateBtnCls} guest-hidden" data-escalate="${article.id}" title="Escalate"${escalateBtnDisabled}>${escalateBtnTxt}</button>
          ${aiAnalyzeButton(article)}
        </div>
        ${aiAnalysisHtml(article)}
      </article>`;
  }

  // Patch priority for the article's CVEs: CISA KEV + EPSS + CVSS -> one plain label
  const VULN_PRI = { now: 'Patch now', soon: 'Patch soon', plan: 'Plan', monitor: 'Monitor' };
  function vulnRowHtml(a) {
    if (!Array.isArray(a.vuln) || !a.vuln.length) return '';
    return `<div class="vuln-rows">${a.vuln.slice(0, 2).map((v) => {
      const bits = [];
      if (v.kev) bits.push(`<span class="vuln-kev" title="Listed in CISA's Known Exploited Vulnerabilities catalog${v.kev.added ? ' since ' + escapeHtml(v.kev.added) : ''}${v.kev.ransomware ? '; used in ransomware campaigns' : ''}">KEV${v.kev.ransomware ? ' · ransomware' : ''}</span>`);
      if (v.epss !== null && v.epss !== undefined) bits.push(`<span title="EPSS: chance of exploitation in the next 30 days (FIRST.org)${v.percentile !== null ? `; higher than ${Math.round(v.percentile * 100)}% of all CVEs` : ''}">EPSS ${(v.epss * 100).toFixed(v.epss < 0.1 ? 1 : 0)}%</span>`);
      if (v.cvss !== null && v.cvss !== undefined) bits.push(`<span title="CVSS base score (NVD)">CVSS ${Number(v.cvss).toFixed(1)}</span>`);
      const pri = VULN_PRI[v.priority] ? v.priority : 'monitor';
      return `<div class="vuln-row"><span class="vuln-pri vuln-pri-${pri}">${VULN_PRI[pri]}</span><code>${escapeHtml(v.cve)}</code>${bits.join('<i aria-hidden="true">·</i>')}</div>`;
    }).join('')}</div>`;
  }

  // ── Watchlist ──
  let watchTerms = [];
  function renderWatchlist() {
    const box = $('#watchlist-chips');
    if (!box) return;
    box.innerHTML = watchTerms.length
      ? watchTerms.map(w => `<span class="watch-chip">${escapeHtml(w.term)}<button type="button" data-watch-remove="${w.id}" aria-label="Remove ${escapeHtml(w.term)} from the watchlist">×</button></span>`).join('')
      : '<span class="watch-empty">Nothing yet. Add the products and vendors you run.</span>';
  }
  async function loadWatchlist() {
    if (!currentUser || currentUser.username === 'guest') { watchTerms = []; renderWatchlist(); return; }
    try { const r = await api('GET', '/api/watchlist'); watchTerms = r.terms || []; } catch { watchTerms = []; }
    renderWatchlist();
  }
  async function addWatchTerm(term) {
    const r = await api('POST', '/api/watchlist', { term });
    if (!r.success) throw new Error(r.error || 'Could not add');
    watchTerms = r.terms || watchTerms;
    renderWatchlist();
    fetchArticles();
  }
  async function removeWatchTerm(id) {
    const r = await api('DELETE', `/api/watchlist/${id}`);
    if (r.success) { watchTerms = r.terms || watchTerms.filter(w => w.id !== id); renderWatchlist(); fetchArticles(); }
  }

  // ── IOCs (stored as "ip:a,b|domain:c|hash:d|email:e") ──
  function parseIocs(raw) {
    const out = [];
    const seen = new Set();
    for (const part of String(raw || '').split('|')) {
      const i = part.indexOf(':');
      if (i < 0) continue;
      const kind = part.slice(0, i);
      for (const v of part.slice(i + 1).split(',').map(x => x.trim()).filter(Boolean)) {
        let type = kind, label = kind;
        if (kind === 'ip') { type = v.includes(':') ? 'ipv6' : 'ipv4'; label = 'IP'; }
        else if (kind === 'domain') label = 'Domain';
        else if (kind === 'email') label = 'Email';
        else if (kind === 'hash') { type = v.length === 32 ? 'md5' : v.length === 40 ? 'sha1' : 'sha256'; label = type.toUpperCase(); }
        const k = type + ':' + v.toLowerCase();
        if (seen.has(k)) continue;
        seen.add(k);
        out.push({ type, label, value: v });
      }
    }
    return out;
  }
  function downloadBlob(name, text, mime) {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: mime }));
    a.download = name;
    document.body.appendChild(a); a.click(); a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 2000);
  }
  function stixBundle(article, iocs) {
    const now = new Date().toISOString();
    const uuid = () => (crypto.randomUUID ? crypto.randomUUID() : 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, c => { const r = Math.random() * 16 | 0; return (c === 'x' ? r : (r & 0x3) | 0x8).toString(16); }));
    const q = (v) => String(v).replace(/\\/g, '\\\\').replace(/'/g, "\\'");
    const pattern = (i) => ({
      ipv4: `[ipv4-addr:value = '${q(i.value)}']`, ipv6: `[ipv6-addr:value = '${q(i.value)}']`,
      domain: `[domain-name:value = '${q(i.value)}']`, email: `[email-addr:value = '${q(i.value)}']`,
      md5: `[file:hashes.MD5 = '${q(i.value)}']`, sha1: `[file:hashes.'SHA-1' = '${q(i.value)}']`, sha256: `[file:hashes.'SHA-256' = '${q(i.value)}']`,
    }[i.type]);
    const ref = /^https?:\/\//i.test(article.url || '') ? [{ source_name: article.source_name || 'source', url: article.url }] : [];
    const indicators = iocs.filter(pattern).map(i => ({
      type: 'indicator', spec_version: '2.1', id: `indicator--${uuid()}`, created: now, modified: now,
      name: `${i.label} ${i.value}`, pattern: pattern(i), pattern_type: 'stix', valid_from: now,
      indicator_types: ['malicious-activity'],
      description: `Extracted automatically by ThreatPulse from: ${article.title}. Review before blocking.`,
      external_references: ref,
    }));
    const report = {
      type: 'report', spec_version: '2.1', id: `report--${uuid()}`, created: now, modified: now,
      name: article.title, published: article.published_date ? new Date(article.published_date).toISOString() : now,
      report_types: ['threat-report'], object_refs: indicators.map(x => x.id), external_references: ref,
    };
    return JSON.stringify({ type: 'bundle', id: `bundle--${uuid()}`, objects: [report, ...indicators] }, null, 2);
  }
  async function exportIocs(article, how) {
    const iocs = parseIocs(article.iocs);
    if (!iocs.length) return;
    const base = `iocs-${article.id}`;
    if (how === 'copy') {
      try { await navigator.clipboard.writeText(iocs.map(i => i.value).join('\n')); showToast('IOCs copied', `${iocs.length} indicator${iocs.length === 1 ? '' : 's'} copied. Review before blocking.`, 'success'); }
      catch { showToast('Copy failed', 'Your browser blocked clipboard access. Use CSV instead.', 'error'); }
    } else if (how === 'csv') {
      const cell = (v) => { const t = String(v ?? ''); const safe = /^[=+\-@]/.test(t) ? `'${t}` : t; return `"${safe.replace(/"/g, '""')}"`; };
      const rows = [['type', 'value', 'article_title', 'article_url', 'published'], ...iocs.map(i => [i.type, i.value, article.title, article.url, article.published_date])];
      downloadBlob(`${base}.csv`, rows.map(r => r.map(cell).join(',')).join('\r\n'), 'text/csv');
    } else if (how === 'stix') {
      downloadBlob(`${base}.stix.json`, stixBundle(article, iocs), 'application/json');
    }
  }

  // Labels shared by feed cards and the admin PoC tracker
  function categoryBadge(a) { return `<span class="badge badge-${escapeHtml(a.category)}">${escapeHtml(a.category)}</span>`; }
  function severityBadge(a) { return `<span class="badge badge-severity-${escapeHtml(a.severity)}">${escapeHtml(a.severity)}</span>`; }
  function patchLabel(a) {
    return a.is_patched === 1 ? '<span class="badge badge-patched">Patched</span>'
      : a.is_patched === 0 ? '<span class="badge badge-unpatched">Unpatched</span>' : '';
  }

  // ── Admin: PoC tracker (sidebar) ──
  // Articles that have (or claim) a proof of concept, with the PoC link(s) the
  // checker found and whether each is real: verified / suspicious / unverified.
  const pocState = { items: [], days: 30, filter: 'all', review: 'todo', kind: 'all', loading: false, error: '', token: false, jira: null, busy: new Set(), deciding: new Set(), seq: 0 };
  const POC_VERDICT = {
    verified: ['Verified PoC', 'Real exploit code found'],
    suspicious: ['Suspicious PoC', 'Looks like a fake PoC / malware lure: do not run'],
    mentioned: ['PoC mentioned', 'The article says a PoC exists; no working exploit link confirmed yet'],
    unverified: ['Unverified', 'Links found but code could not be confirmed'],
    none: ['No PoC found', 'No PoC wording and no exploit link found'],
    unchecked: ['Not checked', 'Run the PoC check'],
  };
  const pocVerdictOf = (it) => (it.poc && it.poc.verdict) || 'unchecked';
  const pocReviewOf = (it) => (it.decision && it.decision.status) || 'todo';
  function isAdminUser() { return !!(currentUser && currentUser.role === 'admin'); }

  async function loadPocTracker() {
    const card = $('#poc-tracker-card');
    if (!card) return;
    if (!isAdminUser()) { card.classList.add('hidden'); pocState.items = []; return; }
    card.classList.remove('hidden');
    const seq = ++pocState.seq;
    pocState.loading = true; pocState.error = '';
    renderPocTracker();
    try {
      const r = await api('GET', `/api/admin/poc-tracker?days=${pocState.days}`);
      if (seq !== pocState.seq) return;
      pocState.items = Array.isArray(r.items) ? r.items : [];
      pocState.token = !!r.githubToken;
      pocState.jira = r.jira || null;
    } catch (err) {
      if (seq !== pocState.seq) return;
      pocState.error = err.message || 'Could not load the PoC tracker';
    } finally {
      if (seq === pocState.seq) { pocState.loading = false; renderPocTracker(); }
    }
  }

  function pocLinkHtml(l) {
    const kind = { github: 'GitHub', gist: 'Gist', exploitdb: 'Exploit-DB', packetstorm: 'Packet Storm', gitlab: 'GitLab', reference: 'Reference' }[l.kind] || 'Link';
    let label = l.url;
    try { const u = new URL(l.url); label = (u.hostname.replace(/^www\./, '') + u.pathname).replace(/\/$/, ''); label = label.replace(/^github\.com\//, ''); } catch { /* keep */ }
    const meta = [kind];
    if (l.stars !== null && l.stars !== undefined) meta.push(`★ ${l.stars}`);
    if (l.source === 'cve-search') meta.push(`found by ${escapeHtml(l.via || 'CVE')} search`);
    else if (l.source === 'nvd-reference') meta.push('NVD exploit reference');
    else meta.push('linked in article');
    return `<li class="poc-link poc-${escapeHtml(l.status)}">` +
      `<span class="poc-dot" aria-hidden="true"></span>` +
      `<div class="poc-link-body"><a href="${escapeHtml(safeUrl(l.url))}" target="_blank" rel="noopener nofollow">${escapeHtml(label.slice(0, 80))}</a>` +
      `<span class="poc-link-meta">${meta.join(' · ')}</span>` +
      (l.reasons && l.reasons.length ? `<span class="poc-link-why">${escapeHtml(l.reasons[0])}${l.reasons.length > 1 ? ` · ${escapeHtml(l.reasons[1])}` : ''}</span>` : '') +
      `</div></li>`;
  }

  function pocItemHtml(it) {
    const v = pocVerdictOf(it);
    const [vLabel, vTip] = POC_VERDICT[v] || POC_VERDICT.unchecked;
    const cves = (it.poc && it.poc.cves && it.poc.cves.length) ? it.poc.cves : (it.cve_id ? [it.cve_id] : []);
    const ttps = Array.isArray(it.ttps) ? it.ttps : [];
    // Summary: AI summary if one exists, else the start of the description (never the title again)
    const sumRaw = it.aiSummary || String(it.description || '').replace(/\s+/g, ' ').trim();
    const sum = sumRaw && sumRaw.toLowerCase() !== String(it.title || '').toLowerCase() ? sumRaw.slice(0, 260) + (sumRaw.length > 260 ? '…' : '') : '';
    const busy = pocState.busy.has(it.id);
    const links = it.poc && Array.isArray(it.poc.links) ? it.poc.links
      : (it.pocRefs || []).map((u) => ({ url: u, kind: /github\.com/i.test(u) ? 'github' : /exploit-db/i.test(u) ? 'exploitdb' : 'reference', source: 'nvd-reference', status: 'unverified', reasons: ['Not checked yet'] }));
    const wording = (it.poc && Array.isArray(it.poc.wording) ? it.poc.wording : it.wording) || [];
    const deciding = pocState.deciding.has(it.id);
    const d = it.decision;
    const review = d && d.status === 'approved'
      ? `<div class="poc-decision poc-approved">Approved${d.jiraKey ? ` · in Jira backlog: <a href="${escapeHtml(safeUrl(d.jiraUrl || ''))}" target="_blank" rel="noopener">${escapeHtml(d.jiraKey)}</a>` : ''}</div>`
      : d && d.status === 'declined'
        ? `<div class="poc-decision poc-declined">Declined <button type="button" class="poc-undo" data-poc-decide="undo" data-id="${it.id}"${deciding ? ' disabled' : ''}>Undo</button></div>`
        : `<div class="poc-decide"><button type="button" class="poc-approve" data-poc-decide="approve" data-id="${it.id}"${deciding ? ' disabled' : ''} title="Create a Jira backlog item: ideation, references, hypothesis, summary, outcome">${deciding ? 'Sending to Jira…' : 'Approve → Jira'}</button>` +
          `<button type="button" class="poc-decline" data-poc-decide="decline" data-id="${it.id}"${deciding ? ' disabled' : ''}>Decline</button></div>`;
    return `<li class="poc-item poc-v-${v}" data-poc-id="${it.id}">` +
      `<div class="poc-labels">${categoryBadge(it)}${severityBadge(it)}${patchLabel(it)}` +
      `<span class="poc-verdict poc-verdict-${v}" title="${escapeHtml(vTip)}">${escapeHtml(vLabel)}</span></div>` +
      `<a class="poc-title" href="${escapeHtml(safeUrl(it.url))}" target="_blank" rel="noopener">${escapeHtml(it.title)}</a>` +
      `<div class="poc-meta">${escapeHtml(it.source_name || '')}${it.published_date ? ` · ${relativeTime(it.published_date)}` : ''}` +
      (cves.length ? ` · ${cves.map(c => `<a href="https://nvd.nist.gov/vuln/detail/${escapeHtml(encodeURIComponent(c))}" target="_blank" rel="noopener" class="cve-link">${escapeHtml(c)}</a>`).join(' ')}` : '') + `</div>` +
      vulnRowHtml(it) +
      `<div class="poc-sub">Links</div><ul class="poc-links">` +
        `<li class="poc-link poc-article"><span class="poc-dot" aria-hidden="true"></span><div class="poc-link-body"><a href="${escapeHtml(safeUrl(it.url))}" target="_blank" rel="noopener">Article / blog</a><span class="poc-link-meta">${escapeHtml(it.source_name || '')}</span></div></li>` +
        links.map(pocLinkHtml).join('') +
        (!it.poc ? `<li class="poc-hint">PoC link not checked yet</li>` : (!links.length ? `<li class="poc-hint">No exploit link found${it.poc.cves && it.poc.cves.length ? '' : ' (no CVE ID to search)'}</li>` : '')) +
      `</ul>` +
      (wording.length ? `<div class="poc-sub">The article says</div>` + wording.slice(0, 2).map((q) => `<blockquote class="poc-quote">${escapeHtml(q)}</blockquote>`).join('') : '') +
      (sum ? `<div class="poc-sub">${it.aiSummary ? 'AI summary' : 'Summary'}</div><p class="poc-sum">${escapeHtml(sum)}</p>` : '') +
      (ttps.length ? `<div class="poc-sub">Attack technique${ttps.length > 1 ? 's' : ''}</div><div class="poc-ttps">` +
        ttps.slice(0, 4).map(t => `<a class="poc-ttp" href="${escapeHtml(mitreLink(t.subId || t.id))}" target="_blank" rel="noopener" title="${escapeHtml(t.tacticName || '')}"><code>${escapeHtml(t.subId || t.id)}</code>${escapeHtml(t.name)}</a>`).join('') +
        (ttps.length > 4 ? `<span class="poc-more">+${ttps.length - 4}</span>` : '') +
        `<button type="button" class="ti-3d-btn" data-attack-path="${it.id}">3D attack path</button></div>` : '') +
      (it.poc && it.poc.notes && it.poc.notes.length ? `<p class="poc-note">${escapeHtml(it.poc.notes[it.poc.notes.length - 1])}</p>` : '') +
      `<div class="poc-actions"><button type="button" class="poc-check-btn" data-poc-check="${it.id}"${busy ? ' disabled' : ''}>` +
        `${busy ? 'Checking…' : it.poc ? 'Re-check PoC' : 'Check PoC'}</button>` +
        (it.poc && it.poc.checkedAt ? `<span class="poc-checked">checked ${relativeTime(it.poc.checkedAt)}</span>` : '') + `</div>` +
      review +
      `</li>`;
  }

  function renderPocTracker() {
    const list = $('#poc-tracker-list');
    if (!list) return;
    const byKind = pocState.items.filter((it) => pocState.kind === 'all' || (it.kind || 'article') === pocState.kind);
    const rCounts = { todo: 0, approved: 0, declined: 0 };
    for (const it of byKind) rCounts[pocReviewOf(it)]++;
    const inReview = byKind.filter((it) => pocReviewOf(it) === pocState.review);
    const counts = { all: inReview.length, verified: 0, mentioned: 0, suspicious: 0, unchecked: 0 };
    for (const it of inReview) { const v = pocVerdictOf(it); if (counts[v] !== undefined) counts[v]++; }
    $$('#poc-tracker-card [data-poc-filter]').forEach((b) => {
      const f = b.dataset.pocFilter;
      b.setAttribute('aria-pressed', String(f === pocState.filter));
      const n = b.querySelector('.poc-n'); if (n) n.textContent = counts[f] ?? '';
    });
    $$('#poc-tracker-card [data-poc-review]').forEach((b) => {
      const f = b.dataset.pocReview;
      b.setAttribute('aria-pressed', String(f === pocState.review));
      const n = b.querySelector('.poc-n'); if (n) n.textContent = rCounts[f] ?? '';
    });
    const countEl = $('#poc-tracker-count'); if (countEl) countEl.textContent = rCounts.todo ? String(rCounts.todo) : '';
    const tokenNote = $('#poc-token-note'); if (tokenNote) tokenNote.classList.toggle('hidden', pocState.token || !pocState.items.length);
    const jiraNote = $('#poc-jira-note'); if (jiraNote) jiraNote.classList.toggle('hidden', !pocState.jira || !!pocState.jira.configured);
    if (pocState.loading && !pocState.items.length) { list.innerHTML = '<li class="poc-empty">Loading…</li>'; return; }
    if (pocState.error) { list.innerHTML = `<li class="poc-empty poc-err">${escapeHtml(pocState.error)}</li>`; return; }
    const shown = inReview.filter((it) => pocState.filter === 'all' || pocVerdictOf(it) === pocState.filter);
    list.innerHTML = shown.length ? shown.map(pocItemHtml).join('')
      : `<li class="poc-empty">${pocState.items.length ? 'Nothing in this filter.' : `No PoC articles in the last ${pocState.days} days.`}</li>`;
  }

  async function decidePoc(id, action) {
    if (pocState.deciding.has(id)) return;
    pocState.deciding.add(id);
    renderPocTracker();
    try {
      const r = await api('POST', '/api/admin/poc-decision', { articleId: id, action });
      if (!r.success) throw new Error(r.error || 'Could not save the decision');
      const it = pocState.items.find((x) => x.id === id);
      if (it) it.decision = r.decision;
      if (action === 'approve' && r.decision && r.decision.jiraKey) {
        showToast('Sent to Jira', `${r.decision.jiraKey} ${r.existing ? 'already exists' : 'is in the backlog'}${r.aiHypothesis === false && !r.existing ? ' (template hypothesis: AI unavailable)' : ''}`, 'success');
      }
    } catch (err) {
      showToast(action === 'approve' ? 'Jira' : 'PoC tracker', err.message || 'Something went wrong', 'error');
    } finally {
      pocState.deciding.delete(id);
      renderPocTracker();
    }
  }

  async function runPocCheck(id) {
    if (pocState.busy.has(id)) return;
    pocState.busy.add(id);
    renderPocTracker();
    try {
      const r = await api('POST', '/api/admin/poc-check', { articleId: id });
      if (!r.success) throw new Error(r.error || 'PoC check failed');
      const it = pocState.items.find((x) => x.id === id);
      if (it) { it.poc = r.poc; if (r.poc.verdict === 'verified') it.has_poc = 1; }
      const art = state.articles.find((x) => x.id === id);
      if (art && r.poc.verdict === 'verified') art.has_poc = 1;
    } catch (err) {
      showToast('PoC check', err.message || 'PoC check failed', 'error');
    } finally {
      pocState.busy.delete(id);
      renderPocTracker();
    }
  }

  // ── AI analysis on a card: one button, one panel ──
  // State lives in aiAnalysis (survives the 60 s auto-refresh re-render).
  // Techniques it finds are merged into the card's ATT&CK box, not listed twice.
  function aiAnalyzeButton(article) {
    const st = aiAnalysis.get(article.id);
    const label = !st ? 'AI analysis' : st.loading ? 'Analysing…' : st.open ? 'Hide AI analysis' : 'AI analysis';
    return `<button type="button" class="btn-ai-analyze${st && st.open ? ' open' : ''}" data-ai-analyze="${article.id}"` +
      ` aria-expanded="${st && st.open ? 'true' : 'false'}" aria-controls="ai-an-${article.id}"${st && st.loading ? ' disabled' : ''}` +
      ` title="Summary, why it matters, priority and MITRE ATT&CK mapping">${label}</button>`;
  }
  function aiAnalysisHtml(article) {
    const st = aiAnalysis.get(article.id);
    if (!st || !st.open) return '';
    const id = `ai-an-${article.id}`;
    if (st.loading) {
      return `<div class="ai-an" id="${id}" aria-busy="true"><div class="ai-an-head"><span class="ai-an-title">AI analysis</span></div>` +
        ['Summarising the report', 'Scoring priority for a defender', 'Mapping behaviour to MITRE ATT&CK']
          .map(t => `<div class="ai-an-loading"><span class="ai-an-spin" aria-hidden="true"></span>${t}…</div>`).join('') + `</div>`;
    }
    if (st.error) {
      return `<div class="ai-an" id="${id}"><div class="ai-an-head"><span class="ai-an-title">AI analysis</span></div>` +
        `<p class="ai-an-error">${escapeHtml(st.error)}</p><button type="button" class="ai-an-retry" data-ai-analyze-retry="${article.id}">Try again</button></div>`;
    }
    const d = st.data || {};
    const tri = d.triage || null;
    const PRI = ['immediate', 'high', 'routine', 'informational'];
    const pri = tri && PRI.includes(tri.priority) ? tri.priority : null;
    const rel = tri && Number.isFinite(tri.relevance) ? tri.relevance : null;
    const sum = d.summary || null;
    const added = Array.isArray(d.addedTtps) ? d.addedTtps : [];
    const attackLine = !d.aiMapped ? (d.errors && d.errors.ttps ? `ATT&CK mapping failed: ${escapeHtml(d.errors.ttps)}` : '')
      : added.length ? `Added ${added.length} technique${added.length === 1 ? '' : 's'} to the ATT&amp;CK box above: ${added.map(x => `<code>${escapeHtml(x)}</code>`).join(' ')}`
      : (article.ttps && article.ttps.length ? 'No techniques beyond those already in the ATT&amp;CK box.' : 'The report doesn’t describe attacker techniques to map.');
    return `<div class="ai-an" id="${id}">` +
      `<div class="ai-an-head"><span class="ai-an-title">AI analysis</span>` +
      (pri ? `<span class="ai-an-pri ai-an-pri-${pri}" title="Priority for a defender">${pri}</span>` : '') +
      (rel !== null ? `<span class="ai-an-rel" title="Operational relevance"><span class="ai-an-bar"><i style="width:${rel}%"></i></span>${rel}/100</span>` : '') +
      `</div>` +
      (sum && sum.summary ? `<p class="ai-an-sum">${escapeHtml(sum.summary)}</p>` : (d.errors && d.errors.summary ? `<p class="ai-an-error">Summary unavailable: ${escapeHtml(d.errors.summary)}</p>` : '')) +
      (sum && sum.keyTakeaway ? `<p class="ai-an-why"><span>Why it matters</span>${escapeHtml(sum.keyTakeaway)}</p>` : '') +
      (tri && tri.reason ? `<p class="ai-an-why"><span>Priority reason</span>${escapeHtml(tri.reason)}</p>` : '') +
      (sum && sum.affectedTech && sum.affectedTech.length ? `<div class="ai-an-tech"><span>Affected</span>${sum.affectedTech.slice(0, 8).map(t => `<span class="ai-an-chip">${escapeHtml(t)}</span>`).join('')}</div>` : '') +
      (attackLine ? `<p class="ai-an-attack">${attackLine}</p>` : '') +
      `<p class="ai-an-note">Generated by AI from this report only. Verify before acting.</p>` +
      `</div>`;
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
    updateDashBulkBar(); // re-render drops the checked boxes; hide a stale bulk bar
  }

  function renderSourceItem(source) {
    const st = sourceStatus(source);
    const lastFetched = source.last_fetched ? relativeTime(source.last_fetched) : 'Never';

    return `
      <div class="source-item" data-source-id="${source.id}">
        <input type="checkbox" class="dash-source-cb guest-hidden" data-src-id="${source.id}" data-src-url="${escapeHtml(source.url)}" data-src-name="${escapeHtml(source.name)}" aria-label="Select ${escapeHtml(source.name)}" style="margin-right:6px;cursor:pointer;">
        <span class="source-status-dot ${st.cls}" title="${st.label}"></span>
        <div class="source-info">
          <div class="source-info-name" title="${escapeHtml(source.name)}"><a href="${escapeHtml(safeUrl(source.url))}" target="_blank" rel="noopener">${escapeHtml(source.name)}</a></div>
          <div class="source-info-meta">Fetched: ${lastFetched} <span style="color:${st.color};font-size:10px;" title="${source.last_error ? escapeHtml(source.last_error) : st.label}">${st.label}</span></div>
        </div>
        <div class="source-actions guest-hidden">
          <label class="toggle-switch source-toggle" aria-label="Enable ${escapeHtml(source.name)}">
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
      const r = await api('POST', d('L2FwaS9zb3VyY2Vz'), formData);
      showToast('Source Added', r && r.fetching
        ? `${formData.name} has been added and is being fetched now.`
        : `${formData.name} has been added. It will be fetched on the next scheduled run.`, 'success');
      fetchSources();
      $('#add-source-form').reset();
      if (r && r.fetching) {
        // The server fetches the new source in the background: pick up the result
        setTimeout(() => { Promise.allSettled([fetchSources(), fetchStats(), fetchArticles()]); }, 8000);
        setTimeout(() => { Promise.allSettled([fetchSources(), fetchStats(), fetchArticles()]); }, 30000);
      }
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
      if ($('#notif-email-enabled').checked && !serverConfig.emailEnabled) {
        showToast('Saved — email alerts unavailable', 'Email delivery is not set up on this server yet, so email alerts cannot be sent. Use Telegram, Teams or WhatsApp for now.', 'warning');
      } else {
        showToast('Saved', 'Notification settings updated.', 'success');
      }
      return true;
    } catch (e) { showToast('Error', e.message, 'error'); return false; }
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
    const done = () => { state.isFetching = false; $('#fetch-now-btn').disabled = false; };
    const reload = () => Promise.allSettled([fetchStats(), fetchArticles(), fetchSources()]);
    try {
      // Users' own sources are fetched while the request waits (up to ~25 s) and
      // the server reports what happened; admins start the full background run.
      // Don't claim "Feeds updated" for a fetch that is still running.
      const r = await api('POST', d('L2FwaS9mZXRjaC1ub3c=')) || {};
      if (r.completed) {
        await reload();
        showToast('Fetch complete', r.message || 'Feeds updated.', r.errors ? 'warning' : 'success');
        done();
      } else {
        showToast('Fetch running', r.message || 'New articles will appear as they arrive.', 'info');
        setTimeout(reload, 10000);
        setTimeout(() => { reload().then(done); }, 30000);
      }
    } catch (e) {
      showToast('Error', e.message, 'error');
      done();
    }
  }

  function clearFilters() {
    state.filters = { category: '', severity: '', source_type: '', search: '', sector: '', threat_actor: '', has_poc: '', has_mitre: '', watchlist: '', is_patched: '', time_range: '', start_date: '', end_date: '' };
    state.currentPage = 1;
    const si = $('#search-input'); if (si) si.value = '';
    ['#severity-filter', '#source-type-filter', '#sector-filter', '#threat-actor-filter', '#patch-filter', '#time-range-filter'].forEach(sel => {
      setSelectValue($(sel), '');
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

  // Query string for the current feed filters (shared by the feed and export)
  function filterParams(page, limit) {
    const params = new URLSearchParams({ page, limit });
    const f = state.filters;
    ['category', 'severity', 'source_type', 'search', 'sector', 'threat_actor', 'has_poc', 'has_mitre', 'watchlist',
      'time_range', 'start_date', 'end_date'].forEach(k => { if (f[k]) params.set(k, f[k]); });
    if (f.is_patched !== '') params.set('is_patched', f.is_patched);
    return params;
  }

  // Shape of one exported article: readable fields only (no internal hashes /
  // flags) and reviews as real objects instead of a JSON string.
  function exportRecord(a) {
    let reviews = [];
    try { reviews = a.reviews ? JSON.parse(a.reviews) : []; } catch (e) { reviews = []; }
    reviews = (Array.isArray(reviews) ? reviews : []).filter(r => r && r.user_id).map(r => ({
      reviewer: r.username, status: r.status, started_at: r.started_at, completed_at: r.completed_at, notes: r.notes
    }));
    const list = (v) => (v ? String(v).split(',').map(x => x.trim()).filter(Boolean) : []);
    return {
      id: a.id, title: a.title, url: a.url, description: a.description,
      source: a.source_name, source_type: a.source_type, author: a.author || null,
      published: a.published_date, fetched: a.fetched_date,
      category: a.category, severity: a.severity, cve: a.cve_id || null,
      patched: a.is_patched === 1 ? true : a.is_patched === 0 ? false : null,
      has_poc: !!a.has_poc, mitre: list(a.mitre_ids), sector: a.sector || null,
      threat_actors: list(a.threat_actors), tags: list(a.tags), iocs: a.iocs || null,
      owner: a.owner_name || null, reviews
    };
  }

  // Exports EVERY article matching the current filters (it used to dump only the
  // 50 loaded on screen while looking like a full export), within the viewer's
  // own scope since it goes through the same /api/articles endpoint.
  const EXPORT_MAX = 5000;
  async function exportArticles() {
    const btn = $('#export-btn');
    if (btn) btn.disabled = true;
    try {
      const all = [];
      let page = 1, totalPages = 1, total = 0;
      do {
        const data = await api('GET', `${d('L2FwaS9hcnRpY2xlcw==')}?${filterParams(page, 200)}`);
        const rows = Array.isArray(data.articles) ? data.articles : [];
        all.push(...rows);
        totalPages = data.totalPages || 0;
        total = data.total || all.length;
        page++;
      } while (page <= totalPages && all.length < EXPORT_MAX);
      const records = all.slice(0, EXPORT_MAX).map(exportRecord);
      const payload = {
        exported_at: new Date().toISOString(),
        filters: Object.fromEntries(Object.entries(state.filters).filter(([, v]) => v !== '')),
        total_matching: total,
        count: records.length,
        articles: records
      };
      const blob = new Blob([JSON.stringify(payload, null, 2)], { type: 'application/json' });
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url; a.download = `threatpulse-export-${localDayKey(new Date())}.json`;
      a.click(); URL.revokeObjectURL(url);
      showToast('Exported', total > records.length
        ? `Exported the newest ${records.length} of ${total} matching articles.`
        : `Exported ${records.length} article(s).`, 'success');
    } catch (e) {
      showToast('Export failed', e.message, 'error');
    } finally {
      if (btn) btn.disabled = false;
    }
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
      // Re-fetching page 1 would throw away pages the user loaded via "Load more"
      const tasks = [fetchStats()];
      if (state.currentPage <= 1) tasks.push(fetchArticles());
      await Promise.allSettled(tasks);
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
          // Don't leave the password in the (hidden) form — the eye toggle would
          // reveal it to whoever sees the login screen after logout.
          $('#login-form').reset();
          // Forced first-login change: reuse the password just typed at sign-in
          // (kept in memory only until the change completes) instead of asking
          // again — the browser tends to autofill a stale saved password there.
          forcedChangeSecret = result.user && result.user.mustChangePassword ? password : null;
          setUser(result.user);
          initDashboard();
        } else {
          errEl.textContent = (result.error || 'Invalid username/email or password') + (result.locked ? '' : dbResetHint());
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
      const inviteCode = $('#reg-invite').value.trim().toUpperCase();

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
      // Invite code: required unless the server runs open registration
      // (REQUIRE_INVITE_CODE=false, reported by /api/auth/config).
      if (serverConfig.requireInvite !== false && !inviteCode) {
        errEl.textContent = 'An invite code is required to register. Ask your admin for one.';
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
          $('#register-form').reset();
          $('#password-strength').className = 'password-strength hidden';
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
          okEl.textContent = (result.message || 'If that email exists, a reset link has been sent.') +
            (result.emailDelivery ? ' Check your inbox and spam folder — the link expires in 1 hour.' : '');
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

    // Sign In / Register (guests) — show auth overlay without killing the guest session
    $('#sign-in-btn').addEventListener('click', () => {
      $('#user-dropdown').classList.add('hidden');
      showAuth();
      // Show "Continue as Guest" back option only if we already have a guest session
      const isGuest = currentUser && currentUser.username === 'guest';
      $('#guest-back').style.display = isGuest ? '' : 'none';
    });

    // Continue as Guest — return to the dashboard from the auth overlay.
    // After a logout there is no session (and no timers) left, so start a new guest one.
    $('#guest-back-btn').addEventListener('click', () => {
      if (currentUser && currentUser.username === 'guest') hideAuth();
      else enterGuestSession();
    });

    // Change email
    $('#change-email-btn').addEventListener('click', () => {
      $('#email-error').classList.add('hidden');
      $('#account-email').value = (currentUser && currentUser.email) || '';
      $('#email-current-password').value = '';
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
        const result = await api('PUT', d('L2FwaS9hdXRoL2VtYWls'), {
          email: $('#account-email').value.trim(),
          currentPassword: $('#email-current-password').value
        });
        if (result.success && result.verificationRequired) {
          $('#email-modal').classList.add('hidden');
          $('#verification-code').value = '';
          $('#verification-error').classList.add('hidden');
          $('#verification-notice').textContent = `We sent a 6-digit verification code to your new email: ${result.email}. Please enter it below to confirm.`;
          state.pendingVerificationType = 'email_change';
          $('#verification-modal').classList.remove('hidden');
        } else if (result.success) {
          // Applied directly (this server cannot send verification email)
          if (currentUser) currentUser.email = result.email;
          $('#email-modal').classList.add('hidden');
          showToast('Email updated', result.message || 'Your email address has been updated.', 'success');
        } else {
          errEl.textContent = result.error || 'Failed to update email'; errEl.classList.remove('hidden');
        }
      } catch (err) {
        errEl.textContent = err.message; errEl.classList.remove('hidden');
      }
    });

    // Change password: confirmed by email. We email a one-time link; the link
    // opens the "choose a new password" page (same as forgot-password).
    $('#change-password-btn').addEventListener('click', () => {
      $('#password-error').classList.add('hidden');
      $('#password-success').classList.add('hidden');
      $('#password-link-email').textContent = (currentUser && currentUser.email) || 'your email address';
      const btn = $('#password-link-submit');
      btn.disabled = false; btn.textContent = 'Email me a link';
      $('#password-modal').classList.remove('hidden');
    });
    $('#cancel-password-btn').addEventListener('click', () => {
      $('#password-modal').classList.add('hidden');
    });
    $('#password-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = $('#password-error'), okEl = $('#password-success'), btn = $('#password-link-submit');
      errEl.classList.add('hidden'); okEl.classList.add('hidden');
      btn.disabled = true; btn.textContent = 'Sending…';
      try {
        const result = await api('POST', '/api/auth/password/request-link', {});
        if (result.success) {
          okEl.textContent = `Link sent to ${result.email}. Check your inbox (and spam folder) and open it within 60 minutes to set your new password.`;
          okEl.classList.remove('hidden');
          btn.textContent = 'Send again';
        } else {
          errEl.textContent = result.error || 'Could not send the link';
          errEl.classList.remove('hidden');
          btn.textContent = 'Email me a link';
        }
      } catch (err) {
        errEl.textContent = err.message;
        errEl.classList.remove('hidden');
        btn.textContent = 'Email me a link';
      } finally {
        btn.disabled = false;
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
            Promise.allSettled([fetchStats(), fetchArticles(), fetchSources(), fetchNotificationSettings()]);
            setForcedPasswordMode(false);
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
        // Picking a preset (or "All Time") drops an earlier custom/card date range;
        // otherwise the stale start/end dates kept filtering the feed and exports.
        if (sel === '#time-range-filter' && e.target.value !== 'custom') {
          state.filters.start_date = '';
          state.filters.end_date = '';
          document.querySelectorAll('.selected-range-tag').forEach(t => t.remove());
        }
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
            <span class="tz-label">${escapeHtml(tz)}</span>
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
          // Empty/invalid inputs made toISOString() throw a RangeError
          if (isNaN(new Date(startEl.value)) || isNaN(new Date(endEl.value))) {
            showToast('Invalid range', 'Pick both a start and an end date.', 'error');
            return;
          }
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
        state.filters.time_range = '';
        setSelectValue($('#time-range-filter'), '');
        const picker = $('#custom-date-picker');
        if (picker) picker.classList.remove('visible');
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

      // Threat actor chip → actor profile (which has "Show all reports in feed")
      const actorBtn = e.target.closest('[data-filter-actor]');
      if (actorBtn && window.ThreatPulseActor) { window.ThreatPulseActor.open(actorBtn.dataset.filterActor, actorBtn); return; }
      if (actorBtn) {
        const name = actorBtn.dataset.filterActor;
        const sel = $('#threat-actor-filter');
        const opt = sel && [...sel.options].find(o => o.value.toLowerCase() === name.toLowerCase());
        if (opt) { sel.value = opt.value; sel.dispatchEvent(new Event('change', { bubbles: true })); }
        else { const si = $('#search-input'); si.value = name; si.dispatchEvent(new Event('input', { bubbles: true })); }
        document.querySelector('.filter-bar')?.scrollIntoView({ behavior: 'smooth', block: 'start' });
        return;
      }

      // 3D attack path for one article
      const pathBtn = e.target.closest('[data-attack-path]');
      if (pathBtn) {
        const id = parseInt(pathBtn.dataset.attackPath, 10);
        const art = state.articles.find(a => a.id === id) || pocState.items.find(a => a.id === id);
        if (art && window.ThreatPulseAttackPath) window.ThreatPulseAttackPath.open(art, pathBtn);
        return;
      }

      // Watchlist chip remove
      const wRm = e.target.closest('[data-watch-remove]');
      if (wRm) { removeWatchTerm(parseInt(wRm.dataset.watchRemove, 10)); return; }

      // IOC export (copy / CSV / STIX 2.1)
      const iocBtn = e.target.closest('[data-ioc-export]');
      if (iocBtn) {
        const id = parseInt(iocBtn.dataset.iocArticle, 10);
        const art = state.articles.find(a => a.id === id);
        if (art) exportIocs(art, iocBtn.dataset.iocExport);
        return;
      }

      // Admin PoC tracker controls
      const pocBtn = e.target.closest('[data-poc-check]');
      if (pocBtn) { runPocCheck(parseInt(pocBtn.dataset.pocCheck, 10)); return; }
      const pocFilter = e.target.closest('[data-poc-filter]');
      if (pocFilter) { pocState.filter = pocFilter.dataset.pocFilter; renderPocTracker(); return; }
      const pocReview = e.target.closest('[data-poc-review]');
      if (pocReview) { pocState.review = pocReview.dataset.pocReview; renderPocTracker(); return; }
      const pocDecide = e.target.closest('[data-poc-decide]');
      if (pocDecide) { decidePoc(parseInt(pocDecide.dataset.id, 10), pocDecide.dataset.pocDecide); return; }
      const pocNext = e.target.closest('#poc-check-next');
      if (pocNext) {
        const todo = pocState.items.filter((it) => !it.poc && pocReviewOf(it) === 'todo' && (pocState.kind === 'all' || (it.kind || 'article') === pocState.kind)).slice(0, 5);
        if (!todo.length) { showToast('PoC check', 'Everything here has been checked.', 'info'); return; }
        pocNext.disabled = true;
        (async () => { for (const it of todo) await runPocCheck(it.id); pocNext.disabled = false; })();
        return;
      }

      // AI analysis (summary + why it matters + priority + ATT&CK) — one button per card
      const anBtn = e.target.closest('[data-ai-analyze], [data-ai-analyze-retry]');
      if (anBtn) {
        const id = parseInt(anBtn.dataset.aiAnalyze || anBtn.dataset.aiAnalyzeRetry, 10);
        const st = aiAnalysis.get(id);
        if (st && st.data && !anBtn.dataset.aiAnalyzeRetry) {       // already loaded: just show / hide
          st.open = !st.open;
          renderArticles();
          return;
        }
        if (st && st.loading) return;
        if (aiAnalysis.size > 200) aiAnalysis.delete(aiAnalysis.keys().next().value);
        aiAnalysis.set(id, { open: true, loading: true });
        renderArticles();
        api('POST', '/api/ai/analyze', { articleId: id }).then((r) => {
          if (!r.success) throw new Error(r.error || 'AI analysis failed');
          const art = state.articles.find(a => a.id === id);
          if (art) { art.ttps = r.ttps; art.aiMapped = r.aiMapped; art.aiActors = r.actors || []; }
          aiAnalysis.set(id, { open: true, loading: false, data: r });
        }).catch((err) => {
          aiAnalysis.set(id, { open: true, loading: false, error: err.message || 'AI analysis failed' });
        }).finally(() => renderArticles());
        return;
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

    // Watchlist add / remove
    $('#watchlist-form')?.addEventListener('submit', async (e) => {
      e.preventDefault();
      const inp = $('#watchlist-input');
      const term = inp.value.trim();
      if (!term) return;
      try { await addWatchTerm(term); inp.value = ''; }
      catch (err) { showToast('Watchlist', err.message, 'error'); }
    });

    // Admin PoC tracker: time range + periodic refresh (picks up background checks)
    $('#poc-days')?.addEventListener('change', (e) => { pocState.days = parseInt(e.target.value, 10) || 30; loadPocTracker(); });
    $('#poc-kind')?.addEventListener('change', (e) => { pocState.kind = ['article', 'cve'].includes(e.target.value) ? e.target.value : 'all'; renderPocTracker(); });
    setInterval(() => { if (isAdminUser() && !document.hidden && !pocState.busy.size) loadPocTracker(); }, 180000);

    // Stat cards clickable — filter feed on click
    $$('.stat-card').forEach(card => {
      card.addEventListener('click', () => {
        const stat = card.dataset.stat;
        clearFilters();
        // Each card filters the feed to the same window its number counts:
        // "today" is the viewer's local day (as is the count, see fetchStats),
        // critical / PoC counts cover the last 7 days.
        if (stat === 'threats') {
          const b = localDayBounds(new Date());
          state.filters.start_date = b.start;
          state.filters.end_date = b.end;
          state.filters.time_range = 'custom';
          setSelectValue($('#time-range-filter'), 'custom');
          showSelectedRangeTag(b.start, b.end);
        } else if (stat === 'critical') {
          state.filters.severity = 'critical';
          state.filters.time_range = '7d';
          setSelectValue($('#severity-filter'), 'critical');
          setSelectValue($('#time-range-filter'), '7d');
        } else if (stat === 'pocs') {
          state.filters.has_poc = '1';
          state.filters.time_range = '7d';
          $('#filter-poc').classList.add('active');
          setSelectValue($('#time-range-filter'), '7d');
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

    // Notifications panel: the whole card and each channel open like dropdowns
    $('#notif-panel-toggle')?.addEventListener('click', () => {
      const btn = $('#notif-panel-toggle');
      const open = btn.getAttribute('aria-expanded') !== 'true';
      btn.setAttribute('aria-expanded', String(open));
      $('#notification-form').classList.toggle('is-collapsed', !open);
      btn.closest('.notif-card')?.classList.toggle('open', open);
    });
    const setChannelOpen = (channel, open) => {
      channel.classList.toggle('open', open);
      channel.querySelector('.notif-channel-head')?.setAttribute('aria-expanded', String(open));
    };
    $$('.notif-channel-head').forEach(head => {
      const channel = head.closest('.notif-channel');
      head.addEventListener('click', (e) => {
        if (e.target.closest('.toggle-switch')) return; // the on/off switch has its own job
        setChannelOpen(channel, !channel.classList.contains('open'));
      });
      head.addEventListener('keydown', (e) => {
        if (e.target !== head || (e.key !== 'Enter' && e.key !== ' ')) return;
        e.preventDefault();
        setChannelOpen(channel, !channel.classList.contains('open'));
      });
      // Switching a channel on opens it so its fields can be filled in
      head.querySelector('.toggle-switch input')?.addEventListener('change', (e) => {
        if (e.target.checked) setChannelOpen(channel, true);
        updateNotifSummary();
      });
    });

    // Notification form
    $('#notification-form').addEventListener('submit', (e) => {
      e.preventDefault();
      saveNotificationSettings();
    });
    // Per-channel test buttons — save first so the test uses current values
    $$('.notif-test').forEach(btn => {
      btn.addEventListener('click', async () => {
        if (await saveNotificationSettings()) testNotification(btn.dataset.test);
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
        let ok = 0, lastErr = '';
        for (const cb of checked) {
          try { await api('DELETE', `${d('L2FwaS9zb3VyY2Vz')}/${cb.dataset.srcId}`); ok++; }
          catch (e) { lastErr = e.message; }
        }
        if (ok) showToast('Deleted', `${ok} source(s) removed.`, 'success');
        if (ok < checked.length) showToast('Error', `${checked.length - ok} source(s) could not be removed: ${lastErr}`, 'error');
        $('#dash-select-all').checked = false;
        fetchSources(); fetchStats();
      }
    });

    // Keyboard shortcut
    document.addEventListener('keydown', (e) => {
      if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        searchInput.focus();
      }
      // Date headers are role="button" — make them operable from the keyboard
      const dh = e.target.closest && e.target.closest('.date-header');
      if (dh && (e.key === 'Enter' || e.key === ' ')) {
        e.preventDefault();
        dh.click();
      }
    });

    // Chart is sized from its container at render time — re-render on resize
    window.addEventListener('resize', debounce(() => {
      if (_chartTimeline.length) renderChart(_chartTimeline, _chartRange);
    }, 200));

    // ─── Ask ThreatPulse (AI) panel ───
    let aiThreadId = null;

    $('#ai-fab').addEventListener('click', () => {
      $('#ai-panel').classList.toggle('hidden');
      if (!$('#ai-panel').classList.contains('hidden')) {
        $('#ai-question').focus();
        loadAiThreads();
      }
    });
    $('#ai-panel-close').addEventListener('click', () => {
      $('#ai-panel').classList.add('hidden');
    });

    // Minimal, safe markdown for AI answers: escape first, then only add <strong>
    // and bullet glyphs (the model often answers with **bold** and "* " lists).
    function formatAnswer(raw) {
      return escapeHtml(String(raw || '')).split('\n').map(line => {
        let l = line.replace(/^\s{0,3}#{1,6}\s+(.+)$/, '**$1**')
                    .replace(/^(\s*)[*\-]\s+/, (m, sp) => `${sp.replace(/ /g, '&nbsp;')}&bull; `);
        return l.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>').replace(/【(\d+)(?:†[^】]*)?】/g, '[$1]');
      }).join('<br>');
    }

    function renderSources(sources) {
      if (!sources || !sources.length) return '';
      const links = sources.map(s => {
        const url = /^https?:\/\//i.test(s.url || '') ? s.url : '';
        return url
          ? `&bull; <a href="${escapeHtml(url)}" target="_blank" rel="noopener noreferrer">${escapeHtml(s.title)}</a>`
          : `&bull; ${escapeHtml(s.title)}`;
      }).join('<br>');
      return `<br><br><strong>Sources:</strong><br>${links}`;
    }

    function loadAiThreads() {
      api('GET', d('L2FwaS9haS90aHJlYWRz')).then(data => {
        const list = $('#ai-thread-list');
        const threads = (data && data.threads) || [];
        if (!threads.length) {
          list.innerHTML = '<div class="ai-thread-empty">No chats yet.</div>';
          return;
        }
        list.innerHTML = threads.map(t => `
          <div class="ai-thread-item ${t.id === aiThreadId ? 'active' : ''}" data-thread-id="${t.id}">
            <span class="ai-thread-title">${escapeHtml(t.title || 'New chat')}</span>
            <button class="ai-thread-delete" data-delete-thread="${t.id}" title="Delete chat">&times;</button>
          </div>
        `).join('');
      }).catch(() => {});
    }

    function openThread(id) {
      aiThreadId = id;
      api('GET', `${d('L2FwaS9haS90aHJlYWRz')}/${id}`).then(data => {
        const thread = data && data.thread;
        if (!thread) return;
        const body = $('#ai-panel-body');
        body.innerHTML = '';
        (thread.messages || []).forEach(m => {
          if (m.role === 'user') {
            body.insertAdjacentHTML('beforeend', `<div class="ai-message ai-user">${escapeHtml(m.content)}</div>`);
          } else {
            const answerHtml = formatAnswer(m.content);
            body.insertAdjacentHTML('beforeend', `<div class="ai-message ai-bot">${answerHtml}${renderSources(m.sources)}</div>`);
          }
        });
        body.scrollTop = body.scrollHeight;
        loadAiThreads();
      }).catch(() => {});
    }

    function newChat() {
      aiThreadId = null;
      $('#ai-panel-body').innerHTML = '<div class="ai-message ai-bot">Ask me about threats in your feed, or toggle web search for anything else.</div>';
      $('#ai-web-toggle').checked = false;
      loadAiThreads();
      $('#ai-question').focus();
    }

    // On logout / account switch: the previous user's chat must not stay on screen,
    // and their threadId would 404 ("Thread not found") for the next user.
    resetAiPanel = () => {
      aiThreadId = null;
      $('#ai-panel').classList.add('hidden');
      $('#ai-panel-body').innerHTML = '<div class="ai-message ai-bot">Ask me about threats in your feed, or toggle web search for anything else.</div>';
      $('#ai-thread-list').innerHTML = '';
      $('#ai-question').value = '';
      $('#ai-web-toggle').checked = false;
    };

    async function askAI() {
      const question = $('#ai-question').value.trim();
      if (!question) return;
      const web = $('#ai-web-toggle').checked;
      const body = $('#ai-panel-body');

      // Append user message
      body.insertAdjacentHTML('beforeend', `<div class="ai-message ai-user">${escapeHtml(question)}</div>`);
      $('#ai-question').value = '';
      body.scrollTop = body.scrollHeight;

      // Typing indicator
      body.insertAdjacentHTML('beforeend', `<div class="ai-message ai-bot ai-typing" id="ai-typing">Thinking…</div>`);
      body.scrollTop = body.scrollHeight;

      try {
        const payload = { question, mode: web ? 'web' : 'rag' };
        if (aiThreadId) payload.threadId = aiThreadId;
        const result = await api('POST', d('L2FwaS9haS9hc2s='), payload);
        const typing = $('#ai-typing');
        if (typing) typing.remove();

        if (result.success) {
          aiThreadId = result.threadId || aiThreadId;
          const answerHtml = formatAnswer(result.answer);
          let extra = '';
          // Both modes return clickable sources (feed articles in RAG mode)
          if (Array.isArray(result.sources) && result.sources.length) {
            extra = renderSources(result.sources);
          }
          body.insertAdjacentHTML('beforeend', `<div class="ai-message ai-bot">${answerHtml}${extra}</div>`);
          loadAiThreads();
        } else {
          body.insertAdjacentHTML('beforeend', `<div class="ai-message ai-error">${escapeHtml(result.error || 'AI request failed')}</div>`);
        }
      } catch (err) {
        const typing = $('#ai-typing');
        if (typing) typing.remove();
        body.insertAdjacentHTML('beforeend', `<div class="ai-message ai-error">${escapeHtml(err.message || 'AI request failed')}</div>`);
      }
      body.scrollTop = body.scrollHeight;
    }

    $('#ai-send').addEventListener('click', askAI);
    $('#ai-question').addEventListener('keydown', (e) => {
      if (e.key === 'Enter') { e.preventDefault(); askAI(); }
    });
    $('#ai-new-chat').addEventListener('click', newChat);
    $('#ai-thread-list').addEventListener('click', (e) => {
      const del = e.target.closest('[data-delete-thread]');
      if (del) {
        e.stopPropagation();
        const id = parseInt(del.dataset.deleteThread);
        if (confirm('Delete this chat?')) {
          api('DELETE', `${d('L2FwaS9haS90aHJlYWRz')}/${id}`).then(() => {
            if (aiThreadId === id) newChat();
            else loadAiThreads();
          }).catch(() => {});
        }
        return;
      }
      const item = e.target.closest('[data-thread-id]');
      if (item) openThread(parseInt(item.dataset.threadId));
    });
  }

  //
  //  INITIALIZATION
  //
  function setCurrentPasswordFieldVisible(visible) {
    const input = $('#current-password');
    if (!input) return;
    const group = input.closest('.form-group');
    if (group) group.classList.toggle('hidden', !visible);
    input.required = visible;
    if (!visible) input.value = '';
  }

  // Forced mode: notice shown, Cancel becomes "Sign out" (see its handler)
  function setForcedPasswordMode(forced) {
    const cancelBtn = $('#cancel-password-btn');
    if (cancelBtn) { cancelBtn.classList.remove('hidden'); cancelBtn.textContent = forced ? 'Sign out' : 'Cancel'; }
    const notice = $('#password-forced-notice');
    if (notice) notice.classList.toggle('hidden', !forced);
  }

  // Forced password changes were removed: they looped on ephemeral hosting, and
  // every password change now goes through the emailed link instead.
  function enforcePasswordChange() { /* intentionally empty */ }


  // Shown under a failed sign-in when this server's database was created at this
  // boot (ephemeral hosting wipes it on every redeploy/restart): the account or
  // password the user remembers may simply no longer exist.
  function dbResetHint() {
    if (!serverConfig.dbCreatedAt) return '';
    const when = new Date(serverConfig.dbCreatedAt);
    if (isNaN(when.getTime())) return '';
    return ` — Note: this server's database was reset on ${when.toLocaleString()} (e.g. by a redeploy). ` +
      'Accounts and password changes made before then no longer exist: register again, or sign in as admin with the initial admin password.';
  }

  function loadServerConfig() {
    return fetch(d('L2FwaS9hdXRoL2NvbmZpZw==')).then(r => (r.ok ? readJson(r) : {})).then(cfg => {
      serverConfig = { ...serverConfig, ...(cfg || {}) };
      const group = $('#reg-invite-group');
      if (group) group.style.display = serverConfig.requireInvite ? '' : 'none';
      const inv = $('#reg-invite');
      if (inv) inv.required = !!serverConfig.requireInvite;
      return serverConfig;
    }).catch(() => serverConfig);
  }

  async function initDashboard() {
    // initDashboard runs again on every login / guest->user switch: don't stack intervals
    updateClock();
    if (!clockInterval) clockInterval = setInterval(updateClock, 1000);
    // Dynamic favicon — shield + pulse, updated every 2s
    updateFavicon();
    if (!faviconInterval) faviconInterval = setInterval(updateFavicon, 2000);
    enforcePasswordChange();
    initCustomDropdowns();
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
        // Re-render chart with new theme colors
        if (_chartTimeline.length) renderChart(_chartTimeline, _chartRange);
      });
    }
  }

  // Custom dropdown component — replaces native <select> popup with styled list
  function initCustomDropdowns() {
    document.querySelectorAll('.filter-select, .form-select').forEach(select => {
      if (select._customized) return;
      select._customized = true;

      const wrapper = document.createElement('div');
      wrapper.className = 'custom-select-wrapper';
      select.parentNode.insertBefore(wrapper, select);
      wrapper.appendChild(select);

      const display = document.createElement('div');
      display.className = 'custom-select-display';
      display.textContent = select.options[select.selectedIndex]?.textContent || '';
      wrapper.appendChild(display);
      // Keep the label in sync with programmatic changes (setSelectValue) and with
      // keyboard changes on the (visually hidden but focusable) native select.
      select._syncDisplay = () => {
        display.textContent = select.options[select.selectedIndex]?.textContent || '';
      };
      select.addEventListener('change', () => {
        select._syncDisplay();
        select.classList.toggle('has-value', select.value !== '');
      });

      const list = document.createElement('div');
      list.className = 'custom-select-list hidden';
      wrapper.appendChild(list);

      function buildOptions() {
        list.innerHTML = '';
        // Iterate direct children to preserve <optgroup> structure
        [...select.children].forEach(child => {
          if (child.tagName === 'OPTGROUP') {
            const header = document.createElement('div');
            header.className = 'custom-select-group';
            header.textContent = child.label;
            list.appendChild(header);
            [...child.children].forEach(opt => appendOption(opt));
          } else if (child.tagName === 'OPTION') {
            appendOption(child);
          }
        });

        function appendOption(opt) {
          const item = document.createElement('div');
          item.className = 'custom-select-option' + (opt.selected ? ' selected' : '');
          item.textContent = opt.textContent;
          item.addEventListener('click', (e) => {
            e.stopPropagation();
            select.value = opt.value;
            display.textContent = opt.textContent;
            list.querySelectorAll('.custom-select-option').forEach(o => o.classList.remove('selected'));
            item.classList.add('selected');
            list.classList.add('hidden');
            select.classList.toggle('has-value', opt.value !== '');
            select.dispatchEvent(new Event('change', { bubbles: true }));
          });
          list.appendChild(item);
        }
      }

      buildOptions();

      display.addEventListener('click', (e) => {
        e.stopPropagation();
        buildOptions(); // refresh in case options changed
        list.classList.toggle('hidden');
        // Close other dropdowns
        document.querySelectorAll('.custom-select-list:not(.hidden)').forEach(l => {
          if (l !== list) l.classList.add('hidden');
        });
      });

      // MutexObserver: rebuild when options change
      const obs = new MutationObserver(() => buildOptions());
      obs.observe(select, { childList: true, subtree: true });
    });

    // Close all dropdowns on outside click
    if (!document._customSelectBound) {
      document._customSelectBound = true;
      document.addEventListener('click', () => {
        document.querySelectorAll('.custom-select-list').forEach(l => l.classList.add('hidden'));
      });
    }
  }

  function init() {
    // Wrap so a single binding error can never leave the login button dead.
    try { bindEvents(); } catch (e) { console.error('[init] bindEvents error:', e); }
    try { initTheme(); } catch (e) { console.error('[init] theme error:', e); }
    loadServerConfig();

    // Arriving from a password-reset email link? Show the reset form.
    const resetToken = new URLSearchParams(window.location.search).get('reset');
    if (resetToken) {
      showAuth();
      $('#login-form')?.classList.add('hidden');
      $('#reset-password-form')?.classList.remove('hidden');
      return;
    }

    // "Secure my account" link in the password-changed email: open Forgot password
    if (new URLSearchParams(window.location.search).get('forgot') === '1') {
      history.replaceState(null, '', window.location.pathname);
      showAuth();
      $('#login-form')?.classList.add('hidden');
      $('#forgot-password-form')?.classList.remove('hidden');
      return;
    }

    // Check if we have an httpOnly session cookie by hitting the auth endpoint
    // (the cookie is sent automatically, no JS involved)
    fetchSessionUser()
      .then(user => {
        if (user) {
          setUser(user);
          initDashboard();
        } else {
          enterGuestSession();
        }
      })
      .catch(() => enterGuestSession());
  }

  // The access token only lives 15 min. A returning user with an expired access
  // token but a valid refresh token used to be dropped straight into a guest
  // session (which also overwrote their refresh cookie). Refresh first.
  async function fetchSessionUser() {
    const me = () => fetch(d('L2FwaS9hdXRoL21l')).then(async r => {
      if (!r.ok) return { status: r.status, user: null };
      const data = await readJson(r);
      return { status: r.status, user: data.success && data.user ? data.user : null };
    });
    let res = await me();
    if (!res.user && res.status === 401 && await refreshAccessToken()) {
      res = await me();   // re-read so we get the full user (incl. mustChangePassword)
    }
    return res.user;
  }

  // Anonymous visitors land straight on the dashboard via a shared guest account.
  // They can still sign in / register from the header to use their own workspace.
  function enterGuestSession() {
    fetch(d('L2FwaS9hdXRoL2d1ZXN0'), { method: 'POST' })
      .then(r => r.json())
      .then(data => {
        if (data.success && data.user) {
          setUser(data.user);
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

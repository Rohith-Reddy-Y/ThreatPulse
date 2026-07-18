/**
 * ThreatPulse v2 — Frontend Application
 * Multi-user dashboard with auth, reviews, sector/adversary filters
 */
'use strict';

(function () {
  // ═══════════════════════════════════════════════════════════
  //  AUTH STATE
  // ═══════════════════════════════════════════════════════════
  let authToken = localStorage.getItem('tp_token');
  let currentUser = JSON.parse(localStorage.getItem('tp_user') || 'null');

  // ═══════════════════════════════════════════════════════════
  //  STATE
  // ═══════════════════════════════════════════════════════════
  const state = {
    articles: [],
    sources: [],
    currentPage: 1,
    totalPages: 1,
    totalArticles: 0,
    filters: { category: '', severity: '', source_type: '', search: '', sector: '', threat_actor: '', has_poc: '', has_mitre: '', is_patched: '' },
    refreshCountdown: 60,
    refreshTimer: null,
    countdownTimer: null,
    isLoading: false,
    isFetching: false
  };

  // ═══════════════════════════════════════════════════════════
  //  DOM REFS
  // ═══════════════════════════════════════════════════════════
  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  // ═══════════════════════════════════════════════════════════
  //  API HELPER (with auth)
  // ═══════════════════════════════════════════════════════════
  async function api(method, endpoint, body = null) {
    const opts = {
      method,
      headers: { 'Content-Type': 'application/json' }
    };
    if (authToken) opts.headers['Authorization'] = `Bearer ${authToken}`;
    if (body) opts.body = JSON.stringify(body);

    const res = await fetch(endpoint, opts);
    if (res.status === 401) {
      // Token expired or invalid
      logout();
      throw new Error('Session expired');
    }
    const data = await res.json();
    if (!res.ok && data.error) throw new Error(data.error);
    return data;
  }

  // ═══════════════════════════════════════════════════════════
  //  AUTH FLOW
  // ═══════════════════════════════════════════════════════════
  function showAuth() {
    $('#auth-overlay').classList.remove('hidden');
    $('#app-container').classList.add('hidden');
  }

  function hideAuth() {
    $('#auth-overlay').classList.add('hidden');
    $('#app-container').classList.remove('hidden');
  }

  function setUser(token, user) {
    authToken = token;
    currentUser = user;
    localStorage.setItem('tp_token', token);
    localStorage.setItem('tp_user', JSON.stringify(user));
    updateUserMenu();
    hideAuth();
  }

  function logout() {
    if (authToken) {
      fetch('/api/auth/logout', { method: 'POST', headers: { 'Authorization': `Bearer ${authToken}` } }).catch(() => {});
    }
    authToken = null;
    currentUser = null;
    localStorage.removeItem('tp_token');
    localStorage.removeItem('tp_user');
    showAuth();
    if (state.refreshTimer) clearInterval(state.refreshTimer);
    if (state.countdownTimer) clearInterval(state.countdownTimer);
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

  // ═══════════════════════════════════════════════════════════
  //  UTILITIES
  // ═══════════════════════════════════════════════════════════
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
    const diff = Math.floor((now - date) / 1000);
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    if (diff < 172800) return 'Yesterday';
    if (diff < 604800) return `${Math.floor(diff / 86400)}d ago`;
    return date.toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' });
  }

  function dateKey(dateStr) {
    if (!dateStr) return 'Unknown';
    const d = new Date(dateStr);
    const today = new Date(); today.setHours(0,0,0,0);
    const yesterday = new Date(today); yesterday.setDate(yesterday.getDate() - 1);
    const articleDate = new Date(d); articleDate.setHours(0,0,0,0);
    if (articleDate.getTime() === today.getTime()) return '📅 Today';
    if (articleDate.getTime() === yesterday.getTime()) return '📅 Yesterday';
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
  }

  function sourceTypeIcon(type) {
    const icons = { rss: '📡', api: '🔌', darkweb: '🕸️', blog: '📝', twitter: '🐦', website: '🌐', custom: '⚙️', other: '📎' };
    return icons[type] || '📎';
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

  // ═══════════════════════════════════════════════════════════
  //  DATA FETCHING
  // ═══════════════════════════════════════════════════════════
  async function fetchStats() {
    try {
      const stats = await api('GET', '/api/articles/stats');
      animateValue($('#stat-threats'), stats.threatsToday || 0);
      animateValue($('#stat-critical'), stats.criticalVulns || 0);
      animateValue($('#stat-pocs'), stats.pocsDetected || 0);
      animateValue($('#stat-sources'), stats.activeSources || 0);
      if (stats.lastUpdated) {
        $('#last-updated-time').textContent = relativeTime(stats.lastUpdated);
      }
      $('#total-sources-count').textContent = stats.activeSources || 0;
    } catch (e) { console.error('Stats error:', e); }
  }

  async function fetchArticles(page = 1, append = false) {
    if (state.isLoading) return;
    state.isLoading = true;
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

      const data = await api('GET', `/api/articles?${params}`);
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
    finally { state.isLoading = false; }
  }

  async function fetchSources() {
    try {
      const data = await api('GET', '/api/sources');
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
      const s = await api('GET', '/api/notifications/settings');
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

  // ═══════════════════════════════════════════════════════════
  //  RENDERING
  // ═══════════════════════════════════════════════════════════
  function renderArticles() {
    const container = $('#articles-container');
    const skeletons = $('#loading-skeletons');
    const empty = $('#empty-state');
    const loadMore = $('#load-more-container');

    skeletons.classList.add('hidden');

    if (state.articles.length === 0) {
      container.innerHTML = '';
      empty.classList.remove('hidden');
      loadMore.classList.add('hidden');
      return;
    }

    empty.classList.add('hidden');

    // Group by date
    const groups = {};
    state.articles.forEach(a => {
      const key = dateKey(a.published_date);
      if (!groups[key]) groups[key] = [];
      groups[key].push(a);
    });

    let html = '';
    for (const [date, articles] of Object.entries(groups)) {
      html += `<div class="date-group"><div class="date-header"><span class="date-label">${date}</span><span class="date-count">${articles.length} items</span></div>`;
      articles.forEach(a => { html += createArticleCard(a); });
      html += '</div>';
    }
    container.innerHTML = html;
    loadMore.classList.toggle('hidden', state.currentPage >= state.totalPages);
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
    const sectorBadge = article.sector ? `<span class="badge badge-sector">${sectorIcon(article.sector)} ${article.sector}</span>` : '';
    const actorBadge = article.threat_actors ? article.threat_actors.split(',').map(a => `<span class="badge badge-actor">🕷️ ${escapeHtml(a.trim())}</span>`).join('') : '';
    const cveLink = article.cve_id ? `<a href="https://nvd.nist.gov/vuln/detail/${article.cve_id}" target="_blank" rel="noopener" class="cve-link">${article.cve_id}</a>` : '';
    const pocBadge = article.has_poc ? '<span class="badge badge-poc">⚡ PoC Available</span>' : '';

    // MITRE ATT&CK technique/tactic IDs — key signal for detection engineering
    const mitreIds = article.mitre_ids ? article.mitre_ids.split(',').map(s => s.trim()).filter(Boolean) : [];
    const mitreBadges = mitreIds.map(id =>
      `<a href="${mitreLink(id)}" target="_blank" rel="noopener" class="badge badge-mitre" title="MITRE ATT&CK ${escapeHtml(id)}">🎯 ${escapeHtml(id)}</a>`
    ).join('');
    const ttpBadge = mitreIds.length ? '<span class="badge badge-ttp">🆕 TTP</span>' : '';

    // Patch status — 1 = patched, 0 = unpatched, -1 = unknown
    const patchBadge = article.is_patched === 1
      ? '<span class="badge badge-patched">✅ Patched</span>'
      : article.is_patched === 0
        ? '<span class="badge badge-unpatched">❌ Unpatched</span>'
        : '';

    const desc = article.description ? escapeHtml(article.description.substring(0, 300)) : '';

    // Reviews
    let reviewHtml = '';
    let reviews = [];
    try { reviews = article.reviews ? JSON.parse(article.reviews) : []; } catch(e) {}
    reviews = reviews.filter(r => r.user_id); // filter out nulls

    if (reviews.length > 0) {
      reviewHtml = '<div class="article-reviews">';
      reviews.forEach(r => {
        const statusIcon = r.status === 'reviewed' ? '✅' : r.status === 'escalated' ? '🔴' : '👁️';
        const timeStr = r.status === 'reviewing' ? `since ${relativeTime(r.started_at)}` : relativeTime(r.completed_at || r.started_at);
        reviewHtml += `<span class="review-tag review-${r.status}">${statusIcon} ${escapeHtml(r.username)} ${timeStr}</span>`;
      });
      reviewHtml += '</div>';
    }

    return `
      <article class="article-card ${article.severity === 'critical' ? 'critical' : ''} ${mitreIds.length ? 'has-ttp' : ''}" data-article-id="${article.id}">
        <div class="article-header">
          <div class="article-badges">${catBadge}${sevBadge}${ttpBadge}${pocBadge}${patchBadge}${sectorBadge}${actorBadge}${mitreBadges}${cveLink}</div>
        </div>
        <h3 class="article-title"><a href="${escapeHtml(article.url)}" target="_blank" rel="noopener">${escapeHtml(article.title)}</a></h3>
        <div class="article-meta">
          <span>${sourceTypeIcon(article.source_type)} ${escapeHtml(article.source_name)}</span>
          ${article.author ? `<span>by ${escapeHtml(article.author)}</span>` : ''}
          <span>${relativeTime(article.published_date)}</span>
        </div>
        ${desc ? `<p class="article-desc">${desc}</p>` : ''}
        ${article.tags ? `<div class="article-tags">${article.tags.split(',').map(t => `<span class="tag">${t.trim()}</span>`).join('')}</div>` : ''}
        ${reviewHtml}
        <div class="article-actions">
          <button class="btn-review" data-review-article="${article.id}" title="Start reviewing">👁️ Review</button>
          <button class="btn-review-done" data-review-done="${article.id}" title="Mark as reviewed">✅ Done</button>
          <button class="btn-escalate" data-escalate="${article.id}" title="Escalate">🔴 Escalate</button>
        </div>
      </article>`;
  }

  function sectorIcon(sector) {
    const icons = { financial: '🏦', healthcare: '🏥', government: '🏛️', technology: '💻' };
    return icons[sector] || '📂';
  }

  // Unified source health status — same logic used by the admin panel
  function sourceStatus(source) {
    if (!source.enabled) return { cls: 'disabled', label: 'Disabled', color: 'var(--text-muted)', icon: '⏸' };
    if (source.last_error) return { cls: 'error', label: 'Error', color: 'var(--red)', icon: '⚠' };
    if (source.last_fetched) return { cls: 'active', label: 'OK', color: 'var(--green)', icon: '✓' };
    return { cls: 'idle', label: 'Not yet fetched', color: 'var(--text-muted)', icon: '○' };
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
        <span class="source-type-icon">${sourceTypeIcon(source.type)}</span>
        <div class="source-info">
          <div class="source-info-name" title="${escapeHtml(source.name)}"><a href="${escapeHtml(source.url || '#')}" target="_blank" rel="noopener" style="color:inherit;text-decoration:none;" onmouseover="this.style.color='#2da8bd'" onmouseout="this.style.color='inherit'">${escapeHtml(source.name)}</a></div>
          <div class="source-info-meta">Fetched: ${lastFetched} <span style="color:${st.color};font-size:10px;" title="${source.last_error ? escapeHtml(source.last_error) : st.label}">${st.icon} ${st.label}</span></div>
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

  // ═══════════════════════════════════════════════════════════
  //  SOURCE & NOTIFICATION ACTIONS
  // ═══════════════════════════════════════════════════════════
  async function addSource(formData) {
    try {
      await api('POST', '/api/sources', formData);
      showToast('Source Added', `${formData.name} has been added.`, 'success');
      fetchSources();
      $('#add-source-form').reset();
    } catch (e) { showToast('Error', e.message, 'error'); }
  }

  async function toggleSource(id, enabled) {
    try {
      await api('PUT', `/api/sources/${id}`, { enabled: enabled ? 1 : 0 });
    } catch (e) { showToast('Error', e.message, 'error'); fetchSources(); }
  }

  async function deleteSource(id) {
    try {
      await api('DELETE', `/api/sources/${id}`);
      showToast('Source Removed', 'Source has been deleted.', 'success');
      fetchSources();
    } catch (e) { showToast('Error', e.message, 'error'); }
  }

  async function saveNotificationSettings() {
    try {
      await api('PUT', '/api/notifications/settings', {
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
      const r = await api('POST', '/api/notifications/test', { type });
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
      await api('POST', '/api/fetch-now');
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

  function exportArticles() {
    const blob = new Blob([JSON.stringify(state.articles, null, 2)], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url; a.download = `threatpulse-export-${new Date().toISOString().split('T')[0]}.json`;
    a.click(); URL.revokeObjectURL(url);
  }

  // ═══════════════════════════════════════════════════════════
  //  AUTO-REFRESH
  // ═══════════════════════════════════════════════════════════
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

  // ═══════════════════════════════════════════════════════════
  //  EVENT BINDING
  // ═══════════════════════════════════════════════════════════
  function bindEvents() {
    // Auth: Login
    $('#login-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = $('#login-error');
      errEl.classList.add('hidden');
      try {
        const result = await fetch('/api/auth/login', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: $('#login-username').value.trim(),
            password: $('#login-password').value
          })
        }).then(r => r.json());

        if (result.success) {
          setUser(result.token, result.user);
          initDashboard();
        } else {
          errEl.textContent = result.error || 'Login failed';
          errEl.classList.remove('hidden');
        }
      } catch (err) {
        errEl.textContent = 'Connection error';
        errEl.classList.remove('hidden');
      }
    });

    // Auth: Register
    $('#register-form').addEventListener('submit', async (e) => {
      e.preventDefault();
      const errEl = $('#register-error');
      errEl.classList.add('hidden');
      try {
        const result = await fetch('/api/auth/register', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({
            username: $('#reg-username').value.trim(),
            displayName: $('#reg-display').value.trim(),
            password: $('#reg-password').value,
            email: $('#reg-email').value.trim(),
            inviteCode: $('#reg-invite').value.trim()
          })
        }).then(r => r.json());

        if (result.success) {
          setUser(result.token, result.user);
          initDashboard();
        } else {
          errEl.textContent = result.error || 'Registration failed';
          errEl.classList.remove('hidden');
        }
      } catch (err) {
        errEl.textContent = 'Connection error';
        errEl.classList.remove('hidden');
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
        const result = await api('PUT', '/api/auth/email', { email: $('#account-email').value.trim() });
        if (result.success) {
          if (currentUser) {
            currentUser.email = result.email;
            localStorage.setItem('tp_user', JSON.stringify(currentUser));
          }
          showToast('Success', 'Email updated.', 'success');
          $('#email-modal').classList.add('hidden');
        } else {
          errEl.textContent = result.error; errEl.classList.remove('hidden');
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
        const result = await api('PUT', '/api/auth/password', {
          currentPassword: $('#current-password').value,
          newPassword: $('#new-password').value
        });
        if (result.success) {
          showToast('Success', 'Password changed successfully.', 'success');
          if (currentUser) {
            currentUser.mustChangePassword = false;
            localStorage.setItem('tp_user', JSON.stringify(currentUser));
          }
          $('#password-modal').classList.add('hidden');
          const notice = $('#password-forced-notice');
          if (notice) notice.classList.add('hidden');
          const cancelBtn = $('#cancel-password-btn');
          if (cancelBtn) cancelBtn.classList.remove('hidden');
          $('#password-form').reset();
        } else {
          errEl.textContent = result.error;
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
      fetchArticles();
    }, 400));

    // Category pills
    $$('#category-filters .pill').forEach(pill => {
      pill.addEventListener('click', () => {
        $$('#category-filters .pill').forEach(p => p.classList.remove('active'));
        pill.classList.add('active');
        state.filters.category = pill.dataset.category;
        state.currentPage = 1;
        fetchArticles();
      });
    });

    // Severity filter
    $('#severity-filter').addEventListener('change', (e) => {
      state.filters.severity = e.target.value;
      state.currentPage = 1;
      fetchArticles();
    });

    // Source type filter
    $('#source-type-filter').addEventListener('change', (e) => {
      state.filters.source_type = e.target.value;
      state.currentPage = 1;
      fetchArticles();
    });

    // Sector filter
    $('#sector-filter').addEventListener('change', (e) => {
      state.filters.sector = e.target.value;
      state.currentPage = 1;
      fetchArticles();
    });

    // Threat actor filter
    $('#threat-actor-filter').addEventListener('change', (e) => {
      state.filters.threat_actor = e.target.value;
      state.currentPage = 1;
      fetchArticles();
    });

    // Patch status filter
    $('#patch-filter').addEventListener('change', (e) => {
      state.filters.is_patched = e.target.value;
      state.currentPage = 1;
      fetchArticles();
    });

    // Detection-engineering toggle pills (PoC / MITRE)
    $$('.toggle-pill').forEach(btn => {
      btn.addEventListener('click', () => {
        const key = btn.dataset.filter; // has_poc | has_mitre
        const active = btn.classList.toggle('active');
        state.filters[key] = active ? '1' : '';
        state.currentPage = 1;
        fetchArticles();
      });
    });

    // Fetch now
    $('#fetch-now-btn').addEventListener('click', fetchNow);

    // Export
    $('#export-btn').addEventListener('click', exportArticles);

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
      // Edit source URL
      const editBtn = e.target.closest('[data-edit-source]');
      if (editBtn) {
        const id = parseInt(editBtn.dataset.editSource);
        const currentUrl = editBtn.dataset.editUrl;
        const newUrl = prompt('Enter new URL for this source:', currentUrl);
        if (newUrl && newUrl.trim() !== currentUrl) {
          api('PUT', `/api/sources/${id}`, { url: newUrl.trim() }).then(() => {
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

      // Review actions
      const reviewBtn = e.target.closest('[data-review-article]');
      if (reviewBtn) {
        const articleId = parseInt(reviewBtn.dataset.reviewArticle);
        api('POST', `/api/articles/${articleId}/review`).then(() => {
          showToast('Reviewing', 'You are now reviewing this article.', 'info');
          fetchArticles();
        }).catch(err => showToast('Error', err.message, 'error'));
      }

      const doneBtn = e.target.closest('[data-review-done]');
      if (doneBtn) {
        const articleId = parseInt(doneBtn.dataset.reviewDone);
        const notes = prompt('Add review notes (optional):') || '';
        api('PUT', `/api/articles/${articleId}/review`, { notes }).then(() => {
          showToast('Reviewed', 'Article marked as reviewed.', 'success');
          fetchArticles();
        }).catch(err => showToast('Error', err.message, 'error'));
      }

      const escalateBtn = e.target.closest('[data-escalate]');
      if (escalateBtn) {
        const articleId = parseInt(escalateBtn.dataset.escalate);
        const notes = prompt('Why are you escalating this?') || '';
        api('POST', `/api/articles/${articleId}/escalate`, { notes }).then(() => {
          showToast('Escalated', 'Article has been escalated.', 'warning');
          fetchArticles();
        }).catch(err => showToast('Error', err.message, 'error'));
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
          eyeBtn.textContent = input.type === 'password' ? '👁️' : '🙈';
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
            await api('PUT', `/api/sources/${cb.dataset.srcId}`, { url: newUrl.trim() });
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
          try { await api('DELETE', `/api/sources/${cb.dataset.srcId}`); } catch(e) {}
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

  // ═══════════════════════════════════════════════════════════
  //  INITIALIZATION
  // ═══════════════════════════════════════════════════════════
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
    enforcePasswordChange();
    await Promise.allSettled([fetchStats(), fetchArticles(), fetchSources(), fetchNotificationSettings()]);
    startAutoRefresh();
  }

  function initTheme() {
    const btn = $('#theme-toggle');
    const apply = (t) => {
      document.documentElement.setAttribute('data-theme', t);
      try { localStorage.setItem('tp_theme', t); } catch (e) {}
      if (btn) btn.textContent = t === 'light' ? '☀️' : '🌙';
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
    bindEvents();
    initTheme();

    if (authToken && currentUser) {
      // Verify token is still valid
      fetch('/api/auth/me', { headers: { 'Authorization': `Bearer ${authToken}` } })
        .then(r => r.json())
        .then(data => {
          if (data.success && data.user) {
            currentUser = data.user;
            localStorage.setItem('tp_user', JSON.stringify(data.user));
            updateUserMenu();
            hideAuth();
            initDashboard();
          } else {
            logout();
          }
        })
        .catch(() => logout());
    } else {
      showAuth();
    }
  }

  // Start
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', init);
  } else {
    init();
  }
})();

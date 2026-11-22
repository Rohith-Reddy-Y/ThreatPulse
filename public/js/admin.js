/**
 * ThreatPulse v2 — Admin Panel Logic
 * Cookie-based auth (httpOnly JWT) — no localStorage tokens
 */
'use strict';
(function() {
  // Decode obfuscated API paths
  function d(b64) { return atob(b64); }

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  let currentUser = null;

  // Read CSRF token from the readable cookie
  function getCsrfToken() {
    const match = document.cookie.match(/(?:^|;\s*)tp_csrf=([^;]*)/);
    return match ? match[1] : null;
  }

  async function api(method, endpoint, body = null) {
    const opts = { method, headers: { 'Content-Type': 'application/json' } };

    // Add CSRF token for state-changing requests
    if (method !== 'GET') {
      const csrf = getCsrfToken();
      if (csrf) opts.headers['X-CSRF-Token'] = csrf;
    }

    if (body) opts.body = JSON.stringify(body);

    let res = await fetch(endpoint, opts);
    // The access token lives 15 min and this page never refreshed it, so any
    // action after 15 min idle bounced the admin to '/'. Refresh once and retry.
    if (res.status === 401 && await refreshSession()) {
      if (method !== 'GET') {
        const csrf = getCsrfToken();
        if (csrf) opts.headers['X-CSRF-Token'] = csrf;
      }
      res = await fetch(endpoint, opts);
    }
    if (res.status === 401 || res.status === 403) {
      window.location.href = '/';
      throw new Error('Access denied');
    }
    try { return await res.json(); } catch { return { success: false, error: `Request failed (${res.status})` }; }
  }

  let refreshPromise = null;
  function refreshSession() {
    if (!refreshPromise) {
      refreshPromise = fetch(d('L2FwaS9hdXRoL3JlZnJlc2g='), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': getCsrfToken() || '' }
      }).then(r => r.ok).catch(() => false).finally(() => { refreshPromise = null; });
    }
    return refreshPromise;
  }

  // Check auth on load — cookie is sent automatically
  async function init() {
    try {
      let res = await fetch(d('L2FwaS9hdXRoL21l'));
      if (res.status === 401 && await refreshSession()) res = await fetch(d('L2FwaS9hdXRoL21l'));
      if (!res.ok) throw new Error('Not authenticated');
      const data = await res.json();
      if (!data.success || !data.user || data.user.role !== 'admin') {
        throw new Error('Admin access required');
      }
      currentUser = data.user;
      // Load all panels
      loadStats();
      loadUsers();
      loadInvites();
      loadSources();
      loadCatalog();
      loadAudit();
      loadResets();
      loadEmailStatus();
      loadAiSettings();
    } catch (e) {
      alert('Admin access required. Redirecting to login...');
      window.location.href = '/';
    }
  }

  // Must escape quotes too — results go into attribute values (title, data-*)
  function escapeHtml(str) {
    if (str === null || str === undefined || str === '') return '';
    return String(str)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function relativeTime(dateStr) {
    if (!dateStr) return 'Never';
    // SQLite datetime('now') strings have no zone but are UTC
    const when = /^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(dateStr) ? new Date(dateStr.replace(' ', 'T') + 'Z') : new Date(dateStr);
    const diff = Math.floor((Date.now() - when) / 1000);
    if (diff < 60) return 'Just now';
    if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
    if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
    return new Date(dateStr).toLocaleDateString('en-US', { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' });
  }

  // Clipboard copy that also works over plain HTTP (no secure context)
  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text);
    }
    return new Promise((resolve, reject) => {
      try {
        const ta = document.createElement('textarea');
        ta.value = text;
        ta.style.position = 'fixed';
        ta.style.opacity = '0';
        document.body.appendChild(ta);
        ta.focus(); ta.select();
        const ok = document.execCommand('copy');
        document.body.removeChild(ta);
        ok ? resolve() : reject(new Error('copy failed'));
      } catch (e) { reject(e); }
    });
  }

  function showToast(msg, type = 'info') {
    const c = $('#toast-container');
    const t = document.createElement('div');
    t.className = `toast toast-${type}`;
    t.innerHTML = `<div class="toast-body">${escapeHtml(msg)}</div>`;
    c.appendChild(t);
    setTimeout(() => t.classList.add('show'), 10);
    setTimeout(() => { t.classList.remove('show'); setTimeout(() => t.remove(), 300); }, 3000);
  }

  // Tab switching
  $$('[data-admin-tab]').forEach(btn => {
    btn.addEventListener('click', () => {
      $$('[data-admin-tab]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      $$('.admin-tab').forEach(t => t.classList.add('hidden'));
      $(`#tab-${btn.dataset.adminTab}`).classList.remove('hidden');
    });
  });

  // Fetch stats
  async function loadStats() {
    const stats = await api('GET', d('L2FwaS9hZG1pbi9zdGF0cw=='));
    if (!stats) return;
    $('#admin-total-users').textContent = stats.totalUsers || 0;
    $('#admin-total-sources').textContent = stats.totalSourcesAll || 0;
    $('#admin-total-articles').textContent = stats.totalArticles || 0;
    $('#admin-errors-today').textContent = stats.errorsToday || 0;
  }

  // Users
  async function loadUsers() {
    const data = await api('GET', d('L2FwaS9hZG1pbi91c2Vycw=='));
    if (!data || !data.users) return;
    const tbody = $('#users-tbody');
    // The server refuses to demote, disable or delete your own account and to
    // promote the shared guest account: don't offer those controls.
    tbody.innerHTML = data.users.map(u => {
      const self = currentUser && u.id === currentUser.id;
      const guest = u.username === 'guest';
      const lock = self ? ' disabled title="You cannot change your own role or status"' : '';
      return `
      <tr>
        <td><strong>${escapeHtml(u.username)}</strong></td>
        <td>${escapeHtml(u.display_name)}</td>
        <td><select data-user-role="${u.id}" class="filter-select" style="padding:4px 8px;font-size:12px;"${lock}>
          <option value="analyst" ${u.role==='analyst'?'selected':''}>Analyst</option>
          <option value="admin" ${u.role==='admin'?'selected':''}${guest ? ' disabled' : ''}>Admin</option>
        </select></td>
        <td>${u.source_count || 0}</td>
        <td>${relativeTime(u.last_login)}</td>
        <td><span class="badge ${u.is_active ? 'badge-advisory' : 'badge-breach'}">${u.is_active ? 'Active' : 'Disabled'}</span></td>
        <td>
          <button class="btn btn-ghost" data-toggle-user="${u.id}" data-active="${u.is_active}" style="font-size:12px;padding:4px 8px;"${lock}>${u.is_active ? 'Disable' : 'Enable'}</button>
          <button class="btn btn-danger" data-delete-user="${u.id}" style="font-size:12px;padding:4px 8px;"${lock}>Delete</button>
        </td>
      </tr>`;
    }).join('');
  }

  // Invite codes
  async function loadInvites() {
    const data = await api('GET', d('L2FwaS9hZG1pbi9pbnZpdGUtY29kZXM='));
    if (!data || !data.codes) return;
    const tbody = $('#invites-tbody');
    tbody.innerHTML = data.codes.map(c => `
      <tr>
        <td><code class="copy-code" data-copy="${escapeHtml(c.code)}" style="color:var(--cyan);font-family:var(--font-mono);font-size:14px;cursor:pointer;" title="Click to copy">${escapeHtml(c.code)}</code></td>
        <td>${escapeHtml(c.created_by_name || 'System')}</td>
        <td>${c.used_by_name ? escapeHtml(c.used_by_name) : '—'}</td>
        <td>${c.used_at ? relativeTime(c.used_at) : '—'}</td>
        <td><span class="badge ${c.used_by ? 'badge-breach' : 'badge-advisory'}">${c.used_by ? 'Used' : 'Available'}</span></td>
      </tr>
    `).join('');
  }

  // Unified source health status — must match the user dashboard exactly
  function sourceStatus(s) {
    if (!s.enabled) return { cls: 'disabled', label: 'Disabled' };
    if (s.last_error) return { cls: 'error', label: 'Error' };
    if (s.last_fetched) return { cls: 'active', label: 'OK' };
    return { cls: 'idle', label: '○ Not yet fetched' };
  }

  // Sources — one section per user (including users with zero sources)
  async function loadSources() {
    const [srcData, userData] = await Promise.all([
      api('GET', d('L2FwaS9hZG1pbi9zb3VyY2Vz')),
      api('GET', d('L2FwaS9hZG1pbi91c2Vycw=='))
    ]);
    if (!srcData || !srcData.sources) return;

    // Group sources by owner id
    const groups = {};
    srcData.sources.forEach(s => {
      const key = s.user_id != null ? String(s.user_id) : 'system';
      if (!groups[key]) groups[key] = { name: s.added_by_name || 'System', sources: [] };
      groups[key].sources.push(s);
    });

    // Ensure every user has a section, even with no sources
    const orderedKeys = [];
    if (userData && userData.users) {
      userData.users.forEach(u => {
        const key = String(u.id);
        if (!groups[key]) groups[key] = { name: u.display_name, sources: [] };
        else groups[key].name = u.display_name;
        orderedKeys.push(key);
      });
    }
    // Append any leftover groups (e.g. legacy 'system')
    Object.keys(groups).forEach(k => { if (!orderedKeys.includes(k)) orderedKeys.push(k); });

    const container = $('#sources-by-user-container');
    let html = '';
    for (const key of orderedKeys) {
      const g = groups[key];
      if (!g) continue;
      const sources = g.sources;
      const errorCount = sources.filter(s => s.last_error).length;
      const errBadge = errorCount ? `<span style="color:var(--red);font-size:12px;margin-left:6px;">● ${errorCount} down</span>` : '';
      html += `<div class="user-source-group">
        <h4 style="color:var(--cyan);margin:16px 0 8px;font-size:14px;">${escapeHtml(g.name)} <span style="color:var(--text-muted);font-size:12px;">(${sources.length} source${sources.length === 1 ? '' : 's'})</span>${errBadge}</h4>`;
      if (sources.length === 0) {
        html += `<p style="color:var(--text-muted);font-size:12px;padding:4px 2px 8px;">No sources yet.</p></div>`;
        continue;
      }
      html += `<table class="admin-table">
          <thead><tr><th style="width:30px;"><input type="checkbox" class="group-select-all" data-group="${escapeHtml(key)}"></th><th>Name</th><th>URL</th><th>Type</th><th>Enabled</th><th>Last Fetched</th><th>Status</th></tr></thead>
          <tbody>${sources.map(s => {
            const st = sourceStatus(s);
            return `
            <tr>
              <td><input type="checkbox" class="source-checkbox" data-source-id="${s.id}" data-source-url="${escapeHtml(s.url)}" data-source-name="${escapeHtml(s.name)}"></td>
              <td><strong>${escapeHtml(s.name)}</strong></td>
              <td style="max-width:250px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap;font-size:11px;color:var(--text-secondary);" title="${escapeHtml(s.url)}">${escapeHtml(s.url)}</td>
              <td>${escapeHtml(s.type)}</td>
              <td><span class="badge ${s.enabled ? 'badge-advisory' : 'badge-breach'}">${s.enabled ? 'Yes' : 'No'}</span></td>
              <td>${relativeTime(s.last_fetched)}</td>
              <td><span class="source-status-dot ${st.cls}" title="${s.last_error ? escapeHtml(s.last_error) : st.label}"></span> ${st.label}</td>
            </tr>`;
          }).join('')}
          </tbody>
        </table>
      </div>`;
    }
    container.innerHTML = html;
  }

  // Source catalog — one row per unique feed, contributors as name labels
  let catalog = { entries: [], totals: {} };
  let catalogFilter = 'all';
  async function loadCatalog() {
    const data = await api('GET', d('L2FwaS9hZG1pbi9zb3VyY2UtY2F0YWxvZw=='));
    if (!data || !Array.isArray(data.entries)) return;
    catalog = data;
    const t = data.totals || {};
    $('#catalog-stats').innerHTML = [
      ['Unique feeds', t.feeds], ['Built-in', t.builtIn], ['User-submitted', t.userSubmitted],
      ['New (48h)', t.newUserSubmitted], ['Duplicate rows folded', t.duplicatesFolded],
    ].map(([k, v]) => `<div class="catalog-stat"><b>${Number(v) || 0}</b><span>${escapeHtml(k)}</span></div>`).join('');
    const n = Number(t.newUserSubmitted) || 0;
    for (const id of ['#catalog-new-badge', '#sources-tab-new']) {
      const el = $(id);
      if (!el) continue;
      el.textContent = id === '#catalog-new-badge' ? `${n} new` : String(n);
      el.classList.toggle('hidden', n === 0);
    }
    renderCatalog();
  }

  function renderCatalog() {
    const q = ($('#catalog-search')?.value || '').trim().toLowerCase();
    const rows = catalog.entries.filter((e) => {
      if (catalogFilter === 'user' && !e.userSubmitted) return false;
      if (catalogFilter === 'builtin' && !e.builtIn) return false;
      if (catalogFilter === 'shared' && !(e.builtIn && e.contributorCount)) return false;
      if (!q) return true;
      return [e.name, e.url, e.host, ...e.contributors.map((c) => `${c.displayName} ${c.username} ${c.nameGiven}`)]
        .some((v) => String(v || '').toLowerCase().includes(q));
    });
    const tbody = $('#catalog-tbody');
    if (!rows.length) {
      tbody.innerHTML = `<tr><td colspan="6" style="color:var(--text-muted);">${catalog.entries.length ? 'No feeds match.' : 'No sources yet.'}</td></tr>`;
      return;
    }
    tbody.innerHTML = rows.slice(0, 600).map((e) => {
      const origin = e.builtIn
        ? '<span class="catalog-origin builtin">Built-in</span>'
        : `<span class="catalog-origin user">User-submitted</span>${e.isNew ? ' <span class="catalog-new">NEW</span>' : ''}`;
      const chips = e.contributors.slice(0, 6).map((c) => {
        const when = utcDate(c.addedAt);
        const tip = `${c.displayName} (@${c.username}) added this${when ? ' ' + relativeTime(when.toISOString()) : ''} as “${c.nameGiven}”${c.enabled ? '' : ' — disabled'}`;
        return `<span class="catalog-chip${c.enabled ? '' : ' off'}" title="${escapeHtml(tip)}">${escapeHtml(c.displayName)}</span>`;
      }).join('') + (e.contributors.length > 6 ? `<span class="catalog-chip more">+${e.contributors.length - 6}</span>` : '');
      const who = chips || '<span style="color:var(--text-muted);font-size:11px;">Platform only</span>';
      const st = e.status === 'ok' ? ['active', 'OK'] : e.status === 'error' ? ['error', 'Error'] : ['idle', 'Pending'];
      const first = utcDate(e.firstAddedAt);
      return `<tr>
        <td><strong>${escapeHtml(e.name)}</strong><div class="catalog-url" title="${escapeHtml(e.url)}">${escapeHtml(e.url)}</div></td>
        <td style="white-space:nowrap;">${origin}</td>
        <td><div class="catalog-chips">${who}</div></td>
        <td>${escapeHtml(e.type || '')}</td>
        <td style="white-space:nowrap;"><span class="source-status-dot ${st[0]}" title="${escapeHtml(e.lastError || st[1])}"></span> ${st[1]}</td>
        <td style="white-space:nowrap;font-size:12px;">${first ? relativeTime(first.toISOString()) : (e.builtIn ? '—' : '')}</td>
      </tr>`;
    }).join('');
  }

  // Audit log
  async function loadAudit() {
    const data = await api('GET', d('L2FwaS9hZG1pbi9hdWRpdC1sb2c='));
    if (!data || !data.log) return;
    const tbody = $('#audit-tbody');
    tbody.innerHTML = data.log.map(e => `
      <tr>
        <td style="font-size:12px;white-space:nowrap;">${relativeTime(e.created_at)}</td>
        <td>${escapeHtml(e.username || '—')}</td>
        <td><code style="font-size:12px;">${escapeHtml(e.action)}</code></td>
        <td style="font-size:12px;max-width:300px;overflow:hidden;text-overflow:ellipsis;">${escapeHtml(e.details || '—')}</td>
        <td style="font-size:11px;">${escapeHtml(e.ip_address || '—')}</td>
      </tr>
    `).join('');
  }

  // SQLite datetime('now') values are UTC without a zone marker
  function utcDate(v) {
    if (!v) return null;
    return new Date(/^\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}$/.test(v) ? v.replace(' ', 'T') + 'Z' : v);
  }

  // Pending password resets: with no SMTP the forgot-password link only exists
  // here (and in the server log), so the admin can hand it to the user.
  async function loadResets() {
    const data = await api('GET', d('L2FwaS9hZG1pbi9yZXNldC10b2tlbnM='));
    if (!data || !Array.isArray(data.tokens)) return;
    const tbody = $('#resets-tbody');
    if (!data.tokens.length) {
      tbody.innerHTML = '<tr><td colspan="5" style="color:var(--text-muted);">No pending reset requests.</td></tr>';
      return;
    }
    tbody.innerHTML = data.tokens.map(t => {
      const link = t.token ? `${window.location.origin}/?reset=${encodeURIComponent(t.token)}` : null;
      const linkCell = link
        ? `<code class="copy-code" data-copy="${escapeHtml(link)}" style="color:var(--cyan);font-size:11px;cursor:pointer;word-break:break-all;" title="Click to copy">${escapeHtml(link)}</code>`
        : `<span style="color:var(--text-muted);font-size:12px;">${t.withheld === 'admin_account' ? 'Hidden (another admin account)' : 'Sent by email'}</span>`;
      const created = utcDate(t.created_at), expires = utcDate(t.expires_at);
      return `
      <tr>
        <td><strong>${escapeHtml(t.username)}</strong></td>
        <td>${escapeHtml(t.email || '—')}</td>
        <td>${created ? relativeTime(created.toISOString()) : '—'}</td>
        <td>${expires ? escapeHtml(expires.toLocaleTimeString()) : '—'}</td>
        <td>${linkCell}</td>
      </tr>`;
    }).join('');
  }

  // Email delivery status (Brevo / SMTP) + test message
  async function loadEmailStatus() {
    try {
      const s = await api('GET', d('L2FwaS9hZG1pbi9lbWFpbC1zdGF0dXM='));
      if (!s) return;
      const badge = $('#email-status-badge');
      badge.textContent = s.configured ? 'working config' : 'not set up';
      badge.className = 'badge ' + (s.configured ? 'badge-advisory' : 'badge-breach');
      $('#email-provider').textContent = s.provider === 'brevo' ? 'Brevo HTTPS API' : s.provider === 'smtp' ? 'SMTP' : 'None';
      $('#email-from').textContent = s.from || '—';
      $('#email-admin').textContent = s.adminEmail || 'none — add one with Change Email on the dashboard';
      $('#email-invite').textContent = s.inviteRequired ? 'Invite code required' : 'Open (anyone can register)';
      const prob = $('#email-problem');
      prob.textContent = s.problem || '';
      prob.classList.toggle('hidden', !s.problem);
    } catch (e) { /* api() already redirects on 401/403 */ }
  }

  async function sendTestEmail() {
    const btn = $('#email-test-btn');
    btn.disabled = true; btn.textContent = 'Sending…';
    try {
      const r = await api('POST', d('L2FwaS9hZG1pbi9lbWFpbC10ZXN0'));
      if (r && r.success) showToast(`Test email sent to ${r.to} — check inbox and spam`, 'success');
      else showToast((r && r.error) || 'Test email failed', 'error');
    } catch (e) {
      showToast(e.message || 'Test email failed', 'error');
    }
    btn.disabled = false; btn.textContent = 'Send test email to me';
  }

  // AI settings (Groq + Tavily keys, stored server-side)
  async function loadAiSettings() {
    try {
      const data = await api('GET', d('L2FwaS9hZG1pbi9haS1zZXR0aW5ncw=='));
      if (!data) return;
      if (data.groq_api_key) $('#ai-groq-key').placeholder = 'Current: ' + data.groq_api_key + ' - paste a new key to replace';
      if (data.tavily_api_key) $('#ai-tavily-key').placeholder = 'Current: ' + data.tavily_api_key + ' - paste a new key to replace';
      const setBadge = (el, set) => { el.textContent = set ? 'set' : 'not set'; el.className = 'badge ' + (set ? 'badge-advisory' : 'badge-breach'); };
      setBadge($('#ai-groq-status'), data.groq_set);
      setBadge($('#ai-tavily-status'), data.tavily_set);
      if (data.model) $('#ai-model').textContent = data.model;
    } catch (e) { /* non-fatal */ }
  }

  async function saveAiSettings() {
    const groq = $('#ai-groq-key').value;
    const tavily = $('#ai-tavily-key').value;
    if (!groq && !tavily) { showToast('Enter at least one key to save', 'error'); return; }
    const btn = $('#ai-save-btn');
    btn.disabled = true; btn.textContent = 'Saving...';
    try {
      // Only send fields that were filled in: a blank box means "keep", not "delete"
      const body = {};
      if (groq.trim()) body.groq_api_key = groq.trim();
      if (tavily.trim()) body.tavily_api_key = tavily.trim();
      const result = await api('PUT', d('L2FwaS9hZG1pbi9haS1zZXR0aW5ncw=='), body);
      if (result && result.success) {
        $('#ai-groq-key').value = '';
        $('#ai-tavily-key').value = '';
        showToast('AI settings saved. AI features are live.', 'success');
        loadAiSettings();
      } else {
        showToast(result?.error || 'Save failed', 'error');
      }
    } catch (e) {
      showToast(e.message || 'Save failed', 'error');
    }
    btn.disabled = false; btn.textContent = 'Save AI Settings';
  }

  // Event listeners
  document.addEventListener('click', async (e) => {
    const toggleBtn = e.target.closest('[data-toggle-user]');
    if (toggleBtn) {
      const id = parseInt(toggleBtn.dataset.toggleUser);
      const isActive = toggleBtn.dataset.active === '1';
      const result = await api('PUT', `${d('L2FwaS9hZG1pbi91c2Vycw==')}/${id}`, { is_active: isActive ? 0 : 1 });
      if (result && result.success) showToast(`User ${isActive ? 'disabled' : 'enabled'}.`, 'success');
      else showToast(result?.error || 'Failed to update user', 'error');
      loadUsers();
    }

    const deleteBtn = e.target.closest('[data-delete-user]');
    if (deleteBtn) {
      const id = parseInt(deleteBtn.dataset.deleteUser);
      if (confirm('Are you sure you want to delete this user and ALL their data?')) {
        const result = await api('DELETE', `${d('L2FwaS9hZG1pbi91c2Vycw==')}/${id}`);
        if (result && result.success) {
          showToast('User deleted.', 'success');
          loadUsers(); loadStats();
        } else {
          showToast(result?.error || 'Failed', 'error');
        }
      }
    }

    // Copy invite code on click
    const copyCode = e.target.closest('.copy-code');
    if (copyCode) {
      copyText(copyCode.dataset.copy).then(() => {
        const original = copyCode.textContent;
        copyCode.textContent = 'Copied!';
        copyCode.style.color = 'var(--green)';
        setTimeout(() => { copyCode.textContent = original; copyCode.style.color = 'var(--cyan)'; }, 1500);
        showToast('Copied to clipboard', 'success');
      }).catch(() => showToast('Could not copy — select and copy manually', 'error'));
    }
  });

  document.addEventListener('change', async (e) => {
    const roleSelect = e.target.closest('[data-user-role]');
    if (roleSelect) {
      const id = parseInt(roleSelect.dataset.userRole);
      const result = await api('PUT', `${d('L2FwaS9hZG1pbi91c2Vycw==')}/${id}`, { role: roleSelect.value });
      if (result && result.success) {
        showToast('Role updated.', 'success');
      } else {
        showToast(result?.error || 'Failed to update role', 'error');
        loadUsers(); // revert the select to the real role
      }
    }

    const groupCheckbox = e.target.closest('.group-select-all');
    if (groupCheckbox) {
      const table = groupCheckbox.closest('table');
      table.querySelectorAll('.source-checkbox').forEach(cb => cb.checked = groupCheckbox.checked);
      updateBulkActions();
    }

    if (e.target.classList.contains('source-checkbox')) {
      updateBulkActions();
    }
  });

  $('#generate-invite-btn').addEventListener('click', async () => {
    const result = await api('POST', d('L2FwaS9hZG1pbi9pbnZpdGUtY29kZXM='));
    if (result && result.success) {
      showToast(`Invite code: ${result.code}`, 'success');
      loadInvites();
    } else {
      showToast(result?.error || 'Failed to create invite code', 'error');
    }
  });

  $('#ai-save-btn').addEventListener('click', saveAiSettings);
  $$('[data-catalog-filter]').forEach((btn) => btn.addEventListener('click', () => {
    $$('[data-catalog-filter]').forEach((b) => b.classList.remove('active'));
    btn.classList.add('active');
    catalogFilter = btn.dataset.catalogFilter;
    renderCatalog();
  }));
  $('#catalog-search')?.addEventListener('input', renderCatalog);
  $('#email-test-btn').addEventListener('click', sendTestEmail);
  $('#email-refresh-btn').addEventListener('click', loadEmailStatus);
  $('#refresh-resets-btn').addEventListener('click', loadResets);

  $('#admin-logout-btn').addEventListener('click', async () => {
    try {
      const csrf = getCsrfToken();
      await fetch(d('L2FwaS9hdXRoL2xvZ291dA=='), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-CSRF-Token': csrf || '' }
      });
    } catch (e) {}
    window.location.href = '/';
  });

  // Bulk action helpers
  function updateBulkActions() {
    const checked = document.querySelectorAll('.source-checkbox:checked');
    const bar = $('#sources-bulk-actions');
    if (checked.length > 0) {
      bar.classList.remove('hidden');
      $('#selected-count').textContent = checked.length + ' selected';
    } else {
      bar.classList.add('hidden');
    }
  }

  $('#bulk-edit-btn').addEventListener('click', async () => {
    const checked = document.querySelectorAll('.source-checkbox:checked');
    if (checked.length === 0) return;
    if (checked.length === 1) {
      const cb = checked[0];
      const newUrl = prompt(`Edit URL for "${cb.dataset.sourceName}":`, cb.dataset.sourceUrl);
      if (newUrl && newUrl.trim() !== cb.dataset.sourceUrl) {
        const result = await api('PUT', `${d('L2FwaS9zb3VyY2Vz')}/${cb.dataset.sourceId}`, { url: newUrl.trim() });
        if (result && result.success) showToast('Source updated.', 'success');
        else showToast(result?.error || 'Failed to update source', 'error');
        loadSources(); loadCatalog();
      }
    } else {
      showToast('Select only one source to edit URL.', 'error');
    }
  });

  $('#bulk-delete-btn').addEventListener('click', async () => {
    const checked = document.querySelectorAll('.source-checkbox:checked');
    if (checked.length === 0) return;
    if (confirm(`Delete ${checked.length} selected source(s)?`)) {
      let ok = 0, lastErr = '';
      for (const cb of checked) {
        const result = await api('DELETE', `${d('L2FwaS9zb3VyY2Vz')}/${cb.dataset.sourceId}`);
        if (result && result.success) ok++; else lastErr = result?.error || 'failed';
      }
      if (ok) showToast(`${ok} source(s) deleted.`, 'success');
      if (ok < checked.length) showToast(`${checked.length - ok} source(s) not deleted: ${lastErr}`, 'error');
      $('#sources-bulk-actions').classList.add('hidden');
      loadSources(); loadCatalog(); loadStats();
    }
  });

  $('#clear-selection-btn').addEventListener('click', () => {
    document.querySelectorAll('.source-checkbox, .group-select-all').forEach(cb => cb.checked = false);
    updateBulkActions();
  });

  // Theme toggle
  (function initTheme() {
    const btn = $('#theme-toggle');
    const apply = (t) => {
      document.documentElement.setAttribute('data-theme', t);
      try { localStorage.setItem('tp_theme', t); } catch (e) {}
      if (btn) btn.innerHTML = t === 'light'
        ? '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M6.3 17.7l-1.4 1.4M19.1 4.9l-1.4 1.4"/></svg>'
        : '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z"/></svg>';
    };
    apply(localStorage.getItem('tp_theme') || 'dark');
    if (btn) btn.addEventListener('click', () => {
      const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
      apply(cur === 'light' ? 'dark' : 'light');
    });
  })();

  // Init — starts async auth check, then loads panels
  init();
})();

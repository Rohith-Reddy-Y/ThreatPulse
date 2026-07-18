/**
 * ThreatPulse v2 — Admin Panel Logic
 */
'use strict';
(function() {
  const token = localStorage.getItem('tp_token');
  const user = JSON.parse(localStorage.getItem('tp_user') || 'null');

  if (!token || !user || user.role !== 'admin') {
    alert('Admin access required. Redirecting...');
    window.location.href = '/';
    return;
  }

  const $ = (sel) => document.querySelector(sel);
  const $$ = (sel) => document.querySelectorAll(sel);

  async function api(method, endpoint, body = null) {
    const opts = { method, headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${token}` } };
    if (body) opts.body = JSON.stringify(body);
    const res = await fetch(endpoint, opts);
    if (res.status === 401 || res.status === 403) { window.location.href = '/'; return; }
    return res.json();
  }

  function escapeHtml(str) {
    if (!str) return '';
    const d = document.createElement('div'); d.textContent = str; return d.innerHTML;
  }

  function relativeTime(dateStr) {
    if (!dateStr) return 'Never';
    const diff = Math.floor((Date.now() - new Date(dateStr)) / 1000);
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
    const stats = await api('GET', '/api/admin/stats');
    if (!stats) return;
    $('#admin-total-users').textContent = stats.totalUsers || 0;
    $('#admin-total-sources').textContent = stats.totalSourcesAll || 0;
    $('#admin-total-articles').textContent = stats.totalArticles || 0;
    $('#admin-errors-today').textContent = stats.errorsToday || 0;
  }

  // Users
  async function loadUsers() {
    const data = await api('GET', '/api/admin/users');
    if (!data || !data.users) return;
    const tbody = $('#users-tbody');
    tbody.innerHTML = data.users.map(u => `
      <tr>
        <td><strong>${escapeHtml(u.username)}</strong></td>
        <td>${escapeHtml(u.display_name)}</td>
        <td><select data-user-role="${u.id}" class="filter-select" style="padding:4px 8px;font-size:12px;">
          <option value="analyst" ${u.role==='analyst'?'selected':''}>Analyst</option>
          <option value="admin" ${u.role==='admin'?'selected':''}>Admin</option>
        </select></td>
        <td>${u.source_count || 0}</td>
        <td>${relativeTime(u.last_login)}</td>
        <td><span class="badge ${u.is_active ? 'badge-advisory' : 'badge-breach'}">${u.is_active ? 'Active' : 'Disabled'}</span></td>
        <td>
          <button class="btn btn-ghost" data-toggle-user="${u.id}" data-active="${u.is_active}" style="font-size:12px;padding:4px 8px;">${u.is_active ? 'Disable' : 'Enable'}</button>
          <button class="btn btn-danger" data-delete-user="${u.id}" style="font-size:12px;padding:4px 8px;">Delete</button>
        </td>
      </tr>
    `).join('');
  }

  // Invite codes
  async function loadInvites() {
    const data = await api('GET', '/api/admin/invite-codes');
    if (!data || !data.codes) return;
    const tbody = $('#invites-tbody');
    tbody.innerHTML = data.codes.map(c => `
      <tr>
        <td><code class="copy-code" data-copy="${escapeHtml(c.code)}" style="color:var(--cyan);font-family:var(--font-mono);font-size:14px;cursor:pointer;" title="Click to copy">${escapeHtml(c.code)} 📋</code></td>
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
    if (s.last_error) return { cls: 'error', label: '⚠️ Error' };
    if (s.last_fetched) return { cls: 'active', label: '✓ OK' };
    return { cls: 'idle', label: '○ Not yet fetched' };
  }

  // Sources — one section per user (including users with zero sources)
  async function loadSources() {
    const [srcData, userData] = await Promise.all([
      api('GET', '/api/admin/sources'),
      api('GET', '/api/admin/users')
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
        <h4 style="color:var(--cyan);margin:16px 0 8px;font-size:14px;">👤 ${escapeHtml(g.name)} <span style="color:var(--text-muted);font-size:12px;">(${sources.length} source${sources.length === 1 ? '' : 's'})</span>${errBadge}</h4>`;
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

  // Audit log
  async function loadAudit() {
    const data = await api('GET', '/api/admin/audit-log');
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

  // Event listeners
  document.addEventListener('click', async (e) => {
    const toggleBtn = e.target.closest('[data-toggle-user]');
    if (toggleBtn) {
      const id = parseInt(toggleBtn.dataset.toggleUser);
      const isActive = toggleBtn.dataset.active === '1';
      await api('PUT', `/api/admin/users/${id}`, { is_active: isActive ? 0 : 1 });
      showToast(`User ${isActive ? 'disabled' : 'enabled'}.`, 'success');
      loadUsers();
    }

    const deleteBtn = e.target.closest('[data-delete-user]');
    if (deleteBtn) {
      const id = parseInt(deleteBtn.dataset.deleteUser);
      if (confirm('Are you sure you want to delete this user and ALL their data?')) {
        const result = await api('DELETE', `/api/admin/users/${id}`);
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
        copyCode.textContent = '✅ Copied!';
        copyCode.style.color = 'var(--green)';
        setTimeout(() => { copyCode.textContent = original; copyCode.style.color = 'var(--cyan)'; }, 1500);
        showToast('Invite code copied to clipboard', 'success');
      }).catch(() => showToast('Could not copy — select and copy manually', 'error'));
    }
  });

  document.addEventListener('change', async (e) => {
    const roleSelect = e.target.closest('[data-user-role]');
    if (roleSelect) {
      const id = parseInt(roleSelect.dataset.userRole);
      await api('PUT', `/api/admin/users/${id}`, { role: roleSelect.value });
      showToast('Role updated.', 'success');
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
    const result = await api('POST', '/api/admin/invite-codes');
    if (result && result.success) {
      showToast(`Invite code: ${result.code}`, 'success');
      loadInvites();
    }
  });

  $('#admin-logout-btn').addEventListener('click', () => {
    localStorage.removeItem('tp_token');
    localStorage.removeItem('tp_user');
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
        await api('PUT', `/api/sources/${cb.dataset.sourceId}`, { url: newUrl.trim() });
        showToast('Source updated.', 'success');
        loadSources();
      }
    } else {
      showToast('Select only one source to edit URL.', 'error');
    }
  });

  $('#bulk-delete-btn').addEventListener('click', async () => {
    const checked = document.querySelectorAll('.source-checkbox:checked');
    if (checked.length === 0) return;
    if (confirm(`Delete ${checked.length} selected source(s)?`)) {
      for (const cb of checked) {
        await api('DELETE', `/api/sources/${cb.dataset.sourceId}`);
      }
      showToast(`${checked.length} source(s) deleted.`, 'success');
      loadSources(); loadStats();
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
      if (btn) btn.textContent = t === 'light' ? '☀️' : '🌙';
    };
    apply(localStorage.getItem('tp_theme') || 'dark');
    if (btn) btn.addEventListener('click', () => {
      const cur = document.documentElement.getAttribute('data-theme') === 'light' ? 'light' : 'dark';
      apply(cur === 'light' ? 'dark' : 'light');
    });
  })();

  // Init
  loadStats();
  loadUsers();
  loadInvites();
  loadSources();
  loadAudit();
})();

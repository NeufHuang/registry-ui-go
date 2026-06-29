// User management functions
async function loadUsers() {
  try {
    const {data} = await api('/api/admin/users');
    const userList = el('userList');
    if (!data.users || data.users.length === 0) {
      userList.innerHTML = `<div class="hint">${t('noUsers')}</div>`;
      return;
    }
    let html = '';
    const currentUserId = (state.user && state.user.id) || 0;
    for (const user of data.users) {
      // Enable/disable toggle, styled like a badge (green when enabled,
      // grey when disabled) but sized like the perms button. Shown for
      // all users including admins; the backend still guards against
      // disabling the last admin / yourself.
      const statusBtn = user.enabled
        ? `<button class="ghost status-btn ok toggle-user-enabled" data-user-id="${user.id}" data-username="${esc(user.username)}" data-enabled="true" type="button" title="${esc(t('disableUserConfirm', {name: user.username}))}">${t('enabled')}</button>`
        : `<button class="ghost status-btn muted toggle-user-enabled" data-user-id="${user.id}" data-username="${esc(user.username)}" data-enabled="false" type="button" title="${esc(t('enableUserConfirm', {name: user.username}))}">${t('disabled')}</button>`;
      const adminBadge = user.isAdmin ? `<span class="badge info">${t('admin')}</span>` : '';
      // Admins already have all-namespace access; the permissions panel
      // is not useful for them.
      const permsBtn = user.isAdmin ? '' : `<button class="ghost edit-user-perms" data-user-id="${user.id}" type="button">${t('permissions')}</button>`;
      // An admin cannot delete their own account (would lock themselves
      // out of the UI). The backend also rejects this; we hide the
      // button so the constraint is obvious.
      const deleteBtn = user.id === currentUserId ? '' : `<button class="ghost danger delete-user" data-user-id="${user.id}" data-username="${esc(user.username)}" type="button">${t('deleteUser')}</button>`;
      html += `
        <div class="user-card" data-user-id="${user.id}">
          <div class="user-header">
            <div>
              <strong>${esc(user.username)}</strong> ${adminBadge}
            </div>
            <div>
              ${permsBtn}
              ${statusBtn}
              ${deleteBtn}
            </div>
          </div>
          <div class="permissions-panel" id="permissions-${user.id}" style="display:none;"></div>
        </div>
      `;
    }
    userList.innerHTML = html;
    // Bind events
    document.querySelectorAll('.toggle-user-enabled').forEach(btn => {
      btn.onclick = async () => await toggleUserEnabled(btn.dataset.userId, btn.dataset.username, btn.dataset.enabled === 'true');
    });
    document.querySelectorAll('.edit-user-perms').forEach(btn => {
      btn.onclick = async () => await toggleUserPermissions(btn.dataset.userId);
    });
    document.querySelectorAll('.delete-user').forEach(btn => {
      btn.onclick = async () => await deleteUser(btn.dataset.userId, btn.dataset.username);
    });
  } catch (err) {
    el('userList').innerHTML = `<div class="hint error">${esc(err.message)}</div>`;
  }
}

async function fetchAllNamespaces() {
  let names = [];
  try {
    const {data} = await api('/api/namespaces');
    names = (data.namespaces || []).map(n => n.name);
  } catch {}
  const catalogNs = [...new Set(state.repos.map(namespaceOf))].filter(n => n && n !== t('root'));
  return [...new Set([...names, ...catalogNs])].sort();
}

function buildMultiSelect(opts) {
  const {label, items, selected, disabled, onToggle} = opts;
  const wrap = document.createElement('div');
  wrap.className = 'multi-select';
  const btn = document.createElement('button');
  btn.type = 'button';
  btn.className = 'ms-btn';
  const refreshBtn = () => {
    const n = [...selected].filter(v => items.includes(v)).length;
    btn.textContent = n > 0 ? `${label} (${n})` : label;
  };
  refreshBtn();
  const panel = document.createElement('div');
  panel.className = 'ms-panel hidden';
  const search = document.createElement('input');
  search.type = 'text';
  search.className = 'ms-search';
  search.placeholder = t('searchNamespaces');
  const list = document.createElement('div');
  list.className = 'ms-list';
  const render = (filter) => {
    list.innerHTML = '';
    const f = (filter || '').toLowerCase();
    const shown = items.filter(it => it.toLowerCase().includes(f));
    if (shown.length === 0) {
      const empty = document.createElement('div');
      empty.className = 'ms-empty';
      empty.textContent = t('noNamespaces');
      list.appendChild(empty);
      return;
    }
    for (const it of shown) {
      const row = document.createElement('label');
      row.className = 'ms-item';
      const cb = document.createElement('input');
      cb.type = 'checkbox';
      cb.checked = selected.has(it);
      cb.disabled = disabled.has(it);
      cb.onchange = async () => {
        cb.disabled = true;
        try { await onToggle(it, cb.checked); }
        catch (e) { toast(e.message, true); cb.checked = !cb.checked; }
        finally { cb.disabled = disabled.has(it); }
        refreshBtn();
      };
      row.appendChild(cb);
      const span = document.createElement('span');
      span.textContent = it;
      row.appendChild(span);
      list.appendChild(row);
    }
  };
  render();
  search.oninput = () => render(search.value);
  btn.onclick = () => {
    panel.classList.toggle('hidden');
    if (!panel.classList.contains('hidden')) { search.value = ''; render(); search.focus(); }
  };
  panel.appendChild(search);
  panel.appendChild(list);
  wrap.appendChild(btn);
  wrap.appendChild(panel);
  wrap._refresh = refreshBtn;
  wrap._render = render;
  return wrap;
}

async function toggleUserPermissions(userId) {
  const panel = el(`permissions-${userId}`);
  const isVisible = panel.style.display !== 'none';
  if (isVisible) {
    panel.style.display = 'none';
    return;
  }
  panel.style.display = 'block';
  panel.innerHTML = `<div class="hint">${t('loading')}</div>`;

  const allNs = await fetchAllNamespaces();
  const {data} = await api(`/api/admin/users/${userId}/permissions`);
  const readSet = new Set();
  const writeSet = new Set();
  for (const p of (data.permissions || [])) {
    if (p.canRead) readSet.add(p.namespacePattern);
    if (p.canWrite) writeSet.add(p.namespacePattern);
  }

  let readMs, writeMs;
  const setPerm = (pattern, canRead, canWrite) => api(`/api/admin/users/${userId}/permissions`, {
    method: 'POST', body: JSON.stringify({patterns: [pattern], canRead, canWrite})
  });
  const delPerm = (pattern) => api(`/api/admin/users/${userId}/permissions`, {
    method: 'DELETE', body: JSON.stringify({namespacePattern: pattern})
  });

  const onReadToggle = async (ns, checked) => {
    if (writeSet.has(ns)) return;
    if (checked) { await setPerm(ns, true, false); readSet.add(ns); }
    else { await delPerm(ns); readSet.delete(ns); }
    toast(t('saved'));
  };
  const onWriteToggle = async (ns, checked) => {
    if (checked) { await setPerm(ns, true, true); writeSet.add(ns); readSet.add(ns); }
    else { await setPerm(ns, true, false); writeSet.delete(ns); readSet.add(ns); }
    if (readMs) { readMs._render(); readMs._refresh(); }
    toast(t('saved'));
  };

  panel.innerHTML = '';
  const cols = document.createElement('div');
  cols.className = 'perm-columns';
  const readCol = document.createElement('div');
  readCol.className = 'perm-col';
  const readLbl = document.createElement('div');
  readLbl.className = 'perm-col-label';
  readLbl.textContent = t('readAccess');
  readMs = buildMultiSelect({label: t('selectNamespaces'), items: allNs, selected: readSet, disabled: writeSet, onToggle: onReadToggle});
  readCol.appendChild(readLbl);
  readCol.appendChild(readMs);
  const writeCol = document.createElement('div');
  writeCol.className = 'perm-col';
  const writeLbl = document.createElement('div');
  writeLbl.className = 'perm-col-label';
  writeLbl.textContent = t('writeAccess');
  writeMs = buildMultiSelect({label: t('selectNamespaces'), items: allNs, selected: writeSet, disabled: new Set(), onToggle: onWriteToggle});
  writeCol.appendChild(writeLbl);
  writeCol.appendChild(writeMs);
  cols.appendChild(readCol);
  cols.appendChild(writeCol);
  panel.appendChild(cols);
}

async function toggleUserEnabled(userId, username, currentlyEnabled) {
  // The confirm dialog mirrors the delete-user pattern but uses a
  // friendlier copy ("Disable" / "Re-enable") appropriate to the
  // reversible nature of the operation.
  const actionKey = currentlyEnabled ? 'disableUserConfirm' : 'enableUserConfirm';
  const submitKey = currentlyEnabled ? 'disabled' : 'enabled';
  const ok = await openFormDialog({
    title: t('userManagement'),
    message: t(actionKey, {name: username}),
    submitLabel: t(submitKey),
    submit: async () => {
      try {
        const path = currentlyEnabled ? 'disable' : 'enable';
        await api(`/api/admin/users/${userId}/${path}`, {method: 'POST'});
        toast(currentlyEnabled ? t('userDisabled') : t('userEnabled'));
        await loadUsers();
        return {ok: true};
      } catch (e) { return {ok: false, error: e.message}; }
    },
  });
}

async function deleteUser(userId, username) {
  const ok = await openFormDialog({
    title: t('deleteUser'),
    message: t('confirmDeleteUser', {name: username}),
    submitLabel: t('delete'),
    danger: true,
    submit: async () => {
      try {
        await api(`/api/admin/users/${userId}`, {method: 'DELETE'});
        toast(t('userDeleted')); await loadUsers();
        return {ok: true};
      } catch (e) { return {ok: false, error: e.message}; }
    },
  });
}

async function showAddUserDialog() {
  const ok = await openFormDialog({
    title: t('addUser'),
    fields: [
      {key: 'username', label: t('username'), placeholder: 'alice', autocomplete: 'username'},
      {key: 'password', label: t('password'), type: 'password', placeholder: '••••••', autocomplete: 'new-password'},
      {key: 'isAdmin', label: t('admin'), type: 'checkbox', value: false},
    ],
    submitLabel: t('save'),
    submit: async (v) => {
      const username = (v.username || '').trim();
      const password = v.password || '';
      if (!username) return {ok: false, error: 'username required'};
      if (password.length < 6) return {ok: false, error: t('passwordMinLength')};
      try {
        await api('/api/admin/users', {method:'POST', body: JSON.stringify({username, password, isAdmin: !!v.isAdmin, enabled: true})});
        toast(t('userCreated'));
        await loadUsers();
        return {ok: true};
      } catch (e) { return {ok: false, error: e.message}; }
    },
  });
}

el('refreshUsersBtn').onclick = async (e) => {
  e.preventDefault();
  e.stopPropagation();
  await loadUsers();
};
el('addUserBtn').onclick = async () => await showAddUserDialog();

// ---- Immutable Tag Rules ----

async function loadImmutableRules() {
  try {
    const {data} = await api('/api/admin/immutable-rules');
    const list = el('immutableRuleList');
    list.innerHTML = (data.rules || []).map(r =>
      `<div class="compact-card"><div class="cc-text"><strong>${esc(r.pattern)}</strong><small>${esc(r.description||'')}</small></div><button class="ghost danger del-immutable-rule" data-id="${r.id}" type="button">×</button></div>`
    ).join('') || `<div class="hint">${t('noRules')}</div>`;
    list.querySelectorAll('.del-immutable-rule').forEach(b => b.onclick = async () => {
      await api(`/api/admin/immutable-rules/${b.dataset.id}`, {method:'DELETE'});
      toast(t('saved')); await loadImmutableRules();
    });
  } catch(e) { el('immutableRuleList').innerHTML = `<div class="hint error">${esc(e.message)}</div>`; }
}

async function showAddImmutableRuleDialog() {
  const ok = await openFormDialog({
    title: t('addRule'),
    fields: [
      {key: 'pattern', label: t('rulePattern'), placeholder: 'release-*'},
      {key: 'description', label: t('ruleDescription'), placeholder: ''},
    ],
    submitLabel: t('save'),
    submit: async (v) => {
      const pattern = (v.pattern || '').trim();
      if (!pattern) return {ok: false, error: 'pattern required'};
      try {
        await api('/api/admin/immutable-rules', {method:'POST', body: JSON.stringify({pattern, description: v.description || ''})});
        toast(t('saved')); await loadImmutableRules();
        return {ok: true};
      } catch (e) { return {ok: false, error: e.message}; }
    },
  });
}

// ---- API Tokens ----

async function loadTokens() {
  try {
    const {data} = await api('/api/admin/tokens');
    const list = el('tokenList');
    list.innerHTML = (data.tokens || []).map(t =>
      `<div class="compact-card"><div class="cc-text"><strong>${esc(t.name)}</strong><small>${esc(t.description||'')} · prefix: ${esc(t.tokenPrefix)}${t.expiresAt ? ' · expires: '+esc(t.expiresAt) : ''}</small></div><button class="ghost danger del-token" data-id="${t.id}" type="button">×</button></div>`
    ).join('') || `<div class="hint">-</div>`;
    list.querySelectorAll('.del-token').forEach(b => b.onclick = async () => {
      await api(`/api/admin/tokens/${b.dataset.id}`, {method:'DELETE'});
      toast(t('tokenRevoked')); await loadTokens();
    });
  } catch(e) { el('tokenList').innerHTML = `<div class="hint error">${esc(e.message)}</div>`; }
}

async function showCreateTokenDialog() {
  const ok = await openFormDialog({
    title: t('createToken'),
    fields: [
      {key: 'name', label: t('tokenName'), placeholder: 'ci-deploy'},
      {key: 'expiresIn', label: t('tokenExpiresIn'), type: 'number', value: 0, min: 0},
    ],
    submitLabel: t('save'),
    submit: async (v) => {
      const name = (v.name || '').trim();
      if (!name) return {ok: false, error: 'name required'};
      const expiresIn = v.expiresIn == null ? 0 : Number(v.expiresIn) || 0;
      try {
        const {data} = await api('/api/admin/tokens', {method:'POST', body: JSON.stringify({name, description: '', expiresIn})});
        await loadTokens();
        return {ok: true, keepOpen: true, resultHtml: `<strong>${esc(t('tokenCreated'))}</strong><pre>${esc(data.fullToken)}</pre>`};
      } catch (e) { return {ok: false, error: e.message}; }
    },
  });
}

// ---- Webhooks ----

async function loadWebhooks() {
  try {
    const {data} = await api('/api/admin/webhooks');
    const list = el('webhookList');
    list.innerHTML = (data.webhooks || []).map(w =>
      `<div class="compact-card"><div class="cc-text"><strong>${esc(w.url)}</strong><small>events: ${esc(w.events)} · ${w.enabled ? 'enabled' : 'disabled'}</small></div><button class="ghost danger del-webhook" data-id="${w.id}" type="button">×</button></div>`
    ).join('') || `<div class="hint">-</div>`;
    list.querySelectorAll('.del-webhook').forEach(b => b.onclick = async () => {
      await api(`/api/admin/webhooks/${b.dataset.id}`, {method:'DELETE'});
      toast(t('saved')); await loadWebhooks();
    });
  } catch(e) { el('webhookList').innerHTML = `<div class="hint error">${esc(e.message)}</div>`; }
}

async function showAddWebhookDialog() {
  const ok = await openFormDialog({
    title: t('addWebhook'),
    fields: [
      {key: 'url', label: t('webhookUrl'), placeholder: 'https://example.com/hook'},
      {key: 'secretHeader', label: t('webhookSecret'), placeholder: 'X-Hub-Signature:secret'},
      {key: 'events', label: t('webhookEvents'), placeholder: 'push,delete,untag,restore', value: 'push,delete,untag,restore'},
    ],
    submitLabel: t('save'),
    submit: async (v) => {
      const url = (v.url || '').trim();
      if (!url) return {ok: false, error: 'url required'};
      try {
        await api('/api/admin/webhooks', {method:'POST', body: JSON.stringify({url, secretHeader: v.secretHeader || '', events: v.events || 'push,delete,untag,restore', enabled: true})});
        toast(t('saved')); await loadWebhooks();
        return {ok: true};
      } catch (e) { return {ok: false, error: e.message}; }
    },
  });
}

// ---- Repo Stats ----

async function loadStats() {
  try {
    const {data} = await api('/api/repo-stats');
    const list = el('statsList');
    const stats = data.stats || [];
    list.innerHTML = stats.length ? stats.map(s =>
      `<div class="mini"><b>${esc(s.repo)}</b><small>${t('pullCount')}: ${s.pullCount} · ${t('pushCount')}: ${s.pushCount}${s.lastPullAt ? ' · '+t('lastAccess')+': '+esc(s.lastPullAt) : ''}</small></div>`
    ).join('') : `<div class="hint">-</div>`;
  } catch(e) { el('statsList').innerHTML = `<div class="hint error">${esc(e.message)}</div>`; }
}

// ---- Export ----

el('exportBtn').onclick = async () => {
  const ok = await openFormDialog({
    title: t('exportTitle'),
    fields: [{
      key: 'fmt', label: t('exportFormatLabel'), type: 'radio', value: 'json',
      options: [{value: 'json', label: t('exportJSON')}, {value: 'csv', label: t('exportCSV')}],
    }],
    submitLabel: t('ok'),
    submit: async (v) => {
      const fmt = v.fmt === 'csv' ? 'csv' : 'json';
      const url = `/api/export?format=${fmt}`;
      try {
        if (fmt === 'csv') { window.open(url, '_blank'); return {ok: true}; }
        const {data} = await api(url);
        const blob = new Blob([JSON.stringify(data, null, 2)], {type:'application/json'});
        const a = document.createElement('a'); a.href = URL.createObjectURL(blob); a.download = `registry-export-${Date.now()}.json`; a.click();
        URL.revokeObjectURL(a.href);
        return {ok: true};
      } catch (e) { return {ok: false, error: e.message}; }
    },
  });
};

// ---- Repo Description ----

async function loadRepoDescription(repo) {
  if (!repo) { el('repoDescription').style.display = 'none'; return; }
  try {
    const {data} = await api(`/api/repo-description/${encodeRepo(repo)}/description`);
    const desc = data?.description || '';
    if (desc) {
      el('repoDescText').innerHTML = simpleMarkdown(desc);
      el('repoDescription').style.display = 'flex';
    } else {
      el('repoDescription').style.display = 'none';
    }
  } catch { el('repoDescription').style.display = 'none'; }
}

function simpleMarkdown(text) {
  return esc(text).replace(/\n\n/g, '</p><p>').replace(/\n/g, '<br>').replace(/`([^`]+)`/g, '<code>$1</code>').replace(/\*\*(.+?)\*\*/g, '<b>$1</b>').replace(/\*(.+?)\*/g, '<i>$1</i>');
}

async function saveRepoDescription() {
  if (!state.selectedRepo) return;
  const desc = el('repoDescInput').value;
  await api(`/api/repo-description/${encodeRepo(state.selectedRepo)}/description`, {method:'PUT', body:JSON.stringify({description: desc})});
  toast(t('descriptionSaved'));
  el('repoDescriptionEdit').style.display = 'none';
  el('repoDescription').style.display = desc ? 'flex' : 'none';
  if (desc) el('repoDescText').innerHTML = simpleMarkdown(desc);
}

async function showRepoDescriptionEdit() {
  if (!state.selectedRepo) return;
  try {
    const {data} = await api(`/api/repo-description/${encodeRepo(state.selectedRepo)}/description`);
    el('repoDescInput').value = data?.description || '';
  } catch { el('repoDescInput').value = ''; }
  el('repoDescription').style.display = 'none';
  el('repoDescriptionEdit').style.display = 'block';
}

// ---- Event Bindings ----

el('addImmutableRuleBtn').onclick = () => showAddImmutableRuleDialog();
el('addTokenBtn').onclick = () => showCreateTokenDialog();
el('addWebhookBtn').onclick = () => showAddWebhookDialog();
el('repoStatsDetails')?.addEventListener('toggle', (e) => { if (e.target.open) loadStats(); });
const _edb = el('editRepoDescBtn'); if (_edb) _edb.onclick = () => showRepoDescriptionEdit();
const _sdb = el('saveRepoDescBtn'); if (_sdb) _sdb.onclick = () => saveRepoDescription();
const _cdb = el('cancelRepoDescBtn'); if (_cdb) _cdb.onclick = () => { el('repoDescriptionEdit').style.display = 'none'; loadRepoDescription(state.selectedRepo); };

// Expose to global scope for inline onclick handlers in HTML
window.closeModal = closeModal;
window.showModal = showModal;

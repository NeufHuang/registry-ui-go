// The tag-policy dialog works on a single repository or on a batch of them —
// checking a namespace row in the tree selects every repo of that namespace, so
// the dialog applies one policy to all of them. The backend only exposes
// per-repository policy (there is no namespace-scoped endpoint), so a batch is
// a client-side loop of PUTs — the same pattern the batch delete already uses.
const tagPolicyScope = {repos: [], label: ''};

// Open the dialog for the given repositories. A single repo keeps the original
// behaviour (its own stats shown, one PUT). Multiple repos show the first
// repo's stats as a starting point and PUT the same values to each.
async function openTagPolicyDialog(repos) {
  if (!repos.length) { toast(t('noRepoSelected'), true); return; }
  tagPolicyScope.repos = repos;
  const ns = namespaceOf(repos[0]);
  tagPolicyScope.label = repos.length === 1 ? repos[0] : `${namespaceLabel(ns)} (${repos.length} 个仓库)`;
  el('tagSettingsRepoName').textContent = tagPolicyScope.label;
  try {
    const {data} = await api(`/api/repositories/${encodeRepo(repos[0])}/stats`);
    el('tagStatsTagCount').textContent = data.tagCount ?? '-';
    el('tagStatsSize').textContent = data.totalSize ? fmtBytes(data.totalSize) : '-';
    el('tagStatsPendingGC').textContent = (data.pendingGCCount || 0) + ' · ' + fmtBytes(data.pendingGCSize || 0);
    const mode = data.protectionMode || 'rules';
    const modeRadio = document.querySelector('input[name="protectionMode"][value="' + mode + '"]');
    if (modeRadio) modeRadio.checked = true;
    el('tagOverwriteActionRow').style.display = mode === 'overwrite' ? '' : 'none';
    const action = data.overwriteAction || 'recycle';
    document.querySelector('input[name="overwriteAction"][value="' + action + '"]').checked = true;
    el('tagSettingKeepCount').value = data.keepCount || 0;
    el('tagSettingAnonymousPull').checked = data.anonymousPull === true;
    el('tagSettingPushCreateRepo').checked = data.pushCreateRepo !== false;
  } catch(e) { toast(e.message, true); return; }
  showModal('tagSettingsModal');
}

el('tagSettingsBtn').onclick = async () => {
  // Prefer the checkbox selection (a namespace row checks every repo of that
  // namespace, a repo row checks just itself), then the repo whose row is
  // selected. Sorting keeps a namespace batch deterministic.
  const checked = [...state.selectedRepos].sort();
  if (checked.length > 0) { await openTagPolicyDialog(checked); return; }
  if (state.selectedRepo) { await openTagPolicyDialog([state.selectedRepo]); return; }
  toast(t('noRepoSelected'), true);
};
document.querySelectorAll('input[name="protectionMode"]').forEach(r => {
  r.addEventListener('change', function() {
    el('tagOverwriteActionRow').style.display = this.value === 'overwrite' ? '' : 'none';
  });
});

// Global tag policy defaults
async function loadGlobalTagPolicy() {
  const {data} = await api('/api/settings');
  const mode = data.protection_mode || 'rules';
  const modeRadio = document.querySelector('input[name="globalProtectionMode"][value="' + mode + '"]');
  if (modeRadio) modeRadio.checked = true;
}
document.querySelectorAll('input[name="globalProtectionMode"]').forEach(r => {
  r.addEventListener('change', function() {
    // overwrite_action only applies when overwrites are allowed at all.
    if (typeof syncGlobalOverwriteRow === 'function') syncGlobalOverwriteRow();
  });
});
el('tagSettingsCancelBtn').onclick = () => closeModal('tagSettingsModal');
el('tagSettingsSaveBtn').onclick = async (e) => {
  e.preventDefault();
  const body = JSON.stringify({
    protectionMode: document.querySelector('input[name="protectionMode"]:checked')?.value || 'rules',
    overwriteAction: document.querySelector('input[name="overwriteAction"]:checked')?.value || 'recycle',
    keepCount: parseInt(el('tagSettingKeepCount').value) || 0,
    anonymousPull: el('tagSettingAnonymousPull').checked,
    pushCreateRepo: el('tagSettingPushCreateRepo').checked,
  });
  // Skip repos the user cannot write to instead of aborting the whole batch;
  // the server would 403 them anyway and the toast below reports the real
  // outcome.
  const writable = tagPolicyScope.repos.filter(canWriteRepo);
  try {
    for (const repo of writable) {
      await api(`/api/repositories/${encodeRepo(repo)}/tag-policy`, {method:'PUT', body});
    }
    if (writable.length < tagPolicyScope.repos.length) {
      toast(`${t('saveOK')} (${writable.length}/${tagPolicyScope.repos.length})`, true);
    } else {
      toast(t('saveOK'));
    }
    closeModal('tagSettingsModal');
    if (state.selectedRepo) await checkRepoProtection(state.selectedRepo);
  } catch(e) { toast(e.message, true); }
};
el('retentionPreviewBtn').onclick = async () => {
  const keepCount = parseInt(el('tagSettingKeepCount').value) || 0;
  if (keepCount <= 0) { toast(t('retentionKeepCountHelp'), true); return; }
  const repo = state.selectedRepo;
  if (!repo) return;
  try {
    const {data} = await api(`/api/repositories/${encodeRepo(repo)}/retention-preview?keepCount=${keepCount}`);
    if (!data.candidates || data.candidates.length === 0) { toast(t('retentionNoCandidates')); return; }
    const list = data.candidates.map(c => {
      const tagList = (c.tags || []).join(', ');
      return `• ${c.digest.slice(0,19)}...  (${c.tags ? c.tags.length : 0} tags: ${tagList})`;
    }).join('\n');
    const ok = await openDeleteConfirm({
      title: t('retentionPreview'),
      message: t('retentionConfirm'),
      details: list + `\n\n${data.candidates.length} images`,
      expected: 'DELETE',
    });
    if (!ok) return;
    const {data: result} = await api(`/api/repositories/${encodeRepo(repo)}/retention-run`, {method:'POST', body:JSON.stringify({keepCount})});
    const success = (result.deleted || []).filter(r => r.ok).length;
    const failed = (result.deleted || []).filter(r => !r.ok).length;
    toast(t('retentionResult', {count: success}) + (failed > 0 ? `, ${failed} failed` : ''));
    await loadRepos(true);
  } catch(e) { toast(e.message, true); }
};
// The single refresh button reloads the repository list and, when a repo is
// selected, re-fetches its tags so the tree shows freshly pushed images.
el('refreshReposBtn').onclick = async () => {
  try {
    await loadRepos(true);
    if (state.selectedRepo && typeof refreshTreeTags === 'function') await refreshTreeTags();
  } catch(e) { toast(e.message, true); }
};
// One delete button for everything the tree can select: repositories (their
// checkboxes) and tags (their checkboxes). The tag selection wins when present,
// otherwise the repository selection decides what happens.
el('deleteSelectedBtn').onclick = async () => {
  // Tags take precedence: they are the more specific selection.
  if (state.selectedTags.size > 0) {
    try { await deleteTags([...state.selectedTags]); } catch(e) { toast(e.message, true); }
    return;
  }
  const all = [...state.selectedRepos];
  // Skip repos the user cannot write to instead of aborting the whole batch.
  const checked = all.filter(canWriteRepo);
  if (all.length > 0 && checked.length === 0) { toast(t('noPermission'), true); return; }
  if (checked.length > 0) {
    const ok = await openDeleteConfirm({
      title: t('deleteConfirmTitle'),
      message: t('deleteMultipleMessage'),
      details: checked.map(r => `- ${r}`).join('\n'),
      expected: 'DELETE',
    });
    if (ok !== 'DELETE') return;
    let total = 0;
    for (const repo of checked) {
      try {
        const {data} = await api(`/api/repositories/${encodeRepo(repo)}/tags`);
        const tags = data.tags || [];
        for (const tag of tags) {
          const d = await manifestDigestForTagRef(repo, tag);
          if (d) { await api(`/api/repositories/${encodeRepo(repo)}/manifests/${encodeURIComponent(d)}`, {method:'DELETE'}); total++; toast(`${t('delete')} ${total}...`, false, true); }
        }
      } catch(e) { /* skip */ }
    }
    toast(`${t('deleteSent')} (${total} digest)`);
    state.selectedRepos.clear(); updateRepoBulkBar();
    state.selectedRepo = ''; state.tags = []; state.selectedTags.clear(); el('selectedRepo').textContent = t('selectImage'); updateRepoActions(); await loadRepos(true);
  } else {
    // Nothing checkbox-selected: falling through to "delete the whole
    // namespace" made a single mis-click destroy every repo in it. Ask for
    // the explicit repo first and delete just that one.
    const repo = state.selectedRepo;
    if (!repo) { toast(t('noRepoSelected'), true); return; }
    if (!canWriteRepo(repo)) { toast(t('noPermission'), true); return; }
    const ok = await openDeleteConfirm({
      title: t('deleteConfirmTitle'),
      message: t('deleteRepoConfirm', {repo}),
      expected: repo,
    });
    if (ok !== repo) return;
    try {
      const {data} = await api(`/api/repositories/${encodeRepo(repo)}/tags`);
      let deleted = 0;
      for (const tag of (data.tags || [])) {
        const d = await manifestDigestForTagRef(repo, tag);
        if (d) { await api(`/api/repositories/${encodeRepo(repo)}/manifests/${encodeURIComponent(d)}`, {method:'DELETE'}); deleted++; toast(`${t('delete')} ${deleted}...`, false, true); }
      }
      toast(`${t('deleteSent')} (${deleted} digest)`);
    } catch(e) { toast(e.message, true); }
    state.selectedRepo = ''; state.tags = []; state.selectedTags.clear(); el('selectedRepo').textContent = t('selectImage'); updateRepoActions(); await loadRepos(true);
  }
};
// One "create" entry point replaces the former separate namespace / repo
// buttons. The kind is inferred from what the user types: "namespace/repo"
// creates the repository (and its namespace, since the server's resolveRepo ->
// UpsertNamespace does that automatically), a bare name creates an empty
// namespace. That removes the radio the user asked to drop, and keeps the
// common case one keystroke shorter.
function openCreateDialog() {
  const ns = state.selectedRepo ? namespaceOf(state.selectedRepo) : '';
  const prefill = ns && ns !== ROOT_NAMESPACE ? ns + '/' : '';
  return openFormDialog({
    title: t('create'),
    fields: [
      {key: 'name', label: t('createName'), placeholder: prefill ? prefill + 'myapp' : 'myteam/myapp', value: prefill, hint: t('createHint')},
    ],
    submitLabel: t('save'),
    submit: async (v) => {
      const name = (v.name || '').trim().replace(/^\/+/, '').replace(/\/+$/, '');
      if (!name) return {ok: false, error: t('createNameRequired')};
      // A name with a "/" is a repository reference; without one it declares a
      // namespace. The server accepts both shapes, so the split is purely a
      // client-side routing decision.
      if (name.includes('/')) {
        const nsOfNew = namespaceOf(name);
        if (nsOfNew === ROOT_NAMESPACE) return {ok: false, error: t('createRepoRootHint')};
        if (!canWriteNamespace(nsOfNew)) return {ok: false, error: t('noPermission')};
        try { await api(`/api/repositories/${encodeRepo(name)}/init`, {method: 'POST'}); toast(t('saveOK')); return {ok: true}; }
        catch (e) { return {ok: false, error: e.message}; }
      }
      // POST /api/namespaces is admin-only.
      if (!isAdminUser()) return {ok: false, error: t('createNamespaceAdminOnly')};
      try { await api('/api/namespaces', {method: 'POST', body: JSON.stringify({name})}); toast(t('saveOK')); return {ok: true}; }
      catch (e) { return {ok: false, error: e.message}; }
    },
  }).then((ok) => { if (ok) loadRepos(true); return ok; });
}

el('createBtn').onclick = async () => {
  // Both branches need write access somewhere: the repository branch needs it
  // on the target namespace, the namespace branch is admin-only. Block a user
  // who can do neither instead of showing a form that always fails.
  if (!isAdminUser()) {
    const ns = state.selectedRepo ? namespaceOf(state.selectedRepo) : '';
    if (!ns || ns === ROOT_NAMESPACE || !canWriteNamespace(ns)) { toast(t('noPermission'), true); return; }
  }
  await openCreateDialog();
};
// ⋮ dropdown toggles
['treeMoreBtn','manifestMoreBtn'].forEach(id => {
  const btn = el(id);
  if (btn) btn.onclick = (e) => { e.stopPropagation(); const dd = el(id.replace('Btn','Dropdown')); if (dd) { const show = dd.classList.contains('hidden-ui'); dd.classList.toggle('hidden-ui'); if (show) { const r = btn.getBoundingClientRect(); dd.style.top = (r.bottom + 8) + 'px'; dd.style.right = (window.innerWidth - r.right) + 'px'; } } };
});
document.addEventListener('click', () => { document.querySelectorAll('[id$=Dropdown]').forEach(d => d.classList.add('hidden-ui')); });
[].forEach.call(document.querySelectorAll('[id$=Dropdown]'), d => { d.addEventListener('click', e => e.stopPropagation()); });
el('repoSearch').oninput = renderTreeView;
el('favoriteBtn').onclick = async () => { try { await favoriteCurrent(); } catch(e) { toast(e.message, true); } };
el('recentRefreshBtn').onclick = e => { e.preventDefault(); e.stopPropagation(); loadRecent(); }; el('favoritesRefreshBtn').onclick = e => { e.preventDefault(); e.stopPropagation(); loadFavorites(); }; el('auditRefreshBtn').onclick = e => { e.preventDefault(); e.stopPropagation(); loadAudit(); }; el('recycleRefreshBtn').onclick = e => { e.preventDefault(); e.stopPropagation(); loadRecycle(); };
(async()=>{ try { await loadUser(); if (state.user && state.user.mustChangePassword) { showModal('profileModal'); toast(t('mustChangePassword'), true, true); return; } await loadSettings(); await checkHealth(); await loadRepos(true); await refreshSidebars(); } catch(e) { toast(e.message, true); } })();
// File upload button click handlers (moved from DOMContentLoaded for module script compatibility)
document.getElementById('settingLogoFileBtn')?.addEventListener('click', (e) => { e.preventDefault(); document.getElementById('settingLogoFile').click(); });
document.getElementById('profileAvatarFileBtn')?.addEventListener('click', (e) => { e.preventDefault(); document.getElementById('profileAvatarFile').click(); });

document.getElementById('settingLogoFile').addEventListener('change', function(e) {
  const btn = document.getElementById('settingLogoFileBtn');
  if (btn) btn.textContent = e.target.files?.[0]?.name || t('selectFile');
});
document.getElementById('profileAvatarFile').addEventListener('change', function(e) {
  const btn = document.getElementById('profileAvatarFileBtn');
  if (btn) btn.textContent = e.target.files?.[0]?.name || t('selectFile');
});


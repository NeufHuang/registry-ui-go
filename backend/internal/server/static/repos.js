async function loadRepos(reset=false) {
  if (reset) { state.repos = []; state.nextLast = ''; }
  let next = state.nextLast || '';
  let guard = 0;
  do {
    const qs = new URLSearchParams({n:String(state.settings.pageSize || 100)}); if (next) qs.set('last', next);
    const {data} = await api(`/api/repositories?${qs}`);
    state.repos = [...new Set([...state.repos, ...(data.repositories || [])])].sort();
    next = data.nextLast || '';
    guard++;
  } while (next && guard < 20);
  state.nextLast = next;
  try { const {data: nsData} = await api('/api/namespaces'); state.namespaces = (nsData.namespaces || []).map(n => n.name); } catch (e) { console.warn('loadRepos: failed to load namespaces', e); }
  if (typeof pruneTreeCache === 'function') pruneTreeCache();
  renderNamespaces(); renderRepos(); updateRepoActions();
}

// The repo list is now rendered as a directory tree (see tree.js), which shows
// the namespace -> repo -> tag hierarchy in one column. renderRepos() is kept
// as the tree entry point: it rebuilds the tree data and re-renders it.
function renderRepos() {
  if (typeof renderTreeView === 'function') { renderTreeView(); return; }
  renderFlatRepos();
}
// The namespace filter dropdown is gone; the tree groups every namespace as a
// folder, so there is no picker to fill. applyI18n() still calls this on a
// language switch, which re-renders the tree with the new labels.
function renderNamespaces() { if (typeof renderTreeView === 'function') { renderTreeView(); return; } }
function updateRepoBulkBar() {
  const count = state.selectedRepos.size;
  el('selectedRepoCount').textContent = t('selectedCount', {count});
  el('selectedRepoCount').classList.toggle('hidden-ui', count === 0);
}

// Legacy flat list. Kept as a fallback in case tree.js fails to load; the
// directory tree in tree.js is the normal rendering path.
function renderFlatRepos() {
  const q = el('repoSearch').value.trim().toLowerCase();
  const repos = state.repos.filter(r => !q || r.toLowerCase().includes(q));
  repoList.innerHTML = ''; if (!repos.length) {
    const noPerm = state.user && !state.user.isAdmin && Array.isArray(state.permissions) && state.permissions.length === 0;
    repoList.innerHTML = `<div class="hint">${noPerm ? t('noPermission') : t('noImages')}</div>`;
    return;
  }
  for (const repo of repos) {
    const checked = state.selectedRepos.has(repo);
    const b = document.createElement('div'); b.className = `item ${repo === state.selectedRepo ? 'active' : ''} ${checked ? 'checked' : ''}`;
    b.innerHTML = `<input class="repo-check-input" type="checkbox" ${checked ? 'checked' : ''} data-repo-check="${esc(repo)}" /><div class="repo-full"><b>📁 ${esc(imageNameInNamespace(repo))}</b><small title="${esc(repo)}">${esc(repo)}</small></div>`;
    b.onclick = (e) => { if (e.target.closest('[data-repo-check]')) return; selectRepo(repo); };
    repoList.appendChild(b);
  }
  repoList.querySelectorAll('[data-repo-check]').forEach(c => {
    c.onclick = e => e.stopPropagation();
    c.onchange = () => { c.checked ? state.selectedRepos.add(c.dataset.repoCheck) : state.selectedRepos.delete(c.dataset.repoCheck); c.closest('.item')?.classList.toggle('checked', c.checked); updateRepoBulkBar(); };
  });
  updateRepoBulkBar();
}
async function checkRepoProtection(repo) {
  try {
    const {data} = await api(`/api/repositories/${encodeRepo(repo)}/stats`);
    const isImmutable = data.protectionMode === 'immutable';
    const icon = el('tagImmutableIcon');
    if (icon) icon.classList.toggle('hidden-ui', !isImmutable);
  } catch (e) { console.warn('checkRepoProtection: failed to load stats', e); const icon = el('tagImmutableIcon'); if (icon) icon.classList.add('hidden-ui'); }
}

async function selectRepo(repo) {
  if (repo === state.selectedRepo) {
    state.selectedRepo = ''; state.selectedTag = ''; state.selectedTags.clear(); state.digest = ''; state.manifest = null; state.tags = [];
    el('selectedRepo').textContent = t('selectImage'); clearDetails(); renderTree(); updateRepoActions();
    if (typeof applyRepoDescriptionPermissions === 'function') applyRepoDescriptionPermissions();
    const icon = el('tagImmutableIcon'); if (icon) icon.classList.add('hidden-ui');
    await refreshSidebars();
    return;
  }
  state.selectedRepo = repo; state.selectedTag = ''; state.selectedTags.clear(); state.digest = ''; state.manifest = null; state.tags = [];
  el('selectedRepo').textContent = repo; clearDetails(); renderTree(); updateRepoActions(); await loadTags(); await refreshSidebars();
  await loadRepoDescription(repo);
  if (typeof applyRepoDescriptionPermissions === 'function') applyRepoDescriptionPermissions();
  await checkRepoProtection(repo);
}
function updateRepoActions() {
  // With the filter dropdown gone, the namespace comes from the selection (or
  // the single delete button). The create button opens a dialog that can create
  // either a repository or (admin-only) a namespace, so it is enabled whenever
  // the caller may do one of the two: any admin, or a user with write access to
  // the selected repo's namespace.
  const ns = state.selectedRepo ? namespaceOf(state.selectedRepo) : '';
  const selected = [...state.selectedRepos];
  const canAct = selected.length
    ? selected.some(canWriteRepo)
    : (state.selectedRepo ? canWriteRepo(state.selectedRepo) : true);
  const canCreate = isAdminUser() || (!!ns && ns !== ROOT_NAMESPACE && canWriteNamespace(ns));
  el('deleteSelectedBtn').disabled = !canAct;
  el('createBtn').disabled = !canCreate;
  el('tagSettingsBtn').disabled = !state.selectedRepo || !canWriteRepo(state.selectedRepo);
}

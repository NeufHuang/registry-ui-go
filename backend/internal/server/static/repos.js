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
  try { const {data: nsData} = await api('/api/namespaces'); state.namespaces = (nsData.namespaces || []).map(n => n.name); } catch {}
  renderNamespaces(); renderRepos(); updateRepoActions();
}
function renderNamespaces() {
  const sel = el('namespaceFilter'); const current = sel.value;
  const catalogNs = state.repos.map(namespaceOf);
  let allNs = [...new Set([...state.namespaces, ...catalogNs])].sort();
  if (state.user && !state.user.isAdmin && state.permissions.length > 0) {
    allNs = allNs.filter(ns => state.permissions.some(p => p.canRead && (ns === p.namespacePattern || ns.startsWith(p.namespacePattern + '/'))));
  }
  sel.innerHTML = `<option value="">${esc(t('allNamespaces'))}</option>` + allNs.map(g => `<option value="${esc(g)}">${esc(g === t('root') ? g : '/' + g)}</option>`).join('');
  if (current && allNs.includes(current)) sel.value = current; else if (!current) sel.value = ''; else if (allNs.length) sel.value = allNs[0];
}
function updateRepoBulkBar() {
  const count = state.selectedRepos.size;
  el('selectedRepoCount').textContent = t('selectedCount', {count});
  el('selectedRepoCount').style.display = count === 0 ? 'none' : '';
}

function renderRepos() {
  const q = el('repoSearch').value.trim().toLowerCase(); const ns = el('namespaceFilter').value;
  const repos = state.repos.filter(r => (!q || r.toLowerCase().includes(q)) && (!ns || namespaceOf(r) === ns));
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
    state._repoImmutable = isImmutable;
  } catch { const icon = el('tagImmutableIcon'); if (icon) icon.classList.add('hidden-ui'); }
}

async function selectRepo(repo) {
  if (repo === state.selectedRepo) {
    state.selectedRepo = ''; state.selectedTag = ''; state.selectedTags.clear(); state.digest = ''; state.manifest = null; state.tags = [];
    el('selectedRepo').textContent = t('selectImage'); clearDetails(); renderRepos(); renderTags(); updateRepoActions();
    const icon = el('tagImmutableIcon'); if (icon) icon.classList.add('hidden-ui');
    await refreshSidebars();
    return;
  }
  state.selectedRepo = repo; state.selectedTag = ''; state.selectedTags.clear(); state.digest = ''; state.manifest = null; state.tags = [];
  el('selectedRepo').textContent = repo; clearDetails(); renderRepos(); updateRepoActions(); await loadTags(); await refreshSidebars();
  await loadRepoDescription(repo);
  await checkRepoProtection(repo);
}
function updateRepoActions() { const ns = el('namespaceFilter').value || (state.selectedRepo ? namespaceOf(state.selectedRepo) : ''); el('deleteSelectedReposBtn').disabled = false; el('createRepoBtn').disabled = !ns || ns === t('root'); el('createNamespaceBtn').disabled = false; el('tagSettingsBtn').disabled = !state.selectedRepo; }

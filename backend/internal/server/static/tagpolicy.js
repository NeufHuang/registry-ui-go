el('tagSettingsBtn').onclick = async () => {
  if (!state.selectedRepo) { toast(t('noRepoSelected'), true); return; }
  el('tagSettingsRepoName').textContent = state.selectedRepo;
  try {
    const {data} = await api(`/api/repositories/${encodeRepo(state.selectedRepo)}/stats`);
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
  r.addEventListener('change', function() { /* no-op */ });
});
el('tagSettingsCancelBtn').onclick = () => closeModal('tagSettingsModal');
el('tagSettingsSaveBtn').onclick = async (e) => {
  e.preventDefault();
  try {
    await api(`/api/repositories/${encodeRepo(state.selectedRepo)}/tag-policy`, {method:'PUT', body:JSON.stringify({
      protectionMode: document.querySelector('input[name="protectionMode"]:checked')?.value || 'rules',
      overwriteAction: document.querySelector('input[name="overwriteAction"]:checked')?.value || 'recycle',
      keepCount: parseInt(el('tagSettingKeepCount').value) || 0,
      anonymousPull: el('tagSettingAnonymousPull').checked,
      pushCreateRepo: el('tagSettingPushCreateRepo').checked,
    })});
    toast(t('saveOK'));
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
el('refreshReposBtn').onclick = async () => { try { await loadRepos(true); } catch(e) { toast(e.message, true); } };
el('deleteSelectedReposBtn').onclick = async () => {
  const checked = [...state.selectedRepos];
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
    try { await deleteNamespace(); } catch(e) { toast(e.message, true); }
  }
};
el('createRepoBtn').onclick = async () => {
  const ns = el('namespaceFilter').value || (state.selectedRepo ? namespaceOf(state.selectedRepo) : '');
  if (!ns || ns === t('root')) { toast(t('noRepoSelected'), true); return; }
  const ok = await openFormDialog({
    title: t('createRepo'),
    message: ns + '/',
    fields: [{key: 'name', label: 'namespace/repo', placeholder: ns + '/myapp', value: ns + '/'}],
    submitLabel: t('save'),
    submit: async (v) => {
      const name = (v.name || '').trim().replace(/^\/+/, '').replace(/\/+$/, '');
      if (!name || !name.includes('/')) return {ok: false, error: 'namespace/repo required'};
      try { await api(`/api/repositories/${encodeRepo(name)}/init`, {method:'POST'}); toast(t('saveOK')); await loadRepos(true); return {ok: true}; }
      catch (e) { return {ok: false, error: e.message}; }
    },
  });
  if (ok) await loadRepos(true);
};
el('createNamespaceBtn').onclick = async () => {
  const ok = await openFormDialog({
    title: t('createNamespace'),
    fields: [{key: 'name', label: t('createNamespace'), placeholder: 'myteam'}],
    submitLabel: t('save'),
    submit: async (v) => {
      const name = (v.name || '').trim();
      if (!name) return {ok: false, error: 'name required'};
      try { await api('/api/namespaces', {method:'POST', body:JSON.stringify({name})}); toast(t('saveOK')); await loadRepos(true); return {ok: true}; }
      catch (e) { return {ok: false, error: e.message}; }
    },
  });
};
// ⋮ dropdown toggles
['repoMoreBtn','tagMoreBtn','manifestMoreBtn'].forEach(id => {
  const btn = el(id);
  if (btn) btn.onclick = (e) => { e.stopPropagation(); const dd = el(id.replace('Btn','Dropdown')); if (dd) { const show = dd.classList.contains('hidden-ui'); dd.classList.toggle('hidden-ui'); if (show) { const r = btn.getBoundingClientRect(); dd.style.top = (r.bottom + 8) + 'px'; dd.style.right = (window.innerWidth - r.right) + 'px'; } } };
});
document.addEventListener('click', () => { document.querySelectorAll('[id$=Dropdown]').forEach(d => d.classList.add('hidden-ui')); });
[].forEach.call(document.querySelectorAll('[id$=Dropdown]'), d => { d.addEventListener('click', e => e.stopPropagation()); });
el('refreshTagsBtn').onclick = async () => { if (state.selectedRepo) try { await loadTags(); } catch(e) { toast(e.message, true); } };
el('repoSearch').oninput = renderRepos; el('namespaceFilter').onchange = () => { const ns = el('namespaceFilter').value; if (state.selectedRepo && ns && namespaceOf(state.selectedRepo) !== ns) { state.selectedRepo = ''; state.selectedTag = ''; state.selectedTags.clear(); state.digest = ''; state.manifest = null; state.tags = []; el('selectedRepo').textContent = t('selectImage'); clearDetails(); renderTags(); const icon = el('tagImmutableIcon'); if (icon) icon.classList.add('hidden-ui'); } renderRepos(); updateRepoActions(); }; el('tagSearch').oninput = renderTags;
el('deleteSelectedTagsBtn').onclick = async () => { try { await deleteTags([...state.selectedTags]); } catch(e) { toast(e.message, true); } };
el('favoriteBtn').onclick = async () => { try { await favoriteCurrent(); } catch(e) { toast(e.message, true); } };
el('recentRefreshBtn').onclick = e => { e.preventDefault(); e.stopPropagation(); loadRecent(); }; el('favoritesRefreshBtn').onclick = e => { e.preventDefault(); e.stopPropagation(); loadFavorites(); }; el('auditRefreshBtn').onclick = e => { e.preventDefault(); e.stopPropagation(); loadAudit(); }; el('recycleRefreshBtn').onclick = e => { e.preventDefault(); e.stopPropagation(); loadRecycle(); };
(async()=>{ try { await loadSettings(); await loadUser(); await checkHealth(); await loadRepos(true); await refreshSidebars(); } catch(e) { toast(e.message, true); } })();

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


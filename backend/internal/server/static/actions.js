async function deleteTags(tags, options={}) {
  tags = [...new Set(tags)].filter(Boolean);
  if (!state.selectedRepo || !tags.length) return false;
  const repo = state.selectedRepo;
  // Resolve digests for the selected tags and, so we can tell whether a tag
  // is the last one for its digest, for every other tag in the repo too.
  const digestCache = {};
  const digestFor = async (tag) => {
    if (digestCache[tag] !== undefined) return digestCache[tag];
    const d = await manifestDigestForTag(tag);
    digestCache[tag] = d || '';
    return digestCache[tag];
  };
  const tagDigests = [];
  for (const tag of tags) {
    const digest = await digestFor(tag);
    if (!digest) throw new Error(`No digest for ${tag}`);
    tagDigests.push({tag, digest});
  }
  // digest -> all repo tags pointing at it
  const allByDigest = {};
  const repoTags = (state.tags || []).filter(tg => tg !== '_init');
  for (const tg of repoTags) {
    const d = await digestFor(tg);
    if (!d) continue;
    (allByDigest[d] = allByDigest[d] || []).push(tg);
  }
  const selectedSet = new Set(tags);
  // Classify each selected tag: 'delete' when it is the last surviving tag of
  // its digest (every sibling is also selected), otherwise 'untag'.
  const classify = (digest) => {
    const all = allByDigest[digest] || [];
    const remaining = all.filter(tg => !selectedSet.has(tg));
    return remaining.length === 0 ? 'delete' : 'untag';
  };
  const isSingle = tags.length === 1;
  const singleRef = `${repo}:${tags[0]}`;
  const expected = isSingle ? singleRef : 'DELETE';
  const tagLines = tagDigests.map(x => {
    const action = classify(x.digest);
    const label = action === 'delete' ? t('willDelete') : t('willUntag');
    return `- ${repo}:${x.tag}  [${label}]`;
  }).join('\n');
  const details = [
    t('deleteConfirmHint'),
    '',
    `Repo: ${repo}`,
    `Tags (${tagDigests.length}):`,
    tagLines,
    '',
    t('affectedByDigest')
  ].join('\n');
  const typed = await openDeleteConfirm({
    title: t('deleteConfirmTitle'),
    message: isSingle ? t('deleteSingleMessage') : t('deleteMultipleMessage'),
    details,
    expected,
  });
  if (typed !== expected) { toast(t('deleteMismatch'), true); return false; }
  const {data} = await api(`/api/repositories/${encodeRepo(repo)}/manifests/batch-delete`, {method:'POST', body:JSON.stringify({tags})});
  const ok = data.results.filter(r => r.ok).length;
  const fail = data.results.filter(r => !r.ok).length;
  toast(`${t('deleteSent')} (ok:${ok}${fail ? ', fail:'+fail : ''})`);
  state.selectedTags.clear(); clearDetails(); await loadTags(); await refreshSidebars();
  return true;
}
async function deleteCurrent() {
  if (!state.selectedRepo || !state.selectedTag) return;
  await deleteTags([state.selectedTag]);
}
async function deleteSelectedRepo() {
  if (!state.selectedRepo) { toast(t('noRepoSelected'), true); return; }
  if (!state.tags.length) await loadTags();
  const ok = await deleteTags([...state.tags]);
  if (!ok) return;
  state.selectedRepo = ''; state.tags = []; state.selectedTags.clear(); el('selectedRepo').textContent = t('selectImage'); updateRepoActions(); await loadRepos(true);
}
async function deleteNamespace() {
  const ns = state.selectedRepo ? namespaceOf(state.selectedRepo) : el('namespaceFilter').value;
  if (!ns || ns === t('root')) { toast(t('noRepoSelected'), true); return; }
  const repos = state.repos.filter(r => namespaceOf(r) === ns);
  if (!repos.length) return;
  const typed = await openDeleteConfirm({
    title: t('deleteConfirmTitle'),
    message: t('deleteRepoConfirm', {repo: ns + '/* (' + repos.length + ' repos)'}),
    details: repos.map(r => `- ${r}`).join('\n'),
    expected: ns,
  });
  if (typed !== ns) { toast(t('deleteMismatch'), true); return; }
  let deleted = 0;
  for (const repo of repos) {
    try {
      const {data} = await api(`/api/repositories/${encodeRepo(repo)}/tags`);
      const tags = data.tags || [];
      for (const tag of tags) {
        const d = await manifestDigestForTagRef(repo, tag);
        if (d) { await api(`/api/repositories/${encodeRepo(repo)}/manifests/${encodeURIComponent(d)}`, {method:'DELETE'}); deleted++; toast(`${t('delete')} ${deleted}...`, false, true); }
      }
    } catch(e) { /* continue */ }
  }
  toast(`${t('deleteSent')} (${deleted} digest)`);
  state.selectedRepo = ''; state.tags = []; state.selectedTags.clear(); el('selectedRepo').textContent = t('selectImage'); updateRepoActions(); await loadRepos(true);
}
async function manifestDigestForTagRef(repo, tag) {
  if (repo === state.selectedRepo && tag === state.selectedTag && state.digest) return state.digest;
  try { const {data} = await api(`/api/repositories/${encodeRepo(repo)}/manifests/${encodeURIComponent(tag)}`); return data.digest || ''; } catch { return ''; }
}
async function uploadAvatar() {
  const file = el('profileAvatarFile')?.files?.[0];
  if (!file) return;
  const form = new FormData(); form.append('avatar', file);
  const {data} = await api('/api/uploads/avatar', {method:'POST', body:form});
  state.user.avatar = data.url; applyUser();
  const btn = el('profileAvatarFileBtn');
  if (btn) btn.textContent = t('selectFile');
  toast(t('saveOK'));
}
async function changePassword() {
  const oldPassword = el('oldPassword').value;
  const newPassword = el('newPassword').value;
  await api('/api/user/password', {method:'POST', body:JSON.stringify({oldPassword,newPassword})});
  toast(t('passwordChanged'));
}
async function logout() { try { await api('/api/logout', {method:'POST'}); } catch {} window.location.href = '/login.html'; }
async function favoriteCurrent() {
  if (!state.selectedRepo) return;
  const ok = await openFormDialog({
    title: t('favoriteNote'),
    fields: [{key: 'note', label: t('note'), placeholder: '', value: ''}],
    submitLabel: t('save'),
    submit: async (v) => {
      try {
        await api('/api/favorites', {method:'POST', body: JSON.stringify({repo: state.selectedRepo, reference: state.selectedTag, digest: state.digest, note: v.note || ''})});
        toast(t('favoriteSaved')); await loadFavorites();
        return {ok: true};
      } catch (e) { return {ok: false, error: e.message}; }
    },
  });
}

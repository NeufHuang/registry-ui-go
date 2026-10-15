async function deleteTags(tags, options={}) {
  tags = [...new Set(tags)].filter(Boolean);
  if (!tags.length) return false;
  // The repository owning these tags. It is normally state.selectedRepo, but a
  // tag can also be selected by its checkbox in a repo whose row was never
  // clicked; tree.js now points state.selectedRepo at that repo, so accept it
  // explicitly as a fallback.
  const repo = state.selectedRepo || options.repo;
  if (!repo) { toast(t('noRepoSelected'), true); return false; }
  if (!canWriteRepo(repo)) { toast(t('noPermission'), true); return false; }
  // Resolve digests for the selected tags and, so we can tell whether a tag
  // is the last one for its digest, for every other tag in the repo too.
  // NOTE: The digest cache is only valid for the duration of this single
  // call. A concurrent push could theoretically change a tag's digest
  // between our resolution and the server-side delete, but the server
  // re-resolves digests atomically in deleteTagsAware, so the worst case
  // is a stale classification shown in the confirmation dialog — the
  // actual delete is always correct.
  const digestCache = {};
  const digestFor = async (tag) => {
    if (digestCache[tag] !== undefined) return digestCache[tag];
    // manifestDigestForTag() reads state.selectedRepo; use the explicit variant
    // so a checkbox-only selection resolves digests from the right repository.
    const d = await manifestDigestForTagRef(repo, tag);
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
  // The sibling-tag list must belong to the repo being deleted from. When the
  // selection came from a checkbox in a repo other than state.selectedRepo's,
  // state.tags holds the wrong repo's tags; the tree cache is authoritative.
  const repoTags = (typeof treeState !== 'undefined' && treeState.loaded.get(repo))
    || state.tags || [];
  for (const tg of repoTags) {
    if (tg === '_init') continue;
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
  const results = data.results || [];
  const ok = results.filter(r => r.ok).length;
  const fail = results.filter(r => !r.ok).length;
  const warnings = [...new Set(results.filter(r => r.warning).map(r => r.warning))];
  const summary = `${t('deleteSent')} (ok:${ok}${fail ? ', fail:'+fail : ''})`;
  // A partial failure — e.g. a surviving sibling tag could not be re-pushed —
  // must be surfaced instead of hiding behind the success toast.
  if (warnings.length) toast(`${summary} — ${warnings.join('; ')}`, true, true);
  else toast(summary);
  state.selectedTags.clear(); clearDetails();
  // Refresh the tag list of the repo we actually deleted from, not of
  // state.selectedRepo (which a checkbox-only selection never set).
  if (typeof refreshTreeTags === 'function' && state.selectedRepo) { treeState.loaded.delete(state.selectedRepo); await refreshTreeTags(); }
  if (typeof treeState !== 'undefined') treeState.loaded.delete(repo);
  if (state.selectedRepo !== repo && typeof renderTreeView === 'function') renderTreeView();
  else if (typeof refreshTreeTags !== 'function') await loadTags();
  await refreshSidebars();
  return true;
}
async function deleteCurrent() {
  if (!state.selectedRepo || !state.selectedTag) return;
  await deleteTags([state.selectedTag]);
}
// Deleting a whole namespace is a much broader action than the repo list's
// "✕ 删除" button implies, so it is no longer reachable from there. It stays
// here as an explicit helper for callers that have already confirmed the
// namespace scope.
async function deleteNamespace(nsOverride) {
  let ns = nsOverride || (state.selectedRepo ? namespaceOf(state.selectedRepo) : '');
  // The picker stores the root namespace as the sentinel, but the API expects
  // the empty string the backend uses for it.
  if (ns === ROOT_NAMESPACE) ns = '';
  if (!ns) { toast(t('noRepoSelected'), true); return; }
  // Only namespaces the user can actually write to; the server rejects the
  // rest with 403. The root namespace holds repos whose namespaceOf() is the
  // sentinel, so compare against that.
  const repos = state.repos.filter(r => namespaceOf(r) === (ns === '' ? ROOT_NAMESPACE : ns) && canWriteRepo(r));
  if (!repos.length) { toast(t('noPermission'), true); return; }
  const typed = await openDeleteConfirm({
    title: t('deleteConfirmTitle'),
    message: t('deleteRepoConfirm', {repo: (ns === '' ? namespaceLabel(ROOT_NAMESPACE) : ns) + '/* (' + repos.length + ' repos)'}),
    details: repos.map(r => `- ${r}`).join('\n'),
    expected: ns === '' ? namespaceLabel(ROOT_NAMESPACE) : ns,
  });
  if (typed !== (ns === '' ? namespaceLabel(ROOT_NAMESPACE) : ns)) { toast(t('deleteMismatch'), true); return; }
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
  try { const {data} = await api(`/api/repositories/${encodeRepo(repo)}/manifests/${encodeURIComponent(tag)}`); return data.digest || ''; } catch (e) { console.warn('manifestDigestForTagRef: failed for', repo, tag, e); return ''; }
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
  // Reload so a forced first-login password change unblocks the rest of the
  // UI (the server rejects every other endpoint until the flag is cleared).
  setTimeout(() => window.location.reload(), 900);
}
async function logout() { try { await api('/api/logout', {method:'POST'}); } catch (e) { console.warn('logout: API call failed, redirecting anyway', e); } window.location.href = '/login.html'; }
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

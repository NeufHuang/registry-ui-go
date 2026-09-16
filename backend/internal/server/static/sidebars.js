async function loadRecent() {
  try {
    const {data} = await api('/api/recent');
    const items = data.recent || [];
    el('recentList').innerHTML = items.length ? items.map(x =>
      `<div class="mini recent-item" data-repo="${esc(x.repo)}" data-ref="${esc(x.reference||'')}"><b>${esc(x.repo)}${x.reference?':'+esc(x.reference):''}</b><small>${esc(x.action)} · ${esc(x.visitedAt)}</small></div>`
    ).join('') : `<div class="hint">${t('noRecent')}</div>`;
    document.querySelectorAll('.recent-item').forEach(elm => {
      elm.onclick = async () => {
        const repo = elm.dataset.repo;
        const ref = elm.dataset.ref;
        if (!repo) return;
        // selectRepo is toggle-shaped: clicking the active repo clears it.
        // From recent-visits we always want to *navigate* to the target repo,
        // so only call selectRepo when we're not already on it. Otherwise
        // manually clear the selected tag so the selectTag below takes the
        // set branch rather than the toggle-off branch.
        if (state.selectedRepo !== repo) {
          await selectRepo(repo);
        } else {
          state.selectedTag = '';
          state.digest = '';
          state.manifest = null;
          clearDetails();
          renderTags();
        }
        if (ref) await selectTag(ref);
      };
    });
  } catch { el('recentList').innerHTML = `<div class="hint">${t('noRecent')}</div>`; }
}
async function loadFavorites() { try { const {data}=await api('/api/favorites'); el('favoritesList').innerHTML=(data.favorites||[]).map(x=>`<div class="mini"><b>${esc(x.repo)}${x.reference?':'+esc(x.reference):''}</b><small>${esc(x.note||x.digest||'')}</small><button class="ghost" data-fav-del="${x.id}">${t('delete')}</button></div>`).join('')||`<div class="hint">${t('noFav')}</div>`; document.querySelectorAll('[data-fav-del]').forEach(b=>b.onclick=async()=>{await api(`/api/favorites/${b.dataset.favDel}`,{method:'DELETE'}); await loadFavorites();}); } catch { el('favoritesList').innerHTML=`<div class="hint">${t('noFav')}</div>`; } }
async function loadAudit() {
  if ((state.settings.showAudit??'true') !== 'true') { el('auditList').innerHTML=`<div class="hint">${t('hidden')}</div>`; return; }
  try {
    const {data}=await api('/api/audit');
    el('auditList').innerHTML=(data.audit||[]).map(x=>{
      let userLabel;
      if (x.username) userLabel = x.username;
      else if (x.userId) userLabel = '#'+x.userId;
      else if ((x.detail||'').includes('anonymous')) userLabel = t('anonymousUser');
      else userLabel = t('systemUser');
      return `<div class="mini"><b>${esc(x.action)} · ${esc(x.status)}</b><small>${esc(userLabel)} · ${esc(x.repo||'')} ${esc(x.reference||'')} ${esc(x.detail||'')}</small></div>`;
    }).join('')||`<div class="hint">${t('noAudit')}</div>`;
  } catch { el('auditList').innerHTML=`<div class="hint">${t('noAudit')}</div>`; }
}
function contentTypeLabel(ct) {
  if (!ct) return '';
  if (ct.includes('helm')) return '⎈ Helm';
  if (ct.includes('manifest.list') || ct.includes('image.index')) return '📋 Manifest List';
  if (ct.includes('image.manifest') || ct.includes('container.image')) return '📦 Image';
  return ct.split('.').pop() || ct;
}

async function loadRecycle() {
  try {
    const {data} = await api('/api/recycle?limit=50');
    const items = data.items || [];
    if (!items.length) { el('recycleList').innerHTML = `<div class="hint">${t('noRecycle')}</div>`; return; }
    el('recycleList').innerHTML = items.map(x => {
      // Restore re-pushes a manifest and deleting a record discards the last
      // recoverable copy, so both need write access on the repo.
      const writable = canWriteRepo(x.repo);
      let actions = '';
      if (x.status === 'pending_gc') {
        actions = `${writable ? `<button class="ghost" data-recycle-restore="${x.id}">${t('restore')}</button>` : ''}${writable ? `<button class="ghost danger" data-recycle-delete="${x.id}">🗑</button>` : ''}`;
      } else if (x.status === 'gc_expired' || x.status === 'gc_failed') {
        const label = x.status === 'gc_expired' ? t('gcExpired') : t('gcFailed');
        actions = `<span class="badge danger">${esc(label)}</span>${writable ? `<button class="ghost danger" data-recycle-delete="${x.id}">🗑</button>` : ''}`;
      } else {
        actions = `<span class="badge muted">${t('restored')}</span>`;
      }
      return `<div class="mini recycle-${esc(x.status)}"><b>${esc(x.repo)}:${esc(x.reference)}</b><small>${esc(x.digest)} · ${esc(contentTypeLabel(x.contentType))} · ${esc(x.status)} · ${esc(x.deletedAt)}</small><div style="display:flex;gap:4px;margin-top:2px">${actions}</div></div>`;
    }).join('');
    document.querySelectorAll('[data-recycle-restore]').forEach(b => b.onclick = async () => {
      try {
        await api(`/api/recycle/${b.dataset.recycleRestore}/restore`, {method:'POST'});
        toast(t('restored'));
        await loadRecycle();
        if (state.selectedRepo) await loadTags();
      } catch (e) {
        // api() exposes the machine-readable code (e.g. "gc_expired"), which is
        // what the 410 response carries; matching on the free-text message never
        // worked because `details` takes precedence there.
        if (e.code === 'gc_expired' || (e.message || '').includes('gc_expired')) toast(t('gcExpired'), true);
        else toast(e.message, true);
      }
    });
    document.querySelectorAll('[data-recycle-delete]').forEach(b => b.onclick = async () => {
      await openFormDialog({
        title: t('delete'),
        message: t('confirmDeleteRecord'),
        submitLabel: t('delete'),
        danger: true,
        submit: async () => {
          try { await api(`/api/recycle/${b.dataset.recycleDelete}`, {method:'DELETE'}); await loadRecycle(); return {ok: true}; }
          catch (e) { return {ok: false, error: e.message}; }
        },
      });
    });
  } catch { el('recycleList').innerHTML = `<div class="hint">${t('noRecycle')}</div>`; }
}
async function refreshSidebars() { await Promise.all([loadRecent(), loadFavorites(), loadAudit(), loadRecycle()]); }

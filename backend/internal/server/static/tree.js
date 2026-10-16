// Directory-tree browser: namespace -> repository -> tag in a single column.
//
// The old UI used two flat panels (a repo list and a tag list for the selected
// repo). That made it impossible to see where a repo lives without reading the
// small "namespace/repo" caption under every row, and it forced a second
// navigation step before any tag became visible.
//
// The tree keeps the existing state (state.selectedRepo / selectedTag /
// selectedTags / selectedRepos) so repos.js, tags.js, actions.js and
// tagpolicy.js keep working unchanged; only the rendering layer differs.

// Folded groups, keyed by full path. Persisted so a reload restores the view.
const TREE_STATE_KEY = 'treeFolded';

const treeState = {
  folded: new Set(),
  // Repositories whose tag list is already loaded (and the tags themselves),
  // so expanding a repo does not refetch on every render.
  loaded: new Map(),
  loading: new Set(),
  // Namespace -> [repos], built from state.repos by rebuildTreeData().
  groups: [],
};

function loadTreeState() {
  try {
    const raw = localStorage.getItem(TREE_STATE_KEY);
    if (raw) treeState.folded = new Set(JSON.parse(raw) || []);
  } catch (e) { /* a malformed value must not break the UI */ }
}
function saveTreeState() {
  try { localStorage.setItem(TREE_STATE_KEY, JSON.stringify([...treeState.folded])); } catch (e) { /* storage may be unavailable */ }
}

// ---------------------------------------------------------------------------
// data layer
// ---------------------------------------------------------------------------

function rebuildTreeData() {
  const byNs = new Map();
  for (const repo of state.repos) {
    const ns = namespaceOf(repo);
    if (!byNs.has(ns)) byNs.set(ns, []);
    byNs.get(ns).push(repo);
  }
  treeState.groups = [...byNs.entries()]
    .map(([ns, repos]) => ({ns, repos: repos.sort()}))
    .sort((a, b) => a.ns.localeCompare(b.ns));
}

// The tree has a single search box (#repoSearch) that matches repositories and
// tags alike. A repo is kept when either its own name matches or one of its
// (already loaded) tags matches, so searching "v1.2" reveals the tag rows.
function repoMatchesQuery(repo, tags) {
  const q = (el('repoSearch').value || '').trim().toLowerCase();
  if (!q) return true;
  if (repo.toLowerCase().includes(q)) return true;
  return (tags || []).some(tg => tg.toLowerCase().includes(q));
}
function tagMatchesQuery(tag) {
  const q = (el('repoSearch').value || '').trim().toLowerCase();
  if (!q) return true;
  return tag.toLowerCase().includes(q);
}

// ---------------------------------------------------------------------------
// rendering
// ---------------------------------------------------------------------------

function treeNode(indent, cls, html, handlers) {
  const node = document.createElement('div');
  node.className = 'tree-node';
  const row = document.createElement('div');
  row.className = `tree-row ${cls || ''}`.trim();
  row.style.paddingLeft = (4 + indent * 16) + 'px';
  row.innerHTML = html;
  node.appendChild(row);
  if (handlers) handlers(row, node);
  return node;
}

function arrowHtml(folded, isEmpty) {
  if (isEmpty) return `<span class="tree-arrow empty" aria-hidden="true"></span>`;
  // The triangle is drawn by CSS (.tree-arrow::before); the expanded class
  // rotates it to point down. Keeping the text content out avoids the
  // font-dependent ▸/▾ glyphs.
  return `<span class="tree-arrow${folded ? '' : ' expanded'}" role="button" tabindex="0" aria-expanded="${!folded}"></span>`;
}

function renderTree() {
  rebuildTreeData();
  const list = el('repoList');
  list.innerHTML = '';
  const groups = treeState.groups;

  if (!groups.length) {
    const noPerm = state.user && !state.user.isAdmin && Array.isArray(state.permissions) && state.permissions.length === 0;
    list.innerHTML = `<div class="hint">${noPerm ? t('noPermission') : t('noImages')}</div>`;
    updateRepoBulkBar(); updateTagBulkBar(); updateRepoActions();
    return;
  }

  // While searching, every group and repo starts expanded so matches are not
  // hidden behind a collapsed folder.
  const searching = !!(el('repoSearch').value || '').trim();

  for (const group of groups) {
    const ns = group.ns;
    const isNsFolded = !searching && treeState.folded.has(ns);
    const nsCheckedAll = group.repos.every(r => state.selectedRepos.has(r));
    const nsCheckedSome = group.repos.some(r => state.selectedRepos.has(r));
    list.appendChild(treeNode(0, 'ns-row', `
      <input type="checkbox" data-ns-check="${esc(ns)}" ${nsCheckedAll ? 'checked' : ''} ${nsCheckedSome && !nsCheckedAll ? 'data-indeterminate="1"' : ''} aria-label="${esc(namespaceLabel(ns))}" />
      ${arrowHtml(isNsFolded, false)}
      <span class="tree-label" title="${esc(namespaceLabel(ns))}">📁 ${esc(namespaceLabel(ns))}</span>
      <span class="tree-count">${group.repos.length}</span>`,
      (row) => {
        row.querySelector('.tree-arrow').onclick = (e) => { e.stopPropagation(); toggleFold(ns); };
        row.querySelector('.tree-arrow').onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); toggleFold(ns); } };
        row.onclick = () => toggleFold(ns);
        const box = row.querySelector('[data-ns-check]');
        if (box.hasAttribute('data-indeterminate')) box.indeterminate = true;
        box.onclick = (e) => e.stopPropagation();
        box.onchange = () => {
          for (const r of group.repos) box.checked ? state.selectedRepos.add(r) : state.selectedRepos.delete(r);
          renderTree();
        };
      }));

    if (isNsFolded) continue;

    const nsNode = list.lastChild;
    for (const repo of group.repos) {
      const tags = treeState.loaded.get(repo) || [];
      // A repo search hides repos that do not match (by name or by an already
      // loaded tag), so their tags are not rendered either.
      if (!repoMatchesQuery(repo, tags)) continue;
      const isRepoFolded = !searching && treeState.folded.has(repo);
      // Only a repo whose tag list has been fetched and came back empty is a
      // leaf; an unloaded repo still gets an arrow so the tree looks uniform
      // before the lazy fetch fills it in. An unloaded repo has nothing
      // expanded below it, so its arrow must always render collapsed (pointing
      // right) — using the folded flag alone would draw it as expanded, since
      // an unloaded repo is never in the folded set.
      const repoIsLeaf = treeState.loaded.has(repo) && !tags.length;
      const arrowFolded = treeState.loaded.has(repo) ? isRepoFolded : true;
      const active = repo === state.selectedRepo;
      nsNode.appendChild(treeNode(1, `repo-row ${active ? 'selected' : ''}`, `
        <input type="checkbox" data-repo-check="${esc(repo)}" ${state.selectedRepos.has(repo) ? 'checked' : ''} aria-label="${esc(repo)}" />
        ${arrowHtml(arrowFolded, repoIsLeaf)}
        <span class="tree-label" title="${esc(repo)}">🗂 ${esc(imageNameInNamespace(repo))}</span>
        ${tags.length ? `<span class="tree-count">${tags.length}</span>` : ''}`,
        (row) => {
          const arrow = row.querySelector('.tree-arrow');
          if (!arrow.classList.contains('empty')) {
            // For a repo whose tags are not loaded yet, the arrow click also
            // goes through expandRepo so the lazy fetch is triggered; for a
            // loaded repo it folds/unfolds the cached tag list.
            const arrowAction = treeState.loaded.has(repo)
              ? () => toggleFold(repo)
              : () => { void expandRepo(repo); };
            arrow.onclick = (e) => { e.stopPropagation(); arrowAction(); };
            arrow.onkeydown = (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); e.stopPropagation(); arrowAction(); } };
          }
          row.onclick = () => { void expandRepo(repo); };
          const box = row.querySelector('[data-repo-check]');
          box.onclick = (e) => e.stopPropagation();
          box.onchange = () => { box.checked ? state.selectedRepos.add(repo) : state.selectedRepos.delete(repo); renderTree(); };
        }));
      // Folded state only matters once the tag list is loaded; an unloaded
      // repo simply renders as a collapsed row with a clickable arrow.
      if (isRepoFolded) continue;
      const repoNode = nsNode.lastChild;
      // When the query matched the repository name itself, show every tag; when
      // it matched a tag, show only the matching tags.
      const q = (el('repoSearch').value || '').trim().toLowerCase();
      const repoMatched = !!q && repo.toLowerCase().includes(q);
      const visibleTags = tags.filter(tg => tg !== '_init' && (repoMatched || tagMatchesQuery(tg)));
      if (active && treeState.loading.has(repo)) {
        repoNode.appendChild(treeNode(2, 'tag-row', `<span class="tree-arrow empty"></span><span class="tree-label hint">${t('loading')}</span>`));
        continue;
      }
      if (!visibleTags.length && treeState.loaded.has(repo)) {
        repoNode.appendChild(treeNode(2, 'tag-row', `<span class="tree-arrow empty"></span><span class="tree-label hint">${t('noTags')}</span>`));
        continue;
      }
      for (const tag of visibleTags) {
        const tagChecked = state.selectedTags.has(tag);
        const tagActive = tag === state.selectedTag;
        repoNode.appendChild(treeNode(2, `tag-row ${tagActive ? 'selected' : ''}`, `
          <input type="checkbox" data-tag-check="${esc(tag)}" ${tagChecked ? 'checked' : ''} aria-label="${esc(tag)}" />
          <span class="tree-arrow empty"></span>
          <span class="tree-label" title="${esc(repo)}:${esc(tag)}">${esc(tag)}</span>`,
          (row) => {
            row.onclick = (e) => { if (e.target.closest('[data-tag-check]')) return; selectTag(tag, repo); };
            const box = row.querySelector('[data-tag-check]');
            box.onclick = (e) => e.stopPropagation();
            box.onchange = () => {
              box.checked ? state.selectedTags.add(tag) : state.selectedTags.delete(tag);
              row.classList.toggle('checked', box.checked);
              // deleteTags() keys off state.selectedRepo, and checking a tag
              // does not select its repo row (the row click does that). Point
              // the state at the repo owning this tag so a checkbox-only
              // selection can be deleted; the tags themselves are the
              // authoritative selection, so this does not change what the
              // delete button acts on.
              if (box.checked && !state.selectedRepo) state.selectedRepo = repo;
              updateTagBulkBar(); updateRepoActions();
            };
          }));
      }
    }
  }
  updateRepoBulkBar(); updateTagBulkBar(); updateRepoActions();
}

function toggleFold(key) {
  if (treeState.folded.has(key)) treeState.folded.delete(key);
  else treeState.folded.add(key);
  saveTreeState();
  renderTree();
}

// Load a repo's tags lazily so the tree does not issue one request per repo
// on first paint. The selected repo is loaded eagerly by loadTags().
// treeState.loading guards against concurrent fetches of the same repo.
async function ensureRepoTags(repo) {
  if (treeState.loaded.has(repo) || treeState.loading.has(repo)) return;
  treeState.loading.add(repo);
  try {
    const {data} = await api(`/api/repositories/${encodeRepo(repo)}/tags`);
    treeState.loaded.set(repo, (data.tags || []).sort());
  } catch (e) { console.warn('ensureRepoTags: failed for', repo, e); treeState.loaded.set(repo, []); }
  treeState.loading.delete(repo);
  renderTree();
}

// Drop the cached tag list of repos that no longer exist (or were renamed).
function pruneTreeCache() {
  const live = new Set(state.repos);
  for (const repo of [...treeState.loaded.keys()]) if (!live.has(repo)) treeState.loaded.delete(repo);
}

// Re-render the tree from the current state. Called by repos.js / tags.js
// instead of renderRepos() / renderTags().
function renderTreeView() { renderTree(); }

// Re-render the tree and cache the selected repo's tags in one step. Used by
// callers that already have the fresh tag list (loadTags) or want the tree to
// fetch it (refreshTreeTags).
function renderTreeAndCache(repo, tags) {
  if (repo) treeState.loaded.set(repo, tags || []);
  renderTree();
}

// Refresh tags for the selected repo and keep its cached entry in sync.
async function refreshTreeTags() {
  if (!state.selectedRepo) return;
  const {data} = await api(`/api/repositories/${encodeRepo(state.selectedRepo)}/tags`);
  const tags = (data.tags || []).sort();
  state.tags = tags;
  treeState.loaded.set(state.selectedRepo, tags);
  renderTree();
}

// Clicking a repo row selects it (as before) and, when it is not yet loaded,
// fetches its tags so the tree can show them. Re-clicking the already-selected
// repo keeps the old toggle behaviour (deselect).
async function expandRepo(repo) {
  if (!treeState.loaded.has(repo) && !treeState.loading.has(repo)) {
    treeState.loading.add(repo);
    renderTree();
    await ensureRepoTags(repo);
    treeState.loading.delete(repo);
  }
  if (repo === state.selectedRepo) {
    state.selectedRepo = ''; state.selectedTag = ''; state.selectedTags.clear(); state.digest = ''; state.manifest = null; state.tags = [];
    el('selectedRepo').textContent = t('selectImage'); clearDetails(); renderTree(); updateRepoActions();
    if (typeof applyRepoDescriptionPermissions === 'function') applyRepoDescriptionPermissions();
    const icon = el('tagImmutableIcon'); if (icon) icon.classList.add('hidden-ui');
    await refreshSidebars();
    return;
  }
  await selectRepo(repo);
}

// ---------------------------------------------------------------------------
// wiring
// ---------------------------------------------------------------------------

function initTree() {
  loadTreeState();
  // Search inputs and the namespace filter are bound here; tagpolicy.js binds
  // its own handlers to the same inputs, so these are added as listeners
  // instead of overwriting .oninput.
  el('repoSearch').addEventListener('input', renderTreeView);
}

initTree();

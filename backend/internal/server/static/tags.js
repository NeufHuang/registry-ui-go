async function loadTags() {
  if (typeof renderTreeView === 'function') {
    // Directory-tree mode: the selected repo's tags are usually already cached
    // by expandRepo(), so only fetch when they are missing.
    if (!treeState.loaded.has(state.selectedRepo)) {
      const {data} = await api(`/api/repositories/${encodeRepo(state.selectedRepo)}/tags`);
      state.tags = (data.tags || []).sort();
      treeState.loaded.set(state.selectedRepo, state.tags);
    } else {
      state.tags = treeState.loaded.get(state.selectedRepo);
    }
    renderTreeView();
    return;
  }
  if (tagList) tagList.innerHTML = `<div class="hint">${t('loading')}</div>`;
  const {data} = await api(`/api/repositories/${encodeRepo(state.selectedRepo)}/tags`);
  state.tags = (data.tags || []).sort(); renderTags();
}
// In tree mode the tree owns the row rendering; this is the flat-list path.
function renderTags() {
  if (typeof renderTreeView === 'function') { renderTreeView(); return; }
  renderFlatTags();
}
function renderFlatTags() {
  // The tree has one search box (#repoSearch); it is the flat-list fallback's
  // only source too, since #tagSearch no longer exists.
  const box = el('repoSearch');
  const q = (box && box.value || '').trim().toLowerCase(); const tags = state.tags.filter(tg => tg !== '_init' && (!q || tg.toLowerCase().includes(q)));
  if (!tagList) return;
  tagList.innerHTML = ''; if (!tags.length) { tagList.innerHTML = `<div class="hint">${t('noTags')}</div>`; updateTagBulkBar(); return; }
  for (const tag of tags) {
    const checked = state.selectedTags.has(tag);
    const row = document.createElement('div'); row.className = `tag-item item ${tag === state.selectedTag ? 'active' : ''} ${checked ? 'checked' : ''}`;
    row.innerHTML = `<input class="tag-check-input" type="checkbox" ${checked ? 'checked' : ''} data-tag-check="${esc(tag)}" /><div class="tag-full"><b>${esc(tag)}</b><small>${esc(state.selectedRepo)}:${esc(tag)}</small></div>`;
    row.onclick = (e) => { if (e.target.closest('[data-tag-check]')) return; selectTag(tag); };
    tagList.appendChild(row);
  }
  tagList.querySelectorAll('[data-tag-check]').forEach(c => {
    c.onclick = e => e.stopPropagation();
    c.onchange = () => { c.checked ? state.selectedTags.add(c.dataset.tagCheck) : state.selectedTags.delete(c.dataset.tagCheck); c.closest('.tag-item')?.classList.toggle('checked', c.checked); updateTagBulkBar(); };
  });
  updateTagBulkBar();
}
function updateTagBulkBar() {
  const count = state.selectedTags.size;
  el('selectedTagCount').textContent = t('selectedCount', {count});
  el('selectedTagCount').classList.toggle('hidden-ui', count === 0);
  // Tags are cached per repo (treeState.loaded), so the selected tags belong to
  // the currently selected repo. Gate the bulk-delete button on it.
  el('deleteSelectedTagsBtn').disabled = count === 0 || !canWriteRepo(state.selectedRepo);
}
async function selectTag(tag) {
  if (tag === state.selectedTag) {
    state.selectedTag = ''; clearDetails(); renderTags(); await refreshSidebars();
    return;
  }
  // Clicking a row selects exactly that tag for the detail panel; leaving a
  // stale entry in state.selectedTags would make the next bulk delete silently
  // include a tag the user checked earlier and then navigated away from.
  state.selectedTags.clear();
  state.selectedTag = tag; const refEl = el('selectedRef'); refEl.textContent = `${state.selectedRepo}:${tag}`; refEl.classList.remove('hidden-ui');
  const {data} = await api(`/api/repositories/${encodeRepo(state.selectedRepo)}/manifests/${encodeURIComponent(tag)}`);
  state.manifest = data.manifest; state.digest = data.digest || ''; state.artifactType = data.artifactType || '';
  manifestEl.textContent = JSON.stringify(data.manifest, null, 2); renderSummary(data); renderPlatforms(data.manifest);
  el('favoriteBtn').disabled = false;
  const rm = el('rawManifest'); if (rm) rm.classList.remove('hidden-ui');
  renderTags(); await refreshSidebars();
}
function renderArtifactType(data) {
  const at = data.artifactType || '';
  if (!at) return '';
  const labels = {'image': '📦 Image', 'manifest-list': '📋 Manifest List', 'helm-chart': '⎈ Helm Chart', 'sbom': '🔍 SBOM', 'attestation': '📝 Attestation', 'image-legacy': '📜 Legacy Image', 'unknown': '❓ Unknown'};
  return `<span class="pill artifact-pill">${labels[at] || esc(at)}</span>`;
}

function renderConfigDetails(data, totalSize) {
  const cfg = data.config;
  if (!cfg) { el('configDetails').classList.add('hidden-ui'); return; }
  let html = '';
  // Image Config basics - 1 column
  html += `<div class="config-section"><b>${t('imageConfig')}</b><div class="summary-grid" style="margin-top:6px;grid-template-columns:1fr">`;
  if (cfg.created) html += card(t('created'), cfg.created);
  if (cfg.os) html += card(t('os'), cfg.os);
  if (cfg.architecture) html += card(t('arch'), cfg.architecture);
  if (cfg.workingDir) html += card(t('workingDir'), cfg.workingDir);
  if (cfg.entrypoint && cfg.entrypoint.length) html += card(t('entrypoint'), cfg.entrypoint.join(' '));
  if (cfg.cmd && cfg.cmd.length) html += card(t('cmd'), cfg.cmd.join(' '));
  html += '</div>';
  // Size - full width
  html += `<div style="margin-top:6px">${card(t('size'), totalSize ? fmtBytes(totalSize) : '-')}</div>`;
  html += '</div>';
  // Env
  if (cfg.env && cfg.env.length) {
    html += `<div class="config-section" style="margin-top:8px"><b>${t('env')} (${cfg.env.length})</b><div class="env-list" style="margin-top:6px">`;
    cfg.env.forEach(e => { html += `<code class="env-line">${esc(e)}</code>`; });
    html += '</div></div>';
  }
  // Exposed Ports
  if (cfg.ports && cfg.ports.length) {
    html += `<div class="config-section" style="margin-top:8px"><b>${t('exposedPorts')} (${cfg.ports.length})</b><div class="env-list" style="margin-top:6px">`;
    cfg.ports.forEach(p => { html += `<code class="env-line">${esc(p)}</code>`; });
    html += '</div></div>';
  }
  // Volumes
  if (cfg.volumes && cfg.volumes.length) {
    html += `<div class="config-section" style="margin-top:8px"><b>${t('volumes')} (${cfg.volumes.length})</b><div class="env-list" style="margin-top:6px">`;
    cfg.volumes.forEach(v => { html += `<code class="env-line">${esc(v)}</code>`; });
    html += '</div></div>';
  }
  // Labels
  if (cfg.labels && Object.keys(cfg.labels).length) {
    html += `<div class="config-section" style="margin-top:8px"><b>${t('labels')} (${Object.keys(cfg.labels).length})</b><div class="env-list" style="margin-top:6px">`;
    for (const [k,v] of Object.entries(cfg.labels)) { html += `<code class="env-line"><b>${esc(k)}</b>=${esc(v)}</code>`; }
    html += '</div></div>';
  }
  el('configDetails').innerHTML = html;
  el('configDetails').classList.remove('hidden-ui');
}

function renderManifestFields(data) {
  const m = data.manifest || {};
  const target = el('manifestFields');
  if (!target) return;
  let html = `<div data-field="artifactType"><div class="field-row"><b>${esc(t('artifactType'))}</b>${renderArtifactType(data)}</div></div>`;
  html += '<div class="summary-grid" style="margin-top:8px;grid-template-columns:1fr">';
  html += `<div data-field="contentType">${card(t('contentType'), data.contentType || '-')}</div>`;
  html += `<div data-field="mediaType">${card(t('mediaType'), m.mediaType || '-')}</div>`;
  html += `<div data-field="schema">${card(t('schema'), m.schemaVersion ?? '-')}</div>`;
  html += '</div>';
  target.innerHTML = html;
}

function renderSummary(data) {
  const m = data.manifest || {}; const layers = Array.isArray(m.layers) ? m.layers : []; const manifests = Array.isArray(m.manifests) ? m.manifests : [];
  const size = layers.reduce((s,l)=>s+Number(l.size||0),0) || manifests.reduce((s,x)=>s+Number(x.size||0),0);
  const shared = Array.isArray(data.sharedTags) && data.sharedTags.length > 0 ? data.sharedTags.join(', ') : '';
  const rows = [
    fieldRow(t('pull'), pullCommand() || '-', 'pull'),
    fieldRow(t('digest'), data.digest || '-', 'digest'),
    fieldRow(t('digestRef'), digestRef() || '-', 'digestRef'),
  ];
  if (shared) {
    rows.push(fieldRow(t('sharedTags'), shared));
  }
  summaryEl.innerHTML = rows.join('');
  renderConfigDetails(data, size);
  renderManifestFields(data);
  applyManifestFieldVisibility();
}
// manifestFieldKey maps a checkbox id (e.g. "mfContentType") to its field name
// ("contentType"). The result is always lowercased so that localStorage keys
// are stable regardless of the HTML id casing convention used. Previously
// only the first character after "mf" was lowercased, which caused keys like
// "mf_contentType" and "mf_ContentType" to diverge and lose user preferences
// on reload.
function manifestFieldKey(id) {
  // Strip the "mf" prefix and lowercase the remainder for a canonical key.
  const raw = id.length > 2 ? id.slice(2) : id;
  return raw.charAt(0).toLowerCase() + raw.slice(1);
}
function applyManifestFieldVisibility() {
  document.querySelectorAll('[id^="mf"]').forEach(cb => {
    const field = manifestFieldKey(cb.id);
    const show = cb.checked;
    localStorage.setItem('mf_' + field, show ? '1' : '0');
    // Match both the canonical lowercase data-field and any legacy casing
    // so existing pages still work after the fix.
    document.querySelectorAll(`[data-field="${field}"], [data-field="${field.charAt(0).toUpperCase() + field.slice(1)}"]`).forEach(node => node.style.display = show ? '' : 'none');
  });
}
document.querySelectorAll('[id^="mf"]').forEach(cb => {
  const field = manifestFieldKey(cb.id);
  // Try the canonical key first, then the legacy uppercase-first variant
  // so users who saved preferences before this fix are not affected.
  let val = localStorage.getItem('mf_' + field);
  if (val === null) {
    const legacy = field.charAt(0).toUpperCase() + field.slice(1);
    val = localStorage.getItem('mf_' + legacy);
  }
  if (val !== null) cb.checked = val === '1';
  cb.addEventListener('change', applyManifestFieldVisibility);
});
function manifestItem(kind, x, idx) {
  const p = x.platform || {};
  const platform = [p.os, p.architecture, p.variant].filter(Boolean).join('/') || '';
  const title = kind === 'config' ? t('config') : kind === 'manifest' ? `${t('manifestList')} #${idx + 1}` : `${t('layerList')} #${idx + 1}`;
  const digest = x.digest || '-';
  const media = x.mediaType || '-';
  const size = x.size ? fmtBytes(Number(x.size)) : '-';
  return `<div class="manifest-item"><div class="manifest-item-main"><b>${esc(title)}</b>${platform ? `<span class="pill">${esc(platform)}</span>` : ''}<code>${esc(digest)}</code></div><div class="manifest-item-meta"><span>${esc(media)}</span><span>${esc(size)}</span></div></div>`;
}
function renderPlatforms(manifest) {
  const config = manifest?.config;
  const layers = Array.isArray(manifest?.layers) ? manifest.layers : [];
  const manifests = Array.isArray(manifest?.manifests) ? manifest.manifests : [];
  let html = '';
  if (config) html += `<div class="manifest-list">${manifestItem('config', config, 0)}</div>`;
  if (layers.length) {
    html += `<div data-field="layers">`;
    html += `<div class="section-title" style="margin-top:12px"><span>${t('layers')} (${layers.length})</span></div>`;
    html += `<div class="manifest-list">${layers.map((x, i) => manifestItem('layer', x, i)).join('')}</div>`;
    html += `</div>`;
  }
  if (manifests.length) {
    html += `<div data-field="platforms">`;
    html += `<div class="section-title" style="margin-top:12px"><span>${t('manifestList')} (${manifests.length})</span></div>`;
    html += `<div class="manifest-list">${manifests.map((x, i) => manifestItem('manifest', x, i)).join('')}</div>`;
    html += `</div>`;
  }
  platformsEl.innerHTML = html;
}
function clearDetails() { const refEl = el('selectedRef'); refEl.textContent = t('selectTag'); refEl.classList.add('hidden-ui'); el('favoriteBtn').disabled = true; summaryEl.innerHTML = ''; platformsEl.innerHTML = ''; manifestEl.textContent = '{}'; const rm = el('rawManifest'); if (rm) rm.classList.add('hidden-ui'); const mf = el('manifestFields'); if (mf) mf.innerHTML = ''; const cd = el('configDetails'); if (cd) cd.classList.add('hidden-ui'); state.artifactType = ''; }
async function manifestDigestForTag(tag) {
  if (tag === state.selectedTag && state.digest) return state.digest;
  const {data} = await api(`/api/repositories/${encodeRepo(state.selectedRepo)}/manifests/${encodeURIComponent(tag)}`);
  return data.digest || '';
}


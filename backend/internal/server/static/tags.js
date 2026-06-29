async function loadTags() { tagList.innerHTML = `<div class="hint">${t('loading')}</div>`; const {data} = await api(`/api/repositories/${encodeRepo(state.selectedRepo)}/tags`); state.tags = (data.tags || []).sort(); renderTags(); }
function renderTags() {
  const q = el('tagSearch').value.trim().toLowerCase(); const tags = state.tags.filter(tg => tg !== '_init' && (!q || tg.toLowerCase().includes(q)));
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
  el('selectedTagCount').style.display = count === 0 ? 'none' : '';
  el('deleteSelectedTagsBtn').disabled = count === 0;
}
async function selectTag(tag) {
  if (tag === state.selectedTag) {
    state.selectedTag = ''; clearDetails(); renderTags(); await refreshSidebars();
    return;
  }
  state.selectedTag = tag; const refEl = el('selectedRef'); refEl.textContent = `${state.selectedRepo}:${tag}`; refEl.style.display = '';
  const {data} = await api(`/api/repositories/${encodeRepo(state.selectedRepo)}/manifests/${encodeURIComponent(tag)}`);
  state.manifest = data.manifest; state.digest = data.digest || ''; state.artifactType = data.artifactType || '';
  manifestEl.textContent = JSON.stringify(data.manifest, null, 2); renderSummary(data); renderPlatforms(data.manifest);
  el('favoriteBtn').disabled = false;
  const rm = el('rawManifest'); if (rm) rm.style.display = '';
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
  if (!cfg) { el('configDetails').style.display = 'none'; return; }
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
  el('configDetails').style.display = 'block';
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
function applyManifestFieldVisibility() {
  document.querySelectorAll('[id^="mf"]').forEach(cb => {
    const field = cb.id.charAt(2).toLowerCase() + cb.id.slice(3);
    const show = cb.checked;
    localStorage.setItem('mf_' + field, show ? '1' : '0');
    document.querySelectorAll(`[data-field="${field}"]`).forEach(el => el.style.display = show ? '' : 'none');
  });
}
document.querySelectorAll('[id^="mf"]').forEach(cb => {
  const val = localStorage.getItem('mf_' + cb.id.slice(2));
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
function clearDetails() { const refEl = el('selectedRef'); refEl.textContent = t('selectTag'); refEl.style.display = 'none'; el('favoriteBtn').disabled = true; summaryEl.innerHTML = ''; platformsEl.innerHTML = ''; manifestEl.textContent = '{}'; const rm = el('rawManifest'); if (rm) rm.style.display = 'none'; const mf = el('manifestFields'); if (mf) mf.innerHTML = ''; const cd = el('configDetails'); if (cd) cd.style.display = 'none'; state.artifactType = ''; }
async function manifestDigestForTag(tag) {
  if (tag === state.selectedTag && state.digest) return state.digest;
  const {data} = await api(`/api/repositories/${encodeRepo(state.selectedRepo)}/manifests/${encodeURIComponent(tag)}`);
  return data.digest || '';
}


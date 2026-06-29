
async function loadSettings() {
  const {data} = await api('/api/settings');
  state.settings = {...state.settings, ...data};
  // Bind settings-modal inputs. The server always returns defaults for
  // known keys, so these inputs are guaranteed to have a value.
  if (el('settingAppLogo')) el('settingAppLogo').value = state.settings.appLogo ?? '';
  if (el('settingAppTitle')) el('settingAppTitle').value = state.settings.appTitle ?? '';
  if (el('settingAppSubtitle')) el('settingAppSubtitle').value = state.settings.appSubtitle ?? '';
  if (el('settingPageSize')) el('settingPageSize').value = state.settings.pageSize ?? '';
  if (el('settingRecycleGCDays')) el('settingRecycleGCDays').value = state.settings.recycleGCDays ?? '';
  if (el('settingShowAudit')) el('settingShowAudit').checked = (state.settings.showAudit ?? 'true') === 'true';
  if (el('settingTlsEnabled')) el('settingTlsEnabled').checked = (state.settings.tls_enabled ?? 'false') === 'true';
  applyTheme(); applyI18n(); applyBrand();
  loadTLSStatus();
}
async function saveSettings() {
  const tlsWas = (state.settings.tls_enabled ?? 'false') === 'true';
  const body = {
    appLogo: el('settingAppLogo').value || '',
    appTitle: el('settingAppTitle').value || '',
    appSubtitle: el('settingAppSubtitle').value || '',
    pageSize: el('settingPageSize').value || '',
    recycleGCDays: el('settingRecycleGCDays').value || '',
    showAudit: String(el('settingShowAudit').checked),
    tls_enabled: String(el('settingTlsEnabled').checked),
    theme: state.settings.theme || '',
    language: state.settings.language || '',
  };
  // Global default protection mode
  body['protection_mode'] = document.querySelector('input[name="globalProtectionMode"]:checked')?.value || 'rules';
  await api('/api/settings', {method:'PUT', body:JSON.stringify(body)});
  state.settings = {...state.settings, ...body};
  applyTheme(); applyI18n(); applyBrand(); renderNamespaces(); renderRepos(); renderTags();
  if (state.manifest) { renderSummary({manifest: state.manifest, digest: state.digest, contentType: state.health?.contentType}); renderPlatforms(state.manifest); }
  closeModal('settingsModal'); toast(t('saveOK')); await refreshSidebars();
  if ((body.tls_enabled === 'true') !== tlsWas) await maybePromptRestart();
}
async function uploadLogo() {
  const file = el('settingLogoFile')?.files?.[0];
  if (!file) return;
  const form = new FormData();
  form.append('logo', file);
  const {data} = await api('/api/uploads/logo', {method:'POST', body:form});
  state.settings.appLogo = data.url;
  el('settingAppLogo').value = data.url;
  applyBrand();
  const btn = el('settingLogoFileBtn');
  if (btn) btn.textContent = t('selectFile');
  toast(t('saveOK'));
}
async function loadTLSStatus() {
  const statusEl = el('tlsCertStatus');
  const delBtn = el('tlsDeleteCertBtn');
  if (!statusEl) return;
  try {
    const {data} = await api('/api/tls/cert');
    if (!data.hasCert) {
      statusEl.textContent = t('tlsNoCert');
      if (delBtn) delBtn.classList.add('hidden-ui');
      return;
    }
    const c = data.cert || {};
    const from = c.notBefore ? new Date(c.notBefore).toLocaleString() : '-';
    const to = c.notAfter ? new Date(c.notAfter).toLocaleString() : '-';
    const sans = [...(c.dnsNames || []), ...(c.ipAddresses || [])].join(', ');
    let html = `<div><b>${esc(t('tlsSubject'))}:</b> ${esc(c.subject || '-')}</div>`;
    if (sans) html += `<div><b>SAN:</b> ${esc(sans)}</div>`;
    html += `<div><b>${esc(t('tlsValidFrom'))}:</b> ${esc(from)}</div>`;
    html += `<div style="${c.expired ? 'color:var(--danger)' : ''}"><b>${esc(t('tlsValidTo'))}:</b> ${esc(to)}${c.expired ? ' · ' + esc(t('tlsExpired')) : ''}</div>`;
    statusEl.innerHTML = html;
    if (delBtn) delBtn.classList.remove('hidden-ui');
  } catch (e) {
    statusEl.textContent = t('tlsNoCert');
    if (delBtn) delBtn.classList.add('hidden-ui');
  }
}
function readFileText(input) {
  return new Promise((resolve) => {
    const file = input?.files?.[0];
    if (!file) { resolve(''); return; }
    const reader = new FileReader();
    reader.onload = () => resolve(String(reader.result || ''));
    reader.onerror = () => resolve('');
    reader.readAsText(file);
  });
}
async function saveTLSCert() {
  let cert = el('tlsCertText').value.trim();
  let key = el('tlsKeyText').value.trim();
  if (!cert) cert = (await readFileText(el('tlsCertFile'))).trim();
  if (!key) key = (await readFileText(el('tlsKeyFile'))).trim();
  if (!cert || !key) { toast(t('tlsInvalidPair'), true); return; }
  const {data} = await api('/api/tls/cert', {method:'POST', body: JSON.stringify({cert, key})});
  closeModal('tlsCertModal');
  el('tlsCertText').value = ''; el('tlsKeyText').value = '';
  toast(t('tlsSaved'));
  await loadTLSStatus();
  if ((state.settings.tls_enabled ?? 'false') === 'true') await maybePromptRestart();
}
async function deleteTLSCert() {
  await api('/api/tls/cert', {method:'DELETE'});
  el('settingTlsEnabled').checked = false;
  state.settings.tls_enabled = 'false';
  toast(t('tlsDeleted'));
  await loadTLSStatus();
  await maybePromptRestart();
}
async function maybePromptRestart() {
  const ok = await openFormDialog({
    title: t('restartService'),
    message: t('tlsRestartConfirm'),
    submitLabel: t('restartService'),
    danger: true,
    submit: async () => ({ok: true}),
  });
  if (ok) await restartService();
}
async function restartService() {
  try {
    await api('/api/restart', {method:'POST'});
  } catch (e) {
    toast(e.code === 'tlsCertInvalid' ? t('tlsCertInvalid') : (e.message || t('restartFailed')), true);
    return;
  }
  toast(t('restarting'), false, true);
  // After restart the listener may flip protocol (HTTP<->HTTPS) on the same
  // port. Target the protocol implied by the saved tls_enabled setting and
  // redirect there once reachable.
  const wantTls = (state.settings.tls_enabled ?? 'false') === 'true';
  const target = `${wantTls ? 'https' : 'http'}://${location.host}/login.html`;
  const started = Date.now();
  const poll = async () => {
    if (Date.now() - started > 60000) { location.href = target; return; }
    try {
      // no-cors so a cross-protocol probe still resolves on success.
      await fetch(target, {mode: 'no-cors', cache: 'no-store'});
      location.href = target;
      return;
    } catch {}
    setTimeout(poll, 2000);
  };
  setTimeout(poll, 3000);
}
function updateStatusDetail() {
  const detail = el('registryStatusDetail');
  const badge = el('registryStatusBadge');
  const versionEl = el('registryVersion');
  if (!detail || !badge) return;
  if (!state.health) {
    badge.textContent = '-';
    badge.className = 'status-badge muted';
    detail.textContent = '-';
    if (versionEl) versionEl.textContent = '';
    return;
  }
  if (state.health.ok) {
    badge.textContent = `OK ${state.health.registryStatus || 200}`;
    badge.className = 'status-badge ok';
    detail.textContent = state.health.dockerDistributionApiVersion || '';
    const repoEl = el('statusRepoCount');
    const tagEl = el('statusTagCount');
    if (repoEl) repoEl.textContent = state.health.repoCount || '0';
    if (tagEl) tagEl.textContent = state.health.tagCount || '0';
    if (versionEl && state.health.dockerDistributionApiVersion) {
      versionEl.textContent = `${t('registryVersion')}: ${state.health.dockerDistributionApiVersion}`;
    } else if (versionEl) {
      versionEl.textContent = '';
    }
    return;
  }
  badge.textContent = `ERR ${state.health.registryStatus || ''}`.trim();
  badge.className = 'status-badge err';
  detail.textContent = state.health.error || 'Registry health check failed';
  if (versionEl) versionEl.textContent = '';
}
async function checkHealth() {
  try {
    const {data} = await api('/api/health');
    state.health = data;
    updateStatusDetail();
  } catch(e) {
    state.health = {ok:false, error:e.message}; updateStatusDetail(); toast(t('connectFail') + ': ' + e.message, true);
  }
}
async function fetchDiskUsage() {
  try {
    const {data} = await api('/api/disk-usage');
    el('diskRegistrySize').textContent = fmtBytes(data.registrySizeBytes || 0);
    el('diskTotalSize').textContent = fmtBytes(data.totalSizeBytes || 0);
    el('diskPendingGCSize').textContent = (data.pendingGCCount || 0) + ' · ' + fmtBytes(data.pendingGCSizeBytes || 0);
  } catch {
    el('diskRegistrySize').textContent = '?';
    el('diskTotalSize').textContent = '?';
    el('diskPendingGCSize').textContent = '?';
  }
}

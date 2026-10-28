el('themeToggleBtn').onclick = async () => { state.settings.theme = (state.settings.theme || 'dark') === 'dark' ? 'light' : 'dark'; applyTheme(); try { await api('/api/settings', {method:'PUT', body:JSON.stringify({theme: state.settings.theme})}); } catch(e) { toast(e.message, true); } };
el('languageToggleBtn').onclick = async () => { state.settings.language = (state.settings.language || 'zh') === 'zh' ? 'en' : 'zh'; applyI18n(); applyBrand(); renderNamespaces(); renderRepos(); renderTags(); try { await api('/api/settings', {method:'PUT', body:JSON.stringify({language: state.settings.language})}); } catch(e) { toast(e.message, true); } };
summaryEl.onclick = e => { const btn = e.target.closest('[data-copy]'); if (btn) copyByKind(btn.dataset.copy); };

// Settings tab switching
function switchSettingsTab(tab) {
  document.querySelectorAll('.tab-btn').forEach(b => b.classList.toggle('active', b.dataset.tab === tab));
  document.querySelectorAll('.tab-content').forEach(c => c.classList.toggle('active', c.id === 'settingsTab' + tab.charAt(0).toUpperCase() + tab.slice(1)));
}
document.querySelectorAll('.tab-btn').forEach(btn => {
  btn.addEventListener('click', () => switchSettingsTab(btn.dataset.tab));
});

el('settingsBtn').onclick = () => {
  updateStatusDetail();
  switchSettingsTab('ui');
  // The admin surfaces need different privileges:
  //   users / API tokens / webhooks -> a real administrator account (the
  //     /api/admin/{users,tokens,webhooks} routes reject the AUTH_MODE=off
  //     nil user outright);
  //   repo settings (global policy, immutable rules, GC) -> requireAdmin(),
  //     which stays open in AUTH_MODE=off because the legacy single-user
  //     model has no account to check. Gating 仓库设置 like the other tabs
  //     hid the only place global policy can be edited in that mode.
  const isAdmin = !!state.user?.isAdmin;
  const canAdminister = isAdminUser();
  const usersTab = document.querySelector('.tab-btn[data-tab="users"]');
  if (usersTab) usersTab.style.display = isAdmin ? '' : 'none';
  const adminTab = document.querySelector('.tab-btn[data-tab="admin"]');
  if (adminTab) adminTab.style.display = canAdminister ? '' : 'none';
  // Credentials (API tokens, webhooks) only exist for authenticated admins;
  // hide them with a hint instead of offering buttons that always 403.
  const credentials = el('adminCredentialsSection');
  if (credentials) credentials.classList.toggle('hidden-ui', !isAdmin);
  // In auth-off mode say explicitly which admin features are unavailable
  // instead of leaving the user to wonder where they went.
  const authOffHint = el('authOffHint');
  if (authOffHint) authOffHint.classList.toggle('hidden-ui', isAdmin);
  const authOffAdminHint = el('authOffAdminHint');
  if (authOffAdminHint) authOffAdminHint.classList.toggle('hidden-ui', isAdmin);
  const gcBtn = el('runManualGC');
  if (gcBtn) gcBtn.style.display = canAdminister ? '' : 'none';
  if (canAdminister) {
    const statsBox = el('repoStatsDetails');
    if (statsBox) { statsBox.classList.remove('hidden-ui'); loadStats(); }
    loadImmutableRules(); loadGlobalTagPolicy();
  }
  if (isAdmin) {
    loadUsers(); loadTokens(); loadWebhooks();
  }
  fetchDiskUsage();
  showModal('settingsModal');
  requestAnimationFrame(normalizeSettingsSize);
};
function normalizeSettingsSize() {
  const panel = document.querySelector('.settings-modal');
  if (!panel) return;
  const anchor = el('settingsWidthAnchor');
  if (!anchor) return;
  const tabs = [...panel.querySelectorAll('.tab-content')];
  const scroll = panel.querySelector('.modal-scroll');
  panel.style.visibility = 'hidden';

  // Step 1: measure modal-scroll's max-content width (includes its 36px
  // horizontal padding). Anchor must be >= this so that switching to a
  // shorter tab does not let modal-scroll's content shrink the panel.
  const savedDisplay = tabs.map(t => t.style.display);
  const savedWidth = tabs.map(t => t.style.width);
  tabs.forEach(tab => { tab.style.display = 'block'; tab.style.width = 'max-content'; });
  const savedScrollW = scroll.style.width;
  const savedScrollPos = scroll.style.position;
  const savedScrollLeft = scroll.style.left;
  scroll.style.position = 'absolute';
  scroll.style.left = '-9999px';
  scroll.style.width = 'max-content';
  const maxW = scroll.offsetWidth;
  scroll.style.width = savedScrollW;
  scroll.style.position = savedScrollPos;
  scroll.style.left = savedScrollLeft;
  tabs.forEach((tab, i) => { tab.style.display = savedDisplay[i]; tab.style.width = savedWidth[i]; });
  const minW = 504;
  anchor.style.minWidth = Math.min(Math.max(maxW, minW), window.innerWidth - 36) + 'px';

  // Step 2: measure height at final width
  let maxH = 0;
  tabs.forEach(tab => {
    const d = tab.style.display, h = tab.style.height, o = tab.style.overflow, f = tab.style.flex;
    tab.style.display = 'block';
    tab.style.flex = '0 0 auto';
    tab.style.height = 'auto';
    tab.style.overflow = 'visible';
    if (tab.offsetHeight > maxH) maxH = tab.offsetHeight;
    tab.style.display = d; tab.style.height = h; tab.style.overflow = o; tab.style.flex = f;
  });
  const title = panel.querySelector('.modal-title');
  const tabBar = panel.querySelector('.tab-bar');
  const foot = panel.querySelector('.modal-foot');
  const fixedH = (title?.offsetHeight || 0) + (tabBar?.offsetHeight || 0) + (foot?.offsetHeight || 0);
  const maxAllowedH = window.innerHeight - 120;
  panel.style.height = Math.min(maxH + fixedH, maxAllowedH) + 'px';

  panel.style.visibility = '';
}
function showModal(id) {
  const overlay = el(id);
  overlay.classList.remove('hidden-ui');
  document.body.style.overflow = 'hidden';
  // Announce the dialog to screen readers and move focus inside it so keyboard
  // users are not left behind on the page that opened the modal.
  overlay.setAttribute('role', 'dialog');
  overlay.setAttribute('aria-modal', 'true');
  const panel = overlay.querySelector('.modal-panel');
  if (panel) {
    if (!panel.hasAttribute('tabindex')) panel.tabIndex = -1;
    panel.focus({preventScroll: true});
  }
  overlay._prevFocus = document.activeElement;
}
function closeModal(id) {
  // While a forced password change is pending the server blocks every other
  // endpoint, so the app is deliberately left uninitialized. Dismissing the
  // profile modal would strand the user on a blank UI with no way back, so
  // the close is refused and the modal is shown again.
  if (id === 'profileModal' && state.mustChangePassword) {
    toast(t('mustChangePassword'), true, true);
    return;
  }
  const overlay = el(id);
  overlay.classList.add('hidden-ui');
  document.body.style.overflow = '';
  overlay.removeAttribute('role');
  overlay.removeAttribute('aria-modal');
  const prev = overlay._prevFocus;
  if (prev && typeof prev.focus === 'function') prev.focus({preventScroll: true});
  overlay._prevFocus = null;
}
document.addEventListener('keydown', e => {
  if (e.key === 'Escape') {
    // Escape must not bypass the forced password change either.
    if (state.mustChangePassword && el('profileModal') && !el('profileModal').classList.contains('hidden-ui')) {
      toast(t('mustChangePassword'), true, true);
      return;
    }
    document.querySelectorAll('.modal-overlay:not(.hidden-ui)').forEach(m => closeModal(m.id));
  }
});

el('userMenuBtn').onclick = (e) => { e.stopPropagation(); const d=el('userDropdown'); d.classList.toggle('hidden-ui'); el('userMenuBtn').setAttribute('aria-expanded', String(!d.classList.contains('hidden-ui'))); };
el('profileBtn').onclick = () => { el('userDropdown').classList.add('hidden-ui'); applyUser(); showModal('profileModal'); };
el('logoutBtn').onclick = logout;
el('profileCloseBtn').onclick = () => closeModal('profileModal');
el('uploadAvatarBtn').onclick = async e => { e.preventDefault(); try { await uploadAvatar(); } catch(err) { toast(err.message, true); } };
el('changePasswordBtn').onclick = async e => { e.preventDefault(); try { await changePassword(); } catch(err) { toast(err.message, true); } };
el('settingsCancelBtn').onclick = () => closeModal('settingsModal');
el('settingsSaveBtn').onclick = async e => { e.preventDefault(); try { await saveSettings(); } catch(err) { toast(err.message, true); } };
el('uploadLogoBtn').onclick = async e => { e.preventDefault(); try { await uploadLogo(); } catch(err) { toast(err.message, true); } };
el('settingAppLogo').oninput = e => { state.settings.appLogo = e.target.value; applyBrand(); };
el('settingAppTitle').oninput = e => { state.settings.appTitle = e.target.value; applyBrand(); };
el('settingAppSubtitle').oninput = e => { state.settings.appSubtitle = e.target.value; applyBrand(); };
el('runManualGC').onclick = async () => {
  const confirmed = await openFormDialog({
    title: t('runManualGC'),
    message: t('gcConfirm'),
    submitLabel: t('runManualGC'),
    danger: true,
    submit: async () => ({ok: true}),
  });
  if (!confirmed) return;
  try {
    const {data}=await api('/api/gc/run',{method:'POST'});
    const freedStr = data.freedBytes ? fmtBytes(data.freedBytes) : '0 B';
    if (data.blobError) {
      // Metadata was cleaned but storage could not be reclaimed: surface it
      // instead of claiming a successful GC.
      toast(t('gcStorageFailed',{count:data.deletedCount||0, freed: freedStr, error:data.blobError}), true, true);
    } else {
      toast(t('gcDone',{count:data.deletedCount||0, freed: freedStr}));
    }
    fetchDiskUsage();
  } catch(e) { toast(e.message, true); }
};
el('tlsUploadCertBtn').onclick = () => { showModal('tlsCertModal'); };
el('tlsCertCancelBtn').onclick = () => closeModal('tlsCertModal');
el('tlsCertSaveBtn').onclick = async e => { e.preventDefault(); try { await saveTLSCert(); } catch(err) { toast(err.message, true); } };
el('tlsDeleteCertBtn').onclick = async () => {
  const ok = await openFormDialog({ title: t('tlsDeleteCert'), message: t('tlsDeleteConfirm'), submitLabel: t('tlsDeleteCert'), danger: true, submit: async () => ({ok: true}) });
  if (!ok) return;
  try { await deleteTLSCert(); } catch(err) { toast(err.message, true); }
};
el('tlsCertFileBtn').onclick = () => el('tlsCertFile').click();
el('tlsKeyFileBtn').onclick = () => el('tlsKeyFile').click();
el('tlsCertFile').onchange = async () => { const txt = await readFileText(el('tlsCertFile')); if (txt) el('tlsCertText').value = txt.trim(); };
el('tlsKeyFile').onchange = async () => { const txt = await readFileText(el('tlsKeyFile')); if (txt) el('tlsKeyText').value = txt.trim(); };
el('settingTlsEnabled').onchange = (e) => {
  if (e.target.checked && el('tlsCertStatus').textContent === t('tlsNoCert')) {
    toast(t('tlsCertNeeded'), true);
  }
};

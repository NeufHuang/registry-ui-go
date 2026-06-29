
const state = {
  // settings is populated by loadSettings() at startup. The server fills
  // in defaults for any known key that is absent, so the frontend does not
  // need its own default dictionary.
  settings: {},
  repos: [],
  namespaces: [],
  tags: [],
  nextLast: '',
  selectedRepo: '',
  selectedTag: '',
  selectedTags: new Set(),
  selectedRepos: new Set(),
  digest: '',
  artifactType: '',
  manifest: null,
  health: null,
  user: { username: 'admin', avatar: '' },
  permissions: [],
};

const el = (id) => document.getElementById(id);
const t = (key, vars={}) => {
  const dict = i18n[state.settings.language || 'zh'] || i18n.zh;
  let v = dict[key] || i18n.zh[key] || key;
  for (const [k,val] of Object.entries(vars)) v = v.replace(`{${k}}`, val);
  return v;
};
const repoList = el('repoList');
const tagList = el('tagList');
const manifestEl = el('manifest');
const summaryEl = el('summary');
const platformsEl = el('platforms');

function getCSRFToken() {
  const match = document.cookie.match(/(?:^|;\s*)csrf_token=([^;]*)/);
  return match ? match[1] : '';
}

async function api(path, options = {}) {
  const headers = options.body && !(options.body instanceof FormData) ? {'Content-Type':'application/json'} : {};
  // Add CSRF token for state-changing methods
  const method = (options.method || 'GET').toUpperCase();
  if (method !== 'GET' && method !== 'HEAD' && method !== 'OPTIONS') {
    const token = getCSRFToken();
    if (token) headers['X-CSRF-Token'] = token;
  }
  const res = await fetch(path, { headers, ...options });
  const text = await res.text();
  let data = null;
  try { data = text ? JSON.parse(text) : null; } catch { data = text; }
  if (!res.ok) {
    const code = data && typeof data === 'object' ? data.code : null;
    const err = new Error((code && t(code) !== code ? t(code) : null) || data?.details || data?.error || text || `${res.status} ${res.statusText}`);
    err.code = code || null;
    throw err;
  }
  return { data, headers: res.headers, status: res.status };
}

function applyI18n() {
  const lang = state.settings.language || 'zh';
  document.documentElement.lang = lang === 'en' ? 'en' : 'zh-CN';
  document.querySelectorAll('[data-i18n]').forEach(n => n.textContent = t(n.dataset.i18n));
  document.querySelectorAll('[data-i18n-placeholder]').forEach(n => n.placeholder = t(n.dataset.i18nPlaceholder));
  document.querySelectorAll('[data-i18n-title]').forEach(n => { n.title = t(n.dataset.i18nTitle); n.setAttribute('aria-label', t(n.dataset.i18nTitle)); });
  const langBtn = el('languageToggleBtn'); if (langBtn) langBtn.textContent = lang === 'en' ? '中' : 'EN';
  const all = el('namespaceFilter')?.querySelector('option[value=""]');
  if (all) all.textContent = t('allNamespaces');
  updateStatusDetail();
}
function applyTheme() { document.documentElement.dataset.theme = state.settings.theme || 'dark'; const btn = el('themeToggleBtn'); if (btn) btn.textContent = (state.settings.theme || 'dark') === 'dark' ? '☀' : '◐'; }
function applyBrand() {
  const logo = (state.settings.appLogo || 'RU').trim();
  const title = (state.settings.appTitle || 'Registry UI').trim();
  const subtitle = (state.settings.appSubtitle || t('subtitle')).trim();
  const logoEl = el('appLogo');
  logoEl.innerHTML = '';
  logoEl.classList.remove('image-logo');
  let previewSrc = '';
  if (/^(https?:\/\/|data:image\/|\/)/i.test(logo)) {
    const img = document.createElement('img');
    img.src = logo; img.alt = title || 'Logo';
    logoEl.appendChild(img); logoEl.classList.add('image-logo');
    previewSrc = logo;
  } else {
    logoEl.textContent = (logo || 'RU').slice(0, 4).toUpperCase();
    previewSrc = `data:image/svg+xml,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128"><rect width="128" height="128" rx="20" fill="var(--accent,#4da3ff)"/><text x="64" y="78" text-anchor="middle" font-family="Arial" font-size="56" font-weight="700" fill="white">${esc(logo.slice(0, 2).toUpperCase() || 'RU')}</text></svg>`)}`;
  }
  el('settingAppLogo').value = logo;
  const preview = el('settingLogoPreview');
  if (preview) preview.src = previewSrc;
  el('appTitle').textContent = title || 'Registry UI';
  el('appSubtitle').textContent = subtitle || t('subtitle');
  document.title = title || 'Registry UI';
}

function applyUser() {
  const u = state.user || {username:'admin', avatar:''};
  const name = u.username || 'admin';
  const fallback = `data:image/svg+xml,${encodeURIComponent(`<svg xmlns="http://www.w3.org/2000/svg" width="128" height="128"><rect width="128" height="128" rx="32" fill="#4da3ff"/><text x="64" y="78" text-anchor="middle" font-family="Arial" font-size="56" font-weight="700" fill="white">${esc(name[0] || 'A')}</text></svg>`)}`;
  el('currentUsername').textContent = name;
  el('profileUsername').textContent = name;
  el('userAvatar').src = u.avatar || fallback;
  el('profileAvatarPreview').src = u.avatar || fallback;
}
async function loadUser() {
  const {data} = await api('/api/user');
  state.user = {...state.user, ...data};
  if (!data.isAdmin) {
    try { const {data: perms} = await api('/api/my-permissions'); state.permissions = perms || []; } catch { state.permissions = []; }
  } else {
    state.permissions = [];
  }
  applyUser();
  if (data.mustChangePassword) {
    toast(t('mustChangePassword'), true, true);
  }
}
function toast(msg, err=false, keep=false) { const b = el('toast'); b.textContent = msg; b.className = `toast ${err ? 'err' : ''}`; clearTimeout(window.__toastTimer); if (!keep) window.__toastTimer = setTimeout(() => b.classList.add('hidden'), 4500); }
function encodeRepo(repo) { return repo.split('/').map(encodeURIComponent).join('/'); }
function esc(s) { return String(s ?? '').replace(/[&<>'"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;',"'":'&#39;','"':'&quot;'}[c])); }
function fmtBytes(n) { const u=['B','KB','MB','GB','TB']; let i=0; while(n>=1024&&i<u.length-1){n/=1024;i++;} return `${n.toFixed(i?1:0)} ${u[i]}`; }
function card(k,v) { return `<div class="card"><b>${esc(k)}</b><span>${esc(v)}</span></div>`; }
function fieldRow(k, v, copyKind='') {
  const btn = copyKind ? `<button class="inline-copy" data-copy="${esc(copyKind)}" title="Copy" aria-label="Copy">⧉</button>` : '';
  return `<div class="field-row"><b>${esc(k)}</b><code>${esc(v || '-')}</code>${btn}</div>`;
}
function namespaceOf(repo) { const i = repo.indexOf('/'); return i > 0 ? repo.slice(0, i) : t('root'); }
function imageNameInNamespace(repo) { const i = repo.indexOf('/'); return i > 0 ? repo.slice(i + 1) : repo; }
function currentHost() { return window.location.host; }
function pullCommand() {
  if (!state.selectedRepo || !state.selectedTag) return '';
  if (state.artifactType === 'helm-chart') {
    return `helm pull oci://${currentHost()}/${state.selectedRepo} --version ${state.selectedTag}`;
  }
  return `docker pull ${currentHost()}/${state.selectedRepo}:${state.selectedTag}`;
}
function digestRef() { return state.selectedRepo && state.digest ? `${currentHost()}/${state.selectedRepo}@${state.digest}` : ''; }
async function copyText(text, label) { if (!text) return; try { await navigator.clipboard.writeText(text); } catch { const ta = document.createElement('textarea'); ta.value = text; document.body.appendChild(ta); ta.select(); document.execCommand('copy'); ta.remove(); } toast(`${label} ${t('copied')}`); }
function copyByKind(kind) {
  if (kind === 'pull') return copyText(pullCommand(), t('copyPull'));
  if (kind === 'digestRef') return copyText(digestRef(), t('digestRef'));
  return copyText(state.digest, t('digest'));
}

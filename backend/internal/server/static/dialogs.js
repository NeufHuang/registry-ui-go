function openDeleteConfirm({title, message, details, expected}) {
  return new Promise((resolve) => {
    const modal = el('deleteConfirmModal');
    const input = el('deleteConfirmInput');
    const ok = el('deleteConfirmOkBtn');
    const cancel = el('deleteConfirmCancelBtn');
    let settled = false;
    el('deleteConfirmTitle').textContent = title || t('deleteConfirmTitle');
    el('deleteConfirmMessage').textContent = message || '';
    el('deleteConfirmDetails').textContent = details || '';
    el('deleteConfirmInputLabel').textContent = t('confirmInputLabel', {expected});
    input.value = '';
    ok.disabled = true;
    const cleanup = (value) => {
      if (settled) return;
      settled = true;
      ok.onclick = null; cancel.onclick = null; input.oninput = null;
      document.removeEventListener('keydown', escHandler);
      closeModal('deleteConfirmModal');
      resolve(value);
    };
    const escHandler = (e) => { if (e.key === 'Escape' && !modal.classList.contains('hidden-ui')) { e.stopImmediatePropagation(); cleanup(null); } };
    document.addEventListener('keydown', escHandler);
    input.oninput = () => { ok.disabled = input.value !== expected; };
    ok.onclick = (e) => { e.preventDefault(); if (!ok.disabled) cleanup(input.value); };
    cancel.onclick = (e) => { e.preventDefault(); cleanup(null); };
    showModal('deleteConfirmModal');
    setTimeout(() => input.focus(), 0);
  });
}

function openFormDialog({title, message, fields, submitLabel, submit, danger, width}) {
  return new Promise((resolve) => {
    const modal = el('formDialogModal');
    const panel = el('formDialogPanel');
    const body = el('formDialogBody');
    const ok = el('formDialogOkBtn');
    const cancel = el('formDialogCancelBtn');
    let settled = false;
    el('formDialogTitle').textContent = title || '';
    ok.classList.toggle('danger', !!danger);
    ok.disabled = false;
    ok.textContent = submitLabel || t('save');
    cancel.textContent = t('cancel');
    if (width) panel.style.width = width; else panel.style.width = '';
    const items = Array.isArray(fields) ? fields : [];
    const inputs = {};
    let html = '';
    if (message) html += `<p class="hint">${esc(message)}</p>`;
    for (const f of items) {
      const key = f.key;
      const label = f.label || '';
      const type = f.type || 'text';
      const ph = f.placeholder != null ? f.placeholder : '';
      const val = f.value != null ? f.value : '';
      const hint = f.hint || '';
      if (type === 'checkbox') {
        const checked = val ? 'checked' : '';
        html += `<label class="switch-row"><span>${esc(label)}</span><input type="checkbox" data-fd-key="${esc(key)}" ${checked} /><span class="switch-pill" aria-hidden="true"></span></label>`;
        if (hint) html += `<p class="hint" style="margin:-2px 0 0">${esc(hint)}</p>`;
      } else if (type === 'radio') {
        const opts = f.options || [];
        const name = `fd-radio-${key}`;
        html += `<div class="fd-field"><div class="fd-label">${esc(label)}</div><div class="fd-radios">${opts.map(o => `<label class="fd-radio"><input type="radio" name="${esc(name)}" value="${esc(o.value)}" data-fd-key="${esc(key)}" ${val === o.value ? 'checked' : ''} /><span>${esc(o.label)}</span></label>`).join('')}</div></div>`;
        if (hint) html += `<p class="hint" style="margin:-2px 0 0">${esc(hint)}</p>`;
      } else {
        const min = f.min != null ? `min="${esc(String(f.min))}"` : '';
        html += `<label><span>${esc(label)}</span><input type="${esc(type)}" data-fd-key="${esc(key)}" placeholder="${esc(ph)}" value="${esc(String(val))}" ${min} autocomplete="off" readonly onfocus="this.removeAttribute('readonly')" /></label>`;
        if (hint) html += `<p class="hint" style="margin:-2px 0 0">${esc(hint)}</p>`;
      }
    }
    html += `<p class="hint fd-error" id="formDialogError" style="display:none;color:var(--danger);margin:4px 0 0"></p>`;
    html += `<div id="formDialogResult" class="fd-result" style="display:none"></div>`;
    body.innerHTML = html;
    items.forEach(f => { inputs[f.key] = body.querySelector(`[data-fd-key="${f.key}"]`); });
    const showError = (msg) => { const e = el('formDialogError'); e.textContent = msg || ''; e.style.display = msg ? 'block' : 'none'; };
    const setResult = (htmlContent) => { const r = el('formDialogResult'); r.innerHTML = htmlContent || ''; r.style.display = htmlContent ? 'block' : 'none'; };
    const readValues = () => {
      const v = {};
      for (const f of items) {
        const node = inputs[f.key];
        if (!node) continue;
        if (f.type === 'checkbox') v[f.key] = node.checked;
        else if (f.type === 'number') v[f.key] = node.value === '' ? null : Number(node.value);
        else v[f.key] = node.value;
      }
      return v;
    };
    const cleanup = (ok) => {
      if (settled) return;
      settled = true;
      okBtn.onclick = null; cancel.onclick = null;
      document.removeEventListener('keydown', escHandler);
      closeModal('formDialogModal');
      resolve(ok);
    };
    const finishSuccess = (res) => {
      showError('');
      if (res && res.resultHtml) {
        setResult(res.resultHtml);
        ok.textContent = t('close');
        ok.disabled = false;
        okBtn = ok;
        okBtn.onclick = (e) => { e.preventDefault(); cleanup(true); };
        return;
      }
      cleanup(true);
    };
    let okBtn = ok;
    const onSubmit = async () => {
      okBtn.disabled = true;
      const origText = okBtn.textContent;
      okBtn.textContent = '...';
      showError('');
      let res;
      try { res = await submit(readValues()); }
      catch (err) { res = { ok: false, error: err && err.message ? err.message : String(err) }; }
      if (res && res.ok && res.keepOpen && res.resultHtml) { finishSuccess(res); return; }
      if (res && res.ok) { cleanup(true); return; }
      showError((res && res.error) || t('error'));
      okBtn.disabled = false;
      okBtn.textContent = origText;
    };
    const escHandler = (e) => { if (e.key === 'Escape' && !modal.classList.contains('hidden-ui')) { e.stopImmediatePropagation(); cleanup(false); } };
    cancel.onclick = (e) => { e.preventDefault(); cleanup(false); };
    okBtn.onclick = (e) => { e.preventDefault(); onSubmit(); };
    document.addEventListener('keydown', escHandler);
    showModal('formDialogModal');
    setTimeout(() => { const first = items.find(f => f.type !== 'checkbox' && f.type !== 'radio'); if (first && inputs[first.key]) { const inp = inputs[first.key]; inp.focus(); const v = inp.value; if (v) { inp.setSelectionRange(v.length, v.length); } } else okBtn.focus(); }, 0);
  });
}

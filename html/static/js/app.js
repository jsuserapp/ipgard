const App = (() => {
  const base = location.pathname.replace(/\/?(login|settings)?\/?$/, '') || '';
  const STORAGE_KEY = 'ipgard.list_prefs';

  async function api(path, options = {}) {
    const res = await fetch(`${base}${path}`, {
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json', ...(options.headers || {}) },
      ...options,
    });
    const data = await res.json().catch(() => ({}));
    if (!res.ok) {
      const err = new Error(data.error || res.statusText);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  async function requireAuth() {
    try {
      await api('/api/me');
      return true;
    } catch (e) {
      if (e.status === 401) {
        location.href = `${base}/login`;
        return false;
      }
      throw e;
    }
  }

  async function logout() {
    await api('/api/logout', { method: 'POST' });
    location.href = `${base}/login`;
  }

  function fmtTime(iso) {
    if (!iso) return '-';
    const d = new Date(iso);
    return d.toLocaleString();
  }

  function fmtBytes(n) {
    if (n == null || n < 0) return '-';
    if (n < 1024) return `${n} B`;
    if (n < 1048576) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1048576).toFixed(1)} MB`;
  }

  function esc(s) {
    const el = document.createElement('span');
    el.textContent = s ?? '';
    return el.innerHTML;
  }

  function loadListPrefs() {
    try {
      const raw = localStorage.getItem(STORAGE_KEY);
      if (!raw) return { sort: 'visit_count', blocked: '', ip: '' };
      const p = JSON.parse(raw);
      return {
        sort: p.sort || 'visit_count',
        blocked: p.blocked ?? '',
        ip: p.ip || '',
      };
    } catch (_) {
      return { sort: 'visit_count', blocked: '', ip: '' };
    }
  }

  function saveListPrefs(prefs) {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(prefs));
    } catch (_) {}
  }

  function ensureToastHost() {
    let host = document.getElementById('toast-host');
    if (!host) {
      host = document.createElement('div');
      host.id = 'toast-host';
      host.setAttribute('aria-live', 'polite');
      document.body.appendChild(host);
    }
    return host;
  }

  function toast(message, type = 'info', ms = 3200) {
    const host = ensureToastHost();
    const el = document.createElement('div');
    el.className = 'toast' + (type === 'error' ? ' error' : type === 'success' ? ' success' : '');
    el.textContent = message;
    host.appendChild(el);
    setTimeout(() => {
      el.style.opacity = '0';
      el.style.transition = 'opacity 0.2s';
      setTimeout(() => el.remove(), 200);
    }, ms);
  }

  function ensureConfirmDialog() {
    let dlg = document.getElementById('app-confirm-dialog');
    if (dlg) return dlg;
    dlg = document.createElement('dialog');
    dlg.id = 'app-confirm-dialog';
    dlg.innerHTML = `
      <article>
        <header><strong id="app-confirm-title">确认</strong></header>
        <p id="app-confirm-message"></p>
        <footer>
          <button type="button" class="secondary outline btn-sm" id="app-confirm-cancel">取消</button>
          <button type="button" class="btn-sm" id="app-confirm-ok">确定</button>
        </footer>
      </article>`;
    document.body.appendChild(dlg);
    return dlg;
  }

  function confirm(opts) {
    const o = typeof opts === 'string' ? { message: opts } : opts;
    const dlg = ensureConfirmDialog();
    const titleEl = dlg.querySelector('#app-confirm-title');
    const msgEl = dlg.querySelector('#app-confirm-message');
    const okBtn = dlg.querySelector('#app-confirm-ok');
    const cancelBtn = dlg.querySelector('#app-confirm-cancel');
    titleEl.textContent = o.title || '确认操作';
    msgEl.textContent = o.message || '';
    okBtn.textContent = o.confirmText || '确定';
    okBtn.className = o.danger ? 'btn-sm contrast' : 'btn-sm';
    return new Promise((resolve) => {
      const done = (val) => {
        dlg.close();
        okBtn.onclick = null;
        cancelBtn.onclick = null;
        dlg.oncancel = null;
        resolve(val);
      };
      okBtn.onclick = () => done(true);
      cancelBtn.onclick = () => done(false);
      dlg.oncancel = () => done(false);
      dlg.showModal();
    });
  }

  function renderScannerBanner(scanner, elId) {
    const el = document.getElementById(elId);
    if (!el) return;
    if (!scanner || !scanner.scanning) {
      el.classList.add('hidden');
      return;
    }
    el.classList.remove('hidden');
    const pct = Math.round(scanner.progress || 0);
    const fileNo = scanner.file_count > 1
      ? `（${scanner.file_index}/${scanner.file_count}）`
      : '';
    const label = el.querySelector('.scan-label');
    const progress = el.querySelector('progress');
    if (label) {
      label.innerHTML =
        `正在扫描日志${fileNo}：<code>${esc(scanner.current_path || '')}</code>` +
        ` <span class="muted">${fmtBytes(scanner.bytes_read)} / ${fmtBytes(scanner.bytes_total)} · ${pct}%</span>`;
    }
    if (progress) {
      progress.value = pct;
      progress.max = 100;
    }
  }

  function debounce(fn, ms) {
    let t;
    return (...args) => {
      clearTimeout(t);
      t = setTimeout(() => fn(...args), ms);
    };
  }

  return {
    base, api, requireAuth, logout, fmtTime, fmtBytes, esc,
    renderScannerBanner, toast, confirm, loadListPrefs, saveListPrefs, debounce,
  };
})();

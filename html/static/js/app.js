const App = (() => {
  const base = location.pathname.replace(/\/?(login|settings)?\/?$/, '') || '';

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
    return `${(n / 1048576).toFixed1} MB`;
  }

  function esc(s) {
    const el = document.createElement('span');
    el.textContent = s ?? '';
    return el.innerHTML;
  }

  return { base, api, requireAuth, logout, fmtTime, fmtBytes, esc };
})();

// Transport only: no catalog decoding, state inference, storage or URL credentials.
(() => {
  const form = document.getElementById('operator-login');
  const input = document.getElementById('operator-token');
  const refresh = document.getElementById('operator-refresh');
  const forget = document.getElementById('operator-forget');
  const status = document.getElementById('operator-status');
  const view = document.getElementById('operator-view');
  let token = '';
  let pending;
  let generation = 0;
  let query = '';
  const safe = location.protocol === 'https:' ||
    ['127.0.0.1', 'localhost', '[::1]'].includes(location.hostname);
  if (!safe) {
    input.disabled = true;
    form.querySelector('button').disabled = true;
    status.textContent = 'Do not send an operator token over remote HTTP. Open this view through HTTPS or a loopback SSH tunnel.';
  }
  async function read(focusId) {
    if (!safe || !token) return;
    pending?.abort();
    const controller = new AbortController();
    pending = controller;
    const current = ++generation;
    const timeout = setTimeout(() => controller.abort(), 10000);
    view.replaceChildren();
    status.textContent = 'Reading the local catalog…';
    refresh.disabled = true;
    try {
      const reply = await fetch('/v1/ui/shell' + query, {
        headers: { 'x-koi-token': token }, cache: 'no-store',
        credentials: 'omit', redirect: 'error', signal: controller.signal,
      });
      if (!reply.ok || !reply.headers.get('content-type')?.startsWith('text/html')) {
        throw new Error('catalog unavailable');
      }
      const html = await reply.text();
      if (current !== generation) return;
      // This exact same-origin endpoint returns escaped Rust-owned components.
      const document = new DOMParser().parseFromString(html, 'text/html');
      view.replaceChildren(...document.body.childNodes);
      if (typeof focusId === 'string') {
        location.hash = focusId;
        view.querySelector('#' + focusId)?.focus();
      }
      status.textContent = 'Snapshot loaded. Refresh to read changes.';
      form.hidden = true;
      refresh.hidden = false;
      forget.hidden = false;
    } catch {
      if (current !== generation) return;
      token = '';
      view.replaceChildren();
      form.hidden = false;
      refresh.hidden = true;
      forget.hidden = true;
      status.textContent = 'Cannot read the local catalog. Check the service and token, then retry.';
    } finally {
      clearTimeout(timeout);
      if (current === generation) refresh.disabled = false;
    }
  }
  form.addEventListener('submit', event => {
    event.preventDefault();
    token = input.value;
    input.value = '';
    read();
  });
  refresh.addEventListener('click', () => read());
  view.addEventListener('submit', event => {
    if (event.target.id !== 'home-search') return;
    event.preventDefault();
    query = '?' + new URLSearchParams(new FormData(event.target)).toString();
    read('service-search');
  });
  view.addEventListener('click', event => {
    const link = event.target.closest('a[data-home-link]');
    if (!link) return;
    event.preventDefault();
    // Rust emits only relative presentation intent; never fetch an arbitrary URL.
    const href = link.getAttribute('href');
    if (!href?.startsWith('?')) return;
    const intent = new URL(href, 'https://koi.invalid/');
    query = intent.search;
    read(intent.hash === '#service-details' ? 'service-details' : 'home');
  });
  forget.addEventListener('click', () => {
    generation++;
    pending?.abort();
    token = '';
    query = '';
    input.value = '';
    view.replaceChildren();
    form.hidden = false;
    refresh.hidden = true;
    forget.hidden = true;
    status.textContent = 'Token forgotten. No catalog is displayed.';
    input.focus();
  });
  window.addEventListener('pagehide', () => {
    generation++;
    pending?.abort();
    token = '';
    query = '';
    input.value = '';
    view.replaceChildren();
    form.hidden = false;
    refresh.hidden = true;
    forget.hidden = true;
    status.textContent = 'Token forgotten. Read the catalog again to continue.';
  });
})();

// Transport only: no catalog decoding, state inference, storage or URL credentials.
(() => {
  const form = document.getElementById('operator-login');
  const input = document.getElementById('operator-token');
  const refresh = document.getElementById('operator-refresh');
  const forget = document.getElementById('operator-forget');
  const status = document.getElementById('operator-status');
  const view = document.getElementById('operator-view');
  let token = '', query = '';
  const safe = location.protocol === 'https:' ||
    ['127.0.0.1', 'localhost', '[::1]'].includes(location.hostname);
  if (!safe) {
    input.disabled = true;
    form.querySelector('button').disabled = true;
    status.textContent = 'Do not send an operator token over remote HTTP. Open this view through HTTPS or a loopback SSH tunnel.';
  }
  const reader = window.KoiRefresh.create({
    load: signal => fetch('/v1/ui/shell' + query, {
      headers: { 'x-koi-token': token }, cache: 'no-store',
      credentials: 'omit', redirect: 'error', signal,
    }),
    apply: (html, intent) => {
      window.KoiRefresh.apply(view, html, intent);
      status.textContent = 'Updating automatically every five seconds.';
      form.hidden = true;
      refresh.hidden = false;
      forget.hidden = false;
    },
    failed: (fatal, delay) => {
      if (fatal) {
        token = '';
        view.replaceChildren();
        form.hidden = false;
        refresh.hidden = true;
        forget.hidden = true;
        status.textContent = 'Operator access or response rejected. Check the token and supported service version, then sign in again.';
      } else {
        window.KoiRefresh.stale(view);
        forget.hidden = false;
        status.textContent = `Catalog unavailable; displayed evidence may be stale. Retrying in ${delay / 1000}s…`;
      }
    },
  });
  function read(focusId) {
    if (!safe || !token) return;
    return reader.read({ focusId });
  }
  form.addEventListener('submit', event => {
    event.preventDefault();
    reader.stop();
    token = input.value;
    input.value = '';
    view.replaceChildren();
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
    const href = link.getAttribute('href');
    if (!href?.startsWith('?')) return;
    const intent = new URL(href, 'https://koi.invalid/');
    query = intent.search;
    read(intent.hash === '#service-details' ? 'service-details' : 'home');
  });
  function clear(message) {
    reader.stop();
    token = '';
    query = '';
    input.value = '';
    view.replaceChildren();
    form.hidden = false;
    refresh.hidden = true;
    forget.hidden = true;
    status.textContent = message;
  }
  forget.addEventListener('click', () => {
    clear('Token forgotten. No catalog is displayed.');
    input.focus();
  });
  window.addEventListener('pagehide', () => clear('Token forgotten. Read the catalog again to continue.'));
})();

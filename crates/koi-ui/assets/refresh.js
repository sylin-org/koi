// Shared transport lifecycle and DOM mechanics only. No catalog or credentials.
(() => {
  function syncFragment() {
    // Replacing a fragment's element can clear the engine's :target match even
    // though the URL is unchanged. Derive narrow-panel visibility from that URL.
    document.documentElement.toggleAttribute('data-home-details', location.hash === '#service-details');
  }
  window.addEventListener('hashchange', syncFragment);
  function create({ load, apply, failed }) {
    let timer, pending, generation = 0, failures = 0, stopped = false;
    function stop() {
      stopped = true;
      generation++;
      clearTimeout(timer);
      pending?.abort();
    }
    async function read(intent = {}) {
      stopped = false;
      clearTimeout(timer);
      pending?.abort();
      const controller = new AbortController();
      pending = controller;
      const current = ++generation;
      const timeout = setTimeout(() => controller.abort(), 10000);
      let delay = 5000;
      try {
        const reply = await load(controller.signal);
        if (current !== generation) return;
        if (!reply.ok) {
          const error = new Error('snapshot unavailable');
          error.fatal = reply.status >= 400 && reply.status < 500 && ![408, 429].includes(reply.status);
          throw error;
        }
        if (!reply.headers.get('content-type')?.startsWith('text/html')) {
          const error = new Error('unsupported snapshot response'); error.fatal = true; throw error;
        }
        const html = await reply.text();
        if (current !== generation) return;
        apply(html, intent);
        failures = 0;
      } catch (error) {
        if (current !== generation) return;
        delay = Math.min(15000, 1000 * 2 ** Math.min(failures++, 4));
        if (error.fatal) stopped = true;
        failed(!!error.fatal, delay);
      } finally {
        clearTimeout(timeout);
        if (current === generation && !stopped) timer = setTimeout(() => read({ automatic: true }), delay);
      }
    }
    return { read, stop };
  }

  function apply(view, html, { automatic = false, focusId } = {}) {
    const rendered = new DOMParser().parseFromString(html, 'text/html');
    if (!rendered.querySelector('#home')) throw Object.assign(new Error('missing Home'), { fatal: true });
    const active = document.activeElement;
    const focused = view.contains(active);
    const rowId = active?.closest('[data-service-id]')?.getAttribute('data-service-id');
    const href = active?.getAttribute('href');
    const x = window.scrollX, y = window.scrollY;
    if (automatic) {
      // Retain actual inputs, including an unsubmitted draft/caret and checkbox.
      const form = view.querySelector('#home-search');
      if (form) rendered.querySelector('#home-search')?.replaceWith(form);
      for (const detail of view.querySelectorAll('details[open]')) {
        const key = detail.id || detail.getAttribute('data-device-id');
        if (!key) continue;
        for (const next of rendered.querySelectorAll('details')) {
          if ((next.id || next.getAttribute('data-device-id')) === key) next.open = true;
        }
      }
    }
    view.replaceChildren(...rendered.body.childNodes);
    view.removeAttribute('data-stale');
    syncFragment();
    if (focusId) {
      location.hash = focusId;
      syncFragment();
      document.getElementById(focusId)?.focus();
    } else if (automatic && focused) {
      let next = active.id ? document.getElementById(active.id) : null;
      if (!next && href) {
        next = [...view.querySelectorAll('a')].find(link => link.getAttribute('href') === href &&
          link.closest('[data-service-id]')?.getAttribute('data-service-id') === rowId);
      }
      (next || document.getElementById('home'))?.focus({ preventScroll: true });
      window.scrollTo(x, y);
    }
  }

  function stale(view) {
    view.setAttribute('data-stale', 'true');
    // Retained evidence is readable, but an old Open permission cannot be reused.
    for (const link of view.querySelectorAll('a[data-external]')) {
      link.removeAttribute('href'); link.setAttribute('aria-disabled', 'true');
    }
  }
  window.KoiRefresh = { create, apply, stale };

  // Native protocol: credentials and schema checks remain inside its Rust reader.
  const native = (location.protocol === 'koi-ui:' && location.hostname === 'localhost') ||
    (location.protocol === 'http:' && location.hostname === 'koi-ui.localhost');
  if (!native) return;
  const view = document.body;
  const status = message => { document.getElementById('catalog-status').textContent = message; };
  const reader = create({
    load: signal => fetch(location.pathname + location.search, { signal, cache: 'no-store', credentials: 'omit', redirect: 'error' }),
    apply: html => { apply(view, html, { automatic: true }); status('Updating automatically every five seconds.'); },
    failed: (fatal, delay) => {
      stale(view);
      status(fatal ? 'Cannot read this Home response. Reopen Home to retry.' : `Catalog unavailable; displayed evidence may be stale. Retrying in ${delay / 1000}s…`);
    },
  });
  reader.read({ automatic: true });
  window.addEventListener('pagehide', () => reader.stop());
  window.addEventListener('pageshow', event => { if (event.persisted) reader.read({ automatic: true }); });
})();

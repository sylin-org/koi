/* Browser session transport. Catalog truth and rendering remain in Rust. */
(() => {
  'use strict';
  const panel = document.getElementById('connect-panel');
  const form = document.getElementById('connect-form');
  const help = document.getElementById('connect-help');
  const status = document.getElementById('browser-status');
  const view = document.getElementById('operator-view');
  const disconnect = document.getElementById('disconnect-browser');
  const pointer = 'koi-browser-session-v1';
  let invitation, automatic = false;
  function takeInvitation() {
    const fragment = new URLSearchParams(location.hash.slice(1));
    if (!fragment.get('invite')) return false;
    invitation = fragment.get('invite');
    automatic = fragment.get('open') === '1';
    // The one-use capability must not survive in the visible/history URL.
    history.replaceState(null, '', location.pathname + location.search);
    return true;
  }
  takeInvitation();
  let current, query = location.search, database, stopped = false;
  const encode = bytes => btoa(String.fromCharCode(...new Uint8Array(bytes))).replaceAll('+', '-').replaceAll('/', '_').replaceAll('=', '');
  const json = async (path, body, signal) => {
    const response = await fetch(path, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body), credentials: 'omit', redirect: 'error', cache: 'no-store', signal });
    if (!response.ok) {
      const data = await response.json().catch(() => ({}));
      const error = new Error(data.message || 'Koi could not complete the connection. Try again.');
      error.status = response.status; throw error;
    }
    return response.json();
  };
  function db() {
    if (database) return Promise.resolve(database);
    return new Promise((resolve, reject) => {
      const request = indexedDB.open('koi-browser-access-v1', 1);
      request.onupgradeneeded = () => request.result.createObjectStore('keys');
      request.onerror = () => reject(new Error('This browser cannot save access. Allow site storage, then try again.'));
      request.onsuccess = () => { database = request.result; resolve(database); };
    });
  }
  async function record(action, id, value) {
    const database = await db();
    return new Promise((resolve, reject) => {
      const tx = database.transaction('keys', action === 'get' ? 'readonly' : 'readwrite');
      const store = tx.objectStore('keys');
      const request = action === 'put' ? store.put(value, id) : action === 'delete' ? store.delete(id) : store.get(id);
      let result;
      request.onsuccess = () => { result = request.result; };
      tx.oncomplete = () => resolve(result);
      tx.onerror = tx.onabort = () => reject(new Error('Browser access could not be saved. Check site storage and try again.'));
    });
  }
  async function prune() {
    const database = await db();
    return new Promise((resolve, reject) => {
      const tx = database.transaction('keys', 'readwrite');
      const cursor = tx.objectStore('keys').openCursor();
      cursor.onsuccess = () => {
        const item = cursor.result;
        if (!item) return;
        if (!item.value.expires || item.value.expires <= Date.now() / 1000) item.delete();
        item.continue();
      };
      tx.oncomplete = resolve;
      tx.onerror = tx.onabort = () => reject(new Error('Browser storage is unavailable. Allow site storage and try again.'));
    });
  }
  async function revokeCurrent() {
    const signal = AbortSignal.timeout(10000);
    const response = await fetch('/ui/disconnect', { method: 'POST', headers: await proof('/ui/disconnect', 'POST', signal), credentials: 'omit', redirect: 'error', signal });
    if (!response.ok && response.status !== 401) throw new Error('Could not disconnect from Koi. Try again when it is reachable.');
  }
  async function forget() {
    const prior = current;
    current = undefined;
    for (const storage of [sessionStorage, localStorage]) {
      if (prior && storage.getItem(pointer) === prior.id) storage.removeItem(pointer);
    }
    if (prior) await record('delete', prior.id);
  }
  async function proof(path, method = 'GET', signal) {
    const session = current;
    if (!session) throw new Error('Connect this browser first.');
    const { challenge } = await json('/ui/challenge', { session: session.id }, signal);
    const message = `koi-browser-session-v1\n${session.id}\n${challenge}\n${method}\n${path}`;
    const signature = await crypto.subtle.sign({ name: 'ECDSA', hash: 'SHA-256' }, session.key, new TextEncoder().encode(message));
    return { 'x-koi-browser': session.id, 'x-koi-challenge': challenge, 'x-koi-proof': encode(signature) };
  }
  const reader = window.KoiRefresh.create({
    load: async signal => {
      const path = '/ui/session/shell' + query;
      let headers;
      try { headers = await proof(path, 'GET', signal); }
      catch (error) {
        if ([401, 403].includes(error.status)) return new Response('', { status: 401 });
        throw error;
      }
      return fetch(path, { headers, credentials: 'omit', redirect: 'error', cache: 'no-store', signal });
    },
    apply: (html, intent) => {
      if (stopped) return;
      window.KoiRefresh.apply(view, html, intent);
      invitation = undefined;
      panel.hidden = true; disconnect.hidden = false;
      status.textContent = 'Connected · View services';
    },
    failed: (fatal, delay) => {
      if (fatal) {
        forget().catch(() => {});
        view.replaceChildren(); panel.hidden = false; disconnect.hidden = true;
        form.hidden = !invitation; help.hidden = !!invitation;
        status.textContent = invitation ? 'Previous access ended. Tap Connect to use this invitation.' : 'This browser’s access ended. Open Koi here or scan a new code to connect again.';
      } else {
        window.KoiRefresh.stale(view);
        status.textContent = `Reconnecting to Koi… Trying again in ${delay / 1000} seconds.`;
      }
    },
  });
  async function connect() {
    if (!invitation) throw new Error('Open Koi here or scan a new code to connect.');
    const button = form.querySelector('button'); button.disabled = true;
    let provisional;
    try {
      status.textContent = 'Connecting…';
      // Check storage before redeeming; an unavailable store must not spend the QR.
      const keypair = await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify']);
      provisional = encode(crypto.getRandomValues(new Uint8Array(16)));
      await record('put', provisional, { key: keypair.privateKey, expires: Date.now() / 1000 + 120 });
      const storage = document.getElementById('remember-browser').checked ? localStorage : sessionStorage;
      storage.setItem(provisional, 'storage-check'); storage.removeItem(provisional);
      const session = await json('/ui/connect', {
        invitation, public_key: encode(await crypto.subtle.exportKey('raw', keypair.publicKey)),
        label: document.getElementById('browser-label').value,
        remember: document.getElementById('remember-browser').checked,
      }, AbortSignal.timeout(10000));
      invitation = undefined;
      const prior = current;
      current = { id: session.id, key: keypair.privateKey, expires: session.expires_at };
      try {
        await record('put', session.id, current);
        storage.setItem(pointer, session.id);
      } catch (error) {
        await revokeCurrent().catch(() => {});
        await record('delete', session.id).catch(() => {});
        current = prior;
        throw new Error('This connection could not be saved. Check site storage, then open a new invitation.');
      }
      reader.read();
    } finally {
      if (provisional) await record('delete', provisional).catch(() => {});
      button.disabled = false;
    }
  }
  form.addEventListener('submit', event => { event.preventDefault(); connect().catch(error => { status.textContent = error.message; }); });
  disconnect.addEventListener('click', async () => {
    disconnect.disabled = true; reader.stop();
    try {
      try { await revokeCurrent(); } catch (error) { if (error.status !== 401) throw error; }
      await forget(); view.replaceChildren(); panel.hidden = false; form.hidden = true; help.hidden = false; disconnect.hidden = true;
      status.textContent = 'This browser is disconnected.';
    } catch (error) { status.textContent = error.message; }
    finally { disconnect.disabled = false; }
  });
  view.addEventListener('submit', event => {
    if (event.target.id !== 'home-search') return;
    event.preventDefault();
    query = '?' + new URLSearchParams(new FormData(event.target));
    history.replaceState(null, '', '/ui' + query);
    reader.read({ focusId: 'service-search' });
  });
  view.addEventListener('click', event => {
    const link = event.target.closest('a[data-home-link]');
    if (!link) return;
    const href = link.getAttribute('href');
    if (!href?.startsWith('?')) return;
    event.preventDefault();
    const intent = new URL(href, location.origin);
    query = intent.search;
    history.replaceState(null, '', '/ui' + query + intent.hash);
    reader.read({ focusId: intent.hash === '#service-details' ? 'service-details' : 'home' });
  });
  window.addEventListener('pagehide', () => { stopped = true; reader.stop(); invitation = undefined; });
  window.addEventListener('pageshow', event => { if (event.persisted && current) { stopped = false; reader.read(); } });
  async function initialize() {
    if (!window.isSecureContext || !crypto.subtle) throw new Error('Open Koi through its local address or trusted HTTPS to connect.');
    await prune();
    for (const storage of [sessionStorage, localStorage]) {
      const id = storage.getItem(pointer);
      if (!id) continue;
      current = await record('get', id);
      if (current) break;
      storage.removeItem(pointer);
    }
    if (current) { form.hidden = true; await reader.read(); return; }
    form.hidden = !invitation; help.hidden = !!invitation;
    status.textContent = invitation ? 'Ready to connect.' : 'Connect from the Koi app or scan a new invitation.';
    if (automatic && invitation && ['127.0.0.1', 'localhost', '[::1]'].includes(location.hostname)) await connect();
  }
  const start = () => initialize().catch(error => { status.textContent = error.message; });
  window.addEventListener('hashchange', () => {
    if (takeInvitation()) { query = location.search; reader.stop(); start(); }
  });
  start();
})();

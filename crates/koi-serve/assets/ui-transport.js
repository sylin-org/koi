// Transport and focus/layout only. Rust owns view state, filtering and catalog meaning.
(() => {
  const form = document.getElementById('operator-login');
  const input = document.getElementById('operator-token');
  const refresh = document.getElementById('operator-refresh');
  const forget = document.getElementById('operator-forget');
  const status = document.getElementById('operator-status');
  const view = document.getElementById('operator-view');
  const sessionControls = document.getElementById('operator-session-controls');
  const sessionHome = sessionControls.parentElement;

  // Keep the same controls/listeners while placing them before navigation.
  // Return them to the login surface before discarding an authenticated view.
  function replaceView(...nodes) {
    sessionHome.append(sessionControls);
    view.replaceChildren(...nodes);
    const slot = view.querySelector('.shell-tools');
    if (slot) slot.append(sessionControls);
    window.KoiCardFoil?.arm(view);
  }
  const narrow = window.matchMedia('(max-width: 1099px)');
  let token = '';
  let pending;
  let preferencePending;
  let mdnsPending;
  let mdnsPoll;
  let generation = 0;
  let preferenceGeneration = 0;
  let currentQuery = location.search.slice(1);
  const safe = location.protocol === 'https:' ||
    ['127.0.0.1', 'localhost', '[::1]'].includes(location.hostname);
  if (!safe) {
    input.disabled = true;
    form.querySelector('button').disabled = true;
    status.textContent = 'Do not send an operator token over remote HTTP. Open this view through HTTPS or a loopback SSH tunnel.';
  }

  function findFocus(key) {
    return key && [...view.querySelectorAll('[data-focus-key]')]
      .find(element => element.dataset.focusKey === key);
  }

  function synchronizeDialog() {
    const dialog = view.querySelector('#service-details');
    if (!dialog) return;
    if (narrow.matches && dialog.dataset.uiModal !== 'true') {
      if (dialog.open) dialog.close();
      dialog.showModal();
      dialog.dataset.uiModal = 'true';
      dialog.setAttribute('aria-modal', 'true');
    } else if (!narrow.matches && dialog.dataset.uiModal === 'true') {
      const focused = document.activeElement;
      dialog.close();
      dialog.show();
      delete dialog.dataset.uiModal;
      dialog.removeAttribute('aria-modal');
      if (focused?.isConnected) focused.focus({ preventScroll: true });
    }
  }

  async function read(query = currentQuery, intent = {}) {
    if (!safe || !token) return;
    const active = document.activeElement;
    let focusKey = intent.focusKey || active?.closest('[data-focus-key]')?.dataset.focusKey;
    let selection = typeof active?.selectionStart === 'number'
      ? [active.selectionStart, active.selectionEnd] : null;
    const previousDialog = view.querySelector('#service-details');
    const previousSelectionKey = previousDialog?.dataset.uiSelectionKey ?? previousDialog?.dataset.originKey;
    const previousOriginKey = previousDialog?.dataset.originKey;
    let scroll = [window.scrollX, window.scrollY];
    let scrollRegions = ['.table-scroll', '.details-body'].map(selector => {
      const region = view.querySelector(selector);
      return { selector, top: region?.scrollTop, left: region?.scrollLeft };
    });
    clearTimeout(mdnsPoll);
    pending?.abort();
    const controller = new AbortController();
    pending = controller;
    const current = ++generation;
    const timeout = setTimeout(() => controller.abort(), 10000);
    view.setAttribute('aria-busy', 'true');
    status.textContent = 'Reading the local catalog…';
    delete status.dataset.error;
    refresh.disabled = true;
    try {
      // Only this fixed endpoint ever receives the token. Links supply a query,
      // never a fetch destination or a catalog to interpret in JavaScript.
      const reply = await fetch('/v1/ui/shell' + (query ? `?${query}` : ''), {
        headers: { 'x-koi-token': token }, cache: 'no-store',
        credentials: 'omit', redirect: 'error', signal: controller.signal,
      });
      if (current !== generation) return;
      if (reply.status === 400) {
        status.dataset.error = 'true';
        status.textContent = 'These view settings were not accepted. Adjust the controls and retry.';
        if (!view.children.length) {
          currentQuery = '';
          history.replaceState(null, '', '/ui');
          form.hidden = true;
          refresh.hidden = false;
          forget.hidden = false;
          status.textContent = 'The requested view settings were invalid. Refresh to open the default view.';
        }
        return;
      }
      if ([401, 403].includes(reply.status)) {
        const error = new Error('operator authorization rejected');
        error.forgetToken = true;
        throw error;
      }
      if (!reply.ok) throw new Error('catalog unavailable');
      if (!reply.headers.get('content-type')?.startsWith('text/html')) {
        const error = new Error('unexpected catalog response');
        error.forgetToken = true;
        throw error;
      }
      const html = await reply.text();
      if (current !== generation) return;
      const rendered = new DOMParser().parseFromString(html, 'text/html');
      const canonical = rendered.querySelector('[data-ui-query]')?.getAttribute('data-ui-query');
      currentQuery = canonical ?? query;
      // A background/refresh request may be in flight while the operator keeps
      // typing, tabs elsewhere, or scrolls. Sample that latest interaction before
      // replacement; only explicit navigation may retain its requested focus.
      if (!intent.focus && !intent.focusKey) {
        const latest = document.activeElement;
        focusKey = latest?.closest('[data-focus-key]')?.dataset.focusKey;
        selection = typeof latest?.selectionStart === 'number'
          ? [latest.selectionStart, latest.selectionEnd] : null;
        scroll = [window.scrollX, window.scrollY];
        scrollRegions = scrollRegions.map(({ selector }) => {
          const region = view.querySelector(selector);
          return { selector, top: region?.scrollTop, left: region?.scrollLeft };
        });
      }
      window.KoiMdns?.beforeRefresh();
      replaceView(...rendered.body.childNodes);
      window.KoiMdns?.afterRefresh();
      if (rendered.title) document.title = rendered.title;
      history.replaceState(null, '', '/ui' + (currentQuery ? `?${currentQuery}` : ''));
      form.hidden = true;
      refresh.hidden = false;
      forget.hidden = false;
      const dialog = view.querySelector('#service-details');
      if (dialog) {
        // Keep Rust's selected-row key separate from the exact opening control.
        // Refresh may replace the dialog, but must not change its return target.
        const selectionKey = dialog.dataset.originKey;
        if (selectionKey) dialog.dataset.uiSelectionKey = selectionKey;
        if (intent.focus === 'dialog' && intent.focusKey) {
          dialog.dataset.originKey = intent.focusKey;
        } else if (selectionKey && selectionKey === previousSelectionKey && previousOriginKey) {
          dialog.dataset.originKey = previousOriginKey;
        }
      }
      synchronizeDialog();
      let target;
      if (intent.focus === 'dialog' && dialog) {
        target = dialog.querySelector('[data-ui-dialog-heading]') || dialog;
      } else if (intent.focus === 'heading') {
        target = view.querySelector('[data-ui-heading]');
      } else {
        target = findFocus(focusKey);
        if (!target && (focusKey || intent.focus === 'origin' || intent.focus === 'dialog')) {
          target = view.querySelector('[data-ui-form] input[name="q"]') || view.querySelector('[data-ui-heading]');
        }
      }
      if (dialog?.dataset.uiModal === 'true' && (!target || (target !== dialog && !dialog.contains(target)))) {
        target = dialog.querySelector('[data-ui-dialog-heading]') || dialog;
      }
      if (target) {
        target.focus({ preventScroll: intent.focus !== 'heading' });
        if (selection && target === findFocus(focusKey) && typeof target.setSelectionRange === 'function') {
          target.setSelectionRange(...selection);
        }
      }
      if (intent.focus !== 'heading') window.scrollTo(...scroll);
      for (const { selector, top, left } of scrollRegions) {
        if (top === undefined || (selector === '.details-body' && intent.focus === 'dialog')) continue;
        const region = view.querySelector(selector);
        if (region) {
          region.scrollTop = top;
          if (left !== undefined) region.scrollLeft = left;
        }
      }
      status.textContent = 'View updated. Refresh to read changes.';
      const live = view.querySelector('[data-mdns-live-status]');
      if (live) live.textContent = 'Live observations refresh every five seconds while this view is visible.';
    } catch (error) {
      if (current !== generation) return;
      status.dataset.error = 'true';
      const live = view.querySelector('[data-mdns-live-status]');
      if (live) live.textContent = 'Live refresh failed. These are the last observations; refresh to reconnect.';
      if (error.forgetToken) {
        token = '';
        mdnsPending?.abort();
        window.KoiMdns?.reset?.();
        replaceView();
        form.hidden = false;
        refresh.hidden = true;
        forget.hidden = true;
        status.textContent = 'Operator access was rejected. Check the service and token, then retry.';
        input.focus();
      } else {
        form.hidden = true;
        refresh.hidden = false;
        forget.hidden = false;
        status.textContent = view.children.length
          ? 'The catalog is temporarily unavailable. The last view remains visible; refresh to reconnect.'
          : 'The catalog is temporarily unavailable. Refresh to reconnect or forget this token.';
      }
    } finally {
      clearTimeout(timeout);
      if (current === generation) {
        refresh.disabled = false;
        view.removeAttribute('aria-busy');
        scheduleMdnsRead();
      }
    }
  }

  function scheduleMdnsRead() {
    clearTimeout(mdnsPoll);
    if (!token || !view.querySelector('#mdns-inspector')) return;
    mdnsPoll = setTimeout(() => {
      if (document.visibilityState === 'hidden' || window.KoiMdns?.isBusy()) scheduleMdnsRead();
      else read(currentQuery);
    }, 5000);
  }

  function follow(link) {
    const href = link.getAttribute('href');
    if (!href?.startsWith('?')) return;
    const intent = { focusKey: link.dataset.focusKey };
    if (link.hasAttribute('data-ui-tab')) intent.focus = 'heading';
    if (link.hasAttribute('data-open-details')) intent.focus = 'dialog';
    if (link.dataset.restoreFocus === 'origin') {
      intent.focus = 'origin';
      intent.focusKey = view.querySelector('#service-details')?.dataset.originKey;
    }
    read(href.slice(1), intent);
  }

  function closeDetails() {
    const close = view.querySelector('#service-details [data-ui-link][data-restore-focus="origin"]');
    if (close) follow(close);
  }

  async function updatePreference(control, change) {
    const button = control.tagName === 'BUTTON'
      ? control : control.querySelector('button[type="submit"]');
    if (!safe || !token || !button || button.disabled) return;
    const serviceId = control.dataset.serviceId;
    if (!serviceId) return;
    preferencePending?.abort();
    const controller = new AbortController();
    preferencePending = controller;
    const current = ++preferenceGeneration;
    button.disabled = true;
    delete status.dataset.error;
    status.textContent = change.working;
    const request = async (path, options = {}) => fetch(path, {
      ...options,
      headers: { 'x-koi-token': token, ...(options.headers ?? {}) },
      cache: 'no-store', credentials: 'omit', redirect: 'error', signal: controller.signal,
    });
    try {
      const currentReply = await request('/v1/preferences');
      if (current !== preferenceGeneration) return;
      if (!currentReply.ok || !currentReply.headers.get('content-type')?.startsWith('application/json')) {
        throw new Error('preferences unavailable');
      }
      const preferences = await currentReply.json();
      const existing = preferences.services?.find(record =>
        record.service_key?.kind === 'koi_service' && record.service_key.id === serviceId);
      if (preferences.mode !== 'writable' || !Number.isInteger(preferences.schema) ||
          !Number.isInteger(preferences.revision)) {
        throw new Error('preferences are read-only');
      }
      const updateReply = await request(`/v1/preferences/services/${encodeURIComponent(serviceId)}`, {
        method: 'PUT', headers: { 'content-type': 'application/json' },
        body: JSON.stringify({
          schema: preferences.schema,
          expected_revision: preferences.revision,
          service_key: { kind: 'koi_service', id: serviceId },
          favorite: Object.prototype.hasOwnProperty.call(change, 'favorite')
            ? change.favorite : existing?.favorite ?? false,
          friendly_alias: Object.prototype.hasOwnProperty.call(change, 'friendlyAlias')
            ? change.friendlyAlias : existing?.friendly_alias ?? null,
        }),
      });
      if (current !== preferenceGeneration) return;
      if (updateReply.status === 409) {
        status.dataset.error = 'true';
        status.textContent = 'Preferences changed elsewhere. Refresh the view, then try again.';
        return;
      }
      if (!updateReply.ok) throw new Error('preference update failed');
      await read(currentQuery, { focusKey: change.focusKey ?? control.dataset.focusKey });
      if (current === preferenceGeneration && token) {
        status.textContent = change.success;
      }
    } catch {
      if (current !== preferenceGeneration || controller.signal.aborted) return;
      status.dataset.error = 'true';
      status.textContent = change.failure;
    } finally {
      if (current === preferenceGeneration && button.isConnected) button.disabled = false;
    }
  }

  function toggleFavorite(button) {
    const value = button.dataset.uiFavorite;
    if (!['true', 'false'].includes(value)) return;
    const favorite = value === 'true';
    updatePreference(button, {
      favorite,
      working: favorite ? 'Adding favorite…' : 'Removing favorite…',
      success: favorite ? 'Added to favorites.' : 'Removed from favorites.',
      failure: 'Could not update the favorite. Check that this is the local operator view, then retry.',
    });
  }

  function saveAlias(form) {
    const input = form.querySelector('input[data-ui-alias]');
    if (!input) return;
    updatePreference(form, {
      friendlyAlias: input.value.trim() || null,
      focusKey: input.dataset.focusKey,
      working: 'Saving friendly name…',
      success: input.value.trim() ? 'Friendly name saved.' : 'Discovered name restored.',
      failure: 'Could not save the friendly name. Check the name and local operator view, then retry.',
    });
  }

  view.addEventListener('click', event => {
    if (event.button !== 0 || event.ctrlKey || event.metaKey || event.shiftKey || event.altKey) return;
    const favorite = event.target.closest('button[data-ui-favorite]');
    if (favorite && view.contains(favorite)) {
      event.preventDefault();
      toggleFavorite(favorite);
      return;
    }
    const copy = event.target.closest('button[data-ui-copy]');
    if (copy && view.contains(copy)) {
      event.preventDefault();
      Promise.resolve().then(() => navigator.clipboard.writeText(copy.dataset.uiCopy)).then(() => {
        if (!copy.isConnected) return;
        delete status.dataset.error;
        status.textContent = 'Address copied.';
        copy.textContent = 'Copied';
      }).catch(() => {
        status.dataset.error = 'true';
        status.textContent = 'Could not copy the address. Select it from the service details and copy it manually.';
      });
      return;
    }
    const link = event.target.closest('a[data-ui-link]');
    if (!link || !view.contains(link)) return;
    event.preventDefault();
    follow(link);
  });
  view.addEventListener('submit', event => {
    const alias = event.target.closest('form[data-ui-alias-form]');
    if (alias && view.contains(alias)) {
      event.preventDefault();
      saveAlias(alias);
      return;
    }
    const filters = event.target.closest('form[data-ui-form]');
    if (!filters || !view.contains(filters)) return;
    event.preventDefault();
    const action = filters.getAttribute('action');
    if ((action && action !== '?') || filters.method.toLowerCase() !== 'get') return;
    read(new URLSearchParams(new FormData(filters, event.submitter)).toString());
  });
  view.addEventListener('change', event => {
    if (event.target.tagName === 'SELECT') {
      event.target.closest('form[data-ui-form]')?.requestSubmit();
    }
  });
  view.addEventListener('cancel', event => {
    if (event.target.id !== 'service-details') return;
    event.preventDefault();
    closeDetails();
  }, true);
  window.addEventListener('keydown', event => {
    const dialog = view.querySelector('#service-details');
    if (!dialog) return;
    if (event.key === 'Tab' && dialog.open && dialog.matches(':modal')) {
      // Native modal inertness does not prevent Tab from reaching browser chrome.
      // Preserve normal traversal inside the dialog and wrap only its boundaries.
      const focusable = [...dialog.querySelectorAll('a[href],button,input,select,textarea,summary,[tabindex]')]
        .filter(element => !element.matches(':disabled') && element.tabIndex >= 0 &&
          !element.closest('[hidden],[inert]') && element.getClientRects().length > 0);
      const first = focusable[0];
      const last = focusable[focusable.length - 1];
      const active = document.activeElement;
      let target;
      if (!first) target = dialog.querySelector('[data-ui-dialog-heading]') || dialog;
      else if (!focusable.includes(active)) target = event.shiftKey ? last : first;
      else if (event.shiftKey && active === first) target = last;
      else if (!event.shiftKey && active === last) target = first;
      if (target) {
        event.preventDefault();
        target.focus();
      }
      return;
    }
    if (event.key !== 'Escape') return;
    event.preventDefault();
    closeDetails();
  });
  narrow.addEventListener('change', synchronizeDialog);

  function entropyHex() {
    const bytes = new Uint8Array(32);
    crypto.getRandomValues(bytes);
    return [...bytes].map(value => value.toString(16).padStart(2, '0')).join('');
  }

  async function performOperatorAction(action, values) {
    if (!safe || !token) throw new Error("Authenticate before querying the daemon.");
    const presets = {
      'just-me': [true, false, true],
      team: [true, true, true],
      organization: [false, true, false],
    };
    const request = { method: 'POST', body: values };
    const paths = {
      ui_mdns_query: '/v1/ui/mdns/query',
      certmesh_unlock: '/v1/certmesh/unlock',
      certmesh_destroy: '/v1/certmesh/destroy',
      certmesh_open_enrollment: '/v1/certmesh/open-enrollment',
      certmesh_close_enrollment: '/v1/certmesh/close-enrollment',
      certmesh_renew_self: '/v1/certmesh/renew-self',
      certmesh_invite: '/v1/certmesh/invite',
      certmesh_revoke: '/v1/certmesh/revoke',
      dns_add: '/v1/dns/add',
      dns_remove: '/v1/dns/remove',
      pond_enable: '/v1/pond',
      pond_disable: '/v1/pond',
    };
    if (action === 'certmesh_create') {
      if (values.passphrase !== values.confirm) throw new Error('The passphrases do not match.');
      const preset = presets[values.profile];
      if (!preset) throw new Error('Choose a valid Certmesh profile.');
      paths.certmesh_create = '/v1/certmesh/create';
      request.body = {
        passphrase: values.passphrase, entropy_hex: entropyHex(), operator: values.operator || null,
        enrollment_open: preset[0], requires_approval: preset[1], auto_unlock: preset[2],
      };
    }
    const target = paths[action];
    if (!target) throw new Error('This action is not available in the browser view.');
    if (action === 'dns_remove' || action === 'pond_disable') request.method = 'DELETE';
    if (action === 'pond_enable' || action === 'pond_disable') request.body = {};
    const mdnsController = action === 'ui_mdns_query' ? new AbortController() : null;
    let queryTimeout;
    if (mdnsController) {
      mdnsPending?.abort();
      mdnsPending = mdnsController;
      queryTimeout = setTimeout(() => mdnsController.abort(), 9000);
    }
    try {
    const reply = await fetch(target, {
      signal: mdnsController?.signal,
      method: request.method,
      headers: { 'x-koi-token': token, 'content-type': 'application/json' },
      body: JSON.stringify(request.body || {}), cache: 'no-store', credentials: 'omit', redirect: 'error',
    });
    const text = await reply.text();
    let result = {};
    try { result = text ? JSON.parse(text) : {}; } catch { result = {}; }
    if (!reply.ok) throw new Error(result.message || result.error || `Koi refused the change (${reply.status}).`);
    if (action === 'ui_mdns_query') {
      if (mdnsController.signal.aborted) throw new Error('The query was cancelled.');
      return result;
    }
    if (result.token) {
      return { message: `Invitation for ${result.hostname}: ${result.token}` };
    }
    return { message: result.message || 'Change applied.' };
    } finally {
      clearTimeout(queryTimeout);
      if (mdnsPending === mdnsController) mdnsPending = null;
    }
  }

  window.KoiOperator = {
    perform: performOperatorAction,
    refresh: () => read(currentQuery),
  };

  form.addEventListener('submit', event => {
    event.preventDefault();
    token = input.value;
    input.value = '';
    read(currentQuery, { focus: 'heading' });
  });
  refresh.addEventListener('click', () => read());
  forget.addEventListener('click', () => {
    generation++;
    preferenceGeneration++;
    pending?.abort();
    preferencePending?.abort();
    mdnsPending?.abort();
    clearTimeout(mdnsPoll);
    window.KoiMdns?.reset?.();
    token = '';
    input.value = '';
    replaceView();
    view.removeAttribute('aria-busy');
    form.hidden = false;
    refresh.hidden = true;
    forget.hidden = true;
    delete status.dataset.error;
    status.textContent = 'Token forgotten. No catalog is displayed.';
    input.focus();
  });
  window.addEventListener('pagehide', () => {
    generation++;
    preferenceGeneration++;
    pending?.abort();
    preferencePending?.abort();
    mdnsPending?.abort();
    clearTimeout(mdnsPoll);
    window.KoiMdns?.reset?.();
    token = '';
    input.value = '';
    replaceView();
    view.removeAttribute('aria-busy');
    form.hidden = false;
    refresh.hidden = true;
    forget.hidden = true;
    delete status.dataset.error;
    status.textContent = 'Token forgotten. Read the catalog again to continue.';
  });
})();

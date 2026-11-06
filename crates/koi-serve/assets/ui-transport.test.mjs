import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('./ui-transport.js', import.meta.url), 'utf8');
// Minimal transport seam, not a browser/layout or native acceptance simulation.
function harness({ hostname = '127.0.0.1', protocol = 'http:', search = '', narrow = false, clipboardError = false } = {}) {
  const nodes = new Map();
  const documentEvents = new Map();
  const document = {
    title: '', activeElement: null, visibilityState: 'visible',
    addEventListener: (name, handler) => documentEvents.set(name, handler),
  };
  // Deterministic clock: no test waits for, or leaks, a real timer.
  const timers = new Map();
  let now = 0;
  let timerSequence = 0;
  const fakeSetTimeout = (callback, delay = 0) => {
    const id = ++timerSequence;
    timers.set(id, { callback, at: now + Number(delay) });
    return id;
  };
  const fakeClearTimeout = id => { timers.delete(id); };
  const advance = async ms => {
    const until = now + ms;
    for (;;) {
      const [due] = [...timers].filter(([, timer]) => timer.at <= until)
        .sort(([left, a], [right, b]) => a.at - b.at || left - right);
      if (!due) break;
      timers.delete(due[0]);
      now = due[1].at;
      due[1].callback();
      await new Promise(resolve => setImmediate(resolve));
    }
    now = until;
    await new Promise(resolve => setImmediate(resolve));
  };
  const dataKey = name => name.slice(5).replace(/-([a-z])/g, (_, letter) => letter.toUpperCase());
  function matches(element, selector) {
    if (selector.includes(',')) return selector.split(',').some(part => matches(element, part));
    if (selector === ':modal') return element.open && element.modal === true;
    if (selector === ':disabled') return element.disabled;
    if (selector.startsWith('#')) return element.id === selector.slice(1);
    const bare = selector.replace(/\[[^\]]*\]/g, '');
    const classes = (element.getAttribute('class') ?? '').split(' ');
    if (![...bare.matchAll(/\.([\w-]+)/g)].every(([, name]) => classes.includes(name))) return false;
    const tag = bare.match(/^[a-z]+/)?.[0];
    if (tag && element.tagName !== tag.toUpperCase()) return false;
    return [...selector.matchAll(/\[([^=\]]+)(?:="([^"]*)")?\]/g)]
      .every(([, name, value]) => element.hasAttribute(name) && (value === undefined || element.getAttribute(name) === value));
  }
  function descendants(element) {
    return element.children.filter(child => typeof child === 'object')
      .flatMap(child => [child, ...descendants(child)]);
  }
  function element(tag = 'div', attributes = {}, children = []) {
    const result = {
      tagName: tag.toUpperCase(), value: '', defaultValue: '', hidden: false, disabled: false,
      children: [], events: new Map(), dataset: {}, attributes: new Map(),
      open: false, scrollTop: 0, scrollLeft: 0, isConnected: false,
      visible: true,
      get parentElement() { return this.parent; },
      append(child) {
        // Like a browser, moving a focused subtree drops its focus.
        if (child.isConnected && (child === document.activeElement || child.contains(document.activeElement))) {
          document.activeElement = null;
        }
        if (child.parent) child.parent.children = child.parent.children.filter(item => item !== child);
        this.children.push(child);
        child.parent = this;
        child.isConnected = true;
      },
      get tabIndex() {
        if (this.hasAttribute('tabindex')) return Number(this.getAttribute('tabindex'));
        return matches(this, 'a[href],button,input,select,textarea,summary') ? 0 : -1;
      },
      matches(selector) { return matches(this, selector); },
      getClientRects() { return this.visible ? [{}] : []; },
      addEventListener(name, handler) { this.events.set(name, handler); },
      setAttribute(name, value) {
        this.attributes.set(name, value);
        if (name.startsWith('data-')) this.dataset[dataKey(name)] = value;
        if (name === 'id') this.id = value;
        if (name === 'open') this.open = true;
      },
      getAttribute(name) { return name.startsWith('data-') ? this.dataset[dataKey(name)] ?? null : this.attributes.get(name) ?? null; },
      hasAttribute(name) { return this.getAttribute(name) !== null; },
      removeAttribute(name) { this.attributes.delete(name); if (name.startsWith('data-')) delete this.dataset[dataKey(name)]; },
      replaceChildren(...children) {
        for (const child of descendants(this)) child.isConnected = false;
        this.children = children;
        for (const child of children.filter(value => typeof value === 'object')) child.parent = this;
        for (const child of descendants(this)) child.isConnected = true;
      },
      querySelectorAll(selector) {
        if (selector.includes(' ')) {
          const [first, rest] = selector.split(' ', 2);
          return this.querySelector(first)?.querySelectorAll(rest) ?? [];
        }
        return descendants(this).filter(child => matches(child, selector));
      },
      querySelector(selector) {
        if (this.id === 'operator-login' && selector === 'button') return node('submit');
        return this.querySelectorAll(selector)[0] ?? null;
      },
      closest(selector) { return matches(this, selector) ? this : this.parent?.closest(selector) ?? null; },
      contains(child) { return descendants(this).includes(child); },
      focus() { this.focused = true; document.activeElement = this; },
      setSelectionRange(start, end) { this.selectionStart = start; this.selectionEnd = end; },
      close() { this.open = false; this.modal = false; },
      show() { this.open = true; this.modal = false; },
      showModal() { this.open = true; this.modal = true; this.modalCalls = (this.modalCalls ?? 0) + 1; },
      requestSubmit() { node('operator-view').events.get('submit')({ target: this, preventDefault() {} }); },
      method: attributes.method ?? 'get', fields: [],
    };
    for (const [name, value] of Object.entries(attributes)) result.setAttribute(name, value);
    result.replaceChildren(...children);
    return result;
  }
  function node(id) {
    if (!nodes.has(id)) nodes.set(id, element('div', { id }));
    return nodes.get(id);
  }
  document.getElementById = node;
  const session = node('operator-session-controls');
  session.replaceChildren(node('operator-refresh'), node('operator-forget'), node('operator-status'));
  element('body', {}, [node('operator-login'), session, node('operator-view')]);
  const requests = [];
  const events = new Map();
  const media = { matches: narrow, addEventListener(name, handler) { this.handler = handler; } };
  const history = { replaceState(_state, _unused, url) { this.url = url; } };
  const clipboard = [];
  const navigator = { clipboard: { async writeText(value) {
    if (clipboardError) throw new Error('clipboard unavailable');
    clipboard.push(value);
  } } };
  const window = {
    addEventListener: (name, handler) => events.set(name, handler),
    matchMedia: () => media, scrollX: 0, scrollY: 30,
    scrollTo(x, y) { this.scrollX = x; this.scrollY = y; },
  };
  let nextDocument;
  vm.runInNewContext(source, {
    document, location: { hostname, protocol, search }, window, history, navigator,
    AbortController, setTimeout: fakeSetTimeout, clearTimeout: fakeClearTimeout,
    URLSearchParams,
    FormData: class { constructor(form) { this.fields = form.fields; } [Symbol.iterator]() { return this.fields[Symbol.iterator](); } },
    DOMParser: class { parseFromString(html) {
      const body = element('body', {}, nextDocument?.elements ?? [html]);
      return { body: { childNodes: body.children }, title: nextDocument?.title ?? '', querySelector: selector => body.querySelector(selector) };
    } },
    fetch: (url, options) => new Promise((resolve, reject) => requests.push({ url, options, resolve, reject })),
  });
  const fire = async (id, event, properties = {}) => {
    node(id).events.get(event)?.({ preventDefault() {}, button: 0, ...properties });
    await new Promise(resolve => setImmediate(resolve));
  };
  const submit = async (token = 'private-test-token') => {
    node('operator-token').value = token;
    await fire('operator-login', 'submit');
  };
  const reply = async (index, { ok = true, status = ok ? 200 : 401, type = 'text/html', body = '<main>Rust output</main>', jsonBody = {}, elements, title } = {}) => {
    nextDocument = { elements, title };
    requests[index].resolve({ ok, status, headers: { get: () => type }, text: async () => body, json: async () => jsonBody });
    await new Promise(resolve => setImmediate(resolve));
  };
  return {
    node, element, document, documentEvents, window, media, history, requests, events, clipboard,
    fire, submit, reply, advance, timers,
  };
}

test('token travels only in an exact same-origin header; refresh applies Rust output', async () => {
  const h = harness();
  await h.submit();
  assert.equal(h.node('operator-token').value, '');
  assert.equal(h.requests[0].url, '/v1/ui/shell');
  assert.equal(h.requests[0].options.headers['x-koi-token'], 'private-test-token');
  assert.equal(h.requests[0].options.credentials, 'omit');
  assert.equal(h.requests[0].options.redirect, 'error');
  await h.reply(0);
  assert.deepEqual(h.node('operator-view').children, ['<main>Rust output</main>']);
  await h.fire('operator-refresh', 'click');
  assert.deepEqual(h.node('operator-view').children, ['<main>Rust output</main>']);
  assert.equal(h.node('operator-view').getAttribute('aria-busy'), 'true');
  await h.reply(1, { body: '<main>New Rust output</main>' });
  assert.deepEqual(h.node('operator-view').children, ['<main>New Rust output</main>']);
});

test('remote cleartext HTTP cannot transmit a token', async () => {
  const h = harness({ hostname: '192.0.2.1' });
  await h.submit();
  assert.equal(h.requests.length, 0);
  assert.equal(h.node('operator-token').disabled, true);
});

test('authorization and content-type failure remove stale content and forget the token', async () => {
  for (const options of [{ ok: false }, { type: 'application/json' }]) {
    const h = harness();
    await h.submit();
    await h.reply(0, options);
    assert.deepEqual(h.node('operator-view').children, []);
    assert.equal(h.node('operator-login').hidden, false);
    await h.fire('operator-refresh', 'click');
    assert.equal(h.requests.length, 1);
  }
});

test('forget and pagehide fence a late response, clear display and prevent refresh', async () => {
  for (const action of ['forget', 'pagehide']) {
    const h = harness();
    await h.submit();
    if (action === 'forget') await h.fire('operator-forget', 'click');
    else h.events.get('pagehide')();
    assert.equal(h.requests[0].options.signal.aborted, true);
    await h.reply(0);
    assert.deepEqual(h.node('operator-view').children, []);
    await h.fire('operator-refresh', 'click');
    assert.equal(h.requests.length, 1);
  }
});

test('a newer read owns the view even when an older request finishes late', async () => {
  const h = harness();
  await h.submit('old-token');
  await h.submit('new-token');
  await h.reply(1, { body: '<main>Latest</main>' });
  await h.reply(0, { body: '<main>Old</main>' });
  assert.deepEqual(h.node('operator-view').children, ['<main>Latest</main>']);
});

test('declared links transport only queries and use Rust canonical state and headings', async () => {
  const h = harness();
  const tab = h.element('a', { href: '?tab=settings', 'data-ui-link': '', 'data-ui-tab': '' });
  const external = h.element('a', { href: 'https://outside.example/?tab=settings', 'data-ui-link': '' });
  await h.submit();
  await h.reply(0, { elements: [tab, external] });
  await h.fire('operator-view', 'click', { target: external });
  await h.fire('operator-view', 'click', { target: tab, ctrlKey: true });
  assert.equal(h.requests.length, 1);
  await h.fire('operator-view', 'click', { target: tab });
  assert.equal(h.requests[1].url, '/v1/ui/shell?tab=settings');
  const heading = h.element('h1', { 'data-ui-heading': '', tabindex: '-1' });
  const shell = h.element('main', { 'data-ui-query': 'tab=settings&sort=name' }, [heading]);
  await h.reply(1, { elements: [shell], title: 'Settings · Koi' });
  assert.equal(h.document.activeElement, heading);
  assert.equal(h.document.title, 'Settings · Koi');
  assert.equal(h.history.url, '/ui?tab=settings&sort=name');
  await h.fire('operator-refresh', 'click');
  assert.equal(h.requests[2].url, '/v1/ui/shell?tab=settings&sort=name');
  await h.reply(2);
});

test('copy address writes only the declared endpoint and never transmits the token', async () => {
  const h = harness();
  const copy = h.element('button', { 'data-ui-copy': 'http://192.0.2.20:8080/path' });
  copy.textContent = 'Copy address';
  await h.submit();
  await h.reply(0, { elements: [copy] });
  await h.fire('operator-view', 'click', { target: copy });
  assert.deepEqual(h.clipboard, ['http://192.0.2.20:8080/path']);
  assert.equal(h.requests.length, 1);
  assert.equal(copy.textContent, 'Copied');
  assert.equal(h.node('operator-status').textContent, 'Address copied.');
});

test('clipboard failure remains visible and leaves the rendered view intact', async () => {
  const h = harness({ clipboardError: true });
  const copy = h.element('button', { 'data-ui-copy': 'http://192.0.2.20:8080/path' });
  await h.submit();
  await h.reply(0, { elements: [copy] });
  await h.fire('operator-view', 'click', { target: copy });
  assert.equal(h.node('operator-status').dataset.error, 'true');
  assert.match(h.node('operator-status').textContent, /Could not copy/);
  assert.equal(h.node('operator-view').children[0], copy);
  assert.equal(h.requests.length, 1);
  // A quiet automatic read keeps the failure visible.
  await h.advance(5000);
  await h.reply(1, { elements: [h.element('button', { 'data-ui-copy': 'http://192.0.2.20:8080/path' })] });
  assert.equal(h.node('operator-status').dataset.error, 'true');
  assert.match(h.node('operator-status').textContent, /Could not copy/);
});

test('favorite uses typed loopback preferences, preserves alias and refreshes in place', async () => {
  const h = harness();
  const favorite = h.element('button', {
    'data-ui-favorite': 'true', 'data-service-id': 'svc_one', 'data-focus-key': 'favorite:svc_one',
  });
  await h.submit();
  await h.reply(0, { elements: [favorite] });
  await h.fire('operator-view', 'click', { target: favorite });
  assert.equal(h.requests[1].url, '/v1/preferences');
  assert.equal(h.requests[1].options.headers['x-koi-token'], 'private-test-token');
  await h.reply(1, {
    type: 'application/json',
    jsonBody: {
      schema: 1, revision: 7, mode: 'writable',
      services: [{ service_key: { kind: 'koi_service', id: 'svc_one' }, friendly_alias: 'Workshop' }],
    },
  });
  assert.equal(h.requests[2].url, '/v1/preferences/services/svc_one');
  assert.equal(h.requests[2].options.method, 'PUT');
  assert.equal(h.requests[2].options.headers['x-koi-token'], 'private-test-token');
  assert.deepEqual(JSON.parse(h.requests[2].options.body), {
    schema: 1,
    expected_revision: 7,
    service_key: { kind: 'koi_service', id: 'svc_one' },
    favorite: true,
    friendly_alias: 'Workshop',
  });
  await h.reply(2, { type: 'application/json' });
  assert.equal(h.requests[3].url, '/v1/ui/shell');
  const updated = h.element('button', {
    'data-ui-favorite': 'false', 'data-service-id': 'svc_one', 'data-focus-key': 'favorite:svc_one',
  });
  await h.reply(3, { elements: [updated] });
  assert.equal(h.document.activeElement, updated);
  assert.equal(h.node('operator-status').textContent, 'Added to favorites.');
});

test('favorite revision conflict stays visible and retryable without guessing success', async () => {
  const h = harness();
  const favorite = h.element('button', {
    'data-ui-favorite': 'false', 'data-service-id': 'svc_conflict', 'data-focus-key': 'favorite:svc_conflict',
  });
  await h.submit();
  await h.reply(0, { elements: [favorite] });
  await h.fire('operator-view', 'click', { target: favorite });
  await h.reply(1, {
    type: 'application/json',
    jsonBody: { schema: 1, revision: 2, mode: 'writable', services: [] },
  });
  await h.reply(2, { ok: false, status: 409, type: 'application/json' });
  assert.equal(h.node('operator-status').dataset.error, 'true');
  assert.match(h.node('operator-status').textContent, /changed elsewhere/);
  assert.equal(favorite.disabled, false);
  assert.equal(h.requests.length, 3);
});

test('friendly name uses typed preferences, preserves favorite and restores input focus', async () => {
  const h = harness();
  const input = h.element('input', {
    'data-ui-alias': '', 'data-focus-key': 'alias:svc/name',
  });
  input.value = '  Workshop console  ';
  const save = h.element('button', { type: 'submit' });
  const form = h.element('form', {
    'data-ui-alias-form': '', 'data-service-id': 'svc/name',
  }, [input, save]);
  await h.submit();
  await h.reply(0, { elements: [form] });
  await h.fire('operator-view', 'submit', { target: form, submitter: save });
  assert.equal(h.requests[1].url, '/v1/preferences');
  await h.reply(1, {
    type: 'application/json',
    jsonBody: {
      schema: 1, revision: 9, mode: 'writable',
      services: [{
        service_key: { kind: 'koi_service', id: 'svc/name' },
        favorite: true,
        friendly_alias: 'Old name',
      }],
    },
  });
  assert.equal(h.requests[2].url, '/v1/preferences/services/svc%2Fname');
  assert.deepEqual(JSON.parse(h.requests[2].options.body), {
    schema: 1,
    expected_revision: 9,
    service_key: { kind: 'koi_service', id: 'svc/name' },
    favorite: true,
    friendly_alias: 'Workshop console',
  });
  await h.reply(2, { type: 'application/json' });
  const updatedInput = h.element('input', {
    'data-ui-alias': '', 'data-focus-key': 'alias:svc/name',
  });
  await h.reply(3, { elements: [updatedInput] });
  assert.equal(h.document.activeElement, updatedInput);
  assert.equal(h.node('operator-status').textContent, 'Friendly name saved.');
});

test('blank friendly name restores the discovered label without changing favorite', async () => {
  const h = harness();
  const input = h.element('input', {
    'data-ui-alias': '', 'data-focus-key': 'alias:svc_one',
  });
  input.value = '   ';
  const save = h.element('button', { type: 'submit' });
  const form = h.element('form', {
    'data-ui-alias-form': '', 'data-service-id': 'svc_one',
  }, [input, save]);
  await h.submit();
  await h.reply(0, { elements: [form] });
  await h.fire('operator-view', 'submit', { target: form, submitter: save });
  await h.reply(1, {
    type: 'application/json',
    jsonBody: {
      schema: 1, revision: 10, mode: 'writable',
      services: [{
        service_key: { kind: 'koi_service', id: 'svc_one' },
        favorite: true,
        friendly_alias: 'Old name',
      }],
    },
  });
  const body = JSON.parse(h.requests[2].options.body);
  assert.equal(body.favorite, true);
  assert.equal(body.friendly_alias, null);
  await h.reply(2, { type: 'application/json' });
  const updatedInput = h.element('input', {
    'data-ui-alias': '', 'data-focus-key': 'alias:svc_one',
  });
  await h.reply(3, { elements: [updatedInput] });
  assert.equal(h.node('operator-status').textContent, 'Discovered name restored.');
});

test('GET view forms preserve search focus and caret without interpreting fields', async () => {
  const h = harness();
  const search = h.element('input', { 'data-focus-key': 'search' });
  const filters = h.element('form', { 'data-ui-form': '', method: 'get', action: '?' }, [search]);
  filters.fields = [['tab', 'services'], ['q', 'printer & scanner'], ['sort', 'host']];
  await h.submit();
  await h.reply(0, { elements: [filters] });
  search.focus();
  search.setSelectionRange(3, 6);
  await h.fire('operator-view', 'submit', { target: filters });
  assert.equal(h.requests[1].url, '/v1/ui/shell?tab=services&q=printer+%26+scanner&sort=host');
  const nextSearch = h.element('input', { 'data-focus-key': 'search' });
  await h.reply(1, { elements: [nextSearch] });
  assert.equal(h.document.activeElement, nextSearch);
  assert.deepEqual([nextSearch.selectionStart, nextSearch.selectionEnd], [3, 6]);
  assert.equal(h.window.scrollY, 30);
  filters.setAttribute('action', 'https://outside.example/');
  h.node('operator-view').replaceChildren(filters);
  await h.fire('operator-view', 'submit', { target: filters });
  assert.equal(h.requests.length, 2);
});

test('filter changes submit the existing form as view intent', async () => {
  const h = harness();
  const select = h.element('select', { 'data-focus-key': 'state' });
  const filters = h.element('form', { 'data-ui-form': '', method: 'get' }, [select]);
  filters.fields = [['state', 'absent']];
  await h.submit();
  await h.reply(0, { elements: [filters] });
  await h.fire('operator-view', 'change', { target: select });
  assert.equal(h.requests[1].url, '/v1/ui/shell?state=absent');
  await h.reply(1);
});

test('narrow details use a modal and Escape requests Rust close state then restores the row', async () => {
  const h = harness({ narrow: true });
  const row = h.element('a', {
    href: '?selected=svc_one', 'data-ui-link': '', 'data-open-details': '', 'data-focus-key': 'service:svc_one',
  });
  await h.submit();
  await h.reply(0, { elements: [row] });
  row.focus();
  await h.fire('operator-view', 'click', { target: row });
  const heading = h.element('h2', { 'data-ui-dialog-heading': '', tabindex: '-1' });
  const close = h.element('a', { href: '?tab=services', 'data-ui-link': '', 'data-restore-focus': 'origin' });
  const dialog = h.element('dialog', { id: 'service-details', open: '', 'data-origin-key': 'service:svc_one' }, [heading, close]);
  await h.reply(1, { elements: [dialog] });
  assert.equal(dialog.modalCalls, 1);
  assert.equal(dialog.getAttribute('aria-modal'), 'true');
  assert.equal(h.document.activeElement, heading);
  h.events.get('keydown')({ key: 'Escape', preventDefault() {} });
  await new Promise(resolve => setImmediate(resolve));
  assert.equal(h.requests[2].url, '/v1/ui/shell?tab=services');
  const returnedRow = h.element('a', { 'data-focus-key': 'service:svc_one' });
  await h.reply(2, { elements: [returnedRow] });
  assert.equal(h.document.activeElement, returnedRow);
});

test('wide details remain nonmodal and resize changes only dialog modality', async () => {
  const h = harness();
  const heading = h.element('h2', { 'data-ui-dialog-heading': '' });
  const dialog = h.element('dialog', { id: 'service-details', open: '' }, [heading]);
  await h.submit();
  await h.reply(0, { elements: [dialog] });
  assert.equal(dialog.modalCalls, undefined);
  h.media.matches = true;
  h.media.handler();
  assert.equal(dialog.modalCalls, 1);
  heading.focus();
  h.media.matches = false;
  h.media.handler();
  assert.equal(dialog.open, true);
  assert.equal(dialog.getAttribute('aria-modal'), null);
  assert.equal(h.document.activeElement, heading);
  assert.equal(h.requests.length, 1);
});

test('modal Tab boundaries wrap visible enabled controls in both directions', async () => {
  const h = harness({ narrow: true });
  const heading = h.element('h2', { 'data-ui-dialog-heading': '', tabindex: '-1' });
  const disabled = h.element('button');
  disabled.disabled = true;
  const hidden = h.element('a', { href: '?hidden' });
  hidden.visible = false;
  const hiddenParent = h.element('div', { hidden: '' }, [h.element('input')]);
  const close = h.element('a', { href: '?tab=services' });
  const summary = h.element('summary');
  const skipped = h.element('button', { tabindex: '-1' });
  const inertParent = h.element('div', { inert: '' }, [h.element('textarea')]);
  const dialog = h.element('dialog', { id: 'service-details', open: '' }, [
    heading, disabled, hidden, hiddenParent, close, summary, skipped, inertParent,
  ]);
  await h.submit();
  await h.reply(0, { elements: [dialog] });
  assert.equal(dialog.matches(':modal'), true);
  const pressTab = shiftKey => {
    let prevented = false;
    h.events.get('keydown')({ key: 'Tab', shiftKey, preventDefault() { prevented = true; } });
    return prevented;
  };
  heading.focus();
  assert.equal(pressTab(false), true);
  assert.equal(h.document.activeElement, close);
  assert.equal(pressTab(false), false, 'ordinary forward traversal stays native');
  summary.focus(); // Browser's ordinary next control after close.
  assert.equal(pressTab(false), true);
  assert.equal(h.document.activeElement, close);
  assert.equal(pressTab(true), true);
  assert.equal(h.document.activeElement, summary);
  assert.equal(pressTab(true), false, 'ordinary reverse traversal stays native');
  heading.focus();
  assert.equal(pressTab(true), true);
  assert.equal(h.document.activeElement, summary);
  h.node('operator-refresh').focus();
  assert.equal(pressTab(false), true, 'a misplaced focus returns inside the modal');
  assert.equal(h.document.activeElement, close);
  assert.equal(h.requests.length, 1);
});

test('a modal without available controls keeps Tab on its heading', async () => {
  const h = harness({ narrow: true });
  const heading = h.element('h2', { 'data-ui-dialog-heading': '', tabindex: '-1' });
  const dialog = h.element('dialog', { id: 'service-details', open: '' }, [heading]);
  await h.submit();
  await h.reply(0, { elements: [dialog] });
  for (const shiftKey of [false, true]) {
    let prevented = false;
    h.events.get('keydown')({ key: 'Tab', shiftKey, preventDefault() { prevented = true; } });
    assert.equal(prevented, true);
    assert.equal(h.document.activeElement, heading);
  }
});

test('temporary daemon loss preserves the last view and reconnects without re-entering the token', async () => {
  const h = harness();
  const row = h.element('div', { 'data-focus-key': 'service:one' });
  await h.submit();
  await h.reply(0, { elements: [row] });
  await h.fire('operator-refresh', 'click');
  await h.reply(1, { ok: false, status: 503 });
  assert.equal(h.node('operator-view').children[0], row);
  assert.equal(h.node('operator-login').hidden, true);
  assert.equal(h.node('operator-refresh').hidden, false);
  assert.equal(h.node('operator-forget').hidden, false);
  assert.equal(h.node('operator-status').dataset.error, 'true');
  assert.match(h.node('operator-status').textContent, /last view is marked stale and Open is disabled; retrying in 1 s/);
  assert.equal(h.node('operator-view').getAttribute('data-stale'), 'true');

  await h.fire('operator-refresh', 'click');
  assert.equal(h.requests[2].options.headers['x-koi-token'], 'private-test-token');
  const current = h.element('div', { 'data-focus-key': 'service:one' });
  await h.reply(2, { elements: [current] });
  assert.equal(h.node('operator-view').children[0], current);
  assert.equal(h.node('operator-view').getAttribute('data-stale'), null);
  assert.equal(h.node('operator-status').dataset.error, undefined);
  assert.equal(h.node('operator-status').textContent, 'Updates automatically every five seconds.');
});

test('wide and closed details never trap Tab even if a modal marker remains', async () => {
  const h = harness();
  const close = h.element('a', { href: '?tab=services' });
  const dialog = h.element('dialog', { id: 'service-details', open: '' }, [close]);
  await h.submit();
  await h.reply(0, { elements: [dialog] });
  dialog.dataset.uiModal = 'true';
  close.focus();
  for (const closed of [false, true]) {
    if (closed) dialog.close();
    for (const shiftKey of [false, true]) {
      let prevented = false;
      h.events.get('keydown')({ key: 'Tab', shiftKey, preventDefault() { prevented = true; } });
      assert.equal(prevented, false);
      assert.equal(h.document.activeElement, close);
    }
  }
});

test('details return to the exact opener across refresh and update when another control opens them', async () => {
  const h = harness();
  const opener = key => h.element('a', {
    href: `?selected=${key.split(':')[1]}`, 'data-ui-link': '',
    'data-open-details': '', 'data-focus-key': key,
  });
  const details = id => h.element('dialog', {
    id: 'service-details', open: '', 'data-origin-key': `service:${id}`,
  }, [
    h.element('h2', { 'data-ui-dialog-heading': '' }),
    h.element('a', { href: '?tab=services', 'data-ui-link': '', 'data-restore-focus': 'origin' }),
  ]);
  const chevron = opener('details:one');
  await h.submit();
  await h.reply(0, { elements: [chevron] });
  await h.fire('operator-view', 'click', { target: chevron });
  const opened = details('one');
  await h.reply(1, { elements: [opened] });
  assert.equal(opened.dataset.originKey, 'details:one');
  await h.fire('operator-refresh', 'click');
  const refreshed = details('one');
  await h.reply(2, { elements: [refreshed] });
  assert.equal(refreshed.dataset.originKey, 'details:one');
  await h.fire('operator-view', 'click', {
    target: refreshed.querySelector('[data-restore-focus="origin"]'),
  });
  const returnedName = opener('service:one');
  const returnedChevron = opener('details:one');
  await h.reply(3, { elements: [returnedName, returnedChevron] });
  assert.equal(h.document.activeElement, returnedChevron);

  await h.fire('operator-view', 'click', { target: returnedChevron });
  const sameRowName = opener('service:one');
  await h.reply(4, { elements: [sameRowName, details('one')] });
  await h.fire('operator-view', 'click', { target: sameRowName });
  const reopened = details('one');
  const nextRow = opener('details:two');
  await h.reply(5, { elements: [nextRow, reopened] });
  assert.equal(reopened.dataset.originKey, 'service:one');
  await h.fire('operator-view', 'click', { target: nextRow });
  const switched = details('two');
  await h.reply(6, { elements: [switched] });
  assert.equal(switched.dataset.originKey, 'details:two');
  await h.fire('operator-refresh', 'click');
  const switchedRefresh = details('two');
  await h.reply(7, { elements: [switchedRefresh] });
  assert.equal(switchedRefresh.dataset.originKey, 'details:two');
});

test('invalid view input retains controls and credentials for a deliberate retry', async () => {
  const h = harness();
  await h.submit();
  await h.reply(0);
  await h.fire('operator-refresh', 'click');
  await h.reply(1, { ok: false, status: 400, type: 'text/plain' });
  assert.deepEqual(h.node('operator-view').children, ['<main>Rust output</main>']);
  assert.match(h.node('operator-status').textContent, /view settings were not accepted/);
  assert.equal(h.node('operator-login').hidden, true);
  await h.fire('operator-refresh', 'click');
  assert.equal(h.requests[2].options.headers['x-koi-token'], 'private-test-token');
  await h.reply(2);
});

test('an invalid initial query can retry the default view without an authentication loop', async () => {
  const h = harness({ search: '?tab=not-a-destination' });
  await h.submit();
  assert.equal(h.requests[0].url, '/v1/ui/shell?tab=not-a-destination');
  await h.reply(0, { ok: false, status: 400, type: 'text/plain' });
  assert.equal(h.history.url, '/ui');
  assert.equal(h.node('operator-refresh').hidden, false);
  assert.equal(h.node('operator-login').hidden, true);
  await h.fire('operator-refresh', 'click');
  assert.equal(h.requests[1].url, '/v1/ui/shell');
  assert.equal(h.requests[1].options.headers['x-koi-token'], 'private-test-token');
  await h.reply(1);
});

test('refresh preserves the actual table and details scroll regions', async () => {
  const h = harness();
  const table = h.element('div', { class: 'table-scroll' });
  const details = h.element('div', { class: 'details-body' });
  await h.submit();
  await h.reply(0, { elements: [table, details] });
  table.scrollTop = 420;
  table.scrollLeft = 12;
  details.scrollTop = 210;
  await h.fire('operator-refresh', 'click');
  const nextTable = h.element('div', { class: 'table-scroll' });
  const nextDetails = h.element('div', { class: 'details-body' });
  await h.reply(1, { elements: [nextTable, nextDetails] });
  assert.deepEqual([nextTable.scrollTop, nextTable.scrollLeft, nextDetails.scrollTop], [420, 12, 210]);
});

test('removed selection restores focus to search and cannot move focus outside a modal', async () => {
  const h = harness({ narrow: true });
  const row = h.element('a', { 'data-focus-key': 'service:removed' });
  await h.submit();
  await h.reply(0, { elements: [row] });
  row.focus();
  await h.fire('operator-refresh', 'click');
  const search = h.element('input', { name: 'q', 'data-focus-key': 'search' });
  const filters = h.element('form', { 'data-ui-form': '' }, [search]);
  await h.reply(1, { elements: [filters] });
  assert.equal(h.document.activeElement, search);
  await h.fire('operator-refresh', 'click');
  const nextSearch = h.element('input', { name: 'q', 'data-focus-key': 'search' });
  const nextFilters = h.element('form', { 'data-ui-form': '' }, [nextSearch]);
  const heading = h.element('h2', { 'data-ui-dialog-heading': '' });
  const dialog = h.element('dialog', { id: 'service-details', open: '' }, [heading]);
  await h.reply(2, { elements: [nextFilters, dialog] });
  assert.equal(h.document.activeElement, heading);
  assert.equal(nextSearch.focused, undefined);
});

test('session controls survive navigation and return to login after authorization loss', async () => {
  const h = harness();
  const controls = h.node('operator-session-controls');
  const home = controls.parentElement;
  const firstSlot = h.element('div', {class: 'shell-tools'});
  await h.submit();
  await h.reply(0, {elements: [firstSlot]});
  assert.equal(controls.parentElement, firstSlot);
  await h.fire('operator-refresh', 'click');
  const nextSlot = h.element('div', {class: 'shell-tools'});
  await h.reply(1, {elements: [nextSlot]});
  assert.equal(controls.parentElement, nextSlot);
  assert.equal(firstSlot.contains(controls), false);
  await h.fire('operator-refresh', 'click');
  await h.reply(2, {ok: false, status: 401});
  assert.equal(controls.parentElement, home);
  assert.equal(h.node('operator-view').children.length, 0);
  assert.equal(h.node('operator-status').textContent.includes('rejected'), true);
  assert.equal(h.node('operator-forget').hidden, true);
});


test('mDNS action uses the exact authenticated endpoint and preserves observed outcomes', async () => {
  const h = harness();
  await h.submit();
  await h.reply(0);
  const action = h.window.KoiOperator.perform('ui_mdns_query', {kind:'browse',value:'_ipp._tcp'});
  assert.equal(h.requests[1].url, '/v1/ui/mdns/query');
  assert.equal(h.requests[1].options.method, 'POST');
  assert.equal(h.requests[1].options.headers['x-koi-token'], 'private-test-token');
  assert.deepEqual(JSON.parse(h.requests[1].options.body), {kind:'browse',value:'_ipp._tcp'});
  const result = {outcome:'no_answer',message:'No observations in five seconds.',records:[],service_types:[],query:'_ipp._tcp',observed_at:'2026-09-13T15:00:00Z'};
  await h.reply(1, {type:'application/json',body:JSON.stringify(result)});
  assert.equal(JSON.stringify(await action), JSON.stringify(result));
  await assert.rejects(h.window.KoiOperator.perform('https://attacker.test/', {}), /not available/);
  assert.equal(h.requests.length, 2);
});

test('forget cancels an mDNS query and fences a late successful reply', async () => {
  const h = harness();
  await h.submit();
  await h.reply(0);
  let reset = 0;
  h.window.KoiMdns = {reset() { reset++; }};
  const action = h.window.KoiOperator.perform('ui_mdns_query', {kind:'requery'});
  const rejection = assert.rejects(action, /cancelled/);
  await h.fire('operator-forget', 'click');
  assert.equal(h.requests[1].options.signal.aborted, true);
  assert.equal(reset, 1);
  await h.reply(1, {type:'application/json',body:JSON.stringify({outcome:'started',message:'Started',records:[]})});
  await rejection;
  await assert.rejects(h.window.KoiOperator.perform('ui_mdns_query', {kind:'requery'}), /Authenticate/);
});


test('implicit refresh preserves focus, caret and scrolling changed while its response was pending', async () => {
  for (const moved of [false, true]) {
    const h = harness();
    const first = h.element('input', {'data-focus-key':'query-first'});
    const second = h.element('input', {'data-focus-key':'query-second'});
    const table = h.element('div', {class:'table-scroll'}, [first, second]);
    await h.submit();
    await h.reply(0, {elements:[table]});
    first.focus();
    first.setSelectionRange(1, 1);
    await h.fire('operator-refresh', 'click');
    const latest = moved ? second : first;
    latest.focus();
    latest.setSelectionRange(7, 9);
    table.scrollTop = 270;
    h.window.scrollY = 93;
    const nextFirst = h.element('input', {'data-focus-key':'query-first'});
    const nextSecond = h.element('input', {'data-focus-key':'query-second'});
    const nextTable = h.element('div', {class:'table-scroll'}, [nextFirst, nextSecond]);
    await h.reply(1, {elements:[nextTable]});
    const expected = moved ? nextSecond : nextFirst;
    assert.equal(h.document.activeElement, expected);
    assert.deepEqual([expected.selectionStart,expected.selectionEnd], [7,9]);
    assert.equal(nextTable.scrollTop,270);
    assert.equal(h.window.scrollY,93);
  }
});

test('a completed read is followed 5 s later by an automatic canonical read that keeps focus', async () => {
  const h = harness();
  const row = () => h.element('a', { href: '?selected=one', 'data-ui-link': '', 'data-focus-key': 'service:one' });
  const shell = child => h.element('main', { 'data-ui-query': 'tab=services&state=all&sort=name' }, [child]);
  const first = row();
  await h.submit();
  await h.reply(0, { elements: [shell(first)] });
  assert.equal(h.node('operator-status').textContent, 'Updates automatically every five seconds.');
  first.focus();
  await h.advance(4999);
  assert.equal(h.requests.length, 1);
  await h.advance(1);
  assert.equal(h.requests.length, 2);
  assert.equal(h.requests[1].url, '/v1/ui/shell?tab=services&state=all&sort=name');
  // Objects from the script's realm: compare their serialized shape.
  assert.equal(JSON.stringify(h.requests[1].options.headers), JSON.stringify({ 'x-koi-token': 'private-test-token' }));
  assert.equal(h.requests[1].url.includes('private-test-token'), false);
  assert.equal(h.requests[1].options.credentials, 'omit');
  // Automatic reads are quiet: no busy view, no "Reading" status, no disabled control.
  assert.equal(h.node('operator-view').getAttribute('aria-busy'), null);
  assert.equal(h.node('operator-refresh').disabled, false);
  assert.equal(h.node('operator-status').textContent, 'Updates automatically every five seconds.');
  const second = row();
  await h.reply(1, { elements: [shell(second)] });
  assert.equal(h.node('operator-view').children[0].children[0], second);
  assert.equal(h.document.activeElement, second);
  assert.equal(h.history.url, '/ui?tab=services&state=all&sort=name');

  // A focused session control survives the move into the replaced view.
  const slotted = () => shell(h.element('div', { class: 'shell-tools' }));
  await h.advance(5000);
  await h.reply(2, { elements: [slotted()] });
  h.node('operator-refresh').focus();
  await h.advance(5000);
  await h.reply(3, { elements: [slotted()] });
  assert.equal(h.document.activeElement, h.node('operator-refresh'));
});

test('temporary loss keeps a stale view, disables Open and retries at 1/2/4/8/15/15 s', async () => {
  const h = harness();
  const view = () => [
    h.element('a', { class: 'button endpoint-open', href: 'https://notes.local:8443/' }),
    h.element('button', { 'data-operator-action': 'open_url', 'data-operator-url': 'https://notes.local:8443/' }),
    h.element('div', { class: 'list-footer' }),
  ];
  const [link, native, footer] = view();
  await h.submit();
  await h.reply(0, { elements: [link, native, footer] });
  await h.advance(5000);
  assert.equal(h.requests.length, 2);
  let index = 1;
  for (const delay of [1, 2, 4, 8, 15, 15]) {
    await h.reply(index, { ok: false, status: index === 1 ? 503 : 502 });
    const status = h.node('operator-status');
    assert.equal(status.dataset.error, 'true');
    assert.equal(status.textContent, `The catalog is temporarily unavailable. The last view is marked stale and Open is disabled; retrying in ${delay} s.`);
    assert.equal(h.node('operator-view').children[0], link);
    assert.equal(h.node('operator-view').getAttribute('data-stale'), 'true');
    assert.equal(link.getAttribute('href'), null);
    assert.equal(link.getAttribute('aria-disabled'), 'true');
    assert.equal(native.disabled, true);
    await h.advance(delay * 1000 - 1);
    assert.equal(h.requests.length, index + 1, `retried before ${delay} s`);
    await h.advance(1);
    assert.equal(h.requests.length, index + 2, `no retry after ${delay} s`);
    assert.equal(h.requests[index + 1].options.headers['x-koi-token'], 'private-test-token');
    index++;
  }
  const fresh = view();
  await h.reply(index, { elements: fresh });
  assert.equal(h.node('operator-view').getAttribute('data-stale'), null);
  assert.equal(fresh[0].getAttribute('href'), 'https://notes.local:8443/');
  assert.equal(fresh[1].disabled, false);
  assert.equal(h.node('operator-status').dataset.error, undefined);
  assert.equal(h.node('operator-status').textContent, 'Updates automatically every five seconds.');
  // A recovered connection starts its next outage from the first backoff step.
  await h.advance(5000);
  await h.reply(index + 1, { ok: false, status: 503 });
  assert.match(h.node('operator-status').textContent, /retrying in 1 s\.$/);
});

test('a network error or missed deadline is temporary, not an authorization failure', async () => {
  const h = harness();
  await h.submit();
  await h.reply(0);
  await h.advance(5000);
  h.requests[1].reject(new TypeError('network unreachable'));
  await new Promise(resolve => setImmediate(resolve));
  assert.match(h.node('operator-status').textContent, /retrying in 1 s/);
  await h.advance(1000);
  assert.equal(h.requests.length, 3);
  await h.advance(10000);
  assert.equal(h.requests[2].options.signal.aborted, true);
  h.requests[2].reject(new DOMException('The operation was aborted.', 'AbortError'));
  await new Promise(resolve => setImmediate(resolve));
  assert.match(h.node('operator-status').textContent, /retrying in 2 s/);
  assert.deepEqual(h.node('operator-view').children, ['<main>Rust output</main>']);
});

test('authorization loss during an automatic read clears the view and stops refreshing', async () => {
  for (const options of [{ ok: false, status: 401 }, { ok: false, status: 403 }, { type: 'application/json' }]) {
    const h = harness();
    await h.submit();
    await h.reply(0, { elements: [h.element('div', { 'data-focus-key': 'service:one' })] });
    await h.advance(5000);
    assert.equal(h.requests.length, 2);
    await h.reply(1, options);
    assert.deepEqual(h.node('operator-view').children, []);
    assert.equal(h.node('operator-login').hidden, false);
    assert.equal(h.node('operator-view').getAttribute('data-stale'), null);
    assert.match(h.node('operator-status').textContent, /rejected/);
    assert.equal(h.timers.size, 0);
    await h.advance(60000);
    assert.equal(h.requests.length, 2);
  }
});

test('a rejected automatic read stops scheduling instead of retrying', async () => {
  for (const status of [400, 404]) {
    const h = harness();
    await h.submit();
    await h.reply(0);
    await h.advance(5000);
    await h.reply(1, { ok: false, status, type: 'text/plain' });
    assert.deepEqual(h.node('operator-view').children, ['<main>Rust output</main>']);
    assert.equal(h.node('operator-login').hidden, true);
    assert.equal(h.timers.size, 0);
    await h.advance(60000);
    assert.equal(h.requests.length, 2);
    h.documentEvents.get('visibilitychange')();
    await h.advance(60000);
    assert.equal(h.requests.length, 2, 'showing the page again does not resume');
    await h.fire('operator-refresh', 'click');
    assert.equal(h.requests.length, 3, 'a deliberate refresh still works');
    await h.reply(2);
    await h.advance(5000);
    assert.equal(h.requests.length, 4, 'and resumes automatic reads');
  }
});

test('an unsent search draft or a focused field is never replaced by an automatic read', async () => {
  const h = harness();
  const search = h.element('input', { name: 'q', 'data-focus-key': 'search' });
  // A select without a declared default starts on its first option: no draft.
  const profile = h.element('select', { name: 'profile' });
  profile.options = [{ selected: true, defaultSelected: false }, { selected: false, defaultSelected: false }];
  const filters = h.element('form', { 'data-ui-form': '', method: 'get' }, [search, profile]);
  await h.submit();
  await h.reply(0, { elements: [filters] });
  search.focus();
  await h.advance(15000);
  assert.equal(h.requests.length, 1, 'a focused field defers the read');
  search.value = 'prin';
  search.setSelectionRange(4, 4);
  await h.advance(15000);
  assert.equal(h.requests.length, 1);
  h.document.activeElement = null;
  await h.advance(15000);
  assert.equal(h.requests.length, 1, 'an unfocused draft is still kept');
  assert.equal(h.node('operator-view').children[0], filters);
  assert.equal(search.value, 'prin');
  assert.deepEqual([search.selectionStart, search.selectionEnd], [4, 4]);
  search.value = search.defaultValue;
  await h.advance(5000);
  assert.equal(h.requests.length, 2, 'refresh resumes once no draft remains');
  await h.reply(1);
});

test('pending operator actions and busy mDNS queries defer automatic reads', async () => {
  const h = harness();
  await h.submit();
  await h.reply(0);
  const action = h.window.KoiOperator.perform('dns_add', { name: 'notes', ip: '192.0.2.40' });
  await h.advance(10000);
  assert.equal(h.requests.length, 2, 'only the action request is in flight');
  await h.reply(1, { type: 'application/json', body: '{"message":"Added."}' });
  assert.equal(JSON.stringify(await action), JSON.stringify({ message: 'Added.' }));
  let busy = true;
  h.window.KoiMdns = { isBusy: () => busy, beforeRefresh() {}, afterRefresh() {}, reset() {} };
  await h.advance(10000);
  assert.equal(h.requests.length, 2);
  busy = false;
  await h.advance(5000);
  assert.equal(h.requests.length, 3);
  assert.equal(h.requests[2].url, '/v1/ui/shell');
});

test('a hidden page defers reads; becoming visible reads at once', async () => {
  const h = harness();
  await h.submit();
  await h.reply(0);
  h.document.visibilityState = 'hidden';
  await h.advance(30000);
  assert.equal(h.requests.length, 1);
  h.document.visibilityState = 'visible';
  h.documentEvents.get('visibilitychange')();
  await h.advance(0);
  assert.equal(h.requests.length, 2);
  await h.reply(1);
});

test('forget and pagehide cancel the pending automatic read', async () => {
  for (const action of ['forget', 'pagehide']) {
    const h = harness();
    await h.submit();
    await h.reply(0);
    assert.equal(h.timers.size, 1, 'an automatic read is scheduled');
    if (action === 'forget') await h.fire('operator-forget', 'click');
    else h.events.get('pagehide')();
    assert.equal(h.timers.size, 0, action);
    await h.advance(60000);
    assert.equal(h.requests.length, 1, action);
    h.documentEvents.get('visibilitychange')();
    await h.advance(1000);
    assert.equal(h.requests.length, 1, `${action} then visible`);
  }
});

test('automatic reads keep disclosures the operator opened', async () => {
  const h = harness();
  const disclosure = () => h.element('details', { class: 'identity-details' }, [h.element('summary')]);
  const first = disclosure();
  await h.submit();
  await h.reply(0, { elements: [first] });
  first.setAttribute('open', '');
  await h.advance(5000);
  const next = disclosure();
  await h.reply(1, { elements: [next] });
  assert.equal(next.open, true);
});

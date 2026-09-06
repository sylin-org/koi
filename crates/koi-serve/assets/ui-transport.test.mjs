import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('./ui-transport.js', import.meta.url), 'utf8');
const refreshSource = await readFile(new URL('../../koi-ui/assets/refresh.js', import.meta.url), 'utf8');
// Minimal transport seam, not a browser/layout or native acceptance simulation.
function harness({ hostname = '127.0.0.1', protocol = 'http:' } = {}) {
  const nodes = new Map();
  function node(id) {
    if (!nodes.has(id)) nodes.set(id, {
      value: '', hidden: false, disabled: false, children: [], events: new Map(),
      addEventListener(name, handler) { this.events.set(name, handler); },
      replaceChildren(...children) { this.children = children; },
      querySelector() { return node('submit'); },
      focus() { this.focused = true; },
    });
    return nodes.get(id);
  }
  const requests = [];
  const events = new Map();
  const timers = new Map();
  let timerId = 0;
  const context = vm.createContext({
    document: { getElementById: node }, location: { hostname, protocol },
    window: { addEventListener: (name, handler) => events.set(name, handler) },
    AbortController, URL, URLSearchParams,
    setTimeout: (callback, delay) => { timers.set(++timerId, { callback, delay }); return timerId; },
    clearTimeout: id => timers.delete(id),
    FormData: class { constructor(form) { return form.fields; } },
    DOMParser: class { parseFromString(html) { return { body: { childNodes: [html] } }; } },
    fetch: (url, options) => new Promise((resolve, reject) => requests.push({ url, options, resolve, reject })),
  });
  vm.runInContext(refreshSource, context);
  // DOM application is a separate seam; this suite exercises the real scheduler,
  // request headers, recovery and intent rather than emulating browser layout.
  context.window.KoiRefresh.apply = (view, html) => { view.replaceChildren(html); view.stale = false; };
  context.window.KoiRefresh.stale = view => { view.stale = true; };
  vm.runInContext(source, context);
  const fire = async (id, event, detail = {}) => {
    node(id).events.get(event)?.({ preventDefault() {}, ...detail });
    await new Promise(resolve => setImmediate(resolve));
  };
  const submit = async (token = 'private-test-token') => {
    node('operator-token').value = token;
    await fire('operator-login', 'submit');
  };
  const reply = async (index, { ok = true, status = ok ? 200 : 401, type = 'text/html', body = '<main>Rust output</main>' } = {}) => {
    requests[index].resolve({ ok, status, headers: { get: () => type }, text: async () => body });
    await new Promise(resolve => setImmediate(resolve));
  };
  const tick = async delay => {
    const next = [...timers].find(([, timer]) => timer.delay === delay);
    assert.ok(next, `expected a ${delay}ms timer`);
    timers.delete(next[0]); next[1].callback();
    await new Promise(resolve => setImmediate(resolve));
  };
  return { node, requests, events, fire, submit, reply, tick, timers };
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
  await h.reply(1, { body: '<main>New Rust output</main>' });
  assert.deepEqual(h.node('operator-view').children, ['<main>New Rust output</main>']);
});

test('search, selection, clear and refresh carry intent without decoding the catalog', async () => {
  const h = harness();
  await h.submit();
  await h.reply(0);
  await h.fire('operator-view', 'submit', { target: { id: 'home-search', fields: [['search', 'Office web'], ['favorites', '1']] } });
  assert.equal(h.requests[1].url, '/v1/ui/shell?search=Office+web&favorites=1');
  await h.reply(1);
  const target = href => ({ closest: () => ({ getAttribute: () => href }) });
  await h.fire('operator-view', 'click', { target: target('?search=Office+web&favorites=1&selected=notes#service-details') });
  assert.equal(h.requests[2].url, '/v1/ui/shell?search=Office+web&favorites=1&selected=notes');
  await h.reply(2);
  await h.fire('operator-refresh', 'click');
  assert.equal(h.requests[3].url, h.requests[2].url);
  await h.reply(3);
  await h.fire('operator-view', 'click', { target: target('?search=&selected=notes#service-details') });
  assert.equal(h.requests[4].url, '/v1/ui/shell?search=&selected=notes');
  await h.reply(4);
  await h.fire('operator-view', 'click', { target: target('https://attacker.invalid/?search=x') });
  assert.equal(h.requests.length, 5, 'cannot send the token to a catalog-supplied destination');
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

test('automatic refresh retries transient loss with the same intent and restores fresh output', async () => {
  const h = harness();
  await h.submit(); await h.reply(0);
  await h.fire('operator-view', 'submit', { target: { id: 'home-search', fields: [['search', 'office'], ['selected', 'notes']] } });
  await h.reply(1, { body: '<main>Notes selected</main>' });
  await h.tick(5000);
  assert.equal(h.requests[2].url, h.requests[1].url);
  assert.equal(h.timers.size, 1, 'only request deadline while read is in flight');
  await h.reply(2, { ok: false, status: 503 });
  assert.deepEqual(h.node('operator-view').children, ['<main>Notes selected</main>']);
  assert.equal(h.node('operator-view').stale, true);
  assert.match(h.node('operator-status').textContent, /Retrying/);
  await h.tick(1000);
  assert.equal(h.requests[3].url, h.requests[1].url);
  assert.equal(h.requests[3].options.headers['x-koi-token'], 'private-test-token');
  await h.reply(3, { body: '<main>Restarted daemon, absent favorite retained</main>' });
  assert.equal(h.node('operator-view').stale, false);
  assert.match(h.node('operator-status').textContent, /automatically/);
  assert.deepEqual([...h.timers.values()].map(timer => timer.delay), [5000]);
  await h.fire('operator-forget', 'click');
  assert.equal(h.timers.size, 0);
});

test('retry delay is bounded and authorization rejection ends automatic reads', async () => {
  const h = harness();
  await h.submit();
  for (const [index, delay] of [1000, 2000, 4000, 8000, 15000, 15000].entries()) {
    await h.reply(index, { ok: false, status: 503 });
    await h.tick(delay);
  }
  await h.reply(6, { ok: false, status: 403 });
  assert.equal(h.timers.size, 0);
  assert.deepEqual(h.node('operator-view').children, []);
  await h.fire('operator-refresh', 'click');
  assert.equal(h.requests.length, 7);
});

test('pagehide during automatic refresh aborts and fences its eventual response', async () => {
  const h = harness();
  await h.submit(); await h.reply(0); await h.tick(5000);
  h.events.get('pagehide')();
  assert.equal(h.requests[1].options.signal.aborted, true);
  await h.reply(1);
  assert.equal(h.timers.size, 0);
  assert.deepEqual(h.node('operator-view').children, []);
});

test('a timed-out read is aborted and retried without scheduling overlapping polls', async () => {
  const h = harness();
  await h.submit();
  h.requests[0].options.signal.addEventListener('abort', () => h.requests[0].reject(new Error('aborted')));
  await h.tick(10000);
  assert.equal(h.requests[0].options.signal.aborted, true);
  assert.deepEqual([...h.timers.values()].map(timer => timer.delay), [1000]);
  await h.tick(1000);
  assert.equal(h.requests.length, 2);
  await h.reply(1);
  assert.deepEqual([...h.timers.values()].map(timer => timer.delay), [5000]);
});

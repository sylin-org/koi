import test from 'node:test';
import assert from 'node:assert/strict';
import { readFile } from 'node:fs/promises';
import vm from 'node:vm';

const source = await readFile(new URL('./ui-transport.js', import.meta.url), 'utf8');
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
  vm.runInNewContext(source, {
    document: { getElementById: node }, location: { hostname, protocol },
    window: { addEventListener: (name, handler) => events.set(name, handler) },
    AbortController, setTimeout, clearTimeout,
    DOMParser: class { parseFromString(html) { return { body: { childNodes: [html] } }; } },
    fetch: (url, options) => new Promise((resolve, reject) => requests.push({ url, options, resolve, reject })),
  });
  const fire = async (id, event) => {
    node(id).events.get(event)?.({ preventDefault() {} });
    await new Promise(resolve => setImmediate(resolve));
  };
  const submit = async (token = 'private-test-token') => {
    node('operator-token').value = token;
    await fire('operator-login', 'submit');
  };
  const reply = async (index, { ok = true, type = 'text/html', body = '<main>Rust output</main>' } = {}) => {
    requests[index].resolve({ ok, headers: { get: () => type }, text: async () => body });
    await new Promise(resolve => setImmediate(resolve));
  };
  return { node, requests, events, fire, submit, reply };
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
  assert.deepEqual(h.node('operator-view').children, []);
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

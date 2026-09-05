// Offline Chromium component smoke, not installed WebKit/native acceptance.
// Only generated HTML in this experiment's target directory may be loaded.
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';

const root = path.dirname(fileURLToPath(import.meta.url));
const input = await realpath(process.argv[2]);
const target = await realpath(path.join(root, 'target'));
assert.ok(input.startsWith(target + path.sep) && input.endsWith('.html'));
const profile = await mkdtemp(path.join(tmpdir(), 'koi-renderer-chromium-'));
const browser = spawn('chromium', [
  '--headless', '--remote-debugging-pipe', '--no-first-run',
  '--disable-background-networking', '--disable-component-update',
  `--user-data-dir=${profile}`, 'about:blank',
], { stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'] });
browser.stderr.resume();
let sequence = 0;
let buffer = '';
const pending = new Map();
browser.stdio[4].on('data', chunk => {
  buffer += chunk.toString();
  while (buffer.includes('\0')) {
    const end = buffer.indexOf('\0');
    const message = JSON.parse(buffer.slice(0, end));
    buffer = buffer.slice(end + 1);
    const waiter = pending.get(message.id);
    if (waiter) {
      pending.delete(message.id);
      clearTimeout(waiter.timer);
      if (message.error) waiter.reject(new Error(JSON.stringify(message.error)));
      else waiter.resolve(message.result);
    }
  }
});
function call(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`CDP timeout: ${method}`));
    }, 15000);
    pending.set(id, { resolve, reject, timer });
    browser.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + '\0');
  });
}
try {
  const { targetId } = await call('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await call('Target.attachToTarget', { targetId, flatten: true });
  const page = (method, params) => call(method, params, sessionId);
  await page('Emulation.setDeviceMetricsOverride', {
    width: 320, height: 900, deviceScaleFactor: 1, mobile: false,
  });
  await page('Emulation.setEmulatedMedia', {
    features: [{ name: 'prefers-reduced-motion', value: 'reduce' }],
  });
  await page('Network.enable');
  await page('Network.emulateNetworkConditions', {
    offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0,
  });
  await page('Page.navigate', { url: pathToFileURL(input).href });
  await page('Runtime.evaluate', {
    expression: `new Promise(resolve => {
      const ready = () => Promise.all([...document.images].map(image => image.decode().catch(() => {}))).then(resolve);
      if (document.readyState === 'complete') ready(); else window.addEventListener('load', ready, {once:true});
    })`, awaitPromise: true,
  });
  const { result, exceptionDetails } = await page('Runtime.evaluate', {
    expression: `(() => {
      const nav = [...document.querySelectorAll('nav a')];
      return {
        width: innerWidth, documentWidth: document.documentElement.scrollWidth,
        clippedText: [...document.querySelectorAll('main p, .service-row strong')].filter(p => {
          const range = document.createRange(); range.selectNodeContents(p);
          return [...range.getClientRects()].some(r => r.left < 0 || r.right > document.documentElement.clientWidth + 1);
        }).length,
        destinations: nav.map(a => ({label: a.textContent, found: !!document.querySelector(a.getAttribute('href')), height: a.getBoundingClientRect().height})),
        images: [...document.images].map(i => ({loaded: i.complete && i.naturalWidth === 100})),
        animations: document.getAnimations().length,
        rowCount: document.querySelectorAll('.service-row').length,
        unavailable: document.body.textContent.includes('Cannot read the local catalog'),
        networkAssets: performance.getEntriesByType('resource').filter(r => /^https?:/.test(r.name)).length
      };
    })()`, returnByValue: true,
  });
  assert.equal(exceptionDetails, undefined);
  const metrics = result.value;
  assert.equal(metrics.width, 320);
  assert.ok(metrics.documentWidth <= 320, JSON.stringify(metrics));
  assert.equal(metrics.clippedText, 0);
  assert.equal(metrics.destinations.length, 4);
  assert.ok(metrics.destinations.every(d => d.found && d.height >= 44));
  assert.equal(metrics.images.length, 2);
  assert.ok(metrics.images.every(i => i.loaded));
  assert.equal(metrics.animations, 0);
  assert.equal(metrics.networkAssets, 0);
  await page('Input.dispatchKeyEvent', { type: 'keyDown', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
  await page('Input.dispatchKeyEvent', { type: 'keyUp', key: 'Tab', code: 'Tab', windowsVirtualKeyCode: 9 });
  const focus = await page('Runtime.evaluate', {
    expression: `({skip:document.activeElement.classList.contains('skip'),visible:document.activeElement.getBoundingClientRect().top>=0,outline:getComputedStyle(document.activeElement).outlineStyle})`,
    returnByValue: true,
  });
  assert.equal(focus.result.value.skip, true);
  assert.equal(focus.result.value.visible, true);
  assert.equal(focus.result.value.outline, 'solid');
  const layout = await page('Page.getLayoutMetrics');
  // Keep the requested viewport width: automatic full-page clipping can drop the
  // scrollbar gutter while capture relayout expands the document into that space.
  const capture = await page('Page.captureScreenshot', {
    captureBeyondViewport: true,
    clip: { x: 0, y: 0, width: 320, height: Math.ceil(layout.cssContentSize.height), scale: 1 },
  });
  await writeFile(input.replace(/\.html$/, '.png'), Buffer.from(capture.data, 'base64'));
  // Exercise the native fallback even when the engine's media preference fails
  // to track the OS: motion must stop and resume without replacing the card.
  await page('Emulation.setEmulatedMedia', {
    features: [{ name: 'prefers-reduced-motion', value: 'no-preference' }],
  });
  const motion = async () => {
    const response = await page('Runtime.evaluate', {
      expression: `new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve({
        halo: getComputedStyle(document.querySelector('.mascot-halo')).animationName,
        reduced: matchMedia('(prefers-reduced-motion: reduce)').matches,
        card: document.querySelector('.tcg').textContent,
        images: [...document.images].every(i => i.complete && i.naturalWidth === 100)
      }))))`, awaitPromise: true, returnByValue: true,
    });
    assert.equal(response.exceptionDetails, undefined);
    return response.result.value;
  };
  const animated = await motion();
  assert.equal(animated.halo, 'card-halo');
  assert.equal(animated.reduced, false);
  const reduction = await readFile(path.join(root, 'assets/reduced-motion.css'), 'utf8');
  await page('Runtime.evaluate', {expression: `(() => {
    const style = document.createElement('style'); style.id = 'native-motion-test';
    style.textContent = ${JSON.stringify(reduction)}; document.head.append(style);
  })()`});
  const reduced = await motion();
  assert.equal(reduced.halo, 'none');
  assert.equal(reduced.reduced, false);
  assert.equal(reduced.card, animated.card);
  assert.equal(reduced.images, true);
  await page('Runtime.evaluate', {expression: `document.getElementById('native-motion-test').remove()`});
  const resumed = await motion();
  assert.equal(resumed.halo, 'card-halo');
  assert.equal(resumed.card, animated.card);
  console.log(JSON.stringify({ ...metrics, keyboard: focus.result.value,
    nativeFallback: [animated.halo, reduced.halo, resumed.halo] }, null, 2));
} finally {
  await call('Browser.close').catch(() => browser.kill('SIGTERM'));
  if (browser.exitCode === null) await new Promise(resolve => browser.once('exit', resolve));
  await rm(profile, { recursive: true, force: true });
}

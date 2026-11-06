// Offline Chromium component smoke, not installed WebKit/native acceptance.
// Only generated HTML in the workspace target directory may be loaded.
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, realpath, rm, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import assert from 'node:assert/strict';

const root = path.dirname(fileURLToPath(import.meta.url));
const input = await realpath(process.argv[2]);
const target = await realpath(path.join(root, '../../../target'));
assert.ok(input.startsWith(target + path.sep) && input.endsWith('.html'));
const profile = await mkdtemp(path.join(tmpdir(), 'koi-renderer-chromium-'));
const browser = spawn(process.env.CHROMIUM_PATH || 'chromium', [
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
    width: 1280, height: 800, deviceScaleFactor: 1, mobile: false,
  });
  await page('Emulation.setEmulatedMedia', {
    features: [{ name: 'prefers-reduced-motion', value: 'reduce' }],
  });
  await page('Network.enable');
  await page('Network.emulateNetworkConditions', {
    offline: true, latency: 0, downloadThroughput: 0, uploadThroughput: 0,
  });
  await page('Page.navigate', { url: pathToFileURL(input).href });
  const evaluate = async expression => {
    const { result, exceptionDetails } = await page('Runtime.evaluate', {
      expression, awaitPromise: true, returnByValue: true,
    });
    assert.equal(exceptionDetails, undefined);
    return result.value;
  };
  await evaluate("new Promise(resolve => { const ready = () => Promise.all([...document.images].map(image => image.decode().catch(() => {}))).then(resolve); if (document.readyState === 'complete') ready(); else window.addEventListener('load', ready, {once:true}); })");
  const measure = () => evaluate(`(() => {
    const nav = [...document.querySelectorAll('header nav [data-ui-tab]')];
    const rows = [...document.querySelectorAll('#services .service-table tr.service-row')];
    const bounds = element => {
      const r = element.getBoundingClientRect();
      return {x:r.x, y:r.y, width:r.width, height:r.height, bottom:r.bottom};
    };
    const controls = [...document.querySelectorAll('header nav a, .service-row a, .service-row button')]
      .filter(element => element.getClientRects().length).map(bounds);
    return {
      width:innerWidth, height:innerHeight, documentWidth:document.documentElement.scrollWidth,
      destinations:nav.map(a => ({label:a.textContent.trim(), active:a.getAttribute('aria-current') === 'page', ...bounds(a)})),
      images:[...document.images].map(i => ({loaded:i.complete && i.naturalWidth > 0, offline:i.currentSrc.startsWith('data:')})),
      animations:document.getAnimations().length,
      rowCount:rows.length, rowBounds:rows.map(bounds), controlBounds:controls,
      completeRows:rows.filter(row => {
        const r=row.getBoundingClientRect();
        const scroll=document.querySelector('.table-scroll')?.getBoundingClientRect();
        const header=document.querySelector('.service-table thead')?.getBoundingClientRect();
        return r.top>=Math.max(0, scroll?.top ?? 0, header?.bottom ?? 0)-1 && r.bottom<=Math.min(innerHeight, scroll?.bottom ?? innerHeight)+1;
      }).length,
      services:!!document.querySelector('#services'),
      details:!!document.querySelector('dialog#service-details'),
      fixture:document.body.hasAttribute('data-offline-fixture'),
      unavailable:!!document.querySelector('[role="alert"]'),
      networkAssets:performance.getEntriesByType('resource').filter(r => /^https?:/.test(r.name)).length
    };
  })()`);
  const desktop = await measure();
  assert.equal(desktop.width, 1280);
  assert.ok(desktop.documentWidth <= 1280, JSON.stringify(desktop));
  assert.deepEqual(desktop.destinations.map(d => d.label), ['Services', 'mDNS', 'Certmesh', 'Settings', 'About']);
  assert.equal(desktop.destinations.filter(d => d.active).length, 1);
  assert.ok(desktop.destinations.every(d => d.height >= 44));
  const navPaint = await evaluate("[...document.querySelectorAll('.nav-link > span')].map(span => ({height:span.getBoundingClientRect().height, fontSize:getComputedStyle(span).fontSize, fontWeight:getComputedStyle(span).fontWeight}))");
  assert.ok(navPaint.every(item => item.height === 30 && item.fontSize === '12.5px' && item.fontWeight === '400'));
  const desktopCapture = await page('Page.captureScreenshot', {captureBeyondViewport:false});
  await writeFile(input.replace(/\.html$/, '-desktop.png'), Buffer.from(desktopCapture.data, 'base64'));
  assert.ok(desktop.images.length > 0 && desktop.images.every(i => i.loaded && i.offline));
  assert.equal(desktop.animations, 0);
  assert.equal(desktop.networkAssets, 0);
  if (desktop.services && desktop.rowCount >= 30 && !desktop.details) {
    assert.ok(desktop.completeRows >= 10, JSON.stringify(desktop));
    assert.ok(desktop.rowBounds.every(r => r.height >= 48 && r.height <= 52), JSON.stringify(desktop));
    assert.ok(desktop.controlBounds.every(r => r.height >= 44 && r.width >= 44), JSON.stringify(desktop));
  }

  await page('Input.dispatchKeyEvent', { type:'keyDown', key:'Tab', code:'Tab', windowsVirtualKeyCode:9 });
  await page('Input.dispatchKeyEvent', { type:'keyUp', key:'Tab', code:'Tab', windowsVirtualKeyCode:9 });
  const focus = await evaluate("({skip:document.activeElement.classList.contains('skip'), visible:document.activeElement.getBoundingClientRect().top>=0, outline:getComputedStyle(document.activeElement).outlineStyle})");
  assert.equal(focus.skip, true);
  assert.equal(focus.visible, true);
  assert.equal(focus.outline, 'solid');

  let mdnsChecks = null;
  if (await evaluate("!!document.querySelector('#mdns-inspector')")) {
    const script = await readFile(path.join(root, '../assets/mdns-interaction.js'), 'utf8');
    await evaluate(script);
    await evaluate(`(() => {
      window.mdnsOriginalShell = document.querySelector('.app-shell').outerHTML;
      window.mdnsRefresh = async () => {
        const focusKey = document.activeElement?.dataset.focusKey;
        KoiMdns.beforeRefresh();
        document.querySelector('.app-shell').outerHTML = window.mdnsOriginalShell;
        KoiMdns.afterRefresh();
        // Both adapters restore a shared, stable focus key after inserting the renderer output.
        if (focusKey) [...document.querySelectorAll('[data-focus-key]')].find(node => node.dataset.focusKey === focusKey)?.focus({preventScroll:true});
      };
      window.KoiOperator = {perform: async () => ({outcome:'started',message:'Discovery accepted; results arrive in the snapshot.',records:[],service_types:[],query:'all',observed_at:'2026-09-13T10:04:00Z'}), refresh:window.mdnsRefresh};
      document.querySelector('[data-mdns-detail="queries"]').open = true;
      document.querySelector('.mdns-instance').open = true;
      document.querySelector('#mdns-browse-type').value = '_ipp._tcp';
      document.querySelector('#mdns-filter').value = 'draft filter';
      document.querySelector('[data-mdns-kind="requery"]').requestSubmit();
    })()`);
    await evaluate("new Promise(resolve => setTimeout(resolve, 30))");
    mdnsChecks = await evaluate(`({
      result:document.querySelector('#mdns-query-result').textContent,
      browse:document.querySelector('#mdns-browse-type').value,
      filter:document.querySelector('#mdns-filter').value,
      open:document.querySelector('.mdns-instance').open,
      types:document.querySelector('.mdns-types').textContent,
      hostile:document.querySelector('.mdns-txt').textContent,
      injected:!!document.querySelector('#mdns-inspector script'),
      disabled:[...document.querySelectorAll('[data-mdns-kind] button')].some(button => button.disabled)
    })`);
    assert.ok(mdnsChecks.result.includes('Started'));
    assert.ok(!mdnsChecks.result.includes('completed'));
    assert.equal(mdnsChecks.browse, '_ipp._tcp');
    assert.equal(mdnsChecks.filter, 'draft filter');
    assert.equal(mdnsChecks.open, true);
    assert.equal(mdnsChecks.disabled, false);
    assert.ok(mdnsChecks.types.includes('_empty._udp'));
    assert.ok(mdnsChecks.hostile.includes("<script>alert('TXT')</script>"));
    assert.equal(mdnsChecks.injected, false);
    for (const selector of ['.mdns-instance > summary', '#mdns-query-summary', '#mdns-browse-submit', '#mdns-resolve-submit', '#mdns-requery-submit', '#mdns-filter-submit', '#mdns-types-summary', '.mdns-type-row a', '#mdns-sources-summary', '#mdns-timing-summary']) {
      const focused = await evaluate(`(async () => {
        const node = document.querySelector(${JSON.stringify(selector)});
        if (node.closest('details') && node.tagName !== 'SUMMARY') node.closest('details').open = true;
        node.focus({preventScroll:true});
        const key = document.activeElement?.dataset.focusKey;
        await window.mdnsRefresh();
        return {key, restored:document.activeElement?.dataset.focusKey};
      })()`);
      assert.ok(focused.key, `Missing focus identity: ${selector}`);
      assert.equal(focused.restored, focused.key, `Focus lost after refresh: ${selector}`);
    }
    await evaluate(`(async () => {
      window.KoiOperator.perform = async () => ({outcome:'answers',message:'One response.',records:[{name:'<img src=x onerror=alert(1)>',type:'_ipp._tcp',txt:{note:'<script>bad()</script>'}}],service_types:['_empty._udp'],query:'_ipp._tcp',observed_at:'2026-09-13T10:05:00Z'});
      document.querySelector('[data-mdns-kind="browse"]').requestSubmit();
      await new Promise(resolve => setTimeout(resolve, 30));
      await window.mdnsRefresh();
    })()`);
    assert.equal(await evaluate("document.querySelector('#mdns-query-result').dataset.outcome"), 'answers');
    assert.equal(await evaluate("document.querySelectorAll('#mdns-query-result img, #mdns-query-result script').length"), 0);
    const expandedCapture = await page('Page.captureScreenshot', {captureBeyondViewport:false});
    await writeFile(input.replace(/\.html$/, '-expanded-desktop.png'), Buffer.from(expandedCapture.data, 'base64'));
  }

  const narrow = [];
  for (const width of [390, 320]) {
    await page('Emulation.setDeviceMetricsOverride', {
      width, height:900, deviceScaleFactor:1, mobile:false,
    });
    const metrics = await measure();
    assert.equal(metrics.width, width);
    assert.ok(metrics.documentWidth <= width, JSON.stringify(metrics));
    assert.ok(metrics.destinations.every(d => d.height >= 44 && d.width >= 44));
    assert.equal(metrics.rowCount, desktop.rowCount);
    assert.equal(metrics.animations, 0);
    assert.ok(metrics.images.every(i => i.loaded && i.offline));
    if (mdnsChecks) {
      const mdnsCapture = await page('Page.captureScreenshot', {captureBeyondViewport:false});
      await writeFile(input.replace(/\.html$/, `-expanded-${width}.png`), Buffer.from(mdnsCapture.data, 'base64'));
    }
    narrow.push(metrics);
  }
  const layout = await page('Page.getLayoutMetrics');
  const capture = await page('Page.captureScreenshot', {
    captureBeyondViewport:true,
    clip:{x:0, y:0, width:320, height:Math.ceil(layout.cssContentSize.height), scale:1},
  });
  await writeFile(input.replace(/\.html$/, '.png'), Buffer.from(capture.data, 'base64'));

  // About retains the original card. Check the native motion fallback only
  // when that optional page is present; Services must not grow a hidden card.
  let nativeFallback = null;
  const hasCard = await evaluate("!!document.querySelector('.tcg .mascot-halo')");
  if (hasCard) {
    await page('Emulation.setEmulatedMedia', {
      features:[{name:'prefers-reduced-motion', value:'no-preference'}],
    });
    const motion = () => evaluate("new Promise(resolve => requestAnimationFrame(() => requestAnimationFrame(() => resolve({halo:getComputedStyle(document.querySelector('.mascot-halo')).animationName, card:document.querySelector('.tcg').textContent, images:[...document.images].every(i => i.complete && i.naturalWidth>0)}))))");
    const animated = await motion();
    const reduction = await readFile(path.join(root, '../assets/reduced-motion.css'), 'utf8');
    await evaluate('(() => { const style=document.createElement("style"); style.id="native-motion-test"; style.textContent=' + JSON.stringify(reduction) + '; document.head.append(style); })()');
    const reduced = await motion();
    assert.equal(reduced.halo, 'none');
    assert.equal(reduced.card, animated.card);
    assert.equal(reduced.images, true);
    await evaluate('document.getElementById("native-motion-test").remove()');
    const resumed = await motion();
    assert.equal(resumed.halo, animated.halo);
    assert.equal(resumed.card, animated.card);
    nativeFallback = [animated.halo, reduced.halo, resumed.halo];
  }
  if (mdnsChecks) {
    for (const outcome of ['no_answer', 'error']) {
      await evaluate(`(async () => {
        window.KoiOperator.perform = async () => ({outcome:${JSON.stringify(outcome)},message:'Explicit query outcome',records:[]});
        document.querySelector('[data-mdns-kind="browse"]').requestSubmit();
        await new Promise(resolve => setTimeout(resolve, 30));
      })()`);
      assert.equal(await evaluate("document.querySelector('#mdns-query-result').dataset.outcome"), outcome);
    }
    await evaluate(`(async () => {
      window.KoiOperator.perform = () => new Promise(resolve => { window.mdnsLateResponse = resolve; });
      document.querySelector('[data-mdns-kind="browse"]').requestSubmit();
      KoiMdns.reset();
      window.mdnsLateResponse({outcome:'answers',message:'Private late result',records:[]});
      await new Promise(resolve => setTimeout(resolve, 30));
    })()`);
    assert.equal(await evaluate("document.querySelector('#mdns-query-result').textContent"), '');
  }
  console.log(JSON.stringify({desktop, narrow, keyboard:focus, nativeFallback, mdnsChecks}, null, 2));
} finally {
  await call('Browser.close').catch(() => browser.kill('SIGTERM'));
  if (browser.exitCode === null) await new Promise(resolve => browser.once('exit', resolve));
  await rm(profile, {recursive:true, force:true});
}

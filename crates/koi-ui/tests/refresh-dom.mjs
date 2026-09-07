// Actual DOM mechanics in isolated Chromium; not native or live-catalog evidence.
// Uses only an ephemeral loopback fixture, never an installed daemon or peer.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { createServer } from 'node:http';
const source = await readFile(new URL('../assets/refresh.js', import.meta.url), 'utf8');
const css = await readFile(new URL('../assets/shell.css', import.meta.url), 'utf8');
const profile = await mkdtemp(path.join(tmpdir(), 'koi-refresh-dom-'));
const browser = spawn('chromium', ['--headless', '--remote-debugging-pipe', '--no-first-run', '--disable-extensions', '--disable-background-networking', `--user-data-dir=${profile}`, 'about:blank'], { stdio: ['ignore', 'ignore', 'pipe', 'pipe', 'pipe'] });
browser.stderr.resume();
let sequence = 0, buffer = '';
const pending = new Map();
browser.stdio[4].on('data', chunk => {
  buffer += chunk.toString();
  while (buffer.includes('\0')) {
    const end = buffer.indexOf('\0');
    const message = JSON.parse(buffer.slice(0, end)); buffer = buffer.slice(end + 1);
    const waiter = pending.get(message.id);
    if (waiter) { pending.delete(message.id); clearTimeout(waiter.timer); message.error ? waiter.reject(new Error(JSON.stringify(message.error))) : waiter.resolve(message.result); }
  }
});
function call(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    const timer = setTimeout(() => { pending.delete(id); reject(new Error(`Timeout: ${method}`)); }, 10000);
    pending.set(id, { resolve, reject, timer });
    browser.stdio[3].write(JSON.stringify({ id, method, params, sessionId }) + '\0');
  });
}
const comparisonRequests = [];
let comparisonState = 'Not run', sawComparing = false;
const fixture = createServer(async (request, response) => {
  const chunks = []; for await (const chunk of request) chunks.push(chunk);
  const body = Buffer.concat(chunks).toString();
  comparisonRequests.push({method:request.method, url:request.url, body, token:request.headers['x-koi-token'], cookie:request.headers.cookie});
  if (request.url === '/refresh.js') { response.writeHead(200, {'content-type':'text/javascript'}); response.end(source); return; }
  if (request.url === '/compare') { comparisonState = 'Comparing'; setTimeout(() => { comparisonState = 'Finished'; }, 300); response.writeHead(202); response.end(); return; }
  response.writeHead(200, {'content-type':'text/html'});
  response.end('<!doctype html><html><head><script defer src="/refresh.js"></script></head><body><section id="home" tabindex="-1"><p id="catalog-status"></p></section><section id="comparison"><p id="comparison-state">' + comparisonState + '</p><form action="/compare" method="post" data-comparison><input type="hidden" name="peer" value="office"><button id="compare-now">Compare now</button></form></section></body></html>');
  if (comparisonState === 'Comparing') sawComparing = true;
});
await new Promise(resolve => fixture.listen(0, '127.0.0.1', resolve));
try {
  const { targetId } = await call('Target.createTarget', { url: 'about:blank' });
  const { sessionId } = await call('Target.attachToTarget', { targetId, flatten: true });
  await call('Emulation.setDeviceMetricsOverride', { width:320, height:872, deviceScaleFactor:1, mobile:false }, sessionId);
  const reply = await call('Runtime.evaluate', { returnByValue: true, expression: `(() => {
    ${source}
    const html = '<section id="home" tabindex="-1"><form id="home-search"><input id="service-search" value="submitted"><input name="favorites" type="checkbox"></form><details id="service-technical-details"><summary>Sources</summary></details><article data-service-id="notes"><a data-external href="https://notes.local/">Open</a></article></section>';
    document.body.innerHTML = '<div id="view">' + html + '</div>';
    const view = document.getElementById('view');
    const input = document.getElementById('service-search');
    input.value = 'unsent draft'; input.focus(); input.setSelectionRange(3, 7);
    document.querySelector('[name=favorites]').checked = true;
    document.querySelector('details').open = true;
    KoiRefresh.apply(view, html, {automatic:true});
    const draft = {sameInput:input === document.getElementById('service-search'), value:input.value, focused:document.activeElement === input, caret:[input.selectionStart,input.selectionEnd], checked:document.querySelector('[name=favorites]').checked, expanded:document.querySelector('details').open};
    document.querySelector('[data-external]').focus();
    KoiRefresh.apply(view, html, {automatic:true});
    const linkFocus = document.activeElement.getAttribute('href');
    KoiRefresh.stale(view);
    const disabled = !document.querySelector('[data-external]').hasAttribute('href') && document.querySelector('[data-external]').getAttribute('aria-disabled') === 'true';
    KoiRefresh.apply(view, html, {automatic:true});
    const recovered = document.querySelector('[data-external]').getAttribute('href');
    KoiRefresh.apply(view, html, {focusId:'service-search'});
    const submitted = document.getElementById('service-search').value;
    const style = document.createElement('style'); style.textContent = ${JSON.stringify(css)}; document.head.append(style);
    const duplicated = html + '<section id="devices"><article data-service-id="notes"><a href="https://notes.local/">Open</a></article></section>';
    KoiRefresh.apply(view, duplicated);
    document.querySelector('#devices a').focus();
    KoiRefresh.apply(view, duplicated, {automatic:true});
    const deviceFocus = document.activeElement.closest('section').id;
    const panels = '<section id="home" tabindex="-1"><div class="home-layout"><div class="home-results">Services</div><aside id="service-details" tabindex="-1">Details</aside></div></section>';
    KoiRefresh.apply(view, panels, {focusId:'service-details'});
    const visible = () => ({details:getComputedStyle(document.getElementById('service-details')).display !== 'none', results:getComputedStyle(document.querySelector('.home-results')).display !== 'none'});
    const selected = visible();
    KoiRefresh.apply(view, panels, {automatic:true});
    const afterRefresh = visible();
    location.hash = '#home'; window.dispatchEvent(new Event('hashchange'));
    const back = visible();
    KoiRefresh.apply(view, panels, {automatic:true});
    const backAfterRefresh = visible();
    return {draft,deviceFocus,linkFocus,disabled,recovered,submitted,stale:view.hasAttribute('data-stale'),selected,afterRefresh,back,backAfterRefresh};
  })()` }, sessionId);
  assert.equal(reply.exceptionDetails, undefined, JSON.stringify(reply.exceptionDetails));
  assert.deepEqual(reply.result.value, {
    draft: { sameInput: true, value: 'unsent draft', focused: true, caret: [3, 7], checked: true, expanded: true },
    deviceFocus: 'devices', linkFocus: 'https://notes.local/', disabled: true, recovered: 'https://notes.local/', submitted: 'submitted', stale: false,
    selected:{details:true,results:false}, afterRefresh:{details:true,results:false},
    back:{details:false,results:true}, backAfterRefresh:{details:false,results:true},
  });
  const fixtureUrl = `http://koi-ui.localhost:${fixture.address().port}/?peer=office#comparison`;
  const { targetId: nativeTarget } = await call('Target.createTarget', {url:fixtureUrl});
  const { sessionId: nativeSession } = await call('Target.attachToTarget', {targetId:nativeTarget,flatten:true});
  async function until(expression) {
    const deadline = Date.now() + 9000;
    while (Date.now() < deadline) {
      const value = await call('Runtime.evaluate', {expression,returnByValue:true}, nativeSession);
      if (value.result?.value) return value.result.value;
      await new Promise(resolve => setTimeout(resolve, 50));
    }
    throw new Error('Fixture condition did not settle: ' + expression);
  }
  await until("!!window.KoiRefresh && document.getElementById('comparison-state')?.textContent === 'Not run'");
  await call('Runtime.evaluate', {expression:"document.getElementById('compare-now').click()"}, nativeSession);
  await until("document.getElementById('comparison-state')?.textContent === 'Comparing'");
  await until("document.getElementById('comparison-state')?.textContent === 'Finished'");
  assert.equal(sawComparing, true);
  assert.deepEqual(comparisonRequests.filter(request => request.method === 'POST').map(({url,body,token,cookie}) => ({url,body,token,cookie})), [{url:'/compare',body:'peer=office',token:undefined,cookie:undefined}]);
  console.log('Chromium comparison transport: explicit POST, comparing and finished refresh; no authority in DOM requests.');
  console.log('Chromium DOM refresh: draft/caret/focus/disclosure retained; stale Open disabled; recovery restored.');
} finally {
  fixture.close(); fixture.closeAllConnections();
  await call('Browser.close').catch(() => browser.kill('SIGTERM'));
  if (browser.exitCode === null) await new Promise(resolve => browser.once('exit', resolve));
  await rm(profile, { recursive: true, force: true });
}

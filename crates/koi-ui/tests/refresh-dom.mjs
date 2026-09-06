// Actual DOM mechanics in isolated Chromium; not native or live-catalog evidence.
// No navigation or network: exercise only the shared DOM refresh helper.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
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
    return {draft,linkFocus,disabled,recovered,submitted,stale:view.hasAttribute('data-stale'),selected,afterRefresh,back,backAfterRefresh};
  })()` }, sessionId);
  assert.equal(reply.exceptionDetails, undefined, JSON.stringify(reply.exceptionDetails));
  assert.deepEqual(reply.result.value, {
    draft: { sameInput: true, value: 'unsent draft', focused: true, caret: [3, 7], checked: true, expanded: true },
    linkFocus: 'https://notes.local/', disabled: true, recovered: 'https://notes.local/', submitted: 'submitted', stale: false,
    selected:{details:true,results:false}, afterRefresh:{details:true,results:false},
    back:{details:false,results:true}, backAfterRefresh:{details:false,results:true},
  });
  console.log('Chromium DOM refresh: draft/caret/focus/disclosure retained; stale Open disabled; recovery restored.');
} finally {
  await call('Browser.close').catch(() => browser.kill('SIGTERM'));
  if (browser.exitCode === null) await new Promise(resolve => browser.once('exit', resolve));
  await rm(profile, { recursive: true, force: true });
}

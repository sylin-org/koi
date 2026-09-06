// Actual DOM mechanics in isolated Chromium; not native or live-catalog evidence.
// No navigation or network: exercise only the shared DOM refresh helper.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
const source = await readFile(new URL('../assets/refresh.js', import.meta.url), 'utf8');
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
    return {draft,linkFocus,disabled,recovered,submitted:document.getElementById('service-search').value,stale:view.hasAttribute('data-stale')};
  })()` }, sessionId);
  assert.equal(reply.exceptionDetails, undefined, JSON.stringify(reply.exceptionDetails));
  assert.deepEqual(reply.result.value, {
    draft: { sameInput: true, value: 'unsent draft', focused: true, caret: [3, 7], checked: true, expanded: true },
    linkFocus: 'https://notes.local/', disabled: true, recovered: 'https://notes.local/', submitted: 'submitted', stale: false,
  });
  console.log('Chromium DOM refresh: draft/caret/focus/disclosure retained; stale Open disabled; recovery restored.');
} finally {
  await call('Browser.close').catch(() => browser.kill('SIGTERM'));
  if (browser.exitCode === null) await new Promise(resolve => browser.once('exit', resolve));
  await rm(profile, { recursive: true, force: true });
}

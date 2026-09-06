// Real browser cryptography/storage + actual Rust exchange. Isolated fixture only.
import assert from 'node:assert/strict';
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import path from 'node:path';
const profile = await mkdtemp(path.join(tmpdir(), 'koi-browser-session-'));
const browser = spawn(process.env.KOI_TEST_BROWSER || 'chromium', ['--headless', '--remote-debugging-pipe', '--no-first-run', '--disable-extensions', '--disable-background-networking', '--password-store=basic', `--user-data-dir=${profile}`, 'about:blank'], { stdio:['ignore','ignore','pipe','pipe','pipe'] });
browser.stderr.resume();
let sequence=0, buffer=''; const pending=new Map();
browser.stdio[4].on('data', chunk => {
  buffer+=chunk.toString();
  while(buffer.includes('\0')) {
    const end=buffer.indexOf('\0'), message=JSON.parse(buffer.slice(0,end)); buffer=buffer.slice(end+1);
    const waiter=pending.get(message.id);
    if(waiter) { pending.delete(message.id);clearTimeout(waiter.timer);message.error?waiter.reject(new Error(JSON.stringify(message.error))):waiter.resolve(message.result); }
  }
});
function call(method,params={},sessionId) {
  return new Promise((resolve,reject)=> {
    const id=++sequence, timer=setTimeout(()=>{pending.delete(id);reject(new Error(`Timeout: ${method}`));},12000);
    pending.set(id,{resolve,reject,timer});browser.stdio[3].write(JSON.stringify({id,method,params,sessionId})+'\0');
  });
}
let sessionId;
async function evaluate(expression) {
  const reply=await call('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true},sessionId);
  assert.equal(reply.exceptionDetails,undefined,JSON.stringify(reply.exceptionDetails));return reply.result.value;
}
async function until(expression) {
  const deadline=Date.now()+12000;
  while(Date.now()<deadline) { if(await evaluate(expression)) return; await new Promise(resolve=>setTimeout(resolve,100)); }
  throw new Error(`Condition failed: ${expression}; ${await evaluate('document.body.innerText')}`);
}
try {
  const {targetId}=await call('Target.createTarget',{url:'about:blank'});
  ({sessionId}=await call('Target.attachToTarget',{targetId,flatten:true}));
  await call('Page.enable',{},sessionId);
  await call('Emulation.setDeviceMetricsOverride',{width:320,height:740,deviceScaleFactor:1,mobile:false},sessionId);
  await call('Page.navigate',{url:process.env.KOI_TEST_INVITATION},sessionId);
  await until('document.getElementById("browser-status")?.textContent === "Ready to connect."');
  assert.equal(await evaluate('location.hash'),'');
  assert.equal(await evaluate('document.documentElement.scrollWidth <= 320'),true);
  assert.equal(await evaluate('document.getElementById("operator-view").children.length'),0);
  await evaluate('document.getElementById("browser-label").value="Fixture browser";document.getElementById("remember-browser").checked=true;document.getElementById("connect-form").requestSubmit()');
  await until('document.getElementById("browser-status")?.textContent === "Connected · View services"');
  assert.equal(await evaluate('!!localStorage.getItem("koi-browser-session-v1")'),true);
  assert.equal(await evaluate('!!sessionStorage.getItem("koi-browser-session-v1")'),false);
  await evaluate('document.getElementById("service-search").value="notes";document.getElementById("home-search").requestSubmit()');
  await until('location.search.includes("search=notes") && document.getElementById("browser-status").textContent.startsWith("Connected")');
  await call('Page.reload',{},sessionId);
  await until('document.getElementById("browser-status")?.textContent === "Connected · View services"');
  assert.equal(await evaluate('document.getElementById("service-search").value'),'notes');
  assert.equal(await evaluate(`new Promise((resolve,reject)=>{const r=indexedDB.open('koi-browser-access-v1',1);r.onsuccess=()=>{const q=r.result.transaction('keys').objectStore('keys').get(localStorage.getItem('koi-browser-session-v1'));q.onsuccess=()=>resolve(q.result.key.extractable);q.onerror=reject;};r.onerror=reject;})`),false);
  // Returning from another page retains the same key/session and Home intent.
  await call('Page.navigate',{url:new URL('/healthz',process.env.KOI_TEST_INVITATION).href},sessionId);
  await call('Page.navigate',{url:new URL('/ui?search=notes',process.env.KOI_TEST_INVITATION).href},sessionId);
  await until('document.getElementById("browser-status")?.textContent === "Connected · View services"');
  // Reopening from Koi reuses valid access and leaves the fresh code unspent.
  const remembered = await evaluate('localStorage.getItem("koi-browser-session-v1")');
  await call('Page.navigate',{url:process.env.KOI_TEST_TEMP_INVITATION + '&open=1'},sessionId);
  await until('document.getElementById("browser-status")?.textContent === "Connected · View services"');
  assert.equal(await evaluate('localStorage.getItem("koi-browser-session-v1")'),remembered);
  assert.equal(await evaluate('sessionStorage.getItem("koi-browser-session-v1")'),null);
  await evaluate('document.getElementById("disconnect-browser").click()');
  await until('document.getElementById("browser-status")?.textContent === "This browser is disconnected."');
  assert.equal(await evaluate('localStorage.getItem("koi-browser-session-v1")'),null);
  await call('Page.reload',{},sessionId);
  await until('document.getElementById("browser-status")?.textContent === "Connect from the Koi app or scan a new invitation."');
  // A temporary grant survives reload in its tab, never a fresh independent tab.
  await call('Page.navigate',{url:process.env.KOI_TEST_TEMP_INVITATION + '&open=1'},sessionId);
  await until('document.getElementById("browser-status")?.textContent === "Connected · View services"');
  assert.equal(await evaluate('localStorage.getItem("koi-browser-session-v1")'),null);
  assert.equal(await evaluate('!!sessionStorage.getItem("koi-browser-session-v1")'),true);
  await call('Page.reload',{},sessionId);
  await until('document.getElementById("browser-status")?.textContent === "Connected · View services"');
  const original = sessionId;
  const other = await call('Target.createTarget',{url:'about:blank'});
  ({sessionId}=await call('Target.attachToTarget',{targetId:other.targetId,flatten:true}));
  await call('Page.enable',{},sessionId);
  await call('Page.navigate',{url:new URL('/ui',process.env.KOI_TEST_INVITATION).href},sessionId);
  await until('document.getElementById("browser-status")?.textContent === "Connect from the Koi app or scan a new invitation."');
  await call('Target.closeTarget',{targetId:other.targetId});
  sessionId = original;
  await evaluate('document.getElementById("disconnect-browser").click()');
  await until('document.getElementById("browser-status")?.textContent === "This browser is disconnected."');
  assert.equal(await evaluate('sessionStorage.getItem("koi-browser-session-v1")'),null);
  console.log('Browser exchange: preview, WebCrypto proof, non-extractable remembered key, search/reload/return, temporary tab isolation, server revocation and client cleanup passed.');
} finally {
  await call('Browser.close').catch(()=>{});
  await new Promise(resolve => {
    if (browser.exitCode !== null || browser.signalCode !== null) return resolve();
    const timeout = setTimeout(() => browser.kill('SIGTERM'), 3000);
    browser.once('exit', () => { clearTimeout(timeout); resolve(); });
  });
  // Chrome helpers can finish their final profile writes just after the leader.
  await rm(profile,{recursive:true,force:true,maxRetries:10,retryDelay:100});
}

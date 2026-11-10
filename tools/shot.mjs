// Full-page screenshot of a URL with headless Chrome, at any width (CDP device metrics, so 390px phones work).
//   node tools/shot.mjs <url> <out.png> [width=1440] [--dark | --light]
// Pages taller than 16,000px are saved as out.png + out-part2.png, … (12,000px each).
// --dark / --light force prefers-color-scheme (this Mac defaults to dark, so pass --light for the light theme).
// Prints the page's console errors and failed requests, so a broken script or missing file shows up too.
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [,, url, out, w = '1440', ...flags] = process.argv;
const width = parseInt(w, 10), dark = flags.includes('--dark'), light = flags.includes('--light');
// random debug port well away from the dev-server ranges (8600-8999, 9400-9700) so parallel runs rarely collide
const port = 20000 + Math.floor(Math.random() * 40000);
const profile = mkdtempSync(join(tmpdir(), 'plshot-'));
const chrome = spawn('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  ['--headless=new', `--remote-debugging-port=${port}`, '--hide-scrollbars', `--user-data-dir=${profile}`, 'about:blank'], { stdio: 'ignore' });
const sleep = ms => new Promise(r => setTimeout(r, ms));
let targets;
for (let i = 0; i < 40 && !targets; i++) { await sleep(250); try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); } catch {} }
const ws = new WebSocket(targets.find(t => t.type === 'page').webSocketDebuggerUrl);
let id = 0; const pending = new Map(), problems = [], urls = new Map();
ws.addEventListener('message', e => {
  const m = JSON.parse(e.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m.result); pending.delete(m.id); }
  if (m.method === 'Runtime.exceptionThrown') problems.push('exception: ' + (m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text));
  if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') problems.push('console.error: ' + m.params.args.map(a => a.value ?? a.description).join(' '));
  if (m.method === 'Network.requestWillBeSent') urls.set(m.params.requestId, m.params.request.url);
  if (m.method === 'Network.loadingFailed' && !m.params.canceled) problems.push('failed request: ' + m.params.errorText + ' ' + (urls.get(m.params.requestId) || m.params.requestId));
  if (m.method === 'Network.responseReceived' && m.params.response.status >= 400) problems.push(`HTTP ${m.params.response.status}: ${m.params.response.url}`);
});
const send = (method, params = {}) => new Promise(res => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
await new Promise(r => ws.addEventListener('open', r));
await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
await send('Emulation.setDeviceMetricsOverride', { width, height: width < 700 ? 844 : 900, deviceScaleFactor: 1, mobile: width < 700 });
if (dark || light) await send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: dark ? 'dark' : 'light' }] });
await send('Page.navigate', { url });
await sleep(3500);
// trigger scroll-reveal animations, then return to the top
await send('Runtime.evaluate', { expression: 'window.scrollTo(0, document.body.scrollHeight); document.querySelectorAll("[data-reveal]").forEach(e=>e.classList.add("in"))' });
await sleep(600);
await send('Runtime.evaluate', { expression: 'window.scrollTo(0, 0)' });
await sleep(400);
// Chrome repeats content past ~16,384px in one capture, so very tall pages are saved in parts: out.png, out-part2.png, …
const PART = 12000;
const fullH = (await send('Runtime.evaluate', { expression: 'document.documentElement.scrollHeight', returnByValue: true })).result.value;
if (fullH <= 16000) {
  const shot = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
  writeFileSync(out, Buffer.from(shot.data, 'base64'));
} else {
  for (let y = 0, n = 1; y < fullH; y += PART, n++) {
    const clip = { x: 0, y, width, height: Math.min(PART, fullH - y), scale: 1 };
    const shot = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true, clip });
    writeFileSync(n === 1 ? out : out.replace(/\.png$/, `-part${n}.png`), Buffer.from(shot.data, 'base64'));
  }
  console.log(`tall page (${fullH}px): saved in ${Math.ceil(fullH / PART)} parts`);
}
const sw = await send('Runtime.evaluate', { expression: 'document.documentElement.scrollWidth', returnByValue: true });
if (sw.result.value > width + 1) problems.push(`horizontal overflow: page is ${sw.result.value}px wide at ${width}px`);
console.log(problems.length ? problems.join('\n') : 'ok: no console errors, failed requests or overflow');
chrome.kill(); await sleep(500); try { rmSync(profile, { recursive: true, force: true, maxRetries: 5 }); } catch {}
process.exit(0);

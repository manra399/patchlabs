// Clicks every control on every page of the built site in headless Chrome and reports what's broken.
//   node tools/qa/clickall.mjs <base-url> [out.json] [--pages=/a,/b] [--width=1440]
// Per page: console errors, anything the Content-Security-Policy blocks, failed requests, links whose target 404s, and "dead" controls: a button, tab,
// summary or [role=button] whose click changes nothing (no DOM change, no navigation, no new tab, no dialog).
// Submit buttons inside forms are skipped (forms are tested by the flow tests). Pages come from <base>/sitemap.xml.
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

const [,, base, out = 'clickall.json', ...flags] = process.argv;
const flag = n => (flags.find(f => f.startsWith(`--${n}=`)) || '').split('=')[1];
const width = parseInt(flag('width') || '1440', 10);
const sleep = ms => new Promise(r => setTimeout(r, ms));
const port = 20000 + Math.floor(Math.random() * 40000);
const profile = mkdtempSync(join(tmpdir(), 'plqa-'));
const chrome = spawn('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  ['--headless=new', `--remote-debugging-port=${port}`, '--hide-scrollbars', `--user-data-dir=${profile}`, 'about:blank'], { stdio: 'ignore' });
let targets;
for (let i = 0; i < 40 && !targets; i++) { await sleep(250); try { targets = await (await fetch(`http://127.0.0.1:${port}/json`)).json(); } catch {} }
const ws = new WebSocket(targets.find(t => t.type === 'page').webSocketDebuggerUrl);
let id = 0; const pending = new Map(); let problems = [];
ws.addEventListener('message', e => {
  const m = JSON.parse(e.data);
  if (m.id && pending.has(m.id)) { pending.get(m.id)(m.result || { error: m.error }); pending.delete(m.id); }
  if (m.method === 'Runtime.exceptionThrown') problems.push('exception: ' + (m.params.exceptionDetails.exception?.description || m.params.exceptionDetails.text).split('\n')[0]);
  if (m.method === 'Runtime.consoleAPICalled' && m.params.type === 'error') problems.push('console.error: ' + m.params.args.map(a => a.value ?? a.description).join(' ').slice(0, 200));
  if (m.method === 'Network.responseReceived' && m.params.response.status >= 400 && !/api\.patchlabs\.dev|localhost:80\d\d/.test(m.params.response.url)) problems.push(`HTTP ${m.params.response.status}: ${m.params.response.url}`);
  if (m.method === 'Page.javascriptDialogOpening') send('Page.handleJavaScriptDialog', { accept: false });
});
const send = (method, params = {}) => new Promise(res => { const i = ++id; pending.set(i, res); ws.send(JSON.stringify({ id: i, method, params })); });
const ev = async (expression) => (await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })).result?.value;
await new Promise(r => ws.addEventListener('open', r));
await send('Page.enable'); await send('Runtime.enable'); await send('Network.enable');
// anything the page's Content-Security-Policy blocks is reported like a console error
await send('Page.addScriptToEvaluateOnNewDocument', { source: `document.addEventListener('securitypolicyviolation', e => console.error('CSP blocked ' + (e.blockedURI || 'inline') + ' (' + e.violatedDirective + ')'))` });
await send('Emulation.setDeviceMetricsOverride', { width, height: 900, deviceScaleFactor: 1, mobile: width < 700 });

const sitemap = await (await fetch(base.replace(/\/$/, '') + '/sitemap.xml')).text();
let pages = [...sitemap.matchAll(/<loc>([^<]+)<\/loc>/g)].map(m => new URL(m[1]).pathname);
if (flag('pages')) pages = flag('pages').split(',');
const linkCache = new Map();
async function linkOk(href) {
  if (linkCache.has(href)) return linkCache.get(href);
  let ok;
  try { const r = await fetch(href, { redirect: 'follow' }); ok = r.status < 400 ? true : r.status; } catch (e) { ok = String(e.message || e); }
  linkCache.set(href, ok); return ok;
}
const load = async (path) => {
  await send('Page.navigate', { url: base.replace(/\/$/, '') + path });
  await sleep(1500);
};
const report = [];
for (const path of pages) {
  problems = [];
  await load(path);
  const links = await ev(`[...document.querySelectorAll('a[href]')].map(a => a.href).filter(h => /^https?:/.test(h))`) || [];
  const internal = [...new Set(links.filter(h => h.startsWith(base)).map(h => h.split('#')[0]))];
  const broken = [];
  for (const h of internal) { const ok = await linkOk(h); if (ok !== true) broken.push(`${ok} ${h.replace(base, '')}`); }
  // tag every clickable control so it can be found again after each reload
  const n = await ev(`(() => { const els = [...document.querySelectorAll('button, summary, [role=button], [role=tab], [data-copy], [aria-controls]')]
    .filter(e => !(e.type === 'submit' && e.form) && !/^(INPUT|TEXTAREA|SELECT)$/.test(e.tagName) && !e.disabled && !e.closest('[hidden]'));
    els.forEach((e, i) => e.setAttribute('data-qa', i)); return els.length; })()`);
  const dead = [], errs = [];
  for (let i = 0; i < n; i++) {
    const before = problems.length;
    const r = await ev(`(async () => {
      let el = document.querySelector('[data-qa="${i}"]');
      if (!el) { [...document.querySelectorAll('button, summary, [role=button], [role=tab], [data-copy], [aria-controls]')]
        .filter(e => !(e.type === 'submit' && e.form) && !/^(INPUT|TEXTAREA|SELECT)$/.test(e.tagName) && !e.disabled && !e.closest('[hidden]')).forEach((e, j) => e.setAttribute('data-qa', j));
        el = document.querySelector('[data-qa="${i}"]'); }
      if (!el) return { skip: 'gone' };
      const label = (el.getAttribute('aria-label') || el.textContent || el.tagName).trim().replace(/\\s+/g, ' ').slice(0, 60);
      // a control hidden inside a closed menu is opened by its parent control; only test what a person can see
      const rect = el.getBoundingClientRect(), style = getComputedStyle(el);
      if (!rect.width || !rect.height || style.visibility === 'hidden') return { skip: 'invisible', label };
      document.querySelectorAll('dialog[open]').forEach(d => d.close()); await new Promise(r => setTimeout(r, 50));  // a box left open by the last click
      let changed = 0; const mo = new MutationObserver(m => changed += m.length);
      mo.observe(document.documentElement, { subtree: true, childList: true, attributes: true, characterData: true });
      const href = location.href; let opened = false; const wo = window.open; window.open = (...a) => { opened = true; return null; };
      let copied = false; try { const ct = navigator.clipboard.writeText.bind(navigator.clipboard); navigator.clipboard.writeText = t => { copied = true; return Promise.resolve(); }; } catch {}
      el.scrollIntoView({ block: 'center' }); el.click();
      await new Promise(r => setTimeout(r, 350));
      mo.disconnect(); window.open = wo;
      return { label, changed, nav: location.href !== href, opened, copied };
    })()`);
    if (!r || r.skip) continue;
    if (problems.length > before) errs.push(`${r.label}: ${problems.slice(before).join(' | ')}`);
    if (!r.changed && !r.nav && !r.opened && !r.copied) dead.push(r.label);
    if (r.nav) { await load(path); await ev(`(() => { [...document.querySelectorAll('button, summary, [role=button], [role=tab], [data-copy], [aria-controls]')]
        .filter(e => !(e.type === 'submit' && e.form) && !/^(INPUT|TEXTAREA|SELECT)$/.test(e.tagName) && !e.disabled && !e.closest('[hidden]')).forEach((e, j) => e.setAttribute('data-qa', j)); })()`); }
  }
  const sw = await ev('document.documentElement.scrollWidth');
  const row = { path, controls: n, links: internal.length, broken, dead, click_errors: errs,
    load_problems: [...new Set(problems)].slice(0, 20), overflow: sw > width + 1 ? sw : 0 };
  report.push(row);
  const bad = broken.length + dead.length + errs.length + (row.overflow ? 1 : 0);
  console.log(`${bad ? 'FAIL' : 'ok  '} ${path}  controls=${n} links=${internal.length}` + (bad ? `  broken=${broken.length} dead=${dead.length} errors=${errs.length}${row.overflow ? ' overflow=' + sw : ''}` : ''));
}
writeFileSync(out, JSON.stringify(report, null, 1));
chrome.kill(); await sleep(500); try { rmSync(profile, { recursive: true, force: true, maxRetries: 5 }); } catch {}
process.exit(0);

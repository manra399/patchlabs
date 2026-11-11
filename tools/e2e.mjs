// End-to-end test of the signed-in app (/app/*, /admin, owner tools on /check) in headless Chrome, driven over CDP,
// against the local stack: start it with `tools/e2e/stack.sh up`, stop it with `tools/e2e/stack.sh down`.
//   node tools/e2e.mjs            # runs every flow, screenshots into .shots/app/, prints pass/fail per step
// Uses synthetic data only (acme/* repos, @example.test emails) and test tokens from tools/e2e/stack.sh.
// Based on tools/shot.mjs; adds typing, clicking, waiting, localStorage, downloads and several browser contexts.
import { spawn } from 'node:child_process';
import { mkdtempSync, writeFileSync, readFileSync, existsSync, rmSync, mkdirSync, readdirSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const SITE = 'http://localhost:9137', API = 'http://localhost:8001', STUB = 'http://localhost:9298';
const OUTBOX = join(ROOT, '.shots/e2e-outbox/outbox.jsonl');
const SHOTS = join(ROOT, '.shots/app');
const W = { Authorization: 'Bearer e2e-worker-token' }, A = { Authorization: 'Bearer e2e-admin-token' };
const OWNER = 'owner@example.test', MATE = 'teammate@example.test';
const SHOT_ONLY = !process.argv.includes('--no-shots');
mkdirSync(SHOTS, { recursive: true });
const DL = mkdtempSync(join(tmpdir(), 'pl-dl-'));
const sleep = ms => new Promise(r => setTimeout(r, ms));

/* ---------- Chrome + CDP (flattened sessions on the browser socket) ---------- */
const port = 9400 + Math.floor(Math.random() * 500);
const profile = mkdtempSync(join(tmpdir(), 'ple2e-'));
const chrome = spawn('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome',
  ['--headless=new', `--remote-debugging-port=${port}`, '--hide-scrollbars', '--no-first-run', `--user-data-dir=${profile}`, 'about:blank'], { stdio: 'ignore' });
let ver;
for (let i = 0; i < 40 && !ver; i++) { await sleep(250); try { ver = await (await fetch(`http://127.0.0.1:${port}/json/version`)).json(); } catch {} }
const ws = new WebSocket(ver.webSocketDebuggerUrl);
let mid = 0; const pending = new Map(), listeners = new Set();
ws.addEventListener('message', e => {
  const m = JSON.parse(e.data);
  if (m.id && pending.has(m.id)) { const p = pending.get(m.id); pending.delete(m.id); m.error ? p.rej(new Error(m.error.message)) : p.res(m.result); }
  else listeners.forEach(f => f(m));
});
const cdp = (method, params = {}, sessionId) => new Promise((res, rej) => { const id = ++mid; pending.set(id, { res, rej }); ws.send(JSON.stringify({ id, method, params, sessionId })); });
await new Promise(r => ws.addEventListener('open', r));
await cdp('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: DL, eventsEnabled: true });

class Page {
  static async open(contextId) {
    const { targetId } = await cdp('Target.createTarget', { url: 'about:blank', ...(contextId ? { browserContextId: contextId } : {}) });
    const { sessionId } = await cdp('Target.attachToTarget', { targetId, flatten: true });
    const p = new Page(sessionId, targetId);
    await p.send('Page.enable'); await p.send('Runtime.enable'); await p.send('Network.enable');
    await p.size(1440, false);
    return p;
  }
  constructor(sid, tid) {
    this.sid = sid; this.tid = tid; this.problems = []; this.loaded = null;
    listeners.add(m => {
      if (m.sessionId !== sid) return;
      const P = m.params || {};
      if (m.method === 'Page.loadEventFired' && this.loaded) { this.loaded(); this.loaded = null; }
      if (m.method === 'Runtime.exceptionThrown') this.problems.push('exception: ' + (P.exceptionDetails.exception?.description || P.exceptionDetails.text));
      if (m.method === 'Runtime.consoleAPICalled' && P.type === 'error') this.problems.push('console.error: ' + P.args.map(a => a.value ?? a.description).join(' '));
      if (m.method === 'Network.loadingFailed' && !P.canceled) this.problems.push('failed request: ' + P.errorText + ' ' + (this.urls?.[P.requestId] || ''));
      if (m.method === 'Network.requestWillBeSent') (this.urls ||= {})[P.requestId] = P.request.method + ' ' + P.request.url;
      if (m.method === 'Network.responseReceived' && P.response.status >= 400) this.problems.push(`HTTP ${P.response.status}: ${(this.urls?.[P.requestId] || P.response.url)}`);
    });
  }
  send(m, p) { return cdp(m, p, this.sid); }
  take() { const p = this.problems; this.problems = []; return p; }
  async size(w, dark) {
    await this.send('Emulation.setDeviceMetricsOverride', { width: w, height: w < 700 ? 844 : 900, deviceScaleFactor: 1, mobile: w < 700 });
    await this.send('Emulation.setEmulatedMedia', { features: [{ name: 'prefers-color-scheme', value: dark ? 'dark' : 'light' }] });
  }
  async goto(url) {
    const done = new Promise(r => { this.loaded = r; });
    await this.send('Page.navigate', { url: url.startsWith('http') ? url : SITE + url });
    await Promise.race([done, sleep(10000)]); await sleep(250);
  }
  async eval(expr) {
    const r = await this.send('Runtime.evaluate', { expression: expr, awaitPromise: true, returnByValue: true });
    if (r.exceptionDetails) throw new Error('eval failed: ' + (r.exceptionDetails.exception?.description || r.exceptionDetails.text) + ' in ' + expr.slice(0, 120));
    return r.result.value;
  }
  async waitFor(expr, desc, timeout = 10000) {
    const end = Date.now() + timeout; let last;
    while (Date.now() < end) { try { last = await this.eval(expr); if (last) return last; } catch {} await sleep(150); }
    throw new Error('timed out waiting for ' + (desc || expr));
  }
  async waitText(text, sel = 'body', timeout = 10000) {
    return this.waitFor(`(document.querySelector(${JSON.stringify(sel)})||{}).innerText?.includes(${JSON.stringify(text)})`, `"${text}" in ${sel}`, timeout);
  }
  async click(sel) {
    await this.waitFor(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); return e && !e.disabled && e.offsetParent !== null; })()`, 'clickable ' + sel);
    await this.eval(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); e.scrollIntoView({block:'center'}); e.click(); })()`);
    await sleep(150);
  }
  async type(sel, text) {
    await this.waitFor(`!!document.querySelector(${JSON.stringify(sel)})`, 'field ' + sel);
    await this.eval(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); e.focus(); e.value = ''; e.dispatchEvent(new Event('input', {bubbles:true})); })()`);
    await this.send('Input.insertText', { text });
  }
  async select(sel, value) {
    await this.waitFor(`!!document.querySelector(${JSON.stringify(sel)})`, 'select ' + sel);
    await this.eval(`(() => { const e = document.querySelector(${JSON.stringify(sel)}); e.value = ${JSON.stringify(value)}; e.dispatchEvent(new Event('change', {bubbles:true})); })()`);
  }
  text(sel = 'body') { return this.eval(`(document.querySelector(${JSON.stringify(sel)})||{}).innerText || ''`); }
  path() { return this.eval('location.pathname + location.search'); }
  async shot(name, { light390 = true, dark = true } = {}) {
    if (!SHOT_ONLY) return;
    const variants = [[1440, false, '1440'], ...(light390 ? [[390, false, '390']] : []), ...(dark ? [[1440, true, 'dark']] : [])];
    for (const [w, d, tag] of variants) {
      await this.size(w, d); await this.eval('window.scrollTo(0, 0)'); await sleep(600);
      const s = await this.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true });
      writeFileSync(join(SHOTS, `${name}-${tag}.png`), Buffer.from(s.data, 'base64'));
      const sw = await this.eval('document.documentElement.scrollWidth');
      if (sw > w + 1) this.problems.push(`horizontal overflow on ${name} at ${w}px: ${sw}px wide`);
    }
    await this.size(1440, false); await sleep(200);
  }
}

/* ---------- helpers: API, outbox, stub ---------- */
async function http(path, { method = 'GET', headers = {}, body, base = API } = {}) {
  const r = await fetch(base + path, { method, headers: { ...(body !== undefined ? { 'Content-Type': 'application/json' } : {}), ...headers }, body: body !== undefined ? JSON.stringify(body) : undefined });
  const t = await r.text(); let json = null; try { json = JSON.parse(t); } catch {}
  return { status: r.status, json, text: t };
}
const outbox = () => existsSync(OUTBOX) ? readFileSync(OUTBOX, 'utf8').split('\n').filter(Boolean).map(l => JSON.parse(l)) : [];
async function linkFor(to, since) {
  for (let i = 0; i < 40; i++) {
    const m = outbox().slice(since).filter(x => x.to === to && /\/app\/login\?/.test(x.text)).pop();
    if (m) return m.text.match(/http:\/\/localhost:9137\/app\/login\?\S+/)[0];
    await sleep(150);
  }
  throw new Error('no sign-in email for ' + to);
}
const assert = (cond, msg) => { if (!cond) throw new Error('assertion failed: ' + msg); };
const QUESTIONS = ['Should sellers’ business emails be public on their shop pages?', { question: 'Is the orders table meant to be readable by signed-in shoppers?', recommended: 'No: only the buyer and the seller' }];
async function workerFinish(expectId, status, tables) {
  const c = (await http('/worker/claim', { method: 'POST', headers: W })).json.check;
  assert(c && (!expectId || c.id === expectId), `worker claimed ${c && c.id}, expected ${expectId}`);
  const report = `# Leak check: ${c.repo}\n\n_Synthetic e2e report._\n\n## What we found\n` + (tables.length ? tables.map(t => `- \`${t}\`: readable by anyone on the internet`).join('\n') : '- No personal data readable by the wrong people.');
  const r = await http(`/worker/checks/${c.id}/result`, { method: 'POST', headers: W, body: {
    status, cost_usd: 0.46, report_md: report, fix_sql: tables.length ? tables.map(t => `ALTER TABLE public.${t} ENABLE ROW LEVEL SECURITY;`).join('\n') + '\n' : null,
    summary: { tables_leaking: tables, readable_by_anyone: tables, readable_by_signed_in: [], lab_proof_passed: status === 'done', break_risk: 'low', questions_for_owner: tables.length ? QUESTIONS : [] } } });
  assert(r.status === 200, 'worker result ' + r.status);
  return c.id;
}

/* ---------- steps ---------- */
const results = [];
let failed = 0;
async function step(name, page, fn, { allow = [] } = {}) {
  const t0 = Date.now(); let err = null;
  try { await fn(); } catch (e) { err = e; }
  const probs = (page ? page.take() : []).filter(p => !allow.some(a => p.includes(a)));
  // the footer status dot on marketing pages calls /health; ignore nothing else
  const ok = !err && !probs.length;
  if (!ok) failed++;
  results.push({ name, ok, err: err?.message, probs, ms: Date.now() - t0 });
  console.log(`${ok ? 'PASS' : 'FAIL'}  ${name}${err ? '\n      ' + err.message : ''}${probs.length ? '\n      ' + probs.join('\n      ') : ''}`);
  if (err && page) try { const s = await page.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }); writeFileSync(join(SHOTS, `FAIL-${results.length}.png`), Buffer.from(s.data, 'base64')); } catch {}
}

const p = await Page.open();
await cdp('Browser.grantPermissions', { origin: SITE, permissions: ['clipboardReadWrite', 'clipboardSanitizedWrite'] });
const S = {};

await step('an anonymous check started from the home page with the same email (before sign-up)', null, async () => {
  const r = await http('/checks', { method: 'POST', body: { email: OWNER, repo: 'acme/landing' } });
  assert(r.status === 201, 'anonymous check ' + r.status);
  S.anonCheck = r.json.id;
});

await step('signed-out guard redirects /app/settings to login with next', p, async () => {
  await p.goto('/app/settings');
  await p.waitFor(`location.pathname === '/app/login'`, 'login redirect');
  await p.waitText('Sign in to PatchLabs');
  assert((await p.path()).includes('next=%2Fapp%2Fsettings'), 'next kept: ' + await p.path());
  await p.shot('login');
});

await step('login: bad email shows an error, good email shows "Check your inbox"', p, async () => {
  await p.type('#email', 'not-an-email'); await p.click('#send');
  await p.waitText('Enter a valid email address', '#err');
  S.mark = outbox().length;
  await p.type('#email', OWNER); await p.click('#send');
  await p.waitText('Check your inbox', 'h1');
  await p.shot('login-sent');
});

await step('magic link from the outbox signs in and lands on ?next (/app/settings)', p, async () => {
  S.link = await linkFor(OWNER, S.mark);
  assert(S.link.includes('next=%2Fapp%2Fsettings'), 'link carries next: ' + S.link);
  await p.goto(S.link);
  await p.waitFor(`location.pathname === '/app/settings'`, 'landed on settings', 15000);
  await p.waitText('Profile', '#sm');
  assert(await p.eval('!!localStorage.pl_session'), 'session stored');
  S.session = await p.eval('localStorage.pl_session');
  const me = await http('/me', { headers: { Authorization: 'Bearer ' + S.session } });
  S.wid = me.json.workspaces[0].id;
});

await step('re-used magic link shows the expired/used message with a fresh-link form', p, async () => {
  const c2 = await Page.open((await cdp('Target.createBrowserContext')).browserContextId);
  await c2.goto(S.link);
  await c2.waitText('expired or was already used', 'h1');
  assert(!(await c2.eval('location.search')).includes('token'), 'token removed from the address bar');
  await c2.shot('login-expired', { dark: false });
  const probs = c2.take().filter(x => !x.includes('HTTP 400'));
  assert(!probs.length, probs.join('; '));
  await cdp('Target.closeTarget', { targetId: c2.tid });
});

await step('dashboard empty state, usage meters and earlier checks', p, async () => {
  await p.goto('/app/');
  await p.waitText('Add the first app to monitor', '#apps');
  await p.waitFor(`document.querySelectorAll('#meters .meter').length === 3`, 'three usage meters');
  await p.waitText('acme/landing', '#earlier');
  await p.waitText('awaiting verification', '#earlier');
  await p.shot('dashboard-empty', { dark: false });
});

await step('add app: unknown repo shows the API error', p, async () => {
  await p.click('#add');
  await p.type('#a-repo', 'acme/missing-repo'); await p.click('#a-go');
  await p.waitText('couldn', '#a-err');
}, { allow: ['HTTP 422'] });

await step('add app → verification panel → "not found yet" error → file added → first check queued', p, async () => {
  await p.type('#a-repo', 'github.com/acme/shop');
  await p.type('#a-label', 'Acme Ltd');
  await p.click('#a-go');
  await p.waitText('Add the file on GitHub', 'dialog');
  S.code = await p.text('#vcode');
  const href = await p.eval(`document.querySelector('dialog a.btn.primary').href`);
  assert(href.startsWith('https://github.com/acme/shop/new/main?filename=patchlabs-verify.txt&value=' + S.code), 'GitHub link: ' + href);
  await p.shot('add-app-verify', { dark: true });
  await p.click('dialog [data-verify]');
  await p.waitText('couldn', 'dialog [data-verr]');
  await http('/_ctl/file', { method: 'POST', base: STUB, body: { repo: 'acme/shop', content: S.code + '\n' } });
  await p.click('dialog [data-verify]');
  await p.waitText('You’re all set', 'dialog');
  await p.waitText('first check of acme/shop is queued', 'dialog');
  S.aid = await p.eval(`new URL(document.querySelector('dialog a[href^="/app/app?id="]').href).searchParams.get('id')`);
  await p.shot('add-app-done', { light390: false, dark: false });
  await p.click('dialog [data-close]');
  await p.waitText('Checking', '#apps');
}, { allow: ['HTTP 409: POST http://localhost:8001/apps/'] });

await step('free plan: "Add app" explains the 1-app limit instead of the form', p, async () => {
  await p.click('#add');
  await p.waitText('allows 1 app', 'dialog');
  await p.click('dialog [data-close]');
});

await step('worker finishes the first check; dashboard shows "Fix ready" via live refresh', p, async () => {
  const apps = await http(`/workspaces/${S.wid}/apps`, { headers: { Authorization: 'Bearer ' + S.session } });
  S.check1 = apps.json.apps[0].open_check_id;
  await workerFinish(S.check1, 'done', ['profiles', 'sellers']);
  await p.waitText('Fix ready', '#apps', 25000);
  await p.waitText('2 tables leaking', '#apps');
});

await step('app page: status, first-check diff, history, then 409 for a stale "Run check now"', p, async () => {
  await p.goto('/app/app?id=' + S.aid);
  await p.waitText('Fix ready', '#top');
  await p.waitText('everything it found counts as new', '#diff');
  await p.waitText('First check', '#history');
  // someone else queues a check meanwhile (API), so this page's button is stale
  const q = await http(`/apps/${S.aid}/checks`, { method: 'POST', headers: { Authorization: 'Bearer ' + S.session } });
  assert(q.status === 201, 'queued via API');
  S.check2 = q.json.check_id;
  await p.click('#run');
  await p.waitText('already queued or running', '#runmsg');
  await p.waitText('Leaking', '#top');           // re-check running while the last result had leaks
  await p.waitText('A check is running', '#top');
}, { allow: ['HTTP 409: POST http://localhost:8001/apps/'] });

await step('worker finishes the re-check; app page refreshes by itself with new / fixed / still leaking', p, async () => {
  await workerFinish(S.check2, 'done', ['profiles', 'orders']);
  await p.waitFor(`document.querySelector('#diff') && document.querySelector('#diff').innerText.includes('orders') && !document.querySelector('#top').innerText.includes('A check is running')`, 'auto refresh with new diff', 25000);
  const diff = await p.text('#diff');
  assert(/New leaks\s*1\s*orders/i.test(diff.replace(/\n/g, ' ')) || diff.includes('orders'), 'new leak orders');
  assert(diff.includes('sellers'), 'fixed sellers'); assert(diff.includes('profiles'), 'still profiles');
  const hist = await p.eval(`document.querySelectorAll('#history li').length`);
  assert(hist === 2, 'two checks in history, got ' + hist);
});

await step('run limit reached shows the 429 message with an upgrade link', p, async () => {
  await http(`/admin/workspaces/${S.wid}`, { method: 'PATCH', headers: A, body: { run_limit: 1 } });
  await p.click('#run');
  await p.waitText(' this month on the ', '#runmsg');
  assert(await p.eval(`!!document.querySelector('#runmsg a[href="/app/settings#plan"]')`), 'upgrade link');
  await http(`/admin/workspaces/${S.wid}`, { method: 'PATCH', headers: A, body: { run_limit: null } });
}, { allow: ['HTTP 429'] });

await step('schedule (free plan: weekly disabled), client label, badge toggle with live preview and snippets', p, async () => {
  assert(await p.eval(`document.querySelector('#sched option[value=weekly]').disabled`), 'weekly disabled on free');
  await p.select('#sched', 'off'); await p.waitText('No scheduled re-checks', '#next-at');
  let a = await http(`/apps/${S.aid}`, { headers: { Authorization: 'Bearer ' + S.session } });
  assert(a.json.schedule === 'off', 'schedule saved off');
  await p.select('#sched', 'monthly'); await p.waitText('Next re-check', '#next-at');
  await p.type('#label', 'Acme Retail'); await p.click('#label-save');
  await p.waitText('Acme Retail', '#top');
  const before = await http(`/badge/${S.aid}.svg`);
  assert(before.text.includes('private'), 'badge private before');
  await p.click('#badge'); await p.waitText('Badge is public', '#badge-l');
  await p.waitFor(`document.querySelector('#badge-img').complete && document.querySelector('#badge-img').naturalWidth > 0`, 'badge image loaded');
  const after = await http(`/badge/${S.aid}.svg`);
  assert(after.text.includes('fix in progress'), 'badge public: ' + after.text.slice(0, 80));
  assert((await http(`/public/apps/${S.aid}`)).status === 200, 'public status 200');
  const md = await p.text('#snip-md');
  assert(md.includes(`https://api.patchlabs.dev/badge/${S.aid}.svg`) && md.includes(`https://patchlabs.dev/proof?app=${S.aid}`), 'markdown snippet');
  await p.click('.snip .copy');
  await p.waitFor(`[...document.querySelectorAll('.snip .copy')].some(b => b.textContent === 'Copied')`, 'copy feedback');
  await p.shot('app-detail');
});

await step('check page as a member: reject (with reason) one table, approve another, answer questions, signed receipt', p, async () => {
  await p.goto('/check?id=' + S.check2);
  await p.waitText('Approve the fix, or mark tables as intended', '#owner');
  await p.waitText('A tamper-evident record', '#receipt');
  // reject "orders" only, with a reason
  await p.eval(`document.querySelector('[data-tbl][value=profiles]').click()`);
  await p.click('#rej-open');
  await p.click('#reject'); await p.waitText('Say why', '#dec-err');
  await p.type('#rej-why', 'Shoppers see their own orders; sellers see orders for their shop. Marking as intended for this e2e run.');
  await p.click('#reject');
  await p.waitText('marked as meant to be readable', '#own-rec');
  // approve "profiles"
  await p.eval(`document.querySelector('[data-tbl][value=profiles]').click(); document.querySelector('[data-tbl][value=orders]').click()`);
  await p.click('#approve');            // early access: approving is free on every plan, so there is no price step
  await p.waitText('approved the fix for', '#own-rec');
  await p.type('#qa1', 'No: only the buyer and the seller.');
  await p.click('#qa-go');
  await p.waitText('only the buyer and the seller.', '#own-rec');
  await p.waitText('Decisions, answers', '#receipt');
  await p.waitFor(`document.querySelector('#receipt').innerText.includes('2, 1')`, 'receipt shows 2 decisions, 1 answer');
  const r = await http(`/receipts/${S.check2}`);
  assert(r.json.receipt.decisions.length === 2 && r.json.receipt.answers.length === 1, 'receipt from API');
  await p.click('#rc-dl');
  await sleep(800);
  assert(readdirSync(DL).some(f => f.startsWith('patchlabs-receipt-')), 'receipt downloaded');
  await p.shot('check-member');
});

await step('app page shows the rejected table as "Marked as intended"', p, async () => {
  await p.goto('/app/app?id=' + S.aid);
  await p.waitFor(`[...document.querySelectorAll('.diff-card')].some(c => /marked as intended/i.test(c.innerText) && c.innerText.includes('orders'))`, 'orders suppressed in diff');
});

await step('check page for an anonymous viewer: no owner tools, recorded decisions and receipt shown; sample still works', null, async () => {
  const ctx = (await cdp('Target.createBrowserContext')).browserContextId;
  const anon = await Page.open(ctx);
  await anon.goto('/check?id=' + S.check2);
  await anon.waitText('Recorded by the app’s team', '#record');
  await anon.waitText('A tamper-evident record', '#receipt');
  assert(!(await anon.eval(`!!document.querySelector('#owner .owner-tools')`)), 'no owner tools');
  await anon.shot('check-anon', { dark: false });
  await anon.goto('/check?id=sample');
  await anon.waitText('We found leaks, and a tested fix is ready.', '#body');
  assert(!(await anon.eval(`!!document.querySelector('#receipt .receipt')`)), 'no receipt for sample');
  const probs = anon.take();
  assert(!probs.length, probs.join('; '));
  await cdp('Target.closeTarget', { targetId: anon.tid });
});

await step('settings: profile name, free plan seat limit blocks invites, upgrade request', p, async () => {
  await p.goto('/app/settings');
  await p.type('#p-name', 'Olive Owner'); await p.click('#p-save');
  await p.waitText('Name saved', '.toast-host');
  await p.waitText('The 1 seat', '#team');
  await p.select('#u-plan', 'maker');
  await p.type('#u-note', 'Need a second seat for a teammate (e2e).');
  await p.click('#u-go');
  await p.waitText('Request sent for Maker', '#plan');
  const fm = outbox().filter(m => m.to === 'founder@example.test').pop();
  assert(fm && fm.subject.includes('to maker'), 'founder emailed');
});

await step('admin: token gate, refused token, upgrade request applied, plan editor, recent checks with cost', null, async () => {
  const ad = await Page.open((await cdp('Target.createBrowserContext')).browserContextId);
  await ad.goto('/admin');
  await ad.type('#tok', 'wrong-token'); await ad.click('#unlock');
  await ad.waitText('refused', '#gate-err');
  await ad.type('#tok', 'e2e-admin-token'); await ad.click('#unlock');
  await ad.waitFor(`!document.querySelector('#console').hidden`, 'console shown');
  assert(await ad.eval(`sessionStorage.pl_admin === 'e2e-admin-token'`), 'token in sessionStorage');
  await ad.shot('admin-workspaces');
  await ad.click('#t-up');
  await ad.waitText('Set Maker', '#up');
  await ad.click('#up [data-apply]');
  await ad.waitText('applied', '#up');
  let w = await http('/admin/workspaces', { headers: A });
  assert(w.json.workspaces.find(x => x.id === S.wid).plan === 'maker', 'plan is maker');
  await ad.shot('admin-upgrades', { light390: false, dark: false });
  // plan editor: raise the app limit to 5
  await ad.click('#t-ws');
  await ad.type(`#ws tr[data-wid="${S.wid}"] [data-k=app_limit]`, '5');
  await ad.click(`#ws tr[data-wid="${S.wid}"] [data-save]`);
  await ad.waitText('is now on Maker', '.toast-host');
  w = await http('/admin/workspaces', { headers: A });
  assert(w.json.workspaces.find(x => x.id === S.wid).app_limit === 5, 'app_limit 5');
  await ad.click('#t-ck');
  await ad.waitText('$0.46', '#ck');
  await ad.shot('admin-checks', { dark: false });
  // reload keeps the token for this tab
  await ad.goto('/admin'); await ad.waitFor(`!document.querySelector('#console').hidden`, 'still unlocked after reload');
  const probs = ad.take().filter(x => !x.includes('HTTP 401: GET http://localhost:8001/admin/'));
  assert(!probs.length, probs.join('; '));
  await cdp('Target.closeTarget', { targetId: ad.tid });
});

await step('settings on Maker: invite, revoke, invite again; seat count updates', p, async () => {
  await p.goto('/app/settings');
  await p.waitText('1 seat left', '#team');
  await p.type('#i-email', MATE); await p.click('#i-go');
  await p.waitText('Pending invites', '#team');
  await p.click('[data-revoke-inv]');
  await p.waitText('Invite revoked', '.toast-host');
  await p.waitFor(`!document.querySelector('#team').innerText.includes('Pending invites')`, 'invite gone');
  S.mark = outbox().length;
  await p.type('#i-email', MATE); await p.click('#i-go');
  await p.waitText('Pending invites', '#team');
});

await step('teammate accepts the invite in another browser: invite page → magic link → joins → switcher shows both workspaces', null, async () => {
  const msg = await (async () => { for (let i = 0; i < 40; i++) { const m = outbox().slice(S.mark).find(x => x.to === MATE && x.text.includes('invite=')); if (m) return m; await sleep(150); } })();
  assert(msg, 'invite email');
  const inviteLink = msg.text.match(/http:\/\/localhost:9137\/app\/login\?invite=\S+/)[0];
  const tm = await Page.open((await cdp('Target.createBrowserContext')).browserContextId);
  await tm.goto(inviteLink);
  await tm.waitText('You’ve been invited to a workspace', 'h1');
  await tm.shot('login-invite', { dark: false });
  const mark = outbox().length;
  await tm.type('#email', MATE); await tm.click('#send');
  await tm.waitText('Check your inbox', 'h1');
  const link = await linkFor(MATE, mark);
  assert(decodeURIComponent(link).includes('next=/app/login?invite='), 'link carries the invite: ' + link);
  await tm.goto(link);
  await tm.waitFor(`location.pathname === '/app/'`, 'teammate on dashboard', 15000);
  await tm.waitText('You joined', '#flash');
  await tm.waitFor(`document.querySelectorAll('#ws-select option').length === 2`, 'two workspaces in the switcher');
  await tm.waitText('acme/shop', '#apps');
  await tm.shot('dashboard-teammate');
  // switch to the teammate's own workspace and back
  const own = await tm.eval(`[...document.querySelectorAll('#ws-select option')].find(o => !o.selected).value`);
  await tm.select('#ws-select', own);
  await tm.waitText('Add the first app to monitor', '#apps');
  assert(await tm.eval(`localStorage.pl_ws`) === own, 'choice remembered');
  await tm.goto('/app/'); await tm.waitText('Add the first app to monitor', '#apps');
  S.mateSession = await tm.eval('localStorage.pl_session');
  const probs = tm.take();
  assert(!probs.length, probs.join('; '));
  await cdp('Target.closeTarget', { targetId: tm.tid });
});

await step('settings: change teammate role to owner and back, then the last-owner rule', p, async () => {
  await p.goto('/app/settings');
  await p.waitText(MATE, '#team');
  const mateRow = `#team tr:not([data-uid=""]) select[data-role]`;
  const uid = await p.eval(`[...document.querySelectorAll('#team tr[data-uid]')].find(r => r.innerText.includes(${JSON.stringify(MATE)})).dataset.uid`);
  await p.select(`#r-${uid}`, 'owner'); await p.waitText('Role updated', '.toast-host');
  await p.select(`#r-${uid}`, 'member'); await sleep(400);
  await p.waitFor(`document.querySelector('#r-${uid}').value === 'member'`, 'back to member');
  const meUid = await p.eval(`[...document.querySelectorAll('#team tr[data-uid]')].find(r => r.innerText.includes('you')).dataset.uid`);
  await p.select(`#r-${meUid}`, 'member');
  await p.waitText('at least one owner', '#t-err');
  void mateRow;
}, { allow: ['HTTP 409: PATCH'] });

await step('API keys: create (shown once, copy), use it, revoke (confirm), key stops working', p, async () => {
  await p.type('#k-name', 'GitHub Actions'); await p.click('#k-go');
  await p.waitText('Copy your new key', '#k-once');
  const key = await p.text('#k-full');
  assert(/^pl_live_/.test(key), 'full key shown');
  await p.click('#k-once [data-copy]'); await p.waitText('Copied', '#k-once');
  await p.shot('settings', { dark: true });
  let r = await http(`/v1/checks/${S.check2}`, { headers: { 'X-API-Key': key } });
  assert(r.status === 200 && r.json.repo === 'acme/shop', 'key works: ' + r.status);
  await p.click('[data-revoke-key]');
  await p.waitText('Revoke “GitHub Actions”?', 'dialog');
  await p.click('#cf-ok');
  await p.waitText('Key revoked', '.toast-host');
  await p.waitText('No API keys yet', '#keys');
  r = await http(`/v1/checks/${S.check2}`, { headers: { 'X-API-Key': key } });
  assert(r.status === 401, 'revoked key refused: ' + r.status);
});

await step('webhook: invalid URL error, save stub URL, Test shows 200 then 500', p, async () => {
  await p.type('#h-url', 'ftp://example.test/hook'); await p.click('#h-save');
  await p.waitText('https://', '#h-err');
  await p.type('#h-url', 'http://pl-e2e-stub:8080/hook'); await p.click('#h-save');
  await p.waitText('Webhook saved', '.toast-host');
  await p.click('#h-test'); await p.waitText('HTTP 200', '#h-res');
  const hooks = (await http('/_ctl/hooks', { base: STUB })).json;
  assert(hooks.some(h => h.body && h.body.event === 'test'), 'stub received the test event');
  await http('/_ctl/hook_status', { method: 'POST', base: STUB, body: { status: 500 } });
  await p.click('#h-test'); await p.waitText('HTTP 500', '#h-res');
  await http('/_ctl/hook_status', { method: 'POST', base: STUB, body: { status: 200 } });
}, { allow: ['HTTP 422: PATCH'] });

await step('data export downloads JSON with the account in it', p, async () => {
  await p.click('#exp');
  let f;
  for (let i = 0; i < 40 && !f; i++) { await sleep(200); f = readdirSync(DL).find(x => x === 'patchlabs-export.json'); }
  assert(f, 'export file downloaded');
  const data = JSON.parse(readFileSync(join(DL, f), 'utf8'));
  assert(data.user.email === OWNER && data.workspaces.length >= 1, 'export content');
});

await step('delete an app (typed confirmation) and see it gone from the dashboard', p, async () => {
  // add a throwaway second app (Maker allows 3), leave it unverified, then delete it from its page
  await p.goto('/app/');
  await p.click('#add'); await p.type('#a-repo', 'acme/blog'); await p.click('#a-go');
  await p.waitText('Add the file on GitHub', 'dialog');
  await p.click('dialog .modal-body [data-close]');
  await p.waitText('Not verified', '#apps');
  await p.shot('dashboard');
  const blog = await p.eval(`[...document.querySelectorAll('#apps tr[data-id]')].find(r => r.innerText.includes('acme/blog')).dataset.id`);
  await p.goto('/app/app?id=' + blog);
  await p.waitText('Prove the repo is yours', '#top');
  await p.click('#del');
  await p.waitText('Delete acme/blog?', 'dialog');
  assert(await p.eval(`document.querySelector('#cf-ok').disabled`), 'confirm disabled until typed');
  await p.type('#cf-in', 'acme/blog'); await p.click('#cf-ok');
  await p.waitFor(`location.pathname === '/app/'`, 'back on dashboard');
  await p.waitText('Deleted acme/blog', '#flash');
  assert(!(await p.text('#apps')).includes('acme/blog'), 'gone from the list');
});

await step('expired session (401) clears the session and returns to login with next', p, async () => {
  const good = await p.eval('localStorage.pl_session');
  await p.eval(`localStorage.pl_session = 'not-a-real-session'`);
  await p.goto('/app/app?id=' + S.aid);
  await p.waitFor(`location.pathname === '/app/login'`, 'back to login');
  assert(!(await p.eval('localStorage.pl_session')), 'session cleared');
  assert((await p.path()).includes('next=%2Fapp%2Fapp%3Fid%3D'), 'next kept');
  await p.eval(`localStorage.pl_session = ${JSON.stringify(good)}`);
}, { allow: ['HTTP 401: GET http://localhost:8001/me'] });

await step('sign out (#signout) revokes the session server-side', p, async () => {
  await p.goto('/app/');
  await p.waitText('acme/shop', '#apps');
  const tok = await p.eval('localStorage.pl_session');
  await p.click('#signout');
  await p.waitFor(`location.pathname === '/app/login'`, 'login after sign out');
  await p.waitText('You’re signed out', '#view');
  assert(!(await p.eval('localStorage.pl_session')), 'session cleared');
  assert((await http('/me', { headers: { Authorization: 'Bearer ' + tok } })).status === 401, 'old session revoked');
});

await step('sign in again and delete the account (type DELETE); teammate inherits the workspace', p, async () => {
  const mark = outbox().length;
  await p.type('#email', OWNER); await p.click('#send'); await p.waitText('Check your inbox', 'h1');
  await p.goto(await linkFor(OWNER, mark));
  await p.waitFor(`location.pathname === '/app/'`, 'dashboard', 15000);
  await p.goto('/app/settings#delete');
  await p.waitText('Delete account', '#delete');
  assert(await p.eval(`document.querySelector('#d-go').disabled`), 'disabled until DELETE typed');
  await p.type('#d-type', 'DELETE'); await p.click('#d-go');
  await p.waitFor(`location.pathname === '/app/login'`, 'login after delete');
  await p.waitText('deleted', '#view');
  const me = await http('/me', { headers: { Authorization: 'Bearer ' + S.mateSession } });
  const shared = me.json.workspaces.find(w => w.id === S.wid);
  assert(shared && shared.role === 'owner', 'teammate now owns the shared workspace');
  const r = await http(`/checks/${S.check2}`);
  assert(r.json.decisions.every(d => d.by === 'a former member'), 'decisions re-labelled');
});

await step('mobile header and pages: login at 390', p, async () => { await p.shot('login-deleted', { dark: false }); });

/* ---------- report ---------- */
console.log(`\n${results.length - failed} of ${results.length} steps passed. Screenshots: ${SHOTS}`);
writeFileSync(join(SHOTS, 'results.json'), JSON.stringify(results, null, 2));
chrome.kill(); await sleep(500);
try { rmSync(profile, { recursive: true, force: true, maxRetries: 5 }); rmSync(DL, { recursive: true, force: true }); } catch {}
process.exit(failed ? 1 : 0);

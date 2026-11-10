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
const OUTBOX = '/Users/manraj/PycharmProjects/patchlabs/.shots/e2e-outbox/outbox.jsonl';
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

/* ---------- account-layer UI checks (roles, client apps, audit, webhook format, findings tags) ---------- */
const results = []; let failed = 0;
async function step(name, page, fn, { allow = [] } = {}) {
  let err = null; try { await fn(); } catch (e) { err = e; }
  const probs = (page ? page.take() : []).filter(x => !allow.some(a => x.includes(a)) && !x.includes('/health'));
  const ok = !err && !probs.length; if (!ok) failed++;
  console.log((ok ? 'PASS  ' : 'FAIL  ') + name + (err ? '\n      ' + err.message : '') + (probs.length ? '\n      ' + probs.join('\n      ') : ''));
  if (!ok && page) { const s = await page.send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: true }); writeFileSync(join(SHOTS, `roles-FAIL-${results.length}.png`), Buffer.from(s.data, 'base64')); }
  results.push({ name, ok });
}
const H = s => ({ Authorization: 'Bearer ' + s });
async function signIn(email, invite) {
  const mark = outbox().length;
  await http('/auth/start', { method: 'POST', body: { email } });
  let tok;
  for (let i = 0; i < 40 && !tok; i++) { const m = outbox().slice(mark).filter(x => x.to === email).pop(); if (m) tok = decodeURIComponent(m.text.match(/token=([^&\s]+)/)[1]); else await sleep(150); }
  const r = await http('/auth/finish', { method: 'POST', body: invite ? { token: tok, invite } : { token: tok } });
  return r.json.session;
}
function inviteToken(email, since) { const m = outbox().slice(since).filter(x => x.to === email && /invite=/.test(x.text)).pop(); return m && decodeURIComponent(m.text.match(/invite=([^&\s]+)/)[1]); }
async function as(session, wid) {
  const ctx = (await cdp('Target.createBrowserContext')).browserContextId;
  await cdp('Browser.setDownloadBehavior', { behavior: 'allow', downloadPath: DL, browserContextId: ctx, eventsEnabled: true });
  const pg = await Page.open(ctx);
  await pg.goto('/'); await pg.eval(`localStorage.pl_session = ${JSON.stringify(session)}; localStorage.pl_ws = ${JSON.stringify(wid)}`);
  return pg;
}
const S = {};
const FIND = [
  { id: 'PL-001', line: 'lab', severity: 'critical', title: 'Anyone on the internet can read personal data', object: 'public.profiles', file: 'supabase/migrations/1_init.sql', line_no: 3, evidence: 'USING (true)', proven: true, proof: 'anon read 2 rows', fix: 'owner-only select', fixed_in_lab: true },
  { id: 'PL-010', line: 'code', severity: 'critical', title: 'Service role key in client code', object: 'src/lib/admin.ts', file: 'src/lib/admin.ts', line_no: 2, evidence: 'eyJ…', proven: false, proof: '', fix: 'rotate', fixed_in_lab: false }];
async function finish(status, findings, tables) {
  const c = (await http('/worker/claim', { method: 'POST', headers: W })).json.check;
  await http(`/worker/checks/${c.id}/result`, { method: 'POST', headers: W, body: { status, report_md: '# test', fix_sql: tables.length ? 'select 1;' : null,
    summary: { tables_leaking: tables, readable_by_anyone: tables, readable_by_signed_in: [], lab_proof_passed: true, findings, counts: { critical: findings.filter(f => f.severity === 'critical').length } } } });
  return c.id;
}

await step('setup: owner, agency plan, two verified apps, two finished checks', null, async () => {
  S.owner = await signIn('boss@example.test');
  S.wid = (await http('/me', { headers: H(S.owner) })).json.workspaces[0].id;
  await http(`/admin/workspaces/${S.wid}`, { method: 'PATCH', headers: A, body: { plan: 'agency' } });
  S.apps = [];
  for (const repo of ['acme/shop', 'acme/blog']) {
    const a = (await http(`/workspaces/${S.wid}/apps`, { method: 'POST', headers: H(S.owner), body: { repo } })).json;
    await http('/_ctl/file', { method: 'POST', base: STUB, body: { repo, content: a.verify.code + '\n' } });
    const v = await http(`/apps/${a.id}/verify`, { method: 'POST', headers: H(S.owner) });
    assert(v.status === 200, 'verify ' + repo + ' ' + v.status + ' ' + v.text);
    S.apps.push(a.id);
    await finish('done', FIND, ['profiles']);
  }
  // a re-check of the shop where PL-010 is gone: it should show as fixed
  await http(`/apps/${S.apps[0]}/checks`, { method: 'POST', headers: H(S.owner) });
  await finish('done', [FIND[0]], ['profiles']);
});

const p = await as(S.owner, S.wid);
await step('owner: invite a viewer and a client (with one app) from the Team form', p, async () => {
  await p.goto('/app/settings#team'); await p.waitText('Invite someone', '#team');
  S.mark = outbox().length;
  await p.type('#i-email', 'viewer@example.test'); await p.select('#i-role', 'viewer'); await p.click('#i-go');
  await p.waitText('viewer@example.test', '#team');
  await p.type('#i-email', 'client@example.test'); await p.select('#i-role', 'client');
  await p.waitFor(`!document.querySelector('#i-apps-box').hidden`, 'app picker shown for clients');
  await p.eval(`document.querySelector('#i-apps input[value="${S.apps[1]}"]').click()`);
  await p.click('#i-go'); await p.waitText('client@example.test', '#team');
  const w = (await http(`/workspaces/${S.wid}`, { headers: H(S.owner) })).json;
  const ci = w.invites.find(i => i.email === 'client@example.test'), vi = w.invites.find(i => i.email === 'viewer@example.test');
  assert(vi && vi.role === 'viewer', 'viewer invite in DB'); assert(ci && ci.role === 'client' && ci.app_ids.length === 1 && ci.app_ids[0] === S.apps[1], 'client invite with app: ' + JSON.stringify(ci));
});
await step('invitees join', null, async () => {
  S.viewer = await signIn('viewer@example.test', inviteToken('viewer@example.test', S.mark));
  S.client = await signIn('client@example.test', inviteToken('client@example.test', S.mark));
  const w = (await http(`/workspaces/${S.wid}`, { headers: H(S.owner) })).json;
  S.vuid = w.members.find(m => m.email === 'viewer@example.test').user_id; S.cuid = w.members.find(m => m.email === 'client@example.test').user_id;
});

const v = await as(S.viewer, S.wid);
await step('viewer: read-only dashboard, app page and settings', v, async () => {
  await v.goto('/app/'); await v.waitText('acme/shop', '#apps');
  assert(await v.eval(`document.querySelector('#add').hidden`), 'Add app hidden');
  assert(!(await v.eval(`!!document.querySelector('[data-run]')`)), 'no Run now');
  await v.goto('/app/app?id=' + S.apps[0]); await v.waitText('Only a workspace owner or admin can change these', '#side');
  assert(!(await v.eval(`!!document.querySelector('#run, #sched, #del, #badge')`)), 'no app controls');
  await v.waitFor(`!!document.querySelector('#findings .fnd')`, 'findings shown');
  assert(!(await v.eval(`[...document.querySelectorAll('#findings a')].some(a => /Approve/.test(a.textContent))`)), 'no approve link');
  await v.goto('/app/settings'); await v.waitText('Team', '#sm');
  assert(!(await v.eval(`!!document.querySelector('#audit, #webhook, #kf, #if, #uf, #team [data-role]')`)), 'no manage controls in settings');
  await v.shot('roles-viewer-settings', { light390: false, dark: false });
});
const c = await as(S.client, S.wid);
await step('client: sees only the shared app, a "Shared with you" note, no team or keys', c, async () => {
  await c.goto('/app/'); await c.waitText('acme/blog', '#apps');
  assert(!(await c.text('#apps')).includes('acme/shop'), 'other app hidden');
  await c.waitText('Shared with you by', '#ws-line');
  assert(await c.eval(`document.querySelector('#usage-sec').hidden`), 'usage hidden');
  await c.goto('/app/settings'); await c.waitText('Profile', '#sm');
  assert(!(await c.eval(`!!document.querySelector('#team, #keys, #audit, #webhook, #plan')`)), 'client settings: profile, data, delete only');
  await c.shot('roles-client-dashboard', { light390: true, dark: false });
});
await step('owner: change the viewer to approver; share both apps with the client', p, async () => {
  await p.goto('/app/settings?r=2#team'); await p.waitText('viewer@example.test', '#team');
  await p.select(`#r-${S.vuid}`, 'approver'); await p.waitText('Role updated', '.toast-host');
  let w = (await http(`/workspaces/${S.wid}`, { headers: H(S.owner) })).json;
  assert(w.members.find(m => m.user_id === S.vuid).role === 'approver', 'role saved');
  await p.waitFor(`!!document.querySelector('tr[data-uid="${S.cuid}"] details.apps-edit')`, 'client app editor');
  await p.eval(`(() => { const d = document.querySelector('tr[data-uid="${S.cuid}"] details.apps-edit'); d.open = true; d.querySelector('input[value="${S.apps[0]}"]').click(); })()`);
  await p.click(`tr[data-uid="${S.cuid}"] [data-save-apps]`); await p.waitText('Shared apps saved', '.toast-host');
  w = (await http(`/workspaces/${S.wid}`, { headers: H(S.owner) })).json;
  assert(w.members.find(m => m.user_id === S.cuid).app_ids.length === 2, 'client now has 2 apps');
});
await step('owner: last owner can’t demote themselves (API sentence shown)', p, async () => {
  const me = (await http('/me', { headers: H(S.owner) })).json.user.id;
  await p.select(`#r-${me}`, 'admin'); await p.waitText('at least one owner', '#t-err');
}, { allow: ['HTTP 409'] });
await step('owner: audit log lists events, filters by family, loads, exports CSV', p, async () => {
  await p.goto('/app/settings?r=3#audit'); await p.waitFor(`document.querySelectorAll('#au-list tbody tr').length > 3`, 'audit rows');
  await p.waitText('changed', '#au-list');
  await p.select('#au-action', 'member'); await p.waitFor(`[...document.querySelectorAll('#au-list tbody tr')].length > 0 && [...document.querySelectorAll('#au-list tbody tr .mono')].every(e => e.textContent.startsWith('member.'))`, 'only member events');
  await p.waitText('role from viewer to approver', '#au-list');
  const before = readdirSync(DL).length;
  await p.click('#au-csv'); await p.waitFor(`document.querySelector('.toast-host') && document.querySelector('.toast-host').innerText.includes('Audit log exported')`, 'export toast');
  for (let i = 0; i < 40 && readdirSync(DL).filter(f => f.endsWith('.csv')).length === 0; i++) await sleep(150);
  assert(readdirSync(DL).some(f => f.endsWith('.csv')), 'csv downloaded');
  const r = await http(`/workspaces/${S.wid}/audit?action=audit.exported`, { headers: H(S.owner) });
  assert(r.json.events.length >= 1, 'export recorded');
  await p.select('#au-action', ''); await p.shot('roles-audit', { light390: true, dark: true });
});
await step('owner: webhook format override saves and shows the kind', p, async () => {
  await p.goto('/app/settings?r=4#webhook');
  await p.type('#h-url', 'https://example.com/hooks/patchlabs'); await p.waitText('Signed JSON', '#h-hint');
  await p.select('#h-fmt', 'slack'); await p.waitText('Always sent as Slack', '#h-hint');
  await p.click('#h-save'); await p.waitText('Webhook saved', '.toast-host');
  const w = (await http(`/workspaces/${S.wid}`, { headers: H(S.owner) })).json;
  assert(w.webhook_format === 'slack' && w.webhook_kind === 'slack', 'format saved: ' + w.webhook_format + '/' + w.webhook_kind);
  await p.waitText('Slack', '#h-kind');
  assert(!(await p.eval(`!!document.querySelector('#h-secret')`)), 'no secret block for Slack');
  await p.click('#h-test'); await p.waitFor(`document.querySelector('#h-res').innerText.includes('Slack') || document.querySelector('#h-err').innerText.length`, 'test result shows the format', 15000);
  await p.select('#h-fmt', 'json'); await p.click('#h-save'); await p.waitText('Webhook saved', '.toast-host');
  await p.waitFor(`!!document.querySelector('#h-secret')`, 'secret block for signed JSON');
  await p.shot('roles-webhook', { light390: false, dark: false });
});
await step('app page: findings carry CWE/OWASP tags, open list and fixed list', p, async () => {
  await p.goto('/app/app?id=' + S.apps[0]);
  await p.waitFor(`document.querySelectorAll('#findings .ftag').length > 0`, 'tags on findings');
  await p.waitFor(`!document.querySelector('#age-sec').hidden`, 'open and fixed section');
  await p.waitText('Fixed recently', '#ages');
  assert(await p.eval(`[...document.querySelectorAll('#ages .age-fixed')].some(d => d.innerText.includes('PL-010'))`), 'PL-010 in the fixed list');
  assert(await p.eval(`!!document.querySelector('a.ftag[href^="https://cwe.mitre.org/data/definitions/"]')`), 'CWE link');
  await p.shot('roles-app-ages', { light390: true, dark: false });
});
await step('report page prints: Download PDF button present', p, async () => {
  const k = (await http(`/apps/${S.apps[0]}`, { headers: H(S.owner) })).json.checks[0].id;
  await p.goto('/app/report?id=' + k); await p.waitFor(`!!document.querySelector('[data-print]')`, 'PDF button');
});
console.log(`\n${results.length - failed} of ${results.length} role steps passed.`);
chrome.kill(); await sleep(400); process.exit(failed ? 1 : 0);

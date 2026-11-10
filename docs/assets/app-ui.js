// PatchLabs signed-in app helpers, shared by /app/*, /admin and the owner tools on /check. Needs app.js (api, session).
// Everything hangs off window.PL:
//   PL.esc(s), PL.date(iso), PL.dateTime(iso), PL.rel(iso)             formatting (always escape API strings)
//   PL.guard()                                                        redirect to /app/login?next=… when signed out
//   PL.call(path, opts)                                               api() that sends a 401 back to the login page
//   PL.boot({ onWorkspace })                                          guard + /me + workspace switcher + sign-out → {me, ws}
//   PL.status(app) / PL.pill(st)                                      the app status pill (Leaking, Fix ready, …)
//   PL.modal({...}), PL.confirm({...})                                <dialog> helpers
//   PL.busy(btn, text) → restore()                                    disable a button while a request runs
//   PL.useDemo(url)                                                   switch the data source to a static demo workspace (see below)
//   PL.href(kind, params)                                             links that stay inside /app/* or /demo/*
//   PL.findings(summary) / PL.report(el, check, ctx)                  findings (V3 shape, older checks mapped) and the report view
// Views (dashboard, app detail, report) live in /assets/app-pages.js and are shared by /app/* and /demo/*.
(function () {
  'use strict';
  var PL = window.PL = {};
  var d = document;

  PL.$ = function (id) { return d.getElementById(id); };
  PL.qs = function (k) { return new URLSearchParams(location.search).get(k); };
  PL.esc = function (s) {
    return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; });
  };
  PL.store = {
    get: function (k) { try { return localStorage.getItem(k); } catch (e) { return null; } },
    set: function (k, v) { try { localStorage.setItem(k, v); } catch (e) {} },
    del: function (k) { try { localStorage.removeItem(k); } catch (e) {} }
  };
  PL.toast = function (msg, kind) {
    if (window.toast) window.toast(msg, kind);
    else setTimeout(function () { PL.toast(msg, kind); }, 120);
  };

  /* ---- dates ---- */
  var MON = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];
  var parse = function (iso) { var t = iso ? new Date(iso) : null; return t && !isNaN(t) ? t : null; };
  var pad = function (n) { return n < 10 ? '0' + n : '' + n; };
  PL.date = function (iso) { var t = parse(iso); return t ? t.getDate() + ' ' + MON[t.getMonth()] + ' ' + t.getFullYear() : ''; };
  PL.dateTime = function (iso) { var t = parse(iso); return t ? PL.date(iso) + ', ' + pad(t.getHours()) + ':' + pad(t.getMinutes()) : ''; };
  PL.rel = function (iso) {
    var t = parse(iso); if (!t) return '';
    var s = (t - Date.now()) / 1000, a = Math.abs(s), f = s > 0;
    var u = a < 45 ? null : a < 3600 ? [Math.round(a / 60), 'minute'] : a < 86400 ? [Math.round(a / 3600), 'hour'] : a < 86400 * 45 ? [Math.round(a / 86400), 'day'] : null;
    if (!u) return a < 45 ? 'just now' : PL.date(iso);
    var txt = u[0] + ' ' + u[1] + (u[0] === 1 ? '' : 's');
    return f ? 'in ' + txt : txt + ' ago';
  };
  PL.when = function (iso) { return iso ? '<span class="when" title="' + PL.esc(PL.dateTime(iso)) + '">' + PL.esc(PL.rel(iso)) + '<small>' + PL.esc(PL.date(iso)) + '</small></span>' : '<span class="muted">–</span>'; };

  /* ---- session ---- */
  PL.loginUrl = function () { return '/app/login?next=' + encodeURIComponent(location.pathname + location.search + location.hash); };
  PL.toLogin = function () { location.replace(PL.loginUrl()); };
  PL.guard = function () { if (!session.get()) { PL.toLogin(); return false; } return true; };
  PL.call = async function (path, opts) {
    if (PL.demo) return PL.demo.call(path, opts || {});
    try { return await api(path, opts); }
    catch (e) {
      if (e.status === 401) { session.clear(); PL.toLogin(); e.redirecting = true; }
      throw e;
    }
  };
  PL.signout = async function () {
    try { await api('/auth/logout', { method: 'POST' }); } catch (e) {}
    session.clear(); PL.store.del('pl_ws');
    location.href = '/app/login?signed_out=1';
  };
  PL.wireSignout = function () {
    var b = PL.$('signout'); if (b) b.addEventListener('click', function () { b.disabled = true; b.textContent = 'Signing out…'; PL.signout(); });
  };

  /* ---- workspaces ---- */
  PL.pickWorkspace = function (me) {
    var ws = me.workspaces || [], saved = PL.store.get('pl_ws');
    return ws.filter(function (w) { return w.id === saved; })[0] || ws.filter(function (w) { return w.role === 'owner'; })[0] || ws[0] || null;
  };
  PL.mountSwitcher = function (me, current, onChange) {
    var slot = PL.$('ws-slot'); if (!slot || !current) return;
    var ws = me.workspaces || [];
    if (ws.length < 2) {
      slot.className = 'single';
      slot.innerHTML = '<span class="ws-name" title="Workspace">' + PL.esc(current.name) + '</span>';
      return;
    }
    slot.className = '';
    slot.innerHTML = '<label class="sr-only" for="ws-select">Workspace</label><select class="input" id="ws-select">' + ws.map(function (w) {
      return '<option value="' + PL.esc(w.id) + '"' + (w.id === current.id ? ' selected' : '') + '>' + PL.esc(w.name) + (w.role === 'owner' ? '' : ' (' + PL.roleName(w.role).toLowerCase() + ')') + '</option>';
    }).join('') + '</select>';
    PL.$('ws-select').addEventListener('change', function () {
      PL.store.set('pl_ws', this.value);
      var w = ws.filter(function (x) { return x.id === this.value; }, this)[0];
      if (onChange) onChange(w); else location.reload();
    });
  };
  // guard + me + switcher + sign out. Resolves {me, ws}; never resolves when redirecting.
  PL.boot = async function (opts) {
    opts = opts || {};
    PL.wireSignout();
    if (!PL.demo && !PL.guard()) return new Promise(function () {});
    var me;
    try { me = await PL.call('/me'); }
    catch (e) { if (e.redirecting) return new Promise(function () {}); throw e; }
    PL.me = me;
    var ws = PL.pickWorkspace(me);
    if (ws) PL.store.set('pl_ws', ws.id);
    PL.mountSwitcher(me, ws, opts.onWorkspace);
    return { me: me, ws: ws };
  };

  /* ---- labels ---- */
  PL.PLANS = { free: 'Free', maker: 'Maker', agency: 'Agency', enterprise: 'Enterprise' };
  PL.planName = function (p) { return PL.PLANS[p] || p; };
  PL.SCHEDULES = { off: 'Off (manual only)', weekly: 'Weekly', monthly: 'Monthly' };
  PL.TRIGGERS = { verify: 'First check', manual: 'Run by hand', scheduled: 'Scheduled re-check', api: 'From the API' };
  PL.plural = function (n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); };

  // Status of a monitored app, from GET /workspaces/{wid}/apps or GET /apps/{id}.
  // info (optional): PL.findingInfo(summary) of the last check, so findings that aren't data leaks (code, other lab
  // checks) show too. "no_leaks" means no DATA leaks: such a check can still carry code findings.
  PL.status = function (a, info) {
    var sup = a.suppressed_tables || [], last = a.last_check;
    var open = (last && last.tables_leaking || []).filter(function (t) { return sup.indexOf(t) < 0; });
    info = info || (last && last.counts ? { counts: last.counts } : null);
    var c = info && info.counts, total = PL.total(c), serious = c ? (c.critical || 0) + (c.high || 0) : 0;
    var what = info && info.code === total ? 'code finding' : 'finding';
    if (a.verified && !a.open_check_id && last && last.status !== 'failed' && !open.length && total)
      return { cls: serious ? 'pending' : 'proven', label: 'No data leaks', note: PL.plural(total, what) + (serious ? ' (' + PL.sevLabel({ critical: c.critical, high: c.high }) + ')' : '') + (sup.length ? ' · ' + PL.plural(sup.length, 'table') + ' marked as intended' : '') };
    if (!a.verified) return { cls: 'neutral', label: 'Not verified', note: 'Prove the repo is yours to start' };
    if (a.open_check_id && last && open.length && last.status !== 'failed') return { cls: 'leak', label: 'Leaking', note: 'Re-check running now' };
    if (a.open_check_id) return { cls: 'pending', label: 'Checking', note: 'Usually 5 to 15 minutes' };
    if (!last) return { cls: 'neutral', label: 'Not checked yet', note: '' };
    if (last.status === 'failed') return { cls: 'neutral', label: 'Check failed', note: 'We were alerted; run it again any time' };
    if (last.status === 'no_leaks' || !open.length) return { cls: 'proven', label: 'No known leaks', note: sup.length ? PL.plural(sup.length, 'table') + ' marked as intended' : '' };
    if (last.status === 'needs_review') return { cls: 'pending', label: 'Needs review', note: PL.plural(open.length, 'table') + ' leaking; a person is checking the fix' };
    return { cls: 'leak', label: 'Fix ready', note: PL.plural(open.length, 'table') + ' leaking; a tested fix is waiting' };
  };
  PL.pill = function (st) { return '<span class="pill ' + st.cls + '">' + PL.esc(st.label) + '</span>'; };
  PL.checkPill = function (status) {
    var m = { done: ['leak', 'fix ready'], no_leaks: ['proven', 'no data leaks'], needs_review: ['pending', 'in review'], queued: ['pending', 'queued'],
      running: ['pending', 'running'], awaiting_verification: ['pending', 'awaiting verification'], failed: ['neutral', 'failed'] }[status] || ['neutral', status];
    return '<span class="pill ' + m[0] + '">' + PL.esc(m[1]) + '</span>';
  };
  PL.tables = function (arr) {
    return arr && arr.length ? '<span class="tlist">' + arr.map(function (t) { return '<code>' + PL.esc(t) + '</code>'; }).join('') + '</span>' : '<span class="muted">none</span>';
  };

  /* ---- UI bits ---- */
  PL.busy = function (btn, text) {
    if (!btn) return function () {};
    var html = btn.innerHTML; btn.disabled = true; btn.setAttribute('aria-busy', 'true');
    btn.innerHTML = '<span class="spin" aria-hidden="true"></span>' + PL.esc(text || 'Working…');
    return function () { btn.disabled = false; btn.removeAttribute('aria-busy'); btn.innerHTML = html; };
  };
  PL.skeleton = function (lines) {
    var h = ''; for (var i = 0; i < (lines || 3); i++) h += '<div class="skeleton sk-line" style="width:' + [72, 94, 58, 86, 66][i % 5] + '%;margin:12px 0"></div>';
    return h;
  };
  PL.errorBox = function (el, err, retry) {
    el.innerHTML = '<div class="panel"><p class="err mb-0" role="alert">' + PL.esc(err.message || String(err)) + '</p>' +
      (retry ? '<button class="btn secondary small mt-2" type="button">Try again</button>' : '') + '</div>';
    if (retry) el.querySelector('button').onclick = retry;
  };
  PL.download = function (blob, name) {
    var a = d.createElement('a'); a.href = URL.createObjectURL(blob); a.download = name; d.body.appendChild(a); a.click(); a.remove();
    setTimeout(function () { URL.revokeObjectURL(a.href); }, 4000);
  };

  // modal({ title, body: html, foot: html, onOpen(dlg), onClose() }) → dialog element (remove()d on close)
  PL.modal = function (o) {
    var dlg = d.createElement('dialog'); dlg.className = 'modal';
    var tid = 'm' + Math.random().toString(36).slice(2, 8);
    dlg.setAttribute('aria-labelledby', tid);
    dlg.innerHTML = '<div class="modal-head"><h2 id="' + tid + '">' + PL.esc(o.title) + '</h2><button class="x" type="button" aria-label="Close" data-close>×</button></div>' +
      '<div class="modal-body">' + (o.body || '') + '</div>' + (o.foot ? '<div class="modal-foot">' + o.foot + '</div>' : '');
    d.body.appendChild(dlg);
    dlg.addEventListener('click', function (e) {
      if (e.target === dlg || (e.target.closest && e.target.closest('[data-close]'))) dlg.close();
    });
    dlg.addEventListener('close', function () { if (o.onClose) o.onClose(); dlg.remove(); });
    dlg.showModal();
    dlg.setTitle = function (t) { dlg.querySelector('#' + tid).textContent = t; };
    dlg.body = dlg.querySelector('.modal-body');
    if (o.onOpen) o.onOpen(dlg);
    return dlg;
  };
  // confirm({ title, text (html), confirm: 'Delete', danger: true, type: 'DELETE' }) → Promise<boolean>
  PL.confirm = function (o) {
    return new Promise(function (res) {
      var done = false;
      var dlg = PL.modal({
        title: o.title,
        body: '<div class="muted">' + o.text + '</div>' + (o.type ? '<div class="field mt-2"><label for="cf-in">Type <code>' + PL.esc(o.type) + '</code> to confirm</label><input id="cf-in" class="input mono" autocomplete="off" spellcheck="false"></div>' : ''),
        foot: '<button class="btn ghost" type="button" data-close>Cancel</button><button class="btn ' + (o.danger ? 'danger' : 'primary') + '" type="button" id="cf-ok"' + (o.type ? ' disabled' : '') + '>' + PL.esc(o.confirm || 'Confirm') + '</button>',
        onClose: function () { if (!done) res(false); }
      });
      var ok = dlg.querySelector('#cf-ok'), inp = dlg.querySelector('#cf-in');
      if (inp) { inp.focus(); inp.addEventListener('input', function () { ok.disabled = inp.value.trim() !== o.type; }); }
      ok.addEventListener('click', function () { done = true; res(true); dlg.close(); });
    });
  };

  // verification panel for an unverified app: { file, code, add_url }
  PL.verifyHtml = function (repo, v) {
    return '<div class="verify-box"><p class="muted">So nobody can monitor an app they don’t own, add a file named <b class="ink">' + PL.esc(v.file) + '</b> to the default branch of <b class="ink">' + PL.esc(repo) + '</b> containing this code:</p>' +
      '<p class="row"><code class="verify-code" id="vcode">' + PL.esc(v.code) + '</code><button class="copy" type="button" data-copy data-copy-text="' + PL.esc(v.code) + '">Copy code</button></p>' +
      '<div class="row mt-2"><a class="btn primary" target="_blank" rel="noopener" href="' + PL.esc(v.add_url) + '">Add the file on GitHub <span aria-hidden="true">↗</span></a>' +
      '<button class="btn secondary" type="button" data-verify>I’ve added it</button></div><p class="err" role="alert" data-verr></p>' +
      '<p class="small muted mt-2 mb-0">The GitHub link opens the new-file page with the name and code filled in: press “Commit changes”, then come back. You can delete the file once you’re verified.</p></div>';
  };
  PL.wireVerify = function (root, appId, onDone) {
    var b = root.querySelector('[data-verify]'), err = root.querySelector('[data-verr]');
    if (!b) return;
    b.addEventListener('click', async function () {
      var restore = PL.busy(b, 'Checking GitHub…'); err.textContent = '';
      try { var r = await PL.call('/apps/' + encodeURIComponent(appId) + '/verify', { method: 'POST' }); onDone(r); }
      catch (e) { restore(); err.textContent = e.message; }
    });
  };

  // refresh(fn, ms): calls fn every ms while the tab is visible; returns {stop}
  PL.every = function (fn, ms) {
    var t = null, stopped = false;
    var tick = async function () { if (stopped) return; if (!d.hidden) { try { await fn(); } catch (e) {} } t = setTimeout(tick, ms); };
    t = setTimeout(tick, ms);
    return { stop: function () { stopped = true; clearTimeout(t); } };
  };
  /* ---- data source: the live API, or a static demo workspace ----------------------------------------------------
     PL.useDemo('/demo/workspace.json') loads {anchor, routes: {"/path": response}}. From then on PL.call() answers every
     GET from routes (dates shifted so that "anchor" reads as now) and never touches the network. Writes are not made:
     they open PL.demoNotice() and reject with err.demo = true; PL.handled(err) is true for those and for 401 redirects,
     so views can simply stop. The views in app-pages.js don't know which source they run on. */
  PL.demo = null;
  PL.useDemo = async function (url) {
    var r = await fetch(url, { cache: 'no-cache' });
    if (!r.ok) throw new Error('The demo workspace didn’t load. Refresh the page to try again.');
    var data = await r.json(), shift = Date.now() - new Date(data.anchor).getTime();
    var ISO = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}/;
    var move = function (v) {
      if (typeof v === 'string') return ISO.test(v) ? new Date(new Date(v).getTime() + shift).toISOString() : v;
      if (Array.isArray(v)) return v.map(move);
      if (v && typeof v === 'object') { var o = {}; for (var k in v) o[k] = move(v[k]); return o; }
      return v;
    };
    // the audit route filters and pages like the real one: action (exact or family), actor, since/until dates, before, limit
    var auditPage = function (r, q) {
      var a = q.get('action'), who = q.get('actor'), since = q.get('since'), until = q.get('until'), before = +q.get('before') || 0, limit = +q.get('limit') || 50;
      var ev = r.events.filter(function (x) {
        var day = x.at.slice(0, 10);
        return (!a || (a.indexOf('.') > 0 ? x.action === a : x.action.indexOf(a + '.') === 0)) &&
          (!who || (['api_key', 'admin', 'system'].indexOf(who) >= 0 ? x.actor.kind === who : x.actor.id === who)) &&
          (!since || day >= since) && (!until || day <= until) && (!before || x.id < before);
      });
      return { events: ev.slice(0, limit), next_before: ev.length > limit ? ev[limit - 1].id : null, actions: r.actions };
    };
    PL.demo = {
      call: async function (path, opts) {
        if ((opts.method || 'GET').toUpperCase() !== 'GET') {
          PL.demoNotice();
          var w = new Error('This is the demo workspace, so nothing is saved.'); w.demo = true; w.status = 0; throw w;
        }
        var bare = path.split('?')[0], hit = data.routes[bare];
        if (!hit) { var e = new Error('That isn’t part of the demo workspace.'); e.status = 404; throw e; }
        var out = move(hit);
        if (/\/audit$/.test(bare)) out = auditPage(out, new URLSearchParams(path.split('?')[1] || ''));
        return out;
      }
    };
  };
  PL.handled = function (e) { return !!(e && (e.redirecting || e.demo)); };
  PL.demoNotice = function (what) {
    if (d.querySelector('dialog.modal[data-demo-notice]')) return;
    var dlg = PL.modal({
      title: 'This is the demo workspace',
      body: '<p class="muted">' + PL.esc(what || 'Everything here is fake data, so nothing you change is saved.') + '</p>' +
        '<p class="muted mb-0">Check your own app to get a real workspace. Your first app is free, and it reads your public repo only.</p>',
      foot: '<button class="btn ghost" type="button" data-close>Keep exploring</button><a class="btn primary" href="/#check">Check my app free</a>'
    });
    dlg.setAttribute('data-demo-notice', '');
  };
  // any element with data-demo="sentence" opens the demo notice (used for links that only make sense when signed in)
  d.addEventListener('click', function (e) {
    var t = e.target.closest && e.target.closest('[data-demo]');
    if (t) { e.preventDefault(); PL.demoNotice(t.getAttribute('data-demo') || undefined); }
  });

  // Links that stay inside the app or the demo. kind: apps | app | report | check (the public report with the owner
  // tools: approve, answers, receipt) | support (new ticket; null in the demo, use PL.supportLink)
  PL.href = function (kind, p) {
    p = p || {};
    var base = PL.demo ? '/demo/' : '/app/', q = encodeURIComponent;
    if (kind === 'apps') return base;
    if (kind === 'app') return base + 'app?id=' + q(p.id);
    if (kind === 'report') return base + 'report?id=' + q(p.id);
    if (kind === 'check') return PL.demo ? '/check?id=sample' : '/check?id=' + q(p.id) + (p.hash ? '#' + p.hash : '');
    if (kind === 'support') return PL.demo ? null : '/app/support?new=1' + (p.app ? '&app=' + q(p.app) : '') + (p.finding ? '&finding=' + q(p.finding) : '');
    return base;
  };
  PL.supportLink = function (p, cls, text) {
    var h = PL.href('support', p);
    return h ? '<a class="' + cls + '" href="' + PL.esc(h) + '">' + PL.esc(text) + '</a>'
      : '<button class="' + cls + '" type="button" data-demo="Support tickets are for signed-in workspaces.">' + PL.esc(text) + '</button>';
  };

  /* ---- findings (V3 shape) ----------------------------------------------------------------------------------------
     summary.findings: [{id, line: lab|code, severity, title, object, file, line_no, evidence, proven, proof, fix,
     fixed_in_lab, advisory?}], summary.counts: {critical: n, …}. Checks from before V3 only have tables_leaking /
     readable_by_anyone / readable_by_signed_in: those become PL-001 / PL-002 lab findings (legacy: true). */
  PL.SEV = ['critical', 'high', 'medium', 'low', 'info'];
  PL.LINES = {
    lab: { name: 'Lab', sub: 'Your database rebuilt from its migrations, each exploit tried as an anonymous visitor, a signed-in stranger and the owner.' },
    code: { name: 'Code', sub: 'Your repo and its full git history: keys, vulnerable dependencies and risky patterns.' },
    live: { name: 'Live posture', sub: 'Your public home page, loaded like any visitor on the domain you verified: HTTPS, the certificate, security headers and cookies.' }
  };
  var CODE_IDS = /^PL-0(09|1[0179]|2[0-6])$/, LIVE_IDS = /^PL-0(2[7-9]|3[0-6])$/;
  PL.total = function (c) { return c ? PL.SEV.reduce(function (n, s) { return n + (+c[s] || 0); }, 0) : 0; };
  var normFinding = function (f) {
    var id = String(f.id || 'PL-000').toUpperCase(), line = String(f.line || '').toLowerCase();
    var sev = String(f.severity || '').toLowerCase();
    return {
      id: id, line: PL.LINES[line] ? line : LIVE_IDS.test(id) ? 'live' : CODE_IDS.test(id) ? 'code' : 'lab', severity: PL.SEV.indexOf(sev) >= 0 ? sev : 'info',
      title: f.title || id, object: f.object || '', file: f.file || '', line_no: f.line_no || null, evidence: f.evidence || '',
      proven: !!f.proven, proof: f.proof || '', fix: f.fix || '', fixed_in_lab: !!f.fixed_in_lab, advisory: f.advisory || '', demo: !!f.demo,
      cwe: Array.isArray(f.cwe) ? f.cwe : null, owasp: f.owasp || null, owasp_name: f.owasp_name || null,
      first_seen: f.first_seen || null, days_open: f.days_open == null ? null : +f.days_open, fixed_at: f.fixed_at || null, regressed: !!f.regressed
    };
  };
  PL.findings = function (summary) {
    var s = summary && typeof summary === 'object' ? summary : {};
    if (Array.isArray(s.findings)) return { list: s.findings.map(normFinding), legacy: false };
    var list = [], seen = {}, passed = !!s.lab_proof_passed;
    var add = function (id, sev, title, t, proof) {
      if (seen[t]) return; seen[t] = 1;
      list.push(normFinding({ id: id, line: 'lab', severity: sev, title: title, object: String(t).indexOf('.') > 0 ? t : 'public.' + t,
        proven: true, proof: proof, fixed_in_lab: passed,
        fix: passed ? 'The fix migration in the full report closes this, and the lab proved it.' : 'A fix is written; a person is reviewing it before it reaches you.' }));
    };
    (s.readable_by_anyone || []).forEach(function (t) { add('PL-001', 'critical', 'Anyone on the internet can read personal data', t, 'An anonymous visitor read rows of this table in the lab rebuild.'); });
    (s.readable_by_signed_in || []).forEach(function (t) { add('PL-002', 'high', 'Any signed-in user can read every row', t, 'A signed-in stranger read other users’ rows in the lab rebuild.'); });
    (s.tables_leaking || []).forEach(function (t) { add('PL-001', 'critical', 'Personal data readable by the wrong people', t, 'The lab read rows of this table as someone who shouldn’t see them.'); });
    return { list: list, legacy: true };
  };
  // {counts, lab, code}: severity counts plus how many findings each line has (for status notes)
  PL.findingInfo = function (summary) {
    var list = PL.findings(summary).list;
    return { counts: PL.countsOf(summary, list), lab: list.filter(function (f) { return f.line === 'lab'; }).length, code: list.filter(function (f) { return f.line === 'code'; }).length };
  };
  PL.countsOf = function (summary, list) {
    var c = {}, given = summary && summary.counts && typeof summary.counts === 'object' ? summary.counts : null;
    PL.SEV.forEach(function (s) { c[s] = 0; });
    if (given) PL.SEV.forEach(function (s) { c[s] = +given[s] || 0; });
    else (list || []).forEach(function (f) { c[f.severity]++; });
    return c;
  };
  var sevRank = function (s) { var i = PL.SEV.indexOf(s); return i < 0 ? 9 : i; };
  PL.sortFindings = function (list) {
    return list.slice().sort(function (a, b) { return sevRank(a.severity) - sevRank(b.severity) || (b.proven - a.proven) || (a.id < b.id ? -1 : a.id > b.id ? 1 : 0); });
  };

  /* ---- small charts (status colours only: red for critical/high, amber for medium, grey below) ---- */
  PL.sevLabel = function (c) {
    var parts = PL.SEV.filter(function (s) { return c[s]; }).map(function (s) { return c[s] + ' ' + s; });
    return parts.length ? parts.join(', ') : 'no findings';
  };
  PL.sevBar = function (c) {
    var t = PL.total(c);
    if (!t) return '<div class="sevbar empty" role="img" aria-label="No findings"><i></i></div>';
    return '<div class="sevbar" role="img" aria-label="' + PL.esc(PL.sevLabel(c)) + '">' + PL.SEV.filter(function (s) { return c[s]; }).map(function (s) {
      return '<i class="s-' + s + '" style="flex-grow:' + c[s] + '" title="' + c[s] + ' ' + s + '"></i>';
    }).join('') + '</div>';
  };
  PL.sevLegend = function (c) {
    return '<ul class="sevlegend">' + PL.SEV.map(function (s) {
      return '<li class="' + (c[s] ? '' : 'zero') + '"><i class="s-' + s + '" aria-hidden="true"></i><b class="num">' + (c[s] || 0) + '</b> ' + s + '</li>';
    }).join('') + '</ul>';
  };
  // compact per-app counts: "2 crit · 5 high · 3 med"
  PL.sevMini = function (c) {
    var short = { critical: 'crit', high: 'high', medium: 'med', low: 'low', info: 'info' };
    var parts = PL.SEV.filter(function (s) { return c[s]; }).map(function (s) { return '<span class="m-' + s + '"><b class="num">' + c[s] + '</b> ' + short[s] + '</span>'; });
    return parts.length ? '<span class="sevmini" title="' + PL.esc(PL.sevLabel(c)) + '">' + parts.join('') + '</span>' : '<span class="sevmini none">None open</span>';
  };
  // sparkline: points [{v, label}], oldest first. One series in ink, the latest value marked.
  PL.spark = function (pts, what) {
    if (!pts || pts.length < 2) return '<span class="muted small">' + (pts && pts.length ? 'One check so far' : '–') + '</span>';
    var W = 104, H = 30, P = 4, max = Math.max.apply(null, pts.map(function (p) { return p.v; })) || 1;
    var xy = pts.map(function (p, i) { return [P + i * (W - 2 * P) / (pts.length - 1), H - P - (p.v / max) * (H - 2 * P)]; });
    var last = pts[pts.length - 1], first = pts[0], delta = last.v - first.v;
    var label = what + ' over the last ' + pts.length + ' checks: ' + pts.map(function (p) { return p.v; }).join(', ');
    return '<span class="spark"><svg viewBox="0 0 ' + W + ' ' + H + '" width="' + W + '" height="' + H + '" role="img" aria-label="' + PL.esc(label) + '">' +
      '<polyline points="' + xy.map(function (q) { return q[0].toFixed(1) + ',' + q[1].toFixed(1); }).join(' ') + '"/>' +
      xy.map(function (q, i) { return '<circle class="hit" cx="' + q[0].toFixed(1) + '" cy="' + q[1].toFixed(1) + '" r="6"><title>' + PL.esc(pts[i].label + ': ' + pts[i].v + ' ' + what.toLowerCase()) + '</title></circle>'; }).join('') +
      '<circle class="end" cx="' + xy[xy.length - 1][0].toFixed(1) + '" cy="' + xy[xy.length - 1][1].toFixed(1) + '" r="3.5"/></svg>' +
      '<span class="spark-d ' + (delta > 0 ? 'up' : delta < 0 ? 'down' : '') + '">' + (delta > 0 ? '+' + delta : delta < 0 ? '−' + (-delta) : '±0') + '</span></span>';
  };

  /* ---- the report view: summary bar, filters, findings grouped by line ------------------------------------------
     PL.report(el, check, {appId}) renders GET /checks/{id} (finished). Filters: severity, line, proven, fixed in lab. */
  PL.report = function (el, check, ctx) {
    ctx = ctx || {};
    var sum = check.summary || {}, F = PL.findings(sum), all = PL.sortFindings(F.list), counts = PL.countsOf(sum, all);
    var total = Math.max(PL.total(counts), all.length), uid = 'r' + Math.random().toString(36).slice(2, 7);
    var by = function (k, v) { return all.filter(function (f) { return f[k] === v; }).length; };
    var st = { sev: {}, line: '', proven: '', fixed: '' };
    var hasFix = !!check.fix_sql, finished = ['done', 'no_leaks', 'needs_review'].indexOf(check.status) >= 0;
    var decide = ctx.ws ? PL.can(ctx.ws, 'decide') : true, tx = ctx.taxonomy, bare = !!ctx.bare;   // bare: the public report page has its own actions

    var actions = '<div class="rpt-actions">' +
      '<a class="btn small secondary" href="' + PL.esc(PL.href('check', { id: check.id })) + '">Full report' + (hasFix ? ' and fix' : '') + '</a>' +
      (hasFix && finished && decide ? (PL.demo ? '<button class="btn small ghost" type="button" data-demo="Approving a fix records a signed decision for your team.">Approve the fix</button>'
        : '<a class="btn small ghost" href="' + PL.esc(PL.href('check', { id: check.id, hash: 'owner' })) + '">Approve or reject the fix</a>') : '') +
      PL.printButton('btn small ghost') + '</div>';
    var head = '<div class="rpt-bar">' +
      '<div class="rpt-total"><b class="num">' + total + '</b><span>' + (total === 1 ? 'finding' : 'findings') + '</span></div>' +
      '<div class="rpt-sev">' + PL.sevBar(counts) + PL.sevLegend(counts) + '</div>' +
      '<dl class="rpt-facts"><div><dt>Lab</dt><dd class="num">' + by('line', 'lab') + '</dd></div><div><dt>Code</dt><dd class="num">' + by('line', 'code') + '</dd></div>' +
      '<div><dt>Proven in the lab</dt><dd class="num">' + by('proven', true) + '</dd></div><div><dt>Fixed in the lab</dt><dd class="num green">' + by('fixed_in_lab', true) + '</dd></div></dl>' +
      (bare ? '' : actions) + '</div>';
    var notes = (F.legacy && all.length ? '<div class="callout note rpt-note"><p>This check ran before per-finding reports, so it lists the tables the lab could read. Newer checks also cover the code and every lab check.</p></div>' : '') +
      (all.length < PL.total(counts) ? '<p class="small muted">Showing the first ' + all.length + ' of ' + PL.total(counts) + ' findings. The full report has every one.</p>' : '') +
      ((sum.questions_for_owner || []).length && decide && !bare ? '<div class="callout question rpt-note"><p><strong>' + PL.plural(sum.questions_for_owner.length, 'question') + ' for you.</strong> Your answers decide what “leaking” means for your app. ' +
        (PL.demo ? '<button class="linkish" type="button" data-demo="Answers are recorded on the report for your team.">Answer them</button>' : '<a href="' + PL.esc(PL.href('check', { id: check.id, hash: 'owner' })) + '">Answer them on the report</a>') + '.</p></div>' : '');

    if (!all.length) {
      el.innerHTML = '<div class="rpt">' + head + '<div class="callout clear"><p><strong>Nothing found.</strong> No one but the owner could read or change data in the rebuilt database, and the code scan found nothing to fix.</p></div></div>';
      return;
    }
    var chip = function (s) { var n = by('severity', s); return '<button type="button" class="fchip s-' + s + '" data-sev="' + s + '" aria-pressed="false"' + (n ? '' : ' disabled') + '><i aria-hidden="true"></i>' + s + ' <b class="num">' + n + '</b></button>'; };
    var sel = function (k, label, opts) {
      return '<label class="fsel"><span class="sr-only">' + label + '</span><select class="input" data-f="' + k + '">' + opts.map(function (o) { return '<option value="' + o[0] + '">' + o[1] + '</option>'; }).join('') + '</select></label>';
    };
    el.innerHTML = '<div class="rpt">' + head + notes +
      '<div class="rpt-filters" role="group" aria-label="Filter findings"><div class="fchips">' + PL.SEV.map(chip).join('') + '</div>' +
      '<div class="fsels">' + sel('line', 'Product line', [['', 'All lines'], ['lab', 'Lab'], ['code', 'Code']]) +
      sel('proven', 'Proof', [['', 'Proven or not'], ['1', 'Proven in the lab'], ['0', 'Not proven in the lab']]) +
      sel('fixed', 'Fixed in the lab', [['', 'Fixed or not'], ['1', 'Fixed in the lab'], ['0', 'Not fixed yet']]) + '</div>' +
      '<p class="fcount" aria-live="polite" id="' + uid + '-n"></p><button class="btn small ghost" type="button" data-reset hidden>Clear filters</button></div>' +
      '<div class="rpt-groups" id="' + uid + '-g"></div></div>';

    var tags, age;
    var row = function (f) {
      var where = f.file ? '<code>' + PL.esc(f.file) + (f.line_no ? ':' + PL.esc(f.line_no) : '') + '</code>' : '';
      var objShown = f.object && f.object !== f.file;   // a code finding's object is often the file itself: show it once
      var badges = (f.proven ? '<span class="pill proven">proven</span>' : '') +
        (f.fixed_in_lab ? '<span class="pill proven">fixed in lab</span>' : f.line === 'lab' && f.proven ? '<span class="pill pending plain">not fixed yet</span>' : '');
      return '<details class="fnd" data-id="' + PL.esc(f.id) + '"><summary>' +
        '<span class="pill sev-' + f.severity + '">' + f.severity + '</span><code class="fid">' + PL.esc(f.id) + '</code>' +
        '<span class="ft">' + PL.esc(f.title) + (f.object ? '<code class="fo">' + PL.esc(f.object) + '</code>' : '') +
        ((tags = PL.tagsHtml(f, tx)) || (age = PL.ageHtml(f)) ? '<span class="fmeta">' + PL.ageHtml(f) + PL.tagsHtml(f, tx) + '</span>' : '') + '</span><span class="fb">' + badges + '</span></summary>' +
        '<div class="fnd-body"><dl class="kv">' +
        '<dt>Where</dt><dd>' + (objShown ? '<code>' + PL.esc(f.object) + '</code>' : '') + (where ? (objShown ? '<br>' : '') + where : '') + (!objShown && !where ? (f.object ? '<code>' + PL.esc(f.object) + '</code>' : '<span class="muted">Not recorded</span>') : '') + '</dd>' +
        (f.evidence ? '<dt>Evidence</dt><dd><pre class="fev">' + PL.esc(f.evidence) + '</pre></dd>' : '') +
        '<dt>Proof</dt><dd>' + (f.proven ? '<span class="green">Reproduced in the lab.</span> ' + PL.esc(f.proof) : f.line === 'code' ? '<span class="muted">Found by reading the code. The lab doesn’t run your code, so this one isn’t reproduced.</span>' : '<span class="muted">Not reproduced in the lab.</span> ' + PL.esc(f.proof)) + '</dd>' +
        (f.fix ? '<dt>Fix</dt><dd>' + PL.esc(f.fix) + (f.fixed_in_lab ? ' <span class="green">The lab proved the fix.</span>' : '') + '</dd>' : '') +
        (f.advisory ? '<dt>Advisory</dt><dd><a href="https://github.com/advisories/' + encodeURIComponent(f.advisory) + '" target="_blank" rel="noopener">' + PL.esc(f.advisory) + ' <span aria-hidden="true">↗</span></a></dd>' : '') +
        '</dl><div class="fnd-foot"><a class="link-arrow small" href="/findings/' + encodeURIComponent(f.id.toLowerCase()) + '">What ' + PL.esc(f.id) + ' means</a>' +
        (ctx.noTicket ? '' : PL.supportLink({ app: ctx.appId || check.app_id, finding: f.id }, 'btn small ghost', 'Raise a ticket')) +
        (f.demo ? '<span class="tag">demo data</span>' : '') + '</div></div></details>';
    };
    var draw = function () {
      var sevOn = Object.keys(st.sev).filter(function (k) { return st.sev[k]; });
      var shown = all.filter(function (f) {
        return (!sevOn.length || st.sev[f.severity]) && (!st.line || f.line === st.line) &&
          (st.proven === '' || f.proven === (st.proven === '1')) && (st.fixed === '' || f.fixed_in_lab === (st.fixed === '1'));
      });
      var filtered = shown.length !== all.length || sevOn.length || st.line || st.proven || st.fixed;
      PL.$(uid + '-n').textContent = filtered ? 'Showing ' + shown.length + ' of ' + all.length : PL.plural(all.length, 'finding');
      el.querySelector('[data-reset]').hidden = !filtered;
      var g = PL.$(uid + '-g');
      if (!shown.length) { g.innerHTML = '<div class="empty small"><p>No findings match these filters. <button class="linkish" type="button" data-reset2>Clear filters</button></p></div>'; g.querySelector('[data-reset2]').onclick = reset; return; }
      g.innerHTML = ['lab', 'code'].map(function (line) {
        var items = shown.filter(function (f) { return f.line === line; }), totalLine = by('line', line);
        if (!items.length && (filtered || F.legacy && line === 'code')) return '';
        var c = {}; PL.SEV.forEach(function (s) { c[s] = 0; }); items.forEach(function (f) { c[f.severity]++; });
        return '<section class="fgroup" aria-label="' + PL.LINES[line].name + ' findings"><div class="fgroup-head"><h3><span class="lab">' + PL.LINES[line].name + '</span>' +
          PL.plural(items.length, 'finding') + (filtered && items.length !== totalLine ? ' <span class="muted">of ' + totalLine + '</span>' : '') + '</h3>' +
          (items.length ? PL.sevMini(c) : '') + '<p>' + PL.esc(PL.LINES[line].sub) + '</p></div>' +
          (items.length ? items.map(row).join('') : '<p class="fnone">' + (line === 'lab' ? 'Nothing found: in the rebuilt database, only the owner could read or change their own rows.' : 'Nothing found in the code or its git history.') + '</p>') + '</section>';
      }).join('');
    };
    var reset = function () {
      st = { sev: {}, line: '', proven: '', fixed: '' };
      el.querySelectorAll('[data-sev]').forEach(function (b) { b.setAttribute('aria-pressed', 'false'); });
      el.querySelectorAll('[data-f]').forEach(function (s) { s.value = ''; });
      draw();
    };
    el.querySelectorAll('[data-sev]').forEach(function (b) {
      b.addEventListener('click', function () { var on = b.getAttribute('aria-pressed') !== 'true'; b.setAttribute('aria-pressed', on ? 'true' : 'false'); st.sev[b.dataset.sev] = on; draw(); });
    });
    el.querySelectorAll('[data-f]').forEach(function (s) { s.addEventListener('change', function () { st[s.dataset.f] = s.value; draw(); }); });
    el.querySelector('[data-reset]').addEventListener('click', reset);
    draw();
  };
  /* ---- roles (SPEC.md "Account layer"). The API enforces them; the UI only stops offering what a role can't do. ----
     PL.can(ws, perm): ws is GET /workspaces/{wid} (uses ws.permissions) or anything with a role. */
  PL.ROLES = ['owner', 'admin', 'approver', 'member', 'viewer', 'client'];
  PL.ROLE_INFO = {
    owner: ['Owner', 'Everything, including making, demoting and removing owners.'],
    admin: ['Admin', 'Everything an owner can, except anything touching owners.'],
    approver: ['Approver', 'Runs checks, and approves or rejects fixes and answers the owner’s questions.'],
    member: ['Member', 'Sees everything, runs checks, creates API keys and raises support tickets.'],
    viewer: ['Viewer', 'Read-only: apps, reports, decisions, teammates and support tickets.'],
    client: ['Client', 'Read-only, and only the apps you share with them. Doesn’t use a seat.']
  };
  PL.roleName = function (r) { return (PL.ROLE_INFO[r] || [r])[0]; };
  var PERMS = {
    view: PL.ROLES, view_team: ['owner', 'admin', 'approver', 'member', 'viewer'], run: ['owner', 'admin', 'approver', 'member'],
    decide: ['owner', 'admin', 'approver'], support: ['owner', 'admin', 'approver', 'member', 'client'], manage: ['owner', 'admin'], owner: ['owner']
  };
  PL.can = function (ws, perm) {
    if (!ws) return false;
    if (Array.isArray(ws.permissions)) return ws.permissions.indexOf(perm) >= 0;
    return (PERMS[perm] || []).indexOf(ws.role) >= 0;
  };
  // the role in a workspace from /me (before the workspace itself has loaded)
  PL.roleIn = function (wid) {
    var w = PL.me && (PL.me.workspaces || []).filter(function (x) { return x.id === wid; })[0];
    return w ? { role: w.role } : null;
  };

  /* ---- finding tags (CWE, OWASP) and history: from summary.findings[] / GET /apps/{aid}.findings, else /taxonomy ---- */
  var taxo = null;
  PL.taxonomy = function () {
    if (!taxo) taxo = PL.call('/taxonomy/findings', { auth: false }).catch(function () { taxo = null; return { findings: {}, cwe: {}, owasp: {} }; });
    return taxo;
  };
  PL.tagsHtml = function (f, tx) {
    tx = tx || { findings: {}, cwe: {}, owasp: {} };
    var t = tx.findings[f.id] || {}, cwe = f.cwe && f.cwe.length ? f.cwe : t.cwe || [], owasp = f.owasp || t.owasp, oname = f.owasp_name || t.owasp_name || (tx.owasp || {})[owasp];
    if (!cwe.length && !owasp) return '';
    return '<span class="ftags">' + cwe.map(function (c) {
      var n = String(c).replace(/^CWE-/i, '');
      return '<a class="ftag" href="https://cwe.mitre.org/data/definitions/' + encodeURIComponent(n) + '.html" target="_blank" rel="noopener" title="' + PL.esc((tx.cwe || {})[c] || c) + '">' + PL.esc(c) + '</a>';
    }).join('') + (owasp ? '<span class="ftag owasp" title="OWASP Top 10 (2021)">' + PL.esc(String(owasp).split(':')[0] + (oname ? ' ' + oname : '')) + '</span>' : '') + '</span>';
  };
  PL.ageHtml = function (f) {
    var out = [];
    if (f.fixed_at) out.push('<span class="fage ok">fixed ' + PL.esc(PL.date(f.fixed_at)) + (f.days_open != null ? ' after ' + PL.plural(f.days_open, 'day') : '') + '</span>');
    else if (f.days_open === 0) out.push('<span class="fage" title="' + (f.first_seen ? 'First seen ' + PL.esc(PL.dateTime(f.first_seen)) : '') + '">new in this check</span>');
    else if (f.days_open != null) out.push('<span class="fage" title="' + (f.first_seen ? 'First seen ' + PL.esc(PL.dateTime(f.first_seen)) : '') + '">open ' + PL.plural(f.days_open, 'day') + (f.first_seen ? ' · since ' + PL.esc(PL.date(f.first_seen)) : '') + '</span>');
    if (f.regressed) out.push('<span class="fage back" title="It had been fixed before and came back">back again</span>');
    return out.join('');
  };

  /* ---- badge freshness: GET /workspaces/{wid}/apps and /apps/{aid} carry freshness {stale, days_since_check, stale_after_days} ---- */
  PL.stale = function (a) { return !!(a && a.freshness && a.freshness.stale && a.last_check && !a.open_check_id); };
  PL.staleHtml = function (a) {
    var f = a.freshness || {};
    return '<span class="pill neutral plain stale-pill" title="Older than ' + PL.esc(f.stale_after_days) + ' days, so the badge stops showing the result">stale</span>';
  };

  /* ---- print / PDF: closed findings don't print, so open them for the print and put them back afterwards ---- */
  var reopened = [];
  window.addEventListener('beforeprint', function () {
    reopened = [].slice.call(d.querySelectorAll('details:not([open])'));
    reopened.forEach(function (x) { x.open = true; });
  });
  window.addEventListener('afterprint', function () { reopened.forEach(function (x) { x.open = false; }); reopened = []; });
  PL.printButton = function (cls) { return '<button class="' + (cls || 'btn small ghost') + '" type="button" data-print>Download PDF</button>'; };
  d.addEventListener('click', function (e) {
    var t = e.target.closest && e.target.closest('[data-print]');
    if (t) { e.preventDefault(); window.print(); }
  });
  // CSV text from rows (arrays); cells that a spreadsheet would run as a formula get a leading quote
  PL.csv = function (rows) {
    return rows.map(function (r) {
      return r.map(function (v) {
        var s = v == null ? '' : String(v);
        if (/^[=+\-@\t\r]/.test(s)) s = "'" + s;
        return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
      }).join(',');
    }).join('\r\n') + '\r\n';
  };
})();

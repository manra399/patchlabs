// PatchLabs signed-in app helpers, shared by /app/*, /admin and the owner tools on /check. Needs app.js (api, session).
// Everything hangs off window.PL:
//   PL.esc(s), PL.date(iso), PL.dateTime(iso), PL.rel(iso)             formatting (always escape API strings)
//   PL.guard()                                                        redirect to /app/login?next=… when signed out
//   PL.call(path, opts)                                               api() that sends a 401 back to the login page
//   PL.boot({ onWorkspace })                                          guard + /me + workspace switcher + sign-out → {me, ws}
//   PL.status(app) / PL.pill(st)                                      the app status pill (Leaking, Fix ready, …)
//   PL.modal({...}), PL.confirm({...})                                <dialog> helpers
//   PL.busy(btn, text) → restore()                                    disable a button while a request runs
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
      return '<option value="' + PL.esc(w.id) + '"' + (w.id === current.id ? ' selected' : '') + '>' + PL.esc(w.name) + (w.role === 'owner' ? '' : ' (member)') + '</option>';
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
    if (!PL.guard()) return new Promise(function () {});
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

  // Status of a monitored app, from GET /workspaces/{wid}/apps or GET /apps/{id}
  PL.status = function (a) {
    var sup = a.suppressed_tables || [], last = a.last_check;
    var open = (last && last.tables_leaking || []).filter(function (t) { return sup.indexOf(t) < 0; });
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
    var m = { done: ['leak', 'fix ready'], no_leaks: ['proven', 'no leaks found'], needs_review: ['pending', 'in review'], queued: ['pending', 'queued'],
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
})();

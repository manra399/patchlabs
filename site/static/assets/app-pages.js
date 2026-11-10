// PatchLabs app views, shared by the signed-in app (/app/, /app/app, /app/report) and the demo (/demo/…).
// Needs app.js and app-ui.js. Each page is a thin shell: <div id="view"></div> and one call, e.g.
//   PL.views.dashboard(document.getElementById('view'))
// The demo pages call PL.useDemo('/demo/workspace.json') first; the views then read the static workspace through
// the same PL.call() and never know the difference (writes open the demo notice instead).
(function () {
  'use strict';
  var esc = PL.esc, $ = PL.$;
  var FINISHED = ['done', 'no_leaks', 'needs_review'];
  var PROD_API = 'https://api.patchlabs.dev', PROD_SITE = 'https://patchlabs.dev';
  var V = PL.views = {};

  var skLines = function (n) { return '<div class="table-wrap"><div style="padding:8px 20px">' + PL.skeleton(n || 3) + '</div></div>'; };
  var flashHtml = function () {
    try {
      var fl = JSON.parse(sessionStorage.getItem('pl_flash') || 'null');
      if (fl) { sessionStorage.removeItem('pl_flash'); return '<div class="callout ' + (fl.kind === 'warn' ? 'limit' : 'note') + ' flash"><p>' + esc(fl.text) + '</p></div>'; }
    } catch (e) {}
    return '';
  };
  // trend points from GET /apps/{id}.checks (newest first): open findings when every check has counts, else leaking tables
  var trendOf = function (checks) {
    var fin = (checks || []).filter(function (c) { return FINISHED.indexOf(c.status) >= 0 && c.finished_at; }).slice(0, 8).reverse();
    var withCounts = fin.length && fin.every(function (c) { return c.counts; });
    return { what: withCounts ? 'Open findings' : 'Leaking tables', pts: fin.map(function (c) {
      return { v: withCounts ? PL.total(c.counts) : (c.tables_leaking || []).length, label: PL.date(c.finished_at), at: c.finished_at };
    }) };
  };

  /* =============================================== dashboard =============================================== */
  V.dashboard = function (root) {
    var S = { me: null, ws: null, wsd: null, apps: [], live: null, extra: {} };
    root.innerHTML = '<div id="flash">' + flashHtml() + '</div>' +
      '<div class="app-head"><div><p class="lab">Monitoring</p><h1 class="app-title">Apps</h1><p class="app-sub" id="ws-line"><span class="skeleton" style="display:inline-block;width:220px;height:14px"></span></p></div>' +
      '<div class="actions"><span id="help" hidden>' + PL.supportLink({}, 'btn ghost', 'Raise a ticket') + '</span><button class="btn primary" type="button" id="add" disabled>Add app</button></div></div>' +
      '<section id="portfolio" class="portfolio" aria-labelledby="pf-h" hidden></section>' +
      '<div id="apps" aria-live="polite">' + skLines(3) + '</div>' +
      '<section class="block" aria-labelledby="usage-h" id="usage-sec"><h2 class="sec-title" id="usage-h">Plan and usage</h2><p class="sec-sub">What this workspace’s plan allows, and how much of it is in use.</p>' +
      '<div id="meters"><div class="skeleton sk-block" style="height:92px"></div></div></section>' +
      '<section class="block" aria-labelledby="earlier-h"><h2 class="sec-title" id="earlier-h">Earlier checks</h2><p class="sec-sub">One-off checks you started from the home page with this email address.</p><div id="earlier">' + PL.skeleton(2) + '</div></section>';

    PL.boot({ onWorkspace: function (w) { S.ws = w; S.extra = {}; $('flash').innerHTML = ''; load(); } }).then(function (b) {
      S.me = b.me; S.ws = b.ws;
      if (!S.ws) {
        $('ws-line').textContent = 'You’re not in any workspace.';
        $('meters').innerHTML = '<p class="muted small mb-0">No plan: you’re not in a workspace.</p>';
        $('apps').innerHTML = '<div class="empty"><h2>No workspace</h2><p>You were removed from your workspaces. Ask a teammate for a new invite, or email <a href="mailto:manraj@patchlabs.dev">manraj@patchlabs.dev</a>.</p></div>';
      } else load();
      earlier();
    }).catch(function (e) { PL.errorBox($('apps'), e, function () { location.reload(); }); $('meters').innerHTML = ''; $('ws-line').textContent = ''; });

    async function load() {
      $('apps').innerHTML = skLines(3);
      try {
        var r = await Promise.all([PL.call('/workspaces/' + S.ws.id), PL.call('/workspaces/' + S.ws.id + '/apps')]);
        S.wsd = r[0]; S.apps = r[1].apps;
        renderHead(); renderMeters(); renderApps(); renderPortfolio(); live(); enrich();
      } catch (e) {
        if (PL.handled(e)) return;
        if (e.status === 404 && !PL.demo) { PL.store.del('pl_ws'); location.reload(); return; }
        PL.errorBox($('apps'), e, load); $('meters').innerHTML = '';
      }
    }
    async function refresh() {
      var r = await Promise.all([PL.call('/workspaces/' + S.ws.id), PL.call('/workspaces/' + S.ws.id + '/apps')]);
      S.wsd = r[0]; S.apps = r[1].apps; renderMeters(); renderApps(); renderPortfolio(); live(); enrich();
    }
    function live() {
      var open = S.apps.some(function (a) { return a.open_check_id; });
      if (open && !S.live) S.live = PL.every(refresh, 15000);
      if (!open && S.live) { S.live.stop(); S.live = null; }
    }

    // severity counts of each app's last check and its trend: GET /apps/{id} (history) + GET /checks/{last} (summary)
    async function enrich() {
      var todo = S.apps.filter(function (a) { return a.verified && a.last_check && (!S.extra[a.id] || S.extra[a.id].key !== a.last_check.id); }).slice(0, 25);
      if (!todo.length) return;
      await Promise.all(todo.map(async function (a) {
        var x = { key: a.last_check.id };
        try {
          var r = await Promise.all([PL.call('/apps/' + encodeURIComponent(a.id)),
            PL.call('/checks/' + encodeURIComponent(a.last_check.id)).catch(function (e) { if (e.redirecting) throw e; return null; })]);
          x.detail = r[0]; x.trend = trendOf(r[0].checks);
          var sum = r[1] && r[1].summary;
          x.info = sum ? PL.findingInfo(sum) : a.last_check.counts ? { counts: a.last_check.counts } : null;
          if (FINISHED.indexOf(a.last_check.status) < 0) x.info = null;
          x.counts = x.info && x.info.counts;
          x.proven = r[0].checks && r[0].checks.filter(function (c) { return c.id === a.last_check.id; }).map(function (c) { return c.lab_proof_passed; })[0];
        } catch (e) { if (PL.handled(e)) return; x.failed = true; }
        S.extra[a.id] = x;
      }));
      renderApps(); renderPortfolio();
    }

    function renderHead() {
      var w = S.wsd, team = PL.can(w, 'view_team');
      $('ws-line').innerHTML = team ? esc(w.name) + ' · ' + esc(PL.planName(w.plan)) + ' plan' + (w.role === 'owner' ? '' : ' · you’re ' + (w.role === 'admin' ? 'an admin' : 'a' + (w.role === 'approver' ? 'n approver' : ' ' + PL.roleName(w.role).toLowerCase())))
        : 'Shared with you by <b class="ink">' + esc(w.name) + '</b>. You can see the apps they chose and their reports.';
      $('add').disabled = false; $('add').hidden = !PL.can(w, 'manage');
      $('help').hidden = !PL.can(w, 'support');
      $('usage-sec').hidden = !team;
    }
    function meter(label, used, max) {
      var pct = max ? Math.min(100, Math.round(used / max * 100)) : 100;
      return '<div class="meter' + (used >= max ? ' full' : '') + '"><div class="k">' + esc(label) + '</div><div class="v">' + used + ' <small>of ' + max + '</small></div>' +
        '<div class="bar" role="img" aria-label="' + used + ' of ' + max + ' used"><i style="--w:' + pct + '%"></i></div></div>';
    }
    function renderMeters() {
      var w = S.wsd, u = w.usage, l = w.limits;
      if (!u || !l) { $('meters').innerHTML = ''; return; }
      $('meters').innerHTML = '<div class="meters">' + meter('Apps', u.apps, l.apps) + meter('Manual runs this month', u.runs_this_month, l.runs_per_month) +
        meter('Team seats', u.members, l.seats) + '<div class="plan-cell"><span class="pill plain">' + esc(PL.planName(w.plan)) + ' plan</span>' +
        (w.plan === 'enterprise' ? '<span class="small muted">Limits set for you</span>'
          : !PL.can(w, 'manage') ? '<span class="small muted">An owner or admin can request more</span>'
          : PL.demo ? '<button class="linkish small" type="button" data-demo="Plans are set per workspace once you sign in.">Request upgrade</button>'
          : '<a class="link-arrow small" href="/app/settings#plan">Request upgrade</a>') + '</div></div>';
    }

    /* ---- portfolio: severity totals, exposure, badges, next check, trend ---- */
    function renderPortfolio() {
      var el = $('portfolio'), apps = S.apps;
      if (!apps.length) { el.hidden = true; return; }
      el.hidden = false;
      var checked = apps.filter(function (a) { return a.last_check; });
      var pending = checked.filter(function (a) { return !S.extra[a.id] || S.extra[a.id].key !== a.last_check.id; }).length;
      var c = {}; PL.SEV.forEach(function (s) { c[s] = 0; });
      var counted = 0;
      checked.forEach(function (a) { var x = S.extra[a.id]; if (x && x.counts) { counted++; PL.SEV.forEach(function (s) { c[s] += x.counts[s] || 0; }); } });
      var serious = checked.filter(function (a) { var x = S.extra[a.id]; return x && x.counts && (x.counts.critical || x.counts.high); }).length;
      var tables = 0, leakingApps = 0;
      apps.forEach(function (a) {
        var sup = a.suppressed_tables || [], n = (a.last_check && a.last_check.tables_leaking || []).filter(function (t) { return sup.indexOf(t) < 0; }).length;
        tables += n; if (n) leakingApps++;
      });
      var pub = apps.filter(function (a) { return a.badge_public; }).length;
      var next = apps.filter(function (a) { return a.verified && a.schedule !== 'off' && a.next_check_at; })
        .sort(function (a, b) { return new Date(a.next_check_at) - new Date(b.next_check_at); })[0];
      var running = apps.filter(function (a) { return a.open_check_id; }).length;

      var sev = !checked.length ? '<p class="muted small mb-0">Appears after the first check finishes.</p>'
        : pending && !counted ? '<div class="skeleton" style="height:10px;border-radius:5px;margin:12px 0 10px"></div><div class="skeleton" style="height:14px;width:70%"></div>'
        : PL.sevBar(c) + PL.sevLegend(c);
      el.innerHTML = '<h2 class="sr-only" id="pf-h">Portfolio</h2><div class="pf-grid">' +
        '<div class="pf-tile pf-sev"><div class="k">Open findings across ' + PL.plural(checked.length, 'app') + '</div><div class="v num">' + (checked.length && (counted || !pending) ? PL.total(c) : '–') +
          (serious ? ' <small class="red">' + PL.plural(serious, 'app') + ' with critical or high</small>' : '') + '</div>' + sev + '</div>' +
        '<div class="pf-tile' + (tables ? ' red' : '') + '"><div class="k">Leaking tables</div><div class="v num">' + tables + '</div><p>' + (tables ? 'in ' + PL.plural(leakingApps, 'app') + ', readable by the wrong people' : checked.length ? 'No personal data readable by the wrong people' : 'None checked yet') + '</p></div>' +
        '<div class="pf-tile"><div class="k">Next check</div><div class="v">' + (running ? PL.plural(running, 'check') + ' running' : next ? esc(PL.rel(next.next_check_at)) : 'None scheduled') + '</div><p>' +
          (running ? 'Results appear here when they finish' : next ? '<a class="mono" href="' + esc(PL.href('app', { id: next.id })) + '">' + esc(next.repo) + '</a> · ' + esc(PL.date(next.next_check_at)) : 'Turn on weekly or monthly re-checks on an app') + '</p></div>' +
        '<div class="pf-tile"><div class="k">Public badges</div><div class="v num">' + pub + ' <small>of ' + apps.length + '</small></div><p>' + (pub ? 'Visitors can see the date and result of the last check' : 'All badges are private') + '</p></div>' +
        '</div>' + trendChart();
    }
    // weekly portfolio trend over 8 weeks: at the end of each week, each app counts its latest finished check
    function trendChart() {
      var series = S.apps.map(function (a) { var x = S.extra[a.id]; return x && x.trend ? x.trend : null; }).filter(Boolean);
      if (!series.some(function (t) { return t.pts.length > 1; })) return '';
      var what = series.every(function (t) { return t.what === 'Open findings'; }) ? 'Open findings' : 'Leaking tables';
      var useTables = what === 'Leaking tables';
      var weeks = [], now = Date.now(), WK = 7 * 86400000;
      for (var i = 7; i >= 0; i--) weeks.push(now - i * WK);
      var vals = weeks.map(function (end) {
        var any = false, v = 0;
        S.apps.forEach(function (a) {
          var x = S.extra[a.id]; if (!x || !x.detail) return;
          var fin = (x.detail.checks || []).filter(function (c) { return FINISHED.indexOf(c.status) >= 0 && c.finished_at && new Date(c.finished_at) <= end; })[0];
          if (!fin) return; any = true;
          v += useTables || !fin.counts ? (fin.tables_leaking || []).length : PL.total(fin.counts);
        });
        return any ? v : null;
      });
      if (vals.filter(function (v) { return v !== null; }).length < 2) return '';
      var max = Math.max.apply(null, vals.map(function (v) { return v || 0; })) || 1, lastI = vals.length - 1;
      return '<div class="pf-trend"><div class="pf-trend-head"><h3>' + what + ' across all apps</h3><span class="small muted">Last 8 weeks · each app counts its latest check by the end of the week</span></div>' +
        '<ol class="tbars" aria-label="' + esc(what + ', weekly: ' + vals.map(function (v, i) { return PL.date(new Date(weeks[i]).toISOString()) + ' ' + (v === null ? 'no data' : v); }).join('; ')) + '">' +
        vals.map(function (v, i) {
          var lbl = 'Week to ' + PL.date(new Date(weeks[i]).toISOString()) + ': ' + (v === null ? 'no checks yet' : v + ' ' + what.toLowerCase());
          return '<li class="' + (v === null ? 'none' : '') + (i === lastI ? ' now' : '') + '" title="' + esc(lbl) + '"><span class="tv">' + (v === null ? '' : v) + '</span><span class="tb" style="--h:' + (v === null ? 0 : Math.max(4, Math.round(v / max * 100))) + '%"></span>' +
            '</li>';
        }).join('') + '</ol><div class="tlabels" aria-hidden="true"><span>8 weeks ago</span><span>This week</span></div></div>';
    }

    function nextCell(a) {
      if (!a.verified) return '<span class="muted">After verification</span>';
      if (a.open_check_id) return '<span class="when">Running now<small><a href="' + esc(PL.href('check', { id: a.open_check_id })) + '">watch it</a></small></span>';
      if (a.schedule === 'off') return '<span class="muted">Off</span>';
      return PL.when(a.next_check_at);
    }
    function renderApps() {
      var el = $('apps');
      if (!S.apps.length && !PL.can(S.wsd, 'manage')) {
        el.innerHTML = '<div class="empty"><p class="lab">No apps yet</p><h2>' + (PL.can(S.wsd, 'view_team') ? 'No apps in this workspace yet' : 'No apps shared with you yet') + '</h2>' +
          '<p>' + (PL.can(S.wsd, 'view_team') ? 'An owner or admin adds apps. They show up here as soon as they do.' : 'When ' + esc(S.wsd.name) + ' shares an app with you, its status and reports show up here.') + '</p></div>';
        return;
      }
      if (!S.apps.length) {
        el.innerHTML = '<div class="empty"><p class="lab">No apps yet</p><h2>Add the first app to monitor</h2>' +
          '<p>Paste a public GitHub repo. You prove it’s yours with one small file, then we rebuild its database from its migrations in our lab, read the code and its history, and re-check it on a schedule.</p>' +
          '<div class="row center"><button class="btn primary" type="button" id="add2">Add app</button><a class="btn ghost" href="/demo/">See the demo workspace</a></div></div>';
        $('add2').onclick = addApp;
        return;
      }
      var canRun = PL.can(S.wsd, 'run'), canManage = PL.can(S.wsd, 'manage');
      el.innerHTML = '<div class="table-wrap"><table class="table apps"><thead><tr><th scope="col">App</th><th scope="col">Status</th><th scope="col">Findings</th><th scope="col">Trend</th><th scope="col">Last checked</th><th scope="col">Next check</th><th scope="col">Badge</th><th scope="col" class="acts"><span class="sr-only">Actions</span></th></tr></thead><tbody>' +
        S.apps.map(function (a) {
          var x = S.extra[a.id], fresh = x && a.last_check && x.key === a.last_check.id, st = PL.status(a, fresh && x.info);
          var findings = !a.last_check ? '<span class="muted">–</span>' : !fresh ? '<span class="skeleton" style="display:inline-block;width:90px;height:12px"></span>'
            : x.counts ? '<a class="fcell" href="' + esc(PL.href('report', { id: a.last_check.id })) + '">' + PL.sevMini(x.counts) + '</a>' : '<span class="muted">–</span>';
          var trend = !a.last_check ? '<span class="muted">–</span>' : !fresh ? '<span class="skeleton" style="display:inline-block;width:80px;height:12px"></span>' : x.trend ? PL.spark(x.trend.pts, x.trend.what) : '<span class="muted">–</span>';
          return '<tr data-id="' + esc(a.id) + '"><th scope="row" class="c-repo"><a class="repo" href="' + esc(PL.href('app', { id: a.id })) + '">' + esc(a.repo) + '</a>' + (a.client_label ? '<span class="note">' + esc(a.client_label) + '</span>' : '') + '</th>' +
            '<td class="c-status">' + PL.pill(st) + (PL.stale(a) ? ' ' + PL.staleHtml(a) : '') + (st.note ? '<span class="note">' + esc(st.note) + '</span>' : '') +
              (PL.stale(a) ? '<span class="note">Last checked ' + PL.plural(a.freshness.days_since_check, 'day') + ' ago: out of date</span>' : '') + '</td>' +
            '<td data-label="Findings">' + findings + '</td>' +
            '<td data-label="Trend" class="c-trend">' + trend + '</td>' +
            '<td data-label="Last checked">' + (a.last_check ? PL.when(a.last_check.finished_at) : '<span class="muted">Never</span>') + '</td>' +
            '<td data-label="Next check">' + nextCell(a) + '</td>' +
            '<td data-label="Badge">' + (a.badge_public ? '<span class="pill proven plain">Public</span>' : '<span class="pill neutral plain">Private</span>') + '</td>' +
            '<td class="acts">' + (a.verified
              ? (canRun ? '<button class="btn small ' + (PL.stale(a) ? 'primary' : 'secondary') + '" type="button" data-run' + (a.open_check_id ? ' disabled title="A check is already running"' : '') + '>Run now</button>' : '')
              : canManage ? '<button class="btn small primary" type="button" data-verify-app>Verify</button>' : '') +
              '<a class="btn small ghost" href="' + esc(PL.href('app', { id: a.id })) + '">Open</a></td></tr>';
        }).join('') + '</tbody></table></div>';
      el.querySelectorAll('[data-run]').forEach(function (b) { b.onclick = function () { runNow(b); }; });
      el.querySelectorAll('[data-verify-app]').forEach(function (b) {
        b.onclick = function () { var a = byId(b.closest('tr').dataset.id); addApp(null, a); };
      });
    }
    function byId(id) { return S.apps.filter(function (a) { return a.id === id; })[0]; }

    async function runNow(b) {
      var a = byId(b.closest('tr').dataset.id), restore = PL.busy(b, 'Queueing…');
      try {
        await PL.call('/apps/' + a.id + '/checks', { method: 'POST' });
        PL.toast('Check queued for ' + a.repo, 'ok'); await refresh();
      } catch (e) {
        restore();
        if (PL.handled(e)) return;
        if (e.status === 429) $('flash').innerHTML = '<div class="callout limit flash"><p>' + esc(e.message) + ' <a href="/app/settings#plan">Request an upgrade</a>.</p></div>';
        else PL.toast(e.message, 'err');
      }
    }

    /* ---- add app: repo → verify → queued ---- */
    function addApp(_, existing) {
      if (PL.demo) { PL.demoNotice('Adding an app needs a real workspace: you prove the repo is yours with one small file.'); return; }
      var w = S.wsd, l = w.limits;
      var steps = function (at) {
        return '<ol class="stepper" aria-label="Steps">' + ['Repo', 'Prove it’s yours', 'First check'].map(function (s, i) {
          return '<li class="' + (i < at ? 'ok' : i === at ? 'on' : '') + '"' + (i === at ? ' aria-current="step"' : '') + '>' + (i < at ? '✓ ' : (i + 1) + '. ') + s + '</li>';
        }).join('') + '</ol>';
      };
      var dlg;
      if (!existing && w.usage.apps >= l.apps) {
        PL.modal({ title: 'Add an app', body: '<div class="callout limit"><p>The ' + esc(PL.planName(w.plan)) + ' plan allows ' + PL.plural(l.apps, 'app') + ', and this workspace has ' + w.usage.apps + '. Remove one, or request an upgrade: we reply within a day.</p></div>',
          foot: '<button class="btn ghost" type="button" data-close>Close</button><a class="btn primary" href="/app/settings#plan">Request upgrade</a>' });
        return;
      }
      var verifyStep = function (a) {
        dlg.setTitle('Prove ' + a.repo + ' is yours');
        dlg.body.innerHTML = steps(1) + PL.verifyHtml(a.repo, a.verify) + '<div class="modal-foot" style="padding-left:0;padding-right:0"><button class="btn ghost" type="button" data-close>Do this later</button></div>';
        PL.wireVerify(dlg.body, a.id, function (r) { doneStep(a, r); });
      };
      var doneStep = function (a, r) {
        dlg.setTitle('You’re all set');
        dlg.body.innerHTML = steps(2) + '<div class="callout done"><p><strong>Verified.</strong> The first check of ' + esc(a.repo) + ' is queued.</p></div>' +
          '<p class="muted">We rebuild the database from its migrations in our lab, try each exploit as an anonymous visitor, a signed-in stranger and the owner, read the code and its history, then write a fix and prove it. It usually takes 5 to 15 minutes, and we’ll email you when the report is ready.</p>' +
          '<div class="modal-foot" style="padding-left:0;padding-right:0">' + (r && r.check_id ? '<a class="btn secondary" href="/check?id=' + esc(r.check_id) + '">Watch the check</a>' : '') + '<a class="btn primary" href="/app/app?id=' + esc(a.id) + '">Open the app</a></div>';
      };
      var schedOpts = ['monthly', 'weekly', 'off'].map(function (s) {
        var ok = l.schedules.indexOf(s) >= 0;
        return '<option value="' + s + '"' + (ok ? '' : ' disabled') + '>' + esc(PL.SCHEDULES[s]) + (ok ? '' : ' (upgrade to use)') + '</option>';
      }).join('');
      dlg = PL.modal({
        title: 'Add an app',
        body: steps(0) + '<form id="af" novalidate><div class="field"><label for="a-repo">Public GitHub repo</label><input id="a-repo" class="mono" required autocomplete="off" spellcheck="false" placeholder="github.com/you/your-app"><span class="hint">Private repos need our GitHub App, which is coming.</span></div>' +
          '<div class="field"><label for="a-label">Client label <span class="muted" style="font-weight:400">(optional)</span></label><input id="a-label" maxlength="100" autocomplete="off" placeholder="e.g. Acme Ltd"><span class="hint">Shown in your list and in alert emails. Handy if you build apps for clients.</span></div>' +
          '<div class="field"><label for="a-sched">Re-check</label><select id="a-sched">' + schedOpts + '</select><span class="hint">' + esc(PL.planName(w.plan)) + ' plan: ' + l.schedules.filter(function (s) { return s !== 'off'; }).join(' or ') + ' re-checks.</span></div>' +
          '<p class="err" role="alert" id="a-err"></p><div class="modal-foot" style="padding-left:0;padding-right:0"><button class="btn ghost" type="button" data-close>Cancel</button><button class="btn primary" type="submit" id="a-go">Add app</button></div></form>',
        onClose: function () { load(); }
      });
      if (existing) { verifyStep(existing); return; }
      $('a-repo').focus();
      $('af').addEventListener('submit', async function (e) {
        e.preventDefault();
        var repo = $('a-repo').value.trim();
        if (!repo) { $('a-err').textContent = 'Enter a GitHub repo, for example github.com/you/your-app'; $('a-repo').focus(); return; }
        var restore = PL.busy($('a-go'), 'Looking it up…'); $('a-err').textContent = '';
        try {
          var body = { repo: repo, schedule: $('a-sched').value };
          if ($('a-label').value.trim()) body.client_label = $('a-label').value.trim();
          var a = await PL.call('/workspaces/' + S.ws.id + '/apps', { method: 'POST', body: body });
          verifyStep(a);
        } catch (x) { restore(); if (!PL.handled(x)) $('a-err').textContent = x.message; }
      });
    }
    $('add').onclick = addApp;

    /* ---- earlier anonymous checks ---- */
    async function earlier() {
      try {
        var r = await PL.call('/me/checks');
        if (!r.checks.length) { $('earlier').innerHTML = '<div class="empty small"><p>None yet. Checks you start from the <a href="/#check">home page</a> with ' + esc(S.me.user.email) + ' show up here.</p></div>'; return; }
        $('earlier').innerHTML = '<div class="table-wrap"><table class="table compact stack-sm"><thead><tr><th scope="col">Repo</th><th scope="col">Status</th><th scope="col">Started</th><th scope="col"><span class="sr-only">Report</span></th></tr></thead><tbody>' +
          r.checks.map(function (c) {
            return '<tr><th scope="row" class="mono">' + esc(c.repo) + '</th><td>' + PL.checkPill(c.status) + '</td><td data-label="Started">' + esc(PL.dateTime(c.created_at)) + '</td><td class="acts"><a class="link-arrow small" href="/check?id=' + esc(c.id) + '">Open</a></td></tr>';
          }).join('') + '</tbody></table></div>';
      } catch (e) { if (!PL.handled(e)) $('earlier').innerHTML = '<p class="err">' + esc(e.message) + '</p>'; }
    }
  };

  /* =============================================== app detail =============================================== */
  V.app = function (root) {
    var id = PL.qs('id'), S = { app: null, ws: null, live: null, reportId: null };
    root.innerHTML = '<nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="' + esc(PL.href('apps')) + '">Apps</a></li><li aria-current="page" id="crumb">App</li></ol></nav>' +
      '<div id="top" aria-live="polite"><div class="app-head"><div><p class="lab">App</p><div class="skeleton" style="height:34px;width:min(420px,80vw)"></div><div class="skeleton mt-2" style="height:14px;width:240px"></div></div></div><div class="skeleton sk-block"></div></div>' +
      '<div id="runmsg"></div>' +
      '<div class="app-layout" id="layout" hidden><div>' +
      '<section aria-labelledby="find-h"><h2 class="sec-title" id="find-h">Findings</h2><p class="sec-sub" id="find-sub">From the latest finished check.</p><div id="findings"></div></section>' +
      '<section class="block" aria-labelledby="age-h" id="age-sec" hidden><h2 class="sec-title" id="age-h">Open and fixed</h2><p class="sec-sub">How long each finding has been open across this app’s checks, and what was fixed.</p><div id="ages"></div></section>' +
      '<section class="block" aria-labelledby="diff-h"><h2 class="sec-title" id="diff-h">Since the last check</h2><div id="diff"></div></section>' +
      '<section class="block" aria-labelledby="hist-h"><h2 class="sec-title" id="hist-h">Check history</h2><p class="sec-sub">Every check of this app, newest first. Each report stays available by its link.</p><div id="history"></div></section>' +
      '</div><aside class="side" id="side" aria-label="App settings"></aside></div>';

    if (!id) { PL.wireSignout(); $('top').innerHTML = '<div class="empty"><h2>No app selected</h2><p>Open an app from your <a href="' + esc(PL.href('apps')) + '">apps list</a>.</p></div>'; return; }

    PL.boot({ onWorkspace: function () { location.href = PL.href('apps'); } }).then(load)
      .catch(function (e) { PL.errorBox($('top'), e, function () { location.reload(); }); });

    async function load() {
      try {
        var a = await PL.call('/apps/' + encodeURIComponent(id));
        var w = await PL.call('/workspaces/' + a.workspace_id);
        S.app = a; S.ws = w;
        if (!PL.demo && PL.store.get('pl_ws') !== a.workspace_id) { PL.store.set('pl_ws', a.workspace_id); var sel = $('ws-select'); if (sel) sel.value = a.workspace_id; }
        renderTop(); renderSide(); live();
      } catch (e) {
        if (PL.handled(e)) return;
        if (e.status === 404) { $('top').innerHTML = '<div class="empty"><h2>App not found</h2><p>It may have been deleted, or it belongs to a workspace you’re not in. <a href="' + esc(PL.href('apps')) + '">Back to your apps</a>.</p></div>'; $('layout').hidden = true; return; }
        PL.errorBox($('top'), e, load);
      }
    }
    async function refresh() {
      S.app = await PL.call('/apps/' + encodeURIComponent(id));
      renderTop(); live();
      var nx = $('next-at'); if (nx) nx.innerHTML = nextText();
    }
    function live() {
      if (S.app.open_check_id && !S.live) S.live = PL.every(refresh, 15000);
      if (!S.app.open_check_id && S.live) { S.live.stop(); S.live = null; }
    }
    function nextText() {
      var a = S.app;
      if (!a.verified) return 'Starts once the repo is verified.';
      if (a.schedule === 'off') return 'No scheduled re-checks. Run one by hand any time.';
      return 'Next re-check ' + esc(PL.rel(a.next_check_at)) + ' (' + esc(PL.dateTime(a.next_check_at)) + ').';
    }
    function latestFinished() { return (S.app.checks || []).filter(function (c) { return FINISHED.indexOf(c.status) >= 0; })[0]; }

    function renderTop() {
      var a = S.app, st = PL.status(a), latest = latestFinished();
      document.title = a.repo + (PL.demo ? ' | PatchLabs demo' : ' | PatchLabs');
      $('crumb').textContent = a.repo;
      var h = '<div class="app-head"><div><p class="lab">App</p><h1 class="app-title mono" style="font-size:clamp(22px,2.6vw,30px)">' + esc(a.repo) + '</h1>' +
        '<p class="app-sub" id="st-line">' + PL.pill(st) + ' <span style="margin-left:6px">' + esc(st.note) + '</span></p>' +
        '<p class="app-sub small">' + (a.client_label ? 'Client: <b class="ink">' + esc(a.client_label) + '</b> · ' : '') + (a.branch ? 'Branch <code>' + esc(a.branch) + '</code> · ' : '') + 'Added ' + esc(PL.date(a.created_at)) + '</p></div>' +
        '<div class="actions">' + (PL.can(S.ws, 'support') ? PL.supportLink({ app: a.id }, 'btn ghost', 'Raise a ticket') : '') +
        (latest ? '<a class="btn secondary" href="' + esc(PL.href('check', { id: latest.id })) + '">Latest report</a>' : '') +
        (a.verified && PL.can(S.ws, 'run') ? '<button class="btn primary" type="button" id="run"' + (a.open_check_id ? ' disabled' : '') + '>' + (a.open_check_id ? '<span class="spin" aria-hidden="true"></span>Check running' : 'Run check now') + '</button>' : '') + '</div></div>';
      if (!a.verified && !PL.can(S.ws, 'manage')) {
        h += '<div class="callout note"><p><strong>Not verified yet.</strong> An owner or admin proves the repo is theirs, then the first check starts.</p></div>';
      } else if (!a.verified) {
        h += '<div class="panel" id="vpanel"><p class="lab">Verify</p><h2>Prove the repo is yours</h2>' + PL.verifyHtml(a.repo, a.verify) + '</div>';
      } else if (a.open_check_id) {
        h += '<div class="callout note"><p><span class="spin" aria-hidden="true"></span><strong>A check is running.</strong> It usually takes 5 to 15 minutes; this page refreshes every 15 seconds. <a href="' + esc(PL.href('check', { id: a.open_check_id })) + '">Watch it live</a>.</p></div>';
      }
      if (PL.stale(a)) h += '<div class="callout stale stale-note"><p><strong>Last checked ' + PL.plural(a.freshness.days_since_check, 'day') + ' ago: this result is out of date.</strong> ' +
        'Results older than ' + PL.plural(a.freshness.stale_after_days, 'day') + ' don’t count, so the public badge shows the age instead of a result.' + (PL.can(S.ws, 'run') ? ' Run a check to bring it up to date.' : '') + '</p></div>';
      $('top').innerHTML = h;
      if ($('vpanel')) PL.wireVerify($('vpanel'), a.id, function () { PL.toast('Verified. The first check is queued.', 'ok'); load(); });
      if ($('run')) $('run').onclick = runNow;
      $('layout').hidden = false;
      renderFindings(); renderAges(); renderDiff(); renderHistory();
    }

    async function renderFindings() {
      var latest = latestFinished(), el = $('findings');
      if (!latest) {
        S.reportId = null;
        $('find-sub').textContent = 'From the latest finished check.';
        el.innerHTML = '<div class="empty small"><p>' + (S.app.verified ? 'Findings appear when the first check finishes.' : 'Verify the repo to start the first check.') + '</p></div>';
        return;
      }
      if (S.reportId === latest.id) return;
      S.reportId = latest.id;
      $('find-sub').innerHTML = 'From the check of ' + esc(PL.dateTime(latest.finished_at)) + '. <a href="' + esc(PL.href('report', { id: latest.id })) + '">Open as a page</a>';
      el.innerHTML = '<div class="panel">' + PL.skeleton(4) + '</div>';
      try {
        var r = await Promise.all([PL.call('/checks/' + encodeURIComponent(latest.id)), PL.taxonomy()]), k = r[0];
        if (S.reportId !== latest.id) return;
        S.taxonomy = r[1];
        PL.report(el, k, { appId: S.app.id, ws: S.ws, taxonomy: r[1] });
        // the status pill can now count code findings too
        var st = PL.status(S.app, PL.findingInfo(k.summary));
        if ($('st-line')) $('st-line').innerHTML = PL.pill(st) + ' <span style="margin-left:6px">' + esc(st.note) + '</span>';
      } catch (e) {
        if (PL.handled(e)) return;
        S.reportId = null;
        PL.errorBox(el, e, renderFindings);
      }
    }

    // GET /apps/{aid}.findings: {open: [...], fixed: [...]} with first_seen, days_open, fixed_at, regressed
    async function renderAges() {
      var F = S.app.findings, el = $('ages');
      if (!F || (!(F.open || []).length && !(F.fixed || []).length)) { $('age-sec').hidden = true; return; }
      $('age-sec').hidden = false;
      var tx = S.taxonomy || await PL.taxonomy(); S.taxonomy = tx;
      var item = function (f) {
        return '<li class="age-row"><span class="pill sev-' + esc(String(f.severity || 'info').toLowerCase()) + '">' + esc(String(f.severity || 'info').toLowerCase()) + '</span><code class="fid">' + esc(f.id) + '</code>' +
          '<span class="ft">' + esc(f.title || f.id) + (f.object || f.file ? '<code class="fo">' + esc(f.object || f.file) + '</code>' : '') + '<span class="fmeta">' + PL.ageHtml(f) + PL.tagsHtml(f, tx) + '</span></span>' +
          '<a class="link-arrow small" href="/findings/' + encodeURIComponent(String(f.id).toLowerCase()) + '">' + esc(f.id) + '</a></li>';
      };
      var open = F.open || [], fixed = F.fixed || [];
      var oldest = open.reduce(function (m, f) { return Math.max(m, f.days_open || 0); }, 0), back = open.filter(function (f) { return f.regressed; }).length;
      el.innerHTML = '<div class="age-sum"><div><b class="num">' + open.length + '</b><span>open</span></div><div><b class="num">' + PL.plural(oldest, 'day') + '</b><span>oldest open</span></div>' +
        '<div><b class="num green">' + fixed.length + '</b><span>fixed recently</span></div><div><b class="num' + (back ? ' amber' : '') + '">' + back + '</b><span>back again</span></div></div>' +
        '<details class="age-fixed"' + (open.length ? '' : ' hidden') + '><summary>Open findings <span class="muted">' + open.length + ', oldest first within each severity</span></summary>' +
        '<ul class="age-list">' + open.map(item).join('') + '</ul></details>' +
        '<details class="age-fixed"' + (fixed.length ? ' open' : '') + '><summary>Fixed recently <span class="muted">' + fixed.length + '</span></summary>' +
        (fixed.length ? '<ul class="age-list">' + fixed.map(item).join('') + '</ul>' : '<p class="small muted">Nothing fixed yet. When a later check stops reporting a finding, it moves here.</p>') + '</details>';
    }

    function renderDiff() {
      var d = S.app.diff || {}, checks = S.app.checks || [];
      if (!d.to_check_id) {
        $('diff').innerHTML = '<div class="empty small"><p>' + (S.app.verified ? 'The comparison appears when the first check finishes.' : 'Verify the repo to start the first check.') + '</p></div>';
        return;
      }
      var at = function (cid) { var c = checks.filter(function (x) { return x.id === cid; })[0]; return c ? PL.date(c.finished_at) : ''; };
      var card = function (cls, k, list, empty) {
        return '<div class="diff-card ' + cls + '"><div class="k">' + k + '</div><div class="n">' + list.length + '</div><div class="t">' + (list.length ? PL.tables(list) : esc(empty)) + '</div></div>';
      };
      $('diff').innerHTML = '<p class="sec-sub">' + (d.from_check_id
          ? 'Leaking tables in the check of <a href="' + esc(PL.href('report', { id: d.to_check_id })) + '">' + esc(at(d.to_check_id)) + '</a> compared with the one before it (<a href="' + esc(PL.href('report', { id: d.from_check_id })) + '">' + esc(at(d.from_check_id)) + '</a>).'
          : 'First finished check (<a href="' + esc(PL.href('report', { id: d.to_check_id })) + '">' + esc(at(d.to_check_id)) + '</a>): everything it found counts as new.') + '</p>' +
        '<div class="diff-grid">' + card('red', 'New leaks', d.new_leaks || [], 'None') + card('green', 'Fixed', d.fixed || [], 'Nothing to fix') +
        card('red', 'Still leaking', d.still_leaking || [], 'None') + card('grey', 'Marked as intended', d.suppressed || [], 'None') + '</div>' +
        ((d.suppressed || []).length ? '<p class="small muted mt-2 mb-0">Your team marked these tables as meant to be readable, so they don’t raise alerts. Approve the fix on a report to start alerting on them again.</p>' : '');
    }

    function renderHistory() {
      var checks = S.app.checks || [], t = trendOf(checks);
      if (!checks.length) { $('history').innerHTML = '<div class="empty small"><p>No checks yet.</p></div>'; return; }
      var dot = { done: 'red', needs_review: 'amber', no_leaks: 'green', queued: 'amber', running: 'amber' };
      $('history').innerHTML = (t.pts.length > 1 ? '<div class="hist-trend"><span class="k">' + esc(t.what) + '</span>' + PL.spark(t.pts, t.what) + '</div>' : '') +
        '<ol class="timeline">' + checks.map(function (c) {
          var open = c.status === 'queued' || c.status === 'running';
          var tl = c.tables_leaking || [];
          var detail = open ? 'Started ' + esc(PL.rel(c.created_at))
            : c.status === 'failed' ? 'Couldn’t finish automatically'
            : tl.length ? PL.plural(tl.length, 'table') + ' leaking: ' + tl.map(function (x) { return '<code>' + esc(x) + '</code>'; }).join(' ') + (c.lab_proof_passed ? ' · lab proof passed' : c.status === 'needs_review' ? ' · fix in review' : '')
            : 'No data leaks: no personal data readable by the wrong people';
          if (c.counts && !open) detail += ' · ' + PL.plural(PL.total(c.counts), 'finding');
          var fin = FINISHED.indexOf(c.status) >= 0;
          return '<li><span class="dot ' + (dot[c.status] || '') + '" aria-hidden="true"></span><div class="what"><b>' + esc(PL.TRIGGERS[c.trigger] || 'Check') + '</b> ' + PL.checkPill(c.status) +
            '<div class="small muted mt-1">' + detail + '</div><div class="meta">' + esc(PL.dateTime(c.finished_at || c.created_at)) + '</div></div>' +
            (fin ? '<a class="btn small ghost go" href="' + esc(PL.href('report', { id: c.id })) + '">Findings</a>'
              : '<a class="btn small ' + (open ? 'secondary' : 'ghost') + ' go" href="' + esc(PL.href('check', { id: c.id })) + '">' + (open ? 'Watch' : 'Report') + '</a>') + '</li>';
        }).join('') + '</ol>' + (checks.length >= 50 ? '<p class="small muted mt-2">Showing the latest 50 checks.</p>' : '');
    }

    async function runNow() {
      var b = $('run'), restore = PL.busy(b, 'Queueing…'); $('runmsg').innerHTML = '';
      try {
        await PL.call('/apps/' + encodeURIComponent(id) + '/checks', { method: 'POST' });
        PL.toast('Check queued', 'ok');
        await refresh();
      } catch (e) {
        restore();
        if (PL.handled(e)) return;
        if (e.status === 429) $('runmsg').innerHTML = '<div class="callout limit"><p>' + esc(e.message) + '</p><p><a class="link-arrow" href="/app/settings#plan">Request an upgrade</a></p></div>';
        else if (e.status === 409) { $('runmsg').innerHTML = '<div class="callout note"><p>' + esc(e.message) + ' This page updates by itself when it finishes.</p></div>'; refresh(); }
        else $('runmsg').innerHTML = '<p class="err" role="alert">' + esc(e.message) + '</p>';
      }
    }

    function badgeSrc(on) {
      if (!PL.demo) return API + '/badge/' + encodeURIComponent(S.app.id) + '.svg?v=' + Date.now();
      var st = PL.status(S.app).cls;   // the demo never calls the API: show the matching example badge
      if (on && PL.stale(S.app)) {     // drawn here, like the API's grey "last checked N days ago" badge
        var msg = 'last checked ' + S.app.freshness.days_since_check + ' days ago', w = 64 + msg.length * 6.2;
        return 'data:image/svg+xml;charset=utf-8,' + encodeURIComponent('<svg xmlns="http://www.w3.org/2000/svg" width="' + Math.round(w) + '" height="20" role="img" aria-label="PatchLabs: ' + msg + '">' +
          '<rect width="64" height="20" fill="#24292f"/><rect x="64" width="' + Math.round(w - 64) + '" height="20" fill="#9f9f9f"/>' +
          '<g fill="#fff" font-family="Verdana,Geneva,sans-serif" font-size="11"><text x="8" y="14">PatchLabs</text><text x="71" y="14">' + msg + '</text></g></svg>');
      }
      return '/assets/pages/badge-example-' + (!on ? 'private' : st === 'neutral' ? 'grey' : st === 'proven' ? 'green' : 'amber') + '.svg';
    }
    function staleBadge() {
      var a = S.app;
      return PL.stale(a) ? '<div class="callout stale badge-stale"><p><strong>Stale: last checked ' + PL.plural(a.freshness.days_since_check, 'day') + ' ago.</strong> ' +
        'Until the next check, the badge shows that age in grey instead of a result (stale after ' + PL.plural(a.freshness.stale_after_days, 'day') + (a.schedule === 'off' ? ' without a schedule' : ' on a ' + a.schedule + ' schedule') + ').</p></div>'
        : a.freshness && a.freshness.days_since_check != null ? '<p class="small muted mb-0">Fresh: last checked ' + (a.freshness.days_since_check ? PL.plural(a.freshness.days_since_check, 'day') + ' ago' : 'today') +
          '. It goes stale after ' + PL.plural(a.freshness.stale_after_days, 'day') + '.</p>' : '';
    }
    function renderSide() {
      var a = S.app, l = S.ws.limits;
      if (!PL.can(S.ws, 'manage')) {   // read-only: what the settings are, no controls
        $('side').innerHTML = '<div class="panel"><h2>Settings</h2><p class="sec-sub">Only a workspace owner or admin can change these.</p><dl class="kv">' +
          '<dt>Re-checks</dt><dd>' + esc(PL.SCHEDULES[a.schedule] || a.schedule) + '</dd><dt>Next</dt><dd id="next-at">' + nextText() + '</dd>' +
          (a.client_label ? '<dt>Client</dt><dd>' + esc(a.client_label) + '</dd>' : '') + '<dt>Badge</dt><dd>' + (a.badge_public ? 'Public' : 'Private') + '</dd></dl>' +
          '<div class="badge-preview"><img id="badge-img" alt="Badge preview" src="' + esc(badgeSrc(a.badge_public)) + '"></div>' + staleBadge() + '</div>';
        return;
      }
      var md = '[![PatchLabs status](' + PROD_API + '/badge/' + a.id + '.svg)](' + PROD_SITE + '/proof?app=' + a.id + ')';
      var html = '<a href="' + PROD_SITE + '/proof?app=' + a.id + '"><img src="' + PROD_API + '/badge/' + a.id + '.svg" alt="PatchLabs status" height="20"></a>';
      $('side').innerHTML =
        '<div class="panel"><h2>Re-check schedule</h2><p class="sec-sub">Scheduled re-checks don’t count towards your manual runs.</p>' +
          '<label class="sr-only" for="sched">Re-check schedule</label><select class="input" id="sched">' + ['weekly', 'monthly', 'off'].map(function (s) {
            var ok = l.schedules.indexOf(s) >= 0;
            return '<option value="' + s + '"' + (s === a.schedule ? ' selected' : '') + (ok ? '' : ' disabled') + '>' + esc(PL.SCHEDULES[s]) + (ok ? '' : ' (upgrade to use)') + '</option>';
          }).join('') + '</select><p class="small muted mt-1 mb-0" id="next-at">' + nextText() + '</p><p class="err" role="alert" id="sched-err"></p>' +
          (l.schedules.indexOf('weekly') < 0 ? '<p class="small mt-1 mb-0"><a href="/app/settings#plan">Weekly re-checks come with Maker and up</a></p>' : '') + '</div>' +
        '<div class="panel"><h2>Client label</h2><p class="sec-sub">Shown in your apps list and alert emails.</p><form id="lf" class="form-row"><div class="field"><label class="sr-only" for="label">Client label</label><input id="label" maxlength="100" placeholder="e.g. Acme Ltd" value="' + esc(a.client_label || '') + '"></div><button class="btn secondary" type="submit" id="label-save">Save</button></form><p class="err" role="alert" id="label-err"></p></div>' +
        '<div class="panel"><h2>Public badge</h2><p class="sec-sub">Show visitors the date of your last check and its result, linked to a public proof page. It never shows table names or the report.</p>' +
          '<label class="switch"><input type="checkbox" id="badge"' + (a.badge_public ? ' checked' : '') + '> <span id="badge-l">' + (a.badge_public ? 'Badge is public' : 'Badge is private') + '</span></label>' +
          '<div class="badge-preview"><img id="badge-img" alt="Badge preview" src="' + esc(badgeSrc(a.badge_public)) + '"></div>' + staleBadge() +
          '<p class="small muted" id="badge-note">' + badgeNote(a.badge_public) + '</p>' +
          '<div class="code snip"><div class="code-bar"><span class="name">Markdown (README)</span><button class="copy" type="button" data-copy="#snip-md">Copy</button></div><pre id="snip-md">' + esc(md) + '</pre></div>' +
          '<div class="code snip"><div class="code-bar"><span class="name">HTML</span><button class="copy" type="button" data-copy="#snip-html">Copy</button></div><pre id="snip-html">' + esc(html) + '</pre></div></div>' +
        '<div class="panel danger-zone"><h2>Delete app</h2><p class="sec-sub">Removes the app and every check and report for it from PatchLabs. Your repo isn’t touched.</p><button class="btn danger" type="button" id="del">Delete app</button></div>';

      $('sched').addEventListener('change', async function () {
        var sel = this, prev = S.app.schedule; sel.disabled = true; $('sched-err').textContent = '';
        try { S.app = Object.assign(S.app, await PL.call('/apps/' + a.id, { method: 'PATCH', body: { schedule: sel.value } })); $('next-at').innerHTML = nextText(); PL.toast('Schedule saved', 'ok'); }
        catch (e) { sel.value = prev; if (!PL.handled(e)) $('sched-err').textContent = e.message; }
        sel.disabled = false;
      });
      $('lf').addEventListener('submit', async function (e) {
        e.preventDefault(); var restore = PL.busy($('label-save'), 'Saving…'); $('label-err').textContent = '';
        try { S.app = Object.assign(S.app, await PL.call('/apps/' + a.id, { method: 'PATCH', body: { client_label: $('label').value.trim() } })); restore(); PL.toast('Client label saved', 'ok'); renderTop(); }
        catch (x) { restore(); if (PL.handled(x)) $('label').value = S.app.client_label || ''; else $('label-err').textContent = x.message; }
      });
      $('badge').addEventListener('change', async function () {
        var cb = this, on = cb.checked; cb.disabled = true;
        try {
          S.app = Object.assign(S.app, await PL.call('/apps/' + a.id, { method: 'PATCH', body: { badge_public: on } }));
          $('badge-l').textContent = on ? 'Badge is public' : 'Badge is private';
          $('badge-note').innerHTML = badgeNote(on);
          $('badge-img').src = badgeSrc(on);
          PL.toast(on ? 'Badge is now public' : 'Badge is now private', 'ok');
        } catch (e) { cb.checked = !on; if (!PL.handled(e)) PL.toast(e.message, 'err'); }
        cb.disabled = false;
      });
      $('del').addEventListener('click', async function () {
        if (PL.demo) { PL.demoNotice(); return; }
        var n = (S.app.checks || []).length;
        var ok = await PL.confirm({ title: 'Delete ' + a.repo + '?', danger: true, confirm: 'Delete app', type: a.repo,
          text: '<p>This deletes the app, its ' + PL.plural(n, 'check') + ' and their reports from PatchLabs, and stops scheduled re-checks. Public badges for it will read “private”. It can’t be undone.</p>' });
        if (!ok) return;
        var restore = PL.busy($('del'), 'Deleting…');
        try {
          await PL.call('/apps/' + a.id, { method: 'DELETE' });
          try { sessionStorage.setItem('pl_flash', JSON.stringify({ text: 'Deleted ' + a.repo + '.', kind: 'ok' })); } catch (e) {}
          location.href = PL.href('apps');
        } catch (e) { restore(); if (!PL.handled(e)) PL.toast(e.message, 'err'); }
      });
    }
    function badgeNote(on) {
      var proof = PL.demo ? '' : '/proof?app=' + esc(id);
      return on ? 'Public: anyone with the link sees the badge and the ' + (proof ? '<a href="' + proof + '">proof page</a>' : 'proof page') + '. The image is cached for up to an hour.'
        : 'Private: the badge reads “private” and the proof page shows nothing. The snippets work as soon as you make it public.';
    }
  };

  /* =============================================== report =============================================== */
  V.report = function (root) {
    var id = PL.qs('id');
    root.innerHTML = '<nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="' + esc(PL.href('apps')) + '">Apps</a></li><li id="crumb-app" hidden></li><li aria-current="page" id="crumb">Report</li></ol></nav>' +
      '<div id="rhead"><div class="app-head"><div><p class="lab">Report</p><div class="skeleton" style="height:34px;width:min(420px,80vw)"></div><div class="skeleton mt-2" style="height:14px;width:260px"></div></div></div></div>' +
      '<div id="report" aria-live="polite"><div class="panel">' + PL.skeleton(5) + '</div></div>';
    if (!id) { PL.wireSignout(); $('rhead').innerHTML = ''; $('report').innerHTML = '<div class="empty"><h2>No report selected</h2><p>Open a report from an app’s <a href="' + esc(PL.href('apps')) + '">check history</a>.</p></div>'; return; }

    PL.boot({ onWorkspace: function () { location.href = PL.href('apps'); } }).then(load)
      .catch(function (e) { PL.errorBox($('report'), e, function () { location.reload(); }); });

    async function load() {
      var k;
      try { k = await PL.call('/checks/' + encodeURIComponent(id)); }
      catch (e) {
        if (PL.handled(e)) return;
        if (e.status === 404) { $('rhead').innerHTML = ''; $('report').innerHTML = '<div class="empty"><h2>Report not found</h2><p>Check the link is complete, or open it from the app’s check history. <a href="' + esc(PL.href('apps')) + '">Back to your apps</a>.</p></div>'; return; }
        PL.errorBox($('report'), e, load); return;
      }
      var app = null;
      var ws = null, tx = await PL.taxonomy();
      if (k.app_id) {
        try { app = await PL.call('/apps/' + encodeURIComponent(k.app_id)); ws = await PL.call('/workspaces/' + encodeURIComponent(app.workspace_id)); }
        catch (e) { if (e.redirecting) return; }
      }
      var c = app && (app.checks || []).filter(function (x) { return x.id === k.id; })[0];
      document.title = 'Report: ' + k.repo + (PL.demo ? ' | PatchLabs demo' : ' | PatchLabs');
      if (app) { var ca = $('crumb-app'); ca.hidden = false; ca.innerHTML = '<a href="' + esc(PL.href('app', { id: app.id })) + '">' + esc(app.repo) + '</a>'; }
      $('crumb').textContent = k.finished_at ? 'Check of ' + PL.date(k.finished_at) : 'Check';
      $('rhead').innerHTML = '<div class="app-head"><div><p class="lab">Report</p><h1 class="app-title mono" style="font-size:clamp(22px,2.6vw,30px)">' + esc(k.repo) + '</h1>' +
        '<p class="app-sub">' + PL.checkPill(k.status) + ' <span style="margin-left:6px">' + esc((c && PL.TRIGGERS[c.trigger]) || 'Check') + (k.finished_at ? ' · finished ' + esc(PL.dateTime(k.finished_at)) : ' · started ' + esc(PL.dateTime(k.created_at))) + (k.branch ? ' · branch <code>' + esc(k.branch) + '</code>' : '') + '</span></p></div>' +
        '<div class="actions">' + (!ws || PL.can(ws, 'support') ? PL.supportLink({ app: k.app_id }, 'btn ghost', 'Raise a ticket') : '') + (app ? '<a class="btn secondary" href="' + esc(PL.href('app', { id: app.id })) + '">Back to the app</a>' : '') + '</div></div>';
      if (FINISHED.indexOf(k.status) >= 0) { PL.report($('report'), k, { appId: k.app_id, ws: ws, taxonomy: tx }); return; }
      $('report').innerHTML = k.status === 'failed'
        ? '<div class="callout limit"><p><strong>This check couldn’t finish.</strong> We were alerted. Run it again from the app any time.</p></div>'
        : '<div class="callout note"><p><span class="spin" aria-hidden="true"></span><strong>This check hasn’t finished yet.</strong> It usually takes 5 to 15 minutes. <a href="' + esc(PL.href('check', { id: k.id })) + '">Watch it live</a>.</p></div>';
    }
  };
  /* =============================================== settings =============================================== */
  // Sections follow the caller's permissions (GET /workspaces/{wid}.permissions): Team and API keys need view_team,
  // the webhook and the audit log need manage. The API enforces the same rules and answers 403 with a sentence.
  V.settings = function (root) {
    var S = { me: null, ws: null, wsd: null, keys: [], apps: [], audit: { events: [], next: null, actions: [], f: {} } };
    root.innerHTML = '<div class="app-head"><div><p class="lab">Settings</p><h1 class="app-title">Settings</h1><p class="app-sub" id="ws-line"><span class="skeleton" style="display:inline-block;width:220px;height:14px"></span></p></div></div>' +
      '<div class="settings-layout"><nav class="settings-nav" aria-label="Settings sections" id="snav"></nav>' +
      '<div class="settings-main" id="sm" aria-live="polite"><div class="panel">' + PL.skeleton(3) + '</div><div class="panel">' + PL.skeleton(2) + '</div></div></div>';

    PL.boot({ onWorkspace: function (w) { S.ws = w; load(); } }).then(function (b) {
      S.me = b.me; S.ws = b.ws;
      if (!S.ws) { S.wsd = null; render(); return; }
      load();
    }).catch(function (e) { PL.errorBox($('sm'), e, function () { location.reload(); }); });

    var can = function (p) { return PL.can(S.wsd, p); };
    async function load() {
      try {
        S.wsd = await PL.call('/workspaces/' + S.ws.id);
        var r = await Promise.all([
          can('view_team') ? PL.call('/workspaces/' + S.ws.id + '/api-keys') : Promise.resolve({ api_keys: [] }),
          can('manage') ? PL.call('/workspaces/' + S.ws.id + '/apps') : Promise.resolve({ apps: [] })]);
        S.keys = r[0].api_keys; S.apps = r[1].apps;
        render();
        if (can('manage')) loadAudit(true);
        if (location.hash) { var t = document.getElementById(location.hash.slice(1)); if (t) t.scrollIntoView(); }
      } catch (e) { if (!PL.handled(e)) PL.errorBox($('sm'), e, load); }
    }
    var fail = function (el, x) { if (!PL.handled(x)) $(el).textContent = x.message; };
    // "Last used" and the audit log change while you're away (CI uses a key, a teammate acts): refresh on return
    async function refreshQuiet() {
      if (!S.wsd || document.hidden || PL.demo) return;
      if (can('view_team') && $('keys')) {
        try {
          var r = await PL.call('/workspaces/' + S.ws.id + '/api-keys');
          if (JSON.stringify(r.api_keys) !== JSON.stringify(S.keys)) {
            var once = $('k-once') ? $('k-once').innerHTML : '';
            S.keys = r.api_keys; $('keys').outerHTML = keys(); wireKeys(); if (once) $('k-once').innerHTML = once;
          }
        } catch (e) {}
      }
      if (can('manage') && S.audit.loaded) loadAudit(false, true);
    }
    window.addEventListener('focus', refreshQuiet);
    document.addEventListener('visibilitychange', function () { if (!document.hidden) refreshQuiet(); });

    function render() {
      var w = S.wsd, secs = [['profile', 'Profile', profile]];
      if (w) {
        if (can('view_team')) secs.push(['team', 'Team', team], ['keys', 'API keys', keys]);
        if (can('manage')) secs.push(['webhook', 'Webhook', webhook]);
        if (can('view_team')) secs.push(['plan', 'Plan & usage', plan]);
        if (can('manage')) secs.push(['audit', 'Audit log', auditShell]);
      }
      secs.push(['data', 'Your data', data], ['delete', 'Delete account', del]);
      $('ws-line').innerHTML = w ? 'Workspace: <b class="ink">' + esc(w.name) + '</b> · ' + esc(PL.planName(w.plan)) + ' plan · your role: <b class="ink">' + esc(PL.roleName(w.role)) + '</b>' : 'You’re not in any workspace.';
      $('snav').innerHTML = secs.map(function (x) { return '<a href="#' + x[0] + '">' + esc(x[1]) + '</a>'; }).join('');
      $('sm').innerHTML = secs.map(function (x) { return x[2](); }).join('');
      wireProfile(); wireData(); wireDelete();
      if (w && can('view_team')) { wireTeam(); wireKeys(); wirePlan(); }
      if (w && can('manage')) { wireWebhook(); wireAudit(); if (S.audit.loaded) { drawAudit(); loadAudit(false, true); } }
    }

    /* ---- profile ---- */
    function profile() {
      var u = S.me.user;
      return '<section class="panel" id="profile" aria-labelledby="h-profile"><h2 id="h-profile">Profile</h2><p class="sec-sub">Your name appears on decisions you record on reports and in team lists.</p>' +
        '<dl class="kv mb-3"><dt>Email</dt><dd>' + esc(u.email) + '</dd><dt>Joined</dt><dd>' + esc(PL.date(u.created_at)) + '</dd></dl>' +
        '<form id="pf" class="form-row"><div class="field"><label for="p-name">Name</label><input id="p-name" maxlength="100" autocomplete="name" value="' + esc(u.name || '') + '" placeholder="Your name"></div><button class="btn secondary" type="submit" id="p-save">Save</button></form><p class="err" role="alert" id="p-err"></p></section>';
    }
    function wireProfile() {
      $('pf').addEventListener('submit', async function (e) {
        e.preventDefault(); var restore = PL.busy($('p-save'), 'Saving…'); $('p-err').textContent = '';
        try { var r = await PL.call('/me', { method: 'PATCH', body: { name: $('p-name').value.trim() } }); S.me.user = r.user; restore(); PL.toast('Name saved', 'ok'); }
        catch (x) { restore(); if (PL.handled(x)) $('p-name').value = S.me.user.name || ''; else $('p-err').textContent = x.message; }
      });
    }

    /* ---- team: roles, client app access, invites ---- */
    var roleOpts = function (current, forInvite, noSeat) {
      var mgrOwner = can('owner');
      return PL.ROLES.filter(function (r) { return mgrOwner || r !== 'owner' || current === 'owner'; }).map(function (r) {
        var off = noSeat && r !== 'client' && current !== r;
        return '<option value="' + r + '"' + (r === current ? ' selected' : '') + (off ? ' disabled' : '') + '>' + esc(PL.roleName(r)) + (off ? ' (no seats left)' : '') + '</option>';
      }).join('');
    };
    var appPicker = function (id, chosen, label) {
      chosen = chosen || [];
      if (!S.apps.length) return '<p class="small muted mb-0" id="' + id + '">No apps in this workspace yet. Add one, then share it here.</p>';
      return '<fieldset class="app-pick" id="' + id + '"><legend class="sr-only">' + esc(label) + '</legend>' + S.apps.map(function (a) {
        return '<label class="check"><input type="checkbox" value="' + esc(a.id) + '"' + (chosen.indexOf(a.id) >= 0 ? ' checked' : '') + '> <span class="mono">' + esc(a.repo) + '</span>' + (a.client_label ? ' <span class="muted small">' + esc(a.client_label) + '</span>' : '') + '</label>';
      }).join('') + '</fieldset>';
    };
    var picked = function (id) { return [].slice.call(document.querySelectorAll('#' + id + ' input:checked')).map(function (i) { return i.value; }); };
    var appNames = function (ids) {
      var n = (ids || []).map(function (id) { var a = S.apps.filter(function (x) { return x.id === id; })[0]; return a ? a.repo : null; }).filter(Boolean);
      return n.length ? n.map(function (x) { return '<code>' + esc(x) + '</code>'; }).join(' ') : '<span class="muted">No apps yet</span>';
    };
    function team() {
      var w = S.wsd, me = S.me.user.id, manage = can('manage'), isOwner = can('owner');
      var pendingSeats = w.invites.filter(function (i) { return i.role !== 'client'; }).length;
      var seatsLeft = w.limits.seats - w.usage.members - pendingSeats;
      var rows = w.members.map(function (m) {
        var self = m.user_id === me, locked = m.role === 'owner' && !isOwner, info = PL.ROLE_INFO[m.role] || [m.role, ''];
        var roleCell = manage && !locked
          ? '<label class="sr-only" for="r-' + esc(m.user_id) + '">Role for ' + esc(m.email) + '</label><select class="input" id="r-' + esc(m.user_id) + '" data-role>' + roleOpts(m.role, false, seatsLeft <= 0 && m.role === 'client') + '</select>'
          : manage ? '<select class="input" id="r-' + esc(m.user_id) + '" disabled title="Only an owner can change an owner"><option>' + esc(info[0]) + '</option></select>' : '<b class="ink">' + esc(info[0]) + '</b>';
        var apps = m.role !== 'client' ? '<span class="muted small">All apps</span>'
          : manage ? '<details class="apps-edit"><summary>' + PL.plural((m.app_ids || []).length, 'app') + ' shared</summary>' + appPicker('ap-' + m.user_id, m.app_ids, 'Apps shared with ' + (m.name || m.email)) +
            (S.apps.length ? '<button class="btn small secondary" type="button" data-save-apps>Save apps</button>' : '') + '</details>'
          : appNames(m.app_ids);
        return '<tr data-uid="' + esc(m.user_id) + '"><th scope="row">' + esc(m.name || m.email) + (self ? '<span class="tag">you</span>' : '') + (m.name ? '<div class="small muted" style="font-weight:400">' + esc(m.email) + '</div>' : '') + '</th>' +
          '<td data-label="Role" class="c-role">' + roleCell + '<div class="role-hint">' + esc(info[1]) + '</div></td>' +
          '<td data-label="Apps">' + apps + '</td>' +
          '<td data-label="Joined">' + esc(PL.date(m.joined_at)) + '</td>' +
          '<td class="acts">' + (manage && !self && !locked ? '<button class="btn small danger" type="button" data-remove>Remove</button>' : self ? '<button class="btn small secondary" type="button" data-remove>Leave</button>' : '') + '</td></tr>';
      }).join('');
      var inv = manage && w.invites.length ? '<h3 class="h4 mt-4 mb-1">Pending invites</h3><div class="table-wrap"><table class="table compact stack-sm"><thead><tr><th scope="col">Email</th><th scope="col">Role</th><th scope="col">Expires</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead><tbody>' +
        w.invites.map(function (i) {
          return '<tr data-iid="' + esc(i.id) + '"><th scope="row">' + esc(i.email) + '</th><td data-label="Role">' + esc(PL.roleName(i.role)) + (i.role === 'client' ? ' <span class="small muted">· ' + PL.plural((i.app_ids || []).length, 'app') + '</span>' : '') + '</td><td data-label="Expires">' + esc(PL.date(i.expires_at)) + '</td>' +
            '<td class="acts">' + (i.role !== 'owner' || isOwner ? '<button class="btn small ghost" type="button" data-revoke-inv>Revoke</button>' : '') + '</td></tr>';
        }).join('') + '</tbody></table></div>' : '';
      var full = seatsLeft <= 0;
      var form = manage ? '<h3 class="h4 mt-4 mb-1">Invite someone</h3><p class="small muted">They get an email with a join link that lasts 14 days. ' +
          (full ? '' : PL.plural(seatsLeft, 'seat') + ' left on the ' + esc(PL.planName(w.plan)) + ' plan. ') + 'Clients don’t use a seat.</p>' +
          (full ? '<div class="callout limit"><p>' + (w.limits.seats === 1 ? 'The 1 seat on the ' + esc(PL.planName(w.plan)) + ' plan is taken.' : 'All ' + w.limits.seats + ' seats on the ' + esc(PL.planName(w.plan)) + ' plan are taken or invited.') +
            ' You can still invite clients. <a href="#plan">Request an upgrade</a> for more seats.</p></div>' : '') +
          '<form id="if" novalidate><div class="form-row"><div class="field"><label for="i-email">Email</label><input id="i-email" type="email" autocomplete="off" placeholder="teammate@company.com"></div>' +
          '<div class="field narrow"><label for="i-role">Role</label><select id="i-role">' + roleOpts(full ? 'client' : 'member', true, full) + '</select></div><button class="btn secondary" type="submit" id="i-go">Send invite</button></div>' +
          '<p class="small muted mt-1 mb-0" id="i-hint">' + esc(PL.ROLE_INFO[full ? 'client' : 'member'][1]) + '</p>' +
          '<div id="i-apps-box" class="mt-2"' + (full ? '' : ' hidden') + '><p class="small ink mb-1"><b>Apps to share</b></p>' + appPicker('i-apps', [], 'Apps to share with the client') + '</div></form><p class="err" role="alert" id="i-err"></p>'
        : '<p class="small muted mt-3 mb-0">Only owners and admins can invite people or change roles.</p>';
      return '<section class="panel" id="team" aria-labelledby="h-team"><h2 id="h-team">Team</h2><p class="sec-sub">Each person’s role decides what they can do here. Clients see only the apps you share with them.</p>' +
        (manage ? '<form id="wf" class="form-row mb-3"><div class="field"><label for="w-name">Workspace name</label><input id="w-name" maxlength="100" value="' + esc(w.name) + '"></div><button class="btn secondary" type="submit" id="w-save">Rename</button></form>' : '') +
        '<div class="table-wrap"><table class="table compact stack-sm team-table"><thead><tr><th scope="col">Member</th><th scope="col">Role</th><th scope="col">Apps</th><th scope="col">Joined</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead><tbody>' + rows + '</tbody></table></div><p class="err" role="alert" id="t-err"></p>' +
        '<details class="roles-help"><summary>What each role can do</summary><dl class="kv">' + PL.ROLES.map(function (r) { return '<dt>' + esc(PL.roleName(r)) + '</dt><dd>' + esc(PL.ROLE_INFO[r][1]) + '</dd>'; }).join('') + '</dl></details>' +
        inv + form + '</section>';
    }
    function wireTeam() {
      var wid = S.ws.id;
      if ($('wf')) $('wf').addEventListener('submit', async function (e) {
        e.preventDefault(); var restore = PL.busy($('w-save'), 'Saving…');
        try {
          S.wsd = await PL.call('/workspaces/' + wid, { method: 'PATCH', body: { name: $('w-name').value.trim() } });
          PL.toast('Workspace renamed', 'ok');
          var me = await PL.call('/me'); PL.mountSwitcher(me, me.workspaces.filter(function (x) { return x.id === wid; })[0], function (w) { S.ws = w; load(); });
          render();
        } catch (x) { restore(); fail('t-err', x); }
      });
      document.querySelectorAll('#team [data-role]').forEach(function (sel) {
        var prev = sel.value;
        sel.addEventListener('change', async function () {
          var uid = sel.closest('tr').dataset.uid, self = uid === S.me.user.id, to = sel.value;
          var owners = S.wsd.members.filter(function (x) { return x.role === 'owner'; }).length;
          var lastOwner = prev === 'owner' && owners <= 1;   // the API refuses with its own sentence; no need to ask first
          if (self && !lastOwner && !PL.can({ role: to }, 'manage')) {
            var ok = await PL.confirm({ title: 'Change your own role to ' + PL.roleName(to) + '?', text: '<p>You’ll lose access to team, webhook and audit settings straight away. Another owner or admin would have to change it back.</p>', confirm: 'Change my role', danger: true });
            if (!ok) { sel.value = prev; return; }
          }
          sel.disabled = true; $('t-err').textContent = '';
          try { S.wsd = await PL.call('/workspaces/' + wid + '/members/' + uid, { method: 'PATCH', body: { role: to } }); PL.toast('Role updated', 'ok'); if (self) { load(); return; } render(); }
          catch (x) { sel.value = prev; sel.disabled = false; fail('t-err', x); }
        });
      });
      document.querySelectorAll('#team [data-save-apps]').forEach(function (b) {
        b.addEventListener('click', async function () {
          var uid = b.closest('tr').dataset.uid, restore = PL.busy(b, 'Saving…'); $('t-err').textContent = '';
          try { S.wsd = await PL.call('/workspaces/' + wid + '/members/' + uid + '/apps', { method: 'PUT', body: { app_ids: picked('ap-' + uid) } }); PL.toast('Shared apps saved', 'ok'); render(); }
          catch (x) { restore(); fail('t-err', x); }
        });
      });
      document.querySelectorAll('#team [data-remove]').forEach(function (b) {
        b.addEventListener('click', async function () {
          var uid = b.closest('tr').dataset.uid, self = uid === S.me.user.id;
          var m = S.wsd.members.filter(function (x) { return x.user_id === uid; })[0];
          var ok = await PL.confirm(self
            ? { title: 'Leave ' + S.wsd.name + '?', text: '<p>You’ll lose access to its apps and reports. An owner or admin can invite you again.</p>', confirm: 'Leave workspace', danger: true }
            : { title: 'Remove ' + (m.name || m.email) + '?', text: '<p>They lose access to this workspace’s apps and reports straight away, and their API keys stop working. Their account stays.</p>', confirm: 'Remove', danger: true });
          if (!ok) return;
          var restore = PL.busy(b, '…'); $('t-err').textContent = '';
          try {
            await PL.call('/workspaces/' + wid + '/members/' + uid, { method: 'DELETE' });
            if (self) { PL.store.del('pl_ws'); location.href = PL.href('apps'); return; }
            PL.toast('Removed', 'ok'); load();
          } catch (x) { restore(); fail('t-err', x); }
        });
      });
      document.querySelectorAll('#team [data-revoke-inv]').forEach(function (b) {
        b.addEventListener('click', async function () {
          var iid = b.closest('tr').dataset.iid, restore = PL.busy(b, '…');
          try { await PL.call('/workspaces/' + wid + '/invites/' + iid, { method: 'DELETE' }); PL.toast('Invite revoked', 'ok'); load(); }
          catch (x) { restore(); fail('t-err', x); }
        });
      });
      if ($('i-role')) $('i-role').addEventListener('change', function () {
        $('i-hint').textContent = PL.ROLE_INFO[this.value][1];
        $('i-apps-box').hidden = this.value !== 'client';
      });
      if ($('if')) $('if').addEventListener('submit', async function (e) {
        e.preventDefault(); var email = $('i-email').value.trim(), role = $('i-role').value;
        if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) { $('i-err').textContent = 'Enter a valid email address.'; $('i-email').focus(); return; }
        var body = { email: email, role: role };
        if (role === 'client') body.app_ids = picked('i-apps');
        var restore = PL.busy($('i-go'), 'Sending…'); $('i-err').textContent = '';
        try { await PL.call('/workspaces/' + wid + '/invites', { method: 'POST', body: body }); PL.toast('Invite sent to ' + email, 'ok'); load(); }
        catch (x) { restore(); fail('i-err', x); }
      });
    }

    /* ---- API keys ---- */
    function keys() {
      var run = can('run'), manage = can('manage'), me = S.me.user.id;
      var rows = S.keys.map(function (k) {
        var mine = k.created_by === me;
        return '<tr data-kid="' + esc(k.id) + '"><th scope="row">' + esc(k.name) + (k.created_by_email ? '<div class="small muted" style="font-weight:400">by ' + esc(mine ? 'you' : k.created_by_email) + '</div>' : '') + '</th><td data-label="Key"><code>' + esc(k.prefix) + '…</code></td><td data-label="Created">' + esc(PL.date(k.created_at)) + '</td><td data-label="Last used">' + (k.last_used_at ? esc(PL.rel(k.last_used_at)) : '<span class="muted">Never</span>') + '</td>' +
          '<td class="acts">' + (run && (mine || manage) ? '<button class="btn small danger" type="button" data-revoke-key>Revoke</button>' : '') + '</td></tr>';
      }).join('');
      return '<section class="panel" id="keys" aria-labelledby="h-keys"><h2 id="h-keys">API keys</h2><p class="sec-sub">Start checks from CI and read results. Keys belong to this workspace and work on every plan. See the <a href="/docs/api">API docs</a>.</p>' +
        (S.keys.length ? '<div class="table-wrap"><table class="table compact stack-sm"><thead><tr><th scope="col">Name</th><th scope="col">Key</th><th scope="col">Created</th><th scope="col">Last used</th><th scope="col"><span class="sr-only">Actions</span></th></tr></thead><tbody>' + rows + '</tbody></table></div>'
          : '<div class="empty small"><p>No API keys yet.</p></div>') +
        (run ? '<form id="kf" class="form-row mt-3"><div class="field"><label for="k-name">New key name</label><input id="k-name" maxlength="100" autocomplete="off" placeholder="e.g. GitHub Actions"></div><button class="btn secondary" type="submit" id="k-go">Create key</button></form>'
          : '<p class="small muted mt-3 mb-0">Your role can only view keys. Members and above create them.</p>') +
        '<p class="err" role="alert" id="k-err"></p><div id="k-once"></div></section>';
    }
    function wireKeys() {
      var wid = S.ws.id;
      if ($('kf')) $('kf').addEventListener('submit', async function (e) {
        e.preventDefault(); var name = $('k-name').value.trim();
        if (!name) { $('k-err').textContent = 'Give the key a name so you know where it’s used.'; $('k-name').focus(); return; }
        var restore = PL.busy($('k-go'), 'Creating…'); $('k-err').textContent = '';
        try {
          var k = await PL.call('/workspaces/' + wid + '/api-keys', { method: 'POST', body: { name: name } });
          S.keys.push(k); render();
          $('k-once').innerHTML = '<div class="key-once" role="status"><p class="mb-0"><strong class="ink">Copy your new key “' + esc(k.name) + '” now.</strong> We store only a hash, so you won’t see it again.</p>' +
            '<code class="k" id="k-full">' + esc(k.key) + '</code><div class="row"><button class="btn small primary" type="button" data-copy="#k-full">Copy key</button>' +
            '<span class="small muted">Use it as <code>X-API-Key</code>, e.g. <code>curl -X POST ' + esc(API) + '/v1/apps/&lt;app id&gt;/checks -H "X-API-Key: …"</code></span></div></div>';
          $('k-once').scrollIntoView({ block: 'nearest' });
        } catch (x) { restore(); fail('k-err', x); }
      });
      document.querySelectorAll('[data-revoke-key]').forEach(function (b) {
        b.addEventListener('click', async function () {
          var kid = b.closest('tr').dataset.kid, k = S.keys.filter(function (x) { return x.id === kid; })[0];
          var ok = await PL.confirm({ title: 'Revoke “' + k.name + '”?', text: '<p>Anything using <code>' + esc(k.prefix) + '…</code> stops working immediately. This can’t be undone.</p>', confirm: 'Revoke key', danger: true });
          if (!ok) return;
          var restore = PL.busy(b, '…');
          try { await PL.call('/workspaces/' + wid + '/api-keys/' + kid, { method: 'DELETE' }); S.keys = S.keys.filter(function (x) { return x.id !== kid; }); render(); PL.toast('Key revoked', 'ok'); }
          catch (x) { restore(); fail('k-err', x); }
        });
      });
    }

    /* ---- webhook (owner/admin): detected format, override, signed-JSON secret ---- */
    var KINDS = { slack: 'Slack', discord: 'Discord', teams: 'Microsoft Teams', json: 'Signed JSON' };
    var detect = function (url) {   // mirrors api/alerts.py detect(), for the live hint while typing
      var u; try { u = new URL(url); } catch (e) { return null; }
      var h = u.hostname.toLowerCase(), p = u.pathname;
      if (h === 'hooks.slack.com' && /^\/(services|workflows|triggers)\//.test(p)) return 'slack';
      if (['discord.com', 'discordapp.com', 'ptb.discord.com', 'canary.discord.com'].indexOf(h) >= 0 && p.indexOf('/api/webhooks/') === 0) return 'discord';
      if (/\.webhook\.office\.com$/.test(h) || (/\.powerplatform\.com$/.test(h) && p.indexOf('/powerautomate/') >= 0)) return 'teams';
      return 'json';
    };
    function webhook() {
      var w = S.wsd, fmt = w.webhook_format || 'auto', kind = w.webhook_kind;
      var secret = w.webhook_url && kind === 'json' && w.webhook_secret
        ? '<div class="form-row mt-3"><div class="field"><label for="h-secret">Signing secret</label><input id="h-secret" class="mono" readonly spellcheck="false" autocomplete="off" value="' + esc(w.webhook_secret) + '"></div>' +
          '<button class="btn secondary" type="button" data-copy data-copy-text="' + esc(w.webhook_secret) + '">Copy secret</button><button class="btn ghost" type="button" id="h-rotate">Rotate</button></div>' +
          '<p class="small muted mb-0">Every request carries <code>X-PatchLabs-Timestamp</code> and <code>X-PatchLabs-Signature</code>, an HMAC-SHA256 of the timestamp and body made with this secret. <a href="/docs/webhooks#security">How to verify it</a>.</p>'
        : w.webhook_url ? '<p class="small muted mt-2 mb-0">Chat apps ignore signatures, so the signing secret shows only for Signed JSON.</p>' : '';
      return '<section class="panel" id="webhook" aria-labelledby="h-hook"><h2 id="h-hook">Webhook</h2><p class="sec-sub">When an app check finishes we post here: a native message for Slack, Discord and Microsoft Teams, or signed JSON for anything else. HTTPS and public hosts only.</p>' +
        '<form id="hf" novalidate><div class="form-row"><div class="field"><label for="h-url">Webhook URL ' + (w.webhook_url && kind ? '<span class="pill plain hook-kind" id="h-kind">' + esc(KINDS[kind] || kind) + '</span>' : '<span class="pill plain hook-kind" id="h-kind" hidden></span>') + '</label>' +
        '<input id="h-url" class="mono" type="url" autocomplete="off" spellcheck="false" placeholder="https://hooks.slack.com/services/…" value="' + esc(w.webhook_url || '') + '"></div>' +
        '<div class="field narrow"><label for="h-fmt">Message format</label><select id="h-fmt">' + [['auto', 'Automatic'], ['slack', 'Slack'], ['discord', 'Discord'], ['teams', 'Microsoft Teams'], ['json', 'Signed JSON']].map(function (o) {
          return '<option value="' + o[0] + '"' + (o[0] === fmt ? ' selected' : '') + '>' + o[1] + '</option>'; }).join('') + '</select></div>' +
        '<button class="btn secondary" type="submit" id="h-save">Save</button><button class="btn ghost" type="button" id="h-test"' + (w.webhook_url ? '' : ' disabled title="Save a webhook URL first"') + '>Send test</button></div>' +
        '<p class="small muted mt-1 mb-0" id="h-hint">Automatic recognises Slack, Discord and Teams webhook URLs.</p></form>' +
        '<p class="err" role="alert" id="h-err"></p><p id="h-res" class="small mb-0" role="status"></p>' + secret + '</section>';
    }
    function wireWebhook() {
      var wid = S.ws.id;
      var hint = function () {
        var url = $('h-url').value.trim(), f = $('h-fmt').value, k = !url ? null : f === 'auto' ? detect(url) : f;
        $('h-hint').textContent = !url ? 'Automatic recognises Slack, Discord and Teams webhook URLs.'
          : f === 'auto' ? 'Automatic: this URL gets ' + (KINDS[k] || 'Signed JSON') + ' messages.' : 'Always sent as ' + KINDS[f] + ', whatever the URL.';
      };
      $('h-url').addEventListener('input', hint); $('h-fmt').addEventListener('change', hint); hint();
      $('hf').addEventListener('submit', async function (e) {
        e.preventDefault();
        var restore = PL.busy($('h-save'), 'Saving…'); $('h-err').textContent = ''; $('h-res').textContent = '';
        try {
          S.wsd = await PL.call('/workspaces/' + wid, { method: 'PATCH', body: { webhook_url: $('h-url').value.trim(), webhook_format: $('h-fmt').value } });
          PL.toast(S.wsd.webhook_url ? 'Webhook saved' : 'Webhook removed', 'ok'); render();
        } catch (x) { restore(); fail('h-err', x); }
      });
      if ($('h-rotate')) $('h-rotate').addEventListener('click', async function () {
        var b = this;
        var ok = await PL.confirm({ title: 'Rotate the signing secret?', text: '<p>The current secret stops working straight away. Put the new one in your endpoint, or it will reject PatchLabs requests.</p>', confirm: 'Rotate secret', danger: true });
        if (!ok) return;
        var restore = PL.busy(b, 'Rotating…'); $('h-err').textContent = '';
        try { var r = await PL.call('/workspaces/' + wid + '/webhook/rotate-secret', { method: 'POST' }); S.wsd.webhook_secret = r.webhook_secret; render(); PL.toast('New signing secret created', 'ok'); }
        catch (x) { restore(); fail('h-err', x); }
      });
      $('h-test').addEventListener('click', async function () {
        var restore = PL.busy(this, 'Sending…'); $('h-err').textContent = ''; $('h-res').textContent = '';
        try {
          var r = await PL.call('/workspaces/' + wid + '/webhook/test', { method: 'POST' }), f = KINDS[r.format] || r.format || 'Signed JSON';
          $('h-res').innerHTML = r.ok ? '<span class="pill proven">HTTP ' + esc(r.status_code) + '</span> <span class="muted">Test sent as ' + esc(f) + ' and accepted.</span>'
            : '<span class="pill leak">' + (r.status_code ? 'HTTP ' + esc(r.status_code) : 'no response') + '</span> <span class="muted">Sent as ' + esc(f) + '. ' + esc(r.detail || 'Your endpoint didn’t accept the test message.') + '</span>';
        } catch (x) { fail('h-err', x); }
        restore();
      });
    }

    /* ---- plan & usage ---- */
    function plan() {
      var w = S.wsd, u = w.usage, l = w.limits;
      var opts = [['maker', 'Maker: £19 a month, 3 apps, weekly re-checks, 2 seats'], ['agency', 'Agency: £99 a month, 10 apps (+£8 per extra), 10 seats'], ['enterprise', 'Enterprise: custom limits']]
        .filter(function (o) { return o[0] !== w.plan; });
      var form = !can('manage') ? '<p class="small muted mb-0">An owner or admin can request a bigger plan.</p>'
        : opts.length ? '<h3 class="h4 mb-1">Request an upgrade</h3><form id="uf"><div class="field"><label for="u-plan">Plan</label><select id="u-plan">' + opts.map(function (o) { return '<option value="' + o[0] + '">' + esc(o[1]) + '</option>'; }).join('') + '</select></div>' +
          '<div class="field"><label for="u-note">Anything we should know? <span class="muted" style="font-weight:400">(optional)</span></label><textarea id="u-note" maxlength="2000" placeholder="e.g. how many apps you need, or a billing contact"></textarea></div>' +
          '<button class="btn primary" type="submit" id="u-go">Request upgrade</button><p class="err" role="alert" id="u-err"></p></form>'
        : '<p class="small muted mb-0">You’re on our largest plan. Email <a href="mailto:manraj@patchlabs.dev">manraj@patchlabs.dev</a> to change your limits.</p>';
      return '<section class="panel" id="plan" aria-labelledby="h-plan"><h2 id="h-plan">Plan &amp; usage</h2><p class="sec-sub">Card payments aren’t live yet: ask for a plan below and we set it up, usually within a day.</p>' +
        '<dl class="kv mb-3"><dt>Plan</dt><dd><span class="pill plain">' + esc(PL.planName(w.plan)) + '</span></dd><dt>Apps</dt><dd>' + u.apps + ' of ' + l.apps + '</dd><dt>Manual runs this month</dt><dd>' + u.runs_this_month + ' of ' + l.runs_per_month + '</dd>' +
        '<dt>Team seats</dt><dd>' + u.members + ' of ' + l.seats + (u.clients ? ' <span class="muted">· ' + PL.plural(u.clients, 'client') + ', who don’t use seats</span>' : '') + '</dd><dt>Re-check schedules</dt><dd>' + l.schedules.filter(function (s) { return s !== 'off'; }).map(function (s) { return PL.SCHEDULES[s]; }).join(', ') + '</dd></dl>' + form + '</section>';
    }
    function wirePlan() {
      if (!$('uf')) return;
      $('uf').addEventListener('submit', async function (e) {
        e.preventDefault(); var restore = PL.busy($('u-go'), 'Sending…'); $('u-err').textContent = '';
        try {
          var note = $('u-note').value.trim();
          var r = await PL.call('/workspaces/' + S.ws.id + '/upgrade-request', { method: 'POST', body: note ? { plan: $('u-plan').value, note: note } : { plan: $('u-plan').value } });
          loadAudit(false, true);
          $('uf').outerHTML = '<div class="callout sent" role="status"><p><strong>Request sent for ' + esc(PL.planName(r.plan)) + '.</strong> ' + esc(r.detail || 'We’ll reply within a day.') + '</p></div>';
        } catch (x) { restore(); fail('u-err', x); }
      });
    }

    /* ---- audit log (owner/admin) ---- */
    function auditShell() {
      var fams = {};
      (S.audit.actions || []).forEach(function (a) { var f = a.split('.')[0]; (fams[f] = fams[f] || []).push(a); });
      var FAM = { auth: 'Sign-ins', member: 'Team', workspace: 'Workspace', plan: 'Plan', upgrade: 'Upgrades', app: 'Apps', check: 'Checks', decision: 'Decisions', suppression: 'Alerts muted', api_key: 'API keys', webhook: 'Webhook', data: 'Data exports', audit: 'Audit exports', ticket: 'Support' };
      var f = S.audit.f;
      var actOpts = '<option value="">Every action</option>' + Object.keys(fams).map(function (k) {
        return '<optgroup label="' + esc(FAM[k] || k) + '"><option value="' + esc(k) + '"' + (f.action === k ? ' selected' : '') + '>All ' + esc((FAM[k] || k).toLowerCase()) + '</option>' +
          fams[k].map(function (a) { return '<option value="' + esc(a) + '"' + (f.action === a ? ' selected' : '') + '>' + esc(a) + '</option>'; }).join('') + '</optgroup>';
      }).join('');
      var actors = '<option value="">Anyone</option>' + S.wsd.members.map(function (m) { return '<option value="' + esc(m.user_id) + '"' + (f.actor === m.user_id ? ' selected' : '') + '>' + esc(m.name || m.email) + '</option>'; }).join('') +
        [['api_key', 'API keys'], ['admin', 'PatchLabs admin'], ['system', 'Scheduler']].map(function (o) { return '<option value="' + o[0] + '"' + (f.actor === o[0] ? ' selected' : '') + '>' + o[1] + '</option>'; }).join('');
      return '<section class="panel" id="audit" aria-labelledby="h-audit"><div class="row between"><div><h2 id="h-audit">Audit log</h2><p class="sec-sub mb-0">Who did what in this workspace. Append-only: entries can’t be edited or deleted.</p></div>' +
        '<div class="row"><button class="btn ghost small" type="button" id="au-refresh">Refresh</button><button class="btn secondary small" type="button" id="au-csv">Export CSV</button></div></div>' +
        '<form id="au-f" class="audit-filters" novalidate><label class="fsel"><span>Action</span><select class="input" id="au-action">' + actOpts + '</select></label>' +
        '<label class="fsel"><span>Who</span><select class="input" id="au-actor">' + actors + '</select></label>' +
        '<label class="fsel"><span>From</span><input class="input" type="date" id="au-since" value="' + esc(f.since || '') + '"></label>' +
        '<label class="fsel"><span>To</span><input class="input" type="date" id="au-until" value="' + esc(f.until || '') + '"></label>' +
        '<button class="btn small ghost" type="button" id="au-reset">Clear</button></form><p class="err" role="alert" id="au-err"></p>' +
        '<div id="au-list">' + PL.skeleton(3) + '</div></section>';
    }
    function wireAudit() {
      var apply = function () {
        S.audit.f = { action: $('au-action').value, actor: $('au-actor').value, since: $('au-since').value, until: $('au-until').value };
        if (S.audit.f.since && S.audit.f.until && S.audit.f.since > S.audit.f.until) { $('au-err').textContent = 'The “From” date is after the “To” date.'; return; }
        loadAudit(true);
      };
      ['au-action', 'au-actor', 'au-since', 'au-until'].forEach(function (id) { $(id).addEventListener('change', apply); });
      $('au-f').addEventListener('submit', function (e) { e.preventDefault(); apply(); });
      $('au-reset').addEventListener('click', function () { S.audit.f = {}; ['au-action', 'au-actor', 'au-since', 'au-until'].forEach(function (id) { $(id).value = ''; }); loadAudit(true); });
      $('au-csv').addEventListener('click', exportAudit);
      $('au-refresh').addEventListener('click', async function () { var restore = PL.busy(this, 'Refreshing…'); await loadAudit(false, true); restore(); });
    }
    var auditQuery = function (extra) {
      var q = new URLSearchParams(), f = S.audit.f;
      ['action', 'actor', 'since', 'until'].forEach(function (k) { if (f[k]) q.set(k, f[k]); });
      for (var k in (extra || {})) if (extra[k] != null) q.set(k, extra[k]);
      var s = q.toString(); return s ? '?' + s : '';
    };
    async function loadAudit(reset, quiet) {
      if (!$('au-list')) return;
      if (quiet) reset = true;
      else if (reset) $('au-list').innerHTML = PL.skeleton(3);
      $('au-err').textContent = '';
      try {
        var r = await PL.call('/workspaces/' + S.ws.id + '/audit' + auditQuery({ limit: 50, before: reset ? null : S.audit.next }));
        var first = !S.audit.actions.length;
        S.audit.events = reset ? r.events : S.audit.events.concat(r.events);
        S.audit.next = r.next_before; S.audit.actions = r.actions || S.audit.actions; S.audit.loaded = true;
        if (first && S.audit.actions.length) { var at = document.getElementById('audit'); if (at) { at.outerHTML = auditShell(); wireAudit(); } }
        drawAudit();
      } catch (x) { if (!PL.handled(x)) { $('au-list').innerHTML = ''; $('au-err').textContent = x.message; } }
    }
    var nameOf = function (t) { return t ? (t.label || t.email || t.type) : 'something'; };
    function sentence(e) {
      var d = e.detail || {}, t = e.target, T = '<b>' + esc(nameOf(t)) + '</b>', role = function (r) { return esc(PL.roleName(r || '').toLowerCase()); };
      switch (e.action) {
        case 'auth.sign_in': return 'signed in';
        case 'auth.sign_out': return 'signed out';
        case 'member.invited': return 'invited ' + T + ' as ' + role(d.role) + (d.apps != null ? ' with ' + PL.plural(d.apps, 'app') : '');
        case 'member.invite_cancelled': return 'cancelled the invite for ' + T;
        case 'member.joined': return 'joined the workspace' + (d.role ? ' as ' + role(d.role) : '');
        case 'member.role_changed': return 'changed ' + T + '’s role from ' + role(d.from) + ' to ' + role(d.to);
        case 'member.apps_changed': return 'changed the apps shared with ' + T + ' (' + (d.added || []).length + ' added, ' + (d.removed || []).length + ' removed)';
        case 'member.removed': return 'removed ' + T + ' from the workspace';
        case 'member.left': return 'left the workspace';
        case 'workspace.renamed': return 'renamed the workspace from “' + esc(d.from) + '” to “' + esc(d.to) + '”';
        case 'plan.changed': return 'changed the plan: ' + esc(Object.keys(d).map(function (k) { return k.replace(/_/g, ' ') + ' ' + (d[k] && d[k].from != null ? d[k].from : '–') + ' → ' + (d[k] && d[k].to != null ? d[k].to : '–'); }).join(', '));
        case 'upgrade.requested': return 'requested the ' + esc(PL.planName(d.plan || '')) + ' plan';
        case 'app.added': return 'added ' + T;
        case 'app.updated': return 'changed ' + esc(Object.keys(d).join(', ').replace(/_/g, ' ') || 'settings') + ' on ' + T;
        case 'app.verified': return 'verified ' + T;
        case 'app.removed': return 'removed ' + T;
        case 'check.started': return 'started ' + ({ verify: 'the first', manual: 'a manual', api: 'an API', scheduled: 'a scheduled' }[d.trigger] || 'a') + ' check of ' + T;
        case 'decision.made': return (d.action === 'reject' ? 'marked ' + esc((d.tables || []).join(', ') || 'tables') + ' as intended on ' : 'approved the fix for ' + esc((d.tables || []).join(', ')) + ' on ') + T;
        case 'check.answered': return 'answered the owner’s questions on ' + T;
        case 'suppression.added': return 'stopped alerts for <code>' + esc(d.table) + '</code>';
        case 'suppression.removed': return 'turned alerts back on for <code>' + esc(d.table) + '</code>';
        case 'api_key.created': return 'created API key ' + T + (d.prefix ? ' <code>' + esc(d.prefix) + '…</code>' : '');
        case 'api_key.revoked': return 'revoked API key ' + T + (d.reason ? ' (' + esc(d.reason) + ')' : '');
        case 'webhook.created': return 'added a ' + esc(KINDS[d.kind] || 'webhook') + ' webhook' + (d.host ? ' on ' + esc(d.host) : '');
        case 'webhook.changed': return d.format ? 'changed the webhook format from ' + esc(d.format.from) + ' to ' + esc(d.format.to) : 'changed the webhook' + (d.host ? ' to ' + esc(d.host) : '');
        case 'webhook.deleted': return 'removed the webhook' + (d.host ? ' on ' + esc(d.host) : '');
        case 'webhook.secret_rotated': return 'rotated the webhook signing secret';
        case 'webhook.tested': return 'sent a test to the webhook (' + (d.status_code ? 'HTTP ' + esc(d.status_code) : 'no response') + (d.format ? ', ' + esc(KINDS[d.format] || d.format) : '') + ')';
        case 'data.exported': return 'downloaded their data';
        case 'audit.exported': return 'exported the audit log' + (d.rows != null ? ' (' + PL.plural(d.rows, 'row') + ')' : '');
        case 'ticket.raised': return 'raised support ticket' + (d.number ? ' #' + esc(d.number) : '') + (d.category ? ' about ' + esc(d.category) : '');
      }
      return '<code>' + esc(e.action) + '</code>';
    }
    function drawAudit() {
      var el = $('au-list'); if (!el) return;
      var ev = S.audit.events, f = S.audit.f, filtered = f.action || f.actor || f.since || f.until;
      if (!ev.length) {
        el.innerHTML = '<div class="empty small"><p>' + (filtered ? 'Nothing matches these filters.' : 'Nothing recorded yet. Sign-ins, team changes, apps, checks, decisions, keys and webhooks show up here.') + '</p></div>';
        return;
      }
      el.innerHTML = '<div class="table-wrap"><table class="table compact stack-sm audit-table"><thead><tr><th scope="col">When</th><th scope="col">Who</th><th scope="col">What</th><th scope="col">Target</th></tr></thead><tbody>' +
        ev.map(function (e) {
          var a = e.actor || {}, t = e.target;
          return '<tr><td data-label="When" class="nowrap" title="' + esc(PL.dateTime(e.at)) + '">' + esc(PL.dateTime(e.at)) + '</td>' +
            '<td data-label="Who"><span' + (a.email ? ' title="' + esc(a.email) + '"' : '') + '>' + esc(a.label || 'Someone') + '</span>' + (a.kind && a.kind !== 'user' ? '<span class="tag">' + esc({ api_key: 'API key', admin: 'admin', system: 'scheduler' }[a.kind] || a.kind) + '</span>' : '') + '</td>' +
            '<td data-label="What">' + sentence(e) + '<div class="tiny muted mono">' + esc(e.action) + '</div></td>' +
            '<td data-label="Target">' + (t ? esc(nameOf(t)) + ' <span class="tag">' + esc(t.type) + '</span>' : '<span class="muted">–</span>') + '</td></tr>';
        }).join('') + '</tbody></table></div>' +
        (S.audit.next ? '<button class="btn secondary small mt-2" type="button" id="au-more">Load more</button>' : '<p class="small muted mt-2 mb-0">' + PL.plural(ev.length, 'entry', 'entries') + (filtered ? ' match' : '') + '. That’s everything.</p>');
      if ($('au-more')) $('au-more').addEventListener('click', async function () { var restore = PL.busy(this, 'Loading…'); await loadAudit(false); restore(); });
    }
    async function exportAudit() {
      var b = $('au-csv'), restore = PL.busy(b, 'Preparing…'); $('au-err').textContent = '';
      try {
        var name = 'patchlabs-audit-' + S.ws.id + '.csv', blob;
        if (PL.demo) {   // the demo builds the same columns from its sample entries
          var r = await PL.call('/workspaces/' + S.ws.id + '/audit' + auditQuery({ limit: 200 }));
          blob = new Blob([PL.csv([['id', 'at', 'action', 'actor_kind', 'actor', 'actor_email', 'target_type', 'target_id', 'target', 'target_email', 'detail']].concat(r.events.map(function (e) {
            var t = e.target || {};
            return [e.id, e.at, e.action, e.actor.kind, e.actor.label, e.actor.email, t.type, t.id, t.label, t.email, JSON.stringify(e.detail || {})];
          })))], { type: 'text/csv' });
        } else {
          var res = await api('/workspaces/' + S.ws.id + '/audit/export' + auditQuery(), { raw: true });
          if (res.status === 401) { session.clear(); PL.toLogin(); return; }
          if (!res.ok) { var j = await res.json().catch(function () { return {}; }); throw new Error(typeof j.detail === 'string' ? j.detail : 'We couldn’t export the audit log. Try again.'); }
          blob = await res.blob();
        }
        PL.download(blob, name); PL.toast('Audit log exported', 'ok');
        if (!PL.demo) loadAudit(true);   // the export itself is now an entry
      } catch (x) { fail('au-err', x); }
      restore();
    }

    /* ---- data export, delete account ---- */
    function data() {
      return '<section class="panel" id="data" aria-labelledby="h-data"><h2 id="h-data">Your data</h2><p class="sec-sub">Download everything we hold about you as JSON: your account, sessions, workspaces, apps, checks you started, keys you created and decisions you recorded.</p>' +
        '<button class="btn secondary" type="button" id="exp">Download my data (JSON)</button><p class="err" role="alert" id="x-err"></p></section>';
    }
    function wireData() {
      $('exp').addEventListener('click', async function () {
        if (PL.demo) { PL.demoNotice('Your data export is for real accounts.'); return; }
        var restore = PL.busy(this, 'Preparing…'); $('x-err').textContent = '';
        try {
          var r = await api('/me/export', { raw: true });
          if (r.status === 401) { session.clear(); PL.toLogin(); return; }
          if (!r.ok) throw new Error('We couldn’t prepare your export. Try again.');
          PL.download(await r.blob(), 'patchlabs-export.json'); PL.toast('Export downloaded', 'ok');
        } catch (x) { $('x-err').textContent = x.message; }
        restore();
      });
    }
    function del() {
      return '<section class="panel danger-zone" id="delete" aria-labelledby="h-del"><h2 id="h-del">Delete account</h2>' +
        '<p class="sec-sub">This deletes your account, your sessions and the one-off checks you started. Workspaces where you are the only member are deleted with their apps, checks and API keys. In shared workspaces your teammates keep everything, and the highest-ranked teammate becomes owner if you were the only one. Decisions you recorded on reports stay, signed as “a former member”.</p>' +
        '<div class="form-row"><div class="field"><label for="d-type">Type <code>DELETE</code> to confirm</label><input id="d-type" class="mono" autocomplete="off" spellcheck="false"></div><button class="btn danger" type="button" id="d-go" disabled>Delete my account</button></div><p class="err" role="alert" id="d-err"></p></section>';
    }
    function wireDelete() {
      $('d-type').addEventListener('input', function () { $('d-go').disabled = this.value.trim() !== 'DELETE'; });
      $('d-go').addEventListener('click', async function () {
        var restore = PL.busy(this, 'Deleting…'); $('d-err').textContent = '';
        try { await PL.call('/me', { method: 'DELETE' }); session.clear(); PL.store.del('pl_ws'); location.href = '/app/login?deleted=1'; }
        catch (x) { restore(); fail('d-err', x); }
      });
    }
  };
})();

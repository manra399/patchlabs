// PatchLabs support tickets: the customer page (/app/support) and the tickets panel on /admin. Needs app.js + app-ui.js.
//   PLSupport.customer()            mounts /app/support (elements #sp-root, #sp-items, #sp-detail, #sp-new, #ws-line)
//   PLSupport.admin(root, call)     mounts the admin panel into root; call(path, opts) is the admin page's token api()
// Links into the page: /app/support?id=<ticket>, /app/support?new=1[&app=<app id>][&category=finding|fix|…]
// User text only ever reaches the page through PL.esc() and is shown with white-space: pre-wrap, never as HTML.
(function () {
  'use strict';
  var PLSupport = window.PLSupport = {};
  var esc = PL.esc, $ = PL.$;
  var CATS = { billing: 'Billing', finding: 'A finding', fix: 'A fix', account: 'Account', bug: 'Bug', other: 'Other' };
  var SUBJECT_MAX = 200, BODY_MAX = 10000;
  // customer view: "open" means it's with us; "waiting on you" is the one that needs them (amber = needs a person)
  var ST = {
    customer: { open: ['t-open', 'Open'], waiting_on_customer: ['pending', 'Waiting on you'], resolved: ['neutral', 'Resolved'], closed: ['plain', 'Closed'] },
    admin: { open: ['pending', 'Open'], waiting_on_customer: ['t-open', 'Waiting on customer'], resolved: ['neutral', 'Resolved'], closed: ['plain', 'Closed'] }
  };
  var pill = function (side, s, t) {
    var m = side === 'admin' && t && t.needs_reply ? ['pending', 'Needs reply'] : ST[side][s] || ['neutral', s];
    return '<span class="pill ' + m[0] + '">' + esc(m[1]) + '</span>';
  };
  var verb = function (side, s) {
    return { open: 'opened the ticket again', resolved: 'marked it resolved', closed: 'closed the ticket',
      waiting_on_customer: side === 'admin' ? 'set it to waiting on the customer' : 'set it to waiting on you' }[s] || ('set the status to ' + s);
  };
  var num = function (n) { return n.toLocaleString('en-GB'); };
  var urgent = function (t) { return t.priority === 'urgent' ? '<span class="tag sp-urgent">urgent</span>' : ''; };

  function thread(msgs, side) {
    return '<ol class="sp-thread">' + msgs.map(function (m) {
      var when = '<time datetime="' + esc(m.created_at) + '" title="' + esc(PL.dateTime(m.created_at)) + '">' + esc(PL.dateTime(m.created_at)) + '</time>';
      if (m.kind === 'status') return '<li class="sp-event"><span><b>' + esc(m.by) + '</b> ' + esc(verb(side, m.body)) + '</span>' + when + '</li>';
      var cls = m.kind === 'note' ? 'note' : m.author;
      var email = side === 'admin' && m.by_email && m.by_email !== m.by ? '<span class="sp-email">' + esc(m.by_email) + '</span>' : '';
      return '<li class="sp-msg ' + cls + '"><div class="sp-meta"><span class="sp-who"><b>' + esc(m.by) + '</b>' + email +
        (m.kind === 'note' ? '<span class="tag">internal note</span>' : '') +
        '</span>' + when + '</div><div class="sp-body">' + esc(m.body) + '</div></li>';
    }).join('') + '</ol>';
  }

  // textarea character counter: "0 / 10,000"
  function counter(ta, out, max) {
    var upd = function () { var n = ta.value.length; out.textContent = num(n) + ' / ' + num(max); out.classList.toggle('over', n > max); };
    ta.addEventListener('input', upd); upd();
  }

  function item(t, side, current) {
    var who = side === 'admin' ? esc(t.workspace_name) + ' · ' + esc(t.created_by_email || t.created_by) : esc(CATS[t.category] || t.category);
    return '<li><a class="sp-item' + (t.id === current ? ' on' : '') + '" href="' + (side === 'admin' ? '/admin?ticket=' : '/app/support?id=') + esc(t.id) + '" data-id="' + esc(t.id) + '"' +
      (t.id === current ? ' aria-current="true"' : '') + '><span class="sp-line1"><span class="sp-num">#' + esc(t.number) + '</span><span class="sp-subj">' + esc(t.subject) + '</span></span>' +
      '<span class="sp-line2">' + pill(side, t.status, t) + urgent(t) + '<span class="sp-sub">' + who + '</span></span>' +
      '<span class="sp-line3">Updated ' + esc(PL.rel(t.updated_at)) + ' · ' + PL.plural(t.message_count || 0, 'message') + (t.app ? ' · <span class="mono">' + esc(t.app.repo) + '</span>' : '') + '</span></a></li>';
  }

  /* =========================================================================================================== */
  /* customer page                                                                                               */
  /* =========================================================================================================== */
  PLSupport.customer = function () {
    var root = $('sp-root'), items = $('sp-items'), detail = $('sp-detail');
    var S = { ws: null, tickets: [], counts: {}, filter: 'active', ticket: null, apps: null, live: null };
    items.innerHTML = PL.skeleton(4);

    PL.boot({ onWorkspace: function (w) { S.ws = w; S.apps = null; go({}, true); loadList(); } })
      .then(function (b) { S.ws = b.ws; header(); route(); loadList(); $('sp-new').disabled = false; })
      .catch(function (e) { PL.errorBox(items, e, function () { location.reload(); }); });

    $('sp-new').addEventListener('click', function () { go({ 'new': '1' }); });
    window.addEventListener('popstate', route);

    function header() {
      $('ws-line').innerHTML = 'Workspace: <b class="ink">' + esc(S.ws.name) + '</b> · everyone in it sees its tickets · we reply within a day';
    }

    // ---- URL state: ?id=… | ?new=1 | nothing ----
    function go(params, replace) {
      var q = new URLSearchParams(params).toString();
      history[replace ? 'replaceState' : 'pushState'](null, '', '/app/support' + (q ? '?' + q : ''));
      route();
    }
    function route() {
      if (S.live) { S.live.stop(); S.live = null; }
      var id = PL.qs('id');
      if (id) { root.dataset.view = 'detail'; openTicket(id); }
      else if (PL.qs('new')) { root.dataset.view = 'detail'; newForm(); }
      else { root.dataset.view = 'list'; S.ticket = null; intro(); }
      renderList();
    }

    // ---- list ----
    async function loadList() {
      try {
        var r = await PL.call('/workspaces/' + encodeURIComponent(S.ws.id) + '/support/tickets');
        S.tickets = r.tickets; S.counts = r.counts; renderList();
      } catch (e) { if (!e.redirecting) PL.errorBox(items, e, loadList); }
    }
    var FILTERS = [['active', 'Active', function (t) { return t.status === 'open' || t.status === 'waiting_on_customer'; }],
      ['done', 'Resolved & closed', function (t) { return t.status === 'resolved' || t.status === 'closed'; }],
      ['all', 'All', function () { return true; }]];
    function renderList() {
      if (!S.ws || !S.counts || S.counts.open === undefined) return;
      var c = S.counts, n = { active: c.open + c.waiting_on_customer, done: c.resolved + c.closed, all: c.open + c.waiting_on_customer + c.resolved + c.closed };
      var f = FILTERS.filter(function (x) { return x[0] === S.filter; })[0];
      var list = S.tickets.filter(f[2]), cur = S.ticket && S.ticket.id;
      var tabs = '<div class="sp-filters" role="group" aria-label="Show tickets">' + FILTERS.map(function (x) {
        return '<button type="button" class="sp-filter" data-f="' + x[0] + '" aria-pressed="' + (x[0] === S.filter) + '">' + x[1] + ' <span class="num">' + n[x[0]] + '</span></button>';
      }).join('') + '</div>';
      var waiting = c.waiting_on_customer ? '<p class="sp-nudge">' + PL.plural(c.waiting_on_customer, 'ticket is', 'tickets are') + ' waiting on you.</p>' : '';
      var body = !n.all ? '<div class="empty small"><p>No tickets yet. When something’s wrong or unclear, raise one and we’ll reply within a day.</p></div>'
        : !list.length ? '<div class="empty small"><p>' + (S.filter === 'active' ? 'Nothing open. Everything you raised has been answered.' : 'No tickets here.') + '</p></div>'
        : '<ul class="sp-items">' + list.map(function (t) { return item(t, 'customer', cur); }).join('') + '</ul>';
      items.innerHTML = tabs + waiting + body;
      items.querySelectorAll('[data-f]').forEach(function (b) { b.onclick = function () { S.filter = b.dataset.f; renderList(); }; });
      items.querySelectorAll('a.sp-item').forEach(function (a) {
        a.addEventListener('click', function (e) { if (e.metaKey || e.ctrlKey || e.shiftKey) return; e.preventDefault(); go({ id: a.dataset.id }); });
      });
    }
    function upsert(t) {
      var s = { id: t.id, number: t.number, subject: t.subject, category: t.category, priority: t.priority, status: t.status, updated_at: t.updated_at,
        message_count: t.message_count, app: t.app, created_by: t.created_by };
      var had = false;
      S.tickets = S.tickets.map(function (x) { if (x.id === t.id) { had = true; return s; } return x; });
      if (!had) S.tickets.unshift(s);
      S.tickets.sort(function (a, b) { return a.updated_at < b.updated_at ? 1 : -1; });
      loadCounts();
    }
    function loadCounts() {
      var c = { open: 0, waiting_on_customer: 0, resolved: 0, closed: 0 };
      S.tickets.forEach(function (t) { c[t.status] = (c[t.status] || 0) + 1; });
      S.counts = c; renderList();
    }

    var back = '<a class="sp-back" href="/app/support" data-back><span aria-hidden="true">←</span> All tickets</a>';
    function wireBack() {
      var b = detail.querySelector('[data-back]');
      if (b) b.addEventListener('click', function (e) { e.preventDefault(); go({}); });
    }

    // ---- empty right-hand pane (wide screens) ----
    function intro() {
      detail.innerHTML = '<div class="panel sp-intro"><p class="lab">How support works</p><h2 class="h3">Ask us anything about your apps, findings, fixes or plan.</h2>' +
        '<ul class="ticks"><li>We reply within a day, by email and on the ticket.</li><li>Everyone in <b class="ink">' + esc(S.ws ? S.ws.name : 'your workspace') + '</b> can see and add to its tickets.</li>' +
        '<li>Mark a ticket <b class="ink">urgent</b> when personal data is exposed right now or you can’t use PatchLabs.</li>' +
        '<li>Never paste keys, passwords or your customers’ data. We never need them.</li></ul>' +
        '<div class="row mt-3"><button class="btn primary" type="button" data-new>New ticket</button><a class="btn ghost" href="mailto:manraj@patchlabs.dev">Email the founder</a></div></div>';
      detail.querySelector('[data-new]').onclick = function () { go({ 'new': '1' }); };
    }

    // ---- new ticket ----
    async function newForm() {
      var app = PL.qs('app') || '', cat = CATS[PL.qs('category')] ? PL.qs('category') : '';
      detail.innerHTML = back + '<form class="panel sp-form" id="nt" novalidate><h2 class="sec-title">New ticket</h2>' +
        '<p class="sec-sub">Everyone in ' + esc(S.ws.name) + ' will see this ticket and our replies. We reply within a day.</p>' +
        '<div class="field"><label for="nt-subject">Subject</label><input id="nt-subject" maxlength="' + SUBJECT_MAX + '" autocomplete="off" placeholder="e.g. The report says profiles leak, but we use an API"></div>' +
        '<div class="sp-two"><div class="field"><label for="nt-cat">What is it about?</label><select id="nt-cat"><option value="">Choose…</option>' +
        Object.keys(CATS).map(function (k) { return '<option value="' + k + '"' + (k === cat ? ' selected' : '') + '>' + CATS[k] + '</option>'; }).join('') + '</select></div>' +
        '<div class="field"><label for="nt-app">App <span class="muted" style="font-weight:400">(optional)</span></label><select id="nt-app"><option value="">No particular app</option></select></div></div>' +
        '<fieldset class="sp-prio"><legend class="label">Priority</legend><label class="check"><input type="radio" name="prio" value="normal" checked> Normal</label>' +
        '<label class="check"><input type="radio" name="prio" value="urgent"> Urgent: data is exposed right now, or PatchLabs is unusable</label></fieldset>' +
        '<div class="field"><label for="nt-msg">Message</label><textarea id="nt-msg" rows="8" maxlength="' + BODY_MAX + '" placeholder="What happened, what you expected, and any check or report link."></textarea>' +
        '<span class="hint sp-hint"><span>Plain text. Don’t paste keys, passwords or customer data.</span><span class="sp-count" id="nt-count"></span></span></div>' +
        '<p class="err" role="alert" id="nt-err"></p><div class="row"><button class="btn primary" type="submit" id="nt-send">Send ticket</button><button class="btn ghost" type="button" data-cancel>Cancel</button></div></form>';
      wireBack();
      counter($('nt-msg'), $('nt-count'), BODY_MAX);
      detail.querySelector('[data-cancel]').onclick = function () { go({}); };
      $('nt-subject').focus();
      $('nt').addEventListener('submit', submit);
      try {
        if (!S.apps) S.apps = (await PL.call('/workspaces/' + encodeURIComponent(S.ws.id) + '/apps')).apps;
        var sel = $('nt-app'); if (!sel) return;
        sel.insertAdjacentHTML('beforeend', S.apps.map(function (a) {
          return '<option value="' + esc(a.id) + '"' + (a.id === app ? ' selected' : '') + '>' + esc(a.repo) + (a.client_label ? ' (' + esc(a.client_label) + ')' : '') + '</option>';
        }).join(''));
      } catch (e) { /* the app list is optional */ }
    }
    async function submit(e) {
      e.preventDefault();
      var err = $('nt-err'), subject = $('nt-subject').value.trim(), message = $('nt-msg').value.trim(), category = $('nt-cat').value;
      err.textContent = '';
      var bad = !subject ? ['nt-subject', 'Add a subject.'] : !category ? ['nt-cat', 'Choose what it’s about.'] : !message ? ['nt-msg', 'Write a message first.']
        : message.length > BODY_MAX ? ['nt-msg', 'Keep the message to 10,000 characters.'] : null;
      if (bad) { err.textContent = bad[1]; $(bad[0]).focus(); return; }
      var body = { subject: subject, category: category, message: message, priority: detail.querySelector('input[name=prio]:checked').value };
      if ($('nt-app').value) body.app_id = $('nt-app').value;
      var restore = PL.busy($('nt-send'), 'Sending…');
      try {
        var t = await PL.call('/workspaces/' + encodeURIComponent(S.ws.id) + '/support/tickets', { method: 'POST', body: body });
        upsert(t); S.filter = 'active';
        PL.toast('Ticket #' + t.number + ' sent. We’ve emailed you a copy.', 'ok');
        S.ticket = t; history.pushState(null, '', '/app/support?id=' + encodeURIComponent(t.id)); renderTicket(); renderList(); watch();
      } catch (x) { restore(); if (!x.redirecting) err.textContent = x.message; }
    }

    // ---- one ticket ----
    async function openTicket(id) {
      if (!S.ticket || S.ticket.id !== id) detail.innerHTML = back + '<div class="panel">' + PL.skeleton(5) + '</div>';
      wireBack();
      try {
        S.ticket = await PL.call('/support/tickets/' + encodeURIComponent(id));
        // links in our emails can point at another of the user's workspaces: follow the ticket there
        if (S.ticket.workspace_id !== S.ws.id) {
          var w = (PL.me.workspaces || []).filter(function (x) { return x.id === S.ticket.workspace_id; })[0];
          if (w) {
            S.ws = w; S.apps = null; PL.store.set('pl_ws', w.id); header(); S.tickets = []; S.counts = {};
            var sel = $('ws-select'); if (sel) sel.value = w.id;
            loadList();
          }
        }
        renderTicket(); renderList(); watch();
      }
      catch (e) {
        if (e.redirecting) return;
        detail.innerHTML = back; wireBack();
        var box = document.createElement('div'); detail.appendChild(box);
        PL.errorBox(box, e.status === 404 ? { message: 'We couldn’t find that ticket in this workspace. If it belongs to another workspace, switch to it above.' } : e,
          e.status === 404 ? null : function () { openTicket(id); });
      }
    }
    // re-read the open ticket every 30 s while the tab is visible, so a reply shows without reloading
    function watch() {
      if (S.live) S.live.stop();
      var id = S.ticket.id;
      S.live = PL.every(async function () {
        if (!S.ticket || S.ticket.id !== id) return;
        var t = await PL.call('/support/tickets/' + encodeURIComponent(id));
        if (t.messages.length !== S.ticket.messages.length || t.status !== S.ticket.status) {
          S.ticket = t; renderTicket(); upsert(t);
        }
      }, 30000);
    }
    // re-renders keep whatever is typed in the reply box for the same ticket (pass clear = true after sending)
    function renderTicket(clear) {
      var t = S.ticket, done = t.status === 'resolved' || t.status === 'closed';
      var box = $('rp-msg'), draft = !clear && box && detail.getAttribute('data-tid') === String(t.id) ? box.value : '';
      // keep the open ticket visible in the list: switch the filter when its status falls outside it
      if (S.filter !== 'all') S.filter = done ? 'done' : 'active';
      var facts = [esc(CATS[t.category] || t.category), 'raised by ' + esc(t.created_by) + ' on ' + esc(PL.date(t.created_at))];
      if (t.app) facts.splice(1, 0, '<a class="mono" href="/app/app?id=' + encodeURIComponent(t.app.id) + '">' + esc(t.app.repo) + '</a>');
      var state = {
        open: 'With us. We reply within a day.',
        waiting_on_customer: 'We’ve replied and are waiting on you. Reply below, or close the ticket if you’re sorted.',
        resolved: 'Resolved. Replying opens it again.',
        closed: 'Closed. Replying opens it again.'
      }[t.status];
      detail.innerHTML = back + '<article class="panel sp-ticket"><header class="sp-head"><p class="sp-kicker"><span class="sp-num">#' + esc(t.number) + '</span>' + pill('customer', t.status) + urgent(t) + '</p>' +
        '<h2 class="sp-title">' + esc(t.subject) + '</h2><p class="sp-facts">' + facts.join(' · ') + '</p></header>' +
        thread(t.messages, 'customer') +
        '<form class="sp-reply" id="rp" novalidate><p class="sp-state' + (t.status === 'waiting_on_customer' ? ' you' : '') + '">' + esc(state) + '</p>' +
        '<label class="sr-only" for="rp-msg">Your reply</label><textarea id="rp-msg" class="input" rows="4" maxlength="' + BODY_MAX + '" placeholder="Write a reply…"></textarea>' +
        '<span class="hint sp-hint"><span>Plain text. Your team sees replies too.</span><span class="sp-count" id="rp-count"></span></span>' +
        '<p class="err" role="alert" id="rp-err"></p><div class="row between"><button class="btn primary" type="submit" id="rp-send">' + (done ? 'Reply and reopen' : 'Send reply') + '</button>' +
        (t.status !== 'closed' ? '<button class="btn secondary" type="button" id="rp-close">Close ticket</button>' : '') + '</div></form></article>';
      detail.setAttribute('data-tid', String(t.id));
      if (draft) $('rp-msg').value = draft;
      wireBack();
      counter($('rp-msg'), $('rp-count'), BODY_MAX);
      $('rp').addEventListener('submit', async function (e) {
        e.preventDefault();
        var msg = $('rp-msg').value.trim(), err = $('rp-err'); err.textContent = '';
        if (!msg) { err.textContent = 'Write a reply first.'; $('rp-msg').focus(); return; }
        var restore = PL.busy($('rp-send'), 'Sending…');
        try {
          S.ticket = await PL.call('/support/tickets/' + encodeURIComponent(t.id) + '/messages', { method: 'POST', body: { body: msg } });
          renderTicket(true); upsert(S.ticket); PL.toast(done ? 'Reply sent; the ticket is open again.' : 'Reply sent.', 'ok');
        } catch (x) { restore(); if (!x.redirecting) err.textContent = x.message; }
      });
      var cl = $('rp-close');
      if (cl) cl.addEventListener('click', async function () {
        var restore = PL.busy(cl, 'Closing…');
        try {
          S.ticket = await PL.call('/support/tickets/' + encodeURIComponent(t.id) + '/close', { method: 'POST' });
          renderTicket(); upsert(S.ticket); PL.toast('Ticket closed. Reply any time to open it again.', 'ok');
        } catch (x) { restore(); if (!x.redirecting) PL.toast(x.message, 'err'); }
      });
    }
  };

  /* =========================================================================================================== */
  /* admin panel                                                                                                 */
  /* =========================================================================================================== */
  PLSupport.admin = function (root, call) {
    var S = { tickets: [], counts: {}, ticket: null, f: { status: 'active', category: '', priority: '', q: '' } };
    var opt = function (v, label, cur) { return '<option value="' + v + '"' + (v === cur ? ' selected' : '') + '>' + label + '</option>'; };
    root.innerHTML = '<form class="sp-afilters" id="spa-f" role="search" aria-label="Filter tickets">' +
      '<div class="field"><label for="spa-st">Status</label><select id="spa-st" class="input">' + opt('active', 'Open + waiting', 'active') + opt('open', 'Open') +
      opt('waiting_on_customer', 'Waiting on customer') + opt('resolved', 'Resolved') + opt('closed', 'Closed') + opt('', 'All') + '</select></div>' +
      '<div class="field"><label for="spa-cat">Category</label><select id="spa-cat" class="input">' + opt('', 'Any') + Object.keys(CATS).map(function (k) { return opt(k, CATS[k]); }).join('') + '</select></div>' +
      '<div class="field"><label for="spa-pr">Priority</label><select id="spa-pr" class="input">' + opt('', 'Any') + opt('urgent', 'Urgent') + opt('normal', 'Normal') + '</select></div>' +
      '<div class="field grow"><label for="spa-q">Search</label><input id="spa-q" class="input" type="search" maxlength="200" placeholder="Subject, email, workspace or #number" autocomplete="off"></div></form>' +
      '<div class="sp-layout admin" data-view="list"><section class="sp-list" aria-label="Tickets"><div id="spa-items" aria-live="polite">' + PL.skeleton(4) + '</div></section>' +
      '<section class="sp-detail" id="spa-detail" aria-live="polite"><div class="empty small"><p>Pick a ticket to read and answer it.</p></div></section></div>';
    var lay = root.querySelector('.sp-layout'), items = root.querySelector('#spa-items'), detail = root.querySelector('#spa-detail');
    var t0 = null;
    root.querySelector('#spa-f').addEventListener('submit', function (e) { e.preventDefault(); load(); });
    ['spa-st', 'spa-cat', 'spa-pr'].forEach(function (id) { root.querySelector('#' + id).addEventListener('change', load); });
    root.querySelector('#spa-q').addEventListener('input', function () { clearTimeout(t0); t0 = setTimeout(load, 300); });

    async function load() {
      var q = new URLSearchParams();
      var st = root.querySelector('#spa-st').value, cat = root.querySelector('#spa-cat').value, pr = root.querySelector('#spa-pr').value, s = root.querySelector('#spa-q').value.trim();
      if (st) q.set('status', st); if (cat) q.set('category', cat); if (pr) q.set('priority', pr); if (s) q.set('q', s);
      try {
        var r = await call('/admin/support/tickets' + (q.toString() ? '?' + q : ''));
        S.tickets = r.tickets; S.counts = r.counts; render();
        if (PLSupport.onCounts) PLSupport.onCounts(r.counts);
      } catch (e) { if (!e.locked) PL.errorBox(items, e, load); }
    }
    function render() {
      var cur = S.ticket && S.ticket.id, c = S.counts;
      items.innerHTML = '<p class="sp-tally small muted">' + num(c.open || 0) + ' open · ' + num(c.waiting_on_customer || 0) + ' waiting · ' + num(c.resolved || 0) + ' resolved · ' + num(c.closed || 0) + ' closed</p>' +
        (S.tickets.length ? '<ul class="sp-items">' + S.tickets.map(function (t) { return item(t, 'admin', cur); }).join('') + '</ul>' : '<div class="empty small"><p>No tickets match.</p></div>');
      items.querySelectorAll('a.sp-item').forEach(function (a) {
        a.addEventListener('click', function (e) { if (e.metaKey || e.ctrlKey || e.shiftKey) return; e.preventDefault(); open(a.dataset.id); });
      });
    }
    async function open(id) {
      lay.dataset.view = 'detail';
      detail.innerHTML = '<div class="panel">' + PL.skeleton(5) + '</div>';
      try {
        S.ticket = await call('/admin/support/tickets/' + encodeURIComponent(id));
        history.replaceState(null, '', '/admin?ticket=' + encodeURIComponent(id));
        show(); render();
      } catch (e) { if (!e.locked) PL.errorBox(detail, e, function () { open(id); }); }
    }
    function refreshRow(t) {
      S.tickets = S.tickets.map(function (x) { return x.id === t.id ? Object.assign({}, x, t) : x; });
      render(); load();
    }
    function show() {
      var t = S.ticket;
      var kv = '<dl class="kv sp-kv"><dt>Workspace</dt><dd>' + esc(t.workspace_name) + ' <span class="tag">' + esc(PL.planName(t.workspace_plan)) + '</span><div class="tiny muted mono">' + esc(t.workspace_id) + '</div></dd>' +
        '<dt>Raised by</dt><dd>' + (t.created_by_email ? '<a href="mailto:' + esc(t.created_by_email) + '">' + esc(t.created_by_email) + '</a>' : esc(t.created_by)) + '</dd>' +
        '<dt>Category</dt><dd>' + esc(CATS[t.category] || t.category) + '</dd>' + (t.app ? '<dt>App</dt><dd class="mono">' + esc(t.app.repo) + '</dd>' : '') +
        '<dt>Opened</dt><dd>' + esc(PL.dateTime(t.created_at)) + '</dd></dl>';
      var acts = '<div class="row sp-acts">' +
        (t.status !== 'resolved' ? '<button class="btn small secondary" type="button" data-st="resolved">Mark resolved</button>' : '') +
        (t.status !== 'closed' ? '<button class="btn small secondary" type="button" data-st="closed">Close</button>' : '') +
        (t.status !== 'open' ? '<button class="btn small secondary" type="button" data-st="open">Reopen</button>' : '') +
        '<button class="btn small secondary" type="button" data-pr="' + (t.priority === 'urgent' ? 'normal' : 'urgent') + '">' + (t.priority === 'urgent' ? 'Make normal priority' : 'Mark urgent') + '</button></div>';
      detail.innerHTML = '<a class="sp-back" href="/admin" data-back><span aria-hidden="true">←</span> All tickets</a><article class="panel sp-ticket"><header class="sp-head">' +
        '<p class="sp-kicker"><span class="sp-num">#' + esc(t.number) + '</span>' + pill('admin', t.status, t) + urgent(t) + '</p>' +
        '<h2 class="sp-title">' + esc(t.subject) + '</h2>' + kv + acts + '</header>' + thread(t.messages, 'admin') +
        '<form class="sp-reply" id="spa-r" novalidate><div class="sp-mode" role="radiogroup" aria-label="Reply or note"><label class="check"><input type="radio" name="mode" value="reply" checked> Reply to customer (emailed)</label>' +
        '<label class="check"><input type="radio" name="mode" value="note"> Internal note (never shown to them)</label></div>' +
        '<label class="sr-only" for="spa-msg">Message</label><textarea id="spa-msg" class="input" rows="5" maxlength="' + BODY_MAX + '" placeholder="Write a reply…"></textarea>' +
        '<span class="hint sp-hint"><span id="spa-hint">Signed as PatchLabs support.</span><span class="sp-count" id="spa-count"></span></span><p class="err" role="alert" id="spa-err"></p>' +
        '<div class="row"><div class="field sp-after" id="spa-after-f"><label for="spa-after">Then set status to</label><select id="spa-after" class="input">' + opt('waiting_on_customer', 'Waiting on customer', 'waiting_on_customer') +
        opt('resolved', 'Resolved') + opt('closed', 'Closed') + opt('open', 'Open') + '</select></div><button class="btn primary" type="submit" id="spa-send">Send reply</button></div></form></article>';
      detail.querySelector('[data-back]').onclick = function (e) { e.preventDefault(); lay.dataset.view = 'list'; S.ticket = null; history.replaceState(null, '', '/admin'); render(); };
      var msg = detail.querySelector('#spa-msg');
      counter(msg, detail.querySelector('#spa-count'), BODY_MAX);
      detail.querySelectorAll('input[name=mode]').forEach(function (r) {
        r.onchange = function () {
          var note = detail.querySelector('input[name=mode]:checked').value === 'note';
          detail.querySelector('#spa-after-f').hidden = note;
          detail.querySelector('#spa-send').textContent = note ? 'Add note' : 'Send reply';
          detail.querySelector('#spa-hint').textContent = note ? 'Only admins see notes. No email is sent.' : 'Signed as PatchLabs support.';
          msg.placeholder = note ? 'Write a note for yourself…' : 'Write a reply…';
          detail.querySelector('.sp-reply').classList.toggle('noting', note);
        };
      });
      detail.querySelector('#spa-r').addEventListener('submit', async function (e) {
        e.preventDefault();
        var text = msg.value.trim(), err = detail.querySelector('#spa-err'), note = detail.querySelector('input[name=mode]:checked').value === 'note';
        err.textContent = '';
        if (!text) { err.textContent = 'Write something first.'; msg.focus(); return; }
        var body = { body: text, internal: note }; if (!note) body.status = detail.querySelector('#spa-after').value;
        var restore = PL.busy(detail.querySelector('#spa-send'), note ? 'Saving…' : 'Sending…');
        try {
          S.ticket = await call('/admin/support/tickets/' + encodeURIComponent(t.id) + '/messages', { method: 'POST', body: body });
          show(); refreshRow(S.ticket); PL.toast(note ? 'Note added' : 'Reply sent to the customer', 'ok');
        } catch (x) { restore(); if (!x.locked) err.textContent = x.message; }
      });
      detail.querySelectorAll('[data-st],[data-pr]').forEach(function (b) {
        b.onclick = async function () {
          var body = b.dataset.st ? { status: b.dataset.st } : { priority: b.dataset.pr }, restore = PL.busy(b, 'Saving…');
          try { S.ticket = await call('/admin/support/tickets/' + encodeURIComponent(t.id), { method: 'PATCH', body: body }); show(); refreshRow(S.ticket); }
          catch (x) { restore(); if (!x.locked) PL.toast(x.message, 'err'); }
        };
      });
    }

    load();
    return { reload: load, open: open };
  };
})();

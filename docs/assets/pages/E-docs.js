// Docs pages only (/docs, /docs/*). Every docs page works without this file; it adds:
//   1. the sidebar collapses on phones        2. docs search ("/" to focus), index at /assets/pages/E-docs-search.json
//   3. hover anchors on headings              4. live tools: [data-tool="try"], [data-tool="receipt"], [data-tool="badge"]
// Uses api(), API and toast() from app.js / site.js.
(function () {
  'use strict';
  var d = document;
  var $ = function (s, el) { return (el || d).querySelector(s); };
  var $$ = function (s, el) { return Array.prototype.slice.call((el || d).querySelectorAll(s)); };
  var esc = function (s) { return String(s == null ? '' : s).replace(/[&<>"']/g, function (c) { return { '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]; }); };

  /* ---- 1. sidebar: closed by default on phones (open without JS) ---- */
  var navDetails = $('.docs-nav details');
  if (navDetails && window.matchMedia('(max-width: 820px)').matches) navDetails.open = false;

  /* ---- 2. search ---- */
  var box = $('.docs-search');
  if (box) {
    var input = $('input', box), list = $('.results', box), index = null, items = [], sel = -1;
    var load = function () {
      if (index) return Promise.resolve(index);
      return fetch('/assets/pages/E-docs-search.json').then(function (r) { return r.json(); }).then(function (j) { index = j; return j; });
    };
    var mark = function (text, terms) {
      var out = esc(text);
      terms.forEach(function (t) { if (t.length > 1) out = out.replace(new RegExp('(' + t.replace(/[.*+?^${}()|[\]\\]/g, '\\$&') + ')', 'ig'), '<mark>$1</mark>'); });
      return out;
    };
    var render = function () {
      var q = input.value.trim().toLowerCase();
      if (!q) { list.hidden = true; input.setAttribute('aria-expanded', 'false'); return; }
      var terms = q.split(/\s+/);
      items = index.map(function (s) {
        var h = (s.h + ' ' + s.p).toLowerCase(), x = s.x.toLowerCase(), score = 0;
        for (var i = 0; i < terms.length; i++) {
          var t = terms[i];
          if (h.indexOf(t) >= 0) score += 10; else if (x.indexOf(t) >= 0) score += 2; else return null;
        }
        if (s.h.toLowerCase().indexOf(q) === 0) score += 8;
        return { s: s, score: score };
      }).filter(Boolean).sort(function (a, b) { return b.score - a.score; }).slice(0, 8);
      sel = -1;
      list.innerHTML = items.length ? items.map(function (it, i) {
        return '<li role="option" id="ds-' + i + '"><a href="' + esc(it.s.u) + '"><b>' + mark(it.s.h, terms) + '</b><span>' + esc(it.s.p) + '</span></a></li>';
      }).join('') : '<li class="none">No matches. Try “webhook”, “receipt” or “verify”.</li>';
      list.hidden = false; input.setAttribute('aria-expanded', 'true');
    };
    var move = function (by) {
      var links = $$('a', list); if (!links.length) return;
      sel = (sel + by + links.length) % links.length;
      links.forEach(function (a, i) { a.setAttribute('aria-selected', String(i === sel)); });
      input.setAttribute('aria-activedescendant', 'ds-' + sel);
      links[sel].scrollIntoView({ block: 'nearest' });
    };
    input.addEventListener('focus', load);
    input.addEventListener('input', function () { load().then(render).catch(function () { list.innerHTML = '<li class="none">Search is unavailable right now.</li>'; list.hidden = false; }); });
    input.addEventListener('keydown', function (e) {
      if (e.key === 'ArrowDown') { e.preventDefault(); move(1); }
      else if (e.key === 'ArrowUp') { e.preventDefault(); move(-1); }
      else if (e.key === 'Enter') { var a = $$('a', list)[sel < 0 ? 0 : sel]; if (a) { e.preventDefault(); location.href = a.href; } }
      else if (e.key === 'Escape') { input.value = ''; list.hidden = true; input.blur(); }
    });
    d.addEventListener('click', function (e) { if (!box.contains(e.target)) list.hidden = true; });
    d.addEventListener('keydown', function (e) {
      var t = e.target.tagName;
      if (e.key === '/' && t !== 'INPUT' && t !== 'TEXTAREA' && t !== 'SELECT' && !e.target.isContentEditable) {
        e.preventDefault();
        if (navDetails && !navDetails.open) navDetails.open = true;
        input.focus();
      }
    });
  }

  /* ---- open a <details> when the URL points at it (FAQ links like /docs/faq#no-migrations) ---- */
  var openTarget = function () {
    var id = decodeURIComponent(location.hash.slice(1)); if (!id) return;
    var t = d.getElementById(id); if (t && t.tagName === 'DETAILS') { t.open = true; t.scrollIntoView(); }
  };
  openTarget(); window.addEventListener('hashchange', openTarget);

  /* ---- 3. heading anchors ---- */
  $$('.docs-main h2[id], .docs-main h3[id]').forEach(function (h) {
    if (h.closest('.doc-tool, .tab-panel, .ep')) return;
    var a = d.createElement('a'); a.className = 'anchor'; a.href = '#' + h.id; a.textContent = '#';
    a.setAttribute('aria-label', 'Link to this section'); h.appendChild(a);
  });

  /* ---- 4a. try-it panels: <div data-tool="try" data-method data-path> with optional textarea[name=body], input[name=param] ---- */
  $$('[data-tool="try"]').forEach(function (el) {
    var btn = $('button[data-send]', el), out = $('.out', el);
    btn.addEventListener('click', async function () {
      var method = el.getAttribute('data-method'), path = el.getAttribute('data-path');
      var p = $('input[name=param]', el);
      if (p) { if (!p.value.trim()) { p.focus(); return; } path = path.replace(/\{[^}]+\}/, encodeURIComponent(p.value.trim())); }
      var ta = $('textarea[name=body]', el), body;
      if (ta) { try { body = JSON.parse(ta.value); } catch (e) { out.innerHTML = '<p class="err" role="alert">That body isn’t valid JSON.</p>'; return; } }
      btn.disabled = true; var label = btn.textContent; btn.innerHTML = '<span class="spin" aria-hidden="true"></span>Sending…';
      var t0 = performance.now();
      try {
        var r = await api(path, { method: method, body: body, raw: true, auth: false });
        var text = await r.text(), shown = text;
        try { shown = JSON.stringify(JSON.parse(text), null, 2); } catch (e) {}
        out.innerHTML = '<p class="result-line"><span class="pill ' + (r.ok ? 'proven' : 'leak') + '">' + r.status + ' ' + esc(r.statusText || '') + '</span><span class="small muted mono">' + esc(method + ' ' + API + path) + ' · ' + Math.round(performance.now() - t0) + ' ms</span></p><pre class="json" tabindex="0">' + esc(shown) + '</pre>';
      } catch (e) {
        out.innerHTML = '<p class="err" role="alert">' + esc(e.message) + '</p>';
      } finally { btn.disabled = false; btn.textContent = label; }
    });
  });

  /* ---- 4b. receipt verifier ---- */
  // Python's json.dumps(obj, sort_keys=True, separators=(",", ":")) with ensure_ascii=True, byte for byte.
  function pyjson(v) {
    if (v === null || v === undefined) return 'null';
    if (v === true) return 'true';
    if (v === false) return 'false';
    if (typeof v === 'number') return Number.isInteger(v) ? String(v) : String(v);
    if (typeof v === 'string') return JSON.stringify(v).replace(/[\u007f-￿]/g, function (c) { return '\\u' + ('0000' + c.charCodeAt(0).toString(16)).slice(-4); });
    if (Array.isArray(v)) return '[' + v.map(pyjson).join(',') + ']';
    return '{' + Object.keys(v).sort().map(function (k) { return pyjson(k) + ':' + pyjson(v[k]); }).join(',') + '}';
  }
  window.plCanonical = pyjson;
  var b64 = function (s) { var bin = atob(s), u = new Uint8Array(bin.length); for (var i = 0; i < bin.length; i++) u[i] = bin.charCodeAt(i); return u; };
  var hex = function (buf) { return Array.prototype.map.call(new Uint8Array(buf), function (x) { return ('0' + x.toString(16)).slice(-2); }).join(''); };

  $$('[data-tool="receipt"]').forEach(function (el) {
    var form = $('form', el), out = $('.out', el);
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      var id = $('[name=check_id]', form).value.trim(), pasted = $('[name=receipt_json]', form).value.trim(), file = $('[name=fix_file]', form).files[0];
      var btn = $('button[type=submit]', form), label = btn.textContent;
      if (!id && !pasted) { out.innerHTML = '<p class="err" role="alert">Enter a check ID, or paste a receipt.</p>'; return; }
      btn.disabled = true; btn.innerHTML = '<span class="spin" aria-hidden="true"></span>Verifying…'; out.innerHTML = '';
      try {
        if (!(window.crypto && crypto.subtle)) throw new Error('This browser can’t run the check. Use the Python script below.');
        var r;
        if (pasted) { try { r = JSON.parse(pasted); } catch (x) { throw new Error('The pasted text isn’t valid JSON.'); } }
        else r = await api('/receipts/' + encodeURIComponent(id), { auth: false });
        if (!r || !r.receipt || !r.signature) throw new Error('That doesn’t look like a PatchLabs receipt: it needs "receipt" and "signature".');
        var k = await api('/.well-known/patchlabs-receipt-key', { auth: false });
        if (r.algorithm && r.algorithm !== 'Ed25519') throw new Error('Unexpected algorithm: ' + r.algorithm);
        var msg = pyjson(r.receipt), ok = false, keyMatch = !r.key_id || r.key_id === k.key_id;
        var key;
        try { key = await crypto.subtle.importKey('raw', b64(k.public_key), { name: 'Ed25519' }, false, ['verify']); }
        catch (x) { throw new Error('This browser doesn’t support Ed25519 signatures yet. Use the Python script below.'); }
        if (keyMatch) ok = await crypto.subtle.verify({ name: 'Ed25519' }, key, b64(r.signature), new TextEncoder().encode(msg));
        var rc = r.receipt, fileLine = '';
        if (file) {
          var got = hex(await crypto.subtle.digest('SHA-256', await file.arrayBuffer()));
          fileLine = '<dt>Your fix file</dt><dd>' + (rc.fix_sha256 && got === rc.fix_sha256 ? '<span class="pill proven">matches the receipt</span>' : '<span class="pill leak">does not match</span>') + ' <code>' + esc(got.slice(0, 16)) + '…</code></dd>';
        }
        var head = ok ? '<p class="result-line"><span class="pill proven">genuine</span><b class="ink">Signed by PatchLabs and unchanged since.</b></p>'
          : !keyMatch ? '<p class="result-line"><span class="pill leak">different key</span><b class="ink">Signed with key ' + esc(r.key_id) + ', not our current key ' + esc(k.key_id) + '.</b></p>'
          : '<p class="result-line"><span class="pill leak">not genuine</span><b class="ink">The signature doesn’t match. Something in this receipt was changed.</b></p>';
        out.innerHTML = head + '<dl class="kv">' +
          '<dt>Repo</dt><dd><code>' + esc(rc.repo) + '</code></dd>' +
          '<dt>Status</dt><dd><code>' + esc(rc.status) + '</code></dd>' +
          '<dt>Tables leaking</dt><dd>' + ((rc.tables_leaking || []).length ? rc.tables_leaking.map(function (t) { return '<code>' + esc(t) + '</code>'; }).join(' ') : 'none') + '</dd>' +
          '<dt>Lab proof passed</dt><dd>' + (rc.lab_proof_passed ? 'yes' : 'no') + '</dd>' +
          '<dt>Finished</dt><dd>' + esc(rc.finished_at) + '</dd>' +
          '<dt>Fix SHA-256</dt><dd><code>' + esc(rc.fix_sha256 || 'no fix') + '</code></dd>' + fileLine +
          '<dt>Decisions, answers</dt><dd>' + (rc.decisions || []).length + ', ' + (rc.answers || []).length + '</dd>' +
          '<dt>Key</dt><dd><code>' + esc(k.key_id) + '</code></dd></dl>' +
          '<details class="acc boxed mt-2"><summary>The exact bytes that were checked</summary><div class="acc-body"><pre class="json" tabindex="0">' + esc(msg) + '</pre></div></details>';
      } catch (x) {
        out.innerHTML = '<p class="err" role="alert">' + esc(x.message) + '</p>';
      } finally { btn.disabled = false; btn.textContent = label; }
    });
  });

  /* ---- 4c. badge builder ---- */
  $$('[data-tool="badge"]').forEach(function (el) {
    var form = $('form', el), out = $('.out', el);
    var UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;
    form.addEventListener('submit', async function (e) {
      e.preventDefault();
      var id = $('[name=app_id]', form).value.trim().toLowerCase();
      if (!UUID.test(id)) { out.innerHTML = '<p class="err" role="alert">An app ID looks like 3f2b9c1e-…: copy it from the app’s page in your dashboard.</p>'; return; }
      var img = 'https://api.patchlabs.dev/badge/' + id + '.svg', page = 'https://patchlabs.dev/proof?app=' + id;
      var md = '[![PatchLabs status](' + img + ')](' + page + ')';
      var html = '<a href="' + page + '"><img src="' + img + '" alt="PatchLabs status" height="20"></a>';
      var status = '';
      try {
        var s = await api('/public/apps/' + id, { auth: false });
        status = '<p class="small mb-0">Public status: <code>' + esc(s.status) + '</code>' + (s.last_checked ? ', last checked ' + esc(String(s.last_checked).slice(0, 10)) : '') + ' · <code>' + esc(s.repo) + '</code></p>';
      } catch (x) {
        status = '<p class="small muted mb-0">' + esc(x.status === 404 ? 'This badge is private, so it shows “private”. Turn on “Public badge” on the app’s page to show its status.' : x.message) + '</p>';
      }
      out.innerHTML = '<div class="badge-preview"><img src="' + esc(API + '/badge/' + id + '.svg') + '" alt="PatchLabs badge preview">' + status + '</div>' +
        '<div class="code"><div class="code-bar"><span class="name">README.md (Markdown)</span><button class="copy" type="button" data-copy-text="' + esc(md) + '">Copy</button></div><pre class="wrap-lines"><code>' + esc(md) + '</code></pre></div>' +
        '<div class="code"><div class="code-bar"><span class="name">HTML</span><button class="copy" type="button" data-copy-text="' + esc(html) + '">Copy</button></div><pre class="wrap-lines"><code>' + esc(html) + '</code></pre></div>';
    });
  });
})();

// PatchLabs site behaviour. Every page works without this file; it only enhances.
// Contents: header + mobile nav, dropdowns, theme toggle, copy buttons, tabs, scroll reveal, scrollspy (.toc, [data-scrollspy]),
// footer status dot, toast(), free-check forms ([data-check-form]), lab replay ([data-replay], optional stage rail),
// mega menu hover + arrow keys (details.dd[data-mega]), live counters ([data-live-stats] reads /stats).
(function () {
  'use strict';
  var d = document, root = d.documentElement;
  var reduce = window.matchMedia && window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var $$ = function (s, el) { return Array.prototype.slice.call((el || d).querySelectorAll(s)); };
  root.classList.remove('no-js'); root.classList.add('js');

  /* ---- toast(message, kind) : kind = 'ok' | 'err' | undefined ---- */
  window.toast = function (msg, kind) {
    var host = d.querySelector('.toast-host');
    if (!host) { host = d.createElement('div'); host.className = 'toast-host'; host.setAttribute('role', 'status'); host.setAttribute('aria-live', 'polite'); d.body.appendChild(host); }
    var t = d.createElement('div'); t.className = 'toast' + (kind ? ' ' + kind : ''); t.textContent = msg; host.appendChild(t);
    setTimeout(function () { t.remove(); }, 3200);
  };

  /* ---- header: border on scroll, mobile menu ---- */
  var header = d.querySelector('.site-header');
  if (header) {
    var onScroll = function () { header.classList.toggle('scrolled', window.scrollY > 8); };
    onScroll(); window.addEventListener('scroll', onScroll, { passive: true });
    var mb = header.querySelector('.menu-btn');
    var setOpen = function (open) {
      header.classList.toggle('open', open); d.body.classList.toggle('nav-open', open);
      if (mb) { mb.setAttribute('aria-expanded', String(open)); mb.setAttribute('aria-label', open ? 'Close menu' : 'Open menu'); }
    };
    if (mb) {
      mb.setAttribute('role', 'button'); mb.setAttribute('aria-expanded', 'false'); mb.setAttribute('aria-controls', 'site-nav');
      mb.addEventListener('click', function (e) { e.preventDefault(); setOpen(!header.classList.contains('open')); });
    }
    d.addEventListener('keydown', function (e) { if (e.key === 'Escape' && header.classList.contains('open')) { setOpen(false); if (mb) mb.focus(); } });
    window.addEventListener('resize', function () { if (window.innerWidth > 980 && header.classList.contains('open')) setOpen(false); });
    $$('.nav a', header).forEach(function (a) { a.addEventListener('click', function () { setOpen(false); }); });
  }

  /* ---- dropdowns (details.dd): one open at a time, close on outside click / Escape ---- */
  var dds = $$('details.dd');
  dds.forEach(function (dd) {
    dd.addEventListener('toggle', function () { if (dd.open) dds.forEach(function (o) { if (o !== dd) o.open = false; }); });
  });
  d.addEventListener('click', function (e) { dds.forEach(function (dd) { if (dd.open && !dd.contains(e.target)) dd.open = false; }); });
  d.addEventListener('keydown', function (e) {
    if (e.key !== 'Escape') return;
    dds.forEach(function (dd) { if (dd.open) { dd.open = false; dd.querySelector('summary').focus(); } });
  });

  /* ---- mega menu: hover opens on wide screens with a fine pointer; ArrowDown from a summary enters the panel ---- */
  var fine = window.matchMedia && window.matchMedia('(hover: hover) and (pointer: fine)');
  $$('details.dd[data-mega]').forEach(function (dd) {
    var sum = dd.querySelector('summary'), t = null;
    var wide = function () { return fine && fine.matches && window.innerWidth > 1080; };
    dd.addEventListener('mouseenter', function () { if (!wide()) return; clearTimeout(t); t = setTimeout(function () { dd.open = true; }, 70); });
    dd.addEventListener('mouseleave', function () { if (!wide()) return; clearTimeout(t); t = setTimeout(function () { dd.open = false; }, 200); });
    var links = function () { return $$('.dd-panel a', dd); };
    sum.addEventListener('keydown', function (e) {
      if (e.key !== 'ArrowDown') return;
      e.preventDefault(); dd.open = true; var l = links(); if (l[0]) l[0].focus();
    });
    dd.addEventListener('keydown', function (e) {
      if (e.key !== 'ArrowDown' && e.key !== 'ArrowUp') return;
      var l = links(), i = l.indexOf(d.activeElement); if (i < 0) return;
      e.preventDefault(); var j = i + (e.key === 'ArrowDown' ? 1 : -1);
      if (j < 0) sum.focus(); else if (l[j]) l[j].focus();
    });
    dd.addEventListener('focusout', function (e) { if (dd.open && e.relatedTarget && !dd.contains(e.relatedTarget) && wide()) dd.open = false; });
  });

  /* ---- theme toggle: [data-theme-toggle]; stored in localStorage "pl_theme" ---- */
  var mq = window.matchMedia ? window.matchMedia('(prefers-color-scheme: dark)') : null;
  var effective = function () { return root.getAttribute('data-theme') || (mq && mq.matches ? 'dark' : 'light'); };
  var label = function () {
    $$('[data-theme-toggle]').forEach(function (b) {
      var dark = effective() === 'dark';
      b.setAttribute('aria-label', dark ? 'Switch to light theme' : 'Switch to dark theme');
      var t = b.querySelector('.t'); if (t) t.textContent = dark ? 'Dark' : 'Light';
    });
  };
  $$('[data-theme-toggle]').forEach(function (b) {
    b.addEventListener('click', function () {
      var next = effective() === 'dark' ? 'light' : 'dark';
      root.setAttribute('data-theme', next);
      try { localStorage.setItem('pl_theme', next); } catch (e) {}
      label();
    });
  });
  if (mq && mq.addEventListener) mq.addEventListener('change', label);
  label();

  /* ---- copy buttons: [data-copy] copies the closest .code/.window pre, or data-copy="#id"; [data-copy-text="literal"] copies a string (data-copy optional) ---- */
  var copyText = function (text) {
    if (navigator.clipboard && window.isSecureContext) return navigator.clipboard.writeText(text);
    return new Promise(function (res, rej) {
      var ta = d.createElement('textarea'); ta.value = text; ta.setAttribute('readonly', ''); ta.style.position = 'fixed'; ta.style.opacity = '0';
      d.body.appendChild(ta); ta.select();
      try { d.execCommand('copy') ? res() : rej(); } catch (e) { rej(e); } finally { ta.remove(); }
    });
  };
  window.copyText = copyText;
  d.addEventListener('click', function (e) {
    var b = e.target.closest && e.target.closest('[data-copy], [data-copy-text]');
    if (!b) return;
    var text = b.getAttribute('data-copy-text');
    if (text == null) {
      var sel = b.getAttribute('data-copy'), src = sel ? d.querySelector(sel) : null;
      if (!src) { var box = b.closest('.code, .window'); src = box && box.querySelector('pre'); }
      text = src ? (src.value != null && src.tagName !== 'PRE' ? src.value : src.innerText) : '';
    }
    var orig = b.getAttribute('data-label') || b.textContent;
    b.setAttribute('data-label', orig);
    copyText(text.replace(/\n$/, '')).then(function () {
      b.textContent = 'Copied'; b.classList.add('done');
      setTimeout(function () { b.textContent = orig; b.classList.remove('done'); }, 1800);
    }, function () { window.toast('Copy failed. Select the text and copy it by hand.', 'err'); });
  });

  /* ---- tabs: .tabs > [role=tablist] > [role=tab][aria-controls] ; panels .tab-panel ---- */
  $$('.tabs').forEach(function (tabs) {
    var list = tabs.querySelector('[role="tablist"]'); if (!list) return;
    var btns = $$('[role="tab"]', list);
    var select = function (btn, focus) {
      btns.forEach(function (b) {
        var on = b === btn, p = d.getElementById(b.getAttribute('aria-controls'));
        b.setAttribute('aria-selected', String(on)); b.tabIndex = on ? 0 : -1;
        if (p) p.hidden = !on;
      });
      if (focus) btn.focus();
    };
    btns.forEach(function (b, i) {
      b.addEventListener('click', function () { select(b); });
      b.addEventListener('keydown', function (e) {
        var j = e.key === 'ArrowRight' ? i + 1 : e.key === 'ArrowLeft' ? i - 1 : e.key === 'Home' ? 0 : e.key === 'End' ? btns.length - 1 : null;
        if (j === null) return; e.preventDefault(); select(btns[(j + btns.length) % btns.length], true);
      });
    });
    select(btns.filter(function (b) { return b.getAttribute('aria-selected') === 'true'; })[0] || btns[0]);
  });

  /* ---- scroll reveal: [data-reveal] -> .in ---- */
  var rv = $$('[data-reveal]');
  if (reduce || !('IntersectionObserver' in window)) rv.forEach(function (el) { el.classList.add('in'); });
  else {
    var io = new IntersectionObserver(function (es) {
      es.forEach(function (e) { if (e.isIntersecting) { e.target.classList.add('in'); io.unobserve(e.target); } });
    }, { rootMargin: '0px 0px -8% 0px', threshold: 0.08 });
    rv.forEach(function (el) { io.observe(el); });
  }

  /* ---- scrollspy: in .toc and any [data-scrollspy] nav, the link to the section in view gets .active + aria-current ---- */
  if ('IntersectionObserver' in window) $$('.toc, [data-scrollspy]').forEach(function (nav) {
    var links = $$('a[href^="#"]', nav), map = {};
    links.forEach(function (a) { var h = d.getElementById(decodeURIComponent(a.getAttribute('href').slice(1))); if (h) map[h.id] = a; });
    var ids = Object.keys(map); if (!ids.length) return;
    var spy = new IntersectionObserver(function (es) {
      es.forEach(function (e) {
        if (!e.isIntersecting || !map[e.target.id]) return;
        links.forEach(function (a) { a.classList.remove('active'); a.removeAttribute('aria-current'); });
        map[e.target.id].classList.add('active'); map[e.target.id].setAttribute('aria-current', 'location');
      });
    }, { rootMargin: '-18% 0px -68% 0px' });
    ids.forEach(function (id) { spy.observe(d.getElementById(id)); });
  });

  /* ---- footer status dot: [data-status] reads /health ---- */
  var st = $$('[data-status]');
  if (st.length) {
    var base = window.API || ((location.hostname === 'localhost' || location.hostname === '127.0.0.1') ? 'http://localhost:8001' : 'https://api.patchlabs.dev');
    var set = function (state, text) {
      st.forEach(function (el) { el.setAttribute('data-state', state); var t = el.querySelector('.status-text'); if (t) t.textContent = text; });
    };
    var go = function () {
      fetch(base + '/health', { cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : Promise.reject(); }).then(function (j) {
        var seen = j.worker_last_seen ? Date.parse(j.worker_last_seen) : 0;
        if (!j.ok) set('down', 'API issue');
        else if (seen && Date.now() - seen < 15 * 60 * 1000) set('ok', 'All systems normal');
        else set('slow', 'Checks may be delayed');
      }).catch(function () { set('down', 'Status unavailable'); });
    };
    ('requestIdleCallback' in window) ? requestIdleCallback(go, { timeout: 2500 }) : setTimeout(go, 1200);
  }

  /* ---- free check forms: form[data-check-form] with inputs name=repo, name=email; error goes in [data-err] ---- */
  $$('form[data-check-form]').forEach(function (f) {
    f.addEventListener('submit', async function (e) {
      if (typeof window.api !== 'function') return; // no API helper: let the browser follow the form's action
      e.preventDefault();
      var btn = f.querySelector('button[type="submit"]'), errEl = f.parentNode.querySelector('[data-err]');
      var label = btn.innerHTML;
      btn.disabled = true; btn.textContent = 'Starting…'; if (errEl) errEl.textContent = '';
      try {
        var r = await window.api('/checks', { method: 'POST', body: { repo: f.repo.value.trim(), email: f.email.value.trim() } });
        location.href = '/check?id=' + encodeURIComponent(r.id);
      } catch (x) {
        if (errEl) errEl.textContent = x.message; else window.toast(x.message, 'err');
        btn.disabled = false; btn.innerHTML = label;
      }
    });
  });

  /* ---- hero lab replay: [data-replay] window; lines .ln (data-wait = ms before the line, data-status/-text update the pill) ---- */
  $$('[data-replay]').forEach(function (el) {
    var lines = $$('.ln', el), btn = el.querySelector('[data-replay-toggle]'), pill = el.querySelector('[data-replay-status]');
    // optional stage rail: data-replay-stages="#id" points at a list of li[data-stage]; lines with data-stage advance it
    var rail = el.getAttribute('data-replay-stages') ? d.querySelector(el.getAttribute('data-replay-stages')) : null;
    var nodes = rail ? $$('[data-stage]', rail) : [];
    var stageTo = function (name) {
      var k = -1; nodes.forEach(function (n, j) { if (n.getAttribute('data-stage') === name) k = j; });
      if (k < 0) return;
      nodes.forEach(function (n, j) { n.classList.toggle('done', j < k); n.classList.toggle('now', j === k); });
    };
    var stagesDone = function () { nodes.forEach(function (n) { n.classList.add('done'); n.classList.remove('now'); }); };
    var stagesReset = function () { nodes.forEach(function (n) { n.classList.remove('done', 'now'); }); };
    var btnText = btn && btn.querySelector('.t');
    var finalPill = pill ? { cls: pill.className, text: pill.textContent } : null;
    if (reduce || !lines.length) { if (btn) btn.hidden = true; return; }
    var i = 0, timer = null, playing = false, started = false;
    var cursor = d.createElement('span'); cursor.className = 'cursor'; cursor.setAttribute('aria-hidden', 'true');
    var setBtn = function (t, icon) { if (btnText) btnText.textContent = t; if (btn) { btn.setAttribute('aria-label', t + ' the lab replay'); btn.setAttribute('data-icon', icon); } };
    var setPill = function (cls, text) { if (pill) { pill.className = cls; pill.textContent = text; } };
    var show = function (ln) {
      ln.classList.remove('off'); ln.appendChild(cursor);
      if (ln.dataset.status) setPill('pill ' + ln.dataset.status, ln.dataset.statusText || ln.dataset.status);
      if (ln.dataset.stage) stageTo(ln.dataset.stage);
    };
    var step = function () {
      if (!playing) return;
      if (i >= lines.length) { playing = false; el.classList.remove('playing'); setBtn('Replay', 'replay'); if (finalPill) setPill(finalPill.cls, finalPill.text); stagesDone(); return; }
      var wait = parseInt(lines[i].dataset.wait || '260', 10);
      timer = setTimeout(function () { show(lines[i]); i++; step(); }, wait);
    };
    var start = function () {
      clearTimeout(timer); started = true; i = 0; playing = true;
      el.classList.add('playing'); lines.forEach(function (l) { l.classList.add('off'); }); stagesReset();
      setPill('pill neutral', 'running'); setBtn('Pause', 'pause'); step();
    };
    if (btn) btn.addEventListener('click', function () {
      if (playing) { playing = false; clearTimeout(timer); setBtn('Play', 'play'); }
      else if (!started || i >= lines.length) start();
      else { playing = true; setBtn('Pause', 'pause'); step(); }
    });
    d.addEventListener('visibilitychange', function () { if (d.hidden && playing) { playing = false; clearTimeout(timer); setBtn('Play', 'play'); } });
    if ('IntersectionObserver' in window) {
      var o = new IntersectionObserver(function (es) { if (es[0].isIntersecting && !started) { o.disconnect(); start(); } }, { threshold: 0.35 });
      o.observe(el);
    } else start();
  });

  /* ---- live counters: [data-live-stats] > [data-k="checks_completed"] .v ; shown only for values above zero ---- */
  $$('[data-live-stats]').forEach(function (box) {
    var base = window.API || ((location.hostname === 'localhost' || location.hostname === '127.0.0.1') ? 'http://localhost:8001' : 'https://api.patchlabs.dev');
    fetch(base + '/stats', { cache: 'no-store' }).then(function (r) { return r.ok ? r.json() : Promise.reject(); }).then(function (j) {
      var any = false;
      $$('[data-k]', box).forEach(function (el) {
        var v = j[el.getAttribute('data-k')];
        if (typeof v === 'number' && v > 0) { any = true; el.hidden = false; var o = el.querySelector('.v'); if (o) o.textContent = v.toLocaleString('en-GB'); }
        else el.hidden = true;
      });
      box.hidden = !any;
    }).catch(function () { box.hidden = true; });
  });
})();

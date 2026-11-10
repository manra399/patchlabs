# PatchLabs design system

Read this before building any page. Everything here already exists in `site/static/assets/style.css` (styles),
`site/static/assets/site.js` (behaviour) and `site/static/assets/app.js` (API helper). Page families add one CSS file
each under `site/static/assets/pages/` (§2.1); don't add more. If a page needs a small one-off, put it in its family's
file; if two families need it, move it to `style.css` with a comment and document it here.

Reference pages: `site/pages/index.html` (marketing, every component in real use) and `site/pages/check.html`
(API-driven page).

## 1. Principles

- **Light-first lab notebook**, full dark mode. Paper background, one ink colour, two signals:
  **red = a stranger can read this**, **green = proven**. Amber is only for "pending / needs a person".
  Never use red or green decoratively.
- **Real artifacts instead of icons**: proof transcripts, SQL diffs, report excerpts, real numbers.
- **Mono for evidence**: JetBrains Mono for every proof line, query, file name, lab label and stat footnote.
  Inter for everything else.
- **Bracketed lab labels** (`[REBUILD]`, `[PROVE]`) as section eyebrows.
- **One meaningful animation per page at most** (the home page has the lab replay). Respect reduced motion.
- **Works without JavaScript.** Numbers are in the HTML. JS only enhances (tabs show all panels without JS, the
  replay shows its finished frame, forms fall back to `mailto:`).
- **No cookies, no third-party analytics.** Fonts from Google Fonts; JS libraries only from cdnjs with an exact version.
- **Accessible**: semantic HTML, one `h1` per page, labelled inputs, visible focus (`:focus-visible` ring), AA contrast
  (`--muted` is the lightest colour allowed for text; `--faint` is decoration only), alt text on every image.

## 2. Page skeletons

Pages live in `site/pages/**.html` and start with a front-matter comment (see `tools/build.py`). Links are
extensionless: `/pricing`, `/docs/api`. Build with `python3 tools/build.py --check`.

### Marketing page

```html
<!--
title: Key scan: exposed keys in code and git history | PatchLabs
description: One sentence for search results, under 160 characters.
layout: marketing
nav: key_scan
-->
<main id="main">
  <section class="sec">
    <div class="wrap">
      <nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">Home</a></li><li><a href="/product/leak-lab">Product</a></li><li aria-current="page">Key scan</li></ol></nav>
      <p class="lab">Key scan</p>
      <h1>A deleted key is still in your git history.</h1>
      <p class="lede">Plain-English subhead. One or two sentences.</p>
      <div class="row mt-3"><a class="btn primary large" href="/#check">Check my app free</a><a class="btn secondary large" href="/sample-report">See a sample report</a></div>
    </div>
  </section>
  <section class="sec band">…</section>
  <section class="sec">…</section>
  <!-- end with the CTA panel, see §4.20 -->
</main>
```

- `<main id="main">` is required (the skip link targets it).
- Sections: `.sec` (112px vertical, 72px on phones), `.sec.tight` (72/52px). Alternate plain sections with
  `.sec.band` (sunken background, top and bottom rules). Two plain sections in a row collapse the gap between them.
  `.band.ink` is an inverted (ink) band: use at most once per page.
- Containers: `.wrap` (1200px), `.wrap.narrow` (760px, long reading), `.wrap.wide` (1360px).
- `nav:` values the header understands: `leak_lab`, `key_scan`, `monitoring`, `badge`, `agencies`, `tools`, `sample`,
  `findings`, `for_lovable`, `for_supabase`, `for_bolt`, `for_replit`, `for_cursor` (Product menu), `how`, `research`,
  `pricing`, `docs`, `leaking`. In the app header: `apps`, `settings`. Any other value (`legal`, `status`, …) marks nothing.
- `head:` is one line, added inside `<head>`; use it for `<meta name="robots" content="noindex">`, JSON-LD, or a
  cdnjs script. Set `sitemap: no` for pages that should not be indexed.

### 2.1 Per-family CSS and JS (`site/static/assets/pages/`)

Load a family file with the page's `head:` line, e.g. `head: <link rel="stylesheet" href="/assets/pages/A-product.css">`.
They build on the tokens and components here and never restyle a shared component globally.

| File | Pages |
|---|---|
| `A-product.css` | `/product/*`, `/how-it-works`, `/agencies`, `/for/*` |
| `B-research.css` | `/research/*`, `/findings/*`, `/leaking-now` |
| `C-commercial.css` | `/pricing`, `/compare/*`, `/changelog`, `/about` |
| `D-trust.css` | `/security`, `/legal/*`, `/status`, `/proof`, `/404` |
| `E-docs.css` + `E-docs.js` | `/docs/*` (search over `E-docs-search.json`, written by the docs generator) |
| `F-tools.css` | `/tools/*`, `/sample-report` |
| `app.css` + `/assets/app-ui.js` | the signed-in app `/app/*`, `/admin`, and the owner tools on `/check` |

`app-ui.js` (needs `app.js`) puts the app helpers on `window.PL`: `PL.boot({onWorkspace})` (sign-in guard, `/me`,
workspace switcher, sign-out), `PL.call()` (an `api()` that sends a 401 to the login page), `PL.esc()`, date helpers,
`PL.pill()` status pills, `PL.modal()` / `PL.confirm()` dialogs and `PL.busy(btn)`. App pages load both:
`head: <link rel="stylesheet" href="/assets/pages/app.css"><script src="/assets/app-ui.js" defer></script>`.

### 2.2 Generated pages

`/for/*`, `/findings/*`, `/docs/*` and `/research/1-in-4` are written by scripts in `tools/gen/` (see its README).
Edit the generator or its sources, rerun it, then build; a hand edit to a generated page is lost on the next run.

### Docs page

```html
<!--
title: REST API | PatchLabs docs
description: …
layout: marketing
nav: docs
-->
<main id="main">
  <div class="wrap wide docs">
    <nav class="docs-nav" aria-label="Docs">
      <h2>Get started</h2>
      <ul><li><a href="/docs">Quickstart</a></li><li><a href="/docs/reports">Reading a report</a></li></ul>
      <h2>Reference</h2>
      <ul><li><a href="/docs/api" aria-current="page">REST API</a></li></ul>
    </nav>
    <article class="docs-main prose">
      <nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/docs">Docs</a></li><li aria-current="page">REST API</li></ol></nav>
      <h1>REST API</h1>
      <h2 id="auth">Authentication</h2>
      <p>…</p>
      <div class="docs-pager"><a href="/docs/webhooks"><span>Previous</span>Webhooks</a><a class="next" href="/docs/cli"><span>Next</span>CLI</a></div>
    </article>
    <aside class="toc" aria-label="On this page">
      <h2>On this page</h2>
      <ul><li><a href="#auth">Authentication</a></li><li class="sub"><a href="#keys">API keys</a></li></ul>
    </aside>
  </div>
</main>
```

The TOC highlights the section in view automatically (site.js scrollspy, §5). Below 1180px the TOC hides; below 820px the sidebar
stacks above the content (wrap its lists in `<details open><summary>Docs menu</summary>…</details>` if long).
Endpoint labels: `<span class="method get">GET</span> <code>/checks/{id}</code>` (`.get .post .delete`; plain
`.method` for PATCH).

### App page (signed in)

```html
<!--
title: Apps | PatchLabs
layout: app
nav: apps
sitemap: no
head: <meta name="robots" content="noindex">
-->
<main id="main" class="app-main">
  <div class="wrap wide">
    <div class="row between"><h1 class="h2">Apps</h1><button class="btn primary" id="add">Add app</button></div>
    <div class="table-wrap mt-3"><table class="table">…</table></div>
  </div>
</main>
<script>
  if (!session.get()) location.href = '/app/login?next=' + encodeURIComponent(location.pathname + location.search);
  api('/me').then(function (me) { /* fill #ws-slot with a workspace <select class="input"> … */ })
    .catch(function (e) { if (e.status === 401) location.href = '/app/login'; else toast(e.message, 'err'); });
  document.getElementById('signout').onclick = async function () {
    try { await api('/auth/logout', { method: 'POST' }); } catch (e) {}
    session.clear(); location.href = '/';
  };
</script>
```

The app header has `<div id="ws-slot"></div>` (empty = hidden) for the workspace switcher and a
`<button id="signout">` the page must wire up (as above).

## 3. Tokens

All colours are CSS custom properties on `:root`, redefined for dark mode under
`@media (prefers-color-scheme: dark)` (when no manual choice) and `:root[data-theme="dark"]`. The toggle stores
`pl_theme` in localStorage; an inline script in `head.html` applies it before paint. Always use tokens, never hex.

| Token | Light | Dark | Use |
|---|---|---|---|
| `--bg` | #fbfaf7 | #0d0f12 | page (paper) |
| `--bg-2` | #f3f1eb | #13161a | bands, code bars, sunken fills |
| `--card` | #ffffff | #171a1f | cards, inputs, tables |
| `--ink` | #15171b | #eef0f2 | headings, primary button, strong text |
| `--text` | #2f343b | #c9cdd3 | body copy |
| `--muted` | #5d636c | #9ba2ac | secondary copy (lightest allowed for text) |
| `--faint` | #8b919a | #6b727c | decoration only |
| `--line` / `--line-2` | #e5e2d9 / #d2cec2 | #252a31 / #343a43 | rules, borders |
| `--red`, `--red-bg`, `--red-line` | #c42b1c | #ff7b6b | **leak**: a stranger can read this |
| `--green`, `--green-bg`, `--green-line` | #17764b | #4cd894 | **proven**, DENIED-as-expected, OK |
| `--amber`, `--amber-bg`, `--amber-line` | #9a5800 | #f3bd5a | pending, needs a person, limits |
| `--term-*` | dark in both themes | | lab windows / transcripts (`--term-bg`, `--term-text`, `--term-dim`, `--term-red`, `--term-green`, `--term-amber`) |

Other tokens: `--sans` (Inter), `--mono` (JetBrains Mono), radii `--r-sm 6px`, `--r 10px`, `--r-lg 16px`,
`--r-xl 22px`; `--shadow`, `--shadow-lg`; `--wrap 1200px`, `--narrow 760px`, `--gutter` (24px, 16px on phones);
`--header-h 64px`.

### Type scale

| Element / class | Size | Notes |
|---|---|---|
| `h1`, `.h1` | clamp(40px, 6.2vw, 76px) | weight 680, tracking -0.038em |
| `.h-xl` | clamp(44px, 7vw, 88px) | rare, hero-only |
| `h2`, `.h2` | clamp(30px, 4vw, 46px) | section titles |
| `.h-md` | clamp(24px, 2.6vw, 30px) | smaller section titles |
| `h3`, `.h3` | 20px | card titles |
| `h4`, `.h4` | 16px | |
| `.lede` | clamp(18px, 1.6vw, 21px) | muted subhead, max 40em |
| body | 16.5px / 1.6 | |
| `.small` 14px, `.tiny` 12.5px, `.mono`, `.num` (tabular figures), `.muted`, `.ink`, `.red`, `.green` | | |

Use sentence case everywhere. Headings use `text-wrap: balance` automatically.

## 4. Components

Every snippet below is copy-paste ready.

### 4.1 Lab label (eyebrow)
```html
<p class="lab">Prove</p>                    <!-- renders [PROVE] -->
<p class="lab red">The 1-in-4 study</p>     <!-- red only for leak topics; .green for proof topics -->
<span class="lab"><span class="n">01</span>Exposed</span>
```

### 4.2 Section head
```html
<div class="sec-head">               <!-- add .center to centre, .split to put a link on the right, .compact for less space below -->
  <p class="lab">How it works</p>
  <h2>From repo to proven fix.</h2>
  <p>One-sentence explanation.</p>
</div>
<div class="sec-head split"><div><p class="lab">…</p><h2>…</h2></div><a class="link-arrow" href="/how-it-works">Full walkthrough</a></div>
```

### 4.3 Buttons and links
```html
<a class="btn primary" href="/#check">Check my app free</a>
<a class="btn secondary" href="/sample-report">See a sample report</a>
<button class="btn ghost" type="button">Cancel</button>
<button class="btn danger" type="button">Delete app</button>
<!-- sizes: .small (34px) .large (52px); .block = full width; disabled: [disabled] or aria-disabled="true" -->
<a class="btn primary">Check my app free <span class="arrow" aria-hidden="true">→</span></a>
<a class="link-arrow" href="/pricing">Full pricing</a>   <!-- bold text link with → -->
```
One primary button per view. The site-wide primary CTA text is **"Check my app free"** → `/#check`.

### 4.4 Inputs
```html
<div class="field">
  <label for="name">Name</label>
  <input id="name" name="name" autocomplete="name">
  <span class="hint">Shown to your team.</span>
</div>
<input class="input mono" …>       <!-- standalone input; .mono for keys, repos, codes -->
<select class="input">…</select>
<label class="check"><input type="checkbox" required> I own this repo or am authorised to test it.</label>
<p class="err" role="alert" id="err"></p>   <!-- hidden while empty -->
<p class="ok-msg">Saved.</p>
```

### 4.5 Paste-a-repo form (the free check)
Any page can include it; `site.js` handles submission (POST `/checks` with repo + email, redirect to `/check?id=…`,
error into the sibling `[data-err]`). Without JS it falls back to an email to the founder, so keep the `action`.
Use unique `id`s per page.
```html
<form class="repo-form" data-check-form action="mailto:manraj@patchlabs.dev?subject=Free%20leak%20check" method="post" enctype="text/plain">
  <div class="in">
    <label class="sr-only" for="repo-x">Public GitHub repo</label>
    <input id="repo-x" name="repo" required autocomplete="off" spellcheck="false" placeholder="github.com/you/your-app">
  </div>
  <div class="in">
    <label class="sr-only" for="email-x">Your email</label>
    <input id="email-x" name="email" type="email" required autocomplete="email" placeholder="you@company.com">
  </div>
  <button class="btn primary" type="submit">Check my app free</button>
</form>
<p class="err" role="alert" data-err></p>
<div class="form-meta"><span>Free for your first app</span><span>Reads your public repo only</span></div>
```
`.repo-form.stacked` puts the repo field on its own row (use in narrow columns). Optional leading icons: an inline
16px `<svg aria-hidden="true">` as the first child of `.in` (see index.html).

### 4.6 Pills / status badges
```html
<span class="pill leak">leaking</span>
<span class="pill proven">proven</span>
<span class="pill pending">in review</span>     <!-- dot pulses -->
<span class="pill neutral">not checked yet</span>
<span class="pill plain">v1.2</span>            <!-- no dot -->
```
Finding severity: `.pill.sev-critical`, `.sev-high` (red), `.sev-medium` (amber), `.sev-low` (muted), text = the
severity word. Map API statuses: `done` → proven ("fix proven"), `no_leaks` → proven ("no leaks found"), `needs_review` → pending,
`queued`/`running`/`awaiting_verification` → pending, `failed` → neutral, open leak → leak.

### 4.7 Cards
```html
<div class="card"><h3>Title</h3><p>Muted body.</p><div class="card-foot"><a class="link-arrow" href="…">More</a></div></div>
<a class="card link" href="/product/key-scan">…</a>   <!-- whole card clickable, lifts on hover -->
<!-- variants: .raised (shadow) .sunk (bg-2) .red-edge .green-edge (3px top rule); <span class="n-big">CORE</span> = mono kicker -->
```
Grids: `.grid.g2 / .g3 / .g4` (collapse to 2 then 1 columns), `.grid.top` aligns items to the top. Two-column
layouts: `.split` (equal), `.split.wide-r` (5:7), `.split.wide-l` (7:5), `.split.top`.

### 4.8 Lab window + proof transcript
The signature visual. Always dark (`--term-*`) in both themes. Tokens: `.ok` / `.deny` (green), `.leak` (red),
`.step` (amber `[STEP]`), `.k` (identity name), `.dim`, `.cmd`, `.add` / `.del` (diff lines), `.redact`, `.done`.
```html
<div class="window">
  <div class="window-bar"><span class="lights" aria-hidden="true"><i></i><i></i><i></i></span><span class="title">lab run · owner/repo</span><button class="copy" type="button" data-copy>Copy</button></div>
<pre class="transcript lines">
<span class="ln"><span class="step">[PROBE]</span>   as <span class="k">anon</span> → 2 rows  <span class="leak">LEAK</span></span>
<span class="ln"><span class="step">[PROVE]</span>   <span class="k">anon</span> → 0 rows  <span class="deny">DENIED</span></span>
<span class="ln"><span class="dim">          </span><span class="k">owner</span> → 1 row   <span class="ok">OK</span></span>
</pre>
  <div class="window-foot"><span class="pill proven">proven</span><span>Real run, 9 Nov 2026</span></div>
</div>
```
With `.lines`, put one `<span class="ln">` per line (whitespace between them is ignored; spaces inside a line are
kept). Without `.lines` it is a normal `<pre>`. `.transcript.light` is a light inline variant for docs.
Keep lines under ~50 characters so they fit a phone. Only show **our demo app** (`manra399/patchlabs-demo-app`)
or clearly synthetic data. Redact emails and phones (`•••••@•••••`).

**Replay** (one per site, used on the home page): add `data-replay` to `.window`, give lines `data-wait="ms"`, add
`<button type="button" data-replay-toggle><span class="t">Pause</span></button>` in the bar and
`<span class="pill proven" data-replay-status>proven</span>` in the foot. Lines with `data-status="leak|proven"`
and `data-status-text` update the pill. The HTML is the complete final frame (no JS / reduced motion shows it as is).

### 4.9 Code block with copy (SQL, diffs, shell)
```html
<div class="code">
  <div class="code-bar"><span class="name">supabase/migrations/…_patchlabs_leak_fix.sql</span><button class="copy" type="button" data-copy>Copy</button></div>
<pre><code><span class="c">-- comment</span>
<span class="del">DROP POLICY "Profiles are viewable by everyone" ON public.profiles;</span>
<span class="add">CREATE POLICY "Users can view own profile" ON public.profiles</span>
<span class="add">  FOR SELECT USING (auth.uid() = user_id);</span></code></pre>
</div>
```
`pre.scroll` caps height at 440px; `pre.wrap-lines` wraps long lines; `.code.dark` for a terminal look.
Highlight spans: `.c` comment, `.kw` keyword, `.s` string, `.add`, `.del`. Escape `<` as `&lt;`.
**Copy buttons**: any `[data-copy]` copies the nearest `.code`/`.window` `<pre>`; `data-copy="#id"` copies an element;
a button with `data-copy-text="literal"` (no `data-copy` needed) copies that string. Hidden without JS (give them class `copy`).

### 4.10 Tables
```html
<div class="table-wrap"><table class="table">
  <thead><tr><th scope="col">Repo</th><th scope="col">Status</th><th scope="col" class="num">Leaks</th></tr></thead>
  <tbody><tr><th scope="row">owner/app</th><td><span class="pill proven">proven</span></td><td class="num">0</td></tr></tbody>
</table></div>
```
`.table.compact` for dense app tables. **Comparison tables**: `table.table.compare`; mark our column `class="us"`
(put it first after the row header so phones see it); cells use `<span class="yes">…</span>`, `.no`, `.part`, plus
`<span class="cell-note">…</span>`. The row header column is sticky on phones. Always add a
"Last checked <date>" line under a comparison and source every competitor fact.

### 4.11 Tabs
```html
<div class="tabs">
  <div role="tablist" aria-label="Install">
    <button role="tab" id="t-cursor" aria-controls="p-cursor" aria-selected="true">Cursor</button>
    <button role="tab" id="t-claude" aria-controls="p-claude" aria-selected="false">Claude Code</button>
  </div>
  <div class="tab-panel" id="p-cursor" role="tabpanel" aria-labelledby="t-cursor"><h3 class="tab-title">Cursor</h3>…</div>
  <div class="tab-panel" id="p-claude" role="tabpanel" aria-labelledby="t-claude"><h3 class="tab-title">Claude Code</h3>…</div>
</div>
```
Arrow keys, Home and End work. Without JS the tab list hides and every panel shows with its `.tab-title`.

### 4.12 Accordion / FAQ
```html
<details class="acc"><summary>Do you touch my live database?</summary><div class="acc-body"><p>No. …</p></div></details>
<details class="acc boxed" open>…</details>   <!-- boxed card style, smaller -->
```

### 4.13 Callouts
```html
<div class="callout note"><p>Neutral information.</p></div>
<div class="callout warn"><p><strong>Rotate this key now.</strong> It is in your git history.</p></div>
<div class="callout limit"><p>What this does not cover. Use for honest limits.</p></div>
<div class="callout ok"><p>Lab proof passed.</p></div>
```
The `[NOTE] [WARN] [LIMIT] [PROVEN]` tag is added by CSS.

### 4.14 Stat strip with footnotes
```html
<div class="stats" style="--cols:4">
  <div class="stat"><b class="num">318</b><span>apps rebuilt<sup class="fn"><a href="#fn1" aria-label="Footnote 1">1</a></sup></span></div>
  <div class="stat red"><b class="num">106</b><span>readable by the wrong people<sup class="fn"><a href="#fn2" aria-label="Footnote 2">2</a></sup></span></div>
  <div class="stat green"><b class="num">18<small>of 20</small></b><span>fixes proven<sup class="fn"><a href="#fn3" aria-label="Footnote 3">3</a></sup></span></div>
</div>
<ol class="footnotes"><li id="fn1">PatchLabs lab study, Nov 2026. …</li>…</ol>
```
`--cols` defaults to 5. Every study number needs a footnote with its sample size and date.

### 4.15 Funnel (bar chart for study numbers)
```html
<div class="funnel" data-reveal>
  <div class="fbar light"><span class="lbl">Apps rebuilt</span><span class="val">318</span><span class="track"><span class="fill" style="--w:100%"></span></span></div>
  <div class="fbar red"><span class="lbl">Readable by the wrong people</span><span class="val">106</span><span class="track"><span class="fill" style="--w:33.3%"></span></span></div>
  <div class="fbar red indent"><span class="lbl">by anyone on the internet</span><span class="val">70</span><span class="track"><span class="fill" style="--w:22%"></span></span></div>
</div>
```
Variants: `.red`, `.green`, `.light`, `.indent` (sub-row). Bars grow in when revealed (motion allowed only).

### 4.16 Steps / timeline
```html
<ol class="steps">
  <li class="done"><h3>Verified</h3><p>…</p><span class="meta">09 Nov 2026, 16:56</span></li>
  <li class="now"><h3>Checking</h3><p>…</p></li>
  <li><h3>Report ready</h3><p>…</p></li>
</ol>
<ul class="progress"><li class="ok">✓ Prove it’s yours</li><li class="on" aria-current="step">Checking</li><li>Report ready</li></ul>
<ol class="pipeline">…7 li steps + <li class="sum">…</li></ol>   <!-- home-page grid of stages, 4 per row -->
```

### 4.17 Breadcrumbs
```html
<nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">Home</a></li><li><a href="/compare">Compare</a></li><li aria-current="page">Aikido</li></ol></nav>
```

### 4.18 Pricing cards
```html
<div class="plans">   <!-- style="--cols:4" for four plans -->
  <div class="plan">
    <h3>Free</h3><p class="for">For one app you built yourself.</p>
    <p class="price"><b>£0</b></p>
    <ul><li>1 app, re-checked monthly</li><li class="off">Team seats</li></ul>
    <a class="btn primary" href="/#check">Check my app free</a>
  </div>
  <div class="plan featured"><span class="badge">Recommended</span>…<p class="fine">Card payments aren’t live yet. We reply within a day.</p></div>
</div>
```

### 4.19 Toast, spinner, panel, key-value list
```js
toast('Saved', 'ok');  toast('That key was revoked', 'err');  toast('Copied');
```
```html
<span class="spin" aria-hidden="true"></span>Checking…
<div class="skeleton" style="height:20px;width:60%"></div>
<div class="panel"><h2>Panel title</h2>…</div>
<dl class="kv"><dt>Plan</dt><dd>Maker</dd><dt>Apps</dt><dd>2 of 3</dd></dl>
<ul class="ticks"><li>Included, with <strong>bold</strong>, <code>code</code> or <a href="#">links</a></li><li class="x">Not included</li><li class="dash">Not yet</li></ul>
<ul class="jump" aria-label="On this page"><li><a href="#probe">Probe <span>01</span></a></li>…</ul>   <!-- pill row of on-page anchors -->
<div class="wordmarks"><a href="/for/lovable">Lovable <span>→</span></a>…</div>   <!-- text wordmarks only, never logos -->
```

### 4.20 Final CTA panel
```html
<section class="sec"><div class="wrap"><div class="cta-panel">
  <p class="lab">Free check</p>
  <h2>Can a stranger read your users table? Find out in minutes.</h2>
  <p class="lede">Paste your public repo. You’ll get the leaks, the fix and the proof on one page.</p>
  <!-- repo form (4.5) -->
  <div class="form-meta"><span>Prefer a person first? <a href="mailto:manraj@patchlabs.dev">Email the founder</a></span></div>
</div></div></section>
```

### 4.21 Scroll reveal
Add `data-reveal` to a block to fade it up when it enters the viewport. Only applied when JS runs and motion is
allowed; use on 3 to 8 blocks per page, never on the hero or on text the user must read first.

### 4.22 Utilities
`[hidden]` always hides (it beats component `display` rules), `.js-only` hides without JS,
`.center`, `.row` (flex, wraps; `.between`, `.center`), `.stack` (16px vertical rhythm), `.mt-0..5`, `.mb-0..4`,
`.maxw-sm` (520px), `.maxw` (680px), `.hide`, `.hide-sm`, `.show-sm`, `.sr-only`, `.divider`, `.prose` (long-form
text: lists, quotes, headings), `.figure` + `figcaption`.

## 5. JavaScript API

Loaded on every page by `head.html`: `app.js` (sync) then `site.js` (defer). Page scripts at the end of `<main>`
can call `api()` and `session` immediately; `toast()` and `copyText()` exist once `site.js` has run (always true
inside event handlers and after any `await`).

```js
api('/checks', { method: 'POST', body: { repo, email } })   // → JSON; throws Error(friendly message), err.status
api('/me')                         // sends Authorization: Bearer <pl_session> automatically when signed in
api('/me', { auth: true })         // throws 401 "Please sign in" without a session (no request made)
api('/v1/…', { headers: { 'X-API-Key': key }, auth: false })
api('/me/export', { raw: true })   // returns the fetch Response (for downloads)
session.get() / session.set(token) / session.clear()     // localStorage "pl_session"
API                                // base URL: http://localhost:8001 on localhost, else https://api.patchlabs.dev
```
A 401 on a signed-in call clears the session. A 404 or 405 with FastAPI's bare "Not Found" (an endpoint the deployed
API doesn't have yet) becomes "This feature isn't available yet. Try again shortly."; our own 404s keep their sentence.

**Scrollspy**: every `.toc` and any element with `data-scrollspy` (e.g. `<nav class="rpt-toc" data-scrollspy>`) gets
`.active` and `aria-current="location"` on the `a[href^="#"]` whose section is in view. Style `.active`; no page script. Escape every API string before putting it in HTML
(see `esc()` in `check.html`), and sanitise Markdown with DOMPurify (`marked` 9.1.6 + `dompurify` 3.1.6 from cdnjs).

## 6. Copy rules

- **Truth only.** Every number comes from `SPEC.md` (or a research file named in your task) and study numbers carry
  their sample size and date: "18 of 20 fixes (n=20, lab study, 9 Nov 2026)". No logos, testimonials, customer counts,
  ratings, certifications, partnerships or unreleased features. Never show a counter at zero.
- **Real numbers** you may use: 500 sampled → 436 run → 318 rebuilt; 106 of 318 (33%) readable by the wrong people: 70 (22%) by
  anyone with the public key, 36 (11%) by anyone who signs up; about 1 in 4 (25–28%) after removing businesses' own
  public contact details. Fixes: 19 of 20 worked first time (5 Nov); 18 of 20 passed the strict lab proof with no
  human (9 Nov, n=20), 15 needed only the smallest model, 2 went to a person; median $0.46 model cost and 3.5 minutes
  per app. Plans: Free £0, Maker £19/month, Agency £99/month (+£8 per extra app), Enterprise custom.
- **Say what happens today.** Fixes are delivered as a downloadable migration and a one-click "commit this file on
  GitHub" link. Automatic pull requests and private repos need the GitHub App: "coming". Paid plans: "Request
  access, we reply within a day" (no card payments yet).
- **Pipeline facts** (say them this way): works from the GitHub repo only; rebuilds the database from
  `supabase/migrations` in a disposable local Postgres with Supabase's roles, auth functions and default grants;
  seeds fake rows; tests as an anonymous visitor (anon key), a signed-in stranger and the owner; never connects to
  the customer's live app or database; scans code and full git history for keys; smallest Claude model first, a
  spend cap per check; ownership proven by committing `patchlabs-verify.txt` with a one-time code.
- **Vocabulary**: leak, proven fix, lab, rebuilt from your migrations, anonymous visitor / signed-in stranger / owner,
  your engineer approves, re-check, who can read what. "RLS" only in engineer-facing sections.
- **Never**: "100% secure", "unhackable", "guaranteed", "military/enterprise-grade", "pentest" (as something we do),
  "certified", "SOC 2", "trusted by", "partner", "official", "integrated with Lovable…" (say "works with apps built
  on …"), "AI-powered", "revolutionary", "next-gen", unsourced industry stats, naming any app from the study.
- **Tone**: calm, specific, plain English, short sentences, British spelling, sentence-case headings. Warm, not
  alarmist. State limits as clearly as features (`.callout.limit`).
- **Contact**: manraj@patchlabs.dev (security reports: same address, subject "Security"). Founder: Manraj Singh
  Dhillon, technical founder, London.
- **Footer line** (already in the partial): "Independent: not affiliated with Lovable, Supabase, Bolt, Replit or Cursor."

## 7. Testing (mandatory for every page)

```sh
python3 tools/build.py --check
python3 tools/e2e/serve.py <port 9400-9700> docs     # background; serves /pricing like GitHub Pages does
node tools/shot.mjs http://127.0.0.1:<port>/your-page .shots/your-page-1440.png 1440 --light
node tools/shot.mjs http://127.0.0.1:<port>/your-page .shots/your-page-390.png 390 --light
node tools/shot.mjs http://127.0.0.1:<port>/your-page .shots/your-page-dark.png 1440 --dark
```
Then look at every screenshot with the Read tool and fix what looks wrong. Notes:
- Keep links in pages extensionless. (`python3 -m http.server` can't serve them; use `serve.py`.)
- On localhost the footer status dot calls `http://localhost:8001/health`; if that local API sends no CORS headers,
  shot.mjs reports one `failed request: net::ERR_FAILED`. That one line is expected locally; anything else is yours.
- This Mac runs in dark mode, so a screenshot without a flag renders dark: pass `--light` or `--dark`. Check both themes.
- Full-page screenshots of very long pages get downscaled when read; crop or check sections if detail matters.

## 8. Page families (all landed 10 Nov 2026)

| Group | Pages |
|---|---|
| Design system (done) | `/` home, `/check`, partials, `style.css`, `site.js`, `app.js`, favicon, OG image, this file |
| A | `/product/leak-lab`, `/product/key-scan`, `/product/monitoring`, `/product/badge`, `/how-it-works`, `/agencies`, `/for/lovable`, `/for/supabase`, `/for/bolt`, `/for/replit`, `/for/cursor` |
| B | `/research/1-in-4`, `/research/methodology`, `/findings`, `/findings/*`, `/leaking-now` |
| C | `/pricing`, `/compare`, `/compare/*` (supabase-security-advisor, lovable-security-scan, aikido, manual-pentest), `/changelog`, `/about` |
| D | `/security`, `/legal/*` (terms, privacy, acceptable-use, dpa, disclosure-policy, cookies), `/status`, `/proof`, `/404`, `/llms.txt`, `/.well-known/security.txt` (static files go in `site/static/`) |
| E | `/docs`, `/docs/*` |
| F | `/tools/*` (rls-check, leak-cost, …), `/sample-report` |
| App | signed-in app `/app/*` (login, dashboard, app detail, settings) and `/admin` |

Every group has landed, so `build.py --check` must report zero broken links.
If you need a new shared component, add it to `style.css` and document it here in the same change.

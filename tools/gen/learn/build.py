#!/usr/bin/env python3
"""Generates the /learn guides: tools/gen/learn/src/<slug>.html (meta, `---`, article body) → site/pages/learn/<slug>.html,
plus the hub site/pages/learn/index.html. Sidebar, byline, TL;DR, table of contents, related findings, CTA and JSON-LD
are built here so every guide has the same shape.

Meta keys (one per line, `key: value`):
  title        <title> text (without the "| PatchLabs" suffix)
  description  meta description, under 160 characters
  h1, lede     heading and the answer-first opening sentence(s)
  topic        one of TOPICS below
  short        one line for the hub card
  tldr         TL;DR bullets separated by " || " (HTML allowed)
  findings     comma-separated finding IDs, e.g. PL-001, PL-002 (also read by tools/gen/findings.py)
  cta          optional: "headers" swaps the bottom repo-check CTA for the free headers check (/tools/headers-check),
               "keys" for the free in-browser key check (/tools/key-check),
               "firebase" for the free in-browser Firebase rules check (/tools/firebase-rules-check)
  checked      optional ISO date the guide's facts were last checked, when newer than UPDATED (e.g. 2026-11-11)
Body: <h2 id="…"> sections (they become the table of contents), <h3> allowed. Use the site's .code / .callout / .table
components. Code blocks: [[CODE name]] … [[/CODE]] is escaped and wrapped for you.
"""
import html, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.environ.get("PL_GEN_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
SRC = os.path.join(HERE, "src")
OUT = os.path.join(REPO, "site", "pages", "learn")
UPDATED, UPDATED_ISO = "10 Nov 2026", "2026-11-10"
AUTHOR = "Manraj Singh Dhillon"

TOPICS = [
    ("supabase", "Supabase database", "Row level security, views, storage and Realtime: who can read what."),
    ("server", "Auth and server code", "Roles, Edge Functions and payment webhooks."),
    ("keys", "Keys and incidents", "Leaked keys, git history and the first hour after a leak."),
    ("launch", "Launch and other stacks", "A pre-launch checklist, security headers, Firebase rules and npm dependencies."),
]
TOPIC_NAME = {k: n for k, n, _ in TOPICS}

sys.path.insert(0, os.path.dirname(HERE))


def esc(s):
    return html.escape(s, quote=False)


def finding_titles():
    """ID → (title, status), from the F list in tools/gen/findings.py (importing it writes nothing)."""
    import findings
    return {f["id"]: (f["title"], f["status"]) for f in findings.F}


def code_blocks(body):
    def rep(m):
        name, text = m.group(1).strip(), m.group(2).strip("\n")
        rows = []
        for line in text.split("\n"):
            s = line.lstrip()
            if s.startswith(("--", "#", "//")):
                rows.append(f'<span class="c">{esc(line)}</span>')
            elif line.startswith("+ "):
                rows.append(f'<span class="add">{esc(line[2:])}</span>')
            elif line.startswith("! "):
                rows.append(f'<span class="del">{esc(line[2:])}</span>')
            else:
                rows.append(esc(line))
        return (f'<div class="code"><div class="code-bar"><span class="name">{esc(name)}</span>'
                f'<button class="copy" type="button" data-copy>Copy</button></div>\n'
                f'<pre class="wrap-lines"><code>' + "\n".join(rows) + '</code></pre></div>')
    return re.sub(r"\[\[CODE ([^\]]*)\]\]\n(.*?)\n\[\[/CODE\]\]", rep, body, flags=re.S)


def parse(path):
    text = open(path).read()
    head, body = text.split("\n---\n", 1)
    meta = {}
    for line in head.strip().splitlines():
        k, v = line.split(":", 1)
        meta[k.strip()] = v.strip()
    return meta, code_blocks(body)


def strip(s):
    s = re.sub(r"<(script|style|svg|pre)\b.*?</\1>", " ", s, flags=re.S)
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s))).strip()


def load():
    guides = []
    for name in sorted(os.listdir(SRC)):
        if name.endswith(".html"):
            meta, body = parse(os.path.join(SRC, name))
            meta["slug"] = name[:-5]
            meta["body"] = body
            words = len(strip(body).split()) + len(re.findall(r"\S+", re.sub(r"<[^>]+>", " ", " ".join(re.findall(r"<pre.*?</pre>", body, flags=re.S))))) // 3
            meta["minutes"] = max(4, round(words / 220))
            guides.append(meta)
    order = [k for k, _, _ in TOPICS]
    guides.sort(key=lambda g: (order.index(g["topic"]), int(g.get("order", 50)), g["slug"]))
    return guides


def sidebar(guides, cur):
    parts = ['<nav class="docs-nav l-nav" aria-label="Guides">', '<details open><summary>All guides</summary>',
             '<h2>Learn</h2><ul><li><a href="/learn"' + (' aria-current="page"' if cur is None else "") + '>All guides</a></li>'
             '<li><a href="/findings">Finding index</a></li></ul>']
    for key, name, _ in TOPICS:
        parts.append(f"<h2>{name}</h2><ul>")
        for g in guides:
            if g["topic"] == key:
                a = ' aria-current="page"' if g["slug"] == cur else ""
                parts.append(f'<li><a href="/learn/{g["slug"]}"{a}>{esc(g.get("navtitle", g["h1"]))}</a></li>')
        parts.append("</ul>")
    parts.append("</details></nav>")
    return "\n".join(parts)


def form(fid, meta_extra):
    return f"""<form class="repo-form" data-check-form action="mailto:manraj@patchlabs.dev?subject=Free%20leak%20check" method="post" enctype="text/plain">
          <div class="in">
            <label class="sr-only" for="repo-{fid}">Public GitHub repo</label>
            <input id="repo-{fid}" name="repo" required autocomplete="off" spellcheck="false" placeholder="github.com/you/your-app">
          </div>
          <div class="in">
            <label class="sr-only" for="email-{fid}">Your email</label>
            <input id="email-{fid}" name="email" type="email" required autocomplete="email" placeholder="you@company.com">
          </div>
          <button class="btn primary" type="submit">Check my app free</button>
        </form>
        <p class="err" role="alert" data-err></p>
        <div class="form-meta">{meta_extra}</div>"""


def headers_form(fid):
    """The free headers check as a plain GET form: /tools/headers-check?url=… runs the check on load."""
    return f"""<form class="repo-form one" action="/tools/headers-check" method="get">
          <div class="in">
            <label class="sr-only" for="url-{fid}">Your site’s address</label>
            <input id="url-{fid}" name="url" type="text" inputmode="url" required autocomplete="url" autocapitalize="off" spellcheck="false" placeholder="https://your-app.com">
          </div>
          <button class="btn primary" type="submit">Check my headers free</button>
        </form>
        <div class="form-meta"><span>Free, no sign-up</span><span>Loads your public home page only</span></div>"""


def page(g, guides, ft):
    heads = re.findall(r'<h2 id="([^"]+)"[^>]*>(.*?)</h2>', g["body"], flags=re.S)
    toc_items = "".join(f'<li><a href="#{i}">{strip(t)}</a></li>' for i, t in heads)
    tldr = "".join(f"<li>{x.strip()}</li>" for x in g["tldr"].split("||"))
    ids = [x.strip() for x in g.get("findings", "").split(",") if x.strip()]
    cards = ""
    for fid in ids:
        title, status = ft.get(fid, (fid, "live"))
        tag = " · coming" if status == "coming" else ""
        cards += (f'<a class="card link" href="/findings/{fid.lower()}"><span class="n-big">{fid}{tag}</span>'
                  f'<h3>{esc(title)}</h3></a>')
    i = [x["slug"] for x in guides].index(g["slug"])
    prev_g = guides[i - 1] if i > 0 else None
    next_g = guides[i + 1] if i + 1 < len(guides) else None
    pager = '<nav class="docs-pager" aria-label="Previous and next guide">'
    pager += (f'<a href="/learn/{prev_g["slug"]}" rel="prev"><span>Previous guide</span>{esc(prev_g["h1"])}</a>' if prev_g
              else '<a href="/learn"><span>Back to</span>All guides</a>')
    if next_g:
        pager += f'<a class="next" href="/learn/{next_g["slug"]}" rel="next"><span>Next guide</span>{esc(next_g["h1"])}</a>'
    pager += "</nav>"
    ld = {"@context": "https://schema.org", "@graph": [
        {"@type": "TechArticle", "headline": g["h1"], "description": g["description"], "datePublished": g.get("checked", UPDATED_ISO),
         "dateModified": g.get("checked", UPDATED_ISO), "author": {"@type": "Person", "name": AUTHOR, "url": "https://patchlabs.dev/about"},
         "publisher": {"@type": "Organization", "name": "PatchLabs", "url": "https://patchlabs.dev"},
         "mainEntityOfPage": f"https://patchlabs.dev/learn/{g['slug']}"},
        {"@type": "BreadcrumbList", "itemListElement": [
            {"@type": "ListItem", "position": 1, "name": "Home", "item": "https://patchlabs.dev/"},
            {"@type": "ListItem", "position": 2, "name": "Learn", "item": "https://patchlabs.dev/learn"},
            {"@type": "ListItem", "position": 3, "name": g["h1"], "item": f"https://patchlabs.dev/learn/{g['slug']}"}]}]}
    faq = re.search(r'<h2 id="faq"[^>]*>.*?</h2>(.*?)(?=<h2 |\Z)', g["body"], flags=re.S)
    if faq:  # an FAQ section of <h3>question</h3><p>answer</p> pairs also becomes FAQPage data, which AI answers quote
        qa = re.findall(r"<h3[^>]*>(.*?)</h3>\s*<p>(.*?)</p>", faq.group(1), flags=re.S)
        if qa:
            ld["@graph"].append({"@type": "FAQPage", "mainEntity": [
                {"@type": "Question", "name": strip(q), "acceptedAnswer": {"@type": "Answer", "text": strip(a)}} for q, a in qa]})
    ld_s = json.dumps(ld, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/")
    related = ""
    if cards:
        related = f"""<h2 id="related-findings" class="l-rel-h">Related findings</h2>
      <p>The checks behind this guide, each with example code, a self-check and the fix.</p>
      <div class="grid g3 not-prose l-rel">{cards}</div>"""
    toc_all = toc_items + ('<li><a href="#related-findings">Related findings</a></li>' if cards else "")
    upd = UPDATED
    if g.get("checked"):
        import datetime
        upd = datetime.date.fromisoformat(g["checked"]).strftime("%-d %b %Y")
    if g.get("cta") == "keys":
        extra_css = ""
        cta = """<div class="f-cta l-cta">
        <p class="lab">Free check</p>
        <h2>Are any of these keys also in your code?</h2>
        <p>Paste code, a <code>.env</code> or your built JavaScript bundle into the free key check. It runs in your browser: no request is sent and nothing is stored. It flags secret keys (AI providers, Stripe, AWS, GitHub, database URLs), tells a Supabase anon key from a service role key, and links to where to rotate each one.</p>
        <p><a class="btn primary" href="/tools/key-check">Open the free key check</a></p>
        <div class="form-meta"><span>Free, no sign-up</span><span>Nothing leaves your browser</span><span><a href="/tools/key-check?sample">See a sample result</a></span></div>
      </div>"""
    elif g.get("cta") == "firebase":
        extra_css = ""
        cta = """<div class="f-cta l-cta">
        <p class="lab">Free check</p>
        <h2>Paste your rules, see what’s open.</h2>
        <p>Paste <code>firestore.rules</code>, <code>storage.rules</code> or <code>database.rules.json</code> into the free Firebase rules check. It runs in your browser: no request is sent and nothing is stored. It flags test-mode dates, catch-all matches, open writes and “any signed-in user” rules, with the line, the fix and a prompt to paste into your AI builder.</p>
        <p><a class="btn primary" href="/tools/firebase-rules-check">Open the free rules check</a></p>
        <div class="form-meta"><span>Free, no sign-up</span><span>Nothing leaves your browser</span><span><a href="/tools/firebase-rules-check?sample">See a sample result</a></span></div>
      </div>"""
    elif g.get("cta") == "headers":
        extra_css = '<link rel="stylesheet" href="/assets/pages/B-findings.css">'
        cta = f"""<div class="f-cta l-cta">
        <p class="lab">Free check</p>
        <h2>Check your site’s headers, free.</h2>
        <p>Type your site’s address. The free headers check loads your public home page once, like any visitor, and grades HTTPS, the certificate, security headers, cookie flags and mixed content, with the fix for each finding.</p>
        {headers_form("l-" + g["slug"][:18])}
      </div>"""
    else:
        extra_css = ""
        cta = f"""<div class="f-cta l-cta">
        <p class="lab">Free check</p>
        <h2>Check your app for this, free.</h2>
        <p>Paste your public repo. PatchLabs rebuilds your database from its migrations, tests it as a visitor, a stranger and the owner, reads the code for keys and risky patterns, and hands you the fix.</p>
        {form("l-" + g["slug"][:18], '<span>Free in early access, fixes included</span><span>Never touches your database</span>')}
      </div>"""
    return f"""<!--
title: {g["title"]} | PatchLabs
description: {g["description"]}
layout: marketing
nav: learn
head: <link rel="stylesheet" href="/assets/pages/E-docs.css"><link rel="stylesheet" href="/assets/pages/G-learn.css">{extra_css}<script type="application/ld+json">{ld_s}</script>
-->
<main id="main">
  <div class="wrap wide docs learn">
    {sidebar(guides, g["slug"])}
    <article class="docs-main prose guide">
      <nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">Home</a></li><li><a href="/learn">Learn</a></li><li aria-current="page">{esc(g.get("navtitle", g["h1"]))}</li></ol></nav>
      <p class="lab">{TOPIC_NAME[g["topic"]]}</p>
      <h1>{esc(g["h1"])}</h1>
      <p class="lede">{g["lede"]}</p>
      <p class="l-byline"><span>By <a href="/about">{AUTHOR}</a>, technical founder</span><span>Checked {upd}</span><span>{g["minutes"]} min read</span></p>
      <div class="l-tldr"><p class="l-tldr-h">TL;DR</p><ul>{tldr}</ul></div>
      <nav class="l-toc" aria-label="In this guide"><p class="l-toc-h">In this guide</p><ol>{toc_all}</ol></nav>
      {g["body"].strip()}
      {related}
      {cta}
      <p class="small muted mt-4">Written by {AUTHOR}. Last checked {upd}. Code samples are synthetic and run against your own project; nothing here names a real app. Spotted a mistake? <a href="mailto:manraj@patchlabs.dev?subject=Guide%3A%20{g["slug"]}">Tell us</a>.</p>
      {pager}
    </article>
    <aside class="toc" aria-label="On this page">
      <h2>On this page</h2>
      <ul>{toc_all}</ul>
    </aside>
  </div>
  <script>if (window.matchMedia('(max-width: 820px)').matches) {{ var dn = document.querySelector('.docs-nav details'); if (dn) dn.open = false; }}</script>
</main>
"""


def hub(guides):
    sections = ""
    for key, name, blurb in TOPICS:
        cards = "".join(
            f'<a class="card link l-card" href="/learn/{g["slug"]}"><span class="n-big">{g["minutes"]} MIN READ</span>'
            f'<h3>{esc(g["h1"])}</h3><p class="small">{esc(g["short"])}</p></a>'
            for g in guides if g["topic"] == key)
        sections += f"""
      <div class="l-topic" id="{key}">
        <div class="l-topic-head"><p class="lab">{name}</p><p class="muted small">{blurb}</p></div>
        <div class="grid g3">{cards}</div>
      </div>"""
    items = [{"@type": "ListItem", "position": n + 1, "url": f"https://patchlabs.dev/learn/{g['slug']}", "name": g["h1"]}
             for n, g in enumerate(guides)]
    ld = json.dumps({"@context": "https://schema.org", "@type": "CollectionPage", "name": "Learn: securing AI-built apps",
                     "url": "https://patchlabs.dev/learn", "mainEntity": {"@type": "ItemList", "itemListElement": items}},
                    ensure_ascii=False, separators=(",", ":"))
    jump = "".join(f'<li><a href="#{k}">{n}</a></li>' for k, n, _ in TOPICS)
    return f"""<!--
title: Security guides for AI-built apps | PatchLabs
description: In-depth, tested guides to securing apps built with AI tools: Supabase RLS, Edge Functions, storage, webhooks, leaked keys, Firebase rules and a pre-launch checklist.
layout: marketing
nav: learn
head: <link rel="stylesheet" href="/assets/pages/G-learn.css"><script type="application/ld+json">{ld}</script>
-->
<main id="main">
  <section class="sec tight l-hero">
    <div class="wrap">
      <nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">Home</a></li><li aria-current="page">Learn</li></ol></nav>
      <p class="lab">Learn</p>
      <h1>Secure the app you built with AI.</h1>
      <p class="lede">{len(guides)} in-depth guides for founders and the engineers who approve their changes. Each one answers a real question, shows code you can run against your own project, and links to the checks behind it. No sign-up.</p>
      <ul class="jump mt-3" aria-label="Topics">{jump}</ul>
    </div>
  </section>

  <section class="sec tight" aria-label="Guides">
    <div class="wrap">{sections}
    </div>
  </section>

  <section class="sec band" aria-labelledby="start-h">
    <div class="wrap split top">
      <div>
        <p class="lab">Where to start</p>
        <h2 id="start-h">Three guides, in this order.</h2>
        <p class="lede">If you have an hour before launch, read these. They cover the problems that expose the most data in apps built with AI tools.</p>
      </div>
      <ol class="l-start">
        <li><a href="/learn/rls-policies-explained"><b>RLS policies explained, with owner and stranger tests</b><span>How to know who can read each table, by testing it.</span></a></li>
        <li><a href="/learn/rotate-leaked-key-git-history"><b>Rotate a leaked key and clean your git history</b><span>Why deleting the key isn't enough, and the order that works.</span></a></li>
        <li><a href="/learn/vibe-coded-app-security-checklist"><b>Pre-launch security checklist for vibe-coded apps</b><span>Everything else, as a list you can work through.</span></a></li>
      </ol>
    </div>
  </section>

  <section class="sec">
    <div class="wrap">
      <div class="cta-panel">
        <p class="lab">Free check</p>
        <h2>Rather have it checked for you?</h2>
        <p class="lede">Paste your public repo. You get every finding, the fix and the proof on one page.</p>
        {form("lh", '<span>Free in early access, fixes included</span><span><a href="/findings">Browse every finding</a></span>')}
      </div>
    </div>
  </section>
</main>
"""


def main():
    guides = load()
    ft = finding_titles()
    os.makedirs(OUT, exist_ok=True)
    for g in guides:
        for fid in [x.strip() for x in g.get("findings", "").split(",") if x.strip()]:
            if fid not in ft:
                sys.exit(f"{g['slug']}: unknown finding {fid}")
        open(os.path.join(OUT, g["slug"] + ".html"), "w").write(page(g, guides, ft))
    open(os.path.join(OUT, "index.html"), "w").write(hub(guides))
    print(f"wrote {len(guides)} guides + hub")


if __name__ == "__main__":
    main()

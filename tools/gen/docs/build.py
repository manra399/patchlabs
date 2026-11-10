#!/usr/bin/env python3
"""Generates PatchLabs docs pages: docs-src/<slug>.html (meta + article body) → site/pages/docs/*.html, with one shared
sidebar, breadcrumbs, prev/next pager, on-page TOC and a search index (site/static/assets/pages/E-docs-search.json)."""
import html, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.environ.get("PL_GEN_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(HERE)))
SRC = os.path.join(HERE, "src")
OUT = os.path.join(REPO, "site/pages/docs")
INDEX = os.path.join(REPO, "site/static/assets/pages/E-docs-search.json")
UPDATED = "10 Nov 2026"

NAV = [
    ("Get started", [("index", "Quickstart"), ("verification", "Proving repo ownership"), ("reading-a-report", "Reading a report"), ("findings", "Findings and product lines"),
                     ("applying-a-fix", "Applying a fix"), ("decisions", "Decisions and questions")]),
    ("Monitor and share", [("monitoring", "Monitoring"), ("badge", "Badge"), ("receipts", "Signed receipts"), ("teams", "Teams and agencies")]),
    ("Build on PatchLabs", [("api", "REST API"), ("webhooks", "Webhooks"), ("github-action", "GitHub Action"), ("mcp", "MCP server")]),
    ("Help", [("faq", "FAQ"), ("glossary", "Glossary")]),
]
ORDER = [s for _, items in NAV for s, _ in items]
LABEL = {s: l for _, items in NAV for s, l in items}


def url(slug):
    return "/docs" if slug == "index" else f"/docs/{slug}"


# real badge SVGs, same drawing code as api/monitor.py svg_badge
def svg_badge(label, message, color):
    label, message = html.escape(label), html.escape(message)
    lw, mw = int(len(label) * 6.6 + 12), int(len(message) * 6.6 + 12)
    return (f'<svg xmlns="http://www.w3.org/2000/svg" width="{lw + mw}" height="20" role="img" aria-label="{label}: {message}">'
            f'<title>{label}: {message}</title><linearGradient id="s{mw}" x2="0" y2="100%"><stop offset="0" stop-color="#bbb" '
            f'stop-opacity=".1"/><stop offset="1" stop-opacity=".1"/></linearGradient><clipPath id="r{mw}"><rect width="{lw + mw}" '
            f'height="20" rx="3" fill="#fff"/></clipPath><g clip-path="url(#r{mw})"><rect width="{lw}" height="20" fill="#1c1917"/>'
            f'<rect x="{lw}" width="{mw}" height="20" fill="{color}"/><rect width="{lw + mw}" height="20" fill="url(#s{mw})"/></g>'
            f'<g fill="#fff" text-anchor="middle" font-family="Verdana,Geneva,DejaVu Sans,sans-serif" font-size="11">'
            f'<text x="{lw / 2:.1f}" y="14">{label}</text><text x="{lw + mw / 2:.1f}" y="14">{message}</text></g></svg>')


BADGES = {"green": ("no known leaks · 9 Nov 2026", "#2ea44f"), "amber": ("fix in progress · 9 Nov 2026", "#dfb317"),
          "grey": ("not checked yet", "#9f9f9f"), "private": ("private", "#9f9f9f")}


def parse(path):
    text = open(path).read()
    head, body = text.split("\n---\n", 1)
    meta = {}
    for line in head.strip().splitlines():
        k, v = line.split(":", 1)
        meta[k.strip()] = v.strip()
    body = re.sub(r"\[\[BADGE (\w+)\]\]", lambda m: svg_badge("PatchLabs", *BADGES[m.group(1)]), body)
    return meta, body


def strip(s):
    s = re.sub(r"<(script|style|svg)\b.*?</\1>", " ", s, flags=re.S)
    s = re.sub(r'<a class="anchor".*?</a>', "", s)
    return html.unescape(re.sub(r"\s+", " ", re.sub(r"<[^>]+>", " ", s))).strip()


def sidebar(cur):
    parts = ['<nav class="docs-nav" aria-label="Docs">',
             '<div class="docs-search" role="search"><svg viewBox="0 0 16 16" aria-hidden="true"><circle cx="7" cy="7" r="4.6" fill="none" stroke="currentColor" stroke-width="1.5"/><path d="M10.5 10.5L14 14" stroke="currentColor" stroke-width="1.5" stroke-linecap="round"/></svg>'
             '<label class="sr-only" for="docs-q">Search the docs</label><input id="docs-q" type="search" placeholder="Search docs" autocomplete="off" spellcheck="false" role="combobox" aria-expanded="false" aria-controls="docs-results" aria-autocomplete="list"><kbd aria-hidden="true">/</kbd>'
             '<ul class="results" id="docs-results" role="listbox" aria-label="Search results" hidden></ul></div>',
             '<details open><summary>Docs menu</summary>']
    for title, items in NAV:
        parts.append(f"<h2>{title}</h2><ul>")
        for s, l in items:
            cur_attr = ' aria-current="page"' if s == cur else ""
            parts.append(f'<li><a href="{url(s)}"{cur_attr}>{l}</a></li>')
        parts.append("</ul>")
    parts.append('<h2>Elsewhere</h2><ul><li><a href="/sample-report">Sample report</a></li><li><a href="/tools/rls-check">Free RLS check</a></li>'
                 '<li><a href="/research/methodology">Methodology</a></li><li><a href="/changelog">Changelog</a></li></ul>')
    parts.append("</details></nav>")
    return "\n".join(parts)


def build_one(slug, meta, body):
    toc_levels = ("h2", "h3") if meta.get("toc") == "h3" else ("h2",)
    heads = re.findall(r'<(h[23]) id="([^"]+)"[^>]*>(.*?)</\1>', body, flags=re.S)
    # don't index headings inside tab panels / tools (they have data-notoc)
    heads = [(lv, i, t) for lv, i, t in heads if f'id="{i}" data-notoc' not in body]
    toc = [f'<li{" class=\"sub\"" if lv == "h3" else ""}><a href="#{i}">{strip(meta.get("toc-" + i, t))}</a></li>'
           for lv, i, t in heads if lv in toc_levels]
    i = ORDER.index(slug)
    prev_s, next_s = (ORDER[i - 1] if i else None), (ORDER[i + 1] if i + 1 < len(ORDER) else None)
    pager = '<nav class="docs-pager" aria-label="Previous and next">'
    if prev_s:
        pager += f'<a href="{url(prev_s)}" rel="prev"><span>Previous</span>{LABEL[prev_s]}</a>'
    if next_s:
        pager += f'<a class="next" href="{url(next_s)}" rel="next"><span>Next</span>{LABEL[next_s]}</a>'
    pager += "</nav>"
    crumbs = ('<nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">Home</a></li>'
              + ('<li aria-current="page">Docs</li>' if slug == "index" else f'<li><a href="/docs">Docs</a></li><li aria-current="page">{LABEL[slug]}</li>')
              + "</ol></nav>")
    title = meta["title"]
    crumb_ld = [{"@type": "ListItem", "position": 1, "name": "Home", "item": "https://patchlabs.dev/"},
                {"@type": "ListItem", "position": 2, "name": "Docs", "item": "https://patchlabs.dev/docs"}]
    if slug != "index":
        crumb_ld.append({"@type": "ListItem", "position": 3, "name": LABEL[slug], "item": f"https://patchlabs.dev{url(slug)}"})
    ld = json.dumps({"@context": "https://schema.org", "@type": "BreadcrumbList", "itemListElement": crumb_ld}, separators=(",", ":"))
    head = (f'<link rel="stylesheet" href="/assets/pages/E-docs.css"><script src="/assets/pages/E-docs.js" defer></script>'
            f'<script type="application/ld+json">{ld}</script>')
    if slug == "faq":
        qa = re.findall(r'<details class="acc"[^>]*><summary>(.*?)</summary><div class="acc-body">(.*?)</div></details>', body, flags=re.S)
        faq = {"@context": "https://schema.org", "@type": "FAQPage", "mainEntity": [
            {"@type": "Question", "name": strip(q), "acceptedAnswer": {"@type": "Answer", "text": strip(a)}} for q, a in qa]}
        head += '<script type="application/ld+json">' + json.dumps(faq, ensure_ascii=False, separators=(",", ":")).replace("</", "<\\/") + "</script>"
    page_title = "PatchLabs docs: find the leak, prove the fix" if slug == "index" else f"{title} | PatchLabs docs"
    mail = f"mailto:manraj@patchlabs.dev?subject=Docs%3A%20{title.replace(' ', '%20')}"
    lede = f'<p class="lede">{meta["lede"]}</p>' if meta.get("lede") else ""
    out = f"""<!--
title: {page_title}
description: {meta['description']}
layout: marketing
nav: docs
head: {head}
-->
<main id="main">
<div class="wrap wide docs">
{sidebar(slug)}
<article class="docs-main prose{' docs-hero' if slug == 'index' else ''}">
{crumbs}
<p class="lab">{meta['lab']}</p>
<h1>{meta['h1']}</h1>
{lede}
{body.strip()}
<div class="docs-meta"><span>Updated {UPDATED}</span><span>Something unclear or wrong? <a href="{mail}">Tell the founder</a></span></div>
{pager}
</article>
<aside class="toc" aria-label="On this page">
<h2>On this page</h2>
<ul>{''.join(toc)}</ul>
</aside>
</div>
</main>
"""
    # search entries: page intro + one per h2/h3 section
    entries = []
    pieces = re.split(r'(<h[23] id="[^"]+"[^>]*>.*?</h[23]>)', body, flags=re.S)
    intro = strip(meta.get("lede", "") + " " + pieces[0])
    entries.append({"p": "Docs › " + LABEL[slug], "h": meta["h1"] if slug != "index" else "Quickstart", "u": url(slug), "x": intro[:300]})
    for j in range(1, len(pieces), 2):
        m = re.match(r'<h[23] id="([^"]+)"[^>]*>(.*?)</h[23]>', pieces[j], flags=re.S)
        entries.append({"p": "Docs › " + LABEL[slug], "h": strip(m.group(2)), "u": f"{url(slug)}#{m.group(1)}",
                        "x": strip(pieces[j + 1] if j + 1 < len(pieces) else "")[:400]})
    for tid, term, dd in re.findall(r'<dt id="([^"]+)"[^>]*>(.*?)</dt>\s*<dd>(.*?)</dd>', body, flags=re.S):
        entries.append({"p": "Docs › " + LABEL[slug], "h": strip(term), "u": f"{url(slug)}#{tid}", "x": strip(dd)[:300]})
    entries = [e for e in entries if len(e["h"]) > 1]
    return out, entries


def main():
    os.makedirs(OUT, exist_ok=True)
    index = []
    only = sys.argv[1:]
    for slug in ORDER:
        p = os.path.join(SRC, slug + ".html")
        if not os.path.exists(p):
            print("missing source:", slug)
            continue
        meta, body = parse(p)
        out, entries = build_one(slug, meta, body)
        index += entries
        if only and slug not in only:
            continue
        dest = os.path.join(OUT, "index.html" if slug == "index" else slug + ".html")
        open(dest, "w").write(out)
    json.dump(index, open(INDEX, "w"), ensure_ascii=False, separators=(",", ":"))
    print(f"wrote {len(ORDER)} pages, {len(index)} search entries")


if __name__ == "__main__":
    main()

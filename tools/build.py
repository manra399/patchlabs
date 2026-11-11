#!/usr/bin/env python3
"""Builds the static site: site/pages/**.html (+ partials) → docs/, which GitHub Pages serves at patchlabs.dev.

Each page starts with a front-matter comment, then its body:

    <!--
    title: Pricing | PatchLabs
    description: One sentence for search results.
    layout: marketing            # marketing (default) | app | bare
    nav: pricing                 # which header link is marked current
    sitemap: yes                 # yes (default for marketing) | no
    head: <script src="/assets/x.js" defer></script>   # optional, one line, added inside <head>
    -->
    <main>…</main>

The layout wraps the body with site/partials/head.html, then header.html + footer.html (marketing) or app-header.html
(app) or nothing (bare). Partials use {{title}}, {{description}}, {{canonical}}, {{head}}, {{nav_<name>}} (expands to
' aria-current="page"' on the current link) and {{year}}. site/static/** is copied to docs/ as is.

    python3 tools/build.py          # build once
    python3 tools/build.py --check  # build, then fail if any internal link points at a missing page or file
"""
import datetime, os, re, shutil, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SITE, OUT = os.path.join(ROOT, "site"), os.path.join(ROOT, "docs")
BASE = "https://patchlabs.dev"


def partial(name):
    return open(os.path.join(SITE, "partials", name)).read()


def front_matter(text):
    m = re.match(r"\s*<!--(.*?)-->\s*", text, re.S)
    meta = {}
    if m:
        for line in m.group(1).strip().splitlines():
            if ":" in line:
                k, v = line.split(":", 1)
                meta[k.strip()] = re.sub(r"\s+#.*$", "", v.strip()) if k.strip() != "head" else v.strip()
        text = text[m.end():]
    return meta, text


def url_for(rel):
    rel = rel.replace(os.sep, "/")
    if rel == "index.html":
        return "/"
    if rel.endswith("/index.html"):
        return "/" + rel[: -len("index.html")]
    return "/" + rel[: -len(".html")]


def render(rel, text):
    meta, body = front_matter(text)
    layout = meta.get("layout", "marketing")
    parts = [partial("head.html")]
    if layout == "marketing":
        parts += [partial("header.html"), body, partial("footer.html")]
    elif layout == "app":
        parts += [partial("app-header.html"), body]
    else:
        parts += [body]
    parts.append("</body>\n</html>\n")
    html = "\n".join(parts)
    values = {"title": meta.get("title", "PatchLabs"), "description": meta.get("description", ""),
              "canonical": BASE + url_for(rel), "head": meta.get("head", ""), "year": str(datetime.date.today().year)}
    # {{svg:name}} inlines site/illustrations/name.svg, so illustrations follow the page theme (light, dark, toggle)
    html = re.sub(r"\{\{svg:([\w-]+)\}\}", lambda m: open(os.path.join(SITE, "illustrations", m.group(1) + ".svg")).read().strip(), html)
    html = re.sub(r"\{\{nav_(\w+)\}\}", lambda m: ' aria-current="page"' if m.group(1) == meta.get("nav") else "", html)
    html = re.sub(r"\{\{(\w+)\}\}", lambda m: values.get(m.group(1), m.group(0)), html)
    in_sitemap = meta.get("sitemap", "yes" if layout == "marketing" else "no") == "yes"
    return html, in_sitemap


def build():
    keep = {"CNAME", ".nojekyll"}
    for name in os.listdir(OUT) if os.path.isdir(OUT) else []:
        if name in keep:
            continue
        p = os.path.join(OUT, name)
        shutil.rmtree(p) if os.path.isdir(p) else os.remove(p)
    os.makedirs(OUT, exist_ok=True)
    static = os.path.join(SITE, "static")
    if os.path.isdir(static):
        shutil.copytree(static, OUT, dirs_exist_ok=True)
    pages, sitemap = os.path.join(SITE, "pages"), []
    for d, _, files in os.walk(pages):
        for f in sorted(files):
            if not f.endswith(".html"):
                continue
            rel = os.path.relpath(os.path.join(d, f), pages)
            html, in_sitemap = render(rel, open(os.path.join(d, f)).read())
            dest = os.path.join(OUT, rel)
            os.makedirs(os.path.dirname(dest), exist_ok=True)
            open(dest, "w").write(html)
            if in_sitemap:
                sitemap.append(BASE + url_for(rel))
    today = datetime.date.today().isoformat()
    open(os.path.join(OUT, "sitemap.xml"), "w").write(
        '<?xml version="1.0" encoding="UTF-8"?>\n<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n'
        + "".join(f"  <url><loc>{u}</loc><lastmod>{today}</lastmod></url>\n" for u in sorted(sitemap)) + "</urlset>\n")
    open(os.path.join(OUT, ".nojekyll"), "w").close()
    return len(sitemap)


def check_links():
    bad = []
    for d, _, files in os.walk(OUT):
        for f in files:
            if not f.endswith(".html"):
                continue
            src = os.path.join(d, f)
            for href in re.findall(r'(?:href|src)="(/[^"#?]*)', open(src).read()):
                if href.startswith("//"):
                    continue
                p = os.path.join(OUT, href.lstrip("/"))
                if not (os.path.exists(p) or os.path.exists(p + ".html") or os.path.exists(os.path.join(p, "index.html"))):
                    bad.append(f"{os.path.relpath(src, OUT)} → {href}")
    return bad


if __name__ == "__main__":
    n = build()
    print(f"built docs/ ({n} pages in the sitemap)")
    if "--check" in sys.argv:
        bad = check_links()
        for b in bad:
            print("broken link:", b)
        sys.exit(1 if bad else 0)

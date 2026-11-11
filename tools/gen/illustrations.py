#!/usr/bin/env python3
"""Illustration set for patchlabs.dev: writes site/illustrations/<name>.svg.

  python3 tools/gen/illustrations.py            # all drawings
  python3 tools/gen/illustrations.py hero-lab   # just some
  PL_GEN_ROOT=<dir> ...                         # write into <dir>/site/illustrations instead

Style: "lab notebook technical drawing". Every drawing is built from the same few hand-placed primitives
(isometric boxes, standing sheets, cylinders, figures, specimen tags, wax seals), so the set reads as one family.
Colours come only from the .ill classes in site/static/assets/style.css section 6b: red only where data leaks,
green only where something is proven or fixed. Small copies are made by scaling coordinates (sd), never with a
scale() transform, so every line stays 1.5px.
"""
import math
import os
import re
import sys

ROOT = os.environ.get("PL_GEN_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "site", "illustrations")
C = 0.8660254  # cos 30


# ------------------------------------------------------------------ primitives
def n(v):
    v = round(float(v), 1)
    if v == 0:
        return "0"
    return str(int(v)) if v == int(v) else str(v)


def esc(s):
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def J(x):
    return "".join(x) if isinstance(x, (list, tuple)) else x


def P(x, y, z=0, o=(0, 0)):
    """True isometric: world x runs right-down at 30 deg, y left-down, z up."""
    return (o[0] + (x - y) * C, o[1] + (x + y) * 0.5 - z)


def pt(p):
    return f"{n(p[0])},{n(p[1])}"


def D(pts, close=True):
    return "M" + " L".join(pt(p) for p in pts) + ("Z" if close else "")


def path(d, cls, extra=""):
    return f'<path class="{cls}" d="{d}"{extra}/>'


def poly(pts, cls, close=True, extra=""):
    return path(D(pts, close), cls, extra)


def segs(pairs, cls):
    return path(" ".join(f"M{pt(a)} L{pt(b)}" for a, b in pairs), cls) if pairs else ""


def circ(cx, cy, r, cls, extra=""):
    return f'<circle class="{cls}" cx="{n(cx)}" cy="{n(cy)}" r="{n(r)}"{extra}/>'


def ell(cx, cy, rx, ry, cls, extra=""):
    return f'<ellipse class="{cls}" cx="{n(cx)}" cy="{n(cy)}" rx="{n(rx)}" ry="{n(ry)}"{extra}/>'


def rect(x, y, w, h, cls, rx=0, extra=""):
    r = f' rx="{n(rx)}"' if rx else ""
    return f'<rect class="{cls}" x="{n(x)}" y="{n(y)}" width="{n(w)}" height="{n(h)}"{r}{extra}/>'


def T(x, y, s, cls="t", size=None, anchor=None, extra=""):
    st = f' style="font-size:{n(size)}px"' if size else ""
    an = f' text-anchor="{anchor}"' if anchor else ""
    return f'<text x="{n(x)}" y="{n(y)}" class="{cls}"{st}{an}{extra}>{esc(s)}</text>'


def g(inner, tf=None, extra=""):
    t = f' transform="{tf}"' if tf else ""
    return f"<g{t}{extra}>{J(inner)}</g>"


def tr(x, y):
    return f"translate({n(x)} {n(y)})"


PLANES = {"xz": ".866 .5 0 1", "yz": ".866 -.5 0 1", "xy": ".866 .5 -.866 .5"}


def plane(k, x, y, inner):
    """Draw flat 2D content (x right, y down) onto an isometric plane whose top-left corner is at screen (x, y)."""
    return g(inner, f"matrix({PLANES[k]} {n(x)} {n(y)})")


def frange(a, b, step):
    out, v = [], a
    while v <= b + 1e-6:
        out.append(v)
        v += step
    return out


ARITY = {"M": 2, "L": 2, "T": 2, "H": 1, "V": 1, "C": 6, "S": 4, "Q": 4, "A": 7}


def sd(d, s=1.0, dx=0.0, dy=0.0):
    """Scale and shift path data written with absolute commands."""
    toks = re.findall(r"[A-Za-z]|-?(?:\d+\.?\d*|\.\d+)", d)
    out, cmd, i = [], None, 0
    while i < len(toks):
        t = toks[i]
        if t.isalpha():
            cmd = t
            out.append(t)
            i += 1
            continue
        U = cmd.upper()
        k = ARITY[U]
        v = [float(x) for x in toks[i:i + k]]
        i += k
        ox, oy = (0, 0) if cmd.islower() else (dx, dy)
        dx_, dy_ = dx, dy
        dx, dy = ox, oy
        if U == "H":
            v = [v[0] * s + dx]
        elif U == "V":
            v = [v[0] * s + dy]
        elif U == "A":
            v = [v[0] * s, v[1] * s, v[2], v[3], v[4], v[5] * s + dx, v[6] * s + dy]
        else:
            v = [x * s + (dx if j % 2 == 0 else dy) for j, x in enumerate(v)]
        dx, dy = dx_, dy_
        out.append(" ".join(n(x) for x in v))
    s_ = ""
    for tok in out:
        s_ += tok if tok.isalpha() else tok + " "
    return s_.strip().replace(" Z", "Z")


# ------------------------------------------------------------------ shared objects
def iso_box(w, d, h, o=(0, 0), top="sf", left="sf", right="sk", hatch=6):
    """Solid box; o is the screen point of its back-bottom corner. Right face is the shadow side (hatched)."""
    A = lambda x, y, z: P(x, y, z, o)
    out = [poly([A(0, 0, h), A(w, 0, h), A(w, d, h), A(0, d, h)], top),
           poly([A(0, d, 0), A(w, d, 0), A(w, d, h), A(0, d, h)], left),
           poly([A(w, 0, 0), A(w, d, 0), A(w, d, h), A(w, 0, h)], right)]
    if hatch and h > 5:
        out.append(segs([(A(w, y, 1.5), A(w, y, h - 1.5)) for y in frange(hatch, d - hatch / 2, hatch)], "h"))
    return J(out)


def glass_box(w, d, h, o, content=""):
    """Glass sandbox: tinted floor and back walls, hidden edges dashed, then content, then the glass front."""
    A = lambda x, y, z: P(x, y, z, o)
    back = [poly([A(0, 0, 0), A(w, 0, 0), A(w, d, 0), A(0, d, 0)], "bl"),
            poly([A(0, 0, 0), A(0, d, 0), A(0, d, h), A(0, 0, h)], "bl"),
            poly([A(0, 0, 0), A(w, 0, 0), A(w, 0, h), A(0, 0, h)], "bl"),
            segs([(A(0, 0, 0), A(w, 0, 0)), (A(0, 0, 0), A(0, d, 0)), (A(0, 0, 0), A(0, 0, h))], "s dash")]
    front = [poly([A(0, 0, h), A(w, 0, h), A(w, d, h), A(0, d, h)], "glass"),
             poly([A(0, d, 0), A(w, d, 0), A(w, d, h), A(0, d, h)], "glass"),
             poly([A(w, 0, 0), A(w, d, 0), A(w, d, h), A(w, 0, h)], "glass"),
             segs([(A(w, y, 2), A(w, y, h - 2)) for y in frange(9, d - 5, 9)], "hs"),
             # glints on the lit face
             segs([(A(w * .1, d, h * .42), A(w * .3, d, h * .9)), (A(w * .2, d, h * .38), A(w * .27, d, h * .58))], "glint")]
    return J(back) + J(content) + J(front)


def cylinder(cx, cy, r, h, body="sf", top="bls", bands=(1 / 3, 2 / 3), hatch=True):
    """Database: vertical cylinder; (cx, cy) is the screen centre of its base."""
    rx, ry = r * 1.2247, r * 0.7071
    o = [path(f"M{n(-rx)} {n(-h)} L{n(-rx)} 0 A{n(rx)} {n(ry)} 0 0 0 {n(rx)} 0 L{n(rx)} {n(-h)} "
              f"A{n(rx)} {n(ry)} 0 0 1 {n(-rx)} {n(-h)}Z", body)]
    if hatch:
        pairs = []
        for x in frange(rx * .34, rx * .96, max(3.5, rx / 12)):
            yb = ry * math.sqrt(max(0, 1 - (x / rx) ** 2))
            pairs.append(((x, -h + yb + 1.5), (x, yb - 1.5)))
        o.append(segs(pairs, "h"))
    for b in bands:
        y = -h * b
        o.append(path(f"M{n(-rx)} {n(y)} A{n(rx)} {n(ry)} 0 0 0 {n(rx)} {n(y)}", "s"))
    o.append(ell(0, -h, rx, ry, top))
    return g(o, tr(cx, cy))


def sheet(x, y, w, h, inner="", k="xz", fold=12, cls="sf", zig=0):
    """A standing sheet of paper on an isometric plane; inner is flat page content (0..w, 0..h)."""
    if zig:
        nz = max(2, int(round(w / zig)))
        st = w / nz
        bottom = "".join(f"L{n(w - st * (i + .5))} {n(h - 5)} L{n(w - st * (i + 1))} {n(h)} " for i in range(nz))
        d = f"M0 0 H{n(w - fold)} L{n(w)} {n(fold)} V{n(h)} {bottom}Z"
    else:
        d = f"M0 0 H{n(w - fold)} L{n(w)} {n(fold)} V{n(h)} H0Z"
    parts = [path(d, cls)]
    if fold:
        parts.append(path(f"M{n(w - fold)} 0 V{n(fold)} H{n(w)}Z", "sk"))
    parts.append(J(inner))
    return plane(k, x, y, parts)


def code(x, y, rows, gap=10.5):
    """Code lines: an ink keyword then a lighter run. rows = [(indent, keyword, rest)]."""
    ink, light = [], []
    for i, (ind, kw, rest) in enumerate(rows):
        yy = y + i * gap
        if kw:
            ink.append(((x + ind, yy), (x + ind + kw, yy)))
        if rest:
            a = x + ind + (kw + 4 if kw else 0)
            light.append(((a, yy), (a + rest, yy)))
    return segs(ink, "s") + segs(light, "lt")


def tag(x, y, rows, w, size=13):
    """Specimen tag: clipped-corner card with a string hole and mono rows [(text, cls)]."""
    lh = size + 5
    h = 14 + lh * len(rows)
    d = f"M{n(x + 9)} {n(y)} H{n(x + w)} V{n(y + h)} H{n(x + 9)} L{n(x)} {n(y + h - 9)} V{n(y + 9)}Z"
    o = [path(d, "sf"), circ(x + 9.5, y + h / 2, 2.6, "sk")]
    for i, (s, cls) in enumerate(rows):
        o.append(T(x + 20, y + 7 + size + lh * i, s, cls, size))
    return J(o)


def ground(x, y, w, h, k="xz", ticks=7):
    """Engineering-drawing ground line with hatch ticks under a standing sheet whose top-left is (x, y)."""
    a, b = (x - 6, y + h + 4 - 3), (x + C * w + 6, y + h + .5 * w + 4 + 3)
    L = math.hypot(b[0] - a[0], b[1] - a[1])
    ux, uy = (b[0] - a[0]) / L, (b[1] - a[1]) / L
    t = [((a[0] + ux * d, a[1] + uy * d), (a[0] + ux * d - 5, a[1] + uy * d + 6)) for d in frange(4, L - 2, ticks)]
    return segs([(a, b)], "s") + segs(t, "h")


def head(tip, frm, cls="bo", L=9, spread=26):
    a = math.atan2(tip[1] - frm[1], tip[0] - frm[0])
    sp = math.radians(spread)
    p1 = (tip[0] - L * math.cos(a - sp), tip[1] - L * math.sin(a - sp))
    p2 = (tip[0] - L * math.cos(a + sp), tip[1] - L * math.sin(a + sp))
    return path(f"M{pt(p1)} L{pt(tip)} L{pt(p2)}", cls)


def arrow(p0, c1, c2, p1, cls="bo", hcls="bo", L=9):
    return path(f"M{pt(p0)} C{pt(c1)} {pt(c2)} {pt(p1)}", cls) + head(p1, c2, hcls, L)


def drop(x, y, s=1.0):
    return path(sd("M0 -6.5 C2.6 -2.8 4.2 -0.6 4.2 1.8 A4.2 4.2 0 0 1 -4.2 1.8 C-4.2 -0.6 -2.6 -2.8 0 -6.5Z", s, x, y), "rf")


def seal(cx, cy, r, lobes=16, check=True):
    """Wax-seal stamp: scalloped green disc, inner ring, check. Green = proven."""
    d = ""
    for i in range(lobes):
        a0, a1 = 2 * math.pi * i / lobes, 2 * math.pi * (i + 1) / lobes
        am = (a0 + a1) / 2
        p0 = (cx + r * .9 * math.cos(a0), cy + r * .9 * math.sin(a0))
        c_ = (cx + r * 1.07 * math.cos(am), cy + r * 1.07 * math.sin(am))
        p1 = (cx + r * .9 * math.cos(a1), cy + r * .9 * math.sin(a1))
        d += (f"M{pt(p0)}" if i == 0 else "") + f" Q{pt(c_)} {pt(p1)}"
    o = [path(d + "Z", "gfs"), circ(cx, cy, r * .7, "ws")]
    if check:
        o.append(path(f"M{pt((cx - r * .3, cy + r * .02))} L{pt((cx - r * .07, cy + r * .25))} "
                      f"L{pt((cx + r * .33, cy - r * .22))}", "ws2"))
    return J(o)


def num(cx, cy, k, r=13):
    return circ(cx, cy, r, "bs") + T(cx, cy + 4.5, f"{k:02d}" if isinstance(k, int) else k, "tw", 12, "middle")


# ------------------------------------------------------------------ people
COAT = "M-7 -71 C-14 -71 -19 -68 -20 -61 L-22 -29 Q0 -25 22 -29 L20 -61 C19 -68 14 -71 7 -71Z"
LEGS = "M-10 -31 L-9.5 -4 L-2.5 -4 L-1 -29Z M1 -29 L2.5 -4 L9.5 -4 L10 -31Z"
ARM_L = "M-17 -67 C-23 -63 -25 -52 -25 -38 L-19.5 -37 C-19.5 -48 -18 -56 -15 -60Z"
ARM_R = "M17 -67 C23 -63 25 -52 25 -38 L19.5 -37 C19.5 -48 18 -56 15 -60Z"
ARM_LT = "M-17 -67 C-22 -62 -22 -52 -18.5 -44 L-13 -45.5 C-15 -52 -15 -57 -14 -60Z"
ARM_RT = "M17 -67 C22 -62 22 -52 18.5 -44 L13 -45.5 C15 -52 15 -57 14 -60Z"
ARM_R_FWD = "M16 -67 C22 -65 27 -58 28.5 -51 L23.5 -48.5 C22 -54 19 -58 14 -60Z"
ARM_R_UP = "M15 -67 C19.5 -67.5 21.5 -71 21.5 -76 L16.5 -76.5 C16.5 -73 15 -71.5 12 -70.5Z"
ARM_L_OUT = "M-15 -67 C-22 -67 -29 -65 -33 -62.5 L-31 -58.5 C-27 -60.5 -21 -61.5 -15 -61Z"
HAIR = {
    "stranger": "M-11.2 -87 C-12 -97 -5 -100 1 -99.5 C7 -99 11.5 -95 11.2 -87 C9 -91 5 -92.5 1 -91.5 C-3 -90.5 -7 -90 -11.2 -87Z",
    "owner": "M-11.2 -86 C-12.5 -95 -6 -100.5 .5 -100 C7 -99.5 12 -95 11.2 -85 C9.5 -89.5 5.5 -92 0 -92 C-3 -89 -7 -87.5 -11.2 -86Z",
    "engineer": "M-11.2 -87 C-11.5 -96 -5 -99.5 0 -99.5 C5 -99.5 11.5 -96 11.2 -87 C8 -90.5 -8 -90.5 -11.2 -87Z",
    "founder": "M-11.4 -84 C-13 -96 -6 -101 1 -100.5 C8 -100 12.5 -95 11.4 -84 C10 -90 7 -91 3 -90.5 C-2 -93 -8 -90 -11.4 -84Z",
}


def person(kind, x, y, s=1.0, pose=None, qmark=None, shadow=True):
    """A standing figure, feet at (x, y), about 100*s tall.
    anon: hood + blank mask. stranger: visitor lanyard + '?'. owner: holds a key. engineer: glasses + stamp or pen.
    founder: hoodie, used with a laptop."""
    o = []

    def p(d, cls):
        o.append(path(sd(d, s), cls))

    def c(cx, cy, r, cls):
        o.append(circ(cx * s, cy * s, r * s, cls))

    def rc(x_, y_, w, h, cls, rx=0):
        o.append(rect(x_ * s, y_ * s, w * s, h * s, cls, rx * s))

    coat = {"anon": "sk", "stranger": "sf", "owner": "bls", "engineer": "sf", "founder": "bls"}[kind]
    if shadow:
        o.append(ell(0, 0, 21 * s, 5.5 * s, "k"))
    p(LEGS, "sk")
    rc(-11.5, -5, 10, 5, "i", 2.5)
    rc(1.5, -5, 10, 5, "i", 2.5)
    if kind != "anon":
        rc(-3.5, -75, 7, 6, "sf")
    if kind == "owner":
        c(7.5, -98, 4.6, "i")
    p(COAT, coat)
    o.append(segs([((xx * s, (-62 if xx < 15 else -60) * s), (xx * s, -30 * s)) for xx in (5, 8.5, 12, 15.5)], "h"))

    # arms
    if kind == "anon":
        p(ARM_LT, coat)
        p(ARM_RT, coat)
        p("M-17.5 -41 L-9 -43.5 M17.5 -41 L9 -43.5", "s")
    else:
        if pose == "stamp":
            p(ARM_L_OUT, coat)
        else:
            p(ARM_L, coat)
            c(-22.3, -35, 3.4, "sf")
        if pose == "key":
            p(ARM_R_FWD, coat)
        elif pose in ("keyup", "pen"):
            p(ARM_R_UP, coat)
        elif pose == "laptop":
            pass
        else:
            p(ARM_R, coat)
            c(22.3, -35, 3.4, "sf")

    # clothing details
    if kind == "stranger":
        p("M-5.5 -71 L-1.5 -60 M5.5 -71 L1.5 -60", "bo")
        rc(-6.5, -61, 13, 15, "sf", 1.5)
        o.append(T(0, -49.6 * s, "?", "tb", 11 * s, "middle"))
    if kind == "engineer":
        p("M-6.5 -71 L0 -57 L6.5 -71", "s")
        p("M8 -54 H15.5", "s")
        p("M10.5 -58.5 V-53.5", "bo")
    if kind == "founder":
        p("M-6 -71 C-4 -64 4 -64 6 -71", "s")
        p("M-2.5 -66 V-58 M2.5 -66 V-58", "s")
        p("M-10 -40 H10", "s")

    # head
    if kind == "anon":
        p("M-15.5 -80 C-17 -94 -10 -101.5 0 -101.5 C10 -101.5 17 -94 15.5 -80 C15 -73 10 -70 0 -70 C-10 -70 -15 -73 -15.5 -80Z", "i")
        o.append(ell(0, -84.5 * s, 8.4 * s, 10.2 * s, "sf"))
        o.append(ell(-3.6 * s, -86 * s, 1.9 * s, 1.2 * s, "i"))
        o.append(ell(3.6 * s, -86 * s, 1.9 * s, 1.2 * s, "i"))
    else:
        c(0, -85, 11, "sf")
        p(HAIR[kind], "i")
        c(-3.8, -84.5, 1.2, "i")
        c(3.8, -84.5, 1.2, "i")
        p("M-2.6 -79.4 Q0 -77.6 2.6 -79.4", "s")
        if kind == "engineer":
            c(-4.4, -84.5, 3.6, "s")
            c(4.4, -84.5, 3.6, "s")
            p("M-.9 -85 Q0 -86 .9 -85", "s")

    # held things
    if pose == "key":
        c(31.5, -49, 4.6, "bs")
        c(31.5, -49, 1.6, "f")
        p("M35.5 -50.5 H46 V-47.5 H44.5 V-44.8 H42.5 V-47.5 H40.5 V-45.3 H38.5 V-47.5 H35.5Z", "bs")
        c(25.8, -48.6, 3.4, "sf")
    if pose == "keyup":
        p("M17.5 -91 V-102 H20.5 V-100.5 H23.2 V-98.5 H20.5 V-97 H22.8 V-95 H20.5 V-91Z", "bs")
        c(19, -86.5, 4.6, "bs")
        c(19, -86.5, 1.6, "f")
        c(19, -80.5, 3.4, "sf")
    if pose == "pen":
        p("M23.3 -101.5 L26.7 -100.5 L21.4 -83.3 L18.5 -79.5 L17.9 -84.3Z", "bs")
        c(20.6, -84.5, 3.4, "sf")
    if pose == "stamp":
        rc(-36, -64.5, 3, 8, "sk")
        c(-34.5, -68, 4, "sk")
        rc(-42, -57, 15, 5, "bs", 1)
        rc(-41, -52, 13, 2, "gf")
        c(-34.5, -60.5, 3.4, "sf")
    if qmark:
        o.append(T(qmark[0] * s, qmark[1] * s, "?", "hand", 30 * s))
    return g(o, tr(x, y))


# ------------------------------------------------------------------ composite pieces
def repo_stack(x, y, w=120, h=150, git=True, label=True):
    """Fanned stack of code sheets standing in the x-z plane; (x, y) = front sheet top-left."""
    o = []
    f = w / 120
    for dx, dy in ((26 * f, -15 * f), (13 * f, -7.5 * f)):
        o.append(sheet(x + dx, y + dy, w, h, fold=12 * min(1, f * 1.3)))
    rows = [(0, 14, 40), (0, 10, 58), (8, 18, 30), (8, 12, 52), (8, 22, 34), (0, 6, 0), (0, 14, 44), (8, 10, 62),
            (8, 20, 26), (0, 6, 0)]
    rows = [(a * f, b * f, c * f) for a, b, c in rows]
    top = 44 if label else max(16, 36 * f)
    gap = max(7, (h - top - 10) / len(rows))
    rows = rows[:int((h - top - 6) / gap) + 1]
    inner = [rect(6 * f, top + 3 * gap - 5, w - 14 * f, 10, "bl", 2)] if label else []
    inner.append(code(12 * f, top, rows, gap))
    if label:
        inner.append(T(12, 24, "migrations/", "tk", 11))
    if git:
        gx = w - 22 * f
        k = min(1, f * 1.4)
        inner.append(g([path(sd("M0 13 V37 M0 20 C9 21 10 26 10 32", k), "bo"),
                        circ(0, 14 * k, 2.8, "bs"), circ(0, 36 * k, 2.8, "bs"), circ(10 * k, 32 * k, 2.8, "bs")], tr(gx, 0)))
    o.append(sheet(x, y, w, h, inner, fold=12 * min(1, f * 1.3)))
    return J(o)


def sandbox(O, w, d, h, cyl_r, cyl_h, rows=True, platform=True, content=None):
    """Glass sandbox on a lab plate, database cylinder inside. O = screen point of the box's back-bottom corner."""
    o = []
    if platform:
        m = max(6, w * .12)
        o.append(iso_box(w + 2 * m, d + 2 * m, 8, P(-m, -m, -8, O), top="k", hatch=5))
    inner = []
    if rows:
        rw = w * .2
        for k in range(3):
            inner.append(iso_box(rw, rw * .78, 3.5, P(w * .06, d * .74, k * 6, O), hatch=0))
        a, b = P(w * .06 + 3, d * .74 + rw * .3, 21, O), P(w * .06 + rw - 3, d * .74 + rw * .3, 21, O)
        inner.append(segs([(a, b), (P(w * .06 + 3, d * .74 + rw * .55, 21, O), P(w * .06 + rw - 8, d * .74 + rw * .55, 21, O))], "s"))
    cx, cy = P(w / 2, d / 2, 0, O)
    if cyl_r:
        inner.append(cylinder(cx, cy, cyl_r, cyl_h))
    if content:
        inner.append(content)
    o.append(glass_box(w, d, h, O, inner))
    return J(o)


def fix_sheet(x, y, w=176, h=176, k="xz"):
    sz = 10
    inner = [T(12, 22, "fix.sql", "tk", 11),
             T(12, 37, "-- PL-001: read policy", "t", 9.5),
             rect(6, 47, w - 12, 15, "rl", 2), T(12, 58, "- using (true)", "tr", sz),
             rect(6, 66, w - 12, 30, "gl", 2), T(12, 77.5, "+ to authenticated", "tg", sz),
             T(12, 91.5, "+ auth.uid() = user_id", "tg", sz),
             code(12, 110, [(0, 12, 50), (8, 18, 40), (8, 10, 66), (0, 6, 0)][:max(1, int((h - 112) / 11))], 11)]
    return sheet(x, y, w, h, inner, k)


def receipt(x, y, w=150, h=200, k="xz"):
    inner = [T(12, 21, "RECEIPT", "tk", 11), T(w - 20, 21, "PL-001", "tb", 9.5, "end"),
             path(f"M12 30 H{w - 12}", "s dash"),
             T(12, 47, "re-run", "t", 9),
             T(12, 61, "anon → 0 rows", "tg", 9.5), T(12, 74, "stranger → 0 rows", "tg", 9.5),
             T(12, 87, "owner → 1 row", "t", 9.5),
             path(f"M12 97 H{w - 12}", "s dash"),
             T(12, 113, "approved by", "t", 9),
             path("M14 132 C20 120 24 121 22 131 C21 136 28 124 33 125 C37 126 33 133 38 131 C44 128 48 124 56 127", "bo"),
             T(12, 152, "Ed25519 signed", "t", 9),
             code(12, 164, [(0, 26, 40)][:1], 10)]
    return sheet(x, y, w, h, inner, k, zig=13)


# ------------------------------------------------------------------ drawings
def svg(name, w, h, body, title=None):
    if title:
        a = f'role="img" aria-labelledby="{name}-title"'
        body = f'<title id="{name}-title">{esc(title)}</title>' + J(body)
    else:
        a = 'aria-hidden="true"'
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {w} {h}" class="ill" {a}>\n{J(body)}\n</svg>\n'


def hero_lab():
    o = []
    O = (480, 215)
    bw = 170
    # repo
    o.append(ground(70, 210, 120, 150))
    o.append(repo_stack(70, 210))
    o.append(tag(70, 436, [("[REPO]", "tb"), ("code + git history", "t")], 172))
    # flow into the lab
    o.append(arrow((206, 362), (250, 337), (300, 308), (343, 283), "bo dash flow", "bo", 11))
    o.append(T(52, 128, "rebuilt from", "hand", 30))
    o.append(T(52, 160, "your migrations", "hand", 30))
    o.append(arrow((222, 162), (262, 180), (284, 240), (268, 310)))
    # the lab
    o.append(sandbox(O, bw, bw, 150, 46, 100))
    o.append(tag(344, 6, [("[REBUILD]", "tb"), ("disposable Postgres · fake rows", "t")], 272))
    o.append(path("M480 56 V64", "s"))
    # who can read what
    o.append(path("M520 326 C560 360 612 396 637 430", "bo dash"))
    o.append(path("M448 324 C430 360 394 398 374 430", "r"))
    o.append(path("M500 332 C506 368 510 402 507 430", "r"))
    for (x, y) in ((424, 377), (394, 418), (514, 378), (519, 414)):
        o.append(drop(x, y, 1.15))
    o.append(person("anon", 365, 560, 1.2))
    o.append(person("stranger", 505, 560, 1.2, qmark=(15, -100)))
    o.append(person("owner", 645, 560, 1.2, pose="key"))
    for x, who, cnt, cls in ((365, "anon", "→ 2 rows", "tr"), (505, "stranger", "→ 2 rows", "tr"), (645, "owner", "→ 1 row", "tk")):
        o.append(T(x, 588, who, "t", 14, "middle"))
        o.append(T(x, 610, cnt, cls, 18, "middle"))
    o.append(T(118, 540, "a stranger can", "hand", 30))
    o.append(T(118, 571, "read this", "hand", 30))
    o.append(arrow((262, 522), (294, 470), (336, 432), (388, 410)))
    # fix
    o.append(arrow((636, 226), (662, 200), (684, 190), (712, 191), "bo dash flow", "bo", 11))
    o.append(tag(712, 46, [("[FIX]", "tb"), ("SQL migration", "t")], 150))
    o.append(ground(722, 108, 176, 176))
    o.append(fix_sheet(722, 108))
    o.append(arrow((826, 390), (846, 420), (880, 432), (912, 428), "bo dash flow", "bo", 11))
    o.append(T(818, 420, "re-run as 3 people", "t", 12, "end"))
    # receipt + engineer
    o.append(ground(918, 284, 150, 200))
    o.append(receipt(918, 284))
    o.append(seal(1022, 512, 28))
    o.append(path("M1066 488 L1056 494 M1068 500 L1057 503", "bo"))
    o.append(person("engineer", 1122, 560, 1.15, pose="stamp"))
    o.append(tag(890, 568, [("[RECEIPT]", "tb"), ("signed · Ed25519", "t")], 166))
    o.append(T(912, 192, "proven, then waits", "hand", 30))
    o.append(T(912, 224, "for your engineer", "hand", 30))
    o.append(arrow((1110, 236), (1146, 280), (1150, 352), (1128, 428)))
    return svg("hero-lab", 1200, 620, o,
               "PatchLabs rebuilds your database from the repo's migrations in a disposable glass sandbox with fake rows, "
               "shows an anonymous visitor and a signed-in stranger each reading 2 rows while the owner reads 1, "
               "then writes an SQL fix, re-runs all three people and issues a signed receipt your engineer approves.")


def hero_lab_m():
    """Phone version of the hero (portrait, text sized for a 390px screen)."""
    o = []
    O = (360, 150)
    o.append(T(22, 50, "rebuilt from", "hand", 32))
    o.append(T(22, 84, "your migrations", "hand", 32))
    o.append(ground(38, 132, 86, 110))
    o.append(repo_stack(38, 132, 86, 110, label=False))
    o.append(arrow((142, 252), (170, 236), (196, 222), (226, 204), "bo dash flow", "bo", 10))
    o.append(arrow((150, 98), (190, 120), (204, 170), (190, 222)))
    o.append(sandbox(O, 150, 150, 130, 40, 86))
    o.append(path("M381 252 C410 296 438 330 446 362", "bo dash"))
    o.append(path("M338 248 C302 296 206 324 162 362", "r"))
    o.append(path("M352 254 C338 296 312 330 304 362", "r"))
    o += [drop(262, 312, 1.25), drop(198, 336, 1.25), drop(334, 304, 1.25), drop(321, 338, 1.25)]
    for x, kind, pose, who, cnt, cls in ((150, "anon", None, "anon", "2 rows", "tr"), (300, "stranger", None, "stranger", "2 rows", "tr"),
                                          (450, "owner", "key", "owner", "1 row", "tk")):
        o.append(person(kind, x, 500, 1.25, pose=pose))
        o.append(T(x, 534, who, "t", 19, "middle"))
        o.append(T(x, 564, cnt, cls, 24, "middle"))
    o.append(T(300, 612, "a stranger can read this", "hand", 32, "middle"))
    # fix -> receipt -> engineer
    inner = [T(10, 20, "fix.sql", "tk", 13), rect(6, 30, 108, 16, "rl", 2), T(12, 42.5, "- using (true)", "tr", 11),
             rect(6, 50, 108, 30, "gl", 2), T(12, 62.5, "+ auth.uid()", "tg", 11), T(12, 76, "+ = user_id", "tg", 11),
             code(12, 96, [(0, 12, 50), (8, 16, 40)], 10)]
    o.append(ground(36, 660, 120, 116))
    o.append(sheet(36, 660, 120, 116, inner))
    o.append(arrow((150, 768), (170, 752), (190, 742), (212, 736), "bo dash flow", "bo", 10))
    rin = [T(10, 19, "RECEIPT", "tk", 12), T(10, 38, "anon → 0", "tg", 11), T(10, 53, "stranger → 0", "tg", 11),
           code(10, 70, [(0, 0, 70), (0, 0, 50)], 10)]
    o.append(sheet(222, 660, 104, 120, rin, zig=13))
    o.append(seal(300, 790, 23))
    o.append(path("M418 772 L406 778 M420 784 L408 787", "bo"))
    o.append(person("engineer", 470, 826, 1.2, pose="stamp"))
    o.append(T(336, 668, "proven, then waits", "hand", 30))
    o.append(T(336, 698, "for your engineer", "hand", 30))
    return svg("hero-lab-m", 600, 840, o,
               "PatchLabs rebuilds your database from the repo's migrations in a disposable glass sandbox; an anonymous visitor and a "
               "signed-in stranger each read 2 rows while the owner reads 1. Then it writes an SQL fix, re-runs all three people and "
               "issues a signed receipt your engineer approves.")


def persona(name, kind, pose, title, q=None):
    cid = f"{name}-clip"
    o = [f'<defs><clipPath id="{cid}"><circle cx="48" cy="48" r="43.2"/></clipPath></defs>',
         circ(48, 48, 44, "bl"),
         g([segs([((x, 70), (x + 26, 96)) for x in range(-20, 96, 7)], "hs"),
            g(person(kind, 0, 0, 1.45, pose=pose, qmark=q, shadow=False), tr(48, 166))], extra=f' clip-path="url(#{cid})"'),
         circ(48, 48, 44, "s")]
    return svg(name, 96, 96, o, title)


def wrap(s, limit):
    if len(s) <= limit:
        return [s]
    mid = len(s) // 2
    cut = min((i for i, ch in enumerate(s) if ch == " "), key=lambda i: abs(i - mid))
    return [s[:cut], s[cut + 1:]]


STEPS = [("Repo", "read repo + history"), ("Rebuild", "rebuild in a throwaway copy"), ("Reproduce", "try as 3 people"),
         ("Fix", "write the migration"), ("Approve", "your engineer approves"), ("Receipt", "signed receipt")]


def step_icon(k, cx, cy):
    """Small drawing for pipeline step k (0-5), centred on (cx, cy), about 120 x 110."""
    if k == 0:
        return repo_stack(cx - 33, cy - 44, 62, 66, label=False)
    if k == 1:
        return sandbox((cx, cy - 12), 50, 50, 44, 14, 30, rows=False)
    if k == 2:
        o = [person("anon", cx - 34, cy + 40, .62), person("stranger", cx, cy + 40, .62), person("owner", cx + 34, cy + 40, .62)]
        o += [drop(cx - 34, cy - 40), drop(cx - 2, cy - 40)]
        return J(o)
    if k == 3:
        inner = [rect(5, 14, 56, 9, "rl", 2), T(9, 21.5, "-", "tr", 9), rect(5, 27, 56, 17, "gl", 2),
                 T(9, 34.5, "+", "tg", 9), T(9, 42.5, "+", "tg", 9),
                 code(16, 19, [(0, 0, 36)], 1), code(16, 32, [(0, 0, 30), (0, 0, 38)], 8), code(8, 54, [(0, 8, 30), (4, 8, 22)], 9)]
        return sheet(cx - 29, cy - 52, 66, 74, inner, fold=9)
    if k == 4:
        return person("engineer", cx + 10, cy + 44, .82, pose="stamp")
    if k == 5:
        inner = [code(8, 14, [(0, 22, 16), (0, 0, 40), (0, 0, 34), (0, 10, 26)], 9)]
        return sheet(cx - 32, cy - 50, 60, 80, inner, fold=9, zig=10) + seal(cx + 14, cy + 30, 17)


def pipeline():
    o = []
    for k, (title, cap) in enumerate(STEPS):
        cx = 100 + 200 * k
        o.append(num(cx, 18, k + 1))
        o.append(step_icon(k, cx, 100))
        o.append(T(cx, 186, title, "tk", 15, "middle"))
        for j, line_ in enumerate(wrap(cap, 22)):
            o.append(T(cx, 207 + 16 * j, line_, "t", 12.5, "middle"))
        if k < 5:
            o.append(arrow((cx + 64, 100), (cx + 84, 100), (cx + 116, 100), (cx + 136, 100), "bo dash flow", "bo", 8))
    return svg("pipeline", 1200, 240, o,
               "Six steps: 1 Repo, read repo and history. 2 Rebuild in a throwaway copy. 3 Reproduce, try as 3 people. "
               "4 Fix, write the migration. 5 Approve, your engineer approves. 6 Receipt, signed receipt.")


def pipeline_v():
    o = []
    for k, (title, cap) in enumerate(STEPS):
        y0 = 12 + 147 * k
        o.append(step_icon(k, 80, y0 + 66))
        o.append(num(174, y0 + 50, k + 1))
        o.append(T(196, y0 + 55, title, "tk", 16))
        for j, line_ in enumerate(wrap(cap, 22)):
            o.append(T(161, y0 + 80 + 17 * j, line_, "t", 13))
        if k < 5:
            o.append(arrow((80, y0 + 128), (80, y0 + 136), (80, y0 + 144), (80, y0 + 152), "bo dash", "bo", 7))
    return svg("pipeline-v", 360, 900, o,
               "Six steps: 1 Repo, read repo and history. 2 Rebuild in a throwaway copy. 3 Reproduce, try as 3 people. "
               "4 Fix, write the migration. 5 Approve, your engineer approves. 6 Receipt, signed receipt.")


# ------------------------------------------------------------------ product spots
def spot_lab():
    o = [sandbox((160, 112), 110, 110, 92, 30, 62)]
    o.append(path("M186 186 C236 200 284 198 312 184", "r"))
    o.append(path("M192 160 C252 130 336 140 372 178", "r"))
    o += [drop(256, 206), drop(300, 146)]
    o.append(person("anon", 318, 252, .76))
    o.append(person("stranger", 378, 252, .76))
    o.append(person("owner", 438, 252, .76, pose="key"))
    for x, who, cnt, cls in ((318, "anon", "2 rows", "tr"), (378, "stranger", "2 rows", "tr"), (438, "owner", "1 row", "tk")):
        o.append(T(x, 274, who, "t", 11, "middle"))
        o.append(T(x, 290, cnt, cls, 12, "middle"))
    o.append(tag(286, 14, [("[LAB]", "tb"), ("rebuild + reproduce", "t")], 178, 12))
    o.append(T(300, 100, "a throwaway copy", "hand", 22))
    o.append(arrow((298, 92), (270, 88), (240, 96), (218, 112), L=7))
    return svg("spot-lab", 480, 300, o,
               "Lab: your database rebuilt in a glass sandbox with fake rows; the anonymous visitor and the stranger each read 2 rows, the owner reads 1.")


def spot_code():
    o = []
    # git history behind: main line, a branch, one red commit where a key went in
    xs = [40, 92, 144, 196, 248, 300, 352, 404, 446]
    o.append(path("M30 44 H456", "s"))
    o.append(path("M144 44 C170 44 172 22 198 22 H274 C300 22 302 44 326 44", "s"))
    for x in xs:
        o.append(circ(x, 44, 5, "sf"))
    o += [circ(222, 22, 5, "sf"), circ(250, 22, 5, "rf")]
    o.append(T(250, 12, "key added", "tr", 10.5, "middle"))
    o.append(T(404, 64, "key removed", "t", 10.5, "middle"))
    # code sheets
    rows = [(0, 14, 40), (0, 10, 58), (8, 18, 30), (8, 12, 52), (0, 0, 0), (8, 22, 34), (0, 6, 0), (0, 14, 44), (8, 10, 62)]
    o.append(sheet(124, 82, 150, 124, fold=10))
    o.append(sheet(112, 89, 150, 124, fold=10))

    def front(clip=False):
        inner = [T(12, 22, ".env.local", "tk", 10.5), code(12, 38, rows[:4], 10),
                 rect(6, 73, 138, 13, "rl", 2), T(12, 83, "SERVICE_ROLE_KEY=eyJ…", "tr", 9.5),
                 code(12, 100, rows[5:7], 10)]
        return sheet(100, 96, 150, 124, inner, fold=10)
    o.append(front())
    # magnifier over the highlighted line (page point u=74, v=79)
    cx, cy, r = 100 + 74 * C, 96 + 74 * .5 + 79, 40
    z = 1.7
    o.append(f'<defs><clipPath id="spot-code-lens"><circle cx="{n(cx)}" cy="{n(cy)}" r="{r - 1}"/></clipPath></defs>')
    o.append(circ(cx, cy, r, "f"))
    o.append(g(g(front(), f"translate({n(cx)} {n(cy)}) scale({z}) translate({n(-cx)} {n(-cy)})"), extra=' clip-path="url(#spot-code-lens)"'))
    hx, hy = cx + r * .72, cy + r * .72
    o.append(path(f"M{n(hx)} {n(hy)} L{n(hx + 11)} {n(hy + 11)}", "s2"))
    o.append(path(sd("M-6 0 L6 0 L6 42 C6 46 -6 46 -6 42Z", 1), "i", f' transform="translate({n(hx + 10)} {n(hy + 10)}) rotate(-45)"'))
    o.append(circ(cx, cy, r, "s2"))
    o.append(path(f"M{n(cx - r * .62)} {n(cy - r * .3)} A{r * .7} {r * .7} 0 0 1 {n(cx - r * .2)} {n(cy - r * .66)}", "glint"))
    o.append(T(300, 132, "deleted later,", "hand", 22))
    o.append(T(300, 154, "still in your history", "hand", 22))
    o.append(arrow((330, 118), (316, 90), (278, 66), (256, 32), L=7))
    o.append(tag(286, 240, [("[CODE]", "tb"), ("repo + git history", "t")], 172, 12))
    return svg("spot-code", 480, 300, o,
               "Code: a magnifier over a leaked service key in a code file, with the git history behind showing the commit where the key was added.")


def spot_fix():
    o = [fix_sheet(30, 70, 160, 150)]
    o.append(arrow((176, 150), (198, 140), (220, 150), (244, 172), "bo dash flow", "bo", 8))
    inner = [T(12, 21, "re-test", "tk", 11), T(150, 21, "3 people", "t", 9.5, "end"),
             rect(6, 31, 150, 17, "gl", 2), T(12, 43, "anon → DENIED", "tg", 10),
             rect(6, 52, 150, 17, "gl", 2), T(12, 64, "stranger → DENIED", "tg", 10),
             T(12, 85, "owner → 1 row", "tk", 10)]
    o.append(sheet(252, 166, 162, 104, inner, k="yz", fold=10))
    o.append(person("engineer", 440, 284, .86, pose="pen"))
    o.append(T(196, 292, "same 3 people, re-run", "hand", 21))
    o.append(tag(262, 14, [("[FIX]", "tb"), ("write · prove · approve", "t")], 204, 12))
    return svg("spot-fix", 480, 300, o,
               "Fix: an SQL diff that replaces an open read policy, a re-test where the anonymous visitor and the stranger are now denied, and your engineer with a pen.")


def bell(cx, cy, s=1.0):
    o = [path(sd("M-20 14 C-16 10 -15 4 -15 -6 C-15 -17 -8 -24 0 -24 C8 -24 15 -17 15 -6 C15 4 16 10 20 14Z", s, cx, cy), "bls"),
         path(sd("M-21 14 H21 C23 14 23 19 21 19 H-21 C-23 19 -23 14 -21 14Z", s, cx, cy), "sf"),
         path(sd("M-6 19 A6 6 0 0 0 6 19", s, cx, cy), "sf"),
         circ(cx, cy - 26 * s, 3 * s, "sf"),
         segs([((cx + 5 * s, cy - 18 * s), (cx + 5 * s, cy + 10 * s)), ((cx + 9 * s, cy - 14 * s), (cx + 9 * s, cy + 11 * s))], "h"),
         path(sd("M24 -18 C29 -12 29 -4 26 2 M30 -24 C38 -14 38 -2 33 6 M-24 -18 C-29 -12 -29 -4 -26 2", s, cx, cy), "bo"),
         circ(cx + 13 * s, cy - 18 * s, 5.5 * s, "rf")]
    return J(o)


def spot_watch():
    o = []
    days = "MTWTFSS"
    cw, rh = 30, 28
    inner = [rect(0, 0, 7 * cw, 18, "bl"), path(f"M0 18 H{7 * cw}", "s")]
    for i, ch in enumerate(days):
        inner.append(T(cw / 2 + cw * i, 13, ch, "tb", 9.5, "middle"))
    inner.append(segs([((cw * i, 18), (cw * i, 18 + 3 * rh)) for i in range(1, 7)] + [((0, 18 + rh * j), (7 * cw, 18 + rh * j)) for j in range(1, 3)], "h"))
    for j in range(3):
        y = 18 + rh / 2 + rh * j
        inner.append(circ(cw / 2, y, 8, "bls"))
        inner.append(path(f"M{cw / 2 - 4} {y} L{cw / 2 - 1} {y + 3} L{cw / 2 + 4.5} {y - 3.5}", "s"))
    o.append(sheet(34, 56, 7 * cw, 18 + 3 * rh, inner, fold=0))
    o.append(T(36, 290, "every week, same checks", "hand", 22))
    o.append(arrow((80, 270), (72, 236), (56, 200), (50, 166), L=7))
    o.append(bell(340, 128, 1.2))
    o.append(T(354, 80, "new leak", "tr", 10.5))
    # dated badge
    bx, by = 400, 226
    o.append(circ(bx, by, 50, "bls"))
    o.append(circ(bx, by, 42, "s dash"))
    o.append(T(bx, by - 11, "RE-CHECKED", "tb", 10, "middle"))
    o.append(T(bx, by + 5, "11 NOV 2026", "tk", 10.5, "middle"))
    o.append(T(bx, by + 20, "PatchLabs", "t", 10, "middle"))
    o.append(tag(286, 6, [("[WATCH]", "tb"), ("weekly re-check", "t")], 160, 12))
    return svg("spot-watch", 480, 300, o,
               "Watch: a week calendar with the same check repeated every week, an alert bell for a new leak and a dated re-checked badge.")


def spot_live():
    o = []
    W_, H_ = 212, 140
    inner = [rect(0, 0, W_, 24, "k"), path(f"M0 24 H{W_}", "s"),
             circ(12, 12, 3.5, "sf"), circ(24, 12, 3.5, "sf"), circ(36, 12, 3.5, "sf"),
             rect(50, 6, 170, 12, "sf", 6), T(58, 15.5, "https://your-app", "t", 9),
             T(18, 46, "posture grade", "t", 10),
             circ(60, 90, 32, "bls"), T(60, 110, "A", "disp", 58, "middle"),
             code(114, 64, [(0, 16, 56), (0, 24, 40), (0, 12, 60), (0, 20, 46), (0, 14, 36)], 13)]
    o.append(sheet(24, 52, W_, H_, inner, fold=0))
    tags = [("[HTTPS]", "redirect + TLS"), ("[HEADERS]", "HSTS · CSP"), ("[COOKIES]", "Secure · HttpOnly"), ("[CERT]", "valid, not expiring")]
    ex = 24 + W_ * C
    for i, (a, b) in enumerate(tags):
        y = 76 + 52 * i
        ey = 52 + W_ * .5 + 22 + 30 * i
        o.append(path(f"M{n(ex)} {n(ey)} L{n(290)} {n(y + 23)}", "h"))
        o.append(tag(290, y, [(a, "tb"), (b, "t")], 176, 11))
    o.append(T(30, 34, "graded once a day", "hand", 22))
    o.append(tag(290, 10, [("[LIVE]", "tb"), ("public site posture", "t")], 176, 11))
    return svg("spot-live", 480, 300, o,
               "Live posture: a browser window with a posture grade, plus tags for HTTPS, security headers, cookies and the certificate, graded once a day.")


def receipt_seal():
    o = []
    x0, y0, w, h = 52, 30, 300, 430
    zig = "".join(f"L{n(x0 + w - 15 * (i + .5))} {y0 + h - 7} L{n(x0 + w - 15 * (i + 1))} {y0 + h} " for i in range(20))
    paper = f"M{x0} {y0} H{x0 + w} V{y0 + h} {zig}Z"
    o.append(path(sd(paper, 1, 12, 12), "sk"))
    o.append(segs([((x0 + w + 2, y0 + 20 + k), (x0 + w + 10, y0 + 28 + k)) for k in range(0, h - 20, 7)], "h"))
    o.append(path(paper, "sf"))
    X = x0 + 24
    o += [rect(X, y0 + 22, 22, 22, "b", 5.5),
          path(sd("M11.5 9H8.5v14h3M20.5 9h3v14h-3", 22 / 32, X, y0 + 22), "lgw"),
          path(sd("M12.6 16.4l2.5 2.5 4.4-5.2", 22 / 32, X, y0 + 22), "lgc"),
          T(X + 30, y0 + 38, "PatchLabs", "tk", 13),
          T(x0 + w - 24, y0 + 38, "RECEIPT", "tb", 11, "end"),
          path(f"M{X} {y0 + 60} H{x0 + w - 24}", "s dash")]
    fields = [("FINDING", [("PL-001 · anon could read", "tk"), ("a table of personal data", "tk")]),
              ("FIX", [("SQL migration", "tk"), ("sha256", "t")]),
              ("RE-TESTED AS 3 PEOPLE", [("anon → 0 rows", "tg"), ("stranger → 0 rows", "tg"), ("owner → 1 row", "tk")]),
              ("APPROVED BY", [("your engineer", "tk")]),
              ("SIGNATURE", [("Ed25519", "tk")])]
    y = y0 + 86
    for label, vals in fields:
        o.append(T(X, y, label, "t", 9.5))
        y += 18
        for v, cls in vals:
            o.append(T(X, y, v, cls, 11.5))
            if v == "sha256":
                o.append(code(X + 50, y - 4, [(0, 0, 150)], 1))
            if v == "Ed25519":
                o.append(code(X + 62, y - 4, [(0, 0, 70)], 1))
            y += 16
        if label == "APPROVED BY":
            o.append(path(sd("M0 14 C8 -2 14 0 11 12 C9 20 20 2 27 4 C33 6 27 15 35 13 C44 10 50 5 62 9", 1, X + 110, y - 42), "bo"))
        y += 12
    cx, cy, r = 290, 404, 62
    o.append(seal(cx, cy, r, 20, check=False))
    o.append(f'<defs><path id="receipt-seal-ring" d="M{cx - r * .8} {cy} A{r * .8} {r * .8} 0 1 1 {cx + r * .8} {cy} A{r * .8} {r * .8} 0 1 1 {cx - r * .8} {cy}"/></defs>')
    L = 2 * math.pi * r * .8
    o.append(f'<text class="tw" style="font-size:10.5px"><textPath href="#receipt-seal-ring" textLength="{n(L - 6)}" lengthAdjust="spacing">'
             f'PROVEN · RE-TESTED · PROVEN · RE-TESTED ·</textPath></text>')
    o.append(path(f"M{cx - 18} {cy + 1} L{cx - 5} {cy + 14} L{cx + 20} {cy - 13}", "ws2"))
    return svg("receipt-seal", 420, 520, o,
               "A signed PatchLabs receipt listing the finding, the fix's hash, the re-test as three people, who approved it and an Ed25519 signature, "
               "with a green seal reading proven, re-tested.")


def study_318():
    cols, rows_, pitch, t = 53, 6, 16, 11
    x0 = (960 - (cols * pitch - (pitch - t))) / 2
    y0 = 72
    red, grey, bars = [], [], []
    for k in range(318):
        c_, r_ = divmod(k, rows_)
        x, y = x0 + c_ * pitch, y0 + r_ * pitch
        (red if k < 106 else grey).append(f"M{n(x)} {n(y)}h{t}v{t}h-{t}Z")
        if k < 106:
            bars.append(f"M{n(x + 2.5)} {n(y + 3.5)}h6")
        else:
            grey.append(f"M{n(x)} {n(y + 3.5)}h{t}")
    assert len(red) == 106 and len(bars) == 106
    o = [T(x0, 40, "318 APPS REBUILT FROM THEIR OWN MIGRATIONS", "tb", 12),
         path("".join(grey), "h"), path("".join(red), "rf"), path("".join(bars), "ws")]
    xr = x0 + 18 * pitch - (pitch - t)  # end of the red block (17 columns + 4)
    yb = y0 + rows_ * pitch + 6
    o.append(path(f"M{n(x0)} {yb} C{n(x0)} {yb + 8} {n(x0 + 4)} {yb + 8} {n(x0 + 20)} {yb + 8} H{n((x0 + xr) / 2 - 8)} "
                  f"C{n((x0 + xr) / 2 - 2)} {yb + 8} {n((x0 + xr) / 2)} {yb + 12} {n((x0 + xr) / 2)} {yb + 16} "
                  f"C{n((x0 + xr) / 2)} {yb + 12} {n((x0 + xr) / 2 + 2)} {yb + 8} {n((x0 + xr) / 2 + 8)} {yb + 8} H{n(xr - 20)} "
                  f"C{n(xr - 4)} {yb + 8} {n(xr)} {yb + 8} {n(xr)} {yb}", "r"))
    o.append(T((x0 + xr) / 2, yb + 36, "106", "tr", 18, "middle"))
    xe = 960 - x0
    o.append(T((xr + 16 + xe) / 2, yb + 36, "212", "tk", 18, "middle"))
    o.append(path(f"M{n(xr + 16)} {yb} V{yb + 8} H{n(xe)} V{yb}", "h"))
    o.append(T((x0 + xr) / 2, yb + 76, "106 of 318 let the wrong", "hand", 26, "middle"))
    o.append(T((x0 + xr) / 2, yb + 102, "people read personal data", "hand", 26, "middle"))
    o.append(T(xe, yb + 36, "", "t"))
    o.append(T(xe, 286, "PatchLabs lab study · Nov 2026", "t", 12, "end"))
    o.append(T((xr + 16 + xe) / 2, yb + 56, "no such leak found in the lab", "t", 12, "middle"))
    return svg("study-318", 960, 300, o,
               "Unit chart of 318 apps rebuilt from their migrations: 106 tiles in red let the wrong people read personal data, "
               "212 did not. PatchLabs lab study, November 2026.")


def laptop(cx, cy, s=1.0):
    """Held laptop seen from the front: screen with an AI builder chat, keyboard deck below. (cx, cy) = deck centre."""
    o = [rect(cx - 40 * s, cy - 50 * s, 80 * s, 50 * s, "sf", 4 * s),
         rect(cx - 35 * s, cy - 45 * s, 70 * s, 40 * s, "k", 2 * s),
         rect(cx - 31 * s, cy - 41 * s, 46 * s, 11 * s, "sf", 5 * s),
         T(cx - 27 * s, cy - 33.2 * s, "add sign-up", "t", 6.6 * s),
         rect(cx - 9 * s, cy - 27 * s, 40 * s, 17 * s, "bls", 5 * s),
         code(cx - 5 * s, cy - 21.5 * s, [(0, 0, 28 * s), (0, 0, 20 * s)], 6 * s),
         path(sd("M-46 0 H46 L40 7 H-40Z", s, cx, cy), "sk")]
    return J(o)


def two_people():
    o = []
    o.append(person("founder", 140, 286, 1.55))
    o.append(laptop(140, 286 - 36 * 1.55, 1.08))
    o.append(circ(140 - 39, 286 - 33 * 1.55, 3.4 * 1.55, "sf"))
    o.append(circ(140 + 39, 286 - 33 * 1.55, 3.4 * 1.55, "sf"))
    o.append(fix_sheet(296, 96, 150, 150))
    o.append(seal(420, 262, 24))
    o.append(person("engineer", 566, 286, 1.55, pose="stamp"))
    o.append(path("M494 232 L470 248 M498 246 L476 258", "bo"))
    o.append(arrow((206, 180), (236, 160), (262, 156), (290, 166), "bo dash flow", "bo", 9))
    o.append(T(204, 70, "we write the fix", "hand", 26))
    o.append(arrow((262, 80), (270, 104), (284, 122), (306, 134), L=8))
    o.append(T(500, 70, "they sign it off", "hand", 26))
    o.append(arrow((562, 80), (570, 100), (570, 120), (564, 140), L=8))
    o.append(tag(28, 302, [("[YOU]", "tb"), ("shipped it with an AI builder", "t")], 262, 12))
    o.append(tag(470, 302, [("[YOUR ENGINEER]", "tb"), ("signs off the fix", "t")], 200, 12))
    return svg("two-people", 720, 360, o,
               "Two people: the founder who shipped the app with an AI builder chat on their laptop, and their engineer who stamps approval, "
               "connected by the fix PatchLabs writes.")


def lost_404():
    O = (250, 150)
    w = 150
    ghost = []
    cx, cy = P(w / 2, w / 2, 0, O)
    ghost.append(ell(cx, cy, 40 * 1.2247, 40 * .7071, "s dash"))
    o = [sandbox(O, w, w, 128, 0, 0, rows=False, content=J(ghost))]
    o.append(person("stranger", 462, 322, 1.1, qmark=(16, -100)))
    o.append(T(14, 52, "no table here", "hand", 30))
    o.append(arrow((96, 68), (112, 130), (160, 182), (208, 204), L=9))
    o.append(tag(30, 286, [("[404]", "tb"), ("page not found", "t")], 160, 12))
    return svg("lost-404", 560, 360, o, "An empty glass sandbox with only a dashed outline where a table should be, and a puzzled visitor: no table here.")


def og_card():
    o = [rect(0, 0, 1200, 630, "pg")]
    X, Y = 80, 74
    o += [rect(X, Y, 46, 46, "b", 11.5),
          path(sd("M11.5 9H8.5v14h3M20.5 9h3v14h-3", 46 / 32, X, Y), "lgw", ' style="stroke-width:3.2px"'),
          path(sd("M12.6 16.4l2.5 2.5 4.4-5.2", 46 / 32, X, Y), "lgc", ' style="stroke-width:3.6px"'),
          T(X + 60, Y + 34, "PatchLabs", "wm", 34)]
    o.append(T(X - 4, 268, "Find the leak.", "disp", 84))
    o.append(T(X - 4, 362, "Prove the fix.", "disp", 84))
    o.append(T(X, 428, "Rebuilds your app's database in a throwaway", "t", 19))
    o.append(T(X, 456, "copy, tries it as 3 people, proves the fix.", "t", 19))
    o.append(T(X, 556, "patchlabs.dev", "tb", 18))
    O = (850, 196)
    o.append(sandbox(O, 150, 150, 130, 40, 86))
    o.append(path("M824 296 C806 336 776 372 760 402", "r"))
    o.append(path("M870 300 C876 336 880 370 878 402", "r"))
    o += [drop(796, 350, 1.1), drop(884, 352, 1.1)]
    o.append(person("anon", 752, 530, 1.2))
    o.append(person("stranger", 872, 530, 1.2))
    o.append(person("owner", 992, 530, 1.2, pose="key"))
    for x, who, cnt, cls in ((752, "anon", "→ 2 rows", "tr"), (872, "stranger", "→ 2 rows", "tr"), (992, "owner", "→ 1 row", "tk")):
        o.append(T(x, 560, who, "t", 14, "middle"))
        o.append(T(x, 582, cnt, cls, 17, "middle"))
    o.append(ground(1018, 192, 140, 170))
    o.append(receipt(1018, 192, 140, 170))
    o.append(seal(1124, 380, 26))
    o.append(T(640, 48, "rebuilt from your migrations", "hand", 28))
    return svg("og-card", 1200, 630, o, "PatchLabs: Find the leak. Prove the fix.")


DRAW = {
    "hero-lab": hero_lab,
    "hero-lab-m": hero_lab_m,
    "persona-anon": lambda: persona("persona-anon", "anon", None, "Anonymous visitor: a hooded figure with a blank mask."),
    "persona-stranger": lambda: persona("persona-stranger", "stranger", None, "Signed-in stranger: a figure with a visitor lanyard and a question mark.", q=(-27, -92)),
    "persona-owner": lambda: persona("persona-owner", "owner", "keyup", "Owner: a figure holding up a key."),
    "persona-engineer": lambda: persona("persona-engineer", "engineer", "pen", "Your engineer: a figure with glasses holding a pen to approve."),
    "pipeline": pipeline,
    "pipeline-v": pipeline_v,
    "spot-lab": spot_lab,
    "spot-code": spot_code,
    "spot-fix": spot_fix,
    "spot-watch": spot_watch,
    "spot-live": spot_live,
    "receipt-seal": receipt_seal,
    "study-318": study_318,
    "two-people": two_people,
    "lost-404": lost_404,
    "og-card": og_card,
}


def main(names):
    os.makedirs(OUT, exist_ok=True)
    for name in names or DRAW:
        s = DRAW[name]()
        with open(os.path.join(OUT, name + ".svg"), "w") as f:
            f.write(s)
        print(f"{name:18} {len(s.encode()) / 1024:5.1f} KB")


if __name__ == "__main__":
    main(sys.argv[1:])

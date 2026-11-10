#!/usr/bin/env python3
"""Builds the SVG charts, the anonymised run table and the aggregate CSV for /research/1-in-4 from the 20-app log,
then fills the {{...}} slots in report_tpl.html and writes site/pages/research/1-in-4.html."""
import csv, io, json, math, os, statistics as st

# The raw run log names real apps, so it stays outside the repo. Point PL_STUDY_BATCH at it to regenerate.
BATCH = os.environ.get("PL_STUDY_BATCH", "/Users/manraj/co-founder/build/leakcheck/batch-20261109-1513.jsonl")
HERE = os.path.dirname(os.path.abspath(__file__))
SITE = os.path.join(os.environ.get("PL_GEN_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(HERE))), "site")

rows = [json.loads(l) for l in open(BATCH) if l.strip()]
assert len(rows) == 20
runs = []
for r in rows:
    tried = [a["model"] for a in r["attempts"]]
    passed_on = next((a["model"] for a in r["attempts"] if a["passed"]), None)
    v = list(r["verdicts"].values())
    runs.append(dict(who="anyone" if r["who"] == "anyone" else "signed-in", tables=len(r["leaking"]), tried=tried,
                     passed_on=passed_on, cost=r["cost"], minutes=r["seconds"] / 60, questions=r["questions"],
                     risk=r["break_risk"], bug=v.count("bug"), pbd=v.count("public_by_design_but_leaky"),
                     fp=v.count("false_positive")))
runs.sort(key=lambda x: x["cost"])
costs = [x["cost"] for x in runs]
mins = [x["minutes"] for x in runs]
S = dict(
    cost_med=st.median(costs), cost_mean=st.mean(costs), cost_min=min(costs), cost_max=max(costs),
    min_med=st.median(mins), min_mean=st.mean(mins), min_min=min(mins), min_max=max(mins),
    haiku_only=[x["cost"] for x in runs if x["tried"] == ["haiku"] and x["passed_on"] == "haiku"],
)
assert round(S["cost_med"], 2) == 0.46 and round(S["min_med"], 1) == 3.5
assert sum(x["tables"] for x in runs) == 37
assert sum(x["bug"] for x in runs) == 28 and sum(x["pbd"] for x in runs) == 7 and sum(x["fp"] for x in runs) == 2
assert sum(x["questions"] for x in runs) == 18
hq = S["haiku_only"]
assert len(hq) == 15 and round(st.median(hq), 2) == 0.41 and round(max(hq), 2) == 0.76


def money(v):
    return f"${v:.2f}"


def pct_log(v, lo, hi):
    return 100 * (math.log(v) - math.log(lo)) / (math.log(hi) - math.log(lo))


def strip(values, kinds, lo, hi, ticks, fmt, median, label, unit_word):
    """Responsive strip plot: x positions in %, so text stays at real size on any width."""
    h = 132
    out = [f'<svg class="strip" role="img" aria-labelledby="{label}-t {label}-d" height="{h}" width="100%" xmlns="http://www.w3.org/2000/svg">',
           f'<title id="{label}-t">{unit_word} per app, all 20 apps</title>',
           f'<desc id="{label}-d">Each dot is one app on a logarithmic scale. Median {fmt(median)}. Range {fmt(min(values))} to {fmt(max(values))}. Data table below.</desc>',
           '<g class="grid">']
    for t, show in ticks:
        x = pct_log(t, lo, hi)
        out.append(f'<line x1="{x:.2f}%" x2="{x:.2f}%" y1="18" y2="96"/>')
    out.append('</g>')
    out.append('<line class="axis" x1="0" x2="100%" y1="96" y2="96"/>')
    for t, show in ticks:
        x = pct_log(t, lo, hi)
        cls = "t-mono" + ("" if show == "all" else " hide-phone")
        anchor = "start" if x < 3 else "end" if x > 97 else "middle"
        out.append(f'<text class="{cls}" x="{x:.2f}%" y="116" text-anchor="{anchor}">{fmt(t)}</text>')
    mx = pct_log(median, lo, hi)
    out.append(f'<line class="ref" x1="{mx:.2f}%" x2="{mx:.2f}%" y1="10" y2="96"/>')
    out.append(f'<text class="t-mono" x="{mx:.2f}%" y="8" dx="6" dy="4">median {fmt(median)}</text>')
    # beeswarm-ish: stack dots that are close
    placed = []
    for v, k in sorted(zip(values, kinds)):
        x = pct_log(v, lo, hi)
        lane = 0
        while any(abs(px - x) < 1.6 and pl == lane for px, pl in placed):
            lane += 1
        placed.append((x, lane))
        y = 78 - lane * 13
        cls = "m-green" if k == "proven" else "m-amber"
        out.append(f'<circle class="dot mark {cls}" cx="{x:.2f}%" cy="{y}" r="6"><title>{fmt(v)}, {k}</title></circle>')
    out.append('</svg>')
    return "\n".join(out)


kinds = ["proven" if x["passed_on"] else "needs a person" for x in runs]
COST_STRIP = strip(costs, kinds, 0.1, 20,
                   [(0.1, "all"), (0.25, "desk"), (0.5, "all"), (1, "desk"), (2.5, "all"), (5, "desk"), (10, "all"), (20, "desk")],
                   lambda v: (f"${v:.2f}" if v < 1 else f"${v:.2f}".rstrip("0").rstrip(".") if v < 10 else f"${v:.0f}") if v not in (0.1, 0.25, 0.5, 1, 2.5, 5, 10, 20) else {0.1: "$0.10", 0.25: "$0.25", 0.5: "$0.50", 1: "$1", 2.5: "$2.50", 5: "$5", 10: "$10", 20: "$20"}[v],
                   S["cost_med"], "cost", "Model cost")
TIME_STRIP = strip(mins, kinds, 0.5, 100,
                   [(0.5, "desk"), (1, "all"), (2, "desk"), (5, "all"), (10, "desk"), (30, "all"), (60, "desk"), (100, "all")],
                   lambda v: (f"{v:g} min" if v in (0.5, 1, 2, 5, 10, 30, 60, 100) else f"{v:.1f} min"),
                   S["min_med"], "time", "Agent working time")


def hatch(label):
    return (f'<defs><pattern id="hatch-{label}" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">'
            f'<rect class="hatch-bg" width="6" height="6"/><line class="hatch-line" x1="0" y1="0" x2="0" y2="6"/></pattern></defs>')


def fillattr(c, label):
    return f' style="fill:url(#hatch-{label})"' if c == "m-redsoft" else ""


def hbars(items, label, title, desc, cls="m-ink", total=None):
    """Horizontal bars with labels above each bar; widths in %, values right-aligned. items: (label, value, cls?)"""
    mx = max(v for _, v, *_ in items)
    row_h = 46
    h = row_h * len(items) + 4
    out = [f'<svg role="img" aria-labelledby="{label}-t {label}-d" width="100%" height="{h}" xmlns="http://www.w3.org/2000/svg">',
           f'<title id="{label}-t">{title}</title><desc id="{label}-d">{desc}</desc>', hatch(label)]
    for i, it in enumerate(items):
        name, v = it[0], it[1]
        c = it[2] if len(it) > 2 else cls
        y = i * row_h
        w = 100 * v / mx
        out.append(f'<text x="0" y="{y + 16}">{name}</text>')
        tv = f"{v}" + (f" of {total}" if total else "")
        vcls = "t-val" + (" red" if c in ("m-red", "m-redsoft") else " green" if c == "m-green" else "")
        out.append(f'<text class="{vcls}" x="100%" y="{y + 16}" text-anchor="end">{v}</text>')
        out.append(f'<rect class="m-track" x="0" y="{y + 24}" width="100%" height="12" rx="3"/>')
        out.append(f'<rect class="mark {c}"{fillattr(c, label)} x="0" y="{y + 24}" width="{w:.2f}%" height="12" rx="3"><title>{name}: {tv}</title></rect>')
    out.append('</svg>')
    return "\n".join(out)


FUNNEL = hbars([
    ("Public repos sampled", 500, "m-faint"),
    ("Run through the lab", 436, "m-faint"),
    ("Migrations built a working database", 318, "m-ink"),
    ("Personal data readable by the wrong people", 106, "m-red"),
    ("…by anyone with the public key", 70, "m-red"),
    ("…only by people who sign up", 36, "m-redsoft"),
], "funnel", "From 500 sampled repos to 106 exposing personal data",
    "500 sampled, 436 run, 318 built a working database, 106 let the wrong people read personal data: 70 to anyone with the public key and 36 more to anyone who signs up.")

TABLES = hbars([
    ("Other people’s records (staff, sellers, suppliers, players)", 9),
    ("User profiles and accounts", 8),
    ("Messages, chat logs and notifications", 6),
    ("Leads, sign-ups, waitlists and requests", 5),
    ("Orders, bookings, sessions and events", 3),
    ("Settings and contact configuration", 3),
    ("Listings, places and stores", 3),
], "tables", "What the 37 leaking tables held, by kind",
    "Of 37 leaking tables in 20 apps: 9 held other people's records, 8 user profiles, 6 messages or notifications, 5 leads or sign-ups, 3 orders or bookings, 3 settings, 3 listings or places.")


def stacked(parts, label, title, desc, total):
    """One 100% stacked bar, widths in %, with 2px gaps. parts: (name, value, cls)."""
    out = [f'<svg role="img" aria-labelledby="{label}-t {label}-d" width="100%" height="44" xmlns="http://www.w3.org/2000/svg">',
           f'<title id="{label}-t">{title}</title><desc id="{label}-d">{desc}</desc>',
           hatch(label)]
    x = 0.0
    for name, v, c in parts:
        w = 100 * v / total
        out.append(f'<svg x="{x:.3f}%" y="0" width="{w:.3f}%" height="44" overflow="visible"><rect class="mark {c}"{fillattr(c, label)} x="0" y="4" width="100%" height="36" rx="4"><title>{name}: {v} of {total}</title></rect></svg>')
        x += w
    # 2px surface gaps between segments
    x = 0.0
    for name, v, c in parts[:-1]:
        x += 100 * v / total
        out.append(f'<line x1="{x:.3f}%" x2="{x:.3f}%" y1="0" y2="44" stroke="var(--card)" stroke-width="3"/>')
    out.append('</svg>')
    return "\n".join(out)


WHO_BAR = stacked([("Anyone with the public key", 70, "m-red"), ("Anyone who signs up", 36, "m-redsoft"),
                   ("No personal data readable by the wrong people", 212, "m-faint")],
                  "who", "Who could read personal data, 318 rebuilt apps",
                  "70 apps (22%) to anyone with the public key, 36 (11%) only to signed-in users, 212 (67%) neither.", 318)
VERDICT_BAR = stacked([("Real bug", 28, "m-red"), ("Public by design, but leaking personal columns", 7, "m-redsoft"),
                       ("False alarm", 2, "m-faint")],
                      "verdict", "Agent verdicts on 37 leaking tables",
                      "28 real bugs, 7 public by design but leaking personal columns, 2 false alarms.", 37)
MODEL_BAR = stacked([("Smallest model (Haiku), first try", 15, "m-green"), ("Escalated to Sonnet", 2, "m-green"),
                     ("Escalated to Opus", 1, "m-green"), ("Needs a person", 2, "m-amber")],
                    "models", "Which model produced the passing fix, 20 apps",
                    "15 passed with the smallest model, 2 needed Sonnet, 1 needed Opus, 2 failed on all three and went to a person.", 20)


def bucket(vals, edges):
    out = []
    for lo, hi, name in edges:
        out.append((name, sum(1 for v in vals if lo <= v < hi)))
    return out


COST_B = bucket(costs, [(0, .5, "under $0.50"), (.5, 1, "$0.50 to $1"), (1, 3, "$1 to $3"), (3, 10, "$3 to $10"), (10, 1e9, "over $10")])
TIME_B = bucket(mins, [(0, 2, "under 2 min"), (2, 4, "2 to 4 min"), (4, 10, "4 to 10 min"), (10, 30, "10 to 30 min"), (30, 1e9, "over 30 min")])
assert [v for _, v in COST_B] == [14, 1, 3, 1, 1] and [v for _, v in TIME_B] == [4, 8, 3, 4, 1]


def btable(b, head):
    body = "".join(f'<tr><th scope="row">{n}</th><td class="num">{v}</td></tr>' for n, v in b)
    return (f'<div class="table-wrap"><table class="table compact"><thead><tr><th scope="col">{head}</th>'
            f'<th scope="col" class="num">Apps</th></tr></thead><tbody>{body}</tbody></table></div>')


def model_cell(x):
    parts = []
    for m in x["tried"]:
        parts.append(f"<b>{m} ✓</b>" if m == x["passed_on"] else f"<s>{m}</s>")
    return '<span class="models">' + " → ".join(parts) + "</span>"


RUN_ROWS = []
for i, x in enumerate(runs, 1):
    res = '<span class="pill proven">proven</span>' if x["passed_on"] else '<span class="pill pending">needs a person</span>'
    w = 100 * math.log(x["cost"] / 0.1) / math.log(20 / 0.1)
    RUN_ROWS.append(
        f'<tr><th scope="row">{i:02d}</th><td>{x["who"]}</td><td class="num">{x["tables"]}</td><td>{model_cell(x)}</td><td>{res}</td>'
        f'<td class="num">{money(x["cost"])}</td><td class="num">{x["minutes"]:.1f}</td><td class="num">{x["questions"]}</td><td>{x["risk"]}</td></tr>')
RUN_TABLE = "\n".join(RUN_ROWS)

# ---------------- CSV ----------------
buf = io.StringIO()
w = csv.writer(buf, lineterminator="\n")
w.writerow(["study", "date", "group", "metric", "value", "denominator", "unit", "notes"])
E = "exposure study (318 rebuilt repos)"
for row in [
    (E, "2026-11-05", "all", "repos_sampled", 500, "", "repos", "public GitHub repos with a Lovable/Supabase layout"),
    (E, "2026-11-05", "all", "repos_run_in_lab", 436, 500, "repos", ""),
    (E, "2026-11-05", "all", "repos_built_working_database", 318, 436, "repos", "the other 118 did not build in the lab and are excluded"),
    (E, "2026-11-05", "all", "personal_data_readable_by_wrong_people", 106, 318, "repos", "33%"),
    (E, "2026-11-05", "all", "readable_by_anyone_with_public_key", 70, 318, "repos", "22%"),
    (E, "2026-11-05", "all", "readable_only_by_signed_in_users", 36, 318, "repos", "11%, in addition to the 70"),
    (E, "2026-11-05", "all", "no_personal_data_readable_by_wrong_people", 212, 318, "repos", "derived: 318 - 106"),
    (E, "2026-11-05", "all", "adjusted_rate_low", 25, "", "percent", "after removing businesses' own public contact details"),
    (E, "2026-11-05", "all", "adjusted_rate_high", 28, "", "percent", "false-alarm rate taken from the fix study, n=24"),
]:
    w.writerow(row)
F5 = "fix-agent study (24 apps)"
for row in [
    (F5, "2026-11-05", "all", "apps_given_to_fix_agents", 24, "", "apps", "35 tables"),
    (F5, "2026-11-05", "all", "tables_confirmed_exposed_at_row_level", 35, 35, "tables", ""),
    (F5, "2026-11-05", "all", "false_alarms_caught_by_agent", 4, 24, "apps", "business's own public contact details"),
    (F5, "2026-11-05", "all", "real_fixes_worked_first_try_and_applied_cleanly", 19, 20, "fixes", "re-verified by us in the lab"),
    (F5, "2026-11-05", "all", "tables_closed_after_fix", 26, 35, "tables", "the other 9 left open on purpose"),
    (F5, "2026-11-05", "all", "fixes_safe_to_apply_with_no_human", 4, 20, "fixes", ""),
    (F5, "2026-11-05", "all", "apps_with_password_check_in_browser", 5, 20, "apps", "fake login: needs real auth, not a patch"),
    (F5, "2026-11-05", "all", "break_risk_high", 5, 20, "fixes", "agent's assessment"),
    (F5, "2026-11-05", "all", "break_risk_medium", 10, 20, "fixes", "agent's assessment"),
    (F5, "2026-11-05", "all", "break_risk_low", 5, 20, "fixes", "agent's assessment"),
    (F5, "2026-11-05", "all", "human_review_minutes_median", 15, "", "minutes", "agent's estimate"),
]:
    w.writerow(row)
P9 = "autonomous pipeline (20 new apps)"
summary = [
    ("apps", 20, "", "apps", "14 readable by anyone, 6 by any signed-up user"),
    ("passed_strict_lab_proof", 18, 20, "apps", "no human involved"),
    ("passed_on_smallest_model_first_try", 15, 20, "apps", "Haiku"),
    ("escalated_to_sonnet_and_passed", 2, 20, "apps", ""),
    ("escalated_to_opus_and_passed", 1, 20, "apps", ""),
    ("needs_a_person", 2, 20, "apps", "failed on all three models; no fix branch"),
    ("tables_flagged", 37, "", "tables", ""),
    ("verdict_real_bug", 28, 37, "tables", ""),
    ("verdict_public_by_design_but_leaky", 7, 37, "tables", ""),
    ("verdict_false_alarm", 2, 37, "tables", ""),
    ("questions_for_owner", 18, "", "questions", "across 20 apps"),
    ("break_risk_low", 18, 20, "apps", ""),
    ("break_risk_medium", 2, 20, "apps", ""),
    ("model_cost_median", round(S["cost_med"], 2), "", "usd", ""),
    ("model_cost_mean", round(S["cost_mean"], 2), "", "usd", "pulled up by one app"),
    ("model_cost_min", round(S["cost_min"], 2), "", "usd", ""),
    ("model_cost_max", round(S["cost_max"], 2), "", "usd", "escalated through all three models"),
    ("model_cost_median_smallest_model_passes", round(st.median(hq), 2), 15, "usd", ""),
    ("model_cost_max_smallest_model_passes", round(max(hq), 2), 15, "usd", ""),
    ("agent_minutes_median", round(S["min_med"], 1), "", "minutes", "agent working time summed across attempts"),
    ("agent_minutes_mean", round(S["min_mean"], 1), "", "minutes", ""),
    ("agent_minutes_min", round(S["min_min"], 1), "", "minutes", ""),
    ("agent_minutes_max", round(S["min_max"], 1), "", "minutes", ""),
]
for m, v, d, u, n in summary:
    w.writerow((P9, "2026-11-09", "all", m, v, d, u, n))
for n, v in COST_B:
    w.writerow((P9, "2026-11-09", "cost bucket " + n, "apps", v, 20, "apps", ""))
for n, v in TIME_B:
    w.writerow((P9, "2026-11-09", "time bucket " + n, "apps", v, 20, "apps", ""))
for i, x in enumerate(runs, 1):
    g = f"run {i:02d}"
    for m, v, u in [("who_could_read", x["who"], ""), ("tables_flagged", x["tables"], "tables"),
                    ("models_tried", " > ".join(x["tried"]), ""), ("passed_on", x["passed_on"] or "none", ""),
                    ("result", "proven" if x["passed_on"] else "needs a person", ""),
                    ("model_cost", round(x["cost"], 2), "usd"), ("agent_minutes", round(x["minutes"], 1), "minutes"),
                    ("questions_for_owner", x["questions"], "questions"), ("break_risk", x["risk"], "")]:
        w.writerow((P9, "2026-11-09", g, m, v, "", u, "runs ordered by cost; no app identifiers"))
os.makedirs(os.path.join(SITE, "static/research"), exist_ok=True)
csv_text = buf.getvalue()
open(os.path.join(SITE, "static/research/1-in-4-aggregate.csv"), "w").write(csv_text)
CSV_ROWS = csv_text.count("\n") - 1

tpl = open(os.path.join(HERE, "report_tpl.html")).read()
for k, v in dict(FUNNEL=FUNNEL, TABLES=TABLES, WHO_BAR=WHO_BAR, VERDICT_BAR=VERDICT_BAR, MODEL_BAR=MODEL_BAR,
                 COST_STRIP=COST_STRIP, TIME_STRIP=TIME_STRIP, RUN_TABLE=RUN_TABLE, COST_BTABLE=btable(COST_B, "Model cost"),
                 TIME_BTABLE=btable(TIME_B, "Agent time"), CSV_ROWS=str(CSV_ROWS),
                 CSV_KB=f"{len(csv_text.encode()) / 1024:.0f}").items():
    tpl = tpl.replace("{{" + k + "}}", v)
assert "{{" not in tpl, tpl[tpl.index("{{"):tpl.index("{{") + 40]
os.makedirs(os.path.join(SITE, "pages/research"), exist_ok=True)
open(os.path.join(SITE, "pages/research/1-in-4.html"), "w").write(tpl)
print("ok", CSV_ROWS, "csv rows;", dict(COST_B), dict(TIME_B))

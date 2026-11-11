"""Generates site/pages/for/*.html (builder pages). Run from anywhere: python3 tools/gen/builders.py
(PL_GEN_ROOT=<dir> writes into <dir>/site/... instead of this repo, for diffing.)"""
import sys, os

ROOT = os.environ.get("PL_GEN_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "site", "pages", "for")

STUDY_LS = """<div class="stats mt-3" style="--cols:3">
        <div class="stat"><b class="num">318</b><span>public Lovable and Supabase apps rebuilt<sup class="fn"><a href="#fn1" aria-label="Footnote 1">1</a></sup></span></div>
        <div class="stat red"><b class="num">106</b><span>let the wrong people read personal data<sup class="fn"><a href="#fn1" aria-label="Footnote 1">1</a></sup></span></div>
        <div class="stat"><b class="num">1<small>in 4</small></b><span>exposed real personal data<sup class="fn"><a href="#fn1" aria-label="Footnote 1">1</a></sup></span></div>
      </div>
      <ol class="footnotes"><li id="fn1">PatchLabs lab study, Nov 2026. 436 public Lovable and Supabase repos run (from a random sample of 500); 318 built a working database in the lab. 106 of 318 (33%): 70 to anyone with the public key, 36 to anyone who signs up. About 1 in 4 (25–28%) after removing businesses’ own public contact details. The study doesn’t separate Lovable from other Supabase projects. <a href="/research/methodology">Methodology</a>.</li></ol>"""

NO_STUDY = """<div class="callout note mt-3"><p><strong>No {name}-specific numbers yet.</strong> Our study sampled public Lovable and Supabase repos, so we don’t publish figures for {name} apps. The access rules work the same way on any Supabase database, which is what we test.</p></div>"""

FIX_SQL = """<div class="code mb-0">
        <div class="code-bar"><span class="name">{title}</span><button class="copy" type="button" data-copy>Copy</button></div>
<pre class="wrap-lines"><code>{body}</code></pre>
      </div>"""

PAGES = {
  "lovable": dict(
    name="Lovable", nav="", title="PatchLabs for Lovable apps: find and fix data leaks",
    desc="Check a Lovable app's Supabase database for personal data strangers can read. PatchLabs rebuilds it from the GitHub repo, writes the fix and proves it. Free for one app.",
    lab="For Lovable apps",
    h1="Built it in Lovable? Check who else can read its data.",
    lede="Lovable apps usually keep their database rules in <code>supabase/migrations</code> in the connected GitHub repo. We rebuild that database in a lab, read it as a stranger, and hand you a fix that has already passed the proof.",
    art="""<pre class="tree" aria-label="Typical layout of a Lovable repo">your-lovable-app/
├─ src/
│  ├─ integrations/supabase/
│  │  └─ client.ts   <span class="dim">public key, by design</span>
│  └─ pages/
└─ <span class="hl">supabase/</span>
   └─ <span class="hl">migrations/</span>    <span class="dim">← we rebuild from here</span>
      ├─ …_init.sql
      └─ …_profiles.sql</pre>""",
    artcap="A typical layout. Yours may differ; what matters is the <code>supabase/migrations</code> folder.",
    works=["Your project is connected to GitHub through Lovable’s GitHub integration", "The repo is public (private repos come with our GitHub App)", "The database is Supabase, with a <code>supabase/migrations</code> folder"],
    notyet=["Private repos, until our GitHub App ships", "Database changes that exist only in Supabase and never reached a migration file", "Anything outside the database rules, such as edge functions"],
    pattern_h="The rule that says “everyone can read profiles”.",
    pattern_p="A common way a Lovable app leaks: a read policy written so the profile page works for everyone, on a table that also holds emails and phone numbers. Anyone with the app’s public key can then read every row. The fix keeps what the app needs and closes the rest.",
    sql_title="the pattern, and the proven fix (our demo app)",
    sql='''<span class="c">-- before: anyone with the public key reads every profile</span>
<span class="del">create policy "Profiles are viewable by everyone"</span>
<span class="del">  on public.profiles for select using (true);</span>

<span class="c">-- after: each user reads only their own profile</span>
<span class="add">create policy "Users can view own profile"</span>
<span class="add">  on public.profiles for select using (auth.uid() = user_id);</span>''',
    study=STUDY_LS,
    lands_intro="Lovable syncs both ways with your GitHub repo, so a file committed on GitHub shows up in your Lovable project. Whether Lovable then applies a new migration file to your database automatically is something we haven’t verified for every setup, so check Lovable’s docs and confirm the result.",
    lands=[("Get the fix", "Download the migration from your report, or use “Commit this file on GitHub”."),
           ("Apply it to the database", "Depending on your setup: let Lovable apply it, paste the SQL into your Supabase project’s SQL editor, or ask Lovable’s agent to apply that migration. If your project uses Lovable Cloud rather than a Supabase project you connected yourself, check Lovable’s docs for how database changes are applied."),
           ("Make sure the repo matches", "If you applied the SQL by hand, keep the migration file in the repo too, so the next change builds on it."),
           ("Re-check", "Run the check again. It confirms the leak is closed in what the repo now describes.")],
    faq=[("Isn’t Lovable’s own security scan enough?", "Use it: it’s built in and catches common problems. It tells you a rule looks risky. We rebuild the database, test as an anonymous visitor, a signed-in stranger and the owner, and prove the fix before you apply it. They work well together. <a href=\"/compare\">Comparisons</a>."),
         ("Do you need access to my Lovable account or Supabase project?", "No. We only read the public GitHub repo. We never ask for your Supabase password or service-role key, and checks never connect to your live app or database."),
         ("My repo is private. What can I do?", "Private repos need our GitHub App, which is coming. If you’d rather not make the repo public, <a href=\"mailto:manraj@patchlabs.dev?subject=Private%20repo\">email us</a> and we’ll tell you when it’s ready."),
         ("Will the fix break my app?", "Every fix must keep the owner reading their own rows, and the report includes a risk note about anything that could behave differently, such as a logged-out page that relied on the old rule. Read it before you apply."),
         ("Is PatchLabs part of Lovable?", "No. PatchLabs is independent and not affiliated with Lovable. We work with apps built on Lovable because their code lives in GitHub.")]),

  "supabase": dict(
    name="Supabase", nav="", title="PatchLabs for Supabase apps: RLS tested as a stranger",
    desc="PatchLabs rebuilds your Supabase database from supabase/migrations, tests RLS as anon, a signed-in stranger and the owner, and proves the fix. Free for one app.",
    lab="For Supabase apps",
    h1="Your row level security, tested as a stranger.",
    lede="Supabase gives <code>anon</code> and <code>authenticated</code> access to new tables in <code>public</code> by default, so your RLS policies are the only thing standing between your public key and your rows. We rebuild your database from <code>supabase/migrations</code> and test those policies as three different people.",
    art="""<div class="code dark mb-0">
        <div class="code-bar"><span class="name">applying a PatchLabs fix with the Supabase CLI</span><button class="copy" type="button" data-copy>Copy</button></div>
<pre class="wrap-lines"><code><span class="c"># put the migration from your report in the repo</span>
mv ~/Downloads/*_patchlabs_leak_fix.sql supabase/migrations/

<span class="c"># see which migrations the linked project has applied</span>
supabase migration list

<span class="c"># apply the pending ones to the linked project</span>
supabase db push</code></pre>
      </div>""",
    artcap="Standard Supabase CLI commands. Review the migration before you push it.",
    works=["Your schema lives in <code>supabase/migrations</code> in a public GitHub repo", "Access control uses RLS with <code>auth.uid()</code> and JWT claims", "Personal data sits in tables in the <code>public</code> schema"],
    notyet=["Schema changes made only in the dashboard and never pulled into a migration", "Custom auth that doesn’t go through Supabase Auth claims", "Storage policies and edge functions, which aren’t proven in the lab"],
    pattern_h="Three ways RLS lets the wrong person in.",
    pattern_p="RLS never enabled on a table (with the default grants, it’s readable through the API). A policy that’s always true. And a policy that checks someone is signed in instead of checking the row is theirs, so one free sign-up unlocks everyone’s data. We test for the effect of all three, not just their shape.",
    sql_title="signed in is not the same as “owns this row”",
    sql='''<span class="c">-- before: any signed-in user reads every order</span>
<span class="del">create policy "Signed-in users can read orders"</span>
<span class="del">  on public.orders for select</span>
<span class="del">  using (auth.role() = 'authenticated');</span>

<span class="c">-- after: users read only their own orders</span>
<span class="add">create policy "Users read own orders"</span>
<span class="add">  on public.orders for select to authenticated</span>
<span class="add">  using (auth.uid() = user_id);</span>''',
    study=STUDY_LS,
    lands_intro="The fix is a normal Supabase migration, timestamped to run after your existing ones. Ship it exactly as you ship any other migration.",
    lands=[("Add it to supabase/migrations", "Download it from the report, or use “Commit this file on GitHub” to open GitHub’s new-file page with the path and SQL filled in."),
           ("Apply it", "With the CLI, <code>supabase db push</code> applies pending migrations to your linked project. If you use Supabase’s GitHub integration with branching, it can run migrations from your repo; check your project’s settings and Supabase’s docs for when that happens."),
           ("Or paste it, then commit it", "Running the SQL in the dashboard’s SQL editor works too. Commit the file as well, so your repo and database stay in step."),
           ("Re-check", "Run the check again, or let the schedule do it.")],
    faq=[("How is this different from the Security Advisor?", "The Advisor lints your live project’s configuration, and it covers health and performance too. Keep using it. We rebuild the database from your repo and test behaviour as real identities, then prove a fix. <a href=\"/product/leak-lab\">How our finding IDs map to its lints</a>."),
         ("Do you need my service-role key or database password?", "No. We never connect to your project. Everything runs on a disposable copy built from your migrations."),
         ("What do you seed?", "Fake rows owned by two test users, with fake values such as <code>x@example.com</code> in required columns. No real data, ever."),
         ("Can a fix use views or column grants instead of policies?", "Yes. Rows and personal columns are tested separately, so a fix that keeps a table publicly readable but hides its personal columns can pass."),
         ("Are you affiliated with Supabase?", "No. PatchLabs is independent. We copy Supabase’s default roles and grants in our lab so the test matches how Supabase behaves.")]),

  "bolt": dict(
    name="Bolt", nav="", title="PatchLabs for Bolt apps: find and fix Supabase data leaks",
    desc="Built with Bolt and Supabase? PatchLabs rebuilds your database from the GitHub repo, finds personal data strangers can read, and proves the fix. Free for one app.",
    lab="For Bolt apps",
    h1="Built with Bolt and Supabase? Check who can read its data.",
    lede="If your Bolt project uses Supabase and its migrations are in a public GitHub repo, we can rebuild the database in a lab, read it as a stranger, and hand you a proven fix.",
    art="""<pre class="tree" aria-label="What we need in a Bolt project's repo">your-bolt-app/
├─ src/
├─ package.json
└─ <span class="hl">supabase/</span>
   └─ <span class="hl">migrations/</span>    <span class="dim">← what we need</span>
      └─ …_create_tables.sql</pre>""",
    artcap="What we look for. If there’s no <code>supabase/migrations</code> folder in the repo, we can’t rebuild the database yet.",
    works=["The project uses Supabase", "Its migrations are in <code>supabase/migrations</code> in a public GitHub repo", "Personal data lives in database tables protected by RLS"],
    notyet=["Projects whose database changes aren’t in the repo as migration files", "Private repos, until our GitHub App ships", "Non-Supabase databases"],
    pattern_h="The same Supabase rules, the same ways to leak.",
    pattern_p="A Bolt app on Supabase is protected by the same row level security as any other. The usual leaks: a table with RLS switched off, a read policy that is always true, or one that lets any signed-in user read every row.",
    sql_title="RLS never enabled: readable through the API",
    sql='''<span class="c">-- before: RLS was never switched on for this table</span>
<span class="c">-- (with Supabase's default grants, anyone with the key can read it)</span>

<span class="c">-- after: RLS on, owners read their own rows</span>
<span class="add">alter table public.customers enable row level security;</span>
<span class="add">create policy "Owners read own customer records"</span>
<span class="add">  on public.customers for select to authenticated</span>
<span class="add">  using (auth.uid() = owner_id);</span>''',
    study=NO_STUDY.format(name="Bolt"),
    lands_intro="How a new migration file reaches your database depends on how your Bolt project is connected to Supabase. We haven’t verified Bolt’s behaviour for every setup, so check your platform’s docs.",
    lands=[("Get the fix", "Download the migration from your report, or commit it on GitHub in one click."),
           ("Apply it to your Supabase database", "Paste the SQL into your Supabase project’s SQL editor, use <code>supabase db push</code> if you work with the Supabase CLI, or ask Bolt to apply the migration. Check your platform’s docs for which applies to you."),
           ("Keep the file in the repo", "So the next change Bolt makes builds on the fixed rules."),
           ("Re-check", "Run the check again to confirm the leak is closed.")],
    faq=[("My Bolt project doesn’t have a supabase/migrations folder.", "Then we can’t rebuild the database yet. The key scan still runs on your code and history. <a href=\"mailto:manraj@patchlabs.dev?subject=Bolt%20project\">Tell us</a> how your project is set up and we’ll see what we can do."),
         ("Do you need access to my Bolt account?", "No. Checks only read the public GitHub repo and never connect to your live app or database."),
         ("Will the fix break my app?", "A fix only passes if the owner can still read their own rows. The report also includes a risk note about anything that could behave differently."),
         ("Is PatchLabs part of Bolt?", "No. PatchLabs is independent and not affiliated with Bolt or StackBlitz.")]),

  "replit": dict(
    name="Replit", nav="", title="PatchLabs for Replit apps: what we can check today",
    desc="If your Replit app uses Supabase with migrations in GitHub, PatchLabs can rebuild its database, find data strangers can read and prove the fix. Here is what works today.",
    lab="For Replit apps",
    h1="On Replit with Supabase? We can test it. Here’s what fits.",
    lede="Many Replit apps use Replit’s own database instead of Supabase. We test Supabase row level security, so here’s how to tell whether your app fits before you paste anything.",
    art="""<div class="fit" style="grid-template-columns:minmax(0,1fr)">
        <div><h3>Fits: Supabase from a Replit app</h3><p class="small muted mb-0">Your app talks to Supabase, and the schema is in <code>supabase/migrations</code> in a public GitHub repo. The leak lab and the key scan both run.</p></div>
        <div><h3>Not yet: Replit’s built-in database</h3><p class="small muted mb-0">No Supabase migrations to rebuild from, so the leak lab can’t run. The key scan of your code and git history still does.</p></div>
      </div>""",
    artcap="Not sure which you use? Look for a <code>supabase/migrations</code> folder in your repo.",
    works=["The app uses Supabase, with its schema in <code>supabase/migrations</code>", "The code is pushed to a public GitHub repo, for example from Replit’s Git pane", "Access control uses Supabase RLS"],
    notyet=["Apps on Replit’s built-in database or another backend", "Private repos, until our GitHub App ships", "API routes and server code that decide who sees what"],
    pattern_h="Where the leak lives depends on your database.",
    pattern_p="With Supabase, the browser often reads the database directly with the public key, so RLS policies decide who sees what, and that’s what we test. With a server-side database, your API routes make that decision instead. We don’t test API routes yet, so we won’t pretend to.",
    sql_title="a Supabase policy that only checks sign-in",
    sql='''<span class="c">-- before: anyone who signs up reads every booking</span>
<span class="del">create policy "Authenticated can read bookings"</span>
<span class="del">  on public.bookings for select to authenticated using (true);</span>

<span class="c">-- after: users read their own bookings only</span>
<span class="add">create policy "Users read own bookings"</span>
<span class="add">  on public.bookings for select to authenticated</span>
<span class="add">  using (auth.uid() = user_id);</span>''',
    study=NO_STUDY.format(name="Replit"),
    lands_intro="For a Replit app on Supabase, the fix is applied to your Supabase project, not to Replit. How your deployment picks up schema changes is something to check in your platform’s docs.",
    lands=[("Get the fix", "Download the migration from your report, or commit it on GitHub in one click."),
           ("Apply it to Supabase", "Paste the SQL into your Supabase project’s SQL editor, or use <code>supabase db push</code> if you work with the Supabase CLI."),
           ("Pull the change into Replit", "Keep the migration file in your repo and pull it into your Repl, so future changes build on it."),
           ("Re-check", "Run the check again to confirm the leak is closed.")],
    faq=[("My Replit app uses Replit’s database. Can you check it at all?", "The key scan runs on any public repo, so exposed AI, payment and database keys in your code and git history are still found. The leak lab needs Supabase migrations, so it can’t run on that app yet."),
         ("How do I get my Repl onto GitHub?", "Replit has Git built in, so you can connect a GitHub repo and push. Check Replit’s docs for the current steps."),
         ("Do you need access to my Replit account?", "No. We only read the public GitHub repo."),
         ("Is PatchLabs part of Replit?", "No. PatchLabs is independent and not affiliated with Replit.")]),

  "cursor": dict(
    name="Cursor", crumb="Cursor projects", nav="", title="PatchLabs for Cursor projects: prove your migrations don't leak",
    desc="Cursor writes your Supabase migrations; PatchLabs rebuilds the database from them, tests RLS as three identities and proves each fix. Free for one app.",
    lab="For Cursor projects",
    h1="Cursor writes your migrations. We prove they don’t leak.",
    lede="Your code is already in git, and your schema is already in <code>supabase/migrations</code>. That’s exactly what we need: we rebuild the database, test who can read what, and hand back a migration your normal review process can take.",
    art="""<div class="code dark mb-0">
        <div class="code-bar"><span class="name">.cursor/mcp.json</span><button class="copy" type="button" data-copy>Copy</button></div>
<pre class="wrap-lines"><code>{
  <span class="s">"mcpServers"</span>: {
    <span class="s">"patchlabs"</span>: {
      <span class="s">"url"</span>: <span class="s">"https://api.patchlabs.dev/mcp"</span>
    }
  }
}</code></pre>
      </div>""",
    artcap="Optional: add the PatchLabs MCP server so your agent can run the free RLS check and start a full check. <a href=\"/docs/mcp\">Setup guide</a>.",
    works=["Your project uses Supabase with migrations in <code>supabase/migrations</code>", "The repo is public on GitHub (private repos come with our GitHub App)", "Access control uses RLS with Supabase Auth"],
    notyet=["Backends without Supabase migrations, such as an ORM on another database", "Checking a pull request before it merges (needs our GitHub App)", "API routes and server code"],
    pattern_h="A policy that looks right and still leaks.",
    pattern_p="AI assistants are good at writing a policy that makes the feature work. The typical miss: a rule that lets the signed-in user through without checking the row is theirs, or an UPDATE policy with no <code>with check</code>. The lab catches the first by reading as a stranger; the free RLS check flags the second.",
    sql_title="the fix arrives as a migration you review",
    sql='''<span class="c">-- after: owner-only reads, and owners can't reassign rows</span>
<span class="add">create policy "Users read own notes"</span>
<span class="add">  on public.notes for select to authenticated</span>
<span class="add">  using (auth.uid() = user_id);</span>
<span class="add">create policy "Users update own notes"</span>
<span class="add">  on public.notes for update to authenticated</span>
<span class="add">  using (auth.uid() = user_id)</span>
<span class="add">  with check (auth.uid() = user_id);</span>''',
    study=NO_STUDY.format(name="Cursor"),
    lands_intro="Cursor is your editor, so the fix lands the way every migration in your project already does.",
    lands=[("Pull it into your branch", "Download the migration, or commit it on GitHub in one click, then pull."),
           ("Review it like any change", "The report shows the proof for each identity and a risk note. Ask Cursor to explain anything you’re unsure about."),
           ("Ship it your usual way", "<code>supabase db push</code>, your CI, or Supabase’s GitHub integration if you use it."),
           ("Re-check after the merge", "From the dashboard, on a schedule, or from CI with an API key. <a href=\"/product/monitoring\">Monitoring</a>.")],
    faq=[("Does the MCP server cost anything?", "The free RLS check and starting a check work without an account. Listing and running checks for monitored apps needs your workspace API key. <a href=\"/docs/mcp\">MCP docs</a>."),
         ("Will Cursor’s agent see my findings?", "Only if you add the MCP server and ask it to check. Reports are otherwise shared by link."),
         ("Do you run my code?", "No. The lab only applies the SQL in your migrations; nothing from your repo is executed."),
         ("Is PatchLabs part of Cursor?", "No. PatchLabs is independent and not affiliated with Cursor or Anysphere.")]),
}

OTHERS = [("lovable", "Lovable"), ("supabase", "Supabase"), ("bolt", "Bolt"), ("replit", "Replit"), ("cursor", "Cursor")]


GUIDES = {
    "lovable": [("is-my-lovable-app-secure", "Is my Lovable app secure? Six checks in 10 minutes"), ("is-supabase-anon-key-safe", "Is it safe to expose the Supabase anon key?"), ("ai-builder-scan-vs-independent-check", "Your builder’s scan vs an independent check")],
    "supabase": [("check-supabase-rls-every-table", "Check RLS is on for every Supabase table"), ("is-supabase-anon-key-safe", "Is it safe to expose the Supabase anon key?"), ("rls-policies-explained", "Supabase RLS policies explained")],
    "bolt": [("bolt-replit-app-security", "How to secure an app built with Bolt or Replit"), ("vibe-coding-security-risks", "Security risks of vibe-coded apps, with data"), ("ai-builder-scan-vs-independent-check", "Your builder’s scan vs an independent check")],
    "replit": [("bolt-replit-app-security", "How to secure an app built with Bolt or Replit"), ("vibe-coding-security-risks", "Security risks of vibe-coded apps, with data"), ("check-supabase-rls-every-table", "Check RLS is on for every Supabase table")],
    "cursor": [("vibe-coding-security-risks", "Security risks of vibe-coded apps, with data"), ("check-supabase-rls-every-table", "Check RLS is on for every Supabase table"), ("is-supabase-anon-key-safe", "Is it safe to expose the Supabase anon key?")],
}


def page(slug, d):
    works = "".join(f"<li><span>{w}</span></li>" for w in d["works"])
    notyet = "".join(f'<li class="x"><span>{w}</span></li>' for w in d["notyet"])
    lands = "".join(f"<li><h3>{h}</h3><p>{p}</p></li>" for h, p in d["lands"])
    faq = "\n      ".join(f'<details class="acc"><summary>{q}</summary><div class="acc-body"><p>{a}</p></div></details>' for q, a in d["faq"])
    others = "".join(f'<a class="link-arrow" href="/for/{s}">{n} apps</a>' for s, n in OTHERS if s != slug)
    sql = FIX_SQL.format(title=d["sql_title"], body=d["sql"])
    guides = "".join(f'<li><a href="/learn/{g}">{t}</a></li>' for g, t in GUIDES.get(slug, []))
    return f"""<!--
title: {d['title']} | PatchLabs
description: {d['desc']}
layout: marketing
nav: for_{slug}
head: <link rel="stylesheet" href="/assets/pages/A-product.css">
-->
<main id="main">

<section class="hero p-hero">
  <div class="wrap hero-grid">
    <div>
      <nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">Home</a></li><li aria-current="page">{d.get("crumb", d["name"] + " apps")}</li></ol></nav>
      <p class="lab">{d['lab']}</p>
      <h1>{d['h1']}</h1>
      <p class="lede">{d['lede']}</p>
      <form class="repo-form stacked" data-check-form action="mailto:manraj@patchlabs.dev?subject=Free%20leak%20check" method="post" enctype="text/plain">
        <div class="in"><label class="sr-only" for="repo-{slug}">Public GitHub repo</label><input id="repo-{slug}" name="repo" required autocomplete="off" spellcheck="false" placeholder="github.com/you/your-app"></div>
        <div class="in"><label class="sr-only" for="email-{slug}">Your email</label><input id="email-{slug}" name="email" type="email" required autocomplete="email" placeholder="you@company.com"></div>
        <button class="btn primary" type="submit">Check my app free</button>
      </form>
      <p class="err" role="alert" data-err></p>
      <div class="form-meta"><span>Free in early access, fixes included</span><span>Reads your public repo only</span><span><a href="/sample-report">See a sample report</a></span></div>
      <p class="indep">Independent: PatchLabs is not affiliated with {d['name']}.</p>
    </div>
    <figure class="figure">
      {d['art']}
      <figcaption>{d['artcap']}</figcaption>
    </figure>
  </div>
</section>

<section class="sec band" aria-labelledby="fit-h">
  <div class="wrap">
    <div class="sec-head">
      <p class="lab">Will it work?</p>
      <h2 id="fit-h">Check this before you paste your repo.</h2>
    </div>
    <div class="fit">
      <div><h3>Works today when</h3><ul class="ticks compact mb-0">{works}</ul></div>
      <div><h3>Not covered yet</h3><ul class="ticks compact mb-0">{notyet}</ul></div>
    </div>
  </div>
</section>

<section class="sec" aria-labelledby="pat-h">
  <div class="wrap split top">
    <div>
      <p class="lab red">The common leak</p>
      <h2 id="pat-h">{d['pattern_h']}</h2>
      <p class="lede">{d['pattern_p']}</p>
      {d['study']}
    </div>
    <div>
      {sql}
      <p class="small muted mt-2">Illustrative SQL. Your report contains the real migration for your tables, and it only counts as proven once the anonymous visitor and the signed-in stranger are denied and the owner still reads their own rows.</p>
    </div>
  </div>
</section>

<section class="sec band" aria-labelledby="land-h">
  <div class="wrap split top">
    <div>
      <p class="lab">How the fix lands</p>
      <h2 id="land-h">From proven fix to your live app.</h2>
      <p class="lede">{d['lands_intro']}</p>
      <div class="callout limit mt-3"><p>We never push to your repo or touch your database. Nothing changes until you, or your engineer, applies the migration. Automatic pull requests need our GitHub App, which is coming.</p></div>
    </div>
    <ol class="steps">{lands}</ol>
  </div>
</section>

<section class="sec" aria-labelledby="faq-h">
  <div class="wrap split top">
    <div>
      <p class="lab">Questions</p>
      <h2 id="faq-h">{d['name']} questions.</h2>
      <p class="muted">Something else? <a href="mailto:manraj@patchlabs.dev">Email the founder</a>.</p>
      <div class="other-builders mt-3" aria-label="Other builders">{others}</div>
      <h3 class="h4 mt-4">Guides</h3>
      <ul class="small">{guides}</ul>
    </div>
    <div>
      {faq}
    </div>
  </div>
</section>

<section class="sec tight" aria-labelledby="final-h">
  <div class="wrap">
    <div class="cta-panel">
      <p class="lab">Free check</p>
      <h2 id="final-h">Can a stranger read your users table? Find out in minutes.</h2>
      <p class="lede">You’ll get the leaks, the fix and the proof on one page. <a href="/how-it-works">How it works</a>.</p>
      <div class="row center" style="justify-content:center"><a class="btn primary large" href="#repo-{slug}">Check my app free</a><a class="btn secondary large" href="/sample-report">See a sample report</a></div>
    </div>
  </div>
</section>

</main>
"""


os.makedirs(OUT, exist_ok=True)
for slug, d in PAGES.items():
    open(os.path.join(OUT, slug + ".html"), "w").write(page(slug, d))
    print("wrote", slug)

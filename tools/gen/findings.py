#!/usr/bin/env python3
"""Generates site/pages/findings/pl-0xx.html for the PatchLabs finding taxonomy (group B).
Mini formats:
  sql(text): lines starting '+ ' -> added, '! ' -> removed, '--' -> comment. Text is HTML-escaped.
  tr(lines): proof transcript; {STEP:NAME} step label, {anon} {stranger} {owner} {admin} identities,
             {LEAK} {DENIED} {OK} tokens, lines starting '~' are dim.
"""
import html, os, re

from builder_prompts import prompt_for, retest_for

ROOT = os.environ.get("PL_GEN_ROOT") or os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
OUT = os.path.join(ROOT, "site", "pages", "findings")
REVIEWED = "10 Nov 2026"


def esc(s):
    return html.escape(s, quote=False)


def sql(text, name, lang_note=None):
    rows = []
    for line in text.strip("\n").split("\n"):
        if line.startswith("+ "):
            rows.append(f'<span class="add">{esc(line[2:])}</span>')
        elif line.startswith("! "):
            rows.append(f'<span class="del">{esc(line[2:])}</span>')
        elif line.lstrip().startswith(("--", "#", "//")):
            rows.append(f'<span class="c">{esc(line)}</span>')
        else:
            # trailing comments
            m = re.match(r"^(.*?)(\s+--\s.*)$", line)
            if m and "'" not in m.group(2):
                rows.append(esc(m.group(1)) + f'<span class="c">{esc(m.group(2))}</span>')
            else:
                rows.append(esc(line))
    body = "\n".join(rows)
    return (f'<div class="code">\n  <div class="code-bar"><span class="name">{esc(name)}</span>'
            f'<button class="copy" type="button" data-copy>Copy</button></div>\n'
            f'<pre class="wrap-lines"><code>{body}</code></pre>\n</div>')


TOK = {"LEAK": '<span class="leak">LEAK</span>', "DENIED": '<span class="deny">DENIED</span>', "OK": '<span class="ok">OK</span>',
       "FLAG": '<span class="step">FLAG</span>'}  # FLAG: a Live posture finding (amber): a missing header is not a data leak


def tr(title, lines, foot):
    out = []
    for raw in lines:
        dim = raw.startswith("^")
        s = esc(raw[1:] if raw[:1] in "~^" else raw)
        s = re.sub(r"\{STEP:([A-Z]+)\}", lambda m: f'<span class="step">[{m.group(1)}]</span>', s)
        for who in ("anon", "stranger", "owner", "admin"):
            s = s.replace("{" + who + "}", f'<span class="k">{who}</span>')
        for k, v in TOK.items():
            s = s.replace("{" + k + "}", v)
        s = s.replace("{RED}", '<span class="redact">').replace("{/RED}", "</span>")
        s = s.replace("{DONE}", '<span class="done">').replace("{/DONE}", "</span>")
        out.append(f'<span class="ln"><span class="dim">{s}</span></span>' if dim else f'<span class="ln">{s}</span>')
    return ('<div class="window">\n  <div class="window-bar"><span class="lights" aria-hidden="true"><i></i><i></i><i></i></span>'
            f'<span class="title">{esc(title)}</span></div>\n'
            '<pre class="transcript lines">\n' + "\n".join(out) + '\n</pre>\n'
            f'  <div class="window-foot">{foot}</div>\n</div>')


def hosts(pid, tabs):
    """Fix snippets per hosting platform, as the tabs component. tabs: [(key, label, html)]. Ids are unique per page
    (pid is the finding number). Without JS every panel shows with its own heading."""
    btns = "".join(f'<button role="tab" id="t-{pid}-{k}" aria-controls="p-{pid}-{k}" aria-selected="{"true" if i == 0 else "false"}">{esc(lbl)}</button>'
                   for i, (k, lbl, _) in enumerate(tabs))
    panels = "\n".join(f'<div class="tab-panel" id="p-{pid}-{k}" role="tabpanel" aria-labelledby="t-{pid}-{k}"><h3 class="tab-title">{esc(lbl)}</h3>\n{h}\n</div>'
                       for k, lbl, h in tabs)
    return f'<div class="tabs f-hosts">\n<div role="tablist" aria-label="Where your site is hosted">{btns}</div>\n{panels}\n</div>'


SEV = {"critical": ("sev-critical", "crit"), "high": ("sev-high", "high"), "medium": ("sev-medium", "med"), "low": ("sev-low", "low"),
       "info": ("sev-low", "low"),
       "high to low": ("sev-high", "high"), "high or medium": ("sev-high", "high"), "from advisory": ("plain", "low")}

F = []

# ------------------------------------------------------------------ PL-001
F.append(dict(
    id="PL-001", slug="pl-001", group="data",
    title="Anonymous visitor can read personal data",
    short="Anyone with your app's public key can read emails, phone numbers or addresses.",
    desc="PL-001: a Supabase table with personal data has a read policy that lets anonymous visitors in. How to check it, the SQL fix PatchLabs writes, and the proof.",
    sev="critical", who="Anyone on the internet", found="Free RLS check (static) and the full lab check",
    proof="Automatic: anon, stranger and owner reads",
    what="""<p>Every Supabase app ships a public key (the <code>anon</code> key) inside its web pages. That is by design: the key is meant to be public, and row level security (RLS) policies decide what it can read. PL-001 means a table holding personal data, such as emails, phone numbers, addresses or dates of birth, has a read policy that lets the <code>anon</code> role through without checking who is asking.</p>
<p>Nobody needs to break in. Anyone who opens your site can copy the key from the page and ask the database for every row. The usual cause is a policy written as <code>using (true)</code> with no <code>to</code> clause, which applies to every role, including logged-out visitors.</p>""",
    vuln=sql("""create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text,
  email text,
  phone text
);
alter table public.profiles enable row level security;

-- No "to" clause: this applies to every role, including anon.
create policy "Profiles are viewable by everyone"
  on public.profiles for select
  using (true);""", "supabase/migrations/…_create_profiles.sql (vulnerable)"),
    check="""<p>Run these in the Supabase SQL editor of your own project. The second query reads the table exactly as a logged-out visitor would, inside a transaction that is rolled back, so nothing changes.</p>""" +
    sql("""-- 1. Read policies that apply to logged-out visitors and don't check the user
select tablename, policyname, roles, qual
from pg_policies
where schemaname = 'public'
  and cmd in ('SELECT', 'ALL')
  and roles && array['anon', 'public']::name[]
  and coalesce(qual, '') not ilike '%auth.uid()%';

-- 2. Read a table as an anonymous visitor (nothing is changed)
begin;
set local role anon;
select count(*) from public.profiles;  -- more than 0 means anyone can read it
rollback;""", "check-pl-001.sql") +
    """<p class="small muted">Tables with RLS switched off never appear in <code>pg_policies</code>. Check those with <a href="/findings/pl-008">PL-008</a>.</p>""",
    fix="""<p>When the rows belong to individual users, PatchLabs replaces the open policy with an owner-only one. Using <code>(select auth.uid())</code> rather than <code>auth.uid()</code> lets Postgres evaluate it once per query instead of once per row.</p>""" +
    sql("""-- supabase/migrations/<timestamp>_patchlabs_leak_fix.sql
! drop policy "Profiles are viewable by everyone" on public.profiles;
+ create policy "Users can view own profile"
+   on public.profiles for select
+   to authenticated
+   using ((select auth.uid()) = id);""", "supabase/migrations/…_patchlabs_leak_fix.sql") +
    """<p>When a public page genuinely needs some columns (a profile page showing a name and avatar), the fix keeps the rows readable and withholds the personal columns from logged-out visitors:</p>""" +
    sql("""-- Visitors keep the public columns; contact details are withheld.
revoke select on public.profiles from anon;
grant select (id, full_name) on public.profiles to anon;
-- The app must now ask for those columns by name: select('id, full_name').
-- select('*') will fail for logged-out visitors, so the report lists that code change.""", "alternative: hide personal columns") +
    """<p class="small muted">Signed-in users are a separate question. If anyone can sign up, see <a href="/findings/pl-002">PL-002</a>.</p>""",
    proof_tr=tr("lab proof · public.profiles", [
        "{STEP:BEFORE}  {anon}      → 2 rows        {LEAK}",
        "^          email {RED}•••••@•••••{/RED} phone {RED}+•• ••••{/RED}",
        "{STEP:FIX}     owner-only select policy",
        "{STEP:PROVE}   {anon}      → 0 rows        {DENIED}",
        "~          {stranger}  → 0 rows        {DENIED}",
        "~          {owner}     → 1 row, own    {OK}",
        "{STEP:DONE}    {DONE}lab proof passed{/DONE}",
    ], '<span class="pill proven">proven</span><span>Illustrative output for the example above · fake rows</span>'),
    proof_note="""<p>This is the check every PatchLabs fix must pass. The lab rebuilds your database from <code>supabase/migrations</code>, seeds fake rows for two users, then reads each flagged table as the anonymous visitor, a signed-in stranger and the owner. A fix only counts as proven when the visitor and the stranger read neither the private rows nor the personal columns, and the owner still reads their own row, personal columns included.</p>""",
    intended="""<p>Some public data is meant to be public. A shop's own phone number, a venue's address or a business's contact email on its listing page are not anyone's private data. In our fix study, 4 of 24 flagged apps (about 1 in 6) turned out to be exactly this, and the agents spotted it themselves (n=24, 5 Nov 2026).</p>
<p>When the fix agent judges a table to be public by design, the report says so, explains why, and asks you to confirm in plain English with a recommended answer. If you confirm, the table is remembered as intended and won't alert again.</p>""",
    study="""In our lab study, 70 of 318 rebuilt apps (22%) let anyone with the public key read personal data, through this pattern or <a href="/findings/pl-008">PL-008</a> (PatchLabs lab study, n=318, Nov 2026).""",
    lint="""<dl class="lint"><dt>0024 permissive_rls_policy</dt><dd>The closest lint, but it does not fire here: by design it skips <code>SELECT</code> policies, because public reads are often intended.</dd>
<dt>0023 sensitive_columns_exposed</dt><dd>Only fires on tables with RLS switched off, and its column list does not include email, phone or address.</dd></dl>
<p class="small muted">Based on the linter's source code and its maintainers' review notes, checked Nov 2026. This is why behaviour testing matters: the lint is right that a public read can be intended, so only knowing what the table holds and who should see it settles the question.</p>""",
    related=["PL-002", "PL-005", "PL-008"],
))

# ------------------------------------------------------------------ PL-002
F.append(dict(
    id="PL-002", slug="pl-002", group="data",
    title="Any signed-in user can read every row",
    short="Signing up unlocks other people's rows. If sign-up is open, that means anyone.",
    desc="PL-002: a Supabase read policy lets any signed-in user read every row. Why sign-up is not a security boundary, how to check, the fix and the proof.",
    sev="high", who="Anyone who signs up", found="Free RLS check (static) and the full lab check",
    proof="Automatic: anon, stranger and owner reads",
    what="""<p>The policy checks that someone is signed in, but not that the row is theirs. It usually looks careful (<code>to authenticated</code>, or <code>auth.uid() is not null</code>), which is why it survives review. But if your app lets anyone create an account, being signed in proves nothing: a stranger signs up with a throwaway email and reads every user's row.</p>
<p>This is the leak most outside scans miss, because they only test as a logged-out visitor. Our lab tests as a signed-in stranger on every check.</p>""",
    vuln=sql("""-- Looks restricted. It isn't, if anyone can sign up.
create policy "Authenticated users can view all profiles"
  on public.profiles for select
  to authenticated
  using (true);

-- The same leak, written differently
create policy "Logged in users can view bookings"
  on public.bookings for select
  using (auth.uid() is not null);""", "supabase/migrations/…_policies.sql (vulnerable)"),
    check=sql("""-- 1. Read policies that only check "is signed in"
select tablename, policyname, roles, qual
from pg_policies
where schemaname = 'public'
  and cmd in ('SELECT', 'ALL')
  and (qual = 'true' and roles && array['authenticated']::name[]
       or qual ilike '%auth.uid() is not null%'
       or qual ilike '%auth.role() = ''authenticated''%');

-- 2. Read a table as a brand-new user who owns nothing (nothing is changed)
begin;
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"00000000-0000-0000-0000-000000000000","role":"authenticated"}', true);
select count(*) from public.profiles;  -- more than 0 means any sign-up can read them
rollback;""", "check-pl-002.sql"),
    fix="""<p>PatchLabs scopes the read to the row's owner. When rows belong to a team or organisation, it scopes them to members instead, using the membership table your app already has.</p>""" +
    sql("""! drop policy "Authenticated users can view all profiles" on public.profiles;
+ create policy "Users can view own profile"
+   on public.profiles for select
+   to authenticated
+   using ((select auth.uid()) = id);""", "supabase/migrations/…_patchlabs_leak_fix.sql") +
    sql("""-- Shared rows: members of the team can read them, nobody else
create policy "Members read their team's projects"
  on public.projects for select
  to authenticated
  using (team_id in (
    select team_id from public.team_members
    where user_id = (select auth.uid())
  ));""", "variant: team-scoped reads"),
    proof_tr=tr("lab proof · public.profiles", [
        "{STEP:BEFORE}  {anon}      → 0 rows        {DENIED}",
        "~          {stranger}  → 2 rows        {LEAK}",
        "{STEP:FIX}     scope reads to the owner",
        "{STEP:PROVE}   {anon}      → 0 rows        {DENIED}",
        "~          {stranger}  → 0 rows        {DENIED}",
        "~          {owner}     → 1 row, own    {OK}",
        "{STEP:DONE}    {DONE}lab proof passed{/DONE}",
    ], '<span class="pill proven">proven</span><span>Illustrative output for the example above · fake rows</span>'),
    proof_note="""<p>The stranger is a second seeded user who owns none of the test rows. The fix passes only if that user reads nothing that isn't theirs and the owner still reads their own row.</p>""",
    intended="""<p>Reading every row is right when every signed-in user is supposed to see the whole table: a product catalogue, a public feed, or a member directory in a community where accounts are approved by hand.</p>
<p>The test is simple: who can create an account? If sign-up is open, treat <code>to authenticated</code> as public. When the answer depends on your business (should new sign-ups see the staff list before they are approved? should every buyer see every seller's email?), the report asks you that question in plain English, with a recommended answer.</p>""",
    study="""In our lab study, 36 of 318 rebuilt apps (11%) leaked personal data only to signed-in users, on top of the 70 that leaked to anyone (PatchLabs lab study, n=318, Nov 2026).""",
    lint="""<dl class="lint"><dt>0024 permissive_rls_policy</dt><dd>The closest lint, but it skips <code>SELECT</code> policies by design, so it does not flag this.</dd></dl>
<p class="small muted">Checked against the linter's source, Nov 2026. A static rule can't know whether your sign-up is open, so this needs a test as a real second user.</p>""",
    related=["PL-001", "PL-005", "PL-004"],
))

# ------------------------------------------------------------------ PL-003
F.append(dict(
    id="PL-003", slug="pl-003", group="data",
    title="RLS enabled but no policies (owner locked out)",
    short="Not a leak, yet. The table is locked to everyone, and the quick fix people reach for is the leak.",
    desc="PL-003: row level security is on but the table has no policies, so the app's own users are locked out. Why it matters, how to check, the fix and the proof.",
    sev="low", who="Nobody, yet", found="Free RLS check (static) and the full lab check",
    proof="Automatic: the owner-still-reads check",
    what="""<p>With RLS switched on and no policies at all, Postgres denies every read and write through the API. Nothing leaks. But the app's own users can't see their data either, so a feature is broken.</p>
<p>It matters because of what usually happens next. Someone asks their AI tool to "make it work", and the fastest change that makes the error go away is <code>using (true)</code>, which turns a broken table into <a href="/findings/pl-001">PL-001</a>. The other common workaround is putting the service role key into the frontend, which is <a href="/findings/pl-010">PL-010</a>.</p>""",
    vuln=sql("""create table public.notes (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  body text
);
alter table public.notes enable row level security;
-- ...and no create policy statements for public.notes anywhere""", "supabase/migrations/…_create_notes.sql"),
    check=sql("""-- Tables with RLS on and no policies at all
select c.relname as table_name
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relkind = 'r'
  and c.relrowsecurity
  and not exists (
    select 1 from pg_policies p
    where p.schemaname = 'public' and p.tablename = c.relname
  );""", "check-pl-003.sql"),
    fix="""<p>PatchLabs writes the four owner policies the table was missing, so users get their own rows back and nobody else gets anything.</p>""" +
    sql("""+ create policy "Owners read own notes" on public.notes
+   for select to authenticated using ((select auth.uid()) = user_id);
+ create policy "Owners add own notes" on public.notes
+   for insert to authenticated with check ((select auth.uid()) = user_id);
+ create policy "Owners edit own notes" on public.notes
+   for update to authenticated
+   using ((select auth.uid()) = user_id)
+   with check ((select auth.uid()) = user_id);
+ create policy "Owners delete own notes" on public.notes
+   for delete to authenticated using ((select auth.uid()) = user_id);""", "supabase/migrations/…_patchlabs_fix.sql"),
    proof_tr=tr("lab proof · public.notes", [
        "{STEP:BEFORE}  {owner}     → 0 rows   (locked out)",
        "{STEP:FIX}     add owner policies",
        "{STEP:PROVE}   {anon}      → 0 rows        {DENIED}",
        "~          {stranger}  → 0 rows        {DENIED}",
        "~          {owner}     → 1 row, own    {OK}",
        "{STEP:DONE}    {DONE}lab proof passed{/DONE}",
    ], '<span class="pill proven">proven</span><span>Illustrative output for the example above · fake rows</span>'),
    proof_note="""<p>The owner check is the part of the proof that catches this. A fix that leaves the owner with 0 rows fails, which is also how the lab catches fixes that close a leak by locking everyone out.</p>""",
    intended="""<p>RLS on with no policies is the correct setup for a table only your server touches: an audit log, a job queue, or data written by an Edge Function using the service role key. The service role bypasses RLS, and the API roles get nothing, which is what you want.</p>
<p>If your frontend never reads the table, there is nothing to fix. The free RLS check reports it as low severity for that reason.</p>""",
    study=None,
    lint="""<dl class="lint"><dt>0008 rls_enabled_no_policy</dt><dd>Flags the same pattern. Supabase's linter reports it; PatchLabs adds the owner policies and proves the owner can read again.</dd></dl>""",
    related=["PL-001", "PL-010", "PL-008"],
))

# ------------------------------------------------------------------ PL-004
F.append(dict(
    id="PL-004", slug="pl-004", group="data",
    title="UPDATE policy missing WITH CHECK",
    short="Users may edit their own row, and nothing stops them changing its role, plan or owner.",
    desc="PL-004: a Supabase UPDATE policy has no WITH CHECK, so users can set columns they should never control. When it matters, how to check, the fix and the test.",
    sev="medium", who="Signed-in users, on rows they can already edit", found="Free RLS check (static)",
    proof="Write test included for your engineer",
    what="""<p>An UPDATE policy answers two questions. <code>USING</code> decides which rows you may change. <code>WITH CHECK</code> decides what a row may look like afterwards. Leave out <code>WITH CHECK</code> and Postgres reuses the <code>USING</code> rule for the new row.</p>
<p>That fallback is safe for the owner column when <code>USING</code> is a strict ownership test. It is not enough when the row carries columns the user should never set themselves (<code>role</code>, <code>plan</code>, <code>credits</code>, <code>is_verified</code>), or when <code>USING</code> is broader than what a changed row should be allowed to be. Then a user edits their own row and makes themselves an admin.</p>""",
    vuln=sql("""create table public.profiles (
  id uuid primary key references auth.users (id) on delete cascade,
  full_name text,
  role text not null default 'member'
);

create policy "Users can update own profile"
  on public.profiles for update
  to authenticated
  using ((select auth.uid()) = id);

-- Any user can now run, from the browser:
--   update profiles set role = 'admin' where id = auth.uid();""", "supabase/migrations/…_profiles.sql (vulnerable)"),
    check=sql("""-- 1. UPDATE (and ALL) policies with no WITH CHECK
select tablename, policyname, cmd, roles, qual
from pg_policies
where schemaname = 'public'
  and cmd in ('UPDATE', 'ALL')
  and with_check is null;

-- 2. Which columns can signed-in users change?
select table_name, column_name
from information_schema.column_privileges
where table_schema = 'public'
  and grantee = 'authenticated'
  and privilege_type = 'UPDATE'
order by table_name, column_name;""", "check-pl-004.sql"),
    fix="""<p>PatchLabs makes the rule explicit and limits which columns a user may change. The column grant is what actually stops the role change; <code>WITH CHECK</code> stops a row being handed to someone else.</p>""" +
    sql("""! drop policy "Users can update own profile" on public.profiles;
+ create policy "Users can update own profile"
+   on public.profiles for update
+   to authenticated
+   using ((select auth.uid()) = id)
+   with check ((select auth.uid()) = id);
+ -- Users may change these columns and no others
+ revoke update on public.profiles from authenticated;
+ grant update (full_name) on public.profiles to authenticated;""", "supabase/migrations/…_patchlabs_fix.sql"),
    proof_tr=tr("write test · public.profiles", [
        "{STEP:TEST}    {owner} set full_name    → 1 row  {OK}",
        "~          {owner} set role='admin'",
        "~            → permission denied     {DENIED}",
        "~          {stranger} set full_name",
        "~            on owner's row → 0 rows {DENIED}",
    ], '<span class="pill plain">test SQL in the report</span><span>Illustrative output · fake rows</span>'),
    proof_note="""<p>Be clear about what is automatic. The lab's three-identity proof covers <strong>reads</strong> on every check. For write findings like this one, the report includes the test above as SQL for your engineer to run in the lab or a branch database; it is not yet part of the automatic proof.</p>""" +
    sql("""begin;
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"<your user id>","role":"authenticated"}', true);
update public.profiles set role = 'admin' where id = '<your user id>';
-- before the fix: UPDATE 1 · after: permission denied for table profiles
rollback;""", "write-test-pl-004.sql"),
    intended="""<p>A missing <code>WITH CHECK</code> is harmless when <code>USING</code> is a strict ownership test and every column on the row is one the user is allowed to set. Many tables are like that, so treat this as a prompt to look, not proof of a hole. The report says which columns signed-in users can change, so you can decide quickly.</p>""",
    study=None, lint=None,
    related=["PL-005", "PL-002", "PL-006"],
))

# ------------------------------------------------------------------ PL-005
F.append(dict(
    id="PL-005", slug="pl-005", group="data",
    title="Always-true policy",
    short="A policy that says yes to everyone. On writes, anyone can change or delete your data.",
    desc="PL-005: a Supabase policy with USING (true) or WITH CHECK (true). When it is a leak, when it is fine, how to check, the fix and the proof.",
    sev="high or medium", sevlabel="high to low", who="Anyone the policy applies to", found="Free RLS check (static) and the full lab check",
    proof="Automatic for reads; write test included",
    what="""<p><code>using (true)</code> or <code>with check (true)</code> means the policy approves every row for every role it applies to. How bad that is depends on the command:</p>
<ul><li><strong>UPDATE, DELETE or ALL:</strong> anyone it applies to can change or wipe every row. With no <code>to</code> clause, that includes logged-out visitors. This is the high-severity case.</li>
<li><strong>INSERT:</strong> anyone can add rows. Fine for a contact form, a problem for an orders or roles table.</li>
<li><strong>SELECT:</strong> everyone can read every row. Fine for a product list; <a href="/findings/pl-001">PL-001</a> when the table holds personal data.</li></ul>
<p>AI builders often write these as a quick way past a permissions error, usually with names like "Enable update for all users".</p>""",
    vuln=sql("""create policy "Enable update for all users"
  on public.orders for update
  using (true);

create policy "Enable delete for all users"
  on public.orders for delete
  using (true);""", "supabase/migrations/…_orders.sql (vulnerable)"),
    check=sql("""-- Every always-true policy, most dangerous commands first
select tablename, policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'public'
  and (qual = 'true' or with_check = 'true')
order by case cmd when 'ALL' then 0 when 'DELETE' then 1
                  when 'UPDATE' then 2 when 'INSERT' then 3 else 4 end;""", "check-pl-005.sql"),
    fix="""<p>PatchLabs replaces each always-true write policy with the narrowest rule the app needs: the row's owner, or staff according to the role table your app already uses.</p>""" +
    sql("""! drop policy "Enable update for all users" on public.orders;
! drop policy "Enable delete for all users" on public.orders;
+ create policy "Customers update own orders"
+   on public.orders for update
+   to authenticated
+   using ((select auth.uid()) = user_id)
+   with check ((select auth.uid()) = user_id);
+ create policy "Admins delete orders"
+   on public.orders for delete
+   to authenticated
+   using (exists (
+     select 1 from public.user_roles r
+     where r.user_id = (select auth.uid()) and r.role = 'admin'
+   ));""", "supabase/migrations/…_patchlabs_fix.sql"),
    proof_tr=tr("lab proof · public.orders", [
        "{STEP:READS}   {anon}      → 0 rows        {DENIED}",
        "~          {stranger}  → 0 rows        {DENIED}",
        "~          {owner}     → 1 row, own    {OK}",
        "{STEP:WRITES}  {anon} update → 0 rows   {DENIED}",
        "~          {owner} update own → 1 row {OK}",
    ], '<span class="pill proven">reads proven</span><span>Writes: test SQL in the report · fake rows</span>'),
    proof_note="""<p>Reads by the anonymous visitor, a signed-in stranger and the owner are proven automatically on every check. For write policies, the report includes the update and delete tests as SQL for your engineer to run; they are not yet part of the automatic proof.</p>""",
    intended="""<p>Always-true is correct in two common cases:</p>
<ul><li><code>select ... using (true)</code> on data meant for everyone: products, blog posts, opening hours.</li>
<li><code>insert ... with check (true)</code> on a contact form or waitlist, as long as nothing lets the public read those rows back.</li></ul>
<p>The report marks these as intended with its reasoning, and you can confirm them so they don't alert again.</p>""",
    study=None,
    lint="""<dl class="lint"><dt>0024 permissive_rls_policy</dt><dd>Flags always-true policies on UPDATE, DELETE, INSERT and ALL. It deliberately skips SELECT, which is where personal-data reads leak (see <a href="/findings/pl-001">PL-001</a>).</dd></dl>""",
    related=["PL-001", "PL-004", "PL-008"],
))

# ------------------------------------------------------------------ PL-006
F.append(dict(
    id="PL-006", slug="pl-006", group="data",
    title="SECURITY DEFINER function exposed",
    short="A function that runs with the owner's powers, callable by anyone through the API.",
    desc="PL-006: a SECURITY DEFINER function in a Supabase app is callable by anonymous users or has no fixed search_path. How to check, the fix and the test.",
    sev="high or medium", sevlabel="high or medium", who="Anyone who can call it", found="Free RLS check (static)",
    proof="Call test included for your engineer",
    what="""<p>A <code>security definer</code> function runs with the rights of whoever created it, usually a role that ignores RLS. That is useful for small, careful helpers. It becomes a leak when two things combine:</p>
<ul><li><strong>Anyone can call it.</strong> Postgres lets every role execute a new function unless you revoke it, and Supabase exposes functions in <code>public</code> through the API at <code>/rest/v1/rpc/&lt;name&gt;</code>.</li>
<li><strong>It returns or changes more than the caller should reach</strong>, such as looking up any user's email by id.</li></ul>
<p>A definer function with no fixed <code>search_path</code> is a second problem: it can be tricked into running a look-alike object created in another schema. The free RLS check flags both (high when anonymous users can call it).</p>""",
    vuln=sql("""create or replace function public.get_user_email(uid uuid)
returns text
language sql
security definer
as $$
  select email from auth.users where id = uid;
$$;
-- No revoke: anon can call it with any user's id.""", "supabase/migrations/…_functions.sql (vulnerable)"),
    check=sql("""-- Definer functions in public: fixed search_path? callable by anon?
select p.proname as function_name,
       p.proconfig as settings,  -- look for search_path=...
       has_function_privilege('anon', p.oid, 'execute') as anon_can_call,
       has_function_privilege('authenticated', p.oid, 'execute') as signed_in_can_call
from pg_proc p
join pg_namespace n on n.oid = p.pronamespace
where n.nspname = 'public'
  and p.prosecdef;""", "check-pl-006.sql"),
    fix="""<p>PatchLabs narrows the function to the caller's own data, pins the search path, and grants it only to the roles that need it.</p>""" +
    sql("""! drop function public.get_user_email(uuid);
+ create or replace function public.get_my_email()
+ returns text
+ language sql
+ security definer
+ set search_path = ''
+ as $$
+   select email from auth.users where id = (select auth.uid());
+ $$;
+ revoke execute on function public.get_my_email() from public, anon;
+ grant execute on function public.get_my_email() to authenticated;""", "supabase/migrations/…_patchlabs_fix.sql") +
    """<p class="small muted">With <code>search_path = ''</code>, every name inside the function must be schema-qualified (<code>auth.users</code>, <code>public.profiles</code>). The report notes any frontend call that has to change from the old function name.</p>""",
    proof_tr=tr("call test · rpc", [
        "{STEP:BEFORE}  {anon} get_user_email(owner)",
        "~            → {RED}•••••@•••••{/RED}         {LEAK}",
        "{STEP:AFTER}   {anon} get_my_email()",
        "~            → permission denied     {DENIED}",
        "~          {owner} get_my_email()",
        "~            → their own email       {OK}",
    ], '<span class="pill plain">test SQL in the report</span><span>Illustrative output · fake data</span>'),
    proof_note="""<p>The automatic three-identity proof covers table reads. For function findings the report includes the call test as SQL, run as the anonymous visitor and as the owner, for your engineer to run in the lab or a branch database.</p>""" +
    sql("""begin;
set local role anon;
select public.get_my_email();  -- expect: permission denied for function get_my_email
rollback;""", "call-test-pl-006.sql"),
    intended="""<p>Definer functions are the right tool in a few common places, and they are fine when the search path is pinned and the grants are narrow:</p>
<ul><li>a helper used inside policies, such as <code>has_role(uid, 'admin')</code>, which returns only true or false about the caller and avoids recursive policies;</li>
<li>a trigger that creates a profile row when a user signs up (trigger functions can't be called through the API).</li></ul>""",
    study=None,
    lint="""<dl class="lint"><dt>0011 function_search_path_mutable</dt><dd>Flags functions without a fixed <code>search_path</code>.</dd>
<dt>0028 anon_security_definer_function_executable</dt><dd>Flags definer functions anonymous users can execute.</dd>
<dt>0029 authenticated_security_definer_function_executable</dt><dd>The same for signed-in users.</dd></dl>""",
    related=["PL-004", "PL-002", "PL-010"],
))

# ------------------------------------------------------------------ PL-007
F.append(dict(
    id="PL-007", slug="pl-007", group="data",
    title="Public storage bucket",
    short="Files in this bucket are served to anyone with the link. ID scans and invoices don't belong there.",
    desc="PL-007: a Supabase storage bucket is set to public. When that exposes personal files, how to check, the fix PatchLabs writes and the test.",
    sev="medium", who="Anyone with, or able to list, the file links", found="Free RLS check (static)",
    proof="Listing test included for your engineer",
    what="""<p>A public bucket serves its files to anyone who has the URL, with no sign-in. That is right for avatars and product photos. It is a leak when the bucket holds personal files: ID documents, CVs, invoices, signed contracts, medical letters.</p>
<p>It gets worse when a broad read policy on <code>storage.objects</code> also lets visitors list the bucket, because then nobody needs to guess the links.</p>""",
    vuln=sql("""insert into storage.buckets (id, name, public)
values ('documents', 'documents', true);

-- Often paired with a broad read policy that also allows listing
create policy "Anyone can view documents"
  on storage.objects for select
  using (bucket_id = 'documents');""", "supabase/migrations/…_storage.sql (vulnerable)"),
    check=sql("""-- 1. Which buckets are public?
select id, name, public from storage.buckets where public;

-- 2. Who can read objects (and so list file names)?
select policyname, roles, cmd, qual
from pg_policies
where schemaname = 'storage' and tablename = 'objects';""", "check-pl-007.sql"),
    fix="""<p>PatchLabs makes the bucket private and lets each user read only the files in their own folder. The app then shows files through short-lived signed links.</p>""" +
    sql("""+ update storage.buckets set public = false where id = 'documents';
! drop policy "Anyone can view documents" on storage.objects;
+ create policy "Owners read own documents"
+   on storage.objects for select
+   to authenticated
+   using (
+     bucket_id = 'documents'
+     and (storage.foldername(name))[1] = (select auth.uid())::text
+   );""", "supabase/migrations/…_patchlabs_fix.sql") +
    """<p>The code change that ships with it: replace <code>getPublicUrl(path)</code> with <code>createSignedUrl(path, 60)</code> wherever the app shows these files, and upload to <code>&lt;user id&gt;/filename</code>. The report lists each place.</p>""",
    proof_tr=tr("listing test · storage.objects", [
        "{STEP:BEFORE}  {anon} list documents → 3 {LEAK}",
        "{STEP:AFTER}   {anon}      → 0 objects     {DENIED}",
        "~          {stranger}  → 0 objects     {DENIED}",
        "~          {owner}     → 1, own folder {OK}",
    ], '<span class="pill plain">test SQL in the report</span><span>Illustrative output · fake files</span>'),
    proof_note="""<p>The listing test reads <code>storage.objects</code> as each identity. It is included as SQL for your engineer; the automatic proof today covers your tables. Whether a public URL still works is decided by the bucket's <code>public</code> flag, which the fix sets to false.</p>""",
    intended="""<p>Public buckets are right for files meant for everyone: avatars, product images, logos, blog images. Keep them public, and keep personal files in a separate private bucket. If a public bucket only holds public assets, there is nothing to fix.</p>""",
    study=None,
    lint="""<dl class="lint"><dt>0025 public_bucket_allows_listing</dt><dd>Flags public buckets whose object policies let clients list their files.</dd></dl>""",
    related=["PL-001", "PL-008", "PL-011"],
))

# ------------------------------------------------------------------ PL-008
F.append(dict(
    id="PL-008", slug="pl-008", group="data",
    title="Row level security not enabled",
    short="No rules at all. With API access granted, anyone with the public key can read and change every row.",
    desc="PL-008: a table in a Supabase app has row level security switched off. How to check, the copy-paste fix, what changed in Supabase's defaults, and the proof.",
    sev="critical", sevlabel="critical (high without personal data)", who="Anyone on the internet", found="Free RLS check (static) and the full lab check",
    proof="Automatic: anon, stranger and owner reads",
    what="""<p>Without RLS, a table has no row-level rules. If the API roles (<code>anon</code>, <code>authenticated</code>) have been granted access to it, anyone holding your public key can read, insert, change and delete every row through the Supabase API. The free RLS check rates it critical when the table has personal columns, high otherwise.</p>
<p>Supabase changed its defaults in 2026: new tables in <code>public</code> are no longer exposed to the API automatically (the default for new projects from 30 May, enforced on all projects from 30 Oct 2026, with existing grants kept). Older tables, and any migration that grants access explicitly, are still exposed.</p>""",
    vuln=sql("""create table public.leads (
  id bigint generated always as identity primary key,
  name text,
  email text,
  phone text,
  created_at timestamptz default now()
);
-- No "alter table public.leads enable row level security;"
grant all on public.leads to anon, authenticated;""", "supabase/migrations/…_create_leads.sql (vulnerable)"),
    check=sql("""-- 1. Tables in public with RLS switched off
select c.relname as table_name
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public' and c.relkind = 'r' and not c.relrowsecurity;

-- 2. Can the API roles reach them?
select table_name, grantee, string_agg(privilege_type, ', ') as privileges
from information_schema.role_table_grants
where table_schema = 'public' and grantee in ('anon', 'authenticated')
group by table_name, grantee
order by table_name;""", "check-pl-008.sql"),
    fix="""<p>PatchLabs switches RLS on and adds back exactly what the app uses. Here the public contact form keeps working and only admins can read the leads.</p>""" +
    sql("""+ alter table public.leads enable row level security;
+ -- The contact form can still submit
+ create policy "Anyone can submit a lead"
+   on public.leads for insert
+   to anon, authenticated
+   with check (true);
+ -- Only admins can read them
+ create policy "Admins read leads"
+   on public.leads for select
+   to authenticated
+   using (exists (
+     select 1 from public.user_roles r
+     where r.user_id = (select auth.uid()) and r.role = 'admin'
+   ));""", "supabase/migrations/…_patchlabs_leak_fix.sql"),
    proof_tr=tr("lab proof · public.leads", [
        "{STEP:BEFORE}  {anon}      → 3 rows        {LEAK}",
        "^          email {RED}•••••@•••••{/RED} phone {RED}+•• ••••{/RED}",
        "{STEP:FIX}     enable RLS + scoped policies",
        "{STEP:PROVE}   {anon}      → 0 rows        {DENIED}",
        "~          {stranger}  → 0 rows        {DENIED}",
        "~          {admin}     → 3 rows        {OK}",
        "{STEP:DONE}    {DONE}lab proof passed{/DONE}",
    ], '<span class="pill proven">proven</span><span>Illustrative output for the example above · fake rows</span>'),
    proof_note="""<p>Here the "owner" is the admin who is meant to read the leads; the proof checks that the right person keeps access, not just that everyone else is locked out. The lab rebuilds with Supabase's default grants, so it sees the same exposure the live API would.</p>""",
    intended="""<p>Strictly, a table with RLS off is safe if the API roles have no grants on it, for example a table only server code uses. Switch RLS on anyway: it costs nothing, and it keeps the table closed if someone adds a grant later. If you must leave it off, the report notes the reason and stops alerting once you confirm.</p>""",
    study="""Of the 70 rebuilt apps (22% of 318) where anyone with the public key could read personal data, this pattern and <a href="/findings/pl-001">PL-001</a> were the two routes (PatchLabs lab study, n=318, Nov 2026).""",
    lint="""<dl class="lint"><dt>0013 rls_disabled_in_public</dt><dd>Flags tables in <code>public</code> without RLS. It reports an error level.</dd>
<dt>0007 policy_exists_rls_disabled</dt><dd>Flags tables that have policies written but RLS switched off, so the policies do nothing.</dd></dl>""",
    related=["PL-001", "PL-003", "PL-005"],
))

# ------------------------------------------------------------------ PL-010
F.append(dict(
    id="PL-010", slug="pl-010", group="keys",
    title="Service role key in client code",
    short="The key that ignores every access rule, shipped to every visitor's browser.",
    desc="PL-010: a Supabase service role key in frontend code or a VITE_ variable. Why every RLS rule stops mattering, how to check, and what to do now.",
    sev="critical", who="Anyone who opens your site", found="Key scan of the code (every check)",
    proof="Re-scan; the real fix is rotation",
    what="""<p>Supabase gives every project two kinds of key. The public key (<code>anon</code>, or <code>sb_publishable_…</code> on newer projects) is meant to be in the browser and is limited by RLS. The service role key (<code>service_role</code>, or <code>sb_secret_…</code>) bypasses RLS entirely. It is meant only for servers.</p>
<p>If the service role key is in frontend code, every policy in your database stops mattering: anyone can copy it from your JavaScript and read or delete everything. A common route in is an environment variable with a <code>VITE_</code> or <code>NEXT_PUBLIC_</code> prefix, which the build tool deliberately copies into the browser bundle.</p>""",
    vuln=sql("""# .env
VITE_SUPABASE_URL=https://xyz.supabase.co
VITE_SUPABASE_SERVICE_ROLE_KEY=eyJhbGciOiJIUzI1NiIs…   # shipped to every browser

// src/lib/admin.ts
export const admin = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.VITE_SUPABASE_SERVICE_ROLE_KEY,
);""", "src/lib/admin.ts and .env (vulnerable)"),
    check="""<p>Search the code and the built bundle. Older Supabase keys are JWTs; decode the middle part locally to see which role a key carries.</p>""" +
    sql("""# 1. In the repo: names and prefixes that mean "server-only key"
grep -rnE "service_role|SERVICE_ROLE|sb_secret_" --exclude-dir=node_modules .

# 2. In the built site (after npm run build)
grep -l "service_role" dist/assets/*.js

# 3. Which role does a JWT-style key carry? (runs locally, sends nothing)
node -e "console.log(JSON.parse(Buffer.from(process.argv[1].split('.')[1],'base64url')))" "<the key>"
# "role":"service_role" means it bypasses RLS""", "check-pl-010.sh"),
    fix="""<p>No migration fixes a leaked key. The fix is in three parts, and the report gives each one for your app:</p>
<ol><li><strong>Rotate the key now</strong> in your Supabase project's API settings. Until you do, the old key works for anyone who copied it.</li>
<li><strong>Move the privileged call to a server</strong>, usually a Supabase Edge Function, where the key lives in a server-side secret.</li>
<li><strong>Remove the variable</strong> from the frontend env file, and add the file to <code>.gitignore</code>.</li></ol>""" +
    sql("""! const { data } = await admin.from('profiles').select('*');
+ const { data, error } = await supabase.functions.invoke('list-profiles');

// supabase/functions/list-profiles/index.ts (runs on the server)
+ const admin = createClient(
+   Deno.env.get('SUPABASE_URL')!,
+   Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
+ );
+ // check the caller is an admin here before returning anything""", "the code change the report suggests"),
    proof_tr=tr("key scan · report excerpt", [
        "{STEP:SCAN}    src/lib/admin.ts",
        "~          service role  eyJh…Q1x8  {LEAK}",
        "{STEP:ACTION}  rotate in Supabase API settings",
        "~          move call to an Edge Function",
        "{STEP:RESCAN}  current code → 0 keys     {OK}",
        "~          still in history → PL-011",
    ], '<span class="pill plain">synthetic example</span><span>Masked, not a real key</span>'),
    proof_note="""<p>Keys can't be lab-proven the way access rules can. The only proof that a leaked key is harmless is that it no longer works, and only you can rotate it. What we confirm on the re-check is that no server-only key remains in the current code. The old key stays in git history, which is why rotation, not deletion, is the fix (see <a href="/findings/pl-011">PL-011</a>).</p>""",
    intended="""<p>The service role key is correct in server code: Edge Functions, a backend, scheduled jobs and CI, loaded from a secret store, never with a public-prefix variable name. A key read from a secret store at run time (<code>Deno.env</code> in an Edge Function) never appears in your code, so there is nothing to flag. For every key the scan does find, the report shows the file or commit, so you can tell a server script from a browser bundle at a glance. The public key belongs in frontend code.</p>""",
    study=None, lint=None,
    related=["PL-009", "PL-011", "PL-003"],
))

# ------------------------------------------------------------------ PL-011
F.append(dict(
    id="PL-011", slug="pl-011", group="keys",
    title="Key still in git history",
    short="You deleted the key. Every old commit still has it, and so does every clone and fork.",
    desc="PL-011: an AI, payment or database key that was removed from the code is still in the repo's git history. How to find it, why rotation is the fix, and how to clean up.",
    sev="high", who="Anyone who can read the repo", found="Key scan of the full git history (every check)",
    proof="Report lists each key with where to rotate it",
    what="""<p>Deleting a key from your code doesn't remove it from the repository. Git keeps every version of every file, so a committed <code>.env</code> or a key pasted into a component is still readable in the old commit, by anyone who can read the repo. For a public repo, that is anyone.</p>
<p>The PatchLabs key scan reads the code <em>and</em> the full git history of every repo it checks, for AI, payment and database keys. Values are masked in the report, with where each key was found and where to rotate it.</p>""",
    vuln=sql("""$ git log --oneline -- .env
a41c9e2 remove .env (oops)
7f03b18 add stripe checkout          # .env with sk_live_… committed here

$ git show 7f03b18:.env
STRIPE_SECRET_KEY=sk_live_51N…       # still readable today""", "what history looks like (illustrative)"),
    check=sql("""# 1. Commits that added or removed something key-shaped (all branches)
git log --all -p -G 'sk_live_|sk-proj-|sk-ant-|service_role|sb_secret_|AIza' \\
  --format='%h %ad %s' --date=short | grep -E '^[0-9a-f]{7}|^[+-].*(sk_|AIza|service_role|sb_secret_)' | head -60

# 2. Was an env file ever committed?
git log --all --format='%h %ad %s' --date=short -- .env '*.env' '.env.*'""", "check-pl-011.sh"),
    fix="""<ol><li><strong>Rotate every key that was ever committed</strong>, at the provider (the report links to the right page for each). This is the fix. Forks, clones and caches keep old commits, so a key that has been public must be treated as known.</li>
<li><strong>Stop it happening again:</strong> add env files to <code>.gitignore</code>, keep secrets in your host's secret store, and re-check after each change.</li>
<li><strong>Optionally, rewrite history</strong> so the old commits disappear from your repo. It's hygiene, not a fix, and it changes every commit id.</li></ol>""" +
    sql("""# Only after rotating. Run on a fresh clone; collaborators must re-clone afterwards.
git filter-repo --invert-paths --path .env
echo ".env*" >> .gitignore
git push --force --all""", "optional clean-up"),
    proof_tr=tr("key scan · report excerpt", [
        "{STEP:SCAN}    full history · 214 commits",
        "^          .env (deleted in a later commit)",
        "~          payment key  sk_l…4f2a   {LEAK}",
        "~          AI key       sk-p…9bQe   {LEAK}",
        "{STEP:ACTION}  rotate both at the provider",
        "~          add .env* to .gitignore",
    ], '<span class="pill plain">synthetic example</span><span>Masked, not real keys</span>'),
    proof_note="""<p>We can't check whether a key still works without using it, and we never use keys we find. So the report doesn't claim the problem is solved. It lists each key, masked, with the commit or file it came from and the page where you rotate it.</p>""",
    intended="""<p>Some key-shaped strings are fine to commit: the Supabase public key (meant for browsers), test-mode keys such as <code>sk_test_…</code>, and placeholder values in <code>.env.example</code>. The report shows the file or commit for every key it finds, so you can tell these apart quickly. If a flagged key was revoked long ago, there is nothing more to do.</p>""",
    study=None, lint=None,
    related=["PL-009", "PL-010", "PL-001"],
))


# ------------------------------------------------------------------ PL-009
F.append(dict(
    id="PL-009", slug="pl-009", group="keys", line="code", status="live",
    title="AI, payment or database key in the code",
    short="A secret key for an AI, payment or database service is sitting in your current code, readable by anyone who can read the repo.",
    desc="PL-009: a secret AI, payment or database key is committed in the current code of an AI-built app. Which keys are secret, how to find them, and how to rotate and move them.",
    sev="high", sevlabel="high (depends on the key)", who="Anyone who can read the repo, or your site if it ships to the browser", found="PatchLabs Code: key scan of the current code",
    proof="Re-scan; the real fix is rotation",
    what="""<p>Some keys are meant to be public: the Supabase anon or publishable key, Stripe's <code>pk_live_…</code> publishable key, a Firebase web config. Others are secrets that act as your account: an OpenAI (<code>sk-proj-…</code>) or Anthropic (<code>sk-ant-…</code>) API key, a Stripe secret key (<code>sk_live_…</code>) or restricted key (<code>rk_live_…</code>), a database connection string with its password in it. PL-009 means one of those secrets is in the current code of your repo, in a source file or a committed <code>.env</code>.</p>
<p>Anyone who can read the repo can use it: run AI requests on your bill, read or refund payments, or connect straight to your database. If the key is also used in frontend code, it ships in your JavaScript bundle and every visitor to your site has it too, public repo or not.</p>
<p>Two neighbours: a Supabase service role or secret key is <a href="/findings/pl-010">PL-010</a>, because it bypasses every access rule; a key that has been removed from the code but is still in old commits is <a href="/findings/pl-011">PL-011</a>.</p>""",
    why="""<p>"Add an AI chat" or "take payments" is one prompt, and the quickest working version puts the key where the code runs. In a Vite or React app that is the browser, often through a <code>VITE_</code> variable, which the build copies into the bundle on purpose. A committed <code>.env</code> file does the rest when it isn't in <code>.gitignore</code>.</p>""",
    vuln=sql("""// src/lib/ai.ts
import OpenAI from 'openai';

export const openai = new OpenAI({
  apiKey: 'sk-proj-••••••••••••',  // a real key here works for anyone
  dangerouslyAllowBrowser: true,
});

# .env (committed)
STRIPE_SECRET_KEY=sk_live_••••••••••••
DATABASE_URL=postgresql://postgres:••••••@db.xyz.supabase.co:5432/postgres""", "src/lib/ai.ts and .env (vulnerable)"),
    check=sql("""# 1. Secret-shaped strings in the current code
grep -rnE "sk-proj-|sk-ant-|sk_live_|rk_live_|AIza[0-9A-Za-z_-]{20}|postgres(ql)?://[^:@/]+:[^@/]+@" \\
  --exclude-dir=node_modules --exclude-dir=.git .

# 2. Is an env file tracked by git?
git ls-files | grep -E "(^|/)\\.env($|\\.)" | grep -v example

# 3. Did a key reach the built site? (after npm run build)
grep -lE "sk-proj-|sk-ant-|sk_live_" dist/assets/*.js""", "check-pl-009.sh") +
    """<p class="small muted"><code>AIza…</code> keys are Google API keys. In a Firebase web config that key is public by design and protected by your security rules; elsewhere (a Gemini or Maps server key) treat it as a secret.</p>""",
    fix="""<p>No code change makes a published key safe again. In this order:</p>
<ol><li><strong>Rotate the key now</strong> at the provider: create a new one and revoke the old. Until you do, anyone who copied it can use it.</li>
<li><strong>Move the call to a server</strong>, usually a Supabase Edge Function, and keep the new key in a server-side secret: <code>supabase secrets set OPENAI_API_KEY=…</code>.</li>
<li><strong>Remove the key from the code</strong>, untrack the env file and ignore it. The old key stays in git history (<a href="/findings/pl-011">PL-011</a>), which is why step 1 comes first.</li></ol>""" +
    sql("""! export const openai = new OpenAI({ apiKey: 'sk-proj-…', dangerouslyAllowBrowser: true });
+ const { data, error } = await supabase.functions.invoke('chat', { body: { messages } });

// supabase/functions/chat/index.ts (runs on the server)
+ import OpenAI from 'npm:openai@4';
+ const openai = new OpenAI({ apiKey: Deno.env.get('OPENAI_API_KEY')! });
+ // verify the caller first (see PL-017), then call openai.chat.completions.create(...)

# untrack and ignore the env file
git rm --cached .env
echo ".env*" >> .gitignore
echo "!.env.example" >> .gitignore""", "the change"),
    proof_tr=tr("key scan · report excerpt", [
        "{STEP:SCAN}    current code",
        "~          src/lib/ai.ts:4",
        "~          AI key       sk-p…Q9xT   {LEAK}",
        "~          .env:1  payment key  sk_l…4f2a {LEAK}",
        "{STEP:ACTION}  rotate both at the provider",
        "{STEP:RESCAN}  current code → 0 keys     {OK}",
    ], '<span class="pill plain">synthetic example</span><span>Masked, not real keys</span>'),
    proof_note="""<p>The key scan reads every file in the current code (and, for <a href="/findings/pl-011">PL-011</a>, the full history). It never uses a key it finds, so it can't tell you whether the key still works. The report shows each key masked, with its file and line, the kind of key and where to rotate it. The re-check confirms the key is gone from the current code; only you can confirm it was revoked.</p>""",
    intended="""<p>Publishable keys (Supabase anon or publishable, Stripe <code>pk_…</code>, a Firebase web config), test-mode keys such as <code>sk_test_…</code>, and placeholders in <code>.env.example</code> are fine to commit. The report shows the file for every key it finds, so these are quick to tell apart.</p>""",
    sevwhy="""<p>High by default, because a working secret key lets anyone act as your account with that provider. The severity follows the kind of key: a database connection string with its password reaches all your data, while a narrowly scoped key does less. The report names the key type so you can judge.</p>""",
    study=None, lint=None,
    related=["PL-010", "PL-011", "PL-017"],
))

# ================================================================== v3 findings (10 Nov 2026)
# line: "lab" or "code". status: "live" (PatchLabs tests for it today) or "coming" (educational page only).
# Lab checks PL-012..016 and PL-019 are not built this round (V3.md status update): keep them "coming" until they ship.

COMING_LAB = """<p>When this check ships, the Lab will run it the way it runs PL-001 to PL-008 today: rebuild your database from <code>supabase/migrations</code> in a disposable Postgres, seed fake rows for two users, and try the exploit as an anonymous visitor, a signed-in stranger and the owner. Until then, the self-check above is the test.</p>"""

# ------------------------------------------------------------------ PL-012
F.append(dict(
    id="PL-012", slug="pl-012", group="data", line="lab", status="coming",
    title="Strangers can change or delete other people's rows",
    short="A write policy checks that someone is signed in, not that the row is theirs. Anyone who signs up can edit or wipe it.",
    desc="PL-012: a Supabase UPDATE or DELETE policy lets any signed-in user change or delete rows they don't own. How to check your project, the fix, and why it's critical.",
    sev="critical", who="Anyone who signs up", found="Not tested yet: coming to PatchLabs Lab",
    proof="Coming",
    what="""<p>Row level security has separate rules for reading, adding, changing and deleting rows. PL-012 means the rule for changing (<code>UPDATE</code>) or deleting (<code>DELETE</code>) checks only that the caller is signed in, for example <code>to authenticated using (true)</code> or <code>using (auth.uid() is not null)</code>, and never compares the row's owner with the caller. If your app has open sign-up, a stranger creates an account and edits or deletes other people's posts, bookings or orders.</p>
<p>Postgres also applies your <code>SELECT</code> policies when an update or delete filters on a column (<code>.eq('id', …)</code> in supabase-js), so in practice the stranger also needs to be able to see the row. Many apps make rows readable to every signed-in user on purpose (a feed, a marketplace, a directory), and that combination is what makes this exploitable.</p>
<p>Two neighbours: in <a href="/findings/pl-005">PL-005</a> the policy is always-true for every role, including logged-out visitors; in <a href="/findings/pl-004">PL-004</a> users change their <em>own</em> rows in ways they shouldn't.</p>""",
    why="""<p>When an app shows "new row violates row-level security policy", the shortest change that makes the error go away is a policy that only asks "is the user signed in?". It reads as careful, because it mentions authentication, and it works in a demo where the only user is the builder. The difference only shows up with a second account, and most people never test with one.</p>""",
    vuln=sql("""create table public.posts (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  title text not null,
  body text
);
alter table public.posts enable row level security;

create policy "Posts are visible to signed-in users"
  on public.posts for select to authenticated using (true);

-- Checks sign-in, not ownership
create policy "Signed-in users can update posts"
  on public.posts for update to authenticated using (true);
create policy "Signed-in users can delete posts"
  on public.posts for delete
  using (auth.uid() is not null);""", "supabase/migrations/…_posts.sql (vulnerable)"),
    check="""<p>Run these in the SQL editor of your own project. The second block acts as a brand-new user who owns nothing, inside a transaction that is rolled back.</p>""" +
    sql("""-- 1. UPDATE and DELETE policies that never compare the row with the caller
select tablename, policyname, cmd, roles, qual
from pg_policies
where schemaname = 'public'
  and cmd in ('UPDATE', 'DELETE', 'ALL')
  and (coalesce(qual, '') not ilike '%auth.uid()%'
       or qual ilike '%auth.uid() is not null%');

-- 2. Try an update as a signed-in stranger (nothing is changed)
begin;
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"00000000-0000-0000-0000-000000000000","role":"authenticated"}', true);
update public.posts set title = title
where user_id <> '00000000-0000-0000-0000-000000000000'
returning id;  -- any id returned is a row a stranger can change
rollback;""", "check-pl-012.sql"),
    fix="""<p>Scope both writes to the row's owner. <code>USING</code> picks the rows a user may touch; <code>WITH CHECK</code> stops them handing a row to someone else.</p>""" +
    sql("""! drop policy "Signed-in users can update posts" on public.posts;
! drop policy "Signed-in users can delete posts" on public.posts;
+ create policy "Authors update own posts"
+   on public.posts for update to authenticated
+   using ((select auth.uid()) = user_id)
+   with check ((select auth.uid()) = user_id);
+ create policy "Authors delete own posts"
+   on public.posts for delete to authenticated
+   using ((select auth.uid()) = user_id);""", "supabase/migrations/…_fix_post_writes.sql") +
    """<p class="small muted">If moderators must delete any post, add a separate delete policy for them using a role helper such as <code>public.has_role('moderator')</code> (see <a href="/findings/pl-020">PL-020</a>), rather than widening the author policy.</p>""",
    proof_tr=None, proof_note=COMING_LAB,
    intended="""<p>Shared editing is real: a team document, a project board, a wiki. Even then the rule is "members of this team", not "anyone signed in", so scope the policy to the membership table your app already has. A table where literally every account may edit every row is rare: a public wiki where accounts are approved by hand is the usual example.</p>""",
    sevwhy="""<p>Critical, because the attacker needs nothing but a free account, and the damage lands on other people: rewritten content, cancelled bookings, deleted records. Deletes can't be undone without a backup.</p>""",
    study=None,
    lint="""<dl class="lint"><dt>0024 permissive_rls_policy</dt><dd>Flags the policy only when it is literally <code>true</code>. <code>using (auth.uid() is not null)</code> does the same thing and passes the lint.</dd></dl>""",
    related=["PL-005", "PL-004", "PL-002"],
))

# ------------------------------------------------------------------ PL-013
F.append(dict(
    id="PL-013", slug="pl-013", group="data", line="lab", status="coming",
    title="Users can make themselves admin",
    short="A role column or roles table that users can write to. One request turns a normal account into an admin.",
    desc="PL-013: users can give themselves the admin role in a Supabase app through a role column or roles table they can write to. How to check, the fix, and why it's critical.",
    sev="critical", who="Anyone who signs up", found="Not tested yet: coming to PatchLabs Lab",
    proof="Coming",
    what="""<p>Many apps keep each user's role in the database: a <code>role</code> column on <code>profiles</code>, or a separate <code>user_roles</code> table read by a helper such as <code>has_role()</code>. Every admin policy then trusts that value. PL-013 means a normal user can write it.</p>
<p>Two shapes are common. In the first, users may update their own profile row and nothing limits which columns they change, so <code>update profiles set role = 'admin'</code> on their own row succeeds (the policy shape is <a href="/findings/pl-004">PL-004</a>). In the second, the roles table has an insert policy like <code>with check (auth.uid() = user_id)</code>, meant as "users can create their own role row", which also lets a user insert the row <em>(their id, 'admin')</em>.</p>""",
    why="""<p>AI builders are good at producing a roles table, a <code>has_role</code> function and admin policies, which looks like a complete design. The write side gets less attention. The sign-up flow needs to create a role row, the quickest way to allow that is to let users insert their own, and nobody constrains the value. Profile edit forms add a generic "users can update own profile" policy that covers every column, including <code>role</code>.</p>""",
    vuln=sql("""create type public.app_role as enum ('admin', 'user');

create table public.user_roles (
  id bigint generated always as identity primary key,
  user_id uuid not null references auth.users (id) on delete cascade,
  role public.app_role not null default 'user',
  unique (user_id, role)
);
alter table public.user_roles enable row level security;

create policy "Users can read own roles"
  on public.user_roles for select to authenticated
  using (auth.uid() = user_id);

-- Meant for sign-up. Also lets a user insert (their id, 'admin').
create policy "Users can insert own role"
  on public.user_roles for insert to authenticated
  with check (auth.uid() = user_id);""", "supabase/migrations/…_roles.sql (vulnerable)"),
    check=sql("""-- 1. Write policies on tables that hold roles or privileges
select p.tablename, p.policyname, p.cmd, p.with_check
from pg_policies p
where p.schemaname = 'public'
  and p.cmd in ('INSERT', 'UPDATE', 'ALL')
  and exists (
    select 1 from information_schema.columns c
    where c.table_schema = 'public' and c.table_name = p.tablename
      and c.column_name in ('role', 'roles', 'is_admin', 'plan', 'credits', 'is_verified')
  );

-- 2. Can signed-in users write a role column directly?
select table_name, column_name, privilege_type
from information_schema.column_privileges
where table_schema = 'public' and grantee = 'authenticated'
  and privilege_type in ('INSERT', 'UPDATE')
  and column_name in ('role', 'is_admin');""", "check-pl-013.sql") +
    """<p>Then try it. Use the id of a real, normal test user in your project (the foreign key needs one); the transaction is rolled back.</p>""" +
    sql("""begin;
set local role authenticated;
select set_config('request.jwt.claims',
  '{"sub":"<a normal test user id>","role":"authenticated"}', true);
insert into public.user_roles (user_id, role)
values ('<a normal test user id>', 'admin');  -- INSERT 0 1 means self-promotion works
rollback;""", "try-pl-013.sql"),
    fix="""<p>Users shouldn't write roles at all. New users get the default role from a trigger, and admins are granted from the server (with the service role key) or the SQL editor.</p>""" +
    sql("""! drop policy "Users can insert own role" on public.user_roles;
+ create or replace function public.handle_new_user_role()
+ returns trigger
+ language plpgsql
+ security definer
+ set search_path = ''
+ as $$
+ begin
+   insert into public.user_roles (user_id, role) values (new.id, 'user');
+   return new;
+ end;
+ $$;
+ create trigger on_auth_user_created_role
+   after insert on auth.users
+   for each row execute function public.handle_new_user_role();""", "supabase/migrations/…_fix_roles.sql") +
    """<p>For a role column on <code>profiles</code>, limit which columns users may change. The column grant is what blocks the role change:</p>""" +
    sql("""revoke update on public.profiles from authenticated;
grant update (full_name, avatar_url) on public.profiles to authenticated;""", "variant: role column on profiles"),
    proof_tr=None, proof_note=COMING_LAB,
    intended="""<p>Never for roles that unlock other people's data. A user choosing a harmless account type at sign-up ("buyer" or "seller") can be fine if neither type grants access to anything extra. Constrain the values so "admin" can't sneak in: <code>with check (auth.uid() = user_id and role in ('buyer', 'seller'))</code>.</p>""",
    sevwhy="""<p>Critical. An admin role usually unlocks every admin policy and every admin screen at once, and getting it needs only a free account and one request.</p>""",
    study=None, lint=None,
    related=["PL-004", "PL-019", "PL-020"],
))

# ------------------------------------------------------------------ PL-014
F.append(dict(
    id="PL-014", slug="pl-014", group="data", line="lab", status="coming",
    title="View skips row level security",
    short="Your table's policies are right, but a view on top of it runs as its owner and hands every row to the API.",
    desc="PL-014: a view in a Supabase app runs with its owner's rights, so it ignores row level security on the tables beneath it. How to check, and the security_invoker fix.",
    sev="high", sevlabel="high (critical with personal data)", who="Anyone the view is granted to, often anon", found="Not tested yet: coming to PatchLabs Lab",
    proof="Coming",
    what="""<p>A Postgres view is a saved query. By default it runs with the privileges of the view's <strong>owner</strong>, not the person querying it. In Supabase, views created by migrations or the SQL editor are owned by <code>postgres</code>, which usually owns the tables too, and a table's owner is not subject to that table's row level security (unless the table uses <code>force row level security</code>). So the view returns every row, whatever your policies say.</p>
<p>Views in the <code>public</code> schema are served by the API just like tables. If <code>anon</code> or <code>authenticated</code> can select from the view, one request to <code>/rest/v1/&lt;view name&gt;</code> skips your careful owner-only policy. Postgres 15 added the fix: <code>security_invoker = true</code> makes the view run as the caller, so the table's policies apply again.</p>
<p>Materialized views are stricter still: they store their results and support neither row level security nor <code>security_invoker</code>, so they must be kept away from the API roles entirely.</p>""",
    why="""<p>Views are how AI builders join tables for a dashboard ("orders with the customer's name") or hide a column. The request is about the shape of the data, and the generated view is correct SQL. Nothing in that SQL says it changes <em>who</em> the query runs as.</p>""",
    vuln=sql("""-- The table is locked to owners...
create policy "Users read own orders"
  on public.orders for select to authenticated
  using ((select auth.uid()) = user_id);

-- ...but this view runs as its owner and returns every order
create view public.order_summaries as
  select o.id, o.total, o.created_at, p.full_name, p.email
  from public.orders o
  join public.profiles p on p.id = o.user_id;

grant select on public.order_summaries to anon, authenticated;""", "supabase/migrations/…_views.sql (vulnerable)"),
    check=sql("""-- 1. Views in public that run as their owner, and who can read them
select c.relname as view_name,
       case c.relkind when 'm' then 'materialized view' else 'view' end as kind,
       has_table_privilege('anon', c.oid, 'select') as anon_can_read,
       has_table_privilege('authenticated', c.oid, 'select') as signed_in_can_read
from pg_class c
join pg_namespace n on n.oid = c.relnamespace
where n.nspname = 'public'
  and c.relkind in ('v', 'm')
  and not coalesce(array_to_string(c.reloptions, ',')
                   ~* 'security_invoker=(true|on|1|yes)', false);

-- 2. Read a view as a logged-out visitor (nothing is changed)
begin;
set local role anon;
select count(*) from public.order_summaries;  -- more than 0: visitors read it
rollback;""", "check-pl-014.sql"),
    fix="""<p>Make the view run as the caller, and take it away from roles that never needed it.</p>""" +
    sql("""+ alter view public.order_summaries set (security_invoker = true);
+ revoke select on public.order_summaries from anon;""", "supabase/migrations/…_fix_views.sql") +
    """<p>With <code>security_invoker</code> on, the caller needs read access to the underlying tables and every table's policies apply, so a signed-in user now sees only their own orders, joined to their own profile. For new views, write it in from the start: <code>create view public.x with (security_invoker = true) as …</code>. For a materialized view, <code>revoke select … from anon, authenticated</code> and serve it through a function that filters by <code>auth.uid()</code>, or move it to a schema the API doesn't expose.</p>""",
    proof_tr=None, proof_note=COMING_LAB,
    intended="""<p>An owner-rights view can be a deliberate way to publish a safe subset: listing counts per city, or the public columns of profiles. That is fine when the view selects only data meant for everyone, and worth a comment in the migration saying so, because Supabase's linter will keep flagging it.</p>""",
    sevwhy="""<p>High by default: the view exposes only the columns it selects, to the roles it is granted to. Treat it as critical when it carries personal columns (emails, phone numbers) to <code>anon</code>, because then it is <a href="/findings/pl-001">PL-001</a> by another route.</p>""",
    study=None,
    lint="""<dl class="lint"><dt>0010 security_definer_view</dt><dd>Flags views that run as their owner. The same pattern, from the database side.</dd>
<dt>0002 auth_users_exposed</dt><dd>Flags views that expose <code>auth.users</code> to the API roles.</dd>
<dt>0016 materialized_view_in_api</dt><dd>Flags materialized views the API can read.</dd></dl>""",
    related=["PL-001", "PL-006", "PL-008"],
))

# ------------------------------------------------------------------ PL-015
F.append(dict(
    id="PL-015", slug="pl-015", group="data", line="lab", status="coming",
    title="Stored files readable or writable by anyone",
    short="The bucket is private, but its storage policies let anyone read, upload, replace or delete other people's files.",
    desc="PL-015: storage.objects policies in a Supabase app let anyone read, upload or delete files in a bucket. How to check, the per-user folder fix, and how it differs from a public bucket.",
    sev="high", who="Anyone the policy applies to, often anon", found="Not tested yet: coming to PatchLabs Lab",
    proof="Coming",
    what="""<p>Supabase Storage keeps a row for every file in <code>storage.objects</code>, and row level security policies on that table decide who can download, list, upload, replace and delete files through the Storage API. PL-015 means one of those policies checks only the bucket, for example <code>using (bucket_id = 'documents')</code>, so it covers every file in the bucket and, with no <code>to</code> clause, logged-out visitors as well.</p>
<p>This is different from <a href="/findings/pl-007">PL-007</a>. A public bucket serves files by URL to anyone, without checking the read policy. A private bucket with a broad read policy is just as open to anyone who asks the API, and a broad insert, update or delete policy is worse: anyone can upload into your bucket, replace another user's file, or delete it.</p>""",
    why="""<p>Uploading is where builders meet their first storage error, "new row violates row-level security policy". The quick fix is one policy per command that names only the bucket. The safer per-user folder pattern needs the upload path to start with the user's id, which means changing the upload code too, so it gets skipped.</p>""",
    vuln=sql("""insert into storage.buckets (id, name, public)
values ('documents', 'documents', false);  -- private, so it looks safe

create policy "Allow uploads" on storage.objects
  for insert with check (bucket_id = 'documents');
create policy "Allow reads" on storage.objects
  for select using (bucket_id = 'documents');
create policy "Allow deletes" on storage.objects
  for delete using (bucket_id = 'documents');""", "supabase/migrations/…_storage.sql (vulnerable)"),
    check=sql("""-- 1. Every policy on storage.objects, ones that never mention the user first
select policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'storage' and tablename = 'objects'
order by (coalesce(qual, '') || coalesce(with_check, '')) ilike '%auth.uid()%', cmd;

-- 2. File names a logged-out visitor can see (nothing is changed)
begin;
set local role anon;
select name from storage.objects where bucket_id = 'documents' limit 20;
rollback;""", "check-pl-015.sql"),
    fix="""<p>Give each user a folder named after their id, and let them touch only that folder.</p>""" +
    sql("""! drop policy "Allow uploads" on storage.objects;
! drop policy "Allow reads" on storage.objects;
! drop policy "Allow deletes" on storage.objects;
+ create policy "Users upload to own folder" on storage.objects
+   for insert to authenticated
+   with check (bucket_id = 'documents'
+     and (storage.foldername(name))[1] = (select auth.uid())::text);
+ create policy "Users read own files" on storage.objects
+   for select to authenticated
+   using (bucket_id = 'documents'
+     and (storage.foldername(name))[1] = (select auth.uid())::text);
+ create policy "Users delete own files" on storage.objects
+   for delete to authenticated
+   using (bucket_id = 'documents'
+     and (storage.foldername(name))[1] = (select auth.uid())::text);""", "supabase/migrations/…_fix_storage.sql") +
    """<p>The code change that goes with it: upload to <code>`${user.id}/${file.name}`</code>, and show files with <code>createSignedUrl(path, 60)</code>. Replacing a file with <code>upsert: true</code> also needs matching select and update policies.</p>""",
    proof_tr=None, proof_note=COMING_LAB,
    intended="""<p>Public reads of public assets, such as avatars or product photos, are fine: use a public bucket or a read policy limited to that bucket. Anonymous uploads are rarely intended. If a public form must accept files, limit the bucket's file size and allowed file types in its settings, and never let the public read that bucket back.</p>""",
    sevwhy="""<p>High. Reading other people's files often means ID documents, invoices or contracts, and write access lets anyone replace a file your users will download and trust.</p>""",
    study=None, lint=None,
    related=["PL-007", "PL-001", "PL-012"],
))

# ------------------------------------------------------------------ PL-016
F.append(dict(
    id="PL-016", slug="pl-016", group="data", line="lab", status="coming",
    title="Realtime sends private rows to subscribers",
    short="A table is published to Realtime and its read policy is too broad, so new rows stream to people who shouldn't see them.",
    desc="PL-016: a Supabase table in the supabase_realtime publication streams private rows because its read policy is too broad or RLS is off. How to check and fix it.",
    sev="high", who="Anyone the table's read policy lets in", found="Not tested yet: coming to PatchLabs Lab",
    proof="Coming",
    what="""<p>Supabase Realtime can stream every insert, update and delete on a table to subscribed browsers ("Postgres Changes"). A table takes part when it is in the <code>supabase_realtime</code> publication, which is what the dashboard's Realtime switch does. Before sending a change, Realtime checks whether each subscriber may read that row under the table's <code>SELECT</code> policies, using the subscriber's own token.</p>
<p>So a stream is exactly as private as the read policy. PL-016 means a published table holds private rows and its read policy lets the wrong people through (<a href="/findings/pl-001">PL-001</a> or <a href="/findings/pl-002">PL-002</a>), or row level security is off (<a href="/findings/pl-008">PL-008</a>). Then anyone can open a channel with your public key and receive new messages, orders or bookings as they happen, without ever querying the table.</p>
<p>Delete events are a special case: Postgres can't check a policy against a row that no longer exists, so they go to every subscriber, and when row level security is on they carry only the primary key. Broadcast and Presence channels have their own authorization and aren't covered here.</p>""",
    why="""<p>Chat, notifications and live dashboards are popular requests, and the fix for "messages don't update live" is to switch Realtime on for the table. The read policy was usually written earlier and loosely, often <code>to authenticated using (true)</code>, because during development every user was the same test account.</p>""",
    vuln=sql("""create table public.messages (
  id bigint generated always as identity primary key,
  sender_id uuid not null references auth.users (id),
  recipient_id uuid not null references auth.users (id),
  body text not null,
  created_at timestamptz not null default now()
);
alter table public.messages enable row level security;

create policy "Signed-in users can read messages"
  on public.messages for select to authenticated using (true);

-- Every new message now streams to every signed-in subscriber
alter publication supabase_realtime add table public.messages;""", "supabase/migrations/…_messages.sql (vulnerable)") +
    sql("""// Any signed-in user, in the browser console of your app
supabase
  .channel('anything')
  .on('postgres_changes',
      { event: 'INSERT', schema: 'public', table: 'messages' },
      (payload) => console.log(payload.new))  // other people's messages
  .subscribe();""", "what a stranger runs"),
    check=sql("""-- 1. Tables published to Realtime, and whether RLS is on
select pt.schemaname, pt.tablename, c.relrowsecurity as rls_on
from pg_publication_tables pt
join pg_namespace n on n.nspname = pt.schemaname
join pg_class c on c.relnamespace = n.oid and c.relname = pt.tablename
where pt.pubname = 'supabase_realtime';

-- 2. Their read policies: Realtime sends a row to whoever these let read it
select tablename, policyname, roles, qual
from pg_policies
where schemaname = 'public' and cmd in ('SELECT', 'ALL')
  and tablename in (select tablename from pg_publication_tables
                    where pubname = 'supabase_realtime');""", "check-pl-016.sql") +
    """<p>Any published table with RLS off, or with a read policy that doesn't mention the user, is streaming to more people than you think. Test those tables with the <a href="/findings/pl-001">PL-001</a> and <a href="/findings/pl-002">PL-002</a> queries.</p>""",
    fix="""<p>Fix the read policy, and the stream fixes itself. If nothing in the app listens to the table, take it out of the publication instead.</p>""" +
    sql("""! drop policy "Signed-in users can read messages" on public.messages;
+ create policy "Participants read their messages"
+   on public.messages for select to authenticated
+   using ((select auth.uid()) in (sender_id, recipient_id));

-- or, if nothing subscribes to this table:
-- alter publication supabase_realtime drop table public.messages;""", "supabase/migrations/…_fix_messages.sql") +
    """<p class="small muted">A client-side <code>filter: 'recipient_id=eq.' + user.id</code> on the subscription saves bandwidth, but it is not security: the subscriber writes the filter.</p>""",
    proof_tr=None, proof_note=COMING_LAB,
    intended="""<p>A public feed or a live scoreboard: if the rows are meant to be public, so is their stream. The question is always the read policy.</p>""",
    sevwhy="""<p>High: private data is delivered the moment it's created, with no query to notice. It needs a read-policy problem first, which carries its own severity; Realtime adds speed and silence.</p>""",
    study=None, lint=None,
    related=["PL-002", "PL-001", "PL-008"],
))

# ------------------------------------------------------------------ PL-019
F.append(dict(
    id="PL-019", slug="pl-019", group="keys", line="code", status="live",
    title="Access decided by user_metadata, which users can edit",
    short="Roles stored where users can rewrite them. One call from the browser and they're an admin.",
    desc="PL-019: a Supabase app decides roles or access from user_metadata, which every user can change. user_metadata vs app_metadata, how to check, and the fix.",
    sev="critical", sevlabel="critical (high for plans and credits)", who="Anyone who signs up", found="PatchLabs Code: SQL policies, triggers and app code",
    proof="Not lab-proven: file and line in the report",
    what="""<p>Every Supabase user has two metadata objects. <code>user_metadata</code> (stored as <code>raw_user_meta_data</code>) is for profile details, and the user can set it: at sign-up through <code>options.data</code>, and at any time with <code>supabase.auth.updateUser({ data: … })</code>. <code>app_metadata</code> (<code>raw_app_meta_data</code>) can only be changed with the service role key, from a server.</p>
<p>Both appear in the user's access token, so a policy can read either through <code>auth.jwt()</code>. PL-019 means something decides access from <code>user_metadata</code>: a policy such as <code>(auth.jwt() -&gt; 'user_metadata' -&gt;&gt; 'role') = 'admin'</code>, a sign-up trigger that copies <code>raw_user_meta_data -&gt;&gt; 'role'</code> into a role column, or frontend code that shows admin screens when <code>user.user_metadata.role === 'admin'</code>. Any user can give themselves that value.</p>""",
    why="""<p>Sign-up forms collect a name and sometimes an account type, and the natural place for extra sign-up fields is <code>options.data</code>, which lands in <code>user_metadata</code>. When roles come up later, a role is already sitting there, readable from both the token and the frontend, so it gets used.</p>""",
    vuln=sql("""-- A policy that trusts a value the user controls
create policy "Admins read all profiles"
  on public.profiles for select to authenticated
  using ((auth.jwt() -> 'user_metadata' ->> 'role') = 'admin');

-- A sign-up trigger that copies the user's chosen role into the database
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = ''
as $$
begin
  insert into public.profiles (id, full_name, role)
  values (new.id, new.raw_user_meta_data ->> 'full_name',
          coalesce(new.raw_user_meta_data ->> 'role', 'user'));
  return new;
end;
$$;

-- What any user can run in the browser:
--   await supabase.auth.updateUser({ data: { role: 'admin' } })
--   await supabase.auth.refreshSession()  -- the new token says admin""", "supabase/migrations/…_auth.sql (vulnerable)"),
    check=sql("""-- 1. Policies that read user_metadata
select schemaname, tablename, policyname, qual, with_check
from pg_policies
where coalesce(qual, '') ilike '%user_metadata%'
   or coalesce(with_check, '') ilike '%user_metadata%';

-- 2. Your functions and triggers that read raw_user_meta_data
select n.nspname as schema, p.proname as function_name
from pg_proc p join pg_namespace n on n.oid = p.pronamespace
where n.nspname not in ('pg_catalog', 'information_schema', 'auth', 'storage')
  and p.prosrc ilike '%raw_user_meta_data%';""", "check-pl-019.sql") +
    """<p>A function that copies <code>full_name</code> or an avatar is fine; look for role, plan, credits or anything like <code>is_admin</code>. In the frontend: <code>grep -rn "user_metadata" src</code>.</p>""",
    fix="""<p>Keep anything that grants access in <code>app_metadata</code>, which only your server can write, or in a roles table users can't write (see <a href="/findings/pl-013">PL-013</a>).</p>""" +
    sql("""! drop policy "Admins read all profiles" on public.profiles;
+ create policy "Admins read all profiles"
+   on public.profiles for select to authenticated
+   using ((auth.jwt() -> 'app_metadata' ->> 'role') = 'admin');
+ -- and in handle_new_user(): always insert role 'user', never the sign-up value""", "supabase/migrations/…_fix_roles.sql") +
    sql("""// On a server or in an Edge Function, with the service role key
await admin.auth.admin.updateUserById(userId, {
  app_metadata: { role: 'admin' },
});
// The user's token picks this up on its next refresh.""", "granting a role from the server"),
    proof_tr=tr("code scan · report excerpt", [
        "{STEP:SCAN}    supabase/migrations/…_auth.sql:4",
        "~          user_metadata ->> 'role'    {LEAK}",
        "^          src/components/AdminRoute.tsx:9",
        "~          user_metadata.role === 'admin'",
        "{STEP:FIX}     app_metadata or a roles table",
    ], '<span class="pill plain">synthetic example</span><span>Report excerpt · read from the repo, not lab-proven</span>'),
    proof_note="""<p>PatchLabs Code reads your SQL (policies, triggers and functions in your migrations) and your app code, and flags any place where a role, admin flag, plan or credit balance is read from <code>user_metadata</code>. Role and admin checks are rated critical; plans and credits high. The report gives the file and line. A Lab test that signs a stranger in with an edited <code>user_metadata</code> and re-reads your tables is coming; until then this is a code finding, not a lab proof.</p>""",
    intended="""<p><code>user_metadata</code> is the right place for display details the user owns: name, avatar URL, preferred language. It is never the right place for anything that grants access, a plan or credits.</p>""",
    sevwhy="""<p>Critical: a one-line privilege escalation from the browser, needing only an account.</p>""",
    study=None,
    lint="""<dl class="lint"><dt>0015 rls_references_user_metadata</dt><dd>Flags policies that read <code>user_metadata</code>. It doesn't look at triggers or frontend code.</dd></dl>""",
    related=["PL-013", "PL-020", "PL-018"],
))

CODE_FOOT = '<span class="pill plain">synthetic example</span><span>Report excerpt · read from the repo, not lab-proven</span>'

# ------------------------------------------------------------------ PL-017
F.append(dict(
    id="PL-017", slug="pl-017", group="keys", line="code", status="live",
    title="Edge function open without sign-in while using the service key",
    short="A server function holding the key that ignores every rule, with nothing checking who is calling it.",
    desc="PL-017: a Supabase Edge Function uses the service role key, has JWT verification off and never checks the caller. How to check, and the fix with auth.getUser.",
    sev="high", who="Anyone who finds the function's URL", found="PatchLabs Code: supabase/config.toml and supabase/functions",
    proof="Not lab-proven: file and line in the report",
    what="""<p>Edge Functions are the right home for the service role key: it lives in a server-side secret and the browser never sees it. But the key bypasses row level security, so the function itself becomes the access rule. PL-017 means a function uses <code>SUPABASE_SERVICE_ROLE_KEY</code>, has the platform's sign-in check switched off with <code>verify_jwt = false</code> in <code>supabase/config.toml</code>, and has no check of its own on who is calling.</p>
<p>A function's URL is not a secret. It follows a fixed pattern, <code>https://&lt;project&gt;.supabase.co/functions/v1/&lt;name&gt;</code>, and appears in your frontend bundle. Anyone can call it with whatever body they like.</p>
<p>Turning <code>verify_jwt</code> back on is not the whole answer either. On projects using the legacy API keys, the public anon key is itself a valid JWT, so the platform check proves only that the caller has your public key, which every visitor does. The check that counts is inside the function: ask Supabase Auth whose token this is.</p>""",
    why="""<p>The service key makes things work: the function reads every table without fighting policies. JWT verification gets switched off when a call from a webhook, a cron job or a not-yet-signed-in page fails with a 401. The generated function handles the happy path, a call from your own app, and nothing tests a call from anywhere else.</p>""",
    vuln=sql("""// supabase/functions/delete-account/index.ts
import { createClient } from 'npm:@supabase/supabase-js@2';

Deno.serve(async (req) => {
  const { userId } = await req.json();
  const admin = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
  );
  // Nothing checks who is calling: anyone can delete any account
  await admin.auth.admin.deleteUser(userId);
  return Response.json({ ok: true });
});

# supabase/config.toml
[functions.delete-account]
verify_jwt = false""", "supabase/functions/delete-account (vulnerable)"),
    check=sql("""# 1. Functions with the platform sign-in check switched off
grep -n -B2 "verify_jwt *= *false" supabase/config.toml

# 2. Which functions use the service key
grep -rln "SUPABASE_SERVICE_ROLE_KEY" supabase/functions

# 3. Of those, which never ask who the caller is
for f in $(grep -rl "SUPABASE_SERVICE_ROLE_KEY" supabase/functions); do
  grep -qE "auth\\.getUser|getClaims|constructEvent" "$f" || echo "no caller check: $f"
done""", "check-pl-017.sh") +
    """<p>Shared helpers in <code>supabase/functions/_shared</code> count too, so read the hits rather than trusting the grep. To try a call without a sign-in, run the function locally (<code>supabase start</code>, then <code>supabase functions serve</code>) and call <code>http://127.0.0.1:54321/functions/v1/&lt;name&gt;</code> with only the anon key. Never test a destructive function against real users.</p>""",
    fix="""<p>Identify the caller from their token before touching the service key, and take the user's id from the token rather than the body.</p>""" +
    sql("""import { createClient } from 'npm:@supabase/supabase-js@2';

Deno.serve(async (req) => {
  const token = req.headers.get('Authorization')?.replace('Bearer ', '');
  if (!token) return new Response('Unauthorized', { status: 401 });

  const admin = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
  );
  // Ask Supabase Auth whose token this is. The anon key has no user, so it fails here.
  const { data: { user }, error } = await admin.auth.getUser(token);
  if (error || !user) return new Response('Unauthorized', { status: 401 });

  // Callers can delete only their own account
  await admin.auth.admin.deleteUser(user.id);
  return Response.json({ ok: true });
});""", "supabase/functions/delete-account/index.ts (fixed)") +
    """<p>Then set <code>verify_jwt = true</code> for the function again, unless it must accept calls without a Supabase session (a webhook, a cron job). Those need their own proof of origin: a verified signature (<a href="/findings/pl-021">PL-021</a>) or a shared secret header. For admin-only functions, check the role after <code>getUser</code>, from <code>app_metadata</code> or a roles table.</p>""",
    proof_tr=tr("code scan · report excerpt", [
        "{STEP:SCAN}    supabase/config.toml:14",
        "~          verify_jwt = false",
        "^          delete-account/index.ts:6",
        "~          service key, no caller check {LEAK}",
        "{STEP:FIX}     verify the caller with getUser",
        "{STEP:RESCAN}  0 open functions          {OK}",
    ], CODE_FOOT),
    proof_note="""<p>PatchLabs Code reads your repo; it never calls your functions. It flags a function when three things line up: <code>verify_jwt = false</code> for it in <code>supabase/config.toml</code>, the service role key used in its files, and no caller check of its own (such as <code>auth.getUser</code>, a webhook signature check or a secret header). A function with <code>verify_jwt = false</code> that does check its caller, or doesn't use the service key, is listed as information, not as this finding. The report gives the file and line; a re-check confirms it's gone.</p>""",
    intended="""<p>Functions that must be callable without a Supabase session are normal: payment webhooks, cron jobs, a public contact form. They are fine when something else proves the caller (a signature, a secret header), or when the function only does something harmless for anyone. A public function that only returns public data shouldn't need the service key at all.</p>""",
    sevwhy="""<p>High: the function can do anything the service key can, which is everything, but an attacker has to find it and work out what body it expects. In practice that is a look at your frontend bundle.</p>""",
    study=None, lint=None,
    related=["PL-022", "PL-010", "PL-021"],
))

# ------------------------------------------------------------------ PL-018
F.append(dict(
    id="PL-018", slug="pl-018", group="keys", line="code", status="live",
    title="Sign-ups need no email confirmation",
    short="Anyone can create a working account with any email address, including one they don't own.",
    desc="PL-018: a Supabase project lets people sign up without confirming their email. When that becomes a security problem, how to check, and the fix.",
    sev="low", who="Anyone", found="PatchLabs Code: supabase/config.toml",
    proof="Not lab-proven: file and line in the report",
    what="""<p>With email confirmation off, <code>signUp()</code> returns a working session straight away, for any address typed in. The account works before anyone proves they own the inbox. On its own that is a product decision, which is why this finding is low severity. It becomes a security problem in two situations:</p>
<ul><li><strong>Access decided by email.</strong> A policy or admin check such as <code>(auth.jwt() -&gt;&gt; 'email') like '%@yourco.com'</code> is passed by signing up with any new address at that domain. An allow-list of addresses is passed by signing up with one that hasn't registered yet.</li>
<li><strong>Rules that trust "signed in".</strong> Every <a href="/findings/pl-002">PL-002</a> and <a href="/findings/pl-012">PL-012</a> becomes reachable by a script creating throwaway accounts with no inbox behind them.</li></ul>""",
    why="""<p>Confirmation emails need an email provider and slow down testing, so they get switched off during development. The local <code>supabase/config.toml</code> created by the Supabase CLI has confirmations off by default, and that file reaches a hosted project if someone pushes the config.</p>""",
    vuln=sql("""# supabase/config.toml
[auth.email]
enable_signup = true
enable_confirmations = false""", "supabase/config.toml (vulnerable)") +
    sql("""-- ...together with a policy that trusts the email claim
create policy "Staff read all orders"
  on public.orders for select to authenticated
  using ((auth.jwt() ->> 'email') like '%@yourco.com');""", "supabase/migrations/…_staff.sql (vulnerable)"),
    check="""<p>Check the hosted project first: in your Supabase dashboard's authentication settings, the Email provider's <strong>Confirm email</strong> option should be on. Hosted projects start with it on. Then check the repo and your policies:</p>""" +
    sql("""# In the repo
grep -n "enable_confirmations" supabase/config.toml""", "check-pl-018.sh") +
    sql("""-- Policies that decide access from an email address
select tablename, policyname, qual, with_check
from pg_policies
where coalesce(qual, '') ilike '%email%'
   or coalesce(with_check, '') ilike '%email%';""", "check-pl-018.sql"),
    fix=sql("""# supabase/config.toml
[auth.email]
enable_confirmations = true""", "supabase/config.toml (fixed)") +
    """<p>And decide staff access from a table you control, not from what an address looks like:</p>""" +
    sql("""! drop policy "Staff read all orders" on public.orders;
+ create policy "Staff read all orders"
+   on public.orders for select to authenticated
+   using (exists (
+     select 1 from public.user_roles r
+     where r.user_id = (select auth.uid()) and r.role = 'staff'
+   ));""", "supabase/migrations/…_fix_staff.sql"),
    proof_tr=tr("code scan · report excerpt", [
        "{STEP:SCAN}    supabase/config.toml:42",
        "~          [auth.email]",
        "~          enable_confirmations = false {LEAK}",
        "{STEP:FIX}     confirm email in config",
        "~          and in the dashboard",
    ], CODE_FOOT),
    proof_note="""<p>PatchLabs reads your repo only, so it sees <code>supabase/config.toml</code>, not the live setting in your hosted project. When the file says confirmations are off, the report asks you to check the dashboard too. If the file is missing, there is nothing to flag, but the dashboard setting still matters.</p>""",
    intended="""<p>Fine for apps where an account holds nothing private and no access depends on the email address. Apps that sign in only with magic links or OAuth prove inbox or account ownership at every sign-in anyway.</p>""",
    sevwhy="""<p>Low, because it exposes nothing by itself. It raises the stakes of other findings: with no confirmation, "anyone who signs up" means anyone with a script, using any address.</p>""",
    study=None, lint=None,
    related=["PL-002", "PL-019", "PL-013"],
))

# ------------------------------------------------------------------ PL-020
F.append(dict(
    id="PL-020", slug="pl-020", group="keys", line="code", status="live",
    title="Admin check only in the browser",
    short="The admin page is hidden in the app, but nothing stops a normal user asking the database for the same data.",
    desc="PL-020: an AI-built React app protects admin pages only with a check in the browser. Why route guards aren't security, how to test it, and the database-side fix.",
    sev="high", who="Anyone who signs up, sometimes anyone", found="PatchLabs Code: your frontend code",
    proof="Not lab-proven: file and line in the report",
    what="""<p>A route guard such as <code>if (!isAdmin) return &lt;Navigate to="/" /&gt;</code> decides what the app <em>shows</em>. It does not decide what the database <em>returns</em>. Everything in the browser, including the admin check and the Supabase client, is under the user's control: they can run the same queries from the console or with curl, using the public key from your bundle and their own session.</p>
<p>PL-020 means admin access is decided in frontend code: comparing the signed-in email with a hard-coded address, reading <code>user_metadata.role</code> (<a href="/findings/pl-019">PL-019</a>), or checking a password stored in a <code>VITE_</code> variable. Whether that is a hole depends on the database. If the tables behind the admin page have their own admin-only rules, the guard is just good manners. If they don't, every user can read and change what the admin page manages.</p>""",
    why="""<p>Ask for an admin dashboard and you get a protected route and a page, which looks finished: a normal user who opens the link is sent away. Enforcing it in the database needs a roles model and policies, which the request never mentioned.</p>""",
    vuln=sql("""// src/pages/Admin.tsx
const ADMIN_EMAIL = 'founder@example.com';

export default function Admin() {
  const { user } = useAuth();
  const [orders, setOrders] = useState<Order[]>([]);

  useEffect(() => {
    supabase.from('orders').select('*').then(({ data }) => setOrders(data ?? []));
  }, []);

  if (user?.email !== ADMIN_EMAIL) return <Navigate to="/" />;
  return <OrdersTable orders={orders} />;
}

-- Meanwhile, in the database, any signed-in user can read every order:
-- create policy "Signed-in users read orders" on public.orders
--   for select to authenticated using (true);""", "src/pages/Admin.tsx (vulnerable)"),
    check="""<p>Sign in to your app as a normal test user, copy that user's access token (in the browser's local storage, under the key starting <code>sb-</code> and ending <code>-auth-token</code>, field <code>access_token</code>), and ask for the admin data directly:</p>""" +
    sql("""curl "https://<project>.supabase.co/rest/v1/orders?select=*&limit=5" \\
  -H "apikey: <your public anon key>" \\
  -H "Authorization: Bearer <the normal user's access token>"
# Rows that aren't this user's mean the admin page's data is open to everyone

# Where the app decides "admin" in the browser
grep -rnE "isAdmin|role ?=== ?['\\"]admin|ADMIN_EMAIL|user_metadata" src""", "check-pl-020.sh"),
    fix="""<p>Put the rule in the database, where the user can't edit it, then keep the route guard for a tidy experience.</p>""" +
    sql("""-- A helper policies can call; it answers only about the caller
create or replace function public.has_role(_role text)
returns boolean
language sql
stable
security definer
set search_path = ''
as $$
  select exists (
    select 1 from public.user_roles
    where user_id = (select auth.uid()) and role::text = _role
  );
$$;
revoke execute on function public.has_role(text) from public, anon;
grant execute on function public.has_role(text) to authenticated;

! drop policy "Signed-in users read orders" on public.orders;
+ create policy "Customers read own orders" on public.orders
+   for select to authenticated using ((select auth.uid()) = user_id);
+ create policy "Admins read all orders" on public.orders
+   for select to authenticated using ((select public.has_role('admin')));""", "supabase/migrations/…_admin_rules.sql") +
    """<p>In the app, decide whether to show the page from the same source: <code>const { data: isAdmin } = await supabase.rpc('has_role', { _role: 'admin' })</code>. The roles table itself must not be writable by users (<a href="/findings/pl-013">PL-013</a>).</p>""",
    proof_tr=tr("code scan · report excerpt", [
        "{STEP:SCAN}    src/pages/Admin.tsx:11",
        "~          admin decided by email      {LEAK}",
        "^          compare: tables the page reads",
        "{STEP:LAB}     orders → stranger reads    ",
        "~          see PL-002 in the same report",
    ], CODE_FOOT),
    proof_note="""<p>PatchLabs Code flags admin gates decided in the browser, with the file and line. Whether the data behind the page is open is a database question, and the Lab answers it for reads: if a signed-in stranger can read those tables, the same report shows <a href="/findings/pl-002">PL-002</a> with the lab proof.</p>""",
    intended="""<p>Hiding admin screens from non-admins is good practice; it is only a problem when it is the only control. If every table the page touches already has an admin-only rule in the database, the guard is just presentation and there is nothing to fix.</p>""",
    sevwhy="""<p>High: what sits behind an admin page is usually everyone's data. Not critical by default, because the database rules may already be right, and code alone can't tell.</p>""",
    study=None, lint=None,
    related=["PL-019", "PL-002", "PL-013"],
))

# ------------------------------------------------------------------ PL-021
F.append(dict(
    id="PL-021", slug="pl-021", group="keys", line="code", status="live",
    title="Payment webhook doesn't verify its signature",
    short="Anyone can send your app a fake 'payment succeeded' event and get the paid plan for free.",
    desc="PL-021: a Stripe, Lemon Squeezy or Paddle webhook handler trusts the request body without verifying the signature. The Supabase Edge Function fix with constructEventAsync.",
    sev="high", who="Anyone who finds the webhook URL", found="PatchLabs Code: webhook handlers in functions and API routes",
    proof="Not lab-proven: file and line in the report",
    what="""<p>A payment webhook tells your app that money moved: "checkout completed, give this user the Pro plan". Payment providers sign every webhook with a secret only you and they know; Stripe puts the signature in the <code>Stripe-Signature</code> header. PL-021 means the handler reads the event from the body and acts on it without checking that signature. Anyone who knows the URL can then post a hand-written <code>checkout.session.completed</code> event and upgrade any account, add credits or mark orders paid.</p>
<p>Webhook functions have to accept calls without a Supabase sign-in, because the provider has no user token, so they normally run with <code>verify_jwt = false</code>. That is correct, but it leaves the signature as the only thing between the URL and your database.</p>""",
    why="""<p>The generated handler parses JSON and switches on <code>event.type</code>, which is how simplified webhook examples look. Verifying needs the <em>raw</em> request body, so code that calls <code>req.json()</code> first can't verify at all. And Node examples use <code>constructEvent</code>, while in an Edge Function Stripe's library needs <code>constructEventAsync</code> with its Web Crypto provider; when the copied version errors, deleting the check gets the function deploying.</p>""",
    vuln=sql("""// supabase/functions/stripe-webhook/index.ts
import { createClient } from 'npm:@supabase/supabase-js@2';

Deno.serve(async (req) => {
  const event = await req.json();  // trusted as-is: anyone can send this
  if (event.type === 'checkout.session.completed') {
    const session = event.data.object;
    const admin = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    );
    await admin.from('profiles')
      .update({ plan: 'pro' })
      .eq('id', session.client_reference_id);
  }
  return new Response('ok');
});""", "supabase/functions/stripe-webhook/index.ts (vulnerable)"),
    check=sql("""# Webhook handlers that never verify a signature
grep -rlE "checkout\\.session\\.completed|invoice\\.paid|customer\\.subscription" \\
  supabase/functions src app pages 2>/dev/null | xargs grep -L "constructEvent"

# Send an unsigned fake event to your local function (supabase functions serve)
curl -i -X POST http://127.0.0.1:54321/functions/v1/stripe-webhook \\
  -H "Content-Type: application/json" \\
  -d '{"type":"checkout.session.completed","data":{"object":{"client_reference_id":"test"}}}'
# Expect 400. A 200 means anyone can fake a payment.""", "check-pl-021.sh"),
    fix="""<p>Read the raw body, verify it with your webhook signing secret, and only then trust the event.</p>""" +
    sql("""import Stripe from 'npm:stripe@17';
import { createClient } from 'npm:@supabase/supabase-js@2';

const stripe = new Stripe(Deno.env.get('STRIPE_SECRET_KEY')!);
const cryptoProvider = Stripe.createSubtleCryptoProvider();

Deno.serve(async (req) => {
  const signature = req.headers.get('Stripe-Signature');
  if (!signature) return new Response('Missing signature', { status: 400 });

  const body = await req.text();  // the raw body: parsing it first breaks the check
  let event: Stripe.Event;
  try {
    event = await stripe.webhooks.constructEventAsync(
      body, signature, Deno.env.get('STRIPE_WEBHOOK_SECRET')!,
      undefined, cryptoProvider,
    );
  } catch (_err) {
    return new Response('Invalid signature', { status: 400 });
  }

  if (event.type === 'checkout.session.completed') {
    const session = event.data.object as Stripe.Checkout.Session;
    const admin = createClient(
      Deno.env.get('SUPABASE_URL')!,
      Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
    );
    await admin.from('profiles')
      .update({ plan: 'pro' })
      .eq('id', session.client_reference_id);
  }
  return Response.json({ received: true });
});""", "supabase/functions/stripe-webhook/index.ts (fixed)") +
    """<p>Store <code>STRIPE_WEBHOOK_SECRET</code> (it starts <code>whsec_</code>) with <code>supabase secrets set</code>. Stripe can deliver the same event more than once, so record <code>event.id</code> and skip events you've already handled. Lemon Squeezy and Paddle sign their webhooks too; verify with their documented method before acting.</p>""",
    proof_tr=tr("code scan · report excerpt", [
        "{STEP:SCAN}    stripe-webhook/index.ts:5",
        "~          event read, never verified  {LEAK}",
        "{STEP:FIX}     constructEventAsync + secret",
        "{STEP:RESCAN}  signature verified        {OK}",
    ], CODE_FOOT),
    proof_note="""<p>PatchLabs Code looks for payment webhook handlers (Stripe, Lemon Squeezy and Paddle) in Edge Functions and API routes, and flags those that read the request body without a signature check. It never sends events to your app. The report gives the file and line where the body is read.</p>""",
    intended="""<p>Never, for payments. If a provider really doesn't sign its webhooks, treat the webhook as a hint only: fetch the payment from the provider's API with your secret key and act on what the API says.</p>""",
    sevwhy="""<p>High: free upgrades and direct revenue loss for anyone who finds a URL that is often guessable (<code>stripe-webhook</code>). Not critical by default, because it doesn't expose other users' data.</p>""",
    study=None, lint=None,
    related=["PL-017", "PL-022", "PL-011"],
))

# ------------------------------------------------------------------ PL-022
F.append(dict(
    id="PL-022", slug="pl-022", group="keys", line="code", status="live",
    title="Edge function trusts a user id sent in the request",
    short="The function acts on whichever user id the request names, so any user can act as any other.",
    desc="PL-022: a Supabase Edge Function or API route takes a user id from the request body and acts on it with the service key. How to check and the fix: take the id from the verified token.",
    sev="high", who="Anyone who can call the function, often any signed-in user", found="PatchLabs Code: functions and API routes",
    proof="Not lab-proven: file and line in the report",
    what="""<p>A function that uses the service role key decides for itself whose data to touch. PL-022 means it takes that decision from the request: <code>const { userId } = await req.json()</code>, or <code>?user_id=</code> in the URL, then reads or changes that user's rows. Even when the function checks that the caller is signed in, so it isn't <a href="/findings/pl-017">PL-017</a>, any user can put someone else's id in the body.</p>
<p>User ids are less secret than they look. They turn up in API responses, URLs, storage paths and other people's rows, so "nobody knows the id" is not a defence.</p>""",
    why="""<p>The frontend already has <code>user.id</code> to hand, so passing it to the function is the obvious way to say "for this user". The function trusts its input, and the test call always sends the right id.</p>""",
    vuln=sql("""// supabase/functions/get-profile/index.ts
import { createClient } from 'npm:@supabase/supabase-js@2';

Deno.serve(async (req) => {
  if (!req.headers.get('Authorization')) {
    return new Response('Unauthorized', { status: 401 });  // presence is not proof
  }
  const { userId } = await req.json();  // chosen by the caller
  const admin = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_SERVICE_ROLE_KEY')!,
  );
  const { data } = await admin.from('profiles')
    .select('email, phone, credits').eq('id', userId).single();
  return Response.json(data);
});""", "supabase/functions/get-profile/index.ts (vulnerable)"),
    check=sql("""# Functions and API routes that read an id from the request
grep -rnE "(userId|user_id|uid|profileId)" supabase/functions src/app app/api pages/api 2>/dev/null \\
  | grep -E "req(uest)?\\.json|searchParams|req\\.body|req\\.query\"""", "check-pl-022.sh") +
    """<p>Then run the function locally, sign in as test user A, and send test user B's id. If you get B's data back, or change B's rows, the function trusts the request.</p>""",
    fix="""<p>The simplest fix is to stop using the service key here: make a client that carries the caller's own token, so row level security applies exactly as it does in the browser.</p>""" +
    sql("""import { createClient } from 'npm:@supabase/supabase-js@2';

Deno.serve(async (req) => {
  const authHeader = req.headers.get('Authorization');
  if (!authHeader) return new Response('Unauthorized', { status: 401 });

  // Acts as the caller: your RLS policies decide what it can see
  const supabase = createClient(
    Deno.env.get('SUPABASE_URL')!,
    Deno.env.get('SUPABASE_ANON_KEY')!,
    { global: { headers: { Authorization: authHeader } } },
  );
  const { data: { user }, error } = await supabase.auth.getUser();
  if (error || !user) return new Response('Unauthorized', { status: 401 });

  // The id comes from the verified token, never from the body
  const { data } = await supabase.from('profiles')
    .select('email, phone, credits').eq('id', user.id).single();
  return Response.json(data);
});""", "supabase/functions/get-profile/index.ts (fixed)") +
    """<p>If the function genuinely needs the service key, verify the caller with <code>admin.auth.getUser(token)</code> first and use <code>user.id</code> from the result. If admins may act for other users, check the admin role, then accept the target id.</p>""",
    proof_tr=tr("code scan · report excerpt", [
        "{STEP:SCAN}    get-profile/index.ts:8",
        "~          userId taken from req.json() {LEAK}",
        "^          used with the service key",
        "{STEP:FIX}     id from auth.getUser()",
    ], CODE_FOOT),
    proof_note="""<p>PatchLabs Code reads Edge Functions and server API routes for user ids taken from the request body or query and used in a query or a privileged call. It doesn't call your functions. The report gives the file and line where the id is read.</p>""",
    intended="""<p>Admin tools that act on other users, after checking the caller is an admin, and public lookups that return only public fields (a seller's display name) are fine.</p>""",
    sevwhy="""<p>High: it reads or changes another user's data with nothing more than a valid account and their id.</p>""",
    study=None, lint=None,
    related=["PL-017", "PL-021", "PL-012"],
))

# ------------------------------------------------------------------ PL-023
F.append(dict(
    id="PL-023", slug="pl-023", group="keys", line="code", status="live",
    title="Dependency with a known vulnerability",
    short="A package version in your lockfile matches a published advisory in the OSV database.",
    desc="PL-023: an npm package version in your lockfile has a published vulnerability in OSV. How PatchLabs finds it, how to check with npm audit, and how to upgrade safely.",
    sev="from advisory", sevlabel="from the advisory", who="Depends on the advisory", found="PatchLabs Code: your lockfile and the OSV database",
    proof="Not lab-proven: package and advisory in the report",
    what="""<p>OSV (<a href="https://osv.dev">osv.dev</a>) is an open database of published vulnerabilities that gathers advisories from GitHub, npm and other sources, keyed by package and version. PL-023 means a package version pinned in your lockfile appears in one of those advisories. The report shows the package, the installed version, the advisory and, where the advisory names one, the version that fixes it.</p>
<p>A match means the version is affected. It doesn't prove your app reaches the vulnerable code. A cross-site scripting bug in a Markdown library matters if you render user content with it; a bug in a build tool's development server rarely matters in production. The advisory text usually says which conditions apply.</p>""",
    why="""<p>AI builders start from templates and pin whatever versions the template or the model knew, which can be well behind the current release. Nobody runs an audit on a project that works, and the lockfile quietly keeps old versions of packages you never installed directly.</p>""",
    vuln=sql("""// package.json
{
  "dependencies": {
    "lodash": "4.17.20"
  }
}
// lodash 4.17.20 is affected by CVE-2021-23337
// (command injection through _.template), fixed in 4.17.21""", "package.json (vulnerable)"),
    check=sql("""# npm's own audit, from the lockfile (production dependencies only)
npm audit --omit=dev

# Ask OSV about one package version directly
curl -s https://api.osv.dev/v1/query \\
  -d '{"package":{"name":"lodash","ecosystem":"npm"},"version":"4.17.20"}' | head -c 600""", "check-pl-023.sh"),
    fix=sql("""# A direct dependency: upgrade to the fixed version
npm install lodash@4.17.21

# A dependency of a dependency: force a fixed version (npm 8.3 or later)
# package.json
"overrides": {
  "lodash": "4.17.21"
}""", "the fix") +
    """<p>Run your tests after any upgrade, especially across a major version. <code>npm audit fix</code> applies the safe upgrades for you; avoid <code>--force</code> unless you have read what it will change.</p>""",
    proof_tr=tr("code scan · report excerpt", [
        "{STEP:SCAN}    package-lock.json",
        "~          lodash 4.17.20              {LEAK}",
        "^          CVE-2021-23337 · fixed 4.17.21",
        "{STEP:OSV}     checked against osv.dev",
        "~          offline: reported as skipped",
    ], CODE_FOOT),
    proof_note="""<p>PatchLabs Code reads exact versions from <code>package-lock.json</code>, <code>npm-shrinkwrap.json</code>, <code>pnpm-lock.yaml</code>, <code>yarn.lock</code> or <code>bun.lock</code>, or exact versions in <code>package.json</code> when there is no lockfile. It never installs packages or runs your code. Package names and versions, and nothing else from your repo, are sent to the public OSV API. If OSV can't be reached, the dependency check is reported as skipped rather than as clean.</p>""",
    intended="""<p>An advisory for a development-only tool that never runs in production can reasonably wait for your next upgrade. Note why, and upgrade when convenient; old versions collect more advisories over time.</p>""",
    sevwhy="""<p>Taken from the advisory, because its authors know the bug best. PatchLabs doesn't re-score it and doesn't check whether your code reaches the vulnerable function.</p>""",
    study=None, lint=None,
    related=["PL-024", "PL-011", "PL-017"],
))

# ------------------------------------------------------------------ PL-024
F.append(dict(
    id="PL-024", slug="pl-024", group="keys", line="code", status="live",
    title="User content rendered as raw HTML",
    short="Text one user wrote goes into the page as HTML, so it can run scripts in other users' browsers.",
    desc="PL-024: an AI-built React app renders user content with dangerouslySetInnerHTML or innerHTML without sanitising it. Why that exposes Supabase sessions, and the fix.",
    sev="medium", who="Any user who can post content others see", found="PatchLabs Code: your frontend code",
    proof="Not lab-proven: file and line in the report",
    what="""<p>React escapes text by default: <code>{comment.body}</code> shows <code>&lt;script&gt;</code> as harmless characters. <code>dangerouslySetInnerHTML</code>, <code>element.innerHTML</code> and Markdown libraries that output raw HTML switch that protection off. PL-024 means content someone else wrote, such as a comment, a bio, a listing description or a chat message, reaches one of those without being sanitised.</p>
<p>A user can then post HTML that runs JavaScript in every viewer's browser (cross-site scripting). In a Supabase app this matters more than usual: supabase-js keeps the session in <code>localStorage</code> by default, and any script running on your page can read it and act as the viewer, including an admin who opens the content to moderate it.</p>""",
    why="""<p>Asked to "support formatting" or "render Markdown", the shortest route is to convert to HTML and insert it. The name <code>dangerouslySetInnerHTML</code> is a warning, but the code works and test content is always friendly.</p>""",
    vuln=sql("""// src/components/Comment.tsx
import { marked } from 'marked';

export function Comment({ body }: { body: string }) {
  // body was written by another user
  return <div dangerouslySetInnerHTML={{ __html: marked.parse(body) as string }} />;
}

// A comment like this runs in every reader's browser:
//   <img src=x onerror="alert(document.domain)">""", "src/components/Comment.tsx (vulnerable)"),
    check=sql("""# Places that insert HTML
grep -rnE "dangerouslySetInnerHTML|\\.innerHTML *=|insertAdjacentHTML|v-html" src

# Then, on a local or staging copy, post this as a comment and view it:
#   <img src=x onerror="alert(document.domain)">
# An alert box means user content runs as code.""", "check-pl-024.sh"),
    fix=sql("""// src/components/Comment.tsx
import { marked } from 'marked';
import DOMPurify from 'dompurify';

export function Comment({ body }: { body: string }) {
  const html = DOMPurify.sanitize(marked.parse(body) as string);
  return <div dangerouslySetInnerHTML={{ __html: html }} />;
}""", "src/components/Comment.tsx (fixed)") +
    """<p>Simpler still, skip HTML: render plain text as <code>{body}</code>, or use <code>react-markdown</code>, which builds React elements and doesn't render raw HTML unless you add <code>rehype-raw</code>.</p>""",
    proof_tr=tr("code scan · report excerpt", [
        "{STEP:SCAN}    src/components/Comment.tsx:6",
        "~          dangerouslySetInnerHTML",
        "~          with unsanitised input      {LEAK}",
        "{STEP:FIX}     DOMPurify.sanitize(...)",
    ], CODE_FOOT),
    proof_note="""<p>PatchLabs Code flags raw-HTML insertion points whose input isn't passed through a sanitiser. It doesn't run your app or post content. The report gives the file and line; you decide whether that input can come from another user.</p>""",
    intended="""<p>HTML you control is fine: a static string, or content from your own CMS written by staff. Sanitising it anyway costs little and protects you if that changes.</p>""",
    sevwhy="""<p>Medium: it needs one user to post and another to view. It becomes serious when admins view user content, because their session can do more.</p>""",
    study=None, lint=None,
    related=["PL-020", "PL-023", "PL-017"],
))

# ------------------------------------------------------------------ PL-025
F.append(dict(
    id="PL-025", slug="pl-025", group="keys", line="code", status="live",
    title="Firebase rules allow anyone",
    short="Your Firestore, Realtime Database or Storage rules say yes to everyone, or do until a test-mode date.",
    desc="PL-025: a Firebase app's security rules let anyone read or write: allow read, write: if true, or expiring test-mode rules. How to check, owner-only rules, and how to test them.",
    sev="critical", who="Anyone on the internet", found="PatchLabs Code: firestore.rules, storage.rules, database.rules.json",
    proof="Not lab-proven: file and line in the report",
    what="""<p>Firebase apps talk to the database straight from the browser, like Supabase apps, and the config in your frontend (<code>apiKey</code>, <code>projectId</code>) is public by design. Security rules decide access. PL-025 means the rules in your repo let anyone in: <code>allow read, write: if true;</code>, a test-mode rule <code>if request.time &lt; timestamp.date(…)</code> that is open to everyone until that date, or <code>".read": true</code> and <code>".write": true</code> in Realtime Database.</p>
<p>A rule of <code>if request.auth != null</code> is Firebase's version of <a href="/findings/pl-002">PL-002</a>: anyone who signs up passes it.</p>""",
    why="""<p>Firebase's "test mode" start opens the database for 30 days so you can build without writing rules. Projects ship like that, or someone pushes the date forward when it expires and the app breaks. Generated rules often stop at <code>request.auth != null</code>, because "only signed-in users" sounds like the requirement.</p>""",
    vuln=sql("""// firestore.rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    match /{document=**} {
      allow read, write: if request.time < timestamp.date(2026, 12, 31);
    }
  }
}""", "firestore.rules (vulnerable)"),
    check=sql("""# Open rules in the repo
grep -nE "if true|request\\.time *<|\\.(read|write)\\"? *: *true" \\
  firestore.rules storage.rules database.rules.json 2>/dev/null""", "check-pl-025.sh") +
    """<p>Then test the rules the way an attacker would, against the local emulator. This test seeds one private document and checks that a visitor and a stranger are refused while the owner still reads it:</p>""" +
    sql("""// rules.test.mjs
// npm i -D firebase @firebase/rules-unit-testing
// run: firebase emulators:exec --only firestore "node rules.test.mjs"
import { readFileSync } from 'node:fs';
import { initializeTestEnvironment, assertFails, assertSucceeds } from '@firebase/rules-unit-testing';
import { doc, getDoc, setDoc } from 'firebase/firestore';

const env = await initializeTestEnvironment({
  projectId: 'demo-rules-check',
  firestore: { rules: readFileSync('firestore.rules', 'utf8') },
});
await env.withSecurityRulesDisabled(async (ctx) => {
  await setDoc(doc(ctx.firestore(), 'users/owner'), { email: 'owner@example.com' });
});

const visitor = env.unauthenticatedContext().firestore();
const stranger = env.authenticatedContext('stranger').firestore();
const owner = env.authenticatedContext('owner').firestore();

await assertFails(getDoc(doc(visitor, 'users/owner')));
await assertFails(getDoc(doc(stranger, 'users/owner')));
await assertSucceeds(getDoc(doc(owner, 'users/owner')));
console.log('visitor and stranger denied, owner reads');
await env.cleanup();""", "rules.test.mjs"),
    fix=sql("""// firestore.rules
rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Each user reads and writes only their own profile
    match /users/{userId} {
      allow read, write: if request.auth != null && request.auth.uid == userId;
    }
    // Posts: anyone can read; only the author can write, and can't hand it to someone else
    match /posts/{postId} {
      allow read: if true;
      allow create: if request.auth != null
        && request.resource.data.authorId == request.auth.uid;
      allow update: if request.auth != null
        && resource.data.authorId == request.auth.uid
        && request.resource.data.authorId == resource.data.authorId;
      allow delete: if request.auth != null
        && resource.data.authorId == request.auth.uid;
    }
  }
}""", "firestore.rules (fixed)") +
    """<p>Deploy with <code>firebase deploy --only firestore:rules</code>, and run the test above in CI so the rules can't quietly open up again.</p>""",
    proof_tr=tr("code scan · report excerpt", [
        "{STEP:SCAN}    firestore.rules:5",
        "~          read, write until 2026-12-31 {LEAK}",
        "{STEP:FIX}     owner-only rules",
        "~          emulator test in the report",
    ], CODE_FOOT),
    proof_note="""<p>PatchLabs Code reads the rules files in your repo. It never contacts your Firebase project, so rules edited in the Firebase console and never saved to the repo are invisible to it. If you edit rules in the console, copy them back into the repo.</p>""",
    intended="""<p>Public reads of public data, such as <code>allow read: if true;</code> on a products collection, are fine. Open writes almost never are.</p>""",
    sevwhy="""<p>Critical: anyone with your public config, which is in your frontend, can read, overwrite or delete the whole database.</p>""",
    study=None, lint=None,
    related=["PL-001", "PL-002", "PL-008"],
))

# ------------------------------------------------------------------ PL-026
F.append(dict(
    id="PL-026", slug="pl-026", group="keys", line="code", status="live",
    title="Any website can call a signed-in function",
    short="The endpoint tells browsers that any website may send your users' cookies to it and read the answer.",
    desc="PL-026: a function or API route reflects any Origin with credentials allowed, or uses CORS * with cookie sign-in, so other sites can act as your users. What CORS does, and the fix.",
    sev="medium", who="Any website your signed-in users visit", found="PatchLabs Code: CORS headers in functions and API routes",
    proof="Not lab-proven: file and line in the report",
    what="""<p>Browsers stop a page on one site from reading responses from another site, unless that site opts in with CORS headers. <code>Access-Control-Allow-Origin: *</code> opts in for every site, but browsers refuse to send cookies with it, so on its own <code>*</code> only shares responses that need no sign-in, or that need a token the other site doesn't have.</p>
<p>The dangerous version is <strong>echoing back whatever origin asked</strong> together with <code>Access-Control-Allow-Credentials: true</code>, often written to get past the browser's error about <code>*</code> and credentials. Now any website your user visits can send requests to your endpoint with their cookies and read the reply: their profile, their orders, an API key. This bites apps that keep the session in cookies, such as Next.js apps using Supabase's server-side auth. PL-026 covers that, and <code>*</code> on endpoints that sign users in with cookies.</p>
<p>Supabase Edge Functions called with a bearer token from <code>localStorage</code> are a different case: another site can't read that token, so <code>*</code> there doesn't hand over your users' sessions. The report lists those as information.</p>""",
    why="""<p>CORS errors are among the errors most often pasted into an AI tool, and the quickest answer that works is "allow everything". When <code>*</code> plus credentials fails too, the next answer is to echo the request's origin.</p>""",
    vuln=sql("""// app/api/me/route.ts (Next.js, session kept in cookies)
import { NextRequest, NextResponse } from 'next/server';
import { createClient } from '@/lib/supabase/server';

export async function GET(req: NextRequest) {
  const supabase = await createClient();  // reads the session cookie
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new NextResponse('Unauthorized', { status: 401 });
  const { data } = await supabase.from('profiles').select('*').eq('id', user.id).single();

  return NextResponse.json(data, {
    headers: {
      'Access-Control-Allow-Origin': req.headers.get('origin') ?? '*',  // any site
      'Access-Control-Allow-Credentials': 'true',
    },
  });
}""", "app/api/me/route.ts (vulnerable)"),
    check=sql("""# Where the app sets CORS headers
grep -rnE "Access-Control-Allow-(Origin|Credentials)" --exclude-dir=node_modules .

# Ask your endpoint as if you were another site
curl -s -i https://yourapp.example/api/me -H "Origin: https://attacker.example" | grep -i "access-control"
# If it echoes https://attacker.example with Allow-Credentials: true, any site can read it""", "check-pl-026.sh"),
    fix=sql("""const ALLOWED = new Set(['https://yourapp.example', 'https://www.yourapp.example']);

export async function GET(req: NextRequest) {
  // ...same as before...
  const origin = req.headers.get('origin');
  const headers: Record<string, string> = { Vary: 'Origin' };
  if (origin && ALLOWED.has(origin)) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Credentials'] = 'true';
  }
  return NextResponse.json(data, { headers });
}""", "app/api/me/route.ts (fixed)") +
    """<p>If only your own site calls the endpoint, from the same origin, you need no CORS headers at all: delete them. CORS controls who can <em>read</em> a response, not who can send a request, so endpoints that change data with cookie sign-in also need SameSite cookies or a CSRF token.</p>""",
    proof_tr=tr("code scan · report excerpt", [
        "{STEP:SCAN}    app/api/me/route.ts:12",
        "~          origin echoed + credentials {LEAK}",
        "{STEP:FIX}     allow-list your own origins",
    ], CODE_FOOT),
    proof_note="""<p>PatchLabs Code reads the CORS headers your functions and API routes set. It flags an echoed origin with credentials, and <code>*</code> where the endpoint signs users in with cookies; <code>*</code> on a bearer-token function is listed as information. It never sends requests to your app.</p>""",
    intended="""<p>A public API that needs no sign-in, such as a status endpoint or public data, can use <code>*</code> safely.</p>""",
    sevwhy="""<p>Medium: the victim has to be signed in and visit the attacker's page, and the endpoint has to use cookie sign-in. When that lines up, the other site reads or acts as them.</p>""",
    study=None, lint=None,
    related=["PL-017", "PL-024", "PL-022"],
))

# ------------------------------------------------------------------ Live posture (PL-027..PL-036)
# line "live": read from the public home page of a domain the team verified (LIVE.md). One plain http:// request, one
# https:// page load (at most 5 redirects) and its TLS handshake. Never the database, never other paths.
LIVE_FOOT = '<span class="pill plain">synthetic example</span><span>Live posture · read from the home page’s response</span>'
LOVABLE_HOST = """<p>Lovable’s documentation (checked 10 Nov 2026) doesn’t describe a way to set your own response headers on Lovable hosting. It does let you connect a custom domain through Cloudflare: choose “Uses Cloudflare or similar proxy” when you add the domain. Cloudflare can then add the header for you, as in the Cloudflare tab. If that changes, the header and value above are the same wherever you set them.</p>"""


def cf_rule(header, value):
    return (f"""<p>For a site proxied through Cloudflare (orange cloud), add a <strong>Response Header Transform Rule</strong> (Rules → Transform Rules in the dashboard): match all incoming requests to your hostname, then <em>Set static</em> header <code>{esc(header)}</code> to:</p>""" +
            sql(value, f"{header} · value") +
            """<p>On Cloudflare Pages or Workers static assets, a <code>_headers</code> file in your build output works the same way as on Netlify.</p>""")


def netlify(header, value):
    return (sql(f"""# public/_headers  (Vite copies public/ into the publish folder)
/*
  {header}: {value}""", "public/_headers") +
            """<p>The file must end up in your publish directory (<code>dist</code> for Vite). Bolt projects deployed to Netlify use this file too. The same rule can live in <code>netlify.toml</code> under <code>[[headers]]</code> if you prefer one config file.</p>""")


def vercel(header, value, extra=""):
    return sql(f"""{{
  "headers": [
    {{
      "source": "/(.*)",
      "headers": [
        {{ "key": "{header}", "value": "{value}" }}
      ]
    }}
  ]
}}""", "vercel.json") + (extra or """<p>Put <code>vercel.json</code> at the root of the project and redeploy. If the file already has a <code>headers</code> array, add the object to it rather than starting a second one.</p>""")


F.append(dict(
    id="PL-027", slug="pl-027", group="live", line="live", status="live",
    title="Site doesn’t force HTTPS",
    short="The plain http:// address of your site serves the page instead of redirecting to https://.",
    desc="PL-027: your site answers on plain http:// without redirecting to HTTPS. Why it matters for AI-built apps, how to check with curl, and the fix on Vercel, Netlify, Cloudflare and Lovable.",
    sev="medium", who="Anyone on the same network as a visitor, such as public Wi-Fi", found="PatchLabs Live posture: one plain http:// request to your home page",
    proof="Not lab-proven: read from your site’s response",
    what="""<p>Forcing HTTPS means that when someone types or follows <code>http://your-app.com</code>, your server answers with a redirect (a <code>301</code> or <code>308</code>) to <code>https://your-app.com</code> and nothing else. PL-027 means the plain <code>http://</code> request got the page itself, or a redirect that lands on another <code>http://</code> address.</p>
<p>Over plain HTTP, everything between the visitor and your server can read and change the page: the café Wi-Fi, a compromised router, anything on the path. Someone there can swap your sign-in form for their own, or inject a script that reads the session your app stores in the browser. The visitor sees your normal domain and no warning.</p>""",
    why="""<p>The big hosts redirect for you on their own domains, so the app works in every preview. The gap appears at launch: a custom domain added in a hurry, DNS pointed at a proxy set to “Flexible” TLS, or an old server left answering on port 80. Nobody types <code>http://</code> by hand while testing, so nobody notices.</p>""",
    vuln=sql("""$ curl -sI http://app.example.com
HTTP/1.1 200 OK
Content-Type: text/html; charset=utf-8
# no redirect: the whole page was sent over plain HTTP""", "curl -sI http://app.example.com (response, shortened)"),
    check="""<p>Ask for the plain address and look at the first line and the <code>Location</code> header. You want a 301 or 308 to an <code>https://</code> address.</p>""" +
    sql("""curl -sI http://your-app.com | head -n 5
# good: HTTP/1.1 308 Permanent Redirect
#       Location: https://your-app.com/

# follow every hop and print where it ends up
curl -sIL -o /dev/null -w '%{url_effective}\\n' http://your-app.com""", "check-pl-027.sh"),
    fix="""<p>The fix is a redirect from every <code>http://</code> URL to the same path on <code>https://</code>, done by your host or proxy, not by JavaScript in the page (a script only runs after the page has already crossed the network in the clear).</p>""" +
    hosts("027", [
        ("vercel", "Vercel", """<p>Vercel redirects HTTP to HTTPS on its own, including for custom domains, once the domain is added to the project and its certificate is issued. If the check fails on Vercel, the request probably isn’t reaching Vercel: look for an old A record or a proxy in front. In the project, open <em>Settings → Domains</em> and make sure every hostname you use (with and without <code>www</code>) is listed and shows a valid configuration.</p>"""),
        ("netlify", "Netlify", """<p>Netlify redirects HTTP to HTTPS automatically once a certificate is provisioned for the domain. If plain HTTP still serves the page, open <em>Domain management → HTTPS</em> and check the certificate covers every hostname you use; a domain waiting for DNS verification has no certificate and no redirect yet.</p>"""),
        ("cloudflare", "Cloudflare", """<p>In the dashboard, <em>SSL/TLS → Edge Certificates</em>, turn on <strong>Always Use HTTPS</strong>. On <em>SSL/TLS → Overview</em>, use <strong>Full (strict)</strong>, not <strong>Flexible</strong>: Flexible sends the request on to your host over plain HTTP, and some hosts then redirect back, which loops.</p>"""),
        ("lovable", "Lovable", """<p>Lovable issues the certificate for a connected custom domain itself, according to its documentation. If the plain <code>http://</code> address still serves the page and the domain goes through Cloudflare, turn on <strong>Always Use HTTPS</strong> there (see the Cloudflare tab). Otherwise, ask Lovable support, since its docs don’t describe a redirect setting.</p>"""),
    ]) + """<p>Once the redirect works, add HSTS (<a href="/findings/pl-029">PL-029</a>) so browsers stop trying plain HTTP at all.</p>""",
    proof_tr=tr("live posture · report excerpt", [
        "{STEP:HTTP}    http://app.example.com/",
        "~          200 OK, no redirect           {FLAG}",
        "{STEP:HTTPS}   https://app.example.com/ → 200",
    ], LIVE_FOOT),
    proof_note="""<p>Live posture sends one plain <code>http://</code> request to your home page and reads only the status line and the <code>Location</code> header. A redirect that reaches <code>https://</code> on the same site passes. Domains on a top-level domain that browsers already force to HTTPS (the HSTS preload list, such as <code>.app</code> and <code>.dev</code>) pass without the redirect, because no browser will load them over plain HTTP. It never follows other links or tries other paths. On the free <a href="/tools/headers-check">headers check</a> the same request is made for any address you type; in the app it runs only on a domain you verified.</p>""",
    intended="""<p>Almost never for a site with sign-in. A local network device or a test box with no certificate is the usual exception, and neither belongs on a public domain.</p>""",
    sevwhy="""<p>Medium: it needs someone on the visitor’s network path, but on shared Wi-Fi that is a low bar, and it undoes every other protection on the page. In the Live posture grade it costs 15 points.</p>""",
    study=None, lint=None,
    related=["PL-029", "PL-028", "PL-034"],
))

F.append(dict(
    id="PL-028", slug="pl-028", group="live", line="live", status="live",
    title="TLS certificate is invalid, expired or expires within 21 days",
    short="Browsers will block your site, or soon will, because its HTTPS certificate doesn’t check out.",
    desc="PL-028: your site’s TLS certificate is invalid, expired or close to expiry. How to check with openssl, why renewals fail on custom domains, and fixes for Vercel, Netlify, Cloudflare and Lovable.",
    sev="high or medium", who="Every visitor sees a browser warning; anyone on their network gains", found="PatchLabs Live posture: the TLS handshake of the home page load",
    proof="Not lab-proven: read from the TLS handshake",
    what="""<p>Your HTTPS certificate proves to the browser that it is talking to your domain. PL-028 is reported in two strengths. <strong>High</strong>: the certificate is invalid (it doesn’t cover the hostname, isn’t signed by a trusted authority, or the chain is incomplete) or has already expired. <strong>Medium</strong>: it is valid today but expires within 21 days.</p>
<p>An invalid or expired certificate puts a full-page warning in front of every visitor. Most leave; the ones who click through have been taught to ignore the one warning that tells them someone is intercepting the connection. That is why an invalid or expired certificate always sets the Live posture grade to F, whatever else passes.</p>""",
    why="""<p>Managed hosts issue and renew certificates on their own, so certificates rarely expire on a default domain. They expire after a change nobody connected to TLS: DNS moved to a new provider, a <code>CAA</code> record added that doesn’t allow the host’s certificate authority, a domain pointed at two hosts at once, or a certificate uploaded by hand for a launch and forgotten.</p>""",
    vuln=sql("""$ curl -sI https://app.example.com
curl: (60) SSL certificate problem: certificate has expired

$ openssl s_client -connect app.example.com:443 -servername app.example.com </dev/null 2>/dev/null \\
    | openssl x509 -noout -enddate
notAfter=Oct 30 11:02:41 2026 GMT""", "what an expired certificate looks like"),
    check=sql("""# who issued it, which names it covers, and when it expires
openssl s_client -connect your-app.com:443 -servername your-app.com </dev/null 2>/dev/null \\
  | openssl x509 -noout -issuer -enddate -ext subjectAltName

# curl refuses an invalid certificate and says why
curl -sS -o /dev/null https://your-app.com && echo "certificate OK"

# a CAA record can stop renewals: it must allow your host's authority
dig +short CAA your-app.com""", "check-pl-028.sh") +
    """<p>Check every hostname you use, including <code>www</code>: each needs its own name on the certificate.</p>""",
    fix="""<p>A managed certificate should renew about a month before it expires without anyone touching it. If yours didn’t, something stopped the host from proving you own the domain. Find that, and the renewal follows.</p>""" +
    hosts("028", [
        ("vercel", "Vercel", """<p>Vercel issues Let’s Encrypt certificates for domains in your project and renews them automatically, as long as the domain’s DNS points at Vercel. Open <em>Settings → Domains</em>: a domain with a configuration warning can’t renew. If you have a <code>CAA</code> record, it must allow <code>letsencrypt.org</code>.</p>""" +
         sql("""your-app.com.  CAA  0 issue "letsencrypt.org\"""", "DNS · CAA record (only if you use CAA)")),
        ("netlify", "Netlify", """<p>Netlify also uses Let’s Encrypt and renews automatically while DNS points at Netlify. Under <em>Domain management → HTTPS</em>, use <strong>Renew certificate</strong> after fixing DNS. If you uploaded your own certificate, Netlify can’t renew it for you: replace it before the date, or switch back to the managed one.</p>"""),
        ("cloudflare", "Cloudflare", """<p>When the site is proxied, visitors see Cloudflare’s edge certificate, which renews on its own (<em>SSL/TLS → Edge Certificates</em>). Behind it, with <strong>Full (strict)</strong>, your host still needs a valid certificate of its own: if that one expires, visitors get a Cloudflare error page instead of your site. A Cloudflare Origin CA certificate on the host is a long-lived option for that hop.</p>"""),
        ("lovable", "Lovable", """<p>Lovable generates and installs the certificate for a connected custom domain and its documentation says you don’t need to upload or reissue one. If the check fails, the usual cause is DNS: records changed or removed after connecting, or a proxy in front. If the domain goes through Cloudflare, the edge certificate is Cloudflare’s; check it there.</p>"""),
    ]),
    proof_tr=tr("live posture · report excerpt", [
        "{STEP:TLS}     app.example.com:443",
        "~          issuer  Let's Encrypt",
        "~          expires 2026-11-24 · 14 days  {FLAG}",
        "~          medium: renew before it lapses",
    ], LIVE_FOOT),
    proof_note="""<p>Live posture reads the certificate from the TLS handshake of the one <code>https://</code> page load it makes: the issuer, the names it covers, the protocol version and the expiry date, which the report shows as days left. It doesn’t try other ciphers or protocol versions. Daily re-checks on a verified domain mean a renewal that silently fails shows up 21 days before visitors notice.</p>""",
    intended="""<p>Never on a public site. A staging host with a self-signed certificate is common, but keep it off the domains people use, and don’t verify it for Live posture.</p>""",
    sevwhy="""<p>High when the certificate is invalid or expired: the site is effectively down for most visitors, and the grade is always F. Medium when it expires within 21 days: nothing is broken yet, but a failed renewal is already likely.</p>""",
    study=None, lint=None,
    related=["PL-027", "PL-029", "PL-034"],
))

F.append(dict(
    id="PL-029", slug="pl-029", group="live", line="live", status="live",
    title="No HSTS header, or max-age under 180 days",
    short="Browsers aren’t told to use HTTPS only, so a visitor’s first request can still go out over plain HTTP.",
    desc="PL-029: no Strict-Transport-Security (HSTS) header, or a max-age under 180 days. What HSTS does, how to check it, and how to add it on Vercel, Netlify, Cloudflare and Lovable.",
    sev="low", who="Someone on the visitor’s network, before the redirect happens", found="PatchLabs Live posture: your home page’s response headers",
    proof="Not lab-proven: read from your home page’s response",
    what="""<p>HSTS (HTTP Strict Transport Security) is one response header: <code>Strict-Transport-Security: max-age=63072000</code>. Once a browser has seen it over HTTPS, it refuses to use plain HTTP for your domain for that many seconds, and won’t let the visitor click past a certificate warning. PL-029 means the header is missing, or its <code>max-age</code> is below 180 days (15,552,000 seconds), too short to cover people who visit now and then.</p>
<p>Without it, a redirect from <code>http://</code> (<a href="/findings/pl-027">PL-027</a>) still leaves one unprotected request every time someone types your domain or follows an old <code>http://</code> link. That single request is where an attacker on the network can stop the upgrade and keep the visitor on HTTP.</p>""",
    why="""<p>HSTS lives in hosting config, which app generators rarely write. Some platforms add it to their own subdomains but not to custom domains, so the header disappears exactly when the app gets its real name.</p>""",
    vuln=sql("""$ curl -sI https://app.example.com
HTTP/2 200
content-type: text/html; charset=utf-8
# no strict-transport-security line""", "curl -sI https://app.example.com (response, shortened)"),
    check=sql("""curl -sI https://your-app.com | grep -i strict-transport-security
# good: strict-transport-security: max-age=63072000; includeSubDomains
# 180 days = 15552000 seconds; anything lower is reported""", "check-pl-029.sh"),
    fix="""<p>Send this on every HTTPS response. Two years is the usual value. Add <code>includeSubDomains</code> only when every subdomain serves HTTPS, and <code>preload</code> only if you intend to submit the domain to the browsers’ preload list, which is hard to undo.</p>""" +
    sql("Strict-Transport-Security: max-age=63072000; includeSubDomains", "the header") +
    hosts("029", [
        ("vercel", "Vercel", vercel("Strict-Transport-Security", "max-age=63072000; includeSubDomains")),
        ("netlify", "Netlify", netlify("Strict-Transport-Security", "max-age=63072000; includeSubDomains")),
        ("cloudflare", "Cloudflare", """<p>Cloudflare has a switch for this: <em>SSL/TLS → Edge Certificates → HTTP Strict Transport Security (HSTS)</em>. Set max-age to 12 months or more, and tick “Include subdomains” only if they all serve HTTPS. On Cloudflare Pages without a proxied zone, use a <code>_headers</code> file as on Netlify.</p>"""),
        ("lovable", "Lovable", LOVABLE_HOST + """<p>HSTS has to be a real response header: it can’t be set with a <code>&lt;meta&gt;</code> tag.</p>"""),
    ]) + """<p>Make sure HTTPS works on every hostname first (<a href="/findings/pl-028">PL-028</a>): once browsers have cached HSTS, a broken certificate becomes a hard error with no way past it.</p>""",
    proof_tr=tr("live posture · report excerpt", [
        "{STEP:LOAD}    https://app.example.com/ → 200",
        "~          strict-transport-security",
        "~          not sent                       {FLAG}",
    ], LIVE_FOOT),
    proof_note="""<p>Live posture reads the <code>Strict-Transport-Security</code> header from the final response of its one <code>https://</code> page load, after at most 5 redirects, and compares <code>max-age</code> with 180 days. Sites on a top-level domain that is itself on the browsers’ HSTS preload list, such as <code>.app</code> or <code>.dev</code>, pass without the header, since browsers already use HTTPS only for them. It doesn’t look up whether your own domain was submitted to the preload list.</p>""",
    intended="""<p>Briefly, while you roll it out: start with a small <code>max-age</code> such as 300, confirm nothing breaks, then raise it. A short value is reported until you do, which is the point.</p>""",
    sevwhy="""<p>Low: it matters only on the first or plain-HTTP request, and only to someone positioned on the network. It is a cheap, one-line fix, so it still counts: 5 points in the Live posture grade.</p>""",
    study=None, lint=None,
    related=["PL-027", "PL-028", "PL-030"],
))

CSP_STARTER = ("default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
               "img-src 'self' data: blob: https://YOUR-PROJECT.supabase.co; font-src 'self' data:; "
               "connect-src 'self' https://YOUR-PROJECT.supabase.co wss://YOUR-PROJECT.supabase.co; "
               "frame-ancestors 'none'; base-uri 'self'; form-action 'self'; object-src 'none'")
F.append(dict(
    id="PL-030", slug="pl-030", group="live", line="live", status="live",
    title="No Content-Security-Policy",
    short="Your page sends no Content-Security-Policy, so any script that gets onto it can run and send data anywhere.",
    desc="PL-030: no Content-Security-Policy header. A starter CSP for a Vite, React and Supabase app, how to test it in report-only mode, and how to set it on Vercel, Netlify, Cloudflare and Lovable.",
    sev="medium", who="Anyone who gets a script onto your page", found="PatchLabs Live posture: your home page’s response headers",
    proof="Not lab-proven: read from your home page’s response",
    what="""<p>A Content-Security-Policy (CSP) is a response header that lists where your page may load scripts, styles, images and connections from. The browser blocks everything else. PL-030 means your home page sends no CSP at all.</p>
<p>A CSP doesn’t fix a bug; it limits the damage of one. If user content reaches the page as HTML (<a href="/findings/pl-024">PL-024</a>), or a third-party script is compromised, a good policy stops the injected script from running or from sending what it reads to another server. That matters more than usual in a Supabase app, because supabase-js keeps the signed-in session in <code>localStorage</code> by default, where any script on the page can read it.</p>""",
    why="""<p>A CSP has to name every place your app talks to, and that list is specific to each app: your Supabase project, your analytics, your fonts. Generators can’t know it, and a wrong guess breaks the app, so the safe default for a tool is to leave it out.</p>""",
    vuln=sql("""$ curl -sI https://app.example.com
HTTP/2 200
content-type: text/html; charset=utf-8
# no content-security-policy line: any script may run and connect anywhere""", "curl -sI https://app.example.com (response, shortened)"),
    check=sql("""curl -sI https://your-app.com | grep -iE 'content-security-policy'
# also check index.html for <meta http-equiv="Content-Security-Policy" ...>""", "check-pl-030.sh") +
    """<p>In the browser, open DevTools → Console after you add a policy: every blocked load is listed with the directive that blocked it, which is how you tune it.</p>""",
    fix="""<p>Start in report-only mode. <code>Content-Security-Policy-Report-Only</code> takes the same value, blocks nothing and prints violations in the console. Use the app for a few days, add the sources it genuinely needs, then switch the header name to <code>Content-Security-Policy</code>. A starter policy for a Vite or React app on Supabase, with your project ref in place of <code>YOUR-PROJECT</code>:</p>""" +
    sql("default-src 'self';\n  script-src 'self';\n  style-src 'self' 'unsafe-inline';\n  img-src 'self' data: blob: https://YOUR-PROJECT.supabase.co;\n  font-src 'self' data:;\n  connect-src 'self' https://YOUR-PROJECT.supabase.co wss://YOUR-PROJECT.supabase.co;\n  frame-ancestors 'none';\n  base-uri 'self';\n  form-action 'self';\n  object-src 'none'", "starter policy (one line in the real header)") +
    """<p>The <code>wss://</code> entry is for Realtime; storage downloads come from the same <code>supabase.co</code> host. Add what your app uses on top, for example <code>https://fonts.googleapis.com</code> to <code>style-src</code> and <code>https://fonts.gstatic.com</code> to <code>font-src</code> for Google Fonts, or your analytics host to <code>script-src</code> and <code>connect-src</code>. Avoid <code>'unsafe-inline'</code> in <code>script-src</code>: it lets injected scripts run, which is what the policy is for.</p>""" +
    hosts("030", [
        ("vercel", "Vercel", vercel("Content-Security-Policy-Report-Only", CSP_STARTER,
                                    """<p>Next.js apps can set the same header from <code>headers()</code> in <code>next.config.js</code>, or per request in middleware when you need a nonce for inline scripts.</p>""")),
        ("netlify", "Netlify", netlify("Content-Security-Policy-Report-Only", CSP_STARTER)),
        ("cloudflare", "Cloudflare", cf_rule("Content-Security-Policy-Report-Only", CSP_STARTER)),
        ("lovable", "Lovable", LOVABLE_HOST + """<p>A CSP can also go in <code>index.html</code> as a meta tag, which works on any host. Meta-tag policies can’t use <code>frame-ancestors</code> or report-only mode, so test the policy in a local build first.</p>""" +
         sql(f"""<!-- index.html, inside <head>, before any script -->
<meta http-equiv="Content-Security-Policy"
      content="{CSP_STARTER.replace("frame-ancestors 'none'; ", "")}">""", "index.html")),
    ]),
    proof_tr=tr("live posture · report excerpt", [
        "{STEP:LOAD}    https://app.example.com/ → 200",
        "~          content-security-policy",
        "~          not sent                       {FLAG}",
        "~          report-only seen: no",
    ], LIVE_FOOT),
    proof_note="""<p>Live posture reads the final response of its one page load and looks for a <code>Content-Security-Policy</code> header, or a <code>&lt;meta http-equiv="Content-Security-Policy"&gt;</code> tag in the HTML. A report-only header on its own doesn’t pass, because it blocks nothing. It doesn’t grade how strict the policy is: a policy with <code>'unsafe-inline'</code> scripts passes this check, so review yours against the starter above.</p>""",
    intended="""<p>A static page with no sign-in, no user content and no third-party scripts gains little from a CSP. Any app with accounts gains a lot.</p>""",
    sevwhy="""<p>Medium: nothing leaks from a missing CSP alone, but it is the difference between a cross-site scripting bug that reads every session and one that can’t send anything anywhere. 15 points in the Live posture grade.</p>""",
    study=None, lint=None,
    related=["PL-024", "PL-031", "PL-034"],
))

F.append(dict(
    id="PL-031", slug="pl-031", group="live", line="live", status="live",
    title="Any site can frame the page",
    short="Neither frame-ancestors nor X-Frame-Options is set, so another site can load your app invisibly inside its own.",
    desc="PL-031: no frame-ancestors or X-Frame-Options, so any site can frame your page (clickjacking). How to check, and the header for Vercel, Netlify, Cloudflare and Lovable.",
    sev="low", who="Any website that frames your page", found="PatchLabs Live posture: your home page’s response headers",
    proof="Not lab-proven: read from your home page’s response",
    what="""<p>By default, any website can show your page inside an <code>&lt;iframe&gt;</code>. Clickjacking uses that: the attacker’s page loads yours, makes it transparent, and lines up a button the visitor thinks is theirs (“Claim your prize”) over a button in your app (“Delete account”, “Make public”, “Approve”). The visitor is signed in to your app, so the click counts.</p>
<p>PL-031 means your page sends neither <code>Content-Security-Policy: frame-ancestors …</code> nor <code>X-Frame-Options</code>, the two headers that tell browsers who may frame it.</p>""",
    why="""<p>Framing protection is a header, so it sits outside the code a generator writes. It also gets left out on purpose sometimes, because the builder’s own preview shows the app in a frame, and a header that blocks framing would break the preview.</p>""",
    vuln=sql("""$ curl -sI https://app.example.com
HTTP/2 200
content-type: text/html; charset=utf-8
# no x-frame-options, and no content-security-policy with frame-ancestors""", "curl -sI https://app.example.com (response, shortened)"),
    check=sql("""curl -sI https://your-app.com | grep -iE 'x-frame-options|content-security-policy'
# passes with either:
#   x-frame-options: DENY            (or SAMEORIGIN)
#   content-security-policy: ... frame-ancestors 'none' ...""", "check-pl-031.sh") +
    sql("""<!-- try it: save as frame-test.html, open it in your browser -->
<iframe src="https://your-app.com" width="800" height="600"></iframe>
<!-- if your app appears, any site can do this -->""", "frame-test.html"),
    fix="""<p>Send both: <code>frame-ancestors</code> is the modern control and wins where it is supported, and <code>X-Frame-Options</code> covers older browsers. Use <code>'none'</code> / <code>DENY</code> unless your own site frames the app, then <code>'self'</code> / <code>SAMEORIGIN</code>. If you already have a CSP (<a href="/findings/pl-030">PL-030</a>), add the directive to it rather than sending a second policy.</p>""" +
    sql("""X-Frame-Options: DENY
Content-Security-Policy: frame-ancestors 'none'""", "the headers") +
    hosts("031", [
        ("vercel", "Vercel", vercel("X-Frame-Options", "DENY", """<p>Then add <code>frame-ancestors 'none'</code> to your <code>Content-Security-Policy</code> value in the same file. Put <code>vercel.json</code> at the project root and redeploy.</p>""")),
        ("netlify", "Netlify", netlify("X-Frame-Options", "DENY")),
        ("cloudflare", "Cloudflare", cf_rule("X-Frame-Options", "DENY")),
        ("lovable", "Lovable", LOVABLE_HOST + """<p>Neither header works as a <code>&lt;meta&gt;</code> tag: browsers ignore <code>X-Frame-Options</code> in HTML, and <code>frame-ancestors</code> is not allowed in a meta-tag CSP. This one needs a real header, so Cloudflare in front is the route.</p>"""),
    ]),
    proof_tr=tr("live posture · report excerpt", [
        "{STEP:LOAD}    https://app.example.com/ → 200",
        "~          x-frame-options    not sent",
        "~          frame-ancestors    not set     {FLAG}",
    ], LIVE_FOOT),
    proof_note="""<p>Live posture reads both headers from the final response of its one page load. Either one passes: <code>X-Frame-Options</code> of <code>DENY</code> or <code>SAMEORIGIN</code>, or a <code>frame-ancestors</code> directive in an enforced <code>Content-Security-Policy</code>. It never frames your page itself.</p>""",
    intended="""<p>Embeddable widgets, such as a booking form other sites put in an iframe, need framing. Allow the sites that embed you by name (<code>frame-ancestors https://partner.example</code>) rather than everyone, and keep account and admin pages unframeable.</p>""",
    sevwhy="""<p>Low: it needs a signed-in visitor to be lured to the attacker’s page and to click where expected. For apps with one-click destructive actions it deserves more attention than the grade gives it (5 points).</p>""",
    study=None, lint=None,
    related=["PL-030", "PL-032", "PL-036"],
))

F.append(dict(
    id="PL-032", slug="pl-032", group="live", line="live", status="live",
    title="No X-Content-Type-Options: nosniff",
    short="Browsers may guess a file’s type from its contents, so an uploaded “image” can be run as a script or page.",
    desc="PL-032: no X-Content-Type-Options: nosniff header. What MIME sniffing is, why it matters for apps with uploads, and the one-line fix on Vercel, Netlify, Cloudflare and Lovable.",
    sev="low", who="Anyone who can get a file served from your domain", found="PatchLabs Live posture: your home page’s response headers",
    proof="Not lab-proven: read from your home page’s response",
    what="""<p>Every response says what it is with <code>Content-Type</code>. Without <code>X-Content-Type-Options: nosniff</code>, browsers may second-guess that label by looking at the bytes (“MIME sniffing”). PL-032 means your page doesn’t send <code>nosniff</code>.</p>
<p>The risk is files you didn’t write. If users can upload files that your domain serves back, a file labelled as plain text or an image but containing HTML or JavaScript can be treated as a page or a script. With <code>nosniff</code>, the browser trusts the label and refuses to run a script whose type isn’t a script type.</p>""",
    why="""<p>It is a header with nothing to configure, so it gets skipped along with the rest of the hosting setup. Modern hosts send correct content types for your own files, which hides the gap until user uploads arrive.</p>""",
    vuln=sql("""$ curl -sI https://app.example.com
HTTP/2 200
content-type: text/html; charset=utf-8
# no x-content-type-options line""", "curl -sI https://app.example.com (response, shortened)"),
    check=sql("""curl -sI https://your-app.com | grep -i x-content-type-options
# good: x-content-type-options: nosniff

# check your JavaScript bundle too: its type must be a script type
curl -sI https://your-app.com/assets/index.js | grep -i content-type""", "check-pl-032.sh"),
    fix=sql("X-Content-Type-Options: nosniff", "the header") +
    """<p>It has one valid value and almost never breaks anything. The one thing to confirm afterwards: scripts and styles must be served with the right type (<code>text/javascript</code>, <code>text/css</code>), which every major host already does for built assets.</p>""" +
    hosts("032", [
        ("vercel", "Vercel", vercel("X-Content-Type-Options", "nosniff")),
        ("netlify", "Netlify", netlify("X-Content-Type-Options", "nosniff")),
        ("cloudflare", "Cloudflare", cf_rule("X-Content-Type-Options", "nosniff")),
        ("lovable", "Lovable", LOVABLE_HOST + """<p><code>nosniff</code> only works as a response header, not as a meta tag.</p>"""),
    ]) + """<p>Uploaded files are better still served from a different domain. Supabase Storage already does that: files come from your <code>supabase.co</code> project host, not your app’s domain. Keep personal uploads in a private bucket (<a href="/findings/pl-007">PL-007</a>).</p>""",
    proof_tr=tr("live posture · report excerpt", [
        "{STEP:LOAD}    https://app.example.com/ → 200",
        "~          x-content-type-options",
        "~          not sent                       {FLAG}",
    ], LIVE_FOOT),
    proof_note="""<p>Live posture reads the header from the final response of its one page load and passes it only when the value is <code>nosniff</code>. It sees the home page, not your other files, so set the header for every path (the snippets above do).</p>""",
    intended="""<p>There is no common reason to leave it out. Set it everywhere.</p>""",
    sevwhy="""<p>Low: it only becomes exploitable when someone can get a file served from your domain. It is the cheapest fix on this list. 5 points in the Live posture grade.</p>""",
    study=None, lint=None,
    related=["PL-030", "PL-031", "PL-024"],
))

F.append(dict(
    id="PL-033", slug="pl-033", group="live", line="live", status="live",
    title="Cookie set without Secure, or a session cookie without HttpOnly",
    short="Your home page sets a cookie that can travel over plain HTTP, or a session cookie that any script on the page can read.",
    desc="PL-033: a cookie set without Secure, or a session cookie without HttpOnly. What each flag protects, how @supabase/ssr and server frameworks set them, and how to check with curl or DevTools.",
    sev="medium", who="Scripts on your page, or someone on the visitor’s network", found="PatchLabs Live posture: Set-Cookie headers on your home page",
    proof="Not lab-proven: read from your home page’s response",
    what="""<p>Two flags decide who can get hold of a cookie. <strong>Secure</strong>: only sent over HTTPS, never over plain HTTP. <strong>HttpOnly</strong>: invisible to JavaScript, so an injected script can’t read it. PL-033 means a cookie set by your home page has no <code>Secure</code>, or a cookie whose name marks it as a session (such as <code>session</code>, <code>sid</code>, <code>auth</code> or <code>token</code>) has no <code>HttpOnly</code>. The report names the cookie and the missing flag.</p>
<p>For a session cookie, each missing flag is a separate way to lose the session: over the network, or to a script. <code>SameSite</code> isn’t part of this finding: browsers treat a cookie without it as <code>Lax</code>, which already keeps it out of most requests other websites trigger. Setting <code>SameSite=Lax</code> explicitly is still good practice.</p>""",
    why="""<p>Plain supabase-js keeps the session in <code>localStorage</code>, so many AI-built apps set no cookies at all and pass this check. Cookies appear when the app moves to server rendering or <code>@supabase/ssr</code>, or adds a server framework, and each library has its own defaults. Code written for <code>localhost</code> often leaves out <code>Secure</code> because it breaks plain-HTTP development.</p>""",
    vuln=sql("""$ curl -sI https://app.example.com
HTTP/2 200
set-cookie: session=eyJ…; Path=/
# no Secure, no HttpOnly""", "curl -sI https://app.example.com (response, shortened)"),
    check=sql("""curl -sI https://your-app.com | grep -i '^set-cookie'
# every cookie should carry Secure; session cookies also HttpOnly""", "check-pl-033.sh") +
    """<p>Cookies set after sign-in don’t show up on a signed-out request. In the browser, sign in, open DevTools → Application → Cookies and read the Secure and HttpOnly columns for every cookie on your domain.</p>""",
    fix="""<p>Set <code>Secure</code> on every cookie, and <code>HttpOnly</code> on anything that identifies a user. Add <code>SameSite=Lax</code> while you’re there, so you don’t depend on the browser’s default; <code>Strict</code> also drops the cookie when someone follows a link to your site from elsewhere, which signs them out on arrival. Fix it where the cookie is created:</p>""" +
    hosts("033", [
        ("supabase", "@supabase/ssr", """<p><code>@supabase/ssr</code> stores the session in cookies so the server can read it. Its browser client reads those cookies too, so they can’t be <code>HttpOnly</code>; set <code>secure</code> explicitly (and <code>sameSite</code> while you’re there), and rely on a Content-Security-Policy (<a href="/findings/pl-030">PL-030</a>) to keep scripts off the page.</p>""" +
         sql("""import { createServerClient } from '@supabase/ssr'

const supabase = createServerClient(url, anonKey, {
  cookies: { getAll, setAll },            // your framework's cookie functions
  cookieOptions: {
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
  },
})""", "lib/supabase/server.ts")),
        ("next", "Next.js", sql("""import { cookies } from 'next/headers'

const store = await cookies()
store.set('session', token, {
  httpOnly: true,
  secure: true,
  sameSite: 'lax',
  path: '/',
})""", "app/api/sign-in/route.ts")),
        ("express", "Express", sql("""// a cookie you set yourself
res.cookie('session', token, { httpOnly: true, secure: true, sameSite: 'lax' })

// express-session: behind a proxy (Vercel, Render, Cloudflare), trust it so secure cookies are sent
app.set('trust proxy', 1)
app.use(session({ secret, cookie: { httpOnly: true, secure: true, sameSite: 'lax' } }))""", "server.js")),
    ]),
    proof_tr=tr("live posture · report excerpt", [
        "{STEP:LOAD}    https://app.example.com/ → 200",
        "~          cookie session",
        "~          secure no · httponly no        {FLAG}",
    ], LIVE_FOOT),
    proof_note="""<p>Live posture reads the <code>Set-Cookie</code> headers on the responses of its one signed-out page load. It records each cookie’s name and flags, never its value, and never signs in. Every cookie needs <code>Secure</code>; <code>HttpOnly</code> is expected when the name looks like a session (it contains sess, auth, token, sid, jwt, login or remember). Several failing cookies count as one failed check in the grade. Cookies your app only sets after sign-in aren’t covered: check those in DevTools as above.</p>""",
    intended="""<p>A cookie that JavaScript must read, such as a theme or language preference, or the <code>@supabase/ssr</code> session cookie, can’t be <code>HttpOnly</code>. That is a deliberate trade, and the report says which flag is missing so you can judge it. <code>Secure</code> has no such trade-off on a live site.</p>""",
    sevwhy="""<p>Medium: a missing flag only matters alongside a second problem, such as a plain-HTTP connection or an injected script. On a session cookie, that second problem is easy to find. 15 points in the Live posture grade, counted once however many cookies fail.</p>""",
    study=None, lint=None,
    related=["PL-026", "PL-030", "PL-027"],
))

F.append(dict(
    id="PL-034", slug="pl-034", group="live", line="live", status="live",
    title="Page loads scripts or styles over plain HTTP",
    short="Your HTTPS page pulls a script or stylesheet from an http:// address, which anyone on the network can replace.",
    desc="PL-034: an HTTPS page loads scripts or styles over plain HTTP (mixed content). How to find the http:// URLs, and the fix in code or with upgrade-insecure-requests.",
    sev="medium", who="Anyone on the visitor’s network", found="PatchLabs Live posture: the HTML of your home page",
    proof="Not lab-proven: read from your home page’s HTML",
    what="""<p>Mixed content is an HTTPS page that loads part of itself over plain <code>http://</code>. PL-034 covers the parts that can take over the page: <code>&lt;script src="http://…"&gt;</code> and stylesheets (<code>&lt;link rel="stylesheet" href="http://…"&gt;</code>). Whoever controls the network can replace that file, and a replaced script runs with full access to your page, including the signed-in session.</p>
<p>Modern browsers block these loads outright, so in practice the usual symptom is a broken feature: a widget, a font or an analytics tag that silently never loads, with a “Mixed Content” error in the console.</p>""",
    why="""<p>An old embed snippet copied from a provider’s documentation, a CDN URL written with <code>http://</code>, or a template from years ago. A generator pastes what it was given, and local development over <code>http://localhost</code> raises no error.</p>""",
    vuln=sql("""<!-- index.html (vulnerable) -->
<link rel="stylesheet" href="http://cdn.example.net/widget/1.4/widget.css">
<script src="http://cdn.example.net/widget/1.4/widget.js"></script>""", "index.html (vulnerable, synthetic)"),
    check=sql("""# script and stylesheet URLs that start with http://
curl -s https://your-app.com | grep -oiE '<(script|link)[^>]+(src|href)="http://[^"]+"'""", "check-pl-034.sh") +
    """<p>Scripts your bundle adds at runtime don’t appear in the HTML. Open the site in the browser with DevTools → Console: every blocked load is listed as “Mixed Content” with its URL.</p>""",
    fix="""<p>Change each URL to <code>https://</code>; nearly every provider serves the same file over HTTPS. Better still, install the library from npm so it ships inside your own bundle. Then add <code>upgrade-insecure-requests</code> as a safety net: it tells the browser to fetch any leftover <code>http://</code> subresource over HTTPS instead.</p>""" +
    hosts("034", [
        ("code", "In your code", sql("""<!-- index.html (fixed) -->
<link rel="stylesheet" href="https://cdn.example.net/widget/1.4/widget.css">
<script src="https://cdn.example.net/widget/1.4/widget.js"></script>""", "index.html (fixed, synthetic)")),
        ("vercel", "Vercel", vercel("Content-Security-Policy", "upgrade-insecure-requests", """<p>If you already send a Content-Security-Policy (<a href="/findings/pl-030">PL-030</a>), add <code>upgrade-insecure-requests</code> to it instead of adding a second header.</p>""")),
        ("netlify", "Netlify / Cloudflare Pages", netlify("Content-Security-Policy", "upgrade-insecure-requests")),
        ("lovable", "Lovable", """<p>This one works as a meta tag in <code>index.html</code>, so it needs nothing from the host:</p>""" +
         sql("""<!-- index.html, inside <head> -->
<meta http-equiv="Content-Security-Policy" content="upgrade-insecure-requests">""", "index.html")),
    ]),
    proof_tr=tr("live posture · report excerpt", [
        "{STEP:LOAD}    https://app.example.com/ → 200",
        "~          <script src=\"http://cdn…\">    {FLAG}",
        "~          1 script, 1 stylesheet",
    ], LIVE_FOOT),
    proof_note="""<p>Live posture reads the HTML of your home page from its one page load and lists <code>&lt;script&gt;</code> and stylesheet URLs that start with <code>http://</code>. It doesn’t download those files, run the page’s JavaScript or look at other pages, so scripts your app adds later are not seen: the console check above covers them.</p>""",
    intended="""<p>Never for scripts or styles on an HTTPS page. Plain-HTTP images are a smaller problem and are not part of this finding, but fix them while you are there.</p>""",
    sevwhy="""<p>Medium: a replaced script is a full takeover of the page, but it needs someone on the network path, and current browsers block most of these loads anyway. 15 points in the Live posture grade.</p>""",
    study=None, lint=None,
    related=["PL-027", "PL-030", "PL-029"],
))

F.append(dict(
    id="PL-035", slug="pl-035", group="live", line="live", status="live",
    title="Server headers reveal software versions",
    short="A Server or X-Powered-By header names the software and its version, which tells attackers which known bugs to try.",
    desc="PL-035: Server or X-Powered-By headers reveal software versions. Why it matters, how to check, and how to remove them in Next.js, Express, nginx and Cloudflare.",
    sev="info", who="Nobody directly; it saves an attacker a step", found="PatchLabs Live posture: your home page’s response headers",
    proof="Not lab-proven: read from your home page’s response",
    what="""<p>Some servers announce themselves in every response: <code>Server: nginx/1.18.0</code>, <code>X-Powered-By: PHP/8.1.2</code>. PL-035 means a header like that carries a version number. On its own it exposes nothing, but it turns “is this server out of date?” into a lookup: anyone can match the version against published advisories without sending a single probe.</p>
<p>A bare product name such as <code>Server: Vercel</code> or <code>Server: cloudflare</code> is not reported; the finding is about versions.</p>""",
    why="""<p>These headers are on by default in many servers and frameworks, and nobody asks a generator to turn them off. They show up most on apps that moved from a managed host to a self-hosted server or container.</p>""",
    vuln=sql("""$ curl -sI https://app.example.com
HTTP/2 200
server: nginx/1.18.0 (Ubuntu)
x-powered-by: PHP/8.1.2""", "curl -sI https://app.example.com (response, synthetic)"),
    check=sql("""curl -sI https://your-app.com | grep -iE '^(server|x-powered-by|x-aspnet-version|x-generator):'""", "check-pl-035.sh"),
    fix="""<p>Turn the header off where it is added. If you see a version, also check that it is current: hiding an old version helps a little, upgrading it helps a lot.</p>""" +
    hosts("035", [
        ("next", "Next.js", sql("""// next.config.js
module.exports = {
  poweredByHeader: false,   // drops X-Powered-By: Next.js
}""", "next.config.js")),
        ("express", "Express", sql("""const app = express()
app.disable('x-powered-by')""", "server.js")),
        ("nginx", "nginx", sql("""# nginx.conf, inside http { }
server_tokens off;   # Server: nginx, without the version""", "nginx.conf")),
        ("cloudflare", "Cloudflare", """<p>For a proxied site, a <strong>Response Header Transform Rule</strong> (Rules → Transform Rules) can <em>Remove</em> <code>X-Powered-By</code> before responses reach visitors. That hides it; the fix at the source above is still better.</p>"""),
    ]),
    proof_tr=tr("live posture · report excerpt", [
        "{STEP:LOAD}    https://app.example.com/ → 200",
        "~          server       nginx/1.18.0",
        "~          x-powered-by PHP/8.1.2",
        "~          info: versions visible",
    ], LIVE_FOOT),
    proof_note="""<p>Live posture reads the <code>Server</code> and <code>X-Powered-By</code> style headers from the final response of its one page load and reports them when they contain a version number. It doesn’t look the versions up or probe for the bugs they might have.</p>""",
    intended="""<p>Harmless on a managed platform that names itself without a version. On your own server there is no reason to publish the version.</p>""",
    sevwhy="""<p>Information: nothing is exposed and nothing can be exploited through the header itself. It costs no points in the Live posture grade, and is listed because the fix takes one line.</p>""",
    study=None, lint=None,
    related=["PL-023", "PL-032", "PL-036"],
))

F.append(dict(
    id="PL-036", slug="pl-036", group="live", line="live", status="live",
    title="No Referrer-Policy",
    short="Your page sends no Referrer-Policy, so the browser’s default decides how much of your URLs other sites see.",
    desc="PL-036: no Referrer-Policy header. What the Referer header leaks from app URLs, why strict-origin-when-cross-origin is the right value, and how to set it on any host or with a meta tag.",
    sev="info", who="The sites your pages link to or load files from", found="PatchLabs Live posture: your home page’s response headers",
    proof="Not lab-proven: read from your home page’s response",
    what="""<p>When a visitor follows a link or your page loads a file from another site, the browser can send a <code>Referer</code> header saying which page they came from. <code>Referrer-Policy</code> controls how much of that URL is shared. PL-036 means your page doesn’t set one.</p>
<p>Current browsers default to <code>strict-origin-when-cross-origin</code>, which sends only your domain to other sites, so the risk is small. Setting it yourself makes that behaviour explicit, covers older browsers, and matters most for apps that put tokens or personal details in URLs, such as reset links, invite codes or search pages.</p>""",
    why="""<p>The browser default is reasonable, so nothing visibly breaks without it, and it lives with the other hosting headers that generated projects leave out.</p>""",
    vuln=sql("""$ curl -sI https://app.example.com
HTTP/2 200
content-type: text/html; charset=utf-8
# no referrer-policy line""", "curl -sI https://app.example.com (response, shortened)"),
    check=sql("""curl -sI https://your-app.com | grep -i referrer-policy
# also check index.html for <meta name="referrer" ...>""", "check-pl-036.sh"),
    fix=sql("Referrer-Policy: strict-origin-when-cross-origin", "the header") +
    """<p><code>strict-origin-when-cross-origin</code> keeps full URLs within your own site (useful for your analytics) and sends only the domain elsewhere, never over plain HTTP. Use <code>no-referrer</code> if pages carry secrets in their URLs and you need nothing at all to leave.</p>""" +
    hosts("036", [
        ("vercel", "Vercel", vercel("Referrer-Policy", "strict-origin-when-cross-origin")),
        ("netlify", "Netlify", netlify("Referrer-Policy", "strict-origin-when-cross-origin")),
        ("cloudflare", "Cloudflare", cf_rule("Referrer-Policy", "strict-origin-when-cross-origin")),
        ("lovable", "Lovable", """<p>A meta tag in <code>index.html</code> works on any host, including Lovable hosting:</p>""" +
         sql("""<!-- index.html, inside <head> -->
<meta name="referrer" content="strict-origin-when-cross-origin">""", "index.html")),
    ]),
    proof_tr=tr("live posture · report excerpt", [
        "{STEP:LOAD}    https://app.example.com/ → 200",
        "~          referrer-policy",
        "~          not sent · info",
    ], LIVE_FOOT),
    proof_note="""<p>Live posture reads the <code>Referrer-Policy</code> header from the final response of its one page load, and the HTML for a <code>&lt;meta name="referrer"&gt;</code> tag. Either one passes.</p>""",
    intended="""<p>Relying on the browser default is a reasonable choice for a site with no secrets in its URLs. Setting the header costs one line, so it is listed.</p>""",
    sevwhy="""<p>Information: modern browsers already behave safely without it. It costs no points in the Live posture grade.</p>""",
    study=None, lint=None,
    related=["PL-035", "PL-031", "PL-030"],
))

# ------------------------------------------------------------------ shared
for _f in F:
    _f.setdefault("line", "lab" if _f["group"] == "data" else "code")
    _f.setdefault("status", "live")
F.sort(key=lambda f: f["id"])
ORDER = [f["id"] for f in F]
BY = {f["id"]: f for f in F}
LINE_NAME = {"lab": "PatchLabs Lab", "code": "PatchLabs Code", "live": "PatchLabs Live posture"}
LINE_URL = {"lab": "/product/lab", "code": "/product/code", "live": "/product/live-posture"}


def guides_for(fid):
    """Learn guides whose source meta lists this finding (tools/gen/learn/src/*.html, `findings:` line)."""
    src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "learn", "src")
    out = []
    if not os.path.isdir(src):
        return out
    for name in sorted(os.listdir(src)):
        if not name.endswith(".html"):
            continue
        head = open(os.path.join(src, name)).read().split("\n---\n", 1)[0]
        meta = dict(l.split(":", 1) for l in head.strip().splitlines() if ":" in l)
        meta = {k.strip(): v.strip() for k, v in meta.items()}
        ids = [x.strip() for x in meta.get("findings", "").split(",")]
        if fid in ids:
            out.append((name[:-5], meta.get("h1", name)))
    return out


def nav(cur):
    def item(f):
        sc = SEV[f["sev"]][1]
        curattr = ' aria-current="page"' if f["id"] == cur else ""
        return (f'<li><a href="/findings/{f["slug"]}"{curattr}><span class="fid"><span class="sev-dot {sc}" aria-hidden="true"></span>{f["id"]}</span>'
                f'{esc(f["title"])}</a></li>')
    lab = "\n        ".join(item(f) for f in F if f["line"] == "lab" and f["status"] == "live")
    code = "\n        ".join(item(f) for f in F if f["line"] == "code" and f["status"] == "live")
    live = "\n        ".join(item(f) for f in F if f["line"] == "live" and f["status"] == "live")
    coming = "\n        ".join(item(f) for f in F if f["status"] == "coming")
    return f"""<nav class="docs-nav" aria-label="Findings">
      <details open><summary class="show-sm">All findings</summary>
      <h2>Overview</h2>
      <ul><li><a href="/findings">Finding index</a></li><li><a href="/learn">Guides</a></li><li><a href="/research/1-in-4">The 1-in-4 Report</a></li><li><a href="/leaking-now">Leaking right now?</a></li><li><a href="/tools/headers-check">Free headers check</a></li></ul>
      <h2>Lab · database</h2>
      <ul>
        {lab}
      </ul>
      <h2>Code · repo</h2>
      <ul>
        {code}
      </ul>
      <h2>Live · public page</h2>
      <ul>
        {live}
      </ul>
      <h2>Not tested yet · coming</h2>
      <ul>
        {coming}
      </ul>
      </details>
    </nav>"""


KEYCHECK_IDS = {"PL-009", "PL-010", "PL-011"}  # secret-key findings the in-browser key check covers
KEYCHECK_NOTE = """
      <p class="small">No terminal? Paste a file, a <code>.env</code> or your built JavaScript into the <a href="/tools/key-check">free key check</a>. It runs in your browser and sends nothing.</p>"""


def page(f):
    i = ORDER.index(f["id"])
    prev_f = F[i - 1] if i > 0 else None
    next_f = F[i + 1] if i < len(F) - 1 else None
    pill_cls = SEV[f["sev"]][0]
    sevlabel = f.get("sevlabel", f["sev"])
    n = f["slug"].replace("pl-", "")
    coming = f["status"] == "coming"
    code = f["line"] == "code"
    live = f["line"] == "live"
    guides = guides_for(f["id"])
    toc = [("what", "What it is")]
    if f.get("why"):
        toc.append(("why", "Why AI builders produce it"))
    toc += [("example", "What we see" if live else "Example"), ("check", "Check it yourself"), ("fix", "The fix" if (coming or code or f.get("why")) else "The fix we write"), ("prompt", "Ask your AI builder"),
            ("proof", "How we test it" if coming else "How we find it" if live else "The proof"), ("intended", "When it’s intended")]
    if f.get("sevwhy"):
        toc.append(("severity", "Severity"))
    if f["lint"]:
        toc.append(("lint", "Supabase linter"))
    toc.append(("related", "Related"))
    toc_html = "".join(f'<li><a href="#{a}">{b}</a></li>' for a, b in toc)
    study = (f'<div class="callout note"><p>{f["study"]}</p></div>' if f["study"] else "")
    lint = (f'<h2 id="lint"><span class="lab" aria-hidden="true">Map</span>Supabase linter</h2>\n{f["lint"]}' if f["lint"] else "")
    why = (f'<h2 id="why"><span class="lab" aria-hidden="true">Cause</span>Why AI builders produce it</h2>\n      {f["why"]}' if f.get("why") else "")
    sevwhy = (f'<h2 id="severity"><span class="lab" aria-hidden="true">Rate</span>Why it’s rated {esc(sevlabel)}</h2>\n      {f["sevwhy"]}' if f.get("sevwhy") else "")
    rel = "".join(
        f'<a class="card link" href="/findings/{BY[r]["slug"]}"><span class="n-big">{r}{" · coming" if BY[r]["status"] == "coming" else ""}</span><h3>{esc(BY[r]["title"])}</h3><p class="small">{esc(BY[r]["short"])}</p></a>'
        for r in f["related"])
    guide_html = ""
    if guides:
        guide_html = ('<h3 class="f-guides-h">Guides</h3><ul class="f-guides">' +
                      "".join(f'<li><a href="/learn/{s}">{esc(t)}</a></li>' for s, t in guides) + "</ul>")
    pager = ""
    if prev_f:
        pager += f'<a href="/findings/{prev_f["slug"]}"><span>Previous · {prev_f["id"]}</span>{esc(prev_f["title"])}</a>'
    else:
        pager += '<a href="/findings"><span>Back to</span>Finding index</a>'
    if next_f:
        pager += f'<a class="next" href="/findings/{next_f["slug"]}"><span>Next · {next_f["id"]}</span>{esc(next_f["title"])}</a>'
    jsonld = ('{"@context":"https://schema.org","@type":"TechArticle","headline":"' + f["id"] + ': ' + f["title"].replace('"', '\\"') +
              '","dateModified":"2026-11-10","author":{"@type":"Person","name":"Manraj Singh Dhillon"},"publisher":{"@type":"Organization","name":"PatchLabs","url":"https://patchlabs.dev"}}')
    status_pill = '<span class="pill pending">coming · not tested yet</span>' if coming else f'<span class="pill plain">{" ".join(LINE_NAME[f["line"]].split()[1:])}</span>'
    status_box = ""
    if coming:
        status_box = ('<div class="callout limit"><p><strong>PatchLabs does not test for this yet (coming).</strong> This page explains the problem, '
                      'how to check your own project and how to fix it. The Lab’s live checks today are PL-001 to PL-008; this one is not part of any report until it ships. '
                      'Shipping dates go in the <a href="/changelog">changelog</a>.</p></div>')
    if coming:
        fix_note = '<p class="small muted">PatchLabs doesn’t write this fix yet. Review the SQL with your engineer and add it as a new migration.</p>'
    elif live:
        fix_note = '<p class="small muted">Live posture findings come with the header or setting to change. PatchLabs never changes your hosting or your repo.</p>'
    elif code:
        fix_note = '<p class="small muted">Code findings come with the file, the line and a one-line fix in the report, for your engineer to make. PatchLabs never pushes to your repo.</p>'
    else:
        fix_note = '<p class="small muted">Every fix arrives as a migration file (plus any code change it needs, noted in the report) for your engineer to approve. Download it, or commit it on GitHub in one click from the report page. Automatic pull requests need our GitHub App, which is coming.</p>'
    retest = None if coming else retest_for(f["id"], f["line"])
    if retest:
        retest_p = f'<p class="small">Then check again with the <a href="{retest[0]}">{retest[1]}</a>, or <a href="/#check">run the full free check</a> on your repo.</p>'
    elif coming:
        retest_p = '<p class="small muted">PatchLabs doesn’t test for this yet, so have your engineer review the change.</p>'
    else:
        retest_p = '<p class="small">Then <a href="/#check">run the free check</a> on your repo again to confirm it’s gone.</p>'
    prompt_block = ('<p>Built with Lovable, Bolt, Replit or Cursor? Paste this into the chat. It asks for this one fix and nothing else, '
                    'and to see the change before it’s applied. Read the change, or have your engineer read it, before you accept.</p>\n      '
                    f'<div class="code">\n  <div class="code-bar"><span class="name">Prompt for your AI builder</span>'
                    f'<button class="copy" type="button" data-copy>Copy</button></div>\n'
                    f'<pre class="wrap-lines"><code>{esc(prompt_for(f["id"]))}</code></pre>\n</div>\n      {retest_p}')
    fix_h = "The fix" if (coming or code or f.get("why")) else "The fix PatchLabs writes"
    proof_h = "How PatchLabs will test it" if coming else ("How PatchLabs finds it" if (code or live) else "The proof it runs")
    proof_block = (f["proof_tr"] or "") + "\n      " + f["proof_note"]
    if coming:
        cta_h = "Check what PatchLabs does test today"
        cta_p = "This check is coming. Today’s free check rebuilds your database from your migrations, tests it as a visitor, a stranger and the owner (PL-001 to PL-008), and reads your repo for keys and risky code."
    elif live:
        cta_h = f"Does your site have {f['id']}?"
        cta_p = "Type your site’s address. The free headers check loads your public home page once, like any visitor, and grades HTTPS, the certificate, security headers, cookie flags and mixed content. No sign-up, and the result isn’t stored."
    elif code:
        cta_h = f"Does your app have {f['id']}?"
        cta_p = "Paste your public repo. PatchLabs Code reads it for this and every other code finding, and the Lab rebuilds your database to test who can read what."
    else:
        cta_h = f"Does your app have {f['id']}?"
        cta_p = "Paste your public repo. We rebuild the database from your migrations, test it as a visitor, a stranger and the owner, and hand you the proven fix."
    found_dd = esc(f["found"])
    if not coming:
        found_dd = f'<a href="{LINE_URL[f["line"]]}">{LINE_NAME[f["line"]]}</a>' + esc(f["found"].split(LINE_NAME[f["line"]], 1)[1]) if f["found"].startswith(LINE_NAME[f["line"]]) else found_dd
    proof_dt = "Status" if coming else "Lab proof"
    if live:
        example_h = ('<h2 id="example"><span class="lab red" aria-hidden="true">Observe</span>What we see</h2>\n'
                     '      <p>A synthetic example for <code>app.example.com</code>, shortened. Not taken from any real site.</p>')
    else:
        example_h = ('<h2 id="example"><span class="lab red" aria-hidden="true">Exploit</span>Example of vulnerable code</h2>\n'
                     '      <p>Simplified from the patterns we see in AI-built apps. Synthetic: not taken from any real app.</p>')
    if live:
        cta_form = f"""<form class="repo-form one" action="/tools/headers-check" method="get">
          <div class="in">
            <label class="sr-only" for="url-f{n}">Your site’s address</label>
            <input id="url-f{n}" name="url" type="text" inputmode="url" required autocomplete="url" autocapitalize="off" spellcheck="false" placeholder="https://your-app.com">
          </div>
          <button class="btn primary" type="submit">Check my headers free</button>
        </form>
        <div class="form-meta"><span>Free, no sign-up</span><span>Loads your public home page only</span><span><a href="/product/live-posture">How Live posture works</a></span></div>"""
    else:
        alt_tool = ('<a href="/tools/key-check">Or paste code into the free key check</a>' if f["id"] in KEYCHECK_IDS
                    else '<a href="/tools/rls-check">Or run the free static RLS check</a>')
        cta_form = f"""<form class="repo-form" data-check-form action="mailto:manraj@patchlabs.dev?subject=Free%20leak%20check" method="post" enctype="text/plain">
          <div class="in">
            <label class="sr-only" for="repo-f{n}">Public GitHub repo</label>
            <input id="repo-f{n}" name="repo" required autocomplete="off" spellcheck="false" placeholder="github.com/you/your-app">
          </div>
          <div class="in">
            <label class="sr-only" for="email-f{n}">Your email</label>
            <input id="email-f{n}" name="email" type="email" required autocomplete="email" placeholder="you@company.com">
          </div>
          <button class="btn primary" type="submit">Check my app free</button>
        </form>
        <p class="err" role="alert" data-err></p>
        <div class="form-meta"><span>Free for your first app</span><span>Reads your public repo only</span><span>{alt_tool}</span></div>"""
    return f"""<!--
title: {f["id"]} {f["title"]} | PatchLabs findings
description: {f["desc"]}
layout: marketing
nav: findings
head: <link rel="stylesheet" href="/assets/pages/B-research.css"><link rel="stylesheet" href="/assets/pages/B-findings.css"><script type="application/ld+json">{jsonld}</script>
-->
<main id="main">
  <div class="wrap wide docs">
    {nav(f["id"])}
    <article class="docs-main prose finding{' is-coming' if coming else ''}">
      <nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">Home</a></li><li><a href="/findings">Findings</a></li><li aria-current="page">{f["id"]}</li></ol></nav>
      <header class="f-head">
        <div class="f-id"><span class="f-chip">{f["id"]}</span><span class="pill {pill_cls}">{esc(sevlabel)}</span>{status_pill}</div>
        <h1>{esc(f["title"])}</h1>
        <p class="lede">{esc(f["short"])}</p>
        <dl class="f-facts">
          <div><dt>Severity</dt><dd>{esc(sevlabel[0].upper() + sevlabel[1:])}</dd></div>
          <div><dt>Who can exploit it</dt><dd>{esc(f["who"])}</dd></div>
          <div><dt>Found by</dt><dd>{found_dd}</dd></div>
          <div><dt>{proof_dt}</dt><dd>{esc(f["proof"])}</dd></div>
        </dl>
      </header>
      {status_box}

      <h2 id="what"><span class="lab" aria-hidden="true">Explain</span>What it is</h2>
      {f["what"]}
      {study}

      {why}

      {example_h}
      {f["vuln"]}

      <h2 id="check"><span class="lab" aria-hidden="true">Check</span>Check it yourself</h2>
      {f["check"]}{KEYCHECK_NOTE if f["id"] in KEYCHECK_IDS else ""}

      <h2 id="fix"><span class="lab" aria-hidden="true">Fix</span>{fix_h}</h2>
      {f["fix"]}
      {fix_note}

      <h2 id="prompt"><span class="lab" aria-hidden="true">Prompt</span>Ask your AI builder to fix it</h2>
      {prompt_block}

      <h2 id="proof"><span class="lab green" aria-hidden="true">Prove</span>{proof_h}</h2>
      {proof_block}

      <h2 id="intended"><span class="lab" aria-hidden="true">Intent</span>When the pattern is intended</h2>
      {f["intended"]}

      {sevwhy}

      {lint}

      <h2 id="related"><span class="lab" aria-hidden="true">See also</span>Related findings</h2>
      <div class="grid g3 not-prose">{rel}</div>
      {guide_html}

      <div class="f-cta">
        <p class="lab">Free check</p>
        <h2>{cta_h}</h2>
        <p>{cta_p}</p>
        {cta_form}
      </div>

      <p class="small muted mt-4">Last reviewed {REVIEWED}. Finding IDs are stable: link to them freely. Spotted a mistake? <a href="mailto:manraj@patchlabs.dev?subject=Finding%20{f["id"]}">Tell us</a>.</p>
      <div class="docs-pager">{pager}</div>
    </article>
    <aside class="toc" aria-label="On this page">
      <h2>On this page</h2>
      <ul>{toc_html}</ul>
    </aside>
  </div>
  <script>if (window.matchMedia('(max-width: 820px)').matches) {{ var dn = document.querySelector('.docs-nav details'); if (dn) dn.open = false; }}</script>
</main>
"""


FOUND_SHORT = {"PL-001": "RLS check · lab", "PL-002": "RLS check · lab", "PL-003": "RLS check · lab", "PL-004": "RLS check",
               "PL-005": "RLS check · lab", "PL-006": "RLS check", "PL-007": "RLS check", "PL-008": "RLS check · lab",
               "PL-010": "Key scan · code", "PL-011": "Key scan · history",
               "PL-012": "Lab · coming", "PL-013": "Lab · coming", "PL-014": "Lab · coming", "PL-015": "Lab · coming",
               "PL-016": "Lab · coming", "PL-019": "Code · SQL + app code", "PL-009": "Key scan · code",
               "PL-017": "Code · functions", "PL-018": "Code · config", "PL-020": "Code · frontend", "PL-021": "Code · webhooks",
               "PL-022": "Code · functions", "PL-023": "Code · lockfile + OSV", "PL-024": "Code · frontend",
               "PL-025": "Code · Firebase rules", "PL-026": "Code · CORS headers",
               "PL-027": "Live · HTTPS redirect", "PL-028": "Live · certificate", "PL-029": "Live · headers", "PL-030": "Live · headers",
               "PL-031": "Live · headers", "PL-032": "Live · headers", "PL-033": "Live · cookies", "PL-034": "Live · page HTML",
               "PL-035": "Live · headers", "PL-036": "Live · headers"}
LINTS = {"PL-001": "none (0024 skips SELECT)", "PL-002": "none (0024 skips SELECT)", "PL-003": "0008", "PL-004": "–",
         "PL-005": "0024 (writes only)", "PL-006": "0011, 0028, 0029", "PL-007": "0025", "PL-008": "0013, 0007",
         "PL-010": "–", "PL-011": "–", "PL-012": "0024 (only literal true)", "PL-013": "–", "PL-014": "0010, 0002, 0016",
         "PL-015": "–", "PL-016": "–", "PL-019": "0015 (policies only)"}
SEV_FILTER = {"critical": "critical", "high": "high", "high or medium": "high", "medium": "medium", "low": "low", "info": "info", "from advisory": "advisory"}


def index_page():
    def row(f):
        pill = SEV[f["sev"]][0]
        label = f.get("sevlabel", f["sev"]).split(" (")[0]
        return (f'<a class="f-row" href="/findings/{f["slug"]}" data-line="{f["line"]}" data-sev="{SEV_FILTER[f["sev"]]}" data-status="{f["status"]}"><span class="fid">{f["id"]}</span>'
                f'<div><h3>{esc(f["title"])}</h3><p>{esc(f["short"])}</p></div>'
                f'<span class="sevcell"><span class="pill {pill}">{esc(label)}</span></span>'
                f'<span class="where">{FOUND_SHORT[f["id"]]}</span><span class="go" aria-hidden="true">→</span></a>')
    lab = "\n      ".join(row(f) for f in F if f["line"] == "lab" and f["status"] == "live")
    code = "\n      ".join(row(f) for f in F if f["line"] == "code" and f["status"] == "live")
    live = "\n      ".join(row(f) for f in F if f["line"] == "live" and f["status"] == "live")
    coming = "\n      ".join(row(f) for f in F if f["status"] == "coming")
    n_live = sum(1 for f in F if f["status"] == "live")
    n_lab = sum(1 for f in F if f["status"] == "live" and f["line"] == "lab")
    n_code = sum(1 for f in F if f["status"] == "live" and f["line"] == "code")
    n_posture = sum(1 for f in F if f["status"] == "live" and f["line"] == "live")
    n_coming = len(F) - n_live
    lint_rows = "\n            ".join(
        f'<tr><th scope="row"><a href="/findings/{f["slug"]}">{f["id"]}</a></th><td>{esc(f["title"])}{" <span class=\"pill pending\">coming</span>" if f["status"] == "coming" else ""}</td><td class="mono">{esc(LINTS[f["id"]])}</td></tr>'
        for f in F if f["id"] in LINTS)
    return f"""<!--
title: Finding index: every issue PatchLabs Lab, Code and Live posture check | PatchLabs
description: Stable IDs for the database, code, HTTPS and header problems PatchLabs finds in AI-built apps, each with an example, a self-check, the fix and how it is found.
layout: marketing
nav: findings
head: <link rel="stylesheet" href="/assets/pages/B-research.css"><link rel="stylesheet" href="/assets/pages/B-findings.css">
-->
<main id="main">
  <section class="sec tight">
    <div class="wrap">
      <nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">Home</a></li><li><a href="/research/1-in-4">Research</a></li><li aria-current="page">Findings</li></ol></nav>
      <p class="lab">Finding index</p>
      <h1>Every problem we test for, with the fix and the proof.</h1>
      <p class="lede">{n_live} live checks with stable IDs: {n_lab} that PatchLabs Lab proves in a database rebuilt from your migrations, {n_code} that PatchLabs Code finds by reading your repo, and {n_posture} that Live posture reads from your public home page on a domain you verify. {n_coming} more are written up but not tested yet, and are marked as coming. Each page shows vulnerable code, a way to check your own project and the fix.</p>
      <div class="row mt-3"><a class="btn primary large" href="/#check">Check my app free</a><a class="btn secondary large" href="/learn">Read the guides</a></div>
    </div>
  </section>

  <section class="sec tight" aria-labelledby="list-h">
    <div class="wrap">
      <h2 id="list-h" class="sr-only">All findings</h2>
      <div class="f-filters js-only" role="group" aria-label="Filter findings">
        <div class="f-fgroup" data-filter-group="line"><span class="f-flabel">Line</span>
          <button type="button" class="f-chipbtn" data-filter="all" aria-pressed="true">All</button>
          <button type="button" class="f-chipbtn" data-filter="lab" aria-pressed="false">Lab</button>
          <button type="button" class="f-chipbtn" data-filter="code" aria-pressed="false">Code</button>
          <button type="button" class="f-chipbtn" data-filter="live" aria-pressed="false">Live</button>
        </div>
        <div class="f-fgroup" data-filter-group="sev"><span class="f-flabel">Severity</span>
          <button type="button" class="f-chipbtn" data-filter="all" aria-pressed="true">All</button>
          <button type="button" class="f-chipbtn" data-filter="critical" aria-pressed="false">Critical</button>
          <button type="button" class="f-chipbtn" data-filter="high" aria-pressed="false">High</button>
          <button type="button" class="f-chipbtn" data-filter="medium" aria-pressed="false">Medium</button>
          <button type="button" class="f-chipbtn" data-filter="low" aria-pressed="false">Low</button>
          <button type="button" class="f-chipbtn" data-filter="info" aria-pressed="false">Info</button>
          <button type="button" class="f-chipbtn" data-filter="advisory" aria-pressed="false">Advisory</button>
        </div>
        <div class="f-fgroup" data-filter-group="status"><span class="f-flabel">Status</span>
          <button type="button" class="f-chipbtn" data-filter="all" aria-pressed="true">All</button>
          <button type="button" class="f-chipbtn" data-filter="live" aria-pressed="false">Live</button>
          <button type="button" class="f-chipbtn" data-filter="coming" aria-pressed="false">Coming</button>
        </div>
        <p class="f-count" aria-live="polite"><span id="f-shown">{len(F)}</span> of {len(F)} shown</p>
      </div>
      <div class="f-group">
        <p class="lab red">Live · PatchLabs Lab · who can read what in your database</p>
        <div class="f-index">
      {lab}
        </div>
      </div>
      <div class="f-group">
        <p class="lab">Live · PatchLabs Code · keys and risky code in your repo</p>
        <div class="f-index">
      {code}
        </div>
      </div>
      <div class="f-group">
        <p class="lab">Live · PatchLabs Live posture · HTTPS and headers on your verified domain</p>
        <div class="f-index">
      {live}
        </div>
      </div>
      <div class="f-group f-group-coming">
        <p class="lab">Coming · not tested yet</p>
        <p class="small muted f-coming-note">Explained, with self-checks and fixes, but PatchLabs does not test for these yet. They won’t appear in a report until they ship.</p>
        <div class="f-index">
      {coming}
        </div>
      </div>
      <p class="f-empty muted" hidden>No findings match those filters.</p>
      <p class="small muted mt-3">IDs never change meaning and are never reused, so you can link to them from tickets and docs. Last reviewed {REVIEWED}.</p>
    </div>
  </section>

  <section class="sec band" aria-labelledby="sev-h">
    <div class="wrap split top">
      <div>
        <p class="lab">Severity</p>
        <h2 id="sev-h">Ranked by who can reach the data.</h2>
        <p class="lede">Severity follows one question: who, outside the people meant to see it, can read or change the data? Dependency findings take the severity of their published advisory.</p>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th scope="col">Level</th><th scope="col">Meaning</th></tr></thead>
          <tbody>
            <tr><th scope="row"><span class="pill sev-critical">critical</span></th><td>Anyone on the internet, or anyone who signs up, can read personal data, change a whole table or make themselves admin.</td></tr>
            <tr><th scope="row"><span class="pill sev-high">high</span></th><td>Anyone who signs up can read personal data, a privileged function or webhook is open, or a user can act on another user's data.</td></tr>
            <tr><th scope="row"><span class="pill sev-medium">medium</span></th><td>A real weakness that needs a specific situation to matter, such as a public bucket, unsanitised HTML or a loose CORS rule.</td></tr>
            <tr><th scope="row"><span class="pill sev-low">low</span></th><td>Nothing exposed by itself, but the app is likely broken or other findings get easier to exploit.</td></tr>
            <tr><th scope="row"><span class="pill sev-low">info</span></th><td>Nothing exposed and nothing to exploit: a one-line hardening step. Costs no points in the Live posture grade.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <section class="sec" aria-labelledby="how-h">
    <div class="wrap">
      <div class="sec-head">
        <p class="lab">How a finding reaches you</p>
        <h2 id="how-h">Data you watched leak, code you can point at, or a header you can read.</h2>
        <p>Every finding in a report uses these IDs and the same shape: severity, the object, the file and line or the address, short evidence, and how it was found.</p>
      </div>
      <div class="grid g4">
        <div class="card green-edge">
          <span class="n-big">LAB · PROVEN</span>
          <h3>PatchLabs Lab</h3>
          <p>Rebuilds the database from your migrations in a disposable Postgres with Supabase's roles and grants, seeds fake rows, and reads every table as an anonymous visitor, a signed-in stranger and the owner. Then writes the fix and proves it the same way.</p>
          <div class="card-foot"><a class="link-arrow" href="/product/lab">PatchLabs Lab</a></div>
        </div>
        <div class="card">
          <span class="n-big">CODE · FILE AND LINE</span>
          <h3>PatchLabs Code</h3>
          <p>Reads the repo without running it: keys in code and the full git history, Edge Functions and their config, webhooks, CORS, admin checks in the browser, raw HTML, Firebase rules, and dependency versions checked against OSV.</p>
          <div class="card-foot"><a class="link-arrow" href="/product/code">PatchLabs Code</a></div>
        </div>
        <div class="card">
          <span class="n-big">LIVE · YOUR HOME PAGE</span>
          <h3>Live posture</h3>
          <p>On a domain you verify, loads your public home page like any visitor and reads the response: HTTPS, the certificate, security headers, cookie flags and mixed content. Never your database.</p>
          <div class="card-foot"><a class="link-arrow" href="/product/live-posture">Live posture</a></div>
        </div>
        <div class="card">
          <span class="n-big">FREE · NO SIGN-UP</span>
          <h3>Static RLS check</h3>
          <p>Reads the SQL in your <code>supabase/migrations</code> and flags PL-001 to PL-008 from the rules as written. The free <a href="/tools/headers-check">headers check</a> does the same for PL-027 to PL-036 on any address.</p>
          <div class="card-foot"><a class="link-arrow" href="/tools/rls-check">Run the free RLS check</a></div>
        </div>
      </div>
    </div>
  </section>

  <section class="sec band" aria-labelledby="lint-h">
    <div class="wrap">
      <div class="sec-head">
        <p class="lab">Map</p>
        <h2 id="lint-h">How our database IDs line up with Supabase’s linter.</h2>
        <p>Use Supabase's Security Advisor as well: it covers health and performance checks we don't. The difference is in the rows marked "none": public reads, which the linter skips on purpose because only the app's intent can say whether they are a leak. Code findings without a linter equivalent are left out.</p>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th scope="col">PatchLabs ID</th><th scope="col">Finding</th><th scope="col">Related Supabase lint</th></tr></thead>
          <tbody>
            {lint_rows}
          </tbody>
        </table>
      </div>
      <p class="small muted mt-2">Lint numbers from Supabase's database linter (splinter), checked against its source in Nov 2026. Independent: PatchLabs is not affiliated with Supabase.</p>
    </div>
  </section>

  <section class="sec">
    <div class="wrap">
      <div class="cta-panel">
        <p class="lab">Free check</p>
        <h2>Which of these does your app have?</h2>
        <p class="lede">Paste your public repo. You get every live finding, the fix and the proof on one page.</p>
        <form class="repo-form" data-check-form action="mailto:manraj@patchlabs.dev?subject=Free%20leak%20check" method="post" enctype="text/plain">
          <div class="in">
            <label class="sr-only" for="repo-fi">Public GitHub repo</label>
            <input id="repo-fi" name="repo" required autocomplete="off" spellcheck="false" placeholder="github.com/you/your-app">
          </div>
          <div class="in">
            <label class="sr-only" for="email-fi">Your email</label>
            <input id="email-fi" name="email" type="email" required autocomplete="email" placeholder="you@company.com">
          </div>
          <button class="btn primary" type="submit">Check my app free</button>
        </form>
        <p class="err" role="alert" data-err></p>
        <div class="form-meta"><span>Free for your first app</span><span>Never touches your database</span></div>
      </div>
    </div>
  </section>
  <script>
  (function () {{
    var bar = document.querySelector('.f-filters'); if (!bar) return;
    var state = {{ line: 'all', sev: 'all', status: 'all' }};
    function apply() {{
      var shown = 0;
      document.querySelectorAll('.f-row').forEach(function (r) {{
        var ok = (state.line === 'all' || r.dataset.line === state.line) &&
                 (state.sev === 'all' || r.dataset.sev === state.sev) &&
                 (state.status === 'all' || r.dataset.status === state.status);
        r.hidden = !ok; if (ok) shown++;
      }});
      document.querySelectorAll('.f-group').forEach(function (g) {{
        g.hidden = !g.querySelector('.f-row:not([hidden])');
      }});
      document.getElementById('f-shown').textContent = shown;
      document.querySelector('.f-empty').hidden = shown > 0;
    }}
    bar.addEventListener('click', function (e) {{
      var b = e.target.closest('[data-filter]'); if (!b) return;
      var grp = b.closest('[data-filter-group]');
      state[grp.dataset.filterGroup] = b.dataset.filter;
      grp.querySelectorAll('[data-filter]').forEach(function (x) {{ x.setAttribute('aria-pressed', x === b ? 'true' : 'false'); }});
      apply();
    }});
  }})();
  </script>
</main>
"""


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for f in F:
        with open(os.path.join(OUT, f["slug"] + ".html"), "w") as fh:
            fh.write(page(f))
    print("wrote", len(F), "finding pages")
    with open(os.path.join(OUT, "index.html"), "w") as fh:
        fh.write(index_page())
    print("wrote findings index")

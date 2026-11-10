#!/usr/bin/env python3
"""Generates site/pages/findings/pl-0xx.html for the PatchLabs finding taxonomy (group B).
Mini formats:
  sql(text): lines starting '+ ' -> added, '! ' -> removed, '--' -> comment. Text is HTML-escaped.
  tr(lines): proof transcript; {STEP:NAME} step label, {anon} {stranger} {owner} {admin} identities,
             {LEAK} {DENIED} {OK} tokens, lines starting '~' are dim.
"""
import html, os, re

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
        elif line.lstrip().startswith("--") or line.lstrip().startswith("#"):
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


TOK = {"LEAK": '<span class="leak">LEAK</span>', "DENIED": '<span class="deny">DENIED</span>', "OK": '<span class="ok">OK</span>'}


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


SEV = {"critical": ("sev-critical", "crit"), "high": ("sev-high", "high"), "medium": ("sev-medium", "med"), "low": ("sev-low", "low"),
       "high to low": ("sev-high", "high"), "high or medium": ("sev-high", "high")}

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
    related=["PL-011", "PL-003", "PL-008"],
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
    proof_note="""<p>We can't check whether a key still works without using it, and we never use keys we find. So the report doesn't claim the problem is solved. It lists each key, masked, with the commit or file it came from and the page where you rotate it,.</p>""",
    intended="""<p>Some key-shaped strings are fine to commit: the Supabase public key (meant for browsers), test-mode keys such as <code>sk_test_…</code>, and placeholder values in <code>.env.example</code>. The report shows the file or commit for every key it finds, so you can tell these apart quickly. If a flagged key was revoked long ago, there is nothing more to do.</p>""",
    study=None, lint=None,
    related=["PL-010", "PL-007", "PL-001"],
))

ORDER = [f["id"] for f in F]
BY = {f["id"]: f for f in F}


def nav(cur):
    def item(f):
        sc = SEV[f["sev"]][1]
        curattr = ' aria-current="page"' if f["id"] == cur else ""
        return (f'<li><a href="/findings/{f["slug"]}"{curattr}><span class="fid"><span class="sev-dot {sc}" aria-hidden="true"></span>{f["id"]}</span>'
                f'{esc(f["title"])}</a></li>')
    data = "\n        ".join(item(f) for f in F if f["group"] == "data")
    keys = "\n        ".join(item(f) for f in F if f["group"] == "keys")
    return f"""<nav class="docs-nav" aria-label="Findings">
      <details open><summary class="show-sm">All findings</summary>
      <h2>Overview</h2>
      <ul><li><a href="/findings">Finding index</a></li><li><a href="/research/1-in-4">The 1-in-4 Report</a></li><li><a href="/leaking-now">Leaking right now?</a></li></ul>
      <h2>Data access</h2>
      <ul>
        {data}
      </ul>
      <h2>Keys</h2>
      <ul>
        {keys}
      </ul>
      </details>
    </nav>"""


def page(f):
    i = ORDER.index(f["id"])
    prev_f = F[i - 1] if i > 0 else None
    next_f = F[i + 1] if i < len(F) - 1 else None
    pill_cls = SEV[f["sev"]][0]
    sevlabel = f.get("sevlabel", f["sev"])
    n = f["slug"].replace("pl-", "")
    toc = [("what", "What it is"), ("example", "Example"), ("check", "Check it yourself"), ("fix", "The fix we write"),
           ("proof", "The proof"), ("intended", "When it’s intended")]
    if f["lint"]:
        toc.append(("lint", "Supabase linter"))
    toc.append(("related", "Related"))
    toc_html = "".join(f'<li><a href="#{a}">{b}</a></li>' for a, b in toc)
    study = (f'<div class="callout note"><p>{f["study"]}</p></div>' if f["study"] else "")
    lint = (f'<h2 id="lint"><span class="lab" aria-hidden="true">Map</span>Supabase linter</h2>\n{f["lint"]}' if f["lint"] else "")
    rel = "".join(
        f'<a class="card link" href="/findings/{BY[r]["slug"]}"><span class="n-big">{r}</span><h3>{esc(BY[r]["title"])}</h3><p class="small">{esc(BY[r]["short"])}</p></a>'
        for r in f["related"])
    pager = ""
    if prev_f:
        pager += f'<a href="/findings/{prev_f["slug"]}"><span>Previous · {prev_f["id"]}</span>{esc(prev_f["title"])}</a>'
    else:
        pager += '<a href="/findings"><span>Back to</span>Finding index</a>'
    if next_f:
        pager += f'<a class="next" href="/findings/{next_f["slug"]}"><span>Next · {next_f["id"]}</span>{esc(next_f["title"])}</a>'
    jsonld = ('{"@context":"https://schema.org","@type":"TechArticle","headline":"' + f["id"] + ': ' + f["title"] +
              '","dateModified":"2026-11-10","author":{"@type":"Person","name":"Manraj Singh Dhillon"},"publisher":{"@type":"Organization","name":"PatchLabs","url":"https://patchlabs.dev"}}')
    return f"""<!--
title: {f["id"]} {f["title"]} | PatchLabs findings
description: {f["desc"]}
layout: marketing
nav: findings
head: <link rel="stylesheet" href="/assets/pages/B-research.css"><script type="application/ld+json">{jsonld}</script>
-->
<main id="main">
  <div class="wrap wide docs">
    {nav(f["id"])}
    <article class="docs-main prose finding">
      <nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">Home</a></li><li><a href="/findings">Findings</a></li><li aria-current="page">{f["id"]}</li></ol></nav>
      <header class="f-head">
        <div class="f-id"><span class="f-chip">{f["id"]}</span><span class="pill {pill_cls}">{esc(sevlabel)}</span></div>
        <h1>{esc(f["title"])}</h1>
        <p class="lede">{esc(f["short"])}</p>
        <dl class="f-facts">
          <div><dt>Severity</dt><dd>{esc(sevlabel[0].upper() + sevlabel[1:])}</dd></div>
          <div><dt>Who can exploit it</dt><dd>{esc(f["who"])}</dd></div>
          <div><dt>Found by</dt><dd>{esc(f["found"])}</dd></div>
          <div><dt>Lab proof</dt><dd>{esc(f["proof"])}</dd></div>
        </dl>
      </header>

      <h2 id="what"><span class="lab" aria-hidden="true">Explain</span>What it is</h2>
      {f["what"]}
      {study}

      <h2 id="example"><span class="lab red" aria-hidden="true">Exploit</span>Example of vulnerable code</h2>
      <p>Simplified from the patterns we see in AI-built apps. Synthetic: not taken from any real app.</p>
      {f["vuln"]}

      <h2 id="check"><span class="lab" aria-hidden="true">Check</span>Check it yourself</h2>
      {f["check"]}

      <h2 id="fix"><span class="lab" aria-hidden="true">Fix</span>The fix PatchLabs writes</h2>
      {f["fix"]}
      <p class="small muted">Every fix arrives as a migration file (plus any code change it needs, noted in the report) for your engineer to approve. Download it, or commit it on GitHub in one click from the report page. Automatic pull requests need our GitHub App, which is coming.</p>

      <h2 id="proof"><span class="lab green" aria-hidden="true">Prove</span>The proof it runs</h2>
      {f["proof_tr"]}
      {f["proof_note"]}

      <h2 id="intended"><span class="lab" aria-hidden="true">Intent</span>When the pattern is intended</h2>
      {f["intended"]}

      {lint}

      <h2 id="related"><span class="lab" aria-hidden="true">See also</span>Related findings</h2>
      <div class="grid g3 not-prose">{rel}</div>

      <div class="f-cta">
        <p class="lab">Free check</p>
        <h2>Does your app have {f["id"]}?</h2>
        <p>Paste your public repo. We rebuild the database from your migrations, test it as a visitor, a stranger and the owner, and hand you the proven fix.</p>
        <form class="repo-form" data-check-form action="mailto:manraj@patchlabs.dev?subject=Free%20leak%20check" method="post" enctype="text/plain">
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
        <div class="form-meta"><span>Free for your first app</span><span>Reads your public repo only</span><span><a href="/tools/rls-check">Or run the free static RLS check</a></span></div>
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


if __name__ == "__main__":
    os.makedirs(OUT, exist_ok=True)
    for f in F:
        with open(os.path.join(OUT, f["slug"] + ".html"), "w") as fh:
            fh.write(page(f))
    print("wrote", len(F), "finding pages")


FOUND_SHORT = {"PL-001": "RLS check · lab", "PL-002": "RLS check · lab", "PL-003": "RLS check · lab", "PL-004": "RLS check",
               "PL-005": "RLS check · lab", "PL-006": "RLS check", "PL-007": "RLS check", "PL-008": "RLS check · lab",
               "PL-010": "Key scan · code", "PL-011": "Key scan · history"}
LINTS = {"PL-001": "none (0024 skips SELECT)", "PL-002": "none (0024 skips SELECT)", "PL-003": "0008", "PL-004": "–",
         "PL-005": "0024 (writes only)", "PL-006": "0011, 0028, 0029", "PL-007": "0025", "PL-008": "0013, 0007",
         "PL-010": "–", "PL-011": "–"}


def index_page():
    def row(f):
        pill = SEV[f["sev"]][0]
        return (f'<a class="f-row" href="/findings/{f["slug"]}"><span class="fid">{f["id"]}</span>'
                f'<div><h3>{esc(f["title"])}</h3><p>{esc(f["short"])}</p></div>'
                f'<span class="sevcell"><span class="pill {pill}">{esc(f.get("sevlabel", f["sev"]).split(" (")[0])}</span></span>'
                f'<span class="where">{FOUND_SHORT[f["id"]]}</span><span class="go" aria-hidden="true">→</span></a>')
    data = "\n      ".join(row(f) for f in F if f["group"] == "data")
    keys = "\n      ".join(row(f) for f in F if f["group"] == "keys")
    lint_rows = "\n            ".join(
        f'<tr><th scope="row"><a href="/findings/{f["slug"]}">{f["id"]}</a></th><td>{esc(f["title"])}</td><td class="mono">{esc(LINTS[f["id"]])}</td></tr>'
        for f in F)
    return f"""<!--
title: Finding index: every Supabase leak PatchLabs tests for | PatchLabs
description: Stable IDs for the data-access and key leaks PatchLabs finds in AI-built Supabase apps, each with example SQL, a self-check, the fix we write and the proof.
layout: marketing
nav: findings
head: <link rel="stylesheet" href="/assets/pages/B-research.css">
-->
<main id="main">
  <section class="sec tight">
    <div class="wrap">
      <nav class="crumbs" aria-label="Breadcrumb"><ol><li><a href="/">Home</a></li><li><a href="/research/1-in-4">Research</a></li><li aria-current="page">Findings</li></ol></nav>
      <p class="lab">Finding index</p>
      <h1>Every leak we test for, with the fix and the proof.</h1>
      <p class="lede">Ten stable IDs for the ways AI-built Supabase apps expose data and keys. Each page shows the vulnerable SQL, a query to check your own project, the fix PatchLabs writes and the test that proves it.</p>
      <div class="row mt-3"><a class="btn primary large" href="/#check">Check my app free</a><a class="btn secondary large" href="/tools/rls-check">Free static RLS check</a></div>
    </div>
  </section>

  <section class="sec tight" aria-labelledby="list-h">
    <div class="wrap">
      <h2 id="list-h" class="sr-only">All findings</h2>
      <div class="f-group">
        <p class="lab red">Data access · who can read what</p>
        <div class="f-index">
      {data}
        </div>
      </div>
      <div class="f-group">
        <p class="lab">Keys · code and git history</p>
        <div class="f-index">
      {keys}
        </div>
      </div>
      <p class="small muted mt-3">IDs never change meaning and are never reused, so you can link to them from tickets and docs. Gaps (such as PL-009) are reserved. Last reviewed {REVIEWED}.</p>
    </div>
  </section>

  <section class="sec band" aria-labelledby="sev-h">
    <div class="wrap split top">
      <div>
        <p class="lab">Severity</p>
        <h2 id="sev-h">Ranked by who can reach the data.</h2>
        <p class="lede">Severity follows one question: who, outside the people meant to see it, can read or change the data? The same rules drive the free RLS check and every full report.</p>
      </div>
      <div class="table-wrap">
        <table class="table">
          <thead><tr><th scope="col">Level</th><th scope="col">Meaning</th></tr></thead>
          <tbody>
            <tr><th scope="row"><span class="pill sev-critical">critical</span></th><td>Anyone on the internet can read personal data, or read and change a whole table.</td></tr>
            <tr><th scope="row"><span class="pill sev-high">high</span></th><td>Anyone who signs up can read personal data, anyone can change rows, or a privileged function is open to anonymous callers.</td></tr>
            <tr><th scope="row"><span class="pill sev-medium">medium</span></th><td>A real weakness that needs a specific situation to matter, such as an UPDATE rule without WITH CHECK or a public bucket.</td></tr>
            <tr><th scope="row"><span class="pill sev-low">low</span></th><td>Nothing exposed, but the app is likely broken, or the rule only opens non-personal data.</td></tr>
          </tbody>
        </table>
      </div>
    </div>
  </section>

  <section class="sec" aria-labelledby="how-h">
    <div class="wrap">
      <div class="sec-head">
        <p class="lab">Static vs proven</p>
        <h2 id="how-h">A rule that looks wrong, or data you watched leak.</h2>
        <p>Two ways a finding reaches you. Both use these IDs.</p>
      </div>
      <div class="grid g2">
        <div class="card">
          <span class="n-big">FREE · NO SIGN-UP</span>
          <h3>Static RLS check</h3>
          <p>Reads the SQL in your <code>supabase/migrations</code> and flags PL-001 to PL-008 from the rules as written. Fast, and honest about its limit: it can't tell whether a public read is intended, or what the database really allows once every migration has run.</p>
          <div class="card-foot"><a class="link-arrow" href="/tools/rls-check">Run the free RLS check</a></div>
        </div>
        <div class="card green-edge">
          <span class="n-big">FULL CHECK · FREE FOR ONE APP</span>
          <h3>Lab proof</h3>
          <p>Rebuilds the database from your migrations in a disposable Postgres with Supabase's roles and grants, seeds fake rows, and reads every table as an anonymous visitor, a signed-in stranger and the owner. Then writes the fix and proves it the same way. Also scans code and full git history for keys (PL-010, PL-011).</p>
          <div class="card-foot"><a class="link-arrow" href="/#check">Check my app free</a></div>
        </div>
      </div>
    </div>
  </section>

  <section class="sec band" aria-labelledby="lint-h">
    <div class="wrap">
      <div class="sec-head">
        <p class="lab">Map</p>
        <h2 id="lint-h">How our IDs line up with Supabase’s linter.</h2>
        <p>Use Supabase's Security Advisor as well: it covers health and performance checks we don't. The difference is in the rows marked "none": public reads, which the linter skips on purpose because only the app's intent can say whether they are a leak.</p>
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
        <p class="lede">Paste your public repo. You get every finding, the fix and the proof on one page.</p>
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
        <div class="form-meta"><span>Free for your first app</span><span>Never connects to your live app or database</span></div>
      </div>
    </div>
  </section>
</main>
"""


with open(os.path.join(OUT, "index.html"), "w") as fh:
    fh.write(index_page())
print("wrote findings index")

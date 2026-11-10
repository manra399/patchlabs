"""Free static RLS check: the analyzer's rules, and the endpoint (GitHub fetch, limits, cache, rate limit)."""
import rls
from helpers import STATE, add_repo

LEAKY = """
-- profiles hold personal data
create table public.profiles (
  id uuid primary key references auth.users,
  full_name text,
  email text not null,
  "Phone_Number" text,
  constraint email_unique unique (email)
);
alter table public.profiles enable row level security;
create policy "Public profiles are viewable by everyone." on profiles
  for select using (true);
create policy "Users can update own profile." on profiles for update to authenticated using (auth.uid() = id);

create table orders (id bigint, user_id uuid, total numeric);
alter table orders enable row level security;
create policy "signed in read" on orders for select to authenticated using (true);
create policy "anyone insert" on public.orders for insert to anon with check (true);

create table products (id int, name text);
alter table products enable row level security;
create policy "read products" on products for select to anon using (true);

create table audit_log (id int, ip_address text);

create table locked (id int);
alter table only public.locked enable row level security;

create table own_rows (id int, user_id uuid, email text);
alter table own_rows enable row level security;
create policy "own" on own_rows for all using (auth.uid() = user_id) with check (auth.uid() = user_id);
"""

FUNCS = """
create or replace function public.get_all_emails() returns setof text
language sql security definer as $$ select email from profiles; $$;
create function public.safe() returns int language plpgsql security definer set search_path = '' as $fn$
begin
  -- a ; inside the body must not split the statement; nor should 'security definer' text here
  return 1;
end; $fn$;
grant execute on function public.safe() to anon;
create function public.invoker() returns int language sql as $$ select 1 $$;
insert into storage.buckets (id, name, public) values ('avatars', 'avatars', true), ('private', 'private', false);
update storage.buckets set public = true where id = 'docs';
/* create table ignored_in_comment (email text); */
"""


def ids(findings):
    return sorted((f["id"], f["table"]) for f in findings)


def test_analyzer_rules():
    tables, findings = rls.analyze([("supabase/migrations/001_init.sql", LEAKY)])
    t = {x["name"]: x for x in tables}
    assert set(t) == {"profiles", "orders", "products", "audit_log", "locked", "own_rows"}
    assert t["profiles"]["personal_columns"] == ["email", "phone_number"] and t["profiles"]["rls_enabled"] and t["profiles"]["policies"] == 2
    assert t["audit_log"]["rls_enabled"] is False
    got = ids(findings)
    assert ("PL-001", "profiles") in got  # anon (no TO = public) can read email/phone
    assert ("PL-002", "orders") in got  # any signed-in user reads every order
    assert ("PL-005", "orders") in got  # anon insert with check (true)
    assert ("PL-005", "products") in got  # public catalogue: always-true, low
    assert ("PL-004", "profiles") in got  # update policy without WITH CHECK
    assert ("PL-008", "audit_log") in got
    assert ("PL-003", "locked") in got
    assert not [f for f in findings if f["table"] == "own_rows"]
    sev = {(f["id"], f["table"]): f["severity"] for f in findings}
    assert sev[("PL-001", "profiles")] == "critical" and sev[("PL-005", "products")] == "low" and sev[("PL-005", "orders")] == "high"
    assert sev[("PL-008", "audit_log")] == "critical"  # ip_address looks personal
    f = next(f for f in findings if f["id"] == "PL-001")
    assert f["file"] == "supabase/migrations/001_init.sql" and f["line"] == 11 and f["snippet"].startswith('create policy "Public profiles')
    assert f["title"] == rls.TITLES["PL-001"]
    assert findings[0]["severity"] == "critical"  # most severe first


def test_analyzer_functions_buckets_and_comments():
    tables, findings = rls.analyze([("m.sql", FUNCS)])
    assert tables == []
    six = [f for f in findings if f["id"] == "PL-006"]
    assert len(six) == 2
    by = {f["detail"].split(":")[0]: f for f in six}
    assert by["Function get_all_emails"]["severity"] == "medium" and "search_path" in by["Function get_all_emails"]["detail"]
    assert by["Function safe"]["severity"] == "high" and "anon" in by["Function safe"]["detail"]
    buckets = [f["detail"] for f in findings if f["id"] == "PL-007"]
    assert len(buckets) == 2 and any("avatars" in b for b in buckets) and any("docs" in b for b in buckets)


def test_analyzer_follows_migration_order():
    files = [("001.sql", "create table notes (id int, email text);"),
             ("002.sql", "alter table notes enable row level security;\ncreate policy p on notes for select using (true);"),
             ("003.sql", "drop policy p on notes;\ncreate policy p2 on notes for select using (auth.uid() = id);"),
             ("004.sql", "create table tmp (id int); drop table tmp;")]
    tables, findings = rls.analyze(files)
    assert [t["name"] for t in tables] == ["notes"] and findings == []


def test_statement_splitter_keeps_lines():
    sql = "select 1;\n\n-- c ; c\ncreate table a (x text default 'a;b');\n/* multi\nline */ select $$;$$;"
    assert list(rls.statements(sql)) == [(1, "select 1"), (4, "create table a (x text default 'a;b')"), (6, "select $$;$$")]


def setup_repo(files, repo="acme/shop"):
    add_repo(repo)
    STATE.migrations[repo.lower()] = files


def test_endpoint(client):
    setup_repo({"20240101_init.sql": LEAKY, "20240102_funcs.sql": FUNCS, "README.md": "x"})
    r = client.post("/tools/rls-check", json={"repo": "https://github.com/acme/shop"})
    assert r.status_code == 200, r.text
    d = r.json()
    assert d["repo"] == "acme/shop" and d["files_scanned"] == 2 and d["commit"] == "a" * 40 and d["cached"] is False
    assert d["limits"] == "static analysis only; the full check proves it in the lab"
    assert {f["id"] for f in d["findings"]} == {f"PL-00{i}" for i in range(1, 9)}
    assert set(d["findings"][0]) >= {"id", "title", "table", "file", "line", "severity", "snippet"}
    assert any(c.startswith("/raw/acme/shop/" + "a" * 40 + "/supabase/migrations/") for c in STATE.calls)  # pinned to the commit


def test_endpoint_cache_per_commit(client):
    setup_repo({"001.sql": LEAKY})
    assert client.post("/tools/rls-check", json={"repo": "acme/shop"}).json()["cached"] is False
    STATE.calls.clear()
    assert client.post("/tools/rls-check", json={"repo": "acme/shop"}).json()["cached"] is True
    assert not [c for c in STATE.calls if c.startswith("/raw/")]
    STATE.shas["acme/shop"] = "b" * 40  # new commit: fresh scan
    d = client.post("/tools/rls-check", json={"repo": "acme/shop"}).json()
    assert d["cached"] is False and d["commit"] == "b" * 40


def test_endpoint_limits(client, monkeypatch):
    setup_repo({f"{i:03}.sql": f"create table t{i} (id int);" for i in range(70)})
    d = client.post("/tools/rls-check", json={"repo": "acme/shop"}).json()
    assert d["files_scanned"] == 60 and d["truncated"] is True and len(d["tables"]) == 60
    monkeypatch.setattr(rls, "MAX_BYTES", 100)
    setup_repo({"001.sql": "create table a (id int);" * 3, "002.sql": "create table b (id int);" * 3}, "acme/big")
    d = client.post("/tools/rls-check", json={"repo": "acme/big"}).json()
    assert d["files_scanned"] == 1 and d["truncated"] is True


def test_endpoint_no_migrations_and_errors(client):
    add_repo("acme/empty")
    d = client.post("/tools/rls-check", json={"repo": "acme/empty"}).json()
    assert d["files_scanned"] == 0 and d["findings"] == [] and "No supabase/migrations" in d["note"]
    assert client.post("/tools/rls-check", json={"repo": "acme/missing"}).status_code == 422
    assert client.post("/tools/rls-check", json={"repo": "not a repo"}).status_code == 422
    assert client.post("/tools/rls-check", json={}).status_code == 422


def test_endpoint_rate_limit_per_ip(client):
    setup_repo({"001.sql": LEAKY})
    h = {"X-Forwarded-For": "5.5.5.5"}
    for _ in range(20):
        assert client.post("/tools/rls-check", json={"repo": "acme/shop"}, headers=h).status_code == 200
    r = client.post("/tools/rls-check", json={"repo": "acme/shop"}, headers=h)
    assert r.status_code == 429
    assert client.post("/tools/rls-check", json={"repo": "acme/shop"}, headers={"X-Forwarded-For": "6.6.6.6"}).status_code == 200
    # failed lookups still count
    for _ in range(20):
        client.post("/tools/rls-check", json={"repo": "acme/missing"}, headers={"X-Forwarded-For": "7.7.7.7"})
    assert client.post("/tools/rls-check", json={"repo": "acme/shop"}, headers={"X-Forwarded-For": "7.7.7.7"}).status_code == 429

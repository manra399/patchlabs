"""The schema must apply cleanly on top of the production database (old tables with data) and be idempotent."""
import os, uuid

import psycopg
import pytest

from helpers import HERE, ROOT

STATUSES = ("awaiting_verification", "queued", "running", "done", "no_leaks", "needs_review", "failed")


@pytest.fixture
def legacy_db():
    base = os.environ["DATABASE_URL"]
    name = "legacy_" + uuid.uuid4().hex[:8]
    with psycopg.connect(base, autocommit=True) as c:
        c.execute(f"CREATE DATABASE {name}")
    url = base.rsplit("/", 1)[0] + "/" + name
    yield url
    with psycopg.connect(base, autocommit=True) as c:
        c.execute(f"DROP DATABASE {name} WITH (FORCE)")


def test_schema_upgrades_legacy_database_without_losing_data(legacy_db):
    old, new = open(os.path.join(HERE, "legacy_schema.sql")).read(), open(os.path.join(ROOT, "db", "schema.sql")).read()
    with psycopg.connect(legacy_db) as c:
        c.execute(old)
        ids = []
        for s in STATUSES:
            i = uuid.uuid4()
            ids.append(i)
            c.execute("INSERT INTO checks (id, email, repo, verify_code, status, summary) VALUES (%s, 'a@b.co', 'o/r', 'code', %s, '{\"x\": 1}')",
                      (i, s))
            c.execute("INSERT INTO check_events (check_id, kind) VALUES (%s, 'requested')", (i,))
        c.execute("INSERT INTO kv (key, value) VALUES ('worker_heartbeat', 'ok')")
    for _ in range(2):  # applied on every start: must be idempotent
        with psycopg.connect(legacy_db) as c:
            c.execute(new)
    with psycopg.connect(legacy_db) as c:
        assert c.execute("SELECT count(*) FROM checks").fetchone()[0] == len(STATUSES)
        assert c.execute("SELECT count(*) FROM check_events").fetchone()[0] == len(STATUSES)
        assert c.execute("SELECT value FROM kv").fetchone()[0] == "ok"
        assert c.execute("SELECT summary FROM checks WHERE id = %s", (ids[0],)).fetchone()[0] == {"x": 1}
        assert c.execute("SELECT count(*) FROM checks WHERE app_id IS NULL AND user_id IS NULL AND trigger IS NULL").fetchone()[0] == len(STATUSES)
        for s in STATUSES:  # every current status is still allowed
            c.execute("INSERT INTO checks (id, email, repo, verify_code, status) VALUES (%s, 'a@b.co', 'o/r', 'c', %s)", (uuid.uuid4(), s))
        tables = {r[0] for r in c.execute("SELECT tablename FROM pg_tables WHERE schemaname = 'public'")}
        assert {"users", "sessions", "login_tokens", "workspaces", "workspace_members", "invites", "apps", "api_keys",
                "upgrade_requests", "checks", "check_events", "kv"} <= tables
        with pytest.raises(psycopg.errors.CheckViolation):
            c.execute("INSERT INTO checks (id, email, repo, verify_code, status) VALUES (%s, 'a@b.co', 'o/r', 'c', 'bogus')", (uuid.uuid4(),))


def test_schema_has_no_destructive_statements():
    s = open(os.path.join(ROOT, "db", "schema.sql")).read().upper()
    for bad in ("DROP TABLE", "DROP COLUMN", "TRUNCATE", "DELETE FROM", "ALTER COLUMN"):
        assert bad not in s


def test_dockerfile_ships_every_api_module():
    import glob, re
    docker = open(os.path.join(ROOT, "api", "Dockerfile")).read()
    shipped = set(re.findall(r"api/(\w+\.py)", docker))
    modules = {os.path.basename(p) for p in glob.glob(os.path.join(ROOT, "api", "*.py"))}
    assert modules <= shipped, modules - shipped

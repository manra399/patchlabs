import os

import pytest

import helpers  # noqa: F401  starts the stub and sets the environment before the app is imported
from fastapi.testclient import TestClient

import app as appmod
import core

TABLES = ("checks, check_events, kv, users, login_tokens, sessions, workspaces, workspace_members, invites, apps, api_keys, "
          "upgrade_requests, decisions, finding_suppressions, check_answers, tool_runs, rls_cache, audit_log, member_app_access")


def pytest_configure(config):
    config.addinivalue_line("filterwarnings", "ignore::DeprecationWarning")


@pytest.fixture(scope="session")
def client():
    with TestClient(appmod.app) as c:
        yield c


@pytest.fixture(autouse=True)
def clean(client):
    helpers.sql(f"TRUNCATE {TABLES} CASCADE")
    if os.path.exists(helpers.OUTBOX):
        os.remove(helpers.OUTBOX)
    helpers.reset_stub()
    yield


@pytest.fixture
def local_webhooks(monkeypatch):
    """Lets webhooks reach the local stub (plain http on 127.0.0.1); production only allows public https."""
    monkeypatch.setattr(core, "WEBHOOK_SCHEMES", ("https", "http"))
    monkeypatch.setattr(core, "ip_allowed", lambda ip: True)
    return f"{helpers.STUB}/hook"

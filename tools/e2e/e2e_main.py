# E2E only: lets webhooks reach the local stub (plain http, private address), exactly like the tests' local_webhooks fixture.
import core
core.WEBHOOK_SCHEMES = ("https", "http")
core.ip_allowed = lambda ip: True
from app import app  # noqa: E402,F401

import base64, json, sys, pathlib

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent.parent))
from src import keys  # noqa: E402


def jwt(role):
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'HS256', 'typ': 'JWT'})}.{enc({'iss': 'supabase', 'ref': 'abcdefghijklmnopqrst', 'role': role})}.c2lnbmF0dXJlc2lnbmF0dXJl"


def test_service_role_flagged_anon_not():
    text = f'createClient("https://abcdefghijklmnopqrst.supabase.co","{jwt("anon")}"); const admin="{jwt("service_role")}"'
    found, facts = keys.scan_text(text, "https://x.test/app.js")
    assert [f["title"] for f in found] == ["Supabase service_role key in code every visitor downloads"]
    assert found[0]["severity"] == "critical" and found[0]["id"] == "PL-010"
    assert facts == {"supabase_projects": ["abcdefghijklmnopqrst"], "supabase_anon_key": True}


def test_values_are_masked():
    key = "sk_live_" + "a1B2c3D4e5" * 3
    found, _ = keys.scan_text(f'stripe("{key}")', "page")
    assert found[0]["evidence"] == {"starts_with": "sk_live_…", "length": len(key)}
    assert key not in json.dumps(found)


def test_other_providers():
    text = " ".join(["sk-proj-" + "x" * 40, "sk-ant-" + "y" * 30, "AKIA" + "ABCDEFGHIJKLMNOP", "ghp_" + "z" * 36,
                     "SG." + "a" * 20 + "." + "b" * 20, "sb_secret_" + "c" * 20, "-----BEGIN PRIVATE KEY-----"])
    names = {f["title"].split(" in code")[0] for f in keys.scan_text(text, "p")[0]}
    assert names == {"OpenAI API key", "Anthropic API key", "AWS access key", "GitHub token", "SendGrid API key",
                     "Supabase secret key", "private key"}


def test_publishable_keys_are_not_secrets():
    text = 'pk_live_' + 'a' * 24 + ' sb_publishable_' + 'b' * 20 + ' AIzaSy' + 'c' * 33
    assert keys.scan_text(text, "p")[0] == []


def test_script_urls_same_site_only():
    body = ('<script src="/assets/index-abc.js"></script><script src="https://cdn.other.com/x.js"></script>'
            '<script type=module src=https://static.myapp.com/a.js></script><link rel="modulepreload" href="/assets/v.js">'
            '<script src="/assets/index-abc.js"></script>')
    assert keys.script_urls("https://www.myapp.com/", body) == [
        "https://www.myapp.com/assets/index-abc.js", "https://static.myapp.com/a.js", "https://www.myapp.com/assets/v.js"]


def test_dedupe_across_chunks(monkeypatch):
    key = "sk-ant-" + "q" * 30
    monkeypatch.setattr(keys, "fetch", lambda u: {"status": 200, "body": f'k="{key}"'})
    out = keys.scan("https://a.myapp.com/", '<script src="/1.js"></script><script src="/2.js"></script>')
    assert len(out["findings"]) == 1 and out["scripts_read"] == ["https://a.myapp.com/1.js", "https://a.myapp.com/2.js"]
    assert out["supabase"]["note"] is None


def test_anthropic_key_not_double_counted_as_openai():
    found, _ = keys.scan_text("sk-ant-api03-" + "w" * 40, "p")
    assert [f["title"].split(" in code")[0] for f in found] == ["Anthropic API key"]

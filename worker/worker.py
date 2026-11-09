#!/usr/bin/env python3
"""PatchLabs worker: takes verified checks from the API, runs the leak-check pipeline on each, and posts
the report back. It runs on the machine that has the lab (Docker) and the fix agent (Claude Code).

    python3 worker.py            # loop forever (launchd keeps it alive)
    python3 worker.py --once     # handle at most one check, then exit

Config comes from ~/.patchlabs/worker.env (KEY=value lines): API_URL, WORKER_TOKEN, PIPELINE (path to run.py).
Only one check runs at a time. The pipeline is always run in dry-run mode: nothing is pushed to anyone's repo.
"""
import json, os, re, subprocess, sys, time, urllib.request

ENV_FILE = os.environ.get("PATCHLABS_ENV", os.path.expanduser("~/.patchlabs/worker.env"))
POLL_SECONDS = 30


def load_env():
    env = {}
    for line in open(ENV_FILE):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            env[k.strip()] = v.strip()
    return env


CFG = load_env()
API, TOKEN, PIPELINE = CFG["API_URL"].rstrip("/"), CFG["WORKER_TOKEN"], CFG["PIPELINE"]


def log(msg):
    print(f"[{time.strftime('%Y-%m-%d %H:%M:%S')}] {msg}", flush=True)


def call(path, body=None):
    req = urllib.request.Request(API + path, method="POST", data=json.dumps(body or {}).encode(),
                                 headers={"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return json.loads(r.read())


def read(path):
    return open(path).read() if os.path.exists(path) else None


def run_check(check):
    repo = check["repo"]
    log(f"checking {repo} ({check['id']})")
    p = subprocess.run([sys.executable, PIPELINE, f"https://github.com/{repo}"], capture_output=True, text=True, timeout=3 * 3600)
    m = re.search(r"done: (\S+)/report\.md", p.stdout)
    if not m:
        return {"status": "failed", "error": (p.stderr or p.stdout)[-2000:]}
    out = m.group(1)
    findings = json.load(open(os.path.join(out, "findings.json")))
    lab = findings["lab"]
    leaking = [t["table"] for t in lab["anyone"] + lab["any_signed_in"]]
    result = json.load(open(os.path.join(out, "result.json"))) if os.path.exists(os.path.join(out, "result.json")) else {}
    proof, agent, decision = result.get("proof", {}), result.get("agent", {}), result.get("decision", {})
    if not leaking:
        status = "no_leaks"
    elif proof.get("passed"):
        status = "done"
    else:
        status = "needs_review"  # the fix didn't pass the lab proof on any model: a person looks before the owner does
    summary = {"tables_leaking": leaking, "readable_by_anyone": [t["table"] for t in lab["anyone"]],
               "readable_by_signed_in": [t["table"] for t in lab["any_signed_in"]], "lab_proof_passed": bool(proof.get("passed")),
               "models": agent.get("attempts"), "break_risk": decision.get("break_risk"),
               "questions_for_owner": decision.get("questions_for_owner") or [], "run_dir": out}
    return {"status": status, "summary": summary, "report_md": read(os.path.join(out, "report.md")),
            "fix_sql": read(os.path.join(out, "fix.sql")) if status != "no_leaks" else None,
            "cost_usd": agent.get("total_cost_usd")}


def once():
    check = call("/worker/claim")["check"]
    if not check:
        return False
    try:
        res = run_check(check)
    except Exception as e:  # report the failure instead of leaving the check stuck in 'running'
        res = {"status": "failed", "error": repr(e)[:2000]}
    call(f"/worker/checks/{check['id']}/result", res)
    log(f"{check['repo']}: {res['status']} cost={res.get('cost_usd')}")
    return True


def main():
    if "--once" in sys.argv:
        once()
        return
    log(f"worker started, polling {API}")
    while True:
        try:
            if not once():
                time.sleep(POLL_SECONDS)
        except Exception as e:
            log(f"error: {e!r}")
            time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    main()

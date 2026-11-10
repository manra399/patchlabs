# PatchLabs leak check (GitHub Action)

Re-checks a [PatchLabs](https://patchlabs.dev) monitored app from CI: it starts a check, waits for the lab result, prints
it in the log and the job summary, and fails the step when personal data is readable by the wrong people.

PatchLabs rebuilds your app's database from `supabase/migrations` in a disposable lab, tests what an anonymous visitor,
a signed-in stranger and the owner can read, and proves a fix before you ship it. Full docs:
<https://patchlabs.dev/docs/github-action>.

## Before you start

1. Sign in at <https://patchlabs.dev/app/login>, add the repo as an app and verify it (one committed file).
2. Create an API key in **Settings → API keys**. It is shown once.
3. In your repo's **Settings → Secrets and variables → Actions**, add the key as the secret `PATCHLABS_API_KEY`
   and the app's ID (from its page in the dashboard) as the variable `PATCHLABS_APP_ID`.

## Usage

```yaml
name: PatchLabs
on:
  push:
    branches: [main]
    paths: ['supabase/migrations/**']
  workflow_dispatch:

concurrency: patchlabs

jobs:
  leak-check:
    runs-on: ubuntu-latest
    steps:
      - uses: manra399/patchlabs/action@main
        with:
          api-key: ${{ secrets.PATCHLABS_API_KEY }}
          app-id: ${{ vars.PATCHLABS_APP_ID }}
          wait: true
          fail-on-leak: true
```

No checkout step is needed: PatchLabs reads the repo from GitHub. For a fixed version, pin a commit SHA instead of
`@main`.

## Inputs

| Input | Default | What it does |
|---|---|---|
| `api-key` | required | Workspace API key (`pl_live_…`). Pass it from a secret. |
| `app-id` | required | The monitored app's ID. |
| `wait` | `true` | Wait for the result. `false` starts the check and finishes the step straight away. |
| `fail-on-leak` | `true` | Fail the step when the finished check (`done` or `needs_review`) has leaking tables your team hasn't marked as intended. |
| `timeout-minutes` | `30` | How long to wait for a result. |
| `fail-on-timeout` | `false` | Fail instead of warn when no result arrives in time. |
| `poll-seconds` | `15` | Seconds between status requests (minimum 5). |
| `api-url` | `https://api.patchlabs.dev` | API base URL. |

## Outputs

| Output | Value |
|---|---|
| `check-id` | The check this run started. |
| `status` | `done`, `no_leaks`, `needs_review`, `failed`; `queued`/`running` if not waited for or timed out; `busy` or `limit` if no check could start. |
| `url` | Link to the report. |
| `leaks-found` | `true` or `false`. |
| `tables-leaking` | Comma-separated table names. |
| `suppressed-tables` | Leaking tables your team marked as intended (not counted by `fail-on-leak`). |
| `lab-proof-passed` | `true` when the fix passed the lab proof. |

## Behaviour

| Situation | Step result |
|---|---|
| `no_leaks` | passes |
| `done` or `needs_review` | fails when `fail-on-leak` is true, otherwise warns |
| Only tables marked as intended are leaking | passes with a notice |
| `failed` (the check couldn't finish) | warns; PatchLabs is alerted and follows up |
| A check is already running for the app (409) | warns and passes; no new check |
| Monthly run limit reached (429) | warns and passes |
| App not verified, bad key, wrong app ID | fails with the reason |
| No result before `timeout-minutes` | warns, or fails with `fail-on-timeout` |

## Good to know

- A check reads the repo's **default branch** as it is on GitHub, not the branch of a pull request, so run this
  after changes land on your default branch.
- Each run uses one of your plan's monthly manual runs (Free 4, Maker 30, Agency 200). Scheduled re-checks don't.
- Tables your team [marked as intended](https://patchlabs.dev/docs/decisions#suppressions) don't count for `fail-on-leak`:
  the step fails only while other leaking tables remain.
- Needs `curl` and `jq`, both preinstalled on GitHub-hosted Linux and macOS runners.

Questions: manraj@patchlabs.dev. Independent: not affiliated with Lovable, Supabase, Bolt, Replit or Cursor.

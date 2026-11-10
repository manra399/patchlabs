#!/usr/bin/env bash
# PatchLabs GitHub Action: starts a check on a monitored app (POST /v1/apps/{app_id}/checks), optionally waits for it
# (GET /v1/checks/{id}), prints the result and fails the step on leaks. Needs curl and jq (both preinstalled on
# GitHub-hosted Linux and macOS runners). Configured through the PL_* environment variables set in action.yml.
set -uo pipefail

api="${PL_API_URL:-https://api.patchlabs.dev}"; api="${api%/}"
out="${GITHUB_OUTPUT:-/dev/null}"
summary="${GITHUB_STEP_SUMMARY:-/dev/null}"

err()  { echo "::error title=PatchLabs::$*"; }
warn() { echo "::warning title=PatchLabs::$*"; }
note() { echo "::notice title=PatchLabs::$*"; }
setout() { printf '%s=%s\n' "$1" "$2" >> "$out"; }
truthy() { case "$(printf '%s' "${1:-}" | tr '[:upper:]' '[:lower:]')" in true|yes|1|on) return 0 ;; *) return 1 ;; esac; }
num() { case "${1:-}" in ''|*[!0-9]*) echo "$2" ;; *) echo "$1" ;; esac; }

command -v curl >/dev/null || { err "This action needs curl on the runner."; exit 1; }
command -v jq >/dev/null || { err "This action needs jq on the runner (it is preinstalled on GitHub-hosted runners)."; exit 1; }
[ -n "${PL_API_KEY:-}" ] || { err "api-key is empty. Add your workspace API key as a secret and pass it: api-key: \${{ secrets.PATCHLABS_API_KEY }}"; exit 1; }
[ -n "${PL_APP_ID:-}" ] || { err "app-id is empty. Copy the app's ID from its page in the PatchLabs dashboard."; exit 1; }
echo "::add-mask::$PL_API_KEY"
case "$PL_API_KEY" in pl_live_*) ;; *) err "api-key doesn't look like a PatchLabs key (they start with pl_live_)."; exit 1 ;; esac

timeout_min=$(num "${PL_TIMEOUT_MINUTES:-}" 30)
poll=$(num "${PL_POLL_SECONDS:-}" 15); [ "$poll" -lt 5 ] && poll=5

CODE=""; BODY=""
call() {  # call METHOD PATH  -> sets CODE (000 on network failure) and BODY
  local resp
  if ! resp=$(curl -sS -X "$1" "$api$2" -H "X-API-Key: $PL_API_KEY" -H "Accept: application/json" \
              -H "User-Agent: patchlabs-github-action/1" --max-time 30 -w $'\n%{http_code}' 2>&1); then
    CODE="000"; BODY="${resp%$'\n'*}"; return 0
  fi
  CODE="${resp##*$'\n'}"; BODY="${resp%$'\n'*}"
}
detail() { printf '%s' "$BODY" | jq -r 'if (.detail | type) == "string" then .detail else (.detail | tostring) end' 2>/dev/null || printf '%s' "$BODY"; }
field() { printf '%s' "$BODY" | jq -r "$1" 2>/dev/null; }

# ---- start the check ---------------------------------------------------------------------------------------------
call POST "/v1/apps/$PL_APP_ID/checks"
case "$CODE" in
  201) ;;
  409)
    msg=$(detail)
    case "$msg" in
      *[Vv]erify*) err "$msg Verify the app in the PatchLabs dashboard first."; exit 1 ;;
      *) warn "$msg No new check was started; the running one will report by email and webhook."; setout status busy; exit 0 ;;
    esac ;;
  429) warn "$(detail)"; setout status limit; exit 0 ;;
  000) err "Couldn't reach PatchLabs at $api: $BODY"; exit 1 ;;
  *) err "Couldn't start a check (HTTP $CODE): $(detail)"; exit 1 ;;
esac

check_id=$(field '.check_id'); url=$(field '.url')
setout check-id "$check_id"; setout url "$url"
echo "PatchLabs check started: $check_id"
echo "Report: $url"

if ! truthy "${PL_WAIT:-true}"; then
  setout status queued
  printf '### PatchLabs\n\nCheck started: [%s](%s). Not waiting for the result (`wait: false`).\n' "$check_id" "$url" >> "$summary"
  exit 0
fi

# ---- wait for it -------------------------------------------------------------------------------------------------
deadline=$(( $(date +%s) + timeout_min * 60 ))
errors=0; last=""
while :; do
  call GET "/v1/checks/$check_id"
  if [ "$CODE" = "200" ]; then
    errors=0
    status=$(field '.status')
    [ "$(field '.finished')" = "true" ] && break
    if [ "$status" != "$last" ]; then echo "Status: $status"; last="$status"; fi
  elif [ "$CODE" = "000" ] || [ "$CODE" -ge 500 ] 2>/dev/null; then
    errors=$((errors + 1))
    warn "PatchLabs didn't answer (attempt $errors of 5): ${BODY:0:200}"
    if [ "$errors" -ge 5 ]; then err "Gave up after 5 failed status requests. The check carries on: $url"; exit 1; fi
  else
    err "Couldn't read the check (HTTP $CODE): $(detail)"; exit 1
  fi
  if [ "$(date +%s)" -ge "$deadline" ]; then
    setout status "${last:-queued}"
    msg="No result after $timeout_min minutes (status: ${last:-unknown}). The check carries on and will report by email: $url"
    printf '### PatchLabs\n\n%s\n' "$msg" >> "$summary"
    if truthy "${PL_FAIL_ON_TIMEOUT:-false}"; then err "$msg"; exit 1; fi
    warn "$msg"; exit 0
  fi
  sleep "$poll"
done

# ---- report ------------------------------------------------------------------------------------------------------
repo=$(field '.repo')
leaks=$(field '.leaks_found')
proof=$(field '.lab_proof_passed')
tables=$(field '(.tables_leaking // []) | join(", ")')
suppressed=$(field '(.suppressed_tables // []) | join(", ")')           # tables the team marked as intended
open_tables=$(field '((.tables_leaking // []) - (.suppressed_tables // [])) | join(", ")')
setout status "$status"; setout leaks-found "$leaks"; setout tables-leaking "$tables"; setout lab-proof-passed "$proof"
setout suppressed-tables "$suppressed"

case "$status" in
  no_leaks)     headline="No data leaks found" ;;
  done)         headline="Leaks found; a lab-proven fix is ready" ;;
  needs_review) headline="Leaks found; a person is reviewing the fix" ;;
  failed)       headline="The check couldn't finish; PatchLabs has been alerted" ;;
  *)            headline="Finished with status $status" ;;
esac

echo ""
echo "PatchLabs · $repo"
echo "  result          $headline"
echo "  tables leaking  ${tables:-none}"
[ -n "$suppressed" ] && echo "  marked intended $suppressed (not counted by fail-on-leak)"
[ "$status" = "done" ] || [ "$status" = "needs_review" ] && echo "  lab proof       $([ "$proof" = "true" ] && echo passed || echo 'not passed (in review)')"
echo "  report          $url"
echo ""

{
  printf '### PatchLabs: %s\n\n' "$headline"
  printf '| | |\n|---|---|\n'
  printf '| Repo | `%s` |\n| Status | `%s` |\n| Tables leaking | %s |\n' "$repo" "$status" "${tables:-none}"
  [ -n "$suppressed" ] && printf '| Marked as intended | %s |\n' "$suppressed"
  if [ "$status" = "done" ] || [ "$status" = "needs_review" ]; then
    printf '| Lab proof | %s |\n' "$([ "$proof" = "true" ] && echo 'passed: anonymous visitor denied, stranger denied, owner OK' || echo 'not passed: a person is reviewing')"
  fi
  printf '| Report | [Open the report](%s) |\n' "$url"
} >> "$summary"

case "$status" in
  no_leaks) note "No data leaks found in $repo." ;;
  failed) warn "The check couldn't finish; PatchLabs has been alerted and will follow up. $url" ;;
  done|needs_review)
    if [ -z "$open_tables" ] && [ -n "$suppressed" ]; then
      note "Only tables your team marked as intended are readable in $repo ($suppressed). Not failing. $url"
    elif truthy "${PL_FAIL_ON_LEAK:-true}"; then
      err "$headline in $repo: ${open_tables:-see report}. Apply the fix, then re-run. $url"; exit 1
    else
      warn "$headline in $repo: ${open_tables:-see report}. $url"
    fi ;;
esac
exit 0

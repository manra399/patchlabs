# Live posture: passive checks of a verified live domain

Written 10 Nov 2026 (board task 49, Manraj chose option B). Memo: `co-founder/ops/patchlabs/live-checks-options.md`.

## What it is, and the line it never crosses

For a domain the app's team proves they control, PatchLabs loads the home page the way any visitor's browser does and
reads what comes back: HTTPS redirect, the TLS certificate, security headers, cookie flags, and whether the page pulls
scripts over plain HTTP. Per check that is one plain `http://` request (to see if it redirects), one `https://` page load
(following at most 5 redirects) and the TLS handshake of that load. Nothing else: no other paths, no forms, no API calls,
no database, no guessing URLs, no attack payloads. It is the same as Mozilla Observatory or securityheaders.com.

Site wording: "PatchLabs never touches your database. Live posture only loads your public home page, like any visitor,
and only on domains you verify." Never say or imply we test the running app for data leaks.

## Finding IDs (line `live`)

| ID | Title | Severity |
|---|---|---|
| PL-027 | Site doesn't force HTTPS | medium |
| PL-028 | TLS certificate is invalid, expired or expires within 21 days | high (invalid or expired), medium (expiring) |
| PL-029 | No HSTS header, or max-age under 180 days | low |
| PL-030 | No Content-Security-Policy | medium |
| PL-031 | Any site can frame the page (no frame-ancestors or X-Frame-Options) | low |
| PL-032 | No X-Content-Type-Options: nosniff | low |
| PL-033 | Cookie set without Secure, or a session cookie without HttpOnly (no SameSite is fine: browsers default to Lax) | medium |
| PL-034 | Page loads scripts or styles over plain HTTP | medium |
| PL-035 | Server headers reveal software versions | info |
| PL-036 | No Referrer-Policy | info |

Grade: score = 100 − 30 per failed high check − 15 per medium − 5 per low (info is free; a check that fails on several
cookies costs its points once), floor 0. A ≥ 90, B ≥ 75, C ≥ 60, D ≥ 40,
else F. An invalid or expired certificate is always F.

## Verifying the domain

Each app gets its own live code (`patchlabs-live-<16 hex>`), separate from the repo code. Either works:
- a file at `https://<domain>/patchlabs-verify.txt` whose whole content is the code, or
- `<meta name="patchlabs-verify" content="<code>">` in the home page's HTML.

## API

`GET /apps/{aid}` gains `live`:
```json
{"url": "https://app.example.com", "verified": false, "verified_at": null, "next_check_at": null,
 "verify": {"file": "patchlabs-verify.txt", "file_url": "https://app.example.com/patchlabs-verify.txt",
            "code": "patchlabs-live-…", "meta": "<meta name=\"patchlabs-verify\" content=\"patchlabs-live-…\">"},
 "last": null}
```
`url` is null when no domain is set (then `verify` and `last` are null). `verify` is present only while unverified.
`last` is the newest posture result (shape below). `GET /workspaces/{wid}/apps` carries the same `live` per app, with
`last` cut down to `{grade, score, checked_at, counts}`.

| Call | Who | What |
|---|---|---|
| `PUT /apps/{aid}/live` `{"url"}` | manage | Set or change the domain (https only, a host name, not an IP). New code, unverified. 422 with a sentence for a bad URL |
| `DELETE /apps/{aid}/live` | manage | Remove the domain and its history |
| `POST /apps/{aid}/live/verify` | manage | Looks for the file or meta tag. 409 with a sentence if missing. On success runs the first check: `{"verified": true, "posture": {...}}` |
| `POST /apps/{aid}/live/checks` | run | Re-check now. 409 if unverified, 429 within 10 minutes of the last one. Returns the posture result |
| `GET /apps/{aid}/live/checks` | view | `{"checks": [{id, grade, score, counts, trigger, checked_at}]}`, newest first, 30 max |
| `GET /badge/{aid}/live.svg` | public | "live posture · B" badge; "private" unless the badge is public and the domain verified |
| `GET /public/apps/{aid}` | public | gains `"live": {"grade", "checked_at"}` or null |
| `POST /tools/headers-check` `{"url"}` | public | Free, no sign-up, any public https or http URL. 10 an hour per IP (429). 422 bad or private URL, 502 when the page can't be loaded. Returns the posture result, nothing stored |

Re-checks: every day while the app's schedule isn't `off`. An email and the workspace webhook (`event:
"posture.changed"`) go out when the grade drops or a finding appears; the Slack/Discord/Teams formats get a short text.

Posture result:
```json
{"id": "uuid (absent from the free tool)", "url": "https://app.example.com", "final_url": "https://app.example.com/",
 "grade": "C", "score": 65, "checked_at": "…", "trigger": "verify|scheduled|manual",
 "counts": {"critical": 0, "high": 0, "medium": 2, "low": 1, "info": 0},
 "findings": [{"id": "PL-030", "line": "live", "severity": "medium", "title": "No Content-Security-Policy",
               "object": "https://app.example.com/", "evidence": "The page sends no Content-Security-Policy header.",
               "fix": "one line", "cwe": ["CWE-693"], "owasp": "A05:2021", "owasp_name": "Security Misconfiguration"}],
 "passed": [{"id": "PL-027", "title": "HTTPS is forced"}],
 "facts": {"status": 200, "redirects": ["https://app.example.com/"], "https_redirect": true,
           "tls": {"version": "TLSv1.3", "issuer": "Let's Encrypt", "expires": "2027-01-05", "days_left": 56},
           "headers": {"strict-transport-security": "max-age=63072000", "content-security-policy": null, …},
           "cookies": [{"name": "sb-session", "secure": true, "httponly": true, "samesite": "Lax"}],
           "server": "cloudflare"}}
```

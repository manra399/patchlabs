# AI-Built App Security Check

Check any website for the security mistakes AI app builders make most often: missing HTTPS and security headers,
weak cookies, and **secret keys shipped in the JavaScript every visitor downloads** (Supabase `service_role`, Stripe,
OpenAI, Anthropic, AWS, GitHub, SendGrid, Resend, Twilio, private keys).

Made by [PatchLabs](https://patchlabs.dev) for apps built with **Lovable, Bolt, Replit, Cursor, v0 and Supabase**. It
runs the same checks as the free PatchLabs [headers check](https://patchlabs.dev/tools/headers-check), across as many
sites as you like, with the output as a dataset you can export or call from an API or MCP client.

## What it checks

| Check | What fails | Severity |
|---|---|---|
| Leaked secret keys | A secret key appears in the home page or any same-site script (values are masked in the output) | critical / high |
| HTTPS | `http://` doesn't redirect to `https://` | medium |
| Certificate | Invalid, expired, or expiring within 21 days | high / medium |
| HSTS | No `Strict-Transport-Security`, or max-age under 180 days | low |
| Content-Security-Policy | None set | medium |
| Framing | No `frame-ancestors` or `X-Frame-Options` | low |
| `X-Content-Type-Options` | Missing or not `nosniff` | low |
| Cookies | Missing `Secure`, or a session cookie without `HttpOnly` | medium |
| Mixed content | Scripts or styles over plain HTTP | medium |
| Version leaks | `Server` or `X-Powered-By` reveal software versions | info |
| Referrer-Policy | None set | info |

Each site gets a grade from A to F. Any critical leaked key makes the grade F. The anon (public) Supabase key is
**not** reported as a leak, because it is meant to be public; the output notes when a site talks to Supabase from the
browser, since whether its data leaks then depends on RLS policies a page load can't see.

## Input

```json
{
  "startUrls": [{ "url": "https://myapp.lovable.app" }, { "url": "https://client-site.com" }],
  "maxConcurrency": 5
}
```

Only check sites you own or have permission to test.

## Output

One dataset item per site:

```json
{
  "url": "https://myapp.lovable.app",
  "grade": "F",
  "headers_grade": "C",
  "headers_score": 65,
  "secrets_found": 1,
  "secrets": [{
    "id": "PL-010",
    "severity": "critical",
    "title": "Supabase service_role key in code every visitor downloads",
    "object": "https://myapp.lovable.app/assets/index-4f2a.js",
    "evidence": { "starts_with": "eyJhbGci…", "length": 219 },
    "fix": "This key skips every RLS policy. Rotate it in Supabase (Settings > API) now and move the code that needs it to a server or edge function."
  }],
  "findings": [{ "id": "PL-030", "severity": "medium", "title": "No Content-Security-Policy", "fix": "..." }],
  "passed": [{ "id": "PL-027", "title": "HTTPS is forced" }],
  "supabase": { "projects": ["abcdefghijklmnopqrst"], "anon_key_in_page": true, "note": "..." },
  "scripts_read": 6,
  "checked_at": "2026-11-19T23:00:00+00:00"
}
```

Secret values are never stored: only the type, the file, the first characters and the length.

## What it does not do

It is passive. Per site it makes one plain `http://` request, one `https://` load of the home page and fetches the
same-site scripts that page loads (up to 20). It does not submit forms, sign in, crawl other pages, or try any key it
finds. It refuses private and local addresses.

## Use cases

- **Agencies and freelancers**: check every client site you've shipped in one run, and show the client the report.
- **Before launch**: run it on your Lovable or Bolt app before you share the link.
- **Monitoring**: schedule it daily on your sites and get alerted when a deploy drops a header or ships a key.
- **From AI agents**: call it over Apify's API or MCP server from Claude, Cursor or any MCP client.

## Found something?

The [PatchLabs guides](https://patchlabs.dev/learn) explain each finding and how to fix it on Lovable, Supabase
and Bolt. To check what the page can't show, such as Row Level Security, storage buckets and
functions, run the free [RLS check](https://patchlabs.dev/check) on your app's repository.

Source: [github.com/manra399/patchlabs](https://github.com/manra399/patchlabs/tree/main/actor)

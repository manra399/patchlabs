# Leak check: manra399/patchlabs-demo-app

_PatchLabs, 09 Nov 2026. Code-only check: no live system or customer data was accessed._

## What we found
- 1 table(s) holding personal data readable by the wrong people.
- No exposed AI or API keys found (code and full git history).

## Proof (our lab rebuilt your database from its migrations, seeded test rows, applied the fix)
| Table | Who could read it | Verdict | Before | After | Result |
|---|---|---|---|---|---|
| `profiles` | anyone on the internet | bug | anon 2, stranger 2 | anon 0, stranger 0, owner 1 | closed |

## The fix
Replace 'Profiles are viewable by everyone' policy with owner-only SELECT, so users can only read their own profile

Risk that something on the site behaves differently: **low**. Only breaks anonymous/other-user access which the frontend never relied on; users still read their own profiles as before

---
Every change here was written and tested by PatchLabs agents. Nothing reaches your live app until your engineer merges this.
_Run: 36s, models tried: haiku (passed)._

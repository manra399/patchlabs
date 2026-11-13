"""Copy-paste prompts for AI app builders (Lovable, Bolt, Replit, Cursor), one per finding.

Each prompt asks the builder to fix one finding, show the change first, and leave everything else alone.
The finding page adds the "retest" line that points at the matching free check.
"""

TAIL = " Show me the exact change before you apply it, and don't change anything else."

PROMPTS = {
    "PL-001": "Some tables in my Supabase database can be read by anyone with the public anon key, including personal data such as emails, phone numbers or addresses. For each table that holds personal data, make sure row level security is enabled and replace any policy that allows the anon role to select with one that only lets a signed-in user read their own rows (auth.uid() = user_id). Write it as a new migration.",
    "PL-002": "In my Supabase database, any signed-in user can read every row of some tables, not just their own. Find the select policies that only check that the user is authenticated (for example using (true) for the authenticated role, or auth.role() = 'authenticated') and change them so each user only sees rows they own (auth.uid() = user_id), or rows their team owns. Write it as a new migration.",
    "PL-003": "Some tables in my Supabase database have row level security enabled but no policies, so even the owner gets empty results. Do not disable row level security and do not add a policy that allows everyone. Add policies so a signed-in user can select, insert, update and delete only their own rows (auth.uid() = user_id). Write it as a new migration.",
    "PL-004": "My Supabase UPDATE policies have a USING clause but no WITH CHECK, so a user can edit their own row and change columns like role, plan or user_id. Add WITH CHECK (auth.uid() = user_id) to each update policy, and stop users from changing role, plan or ownership columns, either with a column-level grant or a trigger that rejects changes to them. Write it as a new migration.",
    "PL-005": "Some of my Supabase policies use true as the condition (using (true) or with check (true)), so they allow everyone. Replace each always-true policy with a real condition: owners only (auth.uid() = user_id) for private data, and keep read-only access for anon only on tables that are meant to be public. Write it as a new migration.",
    "PL-006": "My Supabase database has SECURITY DEFINER functions that anyone can call through the API. For each one, either change it to SECURITY INVOKER, or keep SECURITY DEFINER but set search_path = '' and revoke execute from public and anon so only the roles that need it can call it. If a function should only run on the server, move it out of the public schema. Write it as a new migration.",
    "PL-007": "Some of my Supabase storage buckets are public, so anyone with a file's link can download it. Make buckets that hold private files (IDs, invoices, user uploads) private, add storage policies so users can only read and write files under their own folder (for example a path starting with their user id), and switch the app to signed URLs for downloads.",
    "PL-008": "Some tables in my Supabase database don't have row level security enabled at all. Enable row level security on every table in the public schema, then add policies so each signed-in user can only read and change their own rows (auth.uid() = user_id). Keep anon read access only on tables that are meant to be public. Write it as a new migration.",
    "PL-009": "There is a secret API key (AI, payment or database) in my code. Move it out of the code into a server-side environment variable or a Supabase secret, call the service from a server function or edge function instead of the browser, and make sure .env is in .gitignore. Tell me which key it is so I can revoke it and create a new one, because the old one must be treated as leaked.",
    "PL-010": "My Supabase service_role key is in code that runs in the browser (it may be in a VITE_ or NEXT_PUBLIC_ variable). Remove it from all client code and use only the anon key in the browser. Move anything that needs the service role into an edge function or server route that checks who is calling. Tell me where it was so I can roll the key in the Supabase dashboard, because the old one must be treated as leaked.",
    "PL-011": "A secret key was committed to my git history, even though it is no longer in the current code. Deleting the file is not enough, so first tell me which key and service it is so I can revoke it and create a new one. Then add the file to .gitignore and move the new key into an environment variable or secret. Do not rewrite git history without asking me.",
    "PL-012": "Some of my Supabase write policies only check that a user is signed in, not that the row belongs to them, so anyone who signs up can edit or delete other people's rows. Change each insert, update and delete policy to check ownership (auth.uid() = user_id) in both USING and WITH CHECK. Write it as a new migration.",
    "PL-013": "My app stores user roles in a column or table that users can write to, so a user could make themselves an admin. Move roles to a table users cannot write to (no insert or update policy for normal users), read the role on the server or in policies from that table only, and make sure only an existing admin or a server function can change roles. Write it as a new migration.",
    "PL-014": "I have views in the public schema that run with the owner's permissions, so they return every row even though the underlying tables have row level security. Recreate each view with security_invoker = true so the caller's policies apply, or move views that shouldn't be in the API out of the public schema. Write it as a new migration.",
    "PL-015": "My Supabase storage bucket is private, but its storage policies let users read, upload, replace or delete other people's files. Rewrite the storage.objects policies so each user can only access files under a folder named with their own user id (for example (storage.foldername(name))[1] = auth.uid()::text). Write it as a new migration.",
    "PL-016": "A table published to Supabase Realtime has a read policy that is too broad, so new rows stream to people who shouldn't see them. Tighten the table's select policy so users only receive their own rows (auth.uid() = user_id), or remove the table from the realtime publication if the app doesn't need live updates for it. Write it as a new migration.",
    "PL-017": "One of my edge functions uses the Supabase service_role key and doesn't check who is calling it. Make it require a signed-in user: read the Authorization header, verify the user with supabase.auth.getUser(), reject the request if there is no valid user, and only act on that user's own data. Keep verify_jwt on for this function.",
    "PL-018": "My app lets people create working accounts without confirming their email, so anyone can sign up with an address they don't own. Turn on email confirmation for sign-ups in the auth settings, and make sure the app doesn't give unconfirmed users access to anything that assumes their email is real.",
    "PL-019": "My app decides access (admin, plan or role) from user_metadata, which users can change themselves with supabase.auth.updateUser(). Stop using user_metadata for any access decision. Store roles in app_metadata (set only from the server) or in a roles table users can't write to, and update every policy and check that reads user_metadata.",
    "PL-020": "My admin page is only protected in the browser, so a normal user can still ask the database for the same data. Add the admin check on the server side: row level security policies or a server function that checks the user's role from a table users can't write to. Hiding the page in the UI can stay, but it must not be the only check.",
    "PL-021": "My payment webhook doesn't verify the provider's signature, so anyone can send a fake payment succeeded event. Verify every webhook with the provider's signing secret (for Stripe, stripe.webhooks.constructEvent with the raw request body and the Stripe-Signature header), reject events that fail, and keep the signing secret in a server-side secret, not in the code.",
    "PL-022": "One of my edge functions acts on a user id taken from the request body or query, so any user can act as another. Get the user from the verified auth token instead (supabase.auth.getUser() with the request's Authorization header), and ignore any user id the client sends.",
    "PL-023": "A package in my lockfile has a published security advisory. Upgrade it to the first version that fixes the advisory, update the lockfile, and tell me if the upgrade has breaking changes I need to check. If no fixed version exists, tell me the options.",
    "PL-024": "My app renders text that users wrote as raw HTML (for example with dangerouslySetInnerHTML, v-html or innerHTML), so it can run scripts in other users' browsers. Render user text as plain text instead. If formatting is needed, sanitise it with DOMPurify before rendering.",
    "PL-025": "My Firebase security rules allow everyone, or allow everyone until a test-mode date. Rewrite the Firestore, Realtime Database and Storage rules so only signed-in users can read and write their own data (request.auth != null and request.auth.uid matching the document's owner), and remove any rule that allows read or write if true or until a date.",
    "PL-026": "One of my endpoints sends Access-Control-Allow-Origin based on whatever origin asks, together with Access-Control-Allow-Credentials: true, so any website can call it as the signed-in user. Replace it with a fixed list of my own domains, and only send the credentials header for those origins.",
    "PL-027": "My site's plain http:// address serves the page instead of redirecting to https://. Add a permanent (301) redirect from http to https for every path, using my host's settings (for example Vercel, Netlify or Cloudflare).",
    "PL-028": "My site's HTTPS certificate is invalid, expired or about to expire. Check that the custom domain is set up correctly with my host so it can issue and renew the certificate automatically, and tell me what is wrong (expired, wrong name, missing chain) and how to fix it.",
    "PL-029": "My site doesn't send a Strict-Transport-Security header, or sends one with a short max-age. Add Strict-Transport-Security: max-age=31536000; includeSubDomains to every response, using my host's headers config (for example vercel.json, netlify.toml or _headers).",
    "PL-030": "My site sends no Content-Security-Policy header. Add one that only allows scripts, styles, fonts, images and API calls from the domains my app actually uses, plus object-src 'none' and base-uri 'self'. List the domains you found first, and start with Content-Security-Policy-Report-Only if you're not sure nothing will break.",
    "PL-031": "Any site can load my app inside a frame. Add Content-Security-Policy: frame-ancestors 'self' (and X-Frame-Options: DENY or SAMEORIGIN for older browsers) to every response, using my host's headers config.",
    "PL-032": "My site doesn't send X-Content-Type-Options: nosniff. Add it to every response, using my host's headers config (for example vercel.json, netlify.toml or _headers).",
    "PL-033": "My home page sets a cookie without the Secure flag, or a session cookie without HttpOnly. Set Secure on every cookie, HttpOnly on session and auth cookies, and SameSite=Lax unless a cookie has to work across sites.",
    "PL-034": "My HTTPS page loads a script or stylesheet from an http:// address. Change each one to https://, or host the file myself. If a provider has no https version, replace it.",
    "PL-035": "My server sends Server or X-Powered-By headers that name the software and its version. Remove X-Powered-By and strip version numbers from the Server header, using my framework or host settings (for Express, app.disable('x-powered-by')).",
    "PL-036": "My site sends no Referrer-Policy header. Add Referrer-Policy: strict-origin-when-cross-origin to every response, using my host's headers config.",
}

# The free check that can confirm the fix, per product line or finding.
RETEST = {
    "lab": ("/tools/rls-check", "free RLS check"),
    "live": ("/tools/headers-check", "free headers check"),
}
RETEST_BY_ID = {
    "PL-009": ("/tools/key-check", "free key check"),
    "PL-010": ("/tools/key-check", "free key check"),
    "PL-011": ("/tools/key-check", "free key check"),
    "PL-017": ("/tools/edge-function-check", "free Edge Function check"),
    "PL-021": ("/tools/edge-function-check", "free Edge Function check"),
    "PL-022": ("/tools/edge-function-check", "free Edge Function check"),
    "PL-024": ("/tools/chat-render-check", "free AI chat rendering check"),
    "PL-025": ("/tools/firebase-rules-check", "free Firebase rules check"),
}


def prompt_for(fid):
    return PROMPTS[fid] + TAIL


def retest_for(fid, line):
    return RETEST_BY_ID.get(fid) or RETEST.get(line)

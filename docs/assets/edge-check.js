/* PatchLabs free Supabase Edge Function check (/tools/edge-function-check). Runs only in the browser: no network, no storage.
   Reads the source of a Supabase Edge Function (Deno, TypeScript or JavaScript), optionally with supabase/config.toml,
   and flags the mistakes that let a stranger use the function: the service role key with no check on the caller,
   payment webhooks without a signature check, user ids trusted from the body, hard-coded secrets, filter and SQL
   built from input, and CORS that echoes any origin with credentials. Static reading only. Also loads under Node for tests. */
(function (root) {
  'use strict';

  var RANK = { critical: 0, high: 1, medium: 2, low: 3 };

  // Replace comments with spaces, keeping newlines so line numbers stay right. Strings and template literals are respected.
  function stripComments(s) {
    var out = '', i = 0, q = null;
    while (i < s.length) {
      var c = s[i], n = s[i + 1];
      if (q) { out += c; if (c === '\\') { out += n || ''; i += 2; continue; } if (c === q) q = null; i++; continue; }
      if (c === '"' || c === "'" || c === '`') { q = c; out += c; i++; continue; }
      if (c === '/' && n === '/' && s[i - 1] !== ':') { while (i < s.length && s[i] !== '\n') { out += ' '; i++; } continue; }
      if (c === '/' && n === '*') { out += '  '; i += 2; while (i < s.length && !(s[i] === '*' && s[i + 1] === '/')) { out += s[i] === '\n' ? '\n' : ' '; i++; } out += '  '; i += 2; continue; }
      if (c === '#' && (i === 0 || s[i - 1] === '\n')) { while (i < s.length && s[i] !== '\n') { out += ' '; i++; } continue; } // toml comments
      out += c; i++;
    }
    return out;
  }

  function b64json(seg) {
    try {
      var b = seg.replace(/-/g, '+').replace(/_/g, '/'); while (b.length % 4) b += '=';
      var txt = typeof atob === 'function' ? atob(b) : Buffer.from(b, 'base64').toString('binary');
      return JSON.parse(txt);
    } catch (e) { return null; }
  }

  function mask(s) { return s.length <= 12 ? s.slice(0, 4) + '…' : s.slice(0, 8) + '…' + s.slice(-4); }

  var SECRETS = [
    { re: /\b(sk|rk)_live_[A-Za-z0-9]{16,}/g, name: 'Stripe live secret key' },
    { re: /\b(sk|rk)_test_[A-Za-z0-9]{16,}/g, name: 'Stripe test secret key' },
    { re: /\bwhsec_[A-Za-z0-9]{16,}/g, name: 'Stripe webhook signing secret' },
    { re: /\bsk-ant-[A-Za-z0-9_-]{20,}/g, name: 'Anthropic API key' },
    { re: /\bsk-(proj-)?[A-Za-z0-9_-]{32,}/g, name: 'OpenAI API key' },
    { re: /\bsb_secret_[A-Za-z0-9_-]{16,}/g, name: 'Supabase secret key' },
    { re: /\bre_[A-Za-z0-9]{8,}_[A-Za-z0-9]{16,}/g, name: 'Resend API key' },
    { re: /\beyJ[A-Za-z0-9_-]{10,}\.(eyJ[A-Za-z0-9_-]{10,})\.[A-Za-z0-9_-]{10,}/g, name: 'jwt' }
  ];

  var CALLER = /\bauth\s*\.\s*(getUser|getClaims)\s*\(|\bjwtVerify\s*\(|\bverifyJwt\s*\(|\bverifyJWT\s*\(/;
  var SIG_STRIPE = /\bconstructEvent(Async)?\s*\(/;
  var SIG_OTHER = /\b(webhooks?|wh|svix)\s*\.\s*verify\s*\(|\bcrypto\.subtle\.verify\s*\(|\btimingSafeEqual\s*\(|\bverifySignature\s*\(|\bverifyWebhook\s*\(/;
  var SHARED_SECRET = /headers\s*\.\s*get\s*\([^)]*\)[^\n]*(===|!==|==|!=)[^\n]*Deno\.env\.get|Deno\.env\.get[^\n]*(===|!==|==|!=)[^\n]*headers\s*\.\s*get/;
  var ADMIN = /SUPABASE_SERVICE_ROLE_KEY|SERVICE_ROLE|SUPABASE_SECRET_KEY|\bserviceRole(Key)?\b/;
  var STRIPE_EVENT = /checkout\.session\.completed|payment_intent\.succeeded|invoice\.(paid|payment_succeeded)|customer\.subscription\.|['"]stripe-signature['"]/i;
  var USER_HDR = /global\s*:\s*\{\s*headers\s*:\s*\{\s*Authorization/;
  var ID_NAMES = '(user_?id|userId|uid|owner_?id|ownerId|profile_?id|profileId|account_?id|accountId|customer_?id|customerId|member_?id|memberId)';

  function scan(text) {
    var src = String(text || '');
    if (!src.trim()) return { error: 'Paste the code of your Edge Function first.' };
    if (src.length > 400000) return { error: 'That is more than 400 KB. Paste one function at a time (its index.ts).' };
    var clean = stripComments(src);
    var L = clean.split('\n'), raw = src.split('\n');
    var findings = [], passed = [];
    var firstLine = function (re) { for (var i = 0; i < L.length; i++) if (re.test(L[i])) return i + 1; return 0; };
    var code = function (n) { return (raw[n - 1] || '').trim().slice(0, 220); };
    var add = function (f) { f.code = f.code || code(f.line); findings.push(f); };

    var looksLikeCode = /Deno\.serve|serve\s*\(|export\s+default|addEventListener\s*\(\s*['"]fetch|createClient\s*\(|new\s+Response\s*\(|async\s+function|=>/.test(clean);
    if (!looksLikeCode && !/verify_jwt/.test(clean)) return { error: 'This doesn’t look like an Edge Function. Paste the code from supabase/functions/<name>/index.ts.', lines: L.length };

    var callerLine = firstLine(CALLER);
    var sigLine = firstLine(SIG_STRIPE) || firstLine(SIG_OTHER);
    var sharedLine = firstLine(SHARED_SECRET);
    var adminLine = firstLine(ADMIN);
    var noVerify = firstLine(/verify_jwt\s*=\s*false|--no-verify-jwt/);
    var userHdrLine = firstLine(USER_HDR);
    var stripeEvt = firstLine(STRIPE_EVENT);
    var anyCheck = callerLine || sigLine || sharedLine;

    // 1. Hard-coded secrets.
    var seen = {};
    raw.forEach(function (line, i) {
      SECRETS.forEach(function (s) {
        s.re.lastIndex = 0; var m;
        while ((m = s.re.exec(line))) {
          var name = s.name;
          if (name === 'jwt') {
            var p = b64json(m[1]);
            if (!p || p.role !== 'service_role') continue;
            name = 'Supabase service_role key';
          }
          if (seen[m[0]]) continue; seen[m[0]] = 1;
          add({ line: i + 1, kind: 'secret', severity: name.indexOf('test') >= 0 ? 'high' : 'critical', id: name.indexOf('Supabase') === 0 ? 'PL-010' : 'PL-009',
            title: name + ' written in the code',
            code: line.trim().replace(m[0], mask(m[0])).slice(0, 220),
            detail: 'Anyone who can read this file (your repo, a collaborator, an AI tool you pasted it into) has the key. Rotate it now: deleting the line doesn’t remove it from git history.',
            fix: 'Store it as a secret and read it at run time:\n  supabase secrets set MY_KEY=…\n  const key = Deno.env.get("MY_KEY")!' });
        }
      });
    });

    // 2. Payment webhook with no signature check, or a check that can’t work in Deno.
    if (stripeEvt) {
      var sync = firstLine(/\bconstructEvent\s*\(/), asyncL = firstLine(/\bconstructEventAsync\s*\(/);
      if (!sync && !asyncL && !firstLine(SIG_OTHER)) {
        add({ line: stripeEvt, kind: 'webhook', severity: 'critical', id: 'PL-021', title: 'Stripe webhook handled without checking Stripe’s signature',
          detail: 'Anyone who finds the URL can post a fake “payment succeeded” event and get what a paying customer gets.',
          fix: 'const body = await req.text();\nconst event = await stripe.webhooks.constructEventAsync(\n  body, req.headers.get("Stripe-Signature")!,\n  Deno.env.get("STRIPE_WEBHOOK_SECRET")!, undefined,\n  Stripe.createSubtleCryptoProvider());' });
      } else if (sync && !asyncL) {
        add({ line: sync, kind: 'webhook-sync', severity: 'medium', id: 'PL-021', title: 'constructEvent (not constructEventAsync) in Deno',
          detail: 'Edge Functions have only Web Crypto, which can’t verify synchronously, so this throws on every real event. The usual next step is deleting the check, which leaves the webhook open.',
          fix: 'const event = await stripe.webhooks.constructEventAsync(\n  body, signature, secret, undefined, Stripe.createSubtleCryptoProvider());' });
      }
      var jsonL = firstLine(/\breq(uest)?\s*\.\s*json\s*\(/);
      if ((sync || asyncL) && jsonL && !firstLine(/\breq(uest)?\s*\.\s*(text|arrayBuffer)\s*\(/)) {
        add({ line: jsonL, kind: 'webhook-body', severity: 'medium', id: 'PL-021', title: 'Body parsed as JSON before the signature check',
          detail: 'Stripe signs the exact bytes it sent. Parsing and re-serialising changes them, so real events fail the check.',
          fix: 'const body = await req.text();   // raw text, before anything else reads the body\n// pass body to constructEventAsync, then use the event it returns' });
      }
    }

    // 3. Service role key with no check on who is calling.
    if (adminLine && !anyCheck) {
      add({ line: adminLine, kind: 'admin', severity: 'critical', id: 'PL-017', title: 'Service role key used with no check on the caller',
        detail: 'The service role key ignores every row level security policy, so this function is the only lock on your data, and it never asks who is calling. ' +
          (noVerify ? 'verify_jwt is off too, so anyone on the internet can call it.' : 'The platform’s verify_jwt check accepts your public anon key on projects with legacy keys, so it doesn’t prove a signed-in user either.'),
        fix: 'const authHeader = req.headers.get("Authorization") ?? "";\nconst { data: { user }, error } = await supabase.auth.getUser(authHeader.replace("Bearer ", ""));\nif (error || !user) return new Response("Unauthorized", { status: 401 });\n// then act only on rows that belong to user.id' });
    } else if (noVerify && !anyCheck) {
      add({ line: noVerify, kind: 'noverify', severity: 'high', id: 'PL-017', title: 'verify_jwt is off and the code never checks the caller',
        detail: 'With the platform check off and no check in the code, anyone who finds the URL can run this function.',
        fix: 'Check the caller in the function with supabase.auth.getUser(token), or, for a webhook or cron job, verify a signature or a shared secret header.' });
    }

    // 4. A user id taken from the request body.
    var idRe = new RegExp('\\{[^}]*\\b' + ID_NAMES + '\\b[^}]*\\}\\s*=\\s*await\\s+req(uest)?\\s*\\.\\s*json|\\b(body|payload|data|params|input)\\s*\\.\\s*' + ID_NAMES + '\\b|searchParams\\s*\\.\\s*get\\s*\\(\\s*[\'"]' + ID_NAMES + '[\'"]');
    var idLine = firstLine(idRe);
    if (idLine && !stripeEvt) {
      add({ line: idLine, kind: 'body-id', severity: adminLine ? 'high' : 'medium', id: 'PL-022', title: 'User id taken from the request, not from the signed-in user',
        detail: 'Whoever calls the function chooses this id, so they can act on anyone’s account by sending a different one' + (adminLine ? ', and the service role key means no policy stops them.' : '. Row level security may still stop them if the client uses the caller’s token.') + (callerLine ? ' Your getUser call already knows the real id: use it.' : ''),
        fix: 'const { data: { user } } = await supabase.auth.getUser(token);\nif (!user) return new Response("Unauthorized", { status: 401 });\nconst userId = user.id;   // never the id from the body' });
    }

    // 5. PostgREST filter strings and SQL built from input.
    L.forEach(function (line, i) {
      if (/\.or\s*\(\s*`[^`]*\$\{/.test(line) || /\.or\s*\(\s*['"][^'"]*['"]\s*\+/.test(line)) {
        add({ line: i + 1, kind: 'filter', severity: 'medium', id: 'PL-022', title: 'Filter string built from input in .or()',
          detail: '.or() takes a filter written in PostgREST’s syntax. Commas and dots in the input add new conditions, so a search box can widen the query, and with the service role key nothing else narrows it.',
          fix: 'Strip or reject , . ( ) in the input first, e.g.\n  const q = term.replace(/[,.()]/g, " ");\nor use .ilike("name", `%${q}%`) and .eq() calls instead of one .or() string.' });
      }
      if (/\b(queryObject|queryArray|query|unsafe|execute|raw)\s*\(\s*`[^`]*\b(select|insert|update|delete|where)\b[^`]*\$\{/i.test(line)) {
        add({ line: i + 1, kind: 'sql', severity: 'high', id: 'PL-022', title: 'SQL built by pasting values into the query text',
          detail: 'A value containing a quote ends the string and runs whatever follows: classic SQL injection, with a direct database connection that ignores row level security.',
          fix: 'Pass values as parameters:\n  await client.queryObject("select * from orders where id = $1", [id]);\n  // postgres.js: await sql`select * from orders where id = ${id}`  (the tagged form is safe)' });
      }
    });

    // 6. CORS that echoes any origin with credentials.
    var reflect = firstLine(/Access-Control-Allow-Origin['"]?\s*[:,]\s*(req(uest)?\s*\.\s*headers\s*\.\s*get\s*\(\s*['"]origin|origin\b(?!s)[^'"\w])/i);
    var creds = firstLine(/Access-Control-Allow-Credentials['"]?\s*[:,]\s*['"]?true/i);
    if (reflect && creds && !firstLine(/allowed(Origins)?\s*\.\s*(includes|has)\s*\(|ALLOWED_ORIGINS/i)) {
      add({ line: reflect, kind: 'cors', severity: 'medium', id: 'PL-026', title: 'CORS echoes any origin with credentials allowed',
        detail: 'Any website your users visit can call this function with their cookies and read the answer. It matters most when the session lives in cookies.',
        fix: 'const ALLOWED = ["https://yourapp.com"];\nconst origin = req.headers.get("Origin") ?? "";\nconst allow = ALLOWED.includes(origin) ? origin : ALLOWED[0];\n// "Access-Control-Allow-Origin": allow, plus "Vary": "Origin"' });
    }

    // What the function gets right.
    if (callerLine) passed.push({ line: callerLine, label: 'Checks who is calling' });
    if (sigLine) passed.push({ line: sigLine, label: 'Verifies the webhook signature' });
    if (sharedLine) passed.push({ line: sharedLine, label: 'Checks a shared secret header' });
    if (userHdrLine) passed.push({ line: userHdrLine, label: 'Client uses the caller’s token, so your RLS policies apply' });
    var envLine = firstLine(/Deno\.env\.get\s*\(/);
    if (envLine && !findings.some(function (f) { return f.kind === 'secret'; })) passed.push({ line: envLine, label: 'Reads secrets with Deno.env.get' });

    findings.sort(function (a, b) { return RANK[a.severity] - RANK[b.severity] || a.line - b.line; });
    return { lines: L.length, findings: findings, passed: passed, admin: !!adminLine, webhook: !!stripeEvt };
  }

  function prompt(r) {
    var lines = ['My Supabase Edge Function has these security problems. Fix each one, keep the function’s behaviour the same, and show me the full new index.ts:', ''];
    r.findings.forEach(function (f, i) { lines.push((i + 1) + '. Line ' + f.line + ': ' + f.title + '. ' + f.detail.split('. ')[0].replace(/\.+$/, '') + '.'); });
    lines.push('', 'Rules: check the caller with supabase.auth.getUser(token) before using the service role key and take the user id from that result; verify Stripe webhooks with constructEventAsync over the raw req.text() body; read every secret with Deno.env.get; don’t build .or() filters or SQL from input.');
    return lines.join('\n');
  }

  // A made-up function with the usual mistakes. The Stripe key is assembled at run time so this file never contains one.
  function sample() {
    var key = 'sk_' + 'live_' + '51Pq' + 'X7dDemoOnlyNotARealKey00';
    return [
      'import { createClient } from "npm:@supabase/supabase-js@2";',
      'import Stripe from "npm:stripe@17";',
      '',
      'const stripe = new Stripe("' + key + '");',
      '',
      'Deno.serve(async (req) => {',
      '  const cors = {',
      '    "Access-Control-Allow-Origin": req.headers.get("origin") ?? "*",',
      '    "Access-Control-Allow-Credentials": "true",',
      '  };',
      '  if (req.method === "OPTIONS") return new Response("ok", { headers: cors });',
      '',
      '  const supabase = createClient(',
      '    Deno.env.get("SUPABASE_URL")!,',
      '    Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!,',
      '  );',
      '  const { user_id, search } = await req.json();',
      '',
      '  const { data: orders } = await supabase.from("orders")',
      '    .select("*")',
      '    .or(`status.eq.open,title.ilike.%${search}%`);',
      '',
      '  await supabase.from("profiles").delete().eq("id", user_id);',
      '  await stripe.customers.del(orders?.[0]?.customer_id);',
      '  return new Response(JSON.stringify({ ok: true }), { headers: cors });',
      '});'
    ].join('\n');
  }

  var api = { scan: scan, prompt: prompt, sample: sample };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.PLEdgeCheck = api;
})(typeof window !== 'undefined' ? window : this);

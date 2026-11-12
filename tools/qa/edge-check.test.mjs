// Unit checks for the in-browser Edge Function check (site/static/assets/edge-check.js).  node tools/qa/edge-check.test.mjs
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
const EC = createRequire(import.meta.url)('../../site/static/assets/edge-check.js');
const kinds = r => r.findings.map(f => [f.line, f.kind, f.severity]);

// The sample: hard-coded live Stripe key, service role with no caller check, user id from body, .or() injection, CORS reflect.
const s = EC.scan(EC.sample());
assert.deepEqual(kinds(s), [
  [4, 'secret', 'critical'], [15, 'admin', 'critical'],
  [17, 'body-id', 'high'],
  [8, 'cors', 'medium'], [21, 'filter', 'medium']]);
assert.ok(!s.findings[0].code.includes('NotARealKey00'), 'key is masked in the report');
assert.match(EC.prompt(s), /Line 15: Service role key used with no check on the caller/);

// A good function: getUser first, user.id used, caller-token client. Nothing flagged, three passes.
const good = EC.scan(`import { createClient } from "npm:@supabase/supabase-js@2";
Deno.serve(async (req) => {
  const supabase = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_ANON_KEY")!,
    { global: { headers: { Authorization: req.headers.get("Authorization")! } } });
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) return new Response("Unauthorized", { status: 401 });
  const { data } = await supabase.from("notes").select("*").eq("owner", user.id);
  return Response.json(data);
});`);
assert.equal(good.findings.length, 0, JSON.stringify(good.findings));
assert.deepEqual(good.passed.map(p => p.label).sort(), ['Checks who is calling', 'Client uses the caller’s token, so your RLS policies apply', 'Reads secrets with Deno.env.get'].sort());

// Stripe webhook: none, sync, and correct.
const hook = body => EC.scan(`import Stripe from "npm:stripe@17";
const stripe = new Stripe(Deno.env.get("STRIPE_SECRET_KEY")!);
Deno.serve(async (req) => {
${body}
  if (event.type === "checkout.session.completed") { /* grant access */ }
  return new Response("ok");
});`);
const none = hook('  const event = await req.json();');
assert.deepEqual(kinds(none), [[5, 'webhook', 'critical']]);
const sync = hook('  const body = await req.json();\n  const event = stripe.webhooks.constructEvent(JSON.stringify(body), req.headers.get("stripe-signature"), Deno.env.get("WH")!);');
assert.deepEqual(kinds(sync), [[4, 'webhook-body', 'medium'], [5, 'webhook-sync', 'medium']]);
const ok = hook('  const body = await req.text();\n  const event = await stripe.webhooks.constructEventAsync(body, req.headers.get("Stripe-Signature")!, Deno.env.get("WH")!, undefined, Stripe.createSubtleCryptoProvider());');
assert.equal(ok.findings.length, 0, JSON.stringify(ok.findings));
assert.ok(ok.passed.some(p => p.label === 'Verifies the webhook signature'));

// Service role in a webhook with a signature check is fine; a cron function with a shared secret is fine.
const cron = EC.scan(`Deno.serve(async (req) => {
  if (req.headers.get("x-cron-secret") !== Deno.env.get("CRON_SECRET")) return new Response("no", { status: 401 });
  const admin = createClient(Deno.env.get("SUPABASE_URL")!, Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")!);
  await admin.from("jobs").delete().lt("created_at", new Date().toISOString());
  return new Response("ok");
});`);
assert.equal(cron.findings.length, 0, JSON.stringify(cron.findings));

// verify_jwt off with no check, no admin key: high.
const nv = EC.scan(`# supabase/config.toml\n[functions.hello]\nverify_jwt = false\n\nDeno.serve(async (req) => new Response("hi"));`);
assert.deepEqual(kinds(nv), [[3, 'noverify', 'high']]);

// Raw SQL interpolation is high; postgres.js tagged template is not flagged.
const sql = EC.scan('Deno.serve(async (req) => {\n  const { id } = await req.json();\n  const r = await client.queryObject(`select * from orders where id = \'${id}\'`);\n  const t = await sql`select * from orders where id = ${id}`;\n  return Response.json(r);\n});');
assert.deepEqual(kinds(sql), [[3, 'sql', 'high']]);

// A service_role JWT literal is caught; an anon JWT literal is not. Tokens are built here, not stored in the repo.
const jwt = role => ['eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9', Buffer.from(JSON.stringify({ iss: 'supabase', ref: 'abcdefghij', role })).toString('base64url'), 'c2lnbmF0dXJlX29ubHlfZm9yX3Rlc3Rz'].join('.');
const sr = EC.scan(`const supabase = createClient("https://x.supabase.co", "${jwt('service_role')}");\nDeno.serve(async () => new Response("x"));`);
assert.equal(sr.findings[0].id, 'PL-010'); assert.equal(sr.findings[0].severity, 'critical');
const anon = EC.scan(`const supabase = createClient("https://x.supabase.co", "${jwt('anon')}");\nDeno.serve(async () => new Response("x"));`);
assert.ok(!anon.findings.some(f => f.kind === 'secret'));

// Comments are ignored; non-code is rejected; empty input errors.
const cm = EC.scan('// const k = Deno.env.get("SUPABASE_SERVICE_ROLE_KEY")\nDeno.serve(async () => new Response("x"));');
assert.equal(cm.findings.length, 0);
assert.ok(EC.scan('hello there, this is a note').error);
assert.ok(EC.scan('   ').error);

console.log('edge-check: all checks passed');

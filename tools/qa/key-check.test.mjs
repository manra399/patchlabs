// Unit checks for the in-browser key check (site/static/assets/key-check.js).  node tools/qa/key-check.test.mjs
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
const KC = createRequire(import.meta.url)('../../site/static/assets/key-check.js');

const r = KC.scan(KC.sample());
assert.deepEqual(r.findings.map(f => [f.id, f.severity, f.finding]), [
  ['supabase_service', 'critical', 'PL-010'], ['openai_project', 'critical', 'PL-010'], ['stripe_test', 'low', 'PL-009']]);
assert.deepEqual(r.safe.map(s => s.title), ['Supabase anon key', 'Stripe publishable key']);
assert.ok(r.findings.every(f => f.masked.includes('…')), 'values are masked');

const pg = KC.scan('DATABASE_URL=postgresql://postgres:S3cretPassw0rd@db.x.supabase.co:5432/postgres').findings;
assert.equal(pg[0].id, 'pg_url'); assert.equal(pg[0].masked, 'S3…', 'short secrets show two characters only');

assert.equal(KC.scan('OPENAI_API_KEY=your_openai_key_here').findings.length, 0, 'placeholders ignored');
assert.equal(KC.scan('const k = "AKIA' + 'Q7RZ2M4KX9TB3WLP"').findings[0].id, 'aws');
assert.equal(KC.scan('NEXT_PUBLIC_KEY=sb_secret_' + 'Zq81mLr0Xk2PvT7wYc4N').findings[0].severity, 'critical');
assert.equal(KC.scan('').findings.length, 0);
console.log('key-check: all checks pass');

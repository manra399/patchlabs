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
// Claude Code settings files (allow rules and env block)
const cr = KC.scan(KC.sample('claude'));
assert.equal(cr.claude, true);
assert.deepEqual(cr.findings.map(f => [f.id, f.finding]).sort(), [['claude_rule', 'PL-009'], ['claude_rule', 'PL-009'], ['github', 'PL-009'], ['resend', 'PL-009']].sort());
assert.ok(cr.findings.find(f => f.id === 'github').detail.includes('Claude Code settings'), 'prefixed keys get the settings note');
const clean = JSON.stringify({ permissions: { allow: ['Bash(npm run test *)', 'Bash(mkdir -p src/components)',
  'Bash(curl -H "Authorization: Bearer $TOKEN" *)', 'Bash(PGPASSWORD=$DB_PASSWORD psql *)', 'Bash(export API_KEY=your_api_key_here)'] },
  env: { API_TOKEN: '${API_TOKEN}', MAX_TOKENS: '40960000', DEBUG: 'true' } }, null, 2);
assert.deepEqual(KC.scan(clean).findings, [], 'settings near-misses stay clean');
assert.equal(KC.scan('fetch(url, { headers: { Authorization: "Bearer " + token } })').claude, false, 'plain code is not settings mode');
const envOnly = KC.scan('{ "env": { "DB_PASSWORD": "Wq8' + 'zL2mPx91" }, "permissions": { "allow": [] } }').findings;
assert.equal(envOnly[0].id, 'claude_env');
console.log('key-check: all checks pass');

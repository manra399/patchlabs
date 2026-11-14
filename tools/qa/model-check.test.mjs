// Unit checks for the in-browser AI model shutdown check (site/static/assets/model-check.js).  node tools/qa/model-check.test.mjs
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
const MC = createRequire(import.meta.url)('../../site/static/assets/model-check.js');
const T = '2026-11-14';
const ids = r => r.findings.map(f => [f.id, f.severity, f.days]);

// Sample: Assistants (already off), o3 (11 Dec), gpt-4o-mini-tts (6 Jan), gpt-4o and gpt-4.1-mini (14 Jan); gpt-6-luna passes.
const s = MC.scan(MC.sample(), T);
assert.deepEqual(ids(s), [['Assistants API', 'critical', -80], ['o3', 'high', 27], ['gpt-4o-mini-tts', 'high', 53], ['gpt-4o', 'high', 61], ['gpt-4.1-mini', 'high', 61]]);
assert.deepEqual(s.passed.map(p => p.id), ['gpt-6-luna']);
assert.ok(s.findings.find(f => f.id === 'gpt-4o').alias, 'bare gpt-4o is marked as an alias');
assert.match(MC.prompt(s), /gpt-4o \(line 7\): shuts down on 14 Jan 2027\. Replace with gpt-6-luna\./);

// The longest id wins: a dated TTS snapshot is not reported as gpt-4o or gpt-4o-mini.
assert.deepEqual(MC.scan("model: 'gpt-4o-mini-tts-2025-12-15'", T).findings.map(f => f.id), ['gpt-4o-mini-tts-2025-12-15']);
// Dated snapshot and Python style.
assert.deepEqual(MC.scan('client.responses.create(model="gpt-4.1-2025-04-14")', T).findings.map(f => [f.id, f.alias]), [['gpt-4.1-2025-04-14', false]]);
// Already shut down on 23 Oct 2026.
const old = MC.scan("const MODEL = 'gpt-4.1-nano';", T).findings[0];
assert.equal(old.severity, 'critical'); assert.equal(old.replacement, 'gpt-5.6-luna');
// Bare o3 in prose is ignored; quoted or after MODEL= it counts.
assert.equal(MC.scan('we tried o3 and o1 last year', T).findings.length, 0);
assert.equal(MC.scan('REASONING_MODEL=o3', T).findings.length, 1);
// Ids inside longer names or paths are not matched.
assert.equal(MC.scan('my-gpt-4o-wrapper and /models/gpt-4o.png', T).findings.length, 0);
// Same id twice: one finding listing both lines.
const two = MC.scan("a('gpt-4o')\nb('gpt-4o')", T).findings;
assert.equal(two.length, 1); assert.deepEqual(two[0].lines, [1, 2]);
// Severity bands move with the date: low when more than 180 days away.
assert.equal(MC.scan("'gpt-4o'", '2026-06-01').findings[0].severity, 'low');
// Feature: prompt objects and audio translations.
assert.deepEqual(MC.scan("prompt: { id: 'pmpt_abc123456' }\nopenai.audio.translations.create()", T).findings.map(f => f.id).sort(), ['Audio translations endpoint', 'Reusable prompt objects (/v1/prompts)']);
// Current models pass; empty input errors.
assert.equal(MC.scan("model: 'gpt-6.1-sol'", T).findings.length, 0);
assert.ok(MC.scan('   ', T).error);
// The data really says 14 Jan 2027 for GPT-4o snapshots, per OpenAI's page.
assert.equal(MC.data.models.find(m => m.id === 'gpt-4o-2024-08-06').shutdown, '2027-01-14');
console.log('model-check: all assertions passed');

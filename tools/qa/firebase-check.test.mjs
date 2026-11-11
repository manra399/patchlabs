// Unit checks for the in-browser Firebase rules check (site/static/assets/firebase-check.js).  node tools/qa/firebase-check.test.mjs
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
const FC = createRequire(import.meta.url)('../../site/static/assets/firebase-check.js');
const today = new Date(Date.UTC(2026, 10, 11));

// The sample: test-mode catch-all, signed-in-only orders and users read, public products read; owner write and admin write pass.
const r = FC.scan(FC.sample(today), today);
assert.equal(r.product, 'Firestore');
assert.equal(r.rules, 6);
assert.deepEqual(r.findings.map(f => [f.line, f.kind, f.severity, f.path]), [
  [8, 'testmode', 'critical', '/{document=**}'],
  [12, 'signedin', 'high', '/users/{userId}'],
  [17, 'signedin', 'high', '/orders/{orderId}'],
  [21, 'open', 'medium', '/products/{productId}']]);
assert.deepEqual(r.passed.map(p => p.line), [13, 22]);
assert.match(r.findings[0].detail, /combines rules with OR/);
assert.match(FC.prompt(r), /line 17 \(\/orders\/\{orderId\}\)/);

// Expired test mode is low; open write anywhere is critical; comments and URLs in strings don't break parsing.
const exp = FC.scan(`service cloud.firestore { match /databases/{db}/documents { match /{d=**} { allow read, write: if request.time < timestamp.date(2026, 1, 1); } } }`, today);
assert.equal(exp.findings[0].kind, 'expired'); assert.equal(exp.findings[0].severity, 'low');
const ow = FC.scan(`service cloud.firestore {\n match /databases/{db}/documents {\n  // see https://firebase.google.com/docs\n  match /notes/{id} { allow write: if true; /* temp */ }\n }\n}`, today);
assert.deepEqual(ow.findings.map(f => [f.line, f.severity]), [[4, 'critical']]);

// Owner checks pass, including through helper functions and resource.data fields.
const ok = FC.scan(`service cloud.firestore { match /databases/{db}/documents {
  function isOwner(uid) { return request.auth != null && request.auth.uid == uid; }
  match /users/{userId} { allow read, write: if isOwner(userId); }
  match /posts/{id} { allow read: if request.auth != null && resource.data.published == true; allow update: if resource.data.ownerId == request.auth.uid; }
} }`, today);
assert.equal(ok.findings.length, 0, JSON.stringify(ok.findings));
assert.equal(ok.passed.length, 3);

// Storage rules.
const st = FC.scan(`rules_version = '2';\nservice firebase.storage {\n  match /b/{bucket}/o {\n    match /{allPaths=**} {\n      allow read, write: if request.auth != null;\n    }\n  }\n}`, today);
assert.equal(st.product, 'Storage'); assert.deepEqual(st.findings.map(f => [f.line, f.kind, f.severity]), [[5, 'signedin', 'high']]);
assert.match(st.findings[0].fix, /allPaths=\*\*/);

// Realtime Database JSON.
const db = FC.scan(`{\n  "rules": {\n    ".read": "now < 1999999999000",\n    ".write": "auth != null",\n    "users": {\n      "$uid": { ".read": "auth.uid === $uid", ".write": true }\n    }\n  }\n}`, today);
assert.equal(db.product, 'Realtime Database');
assert.deepEqual(db.findings.map(f => [f.line, f.kind, f.severity, f.path]), [
  [3, 'testmode', 'critical', '/'], [6, 'open', 'critical', '/users/$uid'], [4, 'signedin', 'high', '/']]);
assert.equal(db.passed.length, 1);
assert.match(FC.scan('{ "rules": { ".read": true, }', today).error, /valid JSON/);

assert.equal(FC.scan('', today).findings.length, 0);
console.log('firebase-check: all checks pass');

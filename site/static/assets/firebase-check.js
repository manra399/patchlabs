/* PatchLabs free Firebase rules check (/tools/firebase-rules-check). Runs only in the browser: no network, no storage.
   Reads Cloud Firestore and Cloud Storage security rules (firestore.rules, storage.rules) and Realtime Database
   rules (database.rules.json) and flags rules that let anyone, or any signed-in stranger, read or change data.
   Static reading only: it never contacts a Firebase project. Also loads under Node for tests. */
(function (root) {
  'use strict';

  var SENSITIVE = /^(users?|profiles?|accounts?|customers?|members?|orders?|payments?|invoices?|messages?|chats?|conversations?|bookings?|patients?|employees?|contacts?|leads?|applications?|transactions?|subscriptions?|addresses|private|secrets?|admin|uploads?|documents?|files?|avatars?|photos?|images?|ids?|verifications?)$/i;
  var RANK = { critical: 0, high: 1, medium: 2, low: 3 };

  // Replace comments with spaces, keeping every newline so line numbers stay right. Quotes are respected.
  function stripComments(s) {
    var out = '', i = 0, q = null;
    while (i < s.length) {
      var c = s[i], n = s[i + 1];
      if (q) { out += c; if (c === '\\') { out += n || ''; i += 2; continue; } if (c === q) q = null; i++; continue; }
      if (c === '"' || c === "'") { q = c; out += c; i++; continue; }
      if (c === '/' && n === '/') { while (i < s.length && s[i] !== '\n') { out += ' '; i++; } continue; }
      if (c === '/' && n === '*') { out += '  '; i += 2; while (i < s.length && !(s[i] === '*' && s[i + 1] === '/')) { out += s[i] === '\n' ? '\n' : ' '; i++; } out += '  '; i += 2; continue; }
      out += c; i++;
    }
    return out;
  }

  function lineAt(s, idx) { var n = 1; for (var i = 0; i < idx && i < s.length; i++) if (s[i] === '\n') n++; return n; }
  function squash(s) { return String(s || '').replace(/\s+/g, ' ').trim(); }

  // Inline user functions (function isOwner(uid) { return ...; }) so their bodies are judged, up to three levels deep.
  function expand(cond, fns) {
    for (var d = 0; d < 3; d++) {
      var before = cond;
      cond = cond.replace(/\b([A-Za-z_]\w*)\s*\(([^()]*)\)/g, function (m, name) { return fns[name] != null ? '(' + fns[name] + ')' : m; });
      if (cond === before) break;
    }
    return cond;
  }

  // What a condition allows. Returns {kind, until?}. kinds: open, testmode, expired, signedin, restricted, closed.
  function judge(cond, today, rtdb) {
    var c = squash(cond);
    if (!c || /^\(*\s*true\s*\)*$/.test(c)) return { kind: 'open' };
    if (/^\(*\s*false\s*\)*$/.test(c)) return { kind: 'closed' };
    var auth = rtdb ? /\bauth\b/ : /request\.auth/;
    var owner = rtdb
      ? /auth\.uid\s*={2,3}|={2,3}\s*auth\.uid|auth\.token\.|root\.|data\.child\(|newData\.child\(/
      : /request\.auth\.uid\s*==|==\s*request\.auth\.uid|request\.auth\.token\.\w+\s*(==|in\b)|\bin\s+resource\.data|request\.auth\.uid\s+in\b|\bget\s*\(|\bexists\s*\(|\bgetAfter\s*\(/;
    var tm = rtdb ? /\bnow\s*<\s*(\d{12,14})/ : /request\.time\s*<\s*timestamp\.date\(\s*(\d{4})\s*,\s*(\d{1,2})\s*,\s*(\d{1,2})\s*\)/;
    var t = c.match(tm);
    if (t && !auth.test(c)) {
      var until = rtdb ? new Date(Number(t[1])) : new Date(Date.UTC(+t[1], +t[2] - 1, +t[3]));
      return { kind: until > today ? 'testmode' : 'expired', until: until };
    }
    if (owner.test(c)) return { kind: 'restricted' };
    var signedIn = rtdb ? /auth\s*!={1,2}\s*null|auth\.uid\s*!={1,2}\s*null/ : /request\.auth\s*!=\s*null|request\.auth\.uid\s*!=\s*null/;
    if (signedIn.test(c)) {
      // Signed-in plus a check on the data (resource.data.public == true, a field check) counts as restricted.
      var rest = c.replace(signedIn, '').replace(/&&|\|\||[()\s!]/g, '');
      if (!rest || /^(true)+$/.test(rest)) return { kind: 'signedin' };
      return { kind: 'restricted' };
    }
    return { kind: 'restricted' };
  }

  function isRecursive(path) { return /\{[^}]*=\*\*\}/.test(path) || path === '/'; }
  function lastLiteral(path) {
    var segs = path.split('/').filter(Boolean).filter(function (s) { return !/^\{/.test(s) && !/^(databases|documents|b|o|\$\w+)$/.test(s); });
    return segs.length ? segs[segs.length - 1] : '';
  }
  function lastVar(path) { var m = path.match(/\{(\w+)\}(?!.*\{)/) || path.match(/\$(\w+)(?!.*\$)/); return m ? m[1] : ''; }
  function shortPath(stack) {
    var p = stack.join('');
    p = p.replace(/^\/databases\/\{\w+\}\/documents/, '').replace(/^\/b\/\{\w+\}\/o/, '');
    return p || '/';
  }

  var READ = { read: 1, get: 1, list: 1 }, WRITE = { write: 1, create: 1, update: 1, delete: 1 };

  // create alone adds new documents; it cannot read, change or delete existing ones.
  function createOnly(methods) { return methods.length > 0 && methods.every(function (m) { return m === 'create'; }); }

  function sevFor(kind, methods, path) {
    if ((kind === 'open' || kind === 'signedin') && createOnly(methods) && !isRecursive(path)) return kind === 'open' ? 'high' : 'low';
    var writes = methods.some(function (m) { return WRITE[m]; });
    var reads = methods.some(function (m) { return READ[m]; });
    var broad = isRecursive(path), sens = SENSITIVE.test(lastLiteral(path));
    if (kind === 'testmode') return 'critical';
    if (kind === 'expired') return 'low';
    if (kind === 'open') { if (writes || broad || sens) return 'critical'; return 'medium'; }
    if (kind === 'signedin') { if (broad || (writes && sens)) return 'high'; if (writes) return 'high'; if (sens) return 'high'; return reads ? 'medium' : 'medium'; }
    return null;
  }

  function title(kind, methods, path, product, until) {
    if ((kind === 'open' || kind === 'signedin') && createOnly(methods) && !isRecursive(path)) {
      var into = product === 'Storage' ? 'upload new files under ' + path : 'add new documents to ' + (lastLiteral(path) || path);
      return (kind === 'open' ? 'Anyone, signed in or not, can ' : 'Any signed-in user can ') + into + (kind === 'signedin' ? ' with any content, including someone else\'s user ID' : '');
    }
    var verb = methods.some(function (m) { return WRITE[m]; }) ? (methods.some(function (m) { return READ[m]; }) ? 'read and change' : 'change or delete') : 'read';
    var where = isRecursive(path) ? 'everything in your ' + product : (lastLiteral(path) ? 'every document in ' + lastLiteral(path) : path);
    if (product === 'Storage' && !isRecursive(path)) where = 'every file under ' + path;
    if (product === 'Realtime Database' && !isRecursive(path)) where = 'everything under ' + path;
    if (kind === 'testmode') return 'Test mode: anyone can ' + verb + ' ' + where + ' until ' + until.toISOString().slice(0, 10);
    if (kind === 'expired') return 'Test-mode rule expired on ' + until.toISOString().slice(0, 10) + ': requests to ' + path + ' are now denied';
    if (kind === 'open') return 'Anyone, signed in or not, can ' + verb + ' ' + where;
    return 'Any signed-in user can ' + verb + ' ' + where;
  }

  function fixFor(kind, methods, path, product) {
    var v = lastVar(path), lit = lastLiteral(path);
    if ((kind === 'open' || kind === 'signedin') && createOnly(methods) && !isRecursive(path) && product !== 'Storage') {
      return 'Only let signed-in users create, and only with their own user ID in the owner field:\nallow create: if request.auth != null && request.resource.data.ownerId == request.auth.uid;\n(FlutterFlow stores the owner as a user reference; compare with /databases/$(database)/documents/users/$(request.auth.uid) instead)';
    }
    if (kind === 'expired') return 'Replace the date rule with real rules before you ship, or your app keeps failing with permission-denied.';
    var publicRead = kind === 'open' && !methods.some(function (m) { return WRITE[m]; }) && !isRecursive(path) && !SENSITIVE.test(lit);
    if (publicRead) return 'If this is meant to be public (a product list, published posts), leave read open and make sure writes are limited, for example:\nallow write: if request.auth != null && request.auth.token.admin == true;\nIf it holds anything personal, check the owner instead:\nallow read: if request.auth != null && resource.data.ownerId == request.auth.uid;';
    if (product === 'Realtime Database') {
      return '"users": {\n  "$uid": {\n    ".read": "auth != null && auth.uid === $uid",\n    ".write": "auth != null && auth.uid === $uid"\n  }\n}';
    }
    if (isRecursive(path)) {
      return product === 'Storage'
        ? 'Delete this rule. Give each folder its own rule, for example:\nmatch /users/{userId}/{allPaths=**} {\n  allow read, write: if request.auth != null && request.auth.uid == userId;\n}'
        : 'Delete this rule. Give each collection its own match block, for example:\nmatch /users/{userId} {\n  allow read, write: if request.auth != null && request.auth.uid == userId;\n}';
    }
    if (product === 'Storage') {
      return 'Put each user\'s files under their own folder and check it:\nmatch /' + (lit || 'users') + '/{userId}/{allPaths=**} {\n  allow read, write: if request.auth != null && request.auth.uid == userId;\n}';
    }
    if (/^(users?|profiles?|accounts?|members?)$/i.test(lit) && v) {
      return 'allow read, write: if request.auth != null && request.auth.uid == ' + v + ';';
    }
    return 'allow read, update, delete: if request.auth != null && resource.data.ownerId == request.auth.uid;\nallow create: if request.auth != null && request.resource.data.ownerId == request.auth.uid;\n(use the field that stores the owner\'s user ID)';
  }

  function detailFor(kind, path, product, overrides, methods) {
    var d = [];
    if ((kind === 'open' || kind === 'signedin') && methods && createOnly(methods) && !isRecursive(path)) {
      d.push(kind === 'open'
        ? 'Create cannot read or change existing documents, but anyone with your public Firebase config can script thousands of fake records (orders, sign-ups, messages) and set any field, including the owner and price.'
        : 'Usually acceptable, but without a check on the owner field a user can create documents that claim to belong to someone else.');
      return d.join(' ');
    }
    if (kind === 'testmode') d.push('This is the rule Firebase writes when you start in test mode. Until that date every request is allowed, including from people who never open your app.');
    if (kind === 'open') d.push(isRecursive(path) ? 'No condition at all, on every path.' : 'Fine only if this data is meant to be public, like a product list. Not fine for anything personal.');
    if (kind === 'signedin') d.push('Checking only that someone is signed in does not check who they are. Anyone who can create an account in your app, which on most apps is anyone, gets this access to every user\'s data, not just their own.');
    if (overrides && product !== 'Realtime Database') d.push('Firebase combines rules with OR: if any rule allows a request, it is allowed. So this broad rule overrides every stricter rule elsewhere in the file.');
    if (overrides && product === 'Realtime Database') d.push('Realtime Database rules cascade: access granted here applies to everything below it, and rules deeper down cannot take it away.');
    return d.join(' ');
  }

  function scanRules(raw, today) {
    var s = stripComments(raw);
    var product = /service\s+firebase\.storage/.test(s) ? 'Storage' : 'Firestore';
    var fns = {};
    // Collect functions first (they can be defined after use).
    var fre = /function\s+([A-Za-z_]\w*)\s*\(([^)]*)\)\s*\{([\s\S]*?)\}/g, fm;
    while ((fm = fre.exec(s))) { var ret = fm[3].match(/return\s+([\s\S]*?);?\s*$/); fns[fm[1]] = ret ? squash(ret[1].replace(/;\s*$/, '')) : 'true'; }
    var findings = [], passed = [], stack = [], depthAt = [], depth = 0, i = 0, allows = 0;
    var reMatch = /match\s+(\S+)\s*\{/y, reFn = /function\s+[A-Za-z_]\w*\s*\([^)]*\)\s*\{/y, reAllow = /allow\s+([a-z,\s]+?)\s*(?::\s*if\s+([\s\S]*?))?\s*;/y;
    while (i < s.length) {
      var c = s[i], m;
      if (c === '"' || c === "'") { var j = s.indexOf(c, i + 1); i = j < 0 ? s.length : j + 1; continue; }
      if (/[mfa]/.test(c) && (i === 0 || /[\s{};]/.test(s[i - 1]))) {
        reMatch.lastIndex = i; m = reMatch.exec(s);
        if (m) { depth++; stack.push(m[1].charAt(0) === '/' ? m[1] : '/' + m[1]); depthAt.push(depth); i = reMatch.lastIndex; continue; }
        reFn.lastIndex = i; m = reFn.exec(s);
        if (m) { var d0 = 1, k = reFn.lastIndex; while (k < s.length && d0) { if (s[k] === '{') d0++; else if (s[k] === '}') d0--; k++; } i = k; continue; }
        reAllow.lastIndex = i; m = reAllow.exec(s);
        if (m) {
          allows++;
          var methods = m[1].split(/[\s,]+/).filter(Boolean);
          var path = shortPath(stack), cond = expand(m[2] || '', fns);
          var j2 = judge(cond, today, false), line = lineAt(s, i);
          var sev = sevFor(j2.kind, methods, path);
          var rec = { line: line, path: path, methods: methods, rule: squash(raw.split('\n').slice(line - 1, lineAt(s, reAllow.lastIndex)).join(' ')).slice(0, 240) };
          if (sev) {
            rec.severity = sev; rec.kind = j2.kind;
            rec.title = title(j2.kind, methods, path, product, j2.until);
            rec.detail = detailFor(j2.kind, path, product, isRecursive(path) && j2.kind !== 'expired', methods);
            rec.fix = fixFor(j2.kind, methods, path, product);
            findings.push(rec);
          } else if (j2.kind === 'restricted') {
            rec.title = methods.join(', ') + ' on ' + path + ' checks who is asking'; passed.push(rec);
          }
          i = reAllow.lastIndex; continue;
        }
      }
      if (c === '{') depth++;
      else if (c === '}') { if (depthAt.length && depthAt[depthAt.length - 1] === depth) { depthAt.pop(); stack.pop(); } depth--; }
      i++;
    }
    // FlutterFlow writes one match /<collection>/{document} block per collection.
    var flutterflow = product === 'Firestore' && /match\s+\/\w+\/\{document\}\s*\{/.test(s);
    if (!flutterflow) findings.forEach(function (f) { f.fix = f.fix.replace(/\n\(FlutterFlow stores[\s\S]*$/, ''); });
    return { product: product, findings: findings, passed: passed, rules: allows, flutterflow: flutterflow };
  }

  function scanRtdb(raw, today) {
    var s = stripComments(raw), obj;
    try { obj = JSON.parse(s); } catch (e) { return { product: 'Realtime Database', error: 'This looks like Realtime Database rules, but it isn\'t valid JSON: ' + e.message, findings: [], passed: [], rules: 0 }; }
    var rules = obj && obj.rules ? obj.rules : obj, findings = [], passed = [], count = 0, cursor = 0;
    function locate(key) { var at = s.indexOf('"' + key + '"', cursor); if (at < 0) return 1; cursor = at + key.length + 2; return lineAt(s, at); }
    function walk(node, path, granted) {
      if (!node || typeof node !== 'object') return;
      Object.keys(node).forEach(function (key) {
        var line = locate(key), val = node[key];
        if (key === '.read' || key === '.write') {
          count++;
          var cond = val === true ? 'true' : val === false ? 'false' : String(val);
          var j = judge(cond, today, true), methods = [key.slice(1)];
          var p = path || '/';
          var sev = sevFor(j.kind, methods, p);
          var rec = { line: line, path: p, methods: methods, rule: '"' + key + '": ' + JSON.stringify(val) };
          if (sev) {
            rec.severity = sev; rec.kind = j.kind;
            rec.title = title(j.kind, methods, p, 'Realtime Database', j.until);
            rec.detail = detailFor(j.kind, p, 'Realtime Database', j.kind !== 'expired' && j.kind !== 'closed');
            rec.fix = fixFor(j.kind, methods, p, 'Realtime Database');
            findings.push(rec);
          } else if (j.kind === 'restricted') { rec.title = key.slice(1) + ' on ' + p + ' checks who is asking'; passed.push(rec); }
        } else if (key.charAt(0) !== '.') {
          walk(val, (path || '') + '/' + key, granted);
        }
      });
    }
    walk(rules, '', false);
    return { product: 'Realtime Database', findings: findings, passed: passed, rules: count };
  }

  function scan(text, today) {
    today = today || new Date();
    var t = String(text || '').trim();
    if (!t) return { product: '', findings: [], passed: [], rules: 0 };
    var r = /^\{/.test(stripComments(t).trim()) ? scanRtdb(t, today) : scanRules(t, today);
    r.findings.sort(function (a, b) { return RANK[a.severity] - RANK[b.severity] || a.line - b.line; });
    return r;
  }

  function prompt(r) {
    if (!r.findings.length) return '';
    var file = r.product === 'Storage' ? 'storage.rules' : r.product === 'Realtime Database' ? 'database.rules.json' : 'firestore.rules';
    var lines = ['My Firebase ' + r.product + ' security rules (' + file + ') let the wrong people in. Please rewrite them so that:'];
    r.findings.forEach(function (f) {
      var w = f.methods.some(function (m) { return WRITE[m]; });
      var fix = createOnly(f.methods) && !isRecursive(f.path) ? 'only signed-in users can create, and only with their own user ID as the owner' : f.kind === 'open' && f.severity === 'medium' ? 'keep it public only if it is meant to be (no personal data), and keep writes limited' : 'only the owner can ' + (w ? 'change' : 'read') + ' their own data';
      lines.push('- line ' + f.line + ' (' + f.path + '): ' + f.title + '. Fix: ' + fix + '.');
    });
    lines.push('Rules: never use a catch-all match like {document=**} that allows access; never allow on request.auth != null alone; check request.auth.uid against the document ID or an owner field; keep public data (if any) read-only. Show me the full new file and list what each user can and cannot do after the change.');
    return lines.join('\n');
  }

  function sample(today) {
    today = today || new Date();
    var d = new Date(today.getTime() + 20 * 864e5);
    return [
      "rules_version = '2';",
      'service cloud.firestore {',
      '  match /databases/{database}/documents {',
      '    function signedIn() { return request.auth != null; }',
      '',
      '    // Added by Firebase when the database was created in test mode',
      '    match /{document=**} {',
      '      allow read, write: if request.time < timestamp.date(' + d.getUTCFullYear() + ', ' + (d.getUTCMonth() + 1) + ', ' + d.getUTCDate() + ');',
      '    }',
      '',
      '    match /users/{userId} {',
      '      allow read: if signedIn();',
      '      allow write: if signedIn() && request.auth.uid == userId;',
      '    }',
      '',
      '    match /orders/{orderId} {',
      '      allow read, write: if signedIn();',
      '    }',
      '',
      '    match /products/{productId} {',
      '      allow read;',
      '      allow write: if request.auth.token.admin == true;',
      '    }',
      '  }',
      '}'
    ].join('\n');
  }

  // What FlutterFlow deploys for a users collection on Users Collection, a new collection left on its defaults, and a chats collection on Tagged Users.
  function sampleFlutterflow() {
    return [
      "rules_version = '2';",
      '',
      'service cloud.firestore {',
      '  match /databases/{database}/documents {',
      '    match /users/{document} {',
      '      allow create: if request.auth.uid == document;',
      '      allow read: if request.auth.uid == document;',
      '      allow write: if request.auth.uid == document;',
      '      allow delete: if false;',
      '    }',
      '',
      '    match /bookings/{document} {',
      '      allow create: if true;',
      '      allow read: if true;',
      '      allow write: if false;',
      '      allow delete: if false;',
      '    }',
      '',
      '    match /chats/{document} {',
      '      allow create: if request.auth != null;',
      '      allow read: if resource.data.users.hasAny([/databases/$(database)/documents/users/$(request.auth.uid)]);',
      '      allow write: if resource.data.created_by == /databases/$(database)/documents/users/$(request.auth.uid);',
      '      allow delete: if false;',
      '    }',
      '  }',
      '}'
    ].join('\n');
  }

  var api = { scan: scan, sample: sample, sampleFlutterflow: sampleFlutterflow, prompt: prompt };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.PLFirebaseCheck = api;
})(this);

/* PatchLabs free key check (/tools/key-check). Runs only in the browser: no network, no storage.
   Detector patterns follow the key scan in the full check (PL-009, PL-010). Also loads under Node for tests. */
(function (root) {
  'use strict';

  // [id, title, pattern, severity, finding, where to revoke, value group]
  var DETECTORS = [
    ['anthropic', 'Anthropic API key', /sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{80,}/g, 'high', 'PL-009', 'https://console.anthropic.com/settings/keys'],
    ['openrouter', 'OpenRouter API key', /sk-or-v1-[a-f0-9]{64}/g, 'high', 'PL-009', 'https://openrouter.ai/settings/keys'],
    ['openai_admin', 'OpenAI admin key', /sk-admin-[A-Za-z0-9_\-]{40,}/g, 'critical', 'PL-009', 'https://platform.openai.com/settings/organization/admin-keys'],
    ['openai_project', 'OpenAI API key', /sk-proj-[A-Za-z0-9_\-]{40,}/g, 'high', 'PL-009', 'https://platform.openai.com/api-keys'],
    ['openai_svc', 'OpenAI service account key', /sk-svcacct-[A-Za-z0-9_\-]{40,}/g, 'high', 'PL-009', 'https://platform.openai.com/api-keys'],
    ['openai_legacy', 'OpenAI API key (legacy)', /\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g, 'high', 'PL-009', 'https://platform.openai.com/api-keys'],
    ['groq', 'Groq API key', /\bgsk_[A-Za-z0-9]{52}\b/g, 'high', 'PL-009', 'https://console.groq.com/keys'],
    ['replicate', 'Replicate API token', /\br8_[A-Za-z0-9]{37}\b/g, 'high', 'PL-009', 'https://replicate.com/account/api-tokens'],
    ['huggingface', 'Hugging Face token', /\bhf_[A-Za-z0-9]{34,40}\b/g, 'high', 'PL-009', 'https://huggingface.co/settings/tokens'],
    ['perplexity', 'Perplexity API key', /\bpplx-[A-Za-z0-9]{40,60}\b/g, 'high', 'PL-009', 'https://www.perplexity.ai/settings/api'],
    ['xai', 'xAI API key', /\bxai-[A-Za-z0-9]{60,100}\b/g, 'high', 'PL-009', 'https://console.x.ai'],
    ['fireworks', 'Fireworks API key', /\bfw_[A-Za-z0-9]{20,32}\b/g, 'medium', 'PL-009', 'https://fireworks.ai/account/api-keys'],
    ['elevenlabs', 'ElevenLabs API key', /\bsk_[a-f0-9]{48}\b/g, 'medium', 'PL-009', 'https://elevenlabs.io/app/settings/api-keys'],
    ['deepseek', 'DeepSeek API key', /deepseek[A-Za-z0-9_]*(?:key|token)\W{0,5}(sk-[a-f0-9]{32})/gi, 'high', 'PL-009', 'https://platform.deepseek.com/api_keys', 1],
    ['aws', 'AWS access key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g, 'critical', 'PL-009', 'https://console.aws.amazon.com/iam/home#/security_credentials'],
    ['github', 'GitHub token', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{80,}\b/g, 'critical', 'PL-009', 'https://github.com/settings/tokens'],
    ['stripe_live', 'Stripe live secret key', /\b(?:sk|rk)_live_[A-Za-z0-9]{24,}\b/g, 'critical', 'PL-009', 'https://dashboard.stripe.com/apikeys'],
    ['stripe_test', 'Stripe test secret key', /\b(?:sk|rk)_test_[A-Za-z0-9]{24,}\b/g, 'low', 'PL-009', 'https://dashboard.stripe.com/test/apikeys'],
    ['slack', 'Slack token', /\bxox[abprs]-[A-Za-z0-9\-]{10,}\b/g, 'high', 'PL-009', 'https://api.slack.com/apps'],
    ['resend', 'Resend API key', /\bre_[A-Za-z0-9]{8}_[A-Za-z0-9]{20,}\b/g, 'medium', 'PL-009', 'https://resend.com/api-keys'],
    ['sb_secret', 'Supabase secret key', /\bsb_secret_[A-Za-z0-9_\-]{20,}\b/g, 'critical', 'PL-010', 'https://supabase.com/dashboard/project/_/settings/api-keys'],
    ['pg_url', 'Postgres connection string with a password', /postgres(?:ql)?:\/\/[^:\s"'\/@]+:([^@\s"']{6,})@[^\s"']+/g, 'critical', 'PL-010', 'Supabase: Project settings > Database > Reset database password', 1],
    ['url_creds', 'Token inside a URL', /https?:\/\/[A-Za-z0-9_\-\.]+:([A-Za-z0-9_\-\.~%]{8,})@[A-Za-z0-9\.\-]+/g, 'critical', 'PL-009', 'Revoke the token, then remove it from the URL and use a credential helper', 1],
    ['private_key', 'Private key block', /-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY(?: BLOCK)?-----/g, 'critical', 'PL-009', 'Generate a new key pair and remove the old public key everywhere it is trusted'],
    ['google', 'Google API key', /\bAIza[0-9A-Za-z_\-]{35}\b/g, 'medium', 'PL-009', 'https://console.cloud.google.com/apis/credentials'],
    ['ai_named', 'AI provider key (named variable)', /\b(?:TOGETHER|MISTRAL|COHERE|VOYAGE|CEREBRAS|SAMBANOVA|DEEPINFRA|NOVITA|LANGSMITH|LANGCHAIN|HELICONE|PORTKEY|WANDB|PINECONE|WEAVIATE|TAVILY|SERPER|EXA|ASSEMBLYAI|DEEPGRAM|STABILITY|RUNWAY|LUMA|OPENAI|ANTHROPIC|GEMINI|GOOGLE_AI|GOOGLE_GENAI|GROQ|REPLICATE|HF|HUGGING_?FACE|AZURE_OPENAI)[A-Z0-9_]*(?:API_?KEY|SECRET|TOKEN)\s*[:=]\s*["']?([A-Za-z0-9_\-\.]{24,})["']?/gi, 'medium', 'PL-009', 'At the provider named in the variable', 1]
  ];

  var PLACEHOLDER = /(xxxx|your[_\-]?|example|placeholder|changeme|insert|redacted|dummy|sample|<[a-z_ ]+>|\$\{|\{\{|\.\.\.|\*{4,}|0{8,}|1234567890|abcdefghij)/i;
  var PUBLIC_VAR = /\b(VITE_|NEXT_PUBLIC_|EXPO_PUBLIC_|REACT_APP_|PUBLIC_|NUXT_PUBLIC_)[A-Z0-9_]*\s*[:=]\s*["']?$/;
  var JWT = /\beyJ[A-Za-z0-9_\-]{10,}\.(eyJ[A-Za-z0-9_\-]{10,})\.[A-Za-z0-9_\-]{10,}/g;
  var SAFE = [
    [/\bsb_publishable_[A-Za-z0-9_\-]{20,}\b/g, 'Supabase publishable key', 'Meant to be public; your row level security rules decide what it can read.'],
    [/\bpk_live_[A-Za-z0-9]{24,}\b/g, 'Stripe publishable key', 'Meant for checkout pages in the browser.'],
    [/\bpk_test_[A-Za-z0-9]{24,}\b/g, 'Stripe test publishable key', 'Test mode, meant for the browser.']
  ];

  function placeholder(v) {
    if (PLACEHOLDER.test(v)) return true;
    var core = v.replace(/^(?:[A-Za-z0-9]{1,8}[-_])+/, '');
    var seen = {}; for (var i = 0; i < core.length; i++) seen[core[i]] = 1;
    return Object.keys(seen).length <= 4;
  }

  function mask(s) { return s.length < 24 ? s.slice(0, 2) + '…' : s.slice(0, 8) + '…' + s.slice(-4); }

  function b64url(s) {
    s = s.replace(/-/g, '+').replace(/_/g, '/'); while (s.length % 4) s += '=';
    try { return typeof atob === 'function' ? atob(s) : Buffer.from(s, 'base64').toString('binary'); } catch (e) { return null; }
  }

  function lineAt(text, index) { var n = 1; for (var i = 0; i < index; i++) if (text.charCodeAt(i) === 10) n++; return n; }

  // Variable assignment just before the match, on the same line: is it one the build ships to the browser?
  function publicVar(text, index) {
    var start = text.lastIndexOf('\n', index - 1) + 1, before = text.slice(start, index);
    var m = before.match(PUBLIC_VAR); return m ? m[1] : '';
  }

  function scan(text) {
    var findings = [], safe = [], taken = [];
    var overlaps = function (a, b) { return taken.some(function (t) { return a < t[1] && b > t[0]; }); };
    var add = function (f, a, b) { taken.push([a, b]); findings.push(f); };

    // Supabase (and other) JWTs: read the role from the payload.
    var m; JWT.lastIndex = 0;
    while ((m = JWT.exec(text))) {
      var body = b64url(m[1]), claims = null;
      try { claims = body && JSON.parse(body); } catch (e) { claims = null; }
      if (!claims || typeof claims !== 'object') continue;
      var a = m.index, b = m.index + m[0].length, line = lineAt(text, a);
      var ref = claims.ref ? 'project ' + claims.ref : (claims.iss ? 'issuer ' + claims.iss : '');
      var exp = typeof claims.exp === 'number' ? ' Expires ' + new Date(claims.exp * 1000).toISOString().slice(0, 10) + '.' : '';
      taken.push([a, b]);
      if (claims.role === 'service_role') {
        var pv = publicVar(text, a);
        add({ id: 'supabase_service', title: 'Supabase service_role key' + (pv ? ' in a ' + pv + ' variable' : ''), severity: 'critical', finding: 'PL-010', line: line, masked: mask(m[0]),
          detail: 'The token says role "service_role"' + (ref ? ' for ' + ref : '') + '. It skips row level security: whoever has it can read, change and delete every row.' + (pv ? ' ' + pv + ' variables are copied into the JavaScript every visitor downloads.' : '') + exp,
          rotate: 'https://supabase.com/dashboard/project/' + (claims.ref && /^[a-z0-9]{10,30}$/.test(claims.ref) ? claims.ref : '_') + '/settings/api-keys' }, a, b);
      } else if (claims.role === 'anon') {
        safe.push({ title: 'Supabase anon key', line: line, detail: 'Role "anon"' + (ref ? ' for ' + ref : '') + '. Meant to be public; your row level security rules decide what it can read.' });
      } else if (claims.iss === 'supabase' || /supabase/.test(String(claims.iss || ''))) {
        add({ id: 'supabase_user', title: 'Supabase user session token', severity: 'medium', finding: 'PL-009', line: line, masked: mask(m[0]),
          detail: 'A signed-in user’s token (role "' + String(claims.role || 'unknown') + '"' + (ref ? ', ' + ref : '') + '). Anyone holding it acts as that user until it expires.' + exp, rotate: 'Sign the user out everywhere, or wait for it to expire' }, a, b);
      }
    }

    DETECTORS.forEach(function (d) {
      var re = new RegExp(d[2].source, d[2].flags), x;
      while ((x = re.exec(text))) {
        var value = d[6] ? x[d[6]] : x[0];
        var a = x.index, b = x.index + x[0].length;
        if (!value || overlaps(a, b) || (d[0] !== 'private_key' && placeholder(value))) continue;
        var pv = publicVar(text, a), sev = d[3];
        if (pv && sev !== 'critical' && d[0] !== 'google' && d[0] !== 'stripe_test') sev = 'critical';
        var detail = pv ? pv + ' variables are copied into the JavaScript every visitor downloads, so this key is public.' :
          d[0] === 'google' ? 'Google keys are often public on purpose (Firebase, Maps). It’s a leak if it can call Gemini or other paid APIs: restrict it to your domain and the APIs you use.' :
          d[0] === 'stripe_test' ? 'Test mode only, so no real money, but it still controls your test account. Keep it on the server.' : '';
        add({ id: d[0], title: d[1] + (pv ? ' in a ' + pv + ' variable' : ''), severity: sev, finding: pv ? 'PL-010' : d[4], line: lineAt(text, a), masked: mask(value), detail: detail, rotate: d[5] }, a, b);
      }
    });

    SAFE.forEach(function (s) {
      var re = new RegExp(s[0].source, s[0].flags), x;
      while ((x = re.exec(text))) if (!placeholder(x[0])) safe.push({ title: s[1], line: lineAt(text, x.index), detail: s[2] });
    });

    findings.sort(function (p, q) { return ['critical', 'high', 'medium', 'low'].indexOf(p.severity) - ['critical', 'high', 'medium', 'low'].indexOf(q.severity) || p.line - q.line; });
    safe.sort(function (p, q) { return p.line - q.line; });
    return { findings: findings, safe: safe };
  }

  // A made-up sample, built at run time so no key-shaped string sits in the source.
  function sample() {
    var rnd = function (n, chars) { chars = chars || 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789'; var s = ''; for (var i = 0; i < n; i++) s += chars[Math.floor(Math.random() * chars.length)]; return s; };
    var enc = function (o) { var j = JSON.stringify(o); var b = typeof btoa === 'function' ? btoa(j) : Buffer.from(j, 'binary').toString('base64'); return b.replace(/=+$/, '').replace(/\+/g, '-').replace(/\//g, '_'); };
    var ref = rnd(20, 'abcdefghijklmnopqrstuvwxyz');
    var jwt = function (role) { return enc({ alg: 'HS256', typ: 'JWT' }) + '.' + enc({ iss: 'supabase', ref: ref, role: role, iat: 1760000000, exp: 2075576000 }) + '.' + rnd(43); };
    return [
      '# .env (made-up sample)',
      'VITE_SUPABASE_URL=https://' + ref + '.supabase.co',
      'VITE_SUPABASE_ANON_KEY=' + jwt('anon'),
      'VITE_SUPABASE_SERVICE_ROLE_KEY=' + jwt('service_role'),
      'VITE_OPENAI_API_KEY=sk-proj-' + rnd(56) + 'T3BlbkFJ' + rnd(24),
      'STRIPE_PUBLISHABLE_KEY=pk_' + 'live_' + rnd(32),
      'STRIPE_SECRET_KEY=sk_' + 'test_' + rnd(32)
    ].join('\n');
  }

  var api = { scan: scan, sample: sample, mask: mask };
  if (typeof module !== 'undefined' && module.exports) module.exports = api; else root.PLKeyCheck = api;
})(this);

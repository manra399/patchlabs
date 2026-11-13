// Unit checks for the in-browser AI chat rendering check (site/static/assets/chat-check.js).  node tools/qa/chat-check.test.mjs
import { createRequire } from 'node:module';
import assert from 'node:assert/strict';
const CC = createRequire(import.meta.url)('../../site/static/assets/chat-check.js');
const kinds = r => r.findings.map(f => [f.line, f.kind, f.severity]);
const labels = r => r.passed.map(p => p.label);

// The sample: marked into dangerouslySetInnerHTML (via useMemo), rehype-raw with no sanitizer, images from any host.
const s = CC.scan(CC.sample());
assert.deepEqual(kinds(s), [[9, 'md-html', 'high'], [15, 'rehype-raw', 'high'], [3, 'image', 'medium']]);
assert.match(CC.prompt(s), /Line 9: Markdown from marked inserted as HTML with no sanitiser/);

// The guide's fix: react-markdown, skipHtml, image allowlist. Nothing flagged.
const good = CC.scan(`import ReactMarkdown from 'react-markdown';
const IMAGE_HOSTS = new Set(['yourapp.com']);
export function Reply({ text }: { text: string }) {
  return (
    <ReactMarkdown
      skipHtml
      components={{
        img: ({ src = '', alt = '' }) => IMAGE_HOSTS.has(new URL(src, location.href).hostname) ? <img src={src} alt={alt} /> : <a href={src}>{alt}</a>,
      }}
    >
      {text}
    </ReactMarkdown>
  );
}`);
assert.equal(good.findings.length, 0, JSON.stringify(good.findings));
assert.ok(labels(good).includes('skipHtml drops any HTML in the reply'));
assert.ok(labels(good).some(l => l.startsWith('react-markdown with no raw HTML plugin')));

// Plain react-markdown, no image component: only the image finding.
const plain = CC.scan(`import ReactMarkdown from "react-markdown";\nexport const R = ({ m }) => <ReactMarkdown>{m.content}</ReactMarkdown>;`);
assert.deepEqual(kinds(plain), [[1, 'image', 'medium']]);

// marked sanitised with DOMPurify: no HTML finding, image finding stays.
const pur = CC.scan(`import { marked } from "marked";\nimport DOMPurify from "dompurify";\nconst html = DOMPurify.sanitize(marked.parse(reply));\nexport default () => <div dangerouslySetInnerHTML={{ __html: html }} />;`);
assert.deepEqual(kinds(pur), [[3, 'image', 'medium']]);
assert.ok(labels(pur).includes('Sanitises HTML before inserting it'));

// Inline marked call, multi-line __html.
const inl = CC.scan(`export function B({ reply }) {\n  return <div\n    dangerouslySetInnerHTML={{\n      __html: marked(reply),\n    }} />;\n}`);
assert.equal(inl.findings[0].kind, 'md-html');
assert.equal(inl.findings[0].line, 4);

// rehype-raw followed by rehype-sanitize: fine. Sanitize before raw: flagged.
const ok2 = CC.scan(`import rehypeRaw from "rehype-raw";\nimport rehypeSanitize from "rehype-sanitize";\nconst x = <ReactMarkdown rehypePlugins={[rehypeRaw, rehypeSanitize]} components={{ img: Img }}>{t}</ReactMarkdown>;`);
assert.equal(ok2.findings.length, 0, JSON.stringify(ok2.findings));
const bad2 = CC.scan(`const x = <ReactMarkdown rehypePlugins={[rehypeSanitize, rehypeRaw]} components={{ img: Img }}>{t}</ReactMarkdown>;`);
assert.deepEqual(kinds(bad2), [[1, 'rehype-raw', 'high']]);

// Raw reply text into innerHTML: high. A fixed string and JSON-LD: not flagged. Unknown value: medium.
const dom = CC.scan(`const el = document.getElementById("out");\nel.innerHTML = data.reply;\nbox.innerHTML = "<b>Loading</b>";\nconst ld = <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(schema) }} />;\nfoo.innerHTML = tpl;`);
assert.deepEqual(kinds(dom), [[2, 'raw-html', 'high'], [5, 'raw-html', 'medium']]);

// Vue v-html and Svelte {@html} with reply text.
assert.deepEqual(kinds(CC.scan(`<template><div v-html="msg.content"></div></template>`)), [[1, 'raw-html', 'high']]);
assert.deepEqual(kinds(CC.scan(`<script>export let answer;</script>\n<p>{@html answer}</p>`)), [[2, 'raw-html', 'high']]);

// urlTransform that lets everything through.
const ut = CC.scan(`<ReactMarkdown urlTransform={(url) => url} components={{ img: Img }}>{t}</ReactMarkdown>`);
assert.deepEqual(kinds(ut), [[1, 'url', 'high']]);

// markdown-it default escapes HTML; html: true is flagged.
const md1 = CC.scan(`import MarkdownIt from "markdown-it";\nconst md = new MarkdownIt();\nel.innerHTML = md.render(reply);`);
assert.deepEqual(kinds(md1), [[2, 'image', 'medium']]);
assert.ok(labels(md1).includes('markdown-it escapes raw HTML (html option off)'));
const md2 = CC.scan(`import MarkdownIt from "markdown-it";\nconst md = new MarkdownIt({ html: true });\nel.innerHTML = md.render(reply);`);
assert.equal(md2.findings[0].kind, 'md-html');

// unified pipeline with allowDangerousHtml and no sanitizer.
const uni = CC.scan(`const out = await unified().use(remarkParse).use(remarkRehype, { allowDangerousHtml: true }).use(rehypeRaw).use(rehypeStringify).process(reply);`);
assert.ok(kinds(uni).some(k => k[1] === 'rehype-raw'));

// Comments are ignored.
const com = CC.scan(`// el.innerHTML = reply;\n/* <div dangerouslySetInnerHTML={{ __html: marked(reply) }} /> */\nexport const T = ({ reply }) => <p>{reply}</p>;`);
assert.equal(com.findings.length, 0, JSON.stringify(com.findings));
assert.equal(com.renders, false);

// Errors.
assert.ok(CC.scan('').error);
assert.ok(CC.scan('hello there this is just prose').error);

console.log('chat-check: all checks passed');

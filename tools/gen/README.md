# Page generators

Some pages are generated, so every page in a family has the same shape. The generated HTML is committed in
`site/pages/` and built like any other page by `tools/build.py`. Edit the generator (or its source files), run it,
then build. Paths are relative to the repo; run from anywhere.

| Generator | Writes | Source of truth |
|---|---|---|
| `python3 tools/gen/builders.py` | `site/pages/for/{lovable,supabase,bolt,replit,cursor}.html` | the `PAGES` dict in the script |
| `python3 tools/gen/findings.py` | `site/pages/findings/index.html`, `site/pages/findings/pl-0xx.html` | the `F` list in the script |
| `python3 tools/gen/docs/api_ref.py` | `tools/gen/docs/src/api.html` (then run `build.py` below) | the endpoint list in the script + `api-pre.html` |
| `python3 tools/gen/docs/build.py [slug …]` | `site/pages/docs/*.html` + `site/static/assets/pages/E-docs-search.json` | `tools/gen/docs/src/<slug>.html` (meta, `---`, article body); sidebar, pager, TOC and search index are built from `NAV` |
| `PL_STUDY_BATCH=… python3 tools/gen/research/report_1in4.py` | `site/pages/research/1-in-4.html` + `site/static/research/1-in-4-aggregate.csv` | `report_tpl.html` + the 9 Nov 20-app run log |

Hand-written (no generator): every other page, including `/research/methodology`, `/sample-report`, `/tools/*` and `/app/*`.

## Checking a generator before you write over pages

`PL_GEN_ROOT=<dir>` makes a generator write into `<dir>/site/...` instead of this repo, so you can diff first:

```sh
T=$(mktemp -d); mkdir -p $T/site/pages $T/site/static/assets/pages $T/site/static/research
PL_GEN_ROOT=$T python3 tools/gen/findings.py && diff -r $T/site/pages/findings site/pages/findings
```

On 10 Nov 2026 every generator reproduced the committed pages byte for byte.

## Notes

- **Docs: regenerate selectively while pages are hand-edited.** `build.py` with slugs (`python3 tools/gen/docs/build.py api faq`)
  only writes those pages (the search index always covers all of them). On 10 Nov 2026 `webhooks` and `github-action`
  were being edited by hand in `site/pages/docs/`; port those edits back into `src/webhooks.html` and
  `src/github-action.html` before running `build.py` without arguments, or it will overwrite them.
- **The 1-in-4 report needs the raw run log**, which names real apps and so stays outside the repo
  (default `/Users/manraj/co-founder/build/leakcheck/batch-20261109-1513.jsonl`; set `PL_STUDY_BATCH` to point elsewhere).
  The script asserts the published medians ($0.46, 3.5 minutes) and the 37 flagged tables, so a different log fails loudly.
  Without the log, edit `site/pages/research/1-in-4.html` and `report_tpl.html` together.
- Generated pages use shared components only; per-family CSS lives in `site/static/assets/pages/` (see `site/DESIGN.md`).

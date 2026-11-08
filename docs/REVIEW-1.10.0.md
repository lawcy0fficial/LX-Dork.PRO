# LX-Dork-Pro 1.10.0 — code review

Scope: every application source file, config, CI, Docker and docs were read in
full; the test suite (718 tests) was executed. Tests were *skimmed*, not
line-read. `rich`/`textual` could not be installed in the review environment, so
the 78 CLI/UI/TUI tests were skipped and `cli.py`/`ui.py`/`tui_pro/` behavior
below is from reading (flagged where so). Fixed items are in 1.10.1.

## Fixed in 1.10.1 (reproduced first)
| # | Area | Issue |
|---|------|-------|
| 1 | ssrf_guard | Parser differential bypass (`http://127.0.0.1\@example.com/` reached loopback) |
| 2 | ssrf_guard | DNS rebinding (documented as a known gap) — now checked on the connected peer |
| 3 | engines/ddg | Results returned as scheme-less `duckduckgo.com/l/?uddg=` wrappers (default engine) |
| 4 | cli/async | `--delay` didn't pace pagination/retries inside an engine |
| 5 | fingerprint | Case-sensitive header lookup; wrong evidence; Ghost/Laravel false positives |
| 6 | secrets/vuln | Case-sensitive header lookup |
| 7 | history | Raw-vs-normalized comparison → spurious "new" URLs / webhook spam |
| 8 | async_core | Ctrl+C discarded all results |
| 9 | engines/crtsh | Email SANs became `https://user@host` |
| 10 | notify | `<!channel>` / `@everyone` injection from result URLs |
| 11 | config | 0600 race; env keys persisted by `configure`; keys echoed |
| 12 | report | vuln hints affected score but weren't shown |
| 13 | compose | SearXNG (limiter off) published on all interfaces |

## Done in 1.11.0
Scope enforcement (#1), fetch-once (#2, 1.12.0), `--json-stdout` analyses (#3), confidence/impact severity floor (#4), watch-loop resilience + cumulative seen-set (#7), target normalization (1.13.0), more secret patterns + placeholder suppression (1.14.0), engine/worker exception isolation + slow-drip body deadline (1.14.1), option de-duplication, Python 3.10+ / CI / non-root Docker (1.14.2), soft-404 detection, diff command, filters, jitter, webhook hardening, exporter formats (1.15.0), secrets-in-JS, plugin permission checks, TUI cooperative cancel/coalesced refresh/cached findings (1.16.0; TUI Textual integration still unexecuted), +38 fingerprints / 19 vuln-hint signatures with category floors, TUI watch jobs, working theme.set (1.17.0), probe protected/error-kind/retry + redirect history fix (1.18.0), verify ignores error pages / severity-first sort / secret locations in reports / DNS-free tests / end-to-end suite (1.19.0).

## Open — recommended next
**High value**
1. **Scope enforcement** (`--scope-file`): refuse to probe/verify/secret-scan any
   host outside the program's in-scope domains. Presets like `cloud-storage`
   return third-party hosts; fetching them is an authorization problem.
2. **Fetch once**: probe/verify/fingerprint/secrets/vuln-hints/screenshot each
   re-fetch (up to 6 requests per URL). One cached `FetchedPage` feeds all.
3. **`--json-stdout`/`--json-lines` skip every analysis flag silently** (returns
   before `_maybe_*`), and the JSON drops score/findings. Emit fused findings.
4. **Separate confidence from severity.** `severity_label` is derived from a
   confidence score, so a confirmed leaked AWS key on a raw dork scores ~30
   ("medium"). Programs triage by impact; report both axes.
5. **Cap total request time** in `_cap_body` (size is capped; a slow-drip
   response still ties up a worker for `timeout` per read).
6. **Replace wkhtmltoimage/wkhtmltopdf** (archived upstream, known SSRF in the
   rendering engine — the guard can't cover subresources). Use headless Chromium
   with request interception routed through the guard.
7. `watch` loop: one uncaught exception ends an unattended run. Catch, log,
   back off, continue. Keep a cumulative seen-set so flaky engines don't re-alert.

**Correctness / quality**
- `worker()` only catches `EngineError`; `resp.json()` `ValueError`,
  `KeyError` in plugins etc. abort the whole scan (the async path handles this).
- `google-scrape` selectors (`div.g`) are probably stale — Google now requires JS
  for SERPs; verify with `doctor`. Bing Search API v7 was retired by Microsoft
  in 2025 — verify and remove or replace the `bing` engine.
- `dork`/`preset` duplicate ~35 click options; extract a shared decorator.
- Unescaped Rich markup in `print_info(info_line)`, `print_error` engine
  messages, results-table title (`[category:x]` is read as a style tag), history
  table job key, TUI job rail label. A stray `[/x]` raises `MarkupError`. *(By
  reading; not executed.)*
- Target normalization (`https://example.com/` → `example.com`) before templating.
- Secrets: JWT / `pk_live_` / Google `AIza` keys are public by design but score
  "high". Add DB connection strings, npm/Telegram/Mailgun tokens, `.env` bodies.
- Python 3.9 is EOL: raise `requires-python`, add 3.13/3.14 to CI; add ruff+mypy;
  CI `py_compile` skips `tui_pro/`; pin docker base image + searxng tag; run the
  container as non-root.

**TUI (not executed anywhere yet)**
- Cancel is cosmetic: `asyncio.to_thread(run_search_blocking)` can't be
  cancelled, so work continues after "Cancelled". Run `run_search_async`
  directly on Textual's loop (it already raises `SearchCancelled`).
- `refresh_results_table` clears + rebuilds on every streamed result (O(n²);
  cursor resets to row 0). `JobState.findings` re-sorts on every keypress.
- `--watch` jobs are modeled (`results_per_cycle`, sparkline) but never started;
  `theme.set` is a stub; screenshots go to a predictable `/tmp/lxdorkpro-screenshots`.
- TUI findings omit verify and vuln-hints (CLI parity).

**Release hygiene**
- `dist/` was built before the last TUI edits (wheel lacks `status_dot`,
  cancel, new-dork, export). Rebuild; consider PyPI Trusted Publishing.
- 1.10.0 CHANGELOG has no entry for the later TUI work.

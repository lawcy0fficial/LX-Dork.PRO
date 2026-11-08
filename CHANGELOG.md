# Changelog

All notable changes to LX-Dork-Pro are documented here.

## [1.19.0] — Integration fixes found by end-to-end testing

Every analysis flag is now exercised together, through the real CLI, against a
realistic local target with an out-of-scope second host (`tests/test_end_to_end.py`).
That surfaced problems no single-feature test could:

### Fixed
- **`--verify` no longer "confirms" error pages.** It ignored the HTTP status, so a
  404 `/gone.sql` verified at *medium* purely because the URL ends in `.sql`, and body
  signals were checked against an error page. 404/410/5xx now cap confidence at *low*
  with an explanatory note and `http_status`. 401/403 are exempt (access control is not
  absence; URL-based signals still stand).
- **Findings sort by severity first, then score.** Ordering by score alone let a
  floor-`high` finding (confirmed cloud credential) sort beneath a `low` one,
  contradicting the severity column beside it.
- **Reports say where a secret was found**: one line per distinct secret --
  "AWS Access Key ID in JavaScript file `/static/app.min.js` (`AKIA****MNOP`)" --
  covering page body, response headers and JS files, capped at 10, with remote
  values neutralised so they can't break the Markdown. The full value is never printed.
- Single-IP scopes render as `127.0.0.1`, not `127.0.0.1/32`.

### Tests
- **The suite no longer needs live DNS.** Nine original `guarded_request` tests resolved
  `example.com` for real and failed on any offline machine/CI; they now use a fixed fake
  resolver. The whole suite passes with every non-literal DNS lookup failing.
- New end-to-end suite asserts: stdout is one clean JSON document (notes go to stderr);
  the out-of-scope host receives **zero** requests; each page is fetched once across all
  analyses (jQuery and third-party scripts never requested; one soft-404 probe per
  host/dir/extension); a protected 403 admin is a lead, not dead; JS secrets are
  labelled and floor severity; soft-404 vs real-404 handled; output ordering; and the
  Markdown report carries scope, analyses, every signal and no out-of-scope host.
- Verified the built wheel: contents byte-identical to source (36/36 modules), correct
  metadata, all 13 commands run from the installed files.

## [1.18.0] — Smarter probing

### Changed
- **`--probe` distinguishes "protected" from "dead".** A 401/403 means the server
  answered and the resource very likely exists, so recon treats it as a lead. It was
  scored as dead (-10) and reported as "Probed as dead (HTTP 403)"; it now scores
  +2, is reported as *protected*, and shows as `403 [auth]` in the table with its
  own count. `alive` is unchanged (still exactly `status < 400`).
- **Failures say why**: `dns`, `refused`, `timeout`, `tls`, `reset`, `redirect_loop`,
  `invalid_url`, `blocked` (SSRF guard / scope) instead of just `ConnectionError`.
  The exception-chain walk that finds the real cause is bounded against cycles.
- **One retry on transient failures** (timeout / connection reset) so a network
  blip doesn't mark a live host dead. Guard/scope blocks are never retried.
- Probe results carry content type, length, `Server`, response time and redirect
  count, and `--json-stdout` now includes `protected` and `probe_error_kind`.
  `ProbeResult.state` summarises it (alive / protected / rate_limited / ...).

### Fixed
- **`guarded_request` never populated `response.history`** (it follows redirects by
  hand to re-check every hop). Anything reading it saw zero redirects -- including
  soft-404 detection's "both requests bounced to the same place" branch, which could
  therefore never fire. History is now attached like `requests` does.

## [1.17.0] — Wider detection, TUI watch jobs, working themes

### Added
- **~38 fingerprint signatures**: TYPO3, Craft, Strapi, PrestaShop, BigCommerce,
  Webflow, Gatsby/Hugo/Jekyll, Nuxt, SvelteKit, htmx; servers/proxies/PaaS (Caddy,
  Envoy, OpenResty, Tomcat, Jetty, Gunicorn, Uvicorn, Werkzeug, Kestrel, Passenger,
  Varnish, Akamai, Vercel, Netlify, Heroku, GitHub Pages, AWS ELB, Azure); WAFs
  (Sucuri, Imperva, F5 BIG-IP); frameworks by cookie (JSESSIONID, Symfony,
  CodeIgniter, CakePHP, Yii). Every signature has a positive and a negative test
  (e.g. a post *mentioning* Webflow or Vercel does not match).
- **12 exposure indicators** in `vuln_hints` (already visible in the unmodified
  response): directory listings, `phpinfo()`, exposed `.git/config`, Apache
  server-status, raw PHP source, GraphQL introspection, Spring Actuator index,
  open S3/Azure bucket listings, unauthenticated Elasticsearch / Jenkins / Solr.
  Plus Go and Rust panics, Spring Whitelabel, ASP.NET YSOD, and Laravel/Symfony/
  Spring-Actuator debug pages. Patterns are deliberately specific (escaped sample
  code or a mere mention doesn't match; PHP-source disclosure must start the body).
- **TUI watch jobs**: palette commands "Watch current job: every 15 min / hour /
  stop". Results accumulate across cycles with only genuinely new URLs added
  (so the sparkline and "N new result(s)" notification are real), the job sits
  IDLE between cycles, survives a failed cycle, and gives up after 5 in a row --
  matching the CLI's `--watch`. Switching it off while asleep wakes it at once.

### Changed
- **`vuln_hints` categories now drive the severity floor** (`CATEGORY_FLOOR`):
  exposed services and debug consoles are at least *high*; directory listings and
  information disclosure at least *medium*; a plain stack trace has no floor.
  Score weighting for existing categories is unchanged (a confirmed SQL error
  still outranks a debug page); only `exposed_service` gets a higher base.
- **`theme.set` in the TUI palette now does something real**: it saves the theme
  (without writing env-supplied API keys to disk) and the CLI applies a saved
  theme on its next run; an explicit `--theme` still wins. The TUI's own panes
  are not re-skinned.

**Verification note:** TUI watch/theme logic is tested under real asyncio against
stand-ins for Textual and mutation-checked (one test I first wrote was vacuous --
it passed even with the behaviour broken -- and was rewritten until the mutant
failed). Textual's real widget integration still needs a run with textual installed.

## [1.16.0] — JS secrets, plugin safety, TUI reliability

### Added
- **`--secrets-js`**: also fetch and scan each page's same-site `<script src>`
  files (up to 10; vendored libraries like jQuery/React/analytics skipped; third-party
  hosts ignored; `co.uk`-style domains handled). Implies `--secrets`. Scripts go
  through the same SSRF guard, `--scope` and fetch-once cache as the page, and
  matches are labelled with their origin (`js:/static/app.min.js`) in the table,
  reports and JSON. API keys live in the JS bundle far more often than in HTML.

### Changed
- **Plugins are refused if unsafe**: a plugin is arbitrary Python run with your
  privileges, so a world-writable plugin file or directory, or one owned by another
  non-root user, is skipped with an explanation *before* any of its code is
  imported. Group-writable is allowed. `LXDORK_PLUGINS_INSECURE=1` overrides.
  (POSIX only.)
- **TUI jobs can really be cancelled.** `run_job` now awaits `run_search_async`
  on Textual's own event loop instead of `asyncio.to_thread(run_search_blocking)`;
  previously "cancel" marked the job cancelled while a background thread kept
  querying the engines. No more `call_from_thread` marshalling.
- TUI: streamed results coalesce into one table refresh per 200 ms (was a full
  rebuild per result, O(n^2)), the cursor is restored after a rebuild instead of
  jumping to row 0, and the "why" column shows hints, soft-404 and triage tags.
- TUI state: `JobState.findings` is cached with explicit invalidation (it used
  to rebuild, rescore and re-sort everything on every access, several times per
  keypress); passive URL triage is on by default; verify and vuln-hint row
  overlays are supported (parity with the CLI).

**Verification note:** the TUI logic (cancellation, status handling, refresh
coalescing) is tested under real asyncio against stand-ins for Textual's classes,
and mutation-checked. Textual's own integration (widgets, bindings, rendering)
has still not been run -- please smoke-test `lxdorkpro tui` once with textual installed.

## [1.15.0] — Enhancement sweep

### Added
- **`--verify` soft-404 / wildcard detection** (`soft404.py`). Hosts that answer
  200 to every path "confirm" any dork trivially. After fetching a hit, verify
  requests one random non-existent sibling (same directory, same extension) and
  compares: same page (word-set similarity) or both redirected to the same place
  => `soft_404`, confidence drops to low. One extra request per unique
  host/dir/extension (memoized on the page cache); only inside the CLI pipeline.
  Surfaced in the findings table, reports and `--json-stdout`.
- **`lxdorkpro diff JOB --since 24h`** -- what's new for a saved job (by number,
  key, or unique substring), built on the cumulative first-seen map; `--gone`,
  `--plain` (pipe to httpx/nuclei), `--json`. `history` now shows job numbers.
- **More filters** (both `dork` and `preset`): `--exclude-regex`, `--ext`,
  `--exclude-ext`, `--max-per-host N`. Invalid regexes fail fast with a clear message.
- **`--jitter`** (default 0.3): each `--delay` is lengthened by a random 0-30% so
  request timing isn't machine-regular. Only ever lengthens, so `--delay` stays a
  true minimum. Both the threaded and async limiters.
- **`preset --scope-to-target`**: restrict all fetching/analysis/reporting to the
  target host(s) and subdomains without writing a scope file.
- **Exports**: `jsonl`/`ndjson` and `md`; JSON now includes `source_query` and
  `also_seen_in` (additive). CSV layout deliberately unchanged. All exports are
  written atomically.

### Fixed
- **`normalize_url` no longer treats `ref`, `referrer`, `source` as tracking
  params** -- they're real inputs on many sites, and dropping them merged
  distinct pages (`download.php?source=a.zip` vs `?source=b.zip`), silently
  losing results. More genuine tracking params are ignored instead
  (msclkid, yclid, mc_cid, _ga, igshid, ...).
- **Webhook failures no longer print the webhook URL** (a Slack/Discord webhook
  URL is the credential; `requests` embeds it in exception text).
- Webhook delivery retries transient failures (network, 429 with capped
  Retry-After, 5xx) and Discord messages are trimmed to the 2000-char limit
  instead of being rejected and lost.
- `Retry-After` is capped (60 s) and HTTP-date values are parsed; previously a
  hostile server could stall a worker for hours.
- `history` table escapes job keys (a dork containing `[/x]` would have broken
  the command permanently).

## [1.14.2] — Maintainability & project hygiene

### Changed
- **`dork` and `preset` share one option declaration** (`scan_options()`),
  replacing ~39 copy-pasted `@click.option` lines per command, so a flag can no
  longer be added to one and forgotten on the other. Verified against the
  pre-refactor code: identical option definitions (names, order, flags,
  defaults, help) and byte-identical `--help` output for both commands.
- **Python support: 3.10+** (3.9 reached end-of-life in Oct 2025). CI now tests
  3.10-3.14 and byte-compiles the whole package, including `tui_pro/`, which the
  old `py_compile lxdorkpro/*.py` glob skipped.
- **Docker image runs as an unprivileged user** (`lxdork`, uid 1000) and installs
  the package non-editably. Config volume path moved to
  `/home/lxdork/.config/lx-dork-pro` (compose updated to match; an existing
  named volume from older images is mounted at the old root path and will not
  be picked up -- re-run `lxdorkpro configure` or copy `config.json` across).
  Not built in the review environment -- please build once to confirm.

## [1.14.1] — Robustness hardening

### Fixed
- **A malformed engine response no longer aborts the scan.** A 200 carrying an
  HTML captcha/maintenance page made `resp.json()` raise `ValueError` through
  the whole run (Google, Brave, urlscan, ...). It now surfaces as that one
  engine's `EngineError`. The scan loop also survives any other unexpected
  exception from an engine or plugin, reporting it and carrying on.
  (crt.sh/Wayback keep their intentional "empty body = no results" handling.)
- **One poisoned URL no longer kills an analysis pass.** probe, verify,
  fingerprint, secrets, vuln-hints and screenshot each isolate a worker's
  exception to that URL (reported as `internal error`) instead of letting
  `future.result()` abort the pass for every other URL.
- **Slow-drip responses are bounded.** `guarded_request` takes `max_seconds`
  (default 30 s) as a total read budget. The size cap alone didn't help: a
  server sending a byte every few seconds held a worker indefinitely because
  requests' timeout is per-read. The body is now read with `read1()` so the
  deadline is checked after every network read (older urllib3 falls back to
  small `iter_content` chunks).
- Engine error text is escaped before being printed (it can embed remote content).

## [1.14.0] — URL triage, dork expansion, richer secrets & reports

### Added
- **`--triage`** (`url_triage.py`): passive URL-shape tagging -- open-redirect,
  SSRF, LFI/path-traversal, IDOR/SQLi candidates (value-aware: `?id=abc` is
  not an IDOR shape), command-injection params, secrets in query strings,
  admin/debug/API-doc/VCS paths, sensitive file extensions. Zero requests.
  Contributes at most 15 points, so it ranks but never outranks evidence.
  Shown in the findings table, reports, and `--json-stdout`.
- **`lxdorkpro expand`** (`dorkgen.py`): generate dork families from extension
  and keyword sets, `{target}` templating, `-site:` subdomain exclusions, and
  optional cross-product; deterministic, deduplicated, hard-capped.
- **10 new secret detectors**: npm, Telegram bot, Mailgun, Shopify, OpenAI,
  Anthropic, Sentry DSN, Docker registry auth, database connection strings,
  credentials in URLs.

### Changed
- **Reports now state their context**: target, engagement scope (and how many
  hits were excluded as out of scope), analyses run, and tool version, in
  Markdown, HTML and PDF. Previously the target was never passed through.
- Placeholder suppression for secrets is much stronger: template/config
  indirection and docs-style credentials no longer fire. Connection-string and
  URL-credential matches mask the password inside the match itself.
- `PUBLIC_BY_DESIGN` secret names moved to `secrets_scan` (single source of
  truth, used by the severity floor); Sentry DSN added.

## [1.13.0] — Target normalization, cumulative history

### Added
- **`normalize_target()`**: `--target`/`--targets-file`/TUI targets accept what
  people paste (`https://User@Example.com:8443/path`, `*.example.com`,
  `example.com.`) and reduce it to a bare host. Junk that would silently break
  every `site:` dork (spaces, quotes, operators like `inurl:admin`) is
  rejected with a clear error. The normalized host is used for the job key, so
  `https://example.com` and `example.com` share one history.

### Changed
- **History is cumulative.** Each job keeps a first-seen map of every
  normalized URL it has ever returned, so a URL that drops out of one run
  (engines are flaky) and reappears is no longer reported as new -- which
  previously could re-fire `--watch` notifications. Older history files are
  upgraded transparently; the map is capped at 20,000 URLs per job.
- History files are written atomically (temp file + rename).

## [1.12.0] — Fetch-once, resilient watch mode

### Added
- **`fetchcache.PageCache`**: `--verify`, `--fingerprint`, `--secrets` and
  `--check-vulns` now share one GET per URL instead of four. Goes through
  `guarded_request` (SSRF/scope/size cap), caches failures too, locks per URL
  so concurrent callers share a single fetch, and is bounded by a 200 MB LRU
  budget. The scan prints how many fetches were reused. Modules still work
  standalone (no cache argument = old behavior).

### Fixed
- **`--watch` no longer dies on one bad cycle.** An exception in a cycle is
  reported and the loop continues; it stops only after 5 consecutive failures.

## [1.11.0] — Scope enforcement, real JSON output, impact severity

### Added
- **`--scope-file` / `--scope`** (`lxdorkpro/scope.py`): restrict all fetching,
  analysis and reporting to in-scope hosts/CIDRs, with `=exact` and `!exclude`
  entries. Enforced in `ssrf_guard.is_target_allowed`, so it applies to every
  module and every redirect hop, even with `--allow-private-targets`.
- **`--json-stdout` runs analysis flags** and emits fused findings
  (`score`, `severity`, `score_breakdown`, secrets, vuln hints, technologies,
  probe). `--json-lines` now warns on stderr that analysis flags are ignored.
- Presets: `terraform-state`, `vcs-metadata`, `spring-actuator`,
  `monitoring-dashboards`, `code-hosting-leaks`, `paste-site-leaks`.

### Changed
- **Severity now has an impact floor** (`Finding.severity_floor`): a structural
  credential is at least `high`, a private key `critical`, SQL/template errors
  `medium`. Public-by-design tokens (publishable Stripe, Google `AIza`, JWT)
  don't raise it. The 0-100 score is unchanged.

## [1.10.1] — Code-review fixes (security + correctness)

Found by a full read of the 1.10.0 codebase; each item was reproduced before
fixing and has a regression test in `tests/test_regressions_1_10_1.py`.

### Security
- **SSRF guard bypass via URL-parser differential.** `http://127.0.0.1\@example.com/`
  was read as host `example.com` by `urlparse` (allowed) but connected to
  `127.0.0.1` by urllib3/requests. URLs with backslashes/control characters,
  or whose host the two parsers read differently, are now refused.
- **DNS-rebinding gap closed.** `guarded_request` now verifies the address of
  the socket it actually connected to (skipped for proxied requests and
  caller-supplied sessions). Sessions are now closed after each call.
- Slack/Discord notifications no longer let a crafted URL ping the channel
  (`<!channel>`, `@everyone`).
- `save_config` creates the file `0600` from the start; `configure` no longer
  writes env-supplied API keys to disk and no longer echoes typed keys.
- Example Telegram plugin no longer leaks the bot token in error text.
- `docker-compose.yml`: SearXNG now binds to `127.0.0.1` only.

### Fixed
- **DuckDuckGo results were unusable**: wrapper links (`//duckduckgo.com/l/?uddg=`)
  are now unwrapped (and ad redirects dropped).
- **`--delay` only paced the first request of each search**; pagination and
  retries inside scraping engines went out back-to-back. Every request is now paced.
- Fingerprinting: header matching is now case-insensitive (Cloudflare/PHP/server
  were missed), HTML evidence shows the match instead of the page start, and
  false positives removed (every WordPress site read as Ghost; Angular as Laravel).
- `--secrets`/`--check-vulns` header scans are case-insensitive.
- crt.sh email SANs no longer become `https://user@host` URLs.
- History diff compares normalized URLs (trailing slash etc. no longer "new").
- `--async-core`: Ctrl+C keeps results found so far instead of discarding them.
- Reports now list passive vuln indicators that contributed to a score.

### Not changed (see docs/REVIEW-1.10.0.md)
CLI/UI layer and the Textual TUI could not be executed in the review
environment; `--json-stdout` still skips analysis passes; TUI cancel is not
cooperative; `dist/` should be rebuilt before publishing.

## [1.10.0] — Generalized plugin system: notifiers + exporters

The plugin system (`plugins.py`) previously only discovered `BaseEngine`
subclasses. It now discovers `BaseNotifier` and `BaseExporter` subclasses
too, in the same pass over the plugins directory -- one plugin file can
define any mix of the three.

### Added
- **`notify.BaseNotifier`** + `NOTIFIER_REGISTRY` + `notify_via_plugin()`
  — a notifier plugin interface mirroring `engines.BaseEngine`'s
  `__init__(self, cfg)` pattern; reads its own credentials out of the
  config dict (e.g. a Telegram bot token) the same way a paid-API search
  engine reads its own key. `--notifiers name1,name2` fires registered
  notifiers alongside (or instead of) `--webhook`.
- **`exporter.BaseExporter`** + `EXPORTER_REGISTRY` + `export_via_plugin()`
  — same pattern for push-style exports (Jira/DefectDojo/GitHub Issues
  instead of a local file). `--export-via name` pushes results through a
  registered exporter alongside (or instead of) `--output`.
- **`examples/plugins/example_telegram_notifier.py`** and
  **`example_jira_exporter.py`** — real, working reference
  implementations (verified end-to-end through the actual plugin
  discovery mechanism, not just syntax-checked) demonstrating both new
  interfaces.
- `lxdorkpro plugins` now lists all three kinds separately.

### Changed (breaking, internal API only)
- `plugins.install_plugins_into_registry()` and `plugins.load_plugins()`
  now return a `PluginLoadResult` dataclass (`.engines`/`.notifiers`/
  `.exporters`/`.errors`/`.total_count`) instead of a bare
  `(additions, errors)` tuple. Only affects direct callers of these
  functions (i.e. code integrating with `plugins.py` itself) -- the CLI
  flags/behavior around engine plugins are unchanged.

### Fixed (found while building/testing the above)
- A plugin class with an invalid/missing `.name` produced two confusing,
  contradictory error messages ("has no valid name" *and* "no subclass
  found") instead of one, because the "was a plugin class found at all"
  flag wasn't set before the name-validation check could fail.
- `_maybe_export_via_plugin`'s first draft printed via the rich console
  (which defaults to stdout) even in `--json-stdout`/`--json-lines`
  mode -- would have silently broken those modes' "safe to pipe into
  jq" guarantee the moment `--export-via` was combined with them. Fixed
  with a `quiet` parameter routing to stderr via plain `print()` in
  those two paths, caught by a dedicated regression test before it
  shipped rather than after.
- **Click version drift**: this session's Click (8.3) removed
  `CliRunner`'s `mix_stderr` parameter entirely and changed
  `Result.output` to always be an interleaved stdout+stderr mix (was a
  stdout-only alias in older Click) -- five existing tests were silently
  relying on the old alias behavior and would have started failing (or
  worse, silently stopped catching real stdout-pollution bugs) the
  moment a warning was introduced on any of those code paths. Fixed by
  switching every JSON-stdout-purity test to `result.stdout` specifically.
- Two new plugin-dispatch tests initially used `env=` on
  `CliRunner.invoke()` to point at a temp plugins directory, which
  silently did nothing -- `plugins.PLUGINS_DIR` is resolved once at
  import time, so `env=` (which only patches `os.environ` for the
  duration of one `invoke()` call) can't retroactively change it. Fixed
  by patching `lxdorkpro.plugins.PLUGINS_DIR` directly instead --
  the same underlying issue `test_plugins.py` had already solved via
  `importlib.reload()`, now solved consistently at the CLI-test level too.
- 41 new/updated tests this pass — 575 total.

## [1.9.1] — CI static analysis + dependency scanning

- **`.github/workflows/tests.yml`** — new `security` job running `bandit`
  (SAST, medium+ severity gate) and `pip-audit` (dependency CVE scanning)
  on every push/PR, alongside the existing test matrix.
- **`pyproject.toml`** — `[tool.bandit]` scopes scanning to `lxdorkpro/`
  (excludes `tests/`/`examples/`, whose intentionally mock-y patterns
  aren't the tool's real security surface); new `security` extra
  (`pip install ".[security]"`) for `bandit`/`pip-audit`.
- **Fixed the one genuine finding a real bandit run would likely have
  caught**: a hardcoded `/tmp/lxdorkpro-screenshots` path in the TUI's
  screenshot row-action (`tui_pro/app.py`) -- not just a lint nag, a
  hardcoded shared temp path is a real (if minor) collision/race risk on
  a multi-user host and doesn't work on Windows. Replaced with
  `tempfile.gettempdir()`.
- **Added precise, auditable `# nosec B311` suppressions** at the 7 call
  sites using `random` for UA rotation / proxy selection / retry jitter --
  none of which are security-sensitive uses -- each with a one-line reason
  at the specific line, deliberately not a blanket rule, so a future
  genuine misuse of `random` for something like a token or session id
  would still be caught.
- **Honest caveat**: neither `bandit` nor `pip-audit` could actually be
  installed/run in the environment this was built in (no network access).
  A manual line-by-line pass covered the same ground this session and
  last (no shell=True/eval/exec/pickle/yaml.load, every `requests` call
  has a timeout, no weak hashes, no hardcoded secrets, no SQL string
  building) and this release's fix, but the CI workflow's first real run
  against this repo is the actual verification -- check that it's green.

## [1.9.0] — SSRF guard (security hardening pass)

A manual security self-audit (this project can't yet run bandit/pip-audit
in CI -- see the "Toward enterprise readiness" note in the README) found
the codebase itself clean (no shell=True, no eval/exec/pickle/yaml.load,
every subprocess call uses list-form args, every `requests` call already
had an explicit timeout) but surfaced one real, unaddressed gap: this tool
fetches URLs that come from search-engine indexes -- attacker-influenceable
input -- with nothing stopping a crafted indexed URL like
`http://169.254.169.254/latest/meta-data/` from being fetched by
`--probe`/`--verify`/`--fingerprint`/`--secrets`/`--screenshot` on whatever
network the scanner happens to be running on.

### Added
- **`lxdorkpro/ssrf_guard.py`** — resolves each fetch target's hostname and
  refuses private/loopback/link-local/multicast/reserved address ranges
  before any of the five fetch call sites run. Opt-out by design:
  `--allow-private-targets` exists for engagements whose scope
  legitimately includes internal address space, not as a casual bypass.
  25 dedicated tests, all DNS-mocked (see "Fixed" below for why that
  matters more than it sounds).
- Wired into `probe.py`, `verify.py`, `fingerprint.py`, `secrets_scan.py`,
  and `screenshot.py` — each now reports a clear `blocked (SSRF guard):
  <reason>` through its existing error field rather than a silent failure
  or an unguarded fetch.
- **`tests/test_probe.py`** — probe.py had no dedicated test file at all
  before this pass (a pre-existing gap, not introduced by this change);
  added 17 tests covering HEAD/GET fallback, status interpretation, and
  the new guard integration.

### Fixed (found while building the above)
- Wiring in the guard broke 4 existing tests, and diagnosing why surfaced
  a more important problem than the guard itself: several tests were
  passing only because they happened to depend on **real DNS resolution**
  against domains like `example.com`, which worked by sandbox coincidence
  rather than by design -- exactly the kind of flakiness that silently
  breaks in an offline dev machine or a network-isolated CI runner.
  Fixed by mocking `is_target_allowed` at the point of use in every
  affected test class (`test_verify.py`, `test_fingerprint.py`,
  `test_secrets_scan.py`, `test_screenshot.py`, `test_cli_scan.py`) rather
  than relying on live network -- verified by re-running the entire suite
  (555 tests) with `socket.getaddrinfo` forcibly broken, confirming zero
  hidden network dependencies anywhere in the test suite.
- `tests/test_screenshot.py`'s real end-to-end capture test used a
  `file://` URL (deliberately, to render a local fixture) which the new
  guard correctly blocks by default (no network hostname) -- fixed by
  having that specific test opt in via `allow_private=True`, rather than
  weakening the guard's default behavior.
- 46 new/updated tests this pass — 555 total.

## [1.8.1] — Report generation + TUI row-action score fusion

- **Row-action results now feed the fused score** — a single-row `p`/`f`/`s`
  check in the TUI used to update only the inspector display; it's now
  recorded via `JobState.set_row_overlay()` and folded into
  `JobState.findings` the same way a full batch run's results would be, so
  a quick check on one row actually moves that row's `confidence_score`.
- **`lxdorkpro/report.py`** (`--report-md` / `--report-html` / `--report-pdf`)
  — a bug-bounty-submission-ready report generated directly from the
  `Finding` model: executive summary table, severity-grouped sections with
  plain-English evidence per finding (the same reasoning
  `score_breakdown` carries, written for a human reader), and a prominent
  callout when any finding has exposed secrets. Markdown is the source of
  truth; HTML renders the same structure standalone-styled; PDF shells out
  to `wkhtmltopdf` (the sibling binary to `wkhtmltoimage`, already optional
  for `--screenshot-dir`) rather than adding a second heavy PDF dependency.
- 50 more unit tests (`test_report.py`, plus overlay-scoring additions to
  `test_tui_pro_state.py` and report-flag coverage in `test_cli_scan.py`)
  — 509 total.

## [1.8.0] — Pro: fused scoring, secret scanning, async core, Textual TUI

A major additive pass: nothing existing changed behavior unless you opt
into a new flag, but four substantial new capabilities were added.

### Added
- **`lxdorkpro/findings.py`** — a `Finding` model fusing preset severity,
  cross-engine corroboration, `--verify` confidence, `--fingerprint` tech
  detections, secret-scan hits, and `--probe` liveness into one auditable
  0–100 `confidence_score` per URL, with a fully traceable
  `score_breakdown`. `build_findings()`/`sort_findings()`/
  `filter_findings_by_min_score()` tie it together; rendered via
  `ui.render_findings_table` as the new "Fused Findings" summary that
  appears automatically on any scan with something to score (an analysis
  flag, or a preset/category run).
- **Severity ratings on every preset** (`presets.py`) — `critical` down to
  `info`, plus `severity_rank()`/`get_query_severity_map()` to resolve a
  query back to its preset's severity for the fusion score above.
- **Cross-engine corroboration tracking** — a duplicate URL found by a
  second engine used to just get silently dropped; it's now recorded on
  the kept result's `also_seen_in`, feeding the fusion score instead of
  being thrown away. Applies to both the thread-pool and async paths.
- **`lxdorkpro/secrets_scan.py`** (`--secrets`) — 18 structural signatures
  (AWS/GCP/Azure keys, Slack/Discord webhooks, Stripe/GitHub/GitLab
  tokens, PEM private keys, JWTs, SendGrid/Twilio/Heroku) plus
  entropy-gated generic detection for `api_key = "..."`-style
  assignments. Every match is redacted before it reaches any output.
- **`--min-score N`** — filter the fused findings table to a minimum
  score; warns rather than silently no-oping if there's nothing to score.
- **`lxdorkpro/async_core.py`** (`--async-core`) — an asyncio-native
  alternative orchestration path (adaptive per-engine delay, cooperative
  cancellation via `SearchCancelled`) that runs each engine's blocking
  `.search()` via `asyncio.to_thread` rather than requiring a rewrite of
  all 13 engines onto an async HTTP client. Opt-in; produces identical
  results to the thread-pool path (covered by a parity test).
- **Full-screen Textual TUI** (`lxdorkpro ui`, needs the optional
  `textual` package via `pip install "lx-dork-pro[tui]"`) — a persistent
  app with a job rail (multiple concurrent scan "tabs", live sparkline for
  `--watch` jobs), a streaming results table, a detail inspector, and a
  fuzzy-matched command palette (`Ctrl+P`). All decidable logic (job/
  selection state in `tui_pro/state.py`, command matching in
  `tui_pro/palette.py`, the sparkline renderer in `tui_pro/sparkline.py`)
  is dependency-free and unit tested independently of `textual` itself.
- 200 new unit tests across `test_findings.py`, `test_secrets_scan.py`,
  `test_async_core.py`, `test_tui_pro_state.py`, `test_tui_pro_palette.py`,
  `test_tui_pro_sparkline.py`, and additions to `test_presets.py`/
  `test_cli_scan.py`/a new `test_cli_ui.py` — 459 total, up from 259.

### Fixed (found while building the above)
- `_search_one` (async core) let a `KeyboardInterrupt` raised inside a
  `asyncio.to_thread`-run engine call propagate raw, producing a
  confusing "unhandled exception during shutdown" warning from
  `asyncio.run()`; now handled like any other engine-level error.
- `lxdorkpro ui`'s missing-optional-dependency message contained a
  literal `[tui]`, which `rich`'s `console.print` silently swallows as
  invalid markup unless escaped — was rendering as `lx-dork-pro` with the
  extra name missing entirely.
- `lxdorkpro ui --preset X` (no matching engine installed) checked for the
  optional `textual` dependency *before* validating `--preset`/`--target`,
  so a typo'd preset name on a machine without `textual` installed
  reported "textual isn't installed" instead of "unknown preset" —
  reordered so input validation always happens first.

## [1.7.1] — Full line-by-line code review

A complete read-through of every file in the project, requested explicitly
to catch anything the incremental development process might have missed.
Found and fixed 8 real issues, none of them crashes, all of them genuine
correctness/completeness gaps:

### Fixed
- **`ssti-params` preset dork silently degraded**: the source had
  `intext:"{{"`, but every preset query passes through `str.format()`,
  where a single `{{` is an escape sequence that collapses to one literal
  `{`. This turned a precise Jinja2-template-injection signal into
  `intext:"{"`, which matches almost any page. Fixed to `{{{{` (survives
  formatting as literal `{{`); added a regression test for this exact bug
  class plus a general unsubstituted-placeholder check across all presets.
- **`--webhook` silently never fired in `--json-stdout`/`--json-lines`
  mode**, even on a genuine new result: those code paths called
  `historymod.save_run()` directly without ever diffing against the
  previous run first, so `--watch` + a JSON output mode + `--webhook` — an
  entirely plausible automated-monitoring combination — silently did
  nothing. Fixed with a shared history-diff-then-notify helper; verified
  stdout stays pure, parseable JSON even when a notification fires.
- **`screenshot.py` docstring promised `LXDORK_SCREENSHOT_BIN` env var
  support that was never implemented** — `DEFAULT_BINARY` was a hardcoded
  literal. Implemented it for real, with tests proving both the override
  and default-fallback paths.
- **`configure` command's engine-status printout was hardcoded to 6 of 13
  engines** — a user running it would think the 7 newer engines (including
  all 4 deep-web sources) simply didn't exist. Fixed to iterate the engine
  registry dynamically.
- **Theming was incomplete**: `make_progress()`'s spinner/bar and the
  per-item progress description text were hardcoded to `cyan` regardless
  of `--theme`, so switching themes had no visible effect during an actual
  scan — only the banner/dashboard respected it. Both now pull from the
  active theme.
- **HTML report badge colors only covered the original 6 engines** — the 7
  added later all fell back to the same generic gray, unlike the terminal
  UI which has distinct colors for all 13. Added colors for all of them,
  and a test asserting every registered engine has a color and none
  collide with the fallback used for unknown/plugin engines.
- **`Dockerfile` didn't copy `README.md`** despite `pyproject.toml`
  referencing it in the `readme` field — `pip install -e .` didn't hard
  fail, but silently produced a package with empty long-description
  metadata. Reproduced the exact failure mode outside Docker to confirm,
  fixed, and reproduced again to confirm the fix populates it correctly.
- **Self-contradicting module docstring**: `engines.py` claimed "no
  scraping of live SERPs, official APIs only" while the same file contains
  6 scraping engines explicitly documented as such in their own
  docstrings. Rewritten to accurately describe all three engine
  categories (official APIs, SERP scraping, deep-web archival).

### Removed
- Two pieces of dead code found via full-file review: an unused
  `_get_html_header` helper in `fingerprint.py`, and a stale module-level
  `GRADIENT` constant in `ui.py` that snapshotted the *initial* theme at
  import time and would have silently shown the wrong colors if anything
  had ever referenced it after a `--theme` switch (nothing did — it was a
  trap for later, not an active bug).

### Added
- 7 new regression tests locking in the fixes above, bringing the total
  to 262 (from 255).

## [1.7.0] — Tech fingerprinting + screenshot capture

### Added
- **`--fingerprint`** (new `fingerprint.py`): lightweight, dependency-free
  signature matching against 27+ technologies across CMS, web server,
  language, JS framework, CDN, and analytics categories — headers, HTML
  markers, meta tags, and cookies, no full browser needed. Each detection
  carries the specific evidence that triggered it. 18 tests covering
  individual signature accuracy, multi-technology detection, unreachable
  URLs, and signature-database integrity checks.
- **`--screenshot-dir`** (new `screenshot.py`): captures a real PNG of
  each result via `wkhtmltoimage` rather than bundling a full headless
  browser (which would need a ~300MB download that can't ship with a pip
  package). Fails fast with one clear install-instruction message if the
  binary isn't on `PATH`, instead of N identical per-URL errors. 15 tests,
  including a genuine end-to-end capture test that renders a real local
  HTML file through the actual `wkhtmltoimage` binary (verified via real
  PNG magic-byte inspection, not a mock) — confirmed further by rendering
  and visually inspecting a proof screenshot outside the test suite too.
- 8 new CLI regression tests confirming both flags work through the real
  `dork`/`preset` pipeline, including one that runs a genuine screenshot
  capture through the full CLI command (not just the module in isolation).
- 36 new tests this release — 255 total, up from 219.

## [1.6.0] — Webhook notifications

### Added
- **`--webhook`** (new `notify.py` module): send a Slack/Discord/generic
  JSON notification the moment a scan finds genuinely new results relative
  to history. Auto-detects Slack vs Discord from the URL shape, or use a
  generic JSON payload for anything else (Zapier, a custom endpoint, etc).
  Pairs naturally with `--watch` for unattended continuous monitoring.
- 17 new tests: 15 for `notify.py` (payload building, webhook-kind
  detection, delivery failure handling) and 2 CLI regression tests
  confirming the exact behavior that took a fix to get right (below).

### Fixed
- Notifications initially fired on a job's very first run, since with no
  prior history *every* result trivially counts as "new." Caught this
  during manual end-to-end verification (not by a pre-written test) before
  it shipped: a webhook meant to alert on *changes* would have spammed a
  full result dump on every brand-new job's first scan. Fixed by only
  notifying when a prior run actually exists to diff against, and locked
  in with two permanent regression tests (silent on baseline run, fires
  correctly on a genuine subsequent diff).

## [1.5.0] — Deep web sources + CLI visual overhaul

### Added
- **4 "deep web" archival/intelligence engines** (13 engines total, 10 free):
  `wayback` (Wayback Machine CDX API), `commoncrawl` (Common Crawl CDX API,
  auto-resolves the latest crawl index), `crtsh` (Certificate Transparency
  log search — finds unlinked subdomains), `urlscan` (urlscan.io public
  scan search). These take a domain (via `site:` or bare) rather than a
  full dork string, and surface things live SERP scraping structurally
  cannot: removed pages, never-linked subdomains, historical snapshots.
- **Theme system** (`theme.py`, new): `--theme cyan|matrix|sunset` changes
  the banner/dashboard color palette.
- **Multi-phase animated banner**: a radar-spinner boot beat, a left-to-
  right scan-line reveal of the logo (ties the visual language to the
  tool's purpose), a gradient shimmer pass, then a boot checklist showing
  real engine/config/history counts — replaces the previous single-phase
  gradient sweep.
- **Welcome dashboard**: running bare `lxdorkpro` (no subcommand) now shows
  a status screen — which engines are configured, saved job/plugin counts,
  and ready-to-run quick-start commands — instead of just falling through
  to `--help`.
- 33 new tests this release (8 theme, 20 for the 4 new engines + domain
  parsing, 5 more CLI regression tests for the dashboard/theme wiring) —
  202 total, up from 190... [tracking note: 190 was end of 1.4.0, this
  release added 33 net new after some reorganization, landing at 202]

## [1.4.1] — PyPI publishing readiness

### Changed
- `pyproject.toml` readme field made explicit (`{file = "README.md",
  content-type = "text/markdown"}`) so the README renders correctly as
  Markdown on the PyPI project page instead of raw text — verified by
  inspecting the built wheel's `METADATA` file directly.
- Removed the placeholder `github.com/example/lx-dork-pro` URLs from
  `[project.urls]` (would have rendered as broken links on the live PyPI
  page); left commented with instructions to fill in a real repo URL.
- Added `dork`, `cli` to package keywords for discoverability.

### Added
- `PUBLISHING.md` — exact step-by-step guide for uploading to
  TestPyPI/PyPI, including account/token setup, `twine check`, and a
  clean-venv install verification step.
- Built real sdist + wheel artifacts (`dist/`) using setuptools' PEP 517
  hooks directly, then installed the actual wheel into a fresh virtual
  environment (not just this project's own working directory) and
  confirmed `lxdorkpro --version`, `lxdorkpro --help`, and
  `python -m lxdorkpro --version` all work correctly from the real
  installed package.
- Confirmed via web search that no `lx-dork-pro` project currently exists
  on PyPI (name likely available, though this should be re-checked
  immediately before publishing since names can be claimed at any time).

## [1.4.0] — Next-gen search: more engines, categorized presets, accuracy verification

### Added
- **3 new search engines**: Yandex, Mojeek, Startpage (all free, no API key)
  — total is now 9 engines (6 free, 3 paid). Each new scraping engine has a
  resilient fallback: if its known CSS selectors find nothing (markup
  changed), it degrades to generic link extraction instead of silently
  returning zero results.
- **Categorized preset library** (`presets.py` restructured): 36 dork
  presets across 9 categories ("folders") — injection, exposure, cloud,
  devops, access, web, cms, iot, secrets — up from 10 flat presets. New
  `lxdorkpro categories` command and `lxdorkpro preset --category <name>`
  to run an entire folder of presets against a target in one shot.
- **Result accuracy verification** (`--verify`, new `verify.py` module):
  fetches each result and confirms it still actually satisfies the dork's
  signals (`site:`, `inurl:`, `intitle:`, `intext:`, `ext:`/`filetype:`,
  quoted phrases), rating each high/medium/low/unreachable/unknown
  confidence. `SearchResult` gained a `source_query` field so batch runs
  (`--dork-file`, `preset`, `--category`) verify each result against the
  specific query that produced it, not a single combined dork.
- 82 new tests this release (30 for `verify.py`, 20 for the new engines,
  7 more for categorized presets, 8 more CLI regression tests) — 173 total,
  up from 91 (91 came from summing prior releases' totals as tracked here).

### Fixed
- **Regex false-positive**: the `ext:`/`filetype:` signal parser had no
  word boundary, so `intext:password` was spuriously parsed as *also*
  containing an `ext:` signal (since "ext:" is a literal substring of
  "intext:"), silently downgrading confidence scores. Caught by its own
  test suite before shipping; fixed with word-boundary regexes, applied
  defensively to all the other operator patterns too.
- **`presets` command broke silently after the categorization refactor**:
  `PRESETS[name]` changed from a list of query strings to a metadata dict,
  but the `presets` CLI command still did `len(PRESETS[name])`, which
  would report `3` (dict keys) instead of the actual query count for every
  preset. Caught before shipping by a dedicated regression test, and the
  command was rewritten to group output by category with real descriptions.
- Two smaller slip-ups caught and fixed immediately during this pass: a
  stray `@cli.command()` decorator left over from a rename, and a bad
  string-replace that deleted a line while inserting the new verify-results
  table renderer into `ui.py`.

## [1.3.1] — Refactor & polish

### Changed
- Extracted the near-duplicate ~60-line bodies of `dork` and `preset` in
  `cli.py` into a shared `ScanConfig` dataclass + `_execute_scan()` /
  `_run_with_watch()` execution path. Both commands are now thin option
  parsers that build a `ScanConfig` and delegate — JSON modes, history/
  diffing, probing, and interactive browsing can no longer drift between
  the two commands the way they could when each had its own copy.
- Added type hints to the remaining untyped signatures across the pure/
  testable modules (`filters.py`, `history.py`, `tui_commands.py`,
  `exporter.py`, `presets.py`).
- Removed two dead imports (`field` in `engines.py`, `random` in `ui.py`),
  found with a small AST-based unused-import scanner (no linter was
  available in the dev environment for this pass).

### Added
- 9 new CLI regression tests (`tests/test_cli_scan.py`) specifically
  targeting the shared scan path: JSON stdout/lines output, output-file
  writing, interactive mode, watch-mode interrupt handling, and — the
  actual point of the refactor — a test asserting `dork` and `preset`
  dedupe identically-shaped near-duplicate URLs the same way, so any
  future drift between the two commands gets caught automatically.
- 9 new tests total this release (up to 110 from 101)

### Fixed
- Two of the new regression tests initially took ~6s each because they
  exercised the real per-engine rate limiter (correct behavior, wrong
  thing for these particular tests to exercise) — fixed by passing
  `--delay 0` where only functional correctness, not timing, was under test.

## [1.3.0] — Interactive browser

### Added
- Interactive results browser: `--interactive`/`-i` on `dork`/`preset`, or
  the standalone `lxdorkpro browse results.json` command. Paginated
  navigation with commands to view full item details, open a URL in the
  default web browser, or jump between pages — instead of only a static
  table.
- Command parsing (`lxdorkpro/tui_commands.py`) is kept pure/side-effect-free
  and separate from the I/O loop (`lxdorkpro/tui.py`), following the same
  pattern as `filters.py` — 23 tests for the parser alone, 13 more for the
  full browse loop (input mocked, `webbrowser.open` call verified directly)
- 36 new tests total this release (up to 101 from 65)

## [1.2.0] — Reliability & correctness

### Added
- Automatic retry with exponential backoff + jitter on transient HTTP
  failures (429/500/502/503/504, timeouts, connection errors) across every
  engine, honoring a server's `Retry-After` header when present. Tunable
  via `max_retries` / `retry_backoff_base` in config.
- URL normalization (`lxdorkpro/normalize.py`) for smarter cross-engine
  deduplication — trailing slash, default port, query-param order, and
  known tracking params (`utm_*`, `fbclid`, `gclid`, etc.) no longer cause
  the same page to be counted twice when two engines return it differently
- 20 new tests covering retry/backoff (8) and URL normalization (12)

### Fixed
- URL normalization initially treated `https://a.com` and `https://a.com/`
  as different dedup keys (root path vs. empty path inconsistency) —
  caught by its own test suite before shipping and corrected

## [1.1.0] — Packaging & streaming

### Added
- `pyproject.toml` (PEP 621) as the canonical package definition; `setup.py` removed
- `python -m lxdorkpro` entrypoint via `__main__.py`
- `--json-lines` — stream each result as a JSON line the instant it's found,
  for real-time pipelines on large `--dork-file`/`--targets-file` batch runs
- `Dockerfile` + `docker-compose.yml` bundling LX-Dork-Pro with a self-hosted
  SearXNG instance, JSON API pre-enabled via `searxng/settings.yml`
- Custom engine plugin system (`lxdorkpro/plugins.py`) — drop a `.py` file
  with a `BaseEngine` subclass into a plugins directory and it's usable via
  `-e` immediately; `lxdorkpro plugins` lists what's loaded
- HTML report export (`-o report.html`) — dark-themed, clickable, XSS-safe
- `--json-stdout` / `--no-color` for scripting and CI pipelines
- `--filter-regex` alongside the existing substring `--filter`/`--exclude`
- 45+ unit tests (`tests/`) covering filters, presets, history/diffing,
  config, exporters, engines (mocked HTTP + real BeautifulSoup parsing),
  and the plugin loader
- GitHub Actions CI workflow running the suite across Python 3.9–3.12

### Fixed
- A `class _RateLimiter:` declaration that was accidentally dropped during
  an earlier edit, leaving its body as orphaned module-level code. It was
  syntactically valid (so `py_compile` missed it) but would have crashed on
  the first real scan. Caught by exercising the actual CLI through
  `click.testing.CliRunner`, not just import-time checks.

## [1.0.1] — Free engines

### Added
- `searxng`, `duckduckgo`, `google-scrape` — free, no-API-key engines,
  now the defaults so the tool works out of the box
- Optional proxy support (`http_proxy` / `proxy_pool`) for the scraping engines

## [1.0.0] — Concurrency & recon workflow

### Added
- Concurrent (thread-pooled) multi-engine, multi-query execution with a
  thread-safe per-engine rate limiter
- URL liveness probing (`--probe`)
- Run history + diffing — every scan is logged locally; re-running the same
  dork/preset shows exactly what's new since last time
- `--watch N` continuous monitoring mode
- Batch modes: `--dork-file`, `--targets-file`
- `lxdorkpro doctor` engine health check
- End-of-run summary panel (counts per engine, top TLDs, timing)

## [0.1.0] — Initial release

### Added
- Core CLI (`dork`, `preset`, `configure`, `banner`) built on click + rich
- Google Custom Search / Bing Web Search / Brave Search API backends
- 10 built-in recon presets (SQLi params, LFI params, exposed files, etc.)
- Animated gradient brand banner, colorized result tables
- Export to `.txt` / `.json` / `.csv`

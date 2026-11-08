# LX-Dork-Pro

Advanced multi-engine Google Dorking recon tool for bug bounty hunters and
pentesters. Beautiful animated CLI. **Works completely free, no API key
required** — official paid-tier APIs are supported as an optional add-on
for extra reliability/coverage.

See [CHANGELOG.md](CHANGELOG.md) for release history. See
[PUBLISHING.md](PUBLISHING.md) for how to publish this to PyPI.

## Pro additions (this build)

On top of the base feature set below:

- **Severity-rated presets + fused Finding scoring** — every preset now
  carries a severity (`critical`→`info`); `lxdorkpro/findings.py` fuses that
  with cross-engine corroboration, `--verify` confidence, secret hits, and
  `--probe` liveness into one auditable 0–100 score per URL (`--min-score`
  to filter), rendered as a single ranked "Fused Findings" table instead of
  four separate ones to cross-reference by hand
- **Exposed-secret scanning** (`--secrets`) — fetches each result and scans
  body/headers for AWS/GCP/Azure keys, Slack/Discord webhooks, Stripe/
  GitHub/GitLab tokens, PEM private keys, JWTs, and entropy-gated generic
  `api_key = "..."`-style secrets. Values are always redacted in output
- **Async orchestration core** (`--async-core`) — an asyncio-native
  alternative to the thread pool with an adaptive per-engine delay (backs
  off when an engine goes quiet, recovers automatically) and cooperative
  cancellation; opt-in, byte-identical results to the default path
- **Full-screen Textual TUI** (`lxdorkpro ui`) — a persistent app instead of
  one-shot commands: a job rail (run multiple scans concurrently in tabs,
  with a live sparkline for `--watch` jobs), a results table that streams in
  as findings are found, a detail inspector, and a fuzzy-matched command
  palette (`Ctrl+P`) for jumping to any preset/theme/action. Needs the
  optional `textual` package: `pip install "lx-dork-pro[tui]"`
- **Report generation** (`--report-md` / `--report-html` / `--report-pdf`) —
  a bug-bounty-submission-ready report from the fused findings: executive
  summary table, severity-grouped sections with evidence per finding, a
  secrets callout. PDF reuses the `wkhtmltopdf` binary already optional for
  screenshots (`--screenshot-dir`) rather than adding a new dependency
- **SSRF guard** (`lxdorkpro/ssrf_guard.py`) — every fetch this tool makes
  (`--probe`/`--verify`/`--fingerprint`/`--secrets`/`--screenshot`) resolves
  its target first and refuses private/loopback/link-local addresses by
  default, since dork results come from search-engine indexes and are
  attacker-influenceable input. `--allow-private-targets` opts back in for
  engagements whose scope deliberately includes internal address space.
- **Generalized plugin system** — `plugins.py` now discovers `BaseNotifier`
  and `BaseExporter` subclasses alongside the original `BaseEngine`
  support, one plugin file can define any mix of the three. `--notifiers
  name1,name2` fires custom notification channels (Telegram, PagerDuty,
  email, ...) alongside `--webhook`; `--export-via name` pushes results
  through a custom destination (Jira, DefectDojo, GitHub Issues, ...)
  alongside `--output`. See `examples/plugins/` for working references.

## Toward enterprise readiness

This is a well-tested personal/small-team recon tool. Before relying on it
for enterprise or client-facing engagements, be aware of what hasn't been
done yet:

- **CI static-analysis/dependency scanning is wired in but not yet
  execution-verified** — `.github/workflows/tests.yml` now runs `bandit`
  (SAST, medium+ severity) and `pip-audit` (dependency CVEs) on every
  push/PR, and a manual pass fixed the one genuine finding it would likely
  have caught (a hardcoded `/tmp` path in the TUI). Neither tool could
  actually be installed/run in the environment this was built in (no
  network access), so the workflow syntax is validated but the first real
  run on your repo is the true test — check that it goes green.
- **The Textual TUI (`lxdorkpro ui`) has not been execution-verified** --
  `textual` couldn't be installed in the build environment, so `tui_pro/app.py`
  is syntax-checked, not run. Install it and try it before relying on it.
- **Search-engine ToS.** The free scraping engines (Google-scrape, Yandex,
  Mojeek, Startpage, DuckDuckGo) violate those engines' terms of service to
  varying degrees. For enterprise use, prefer the official paid APIs
  (Google CSE, Bing, Brave) or make an explicit organizational decision
  about that risk.
- **No auth/RBAC/multi-tenant isolation, no secrets-vault integration**
  (API keys sit in local config) -- this is a single-operator tool, not a
  shared platform.
- **No independent third-party security review** of this codebase.

## Scope enforcement (`--scope-file` / `--scope`)

Dorks return whatever got indexed, including hosts outside your program.
Give the run a scope and nothing else is ever fetched, probed, scanned, or
reported -- enforced inside the fetch layer, so redirects can't leave it:

```bash
lxdorkpro preset --category exposure --target example.com \
    --scope "example.com,!dev.example.com" --secrets --report-md out.md
lxdorkpro dork -d 'site:example.com' --scope-file scope.txt --json-stdout --secrets
```

Syntax: `example.com` (domain + subdomains), `=www.example.com` (exact),
`!host` (exclude), CIDRs like `10.0.0.0/8`. Out-of-scope hits are still
listed and saved to history; they just never get touched. `--json-stdout` now
runs analysis flags and emits fused findings (score, severity, breakdown,
secrets, hints) instead of silently ignoring them.

## Fewer requests to the target

`--verify`, `--fingerprint`, `--secrets` and `--check-vulns` share a single
GET per URL (plus `--probe`'s HEAD), so enabling all of them costs the target
about the same as enabling one. `--watch` keeps running through a failed
cycle and stops only after 5 failures in a row.

## URL triage (`--triage`)

Passive, no-request tagging of every result by URL shape: open-redirect /
SSRF / LFI / IDOR / SQLi / command-injection **parameter candidates**, secrets
and tokens sitting in query strings, admin/debug/API-doc paths, VCS and config
directories, and backup/key/dump file extensions. Tags are leads that nudge
the fused score (capped at 15 points, so they can rank a long list but never
outrank a confirmed secret or an observed error message).

```bash
lxdorkpro preset exposed-files --target example.com --scope example.com --triage --report-md out.md
```

## Dork expansion (`expand`)

One dork only sees what the engine ranks first. `expand` generates the long
tail -- extension sets, keyword sets, subdomain exclusions -- as a plain list:

```bash
lxdorkpro expand 'site:{target} inurl:admin' --target example.com --exts @config,toml --words @dev
lxdorkpro expand 'site:example.com' --words @secrets --ops intext --exclude-subdomains www,blog -o dorks.txt
lxdorkpro dork --dork-file dorks.txt --scope example.com --triage
```

Sets: ext `@docs @config @backup @logs @keys`; words `@admin @files @secrets
@api @dev @errors`. Output is capped (`--max-queries`, default 500) and fails
loudly instead of silently truncating.

## Probing

`--probe` reports one of: alive (< 400), **protected** (401/403 -- exists but access-controlled, ranked as a lead rather than a dead link), rate-limited, server/client error, or unreachable with the reason (`dns`, `refused`, `timeout`, `tls`, `reset`, `blocked`...). Transient timeouts/resets get one retry.

## Detection coverage

`--fingerprint` recognises ~70 technologies (CMS, frameworks, servers, CDNs, WAFs); `--check-vulns` flags 40+ passive indicators already present in the response -- SQL/template errors, stack traces, debug consoles, directory listings, `phpinfo()`, exposed `.git`, open bucket listings and unauthenticated services. Each carries a severity floor, so an exposed debugger or open bucket is never ranked below its raw score.

## Secret detection

`--secrets-js` extends the scan to each page's own JavaScript bundles (same-site, vendored libraries skipped, scoped and cached like everything else).

Structural detectors for AWS/GCP/Azure/Slack/Discord/Stripe/GitHub/GitLab/npm/
Telegram/Mailgun/Shopify/SendGrid/Twilio/OpenAI/Anthropic keys, PEM private
keys, Docker registry auth, database connection strings and credentials in
URLs (the password is masked inside the match -- it never reaches output),
plus entropy-gated generic `password=`/`token=` assignments. Template
indirection (`${VAR}`, `{{ x }}`, `process.env.X`, `<your-key>`) and docs
placeholders (`user:password@localhost`) are suppressed. Public-by-design
tokens (Sentry DSN, publishable Stripe, Google `AIza`, JWT) are reported but
never raise severity.

## Soft-404 detection, `diff`, and noise control

```bash
# Is that "verified" hit real, or does the host return 200 for everything?
lxdorkpro preset exposed-files --target example.com --scope-to-target --verify --triage

# What's new since yesterday? (numbers come from `lxdorkpro history`)
lxdorkpro diff 1 --since 24h
lxdorkpro diff example.com --since 7d --plain | httpx -silent

# Cut noise before analysis
lxdorkpro dork -d 'site:example.com' --ext pdf,sql --exclude-ext jpg,png --max-per-host 5 --exclude-regex 'forum|blog'

# Less robotic pacing for scraping engines (each delay lengthened by up to 50%)
lxdorkpro dork -d 'inurl:admin' -e google-scrape --delay 3 --jitter 0.5 -o results.jsonl
```

## Features

- Multi-engine dorking run **fully concurrently** (thread pool across every
  query × engine pair), with a per-engine rate limiter so one engine never
  gets hammered while others still run in parallel
- Automatic de-duplication of URLs across engines
- **URL liveness probing** (`--probe`) — concurrently HEAD/GET-checks every
  found URL and shows you status codes, so you know what's actually live
- **Run history + diffing** — every scan is auto-logged locally; re-run the
  same dork/preset later and LX-Dork-Pro tells you exactly which URLs are
  *new* since last time (great for ongoing bug-bounty monitoring)
- **Watch mode** (`--watch N`) — re-runs a scan every N minutes and
  highlights new hits, without leaving the terminal
- **Batch modes** — run a whole file of raw dorks (`--dork-file`) or run one
  preset across many target domains at once (`--targets-file`)
- **Automatic retry with backoff** on transient failures (429/500/502/503/504,
  timeouts, connection errors), honoring `Retry-After` when a server sends one
- **Smart cross-engine deduplication** — URLs are normalized before
  comparison (trailing slash, default port, param order, tracking params
  like `utm_*`/`fbclid` all ignored), so the same page found by two engines
  in slightly different forms doesn't inflate your result count
- **Result accuracy verification** (`--verify`) — fetches each result and
  confirms it still actually matches the dork's signals (`site:`, `inurl:`,
  `intitle:`, `intext:`, `ext:`/`filetype:`, quoted phrases), rating each
  as high/medium/low/unreachable confidence — catches results a search
  engine's stale index still lists but no longer hold up in reality
- **13 search engines** (10 free, 3 paid), including 3 SERP-scraping
  engines (Yandex, Mojeek, Startpage) with resilient fallback parsing, and
  4 "deep web" archival sources (Wayback Machine, Common Crawl, crt.sh
  certificate transparency, urlscan.io) that surface removed pages and
  unlinked subdomains live search can't
- **Interactive results browser** (`--interactive` / `-i`, or standalone
  `lxdorkpro browse results.json`) — paginated navigation with commands to
  view full details, open a URL in your browser, or jump pages, instead of
  just a static table
- **Webhook notifications** (`--webhook`) — Slack/Discord/generic alert the
  moment a `--watch` scan finds something genuinely new, so you don't have
  to babysit a terminal
- **Tech fingerprinting** (`--fingerprint`) — lightweight, Wappalyzer-style
  signature matching against 27+ technologies (CMS, web server, language,
  JS framework, CDN, analytics) for every result, no heavy dependencies
- **Screenshot capture** (`--screenshot-dir`) — renders a real PNG of each
  result via `wkhtmltoimage` (a lightweight static binary, not a bundled
  headless browser), so you can visually triage a scan without opening
  every URL by hand
- **Custom engine plugins** — drop a `.py` file with a `BaseEngine`
  subclass into your plugins directory and it's usable via `-e` immediately
- `doctor` command — tests connectivity/latency of every configured engine
- End-of-run summary panel (counts per engine, top TLDs, timing)
- **Multi-phase animated banner** (radar boot beat → scan-line logo reveal
  → gradient shimmer → boot checklist) with 3 selectable color themes
  (`--theme cyan|matrix|sunset`), plus a status **dashboard** on bare
  `lxdorkpro` invocation and clean `rich`-powered result tables throughout
- **36 dork presets across 9 categories** ("folders") — injection, exposure,
  cloud, devops, access, web, cms, iot, secrets. Run a single preset with
  `--target`, or a whole category at once with `--category` (see
  `lxdorkpro categories` / `lxdorkpro presets`)
- Result filtering (`--filter` / `--exclude` / `--filter-regex`) by
  substring, regex, or TLD
- Export to `.txt` (plain URL list, pipe-friendly into other recon tools),
  `.json`, `.csv`, or a styled clickable `.html` report
- `--json-stdout` / `--json-lines` / `--no-color` for scripting, streaming,
  and CI pipelines
- Optional proxy support for the free scraping engines to reduce blocking
- Config stored once via `lxdorkpro configure`, or override via env vars
- 570+ unit tests (`tests/`) with a GitHub Actions CI workflow included
- Docker + bundled SearXNG (JSON API pre-enabled) via `docker-compose.yml`

## Install

```bash
git clone <this-repo> lx-dork-pro
cd lx-dork-pro
pip install -r requirements.txt
pip install -e .
```

This installs the `lxdorkpro` command globally in your environment (via
the `pyproject.toml` entry point). You can also run it without installing:
`python -m lxdorkpro <command>` works identically once the requirements
are installed.

## Engines

### Free, no API key (defaults)

| Engine | What it is | Notes |
|---|---|---|
| `searxng` | Open-source meta search — aggregates Google, Bing, Brave, DuckDuckGo, Yandex etc. behind one JSON API | **Recommended.** Easiest: `docker compose up -d searxng` (uses the bundled config in `searxng/settings.yml` with the JSON API already enabled — see [Docker section](#docker) below). Or point at a public instance from https://searx.space |
| `duckduckgo` | DuckDuckGo's HTML search endpoint | No setup needed, works immediately, unofficial |
| `google-scrape` | Direct Google SERP scraping | No setup needed, but Google actively rate-limits/CAPTCHAs bots — use a larger `--delay` (2-5s+) |
| `yandex` | Yandex SERP scraping | No setup needed, unofficial; falls back to generic link extraction if Yandex's markup changes |
| `mojeek` | Mojeek SERP scraping | No setup needed; Mojeek has historically been more tolerant of light automated use than Google/Bing, though this is still unofficial |
| `startpage` | Startpage SERP scraping (proxies Google with privacy protections) | No setup needed, unofficial |

**"Deep web" archival/intelligence sources** — find things live SERP
scraping structurally cannot (removed pages, unlinked subdomains,
historical snapshots). Query with `site:domain` or a bare domain; these
ignore other dork operators since they aren't SERP indexes:

| Engine | What it is | Notes |
|---|---|---|
| `wayback` | Wayback Machine (archive.org) CDX API | Official free API. Every URL ever crawled for a domain, including long-removed pages |
| `commoncrawl` | Common Crawl's petabyte-scale web index | Official free API. Auto-resolves the latest crawl index each run |
| `crtsh` | Certificate Transparency log search | Official free API. Finds subdomains that were never linked anywhere public |
| `urlscan` | urlscan.io public scan search | Free public search API. Live pages plus scan metadata (IP, server, etc.) |

These need zero configuration — `lxdorkpro dork ...` works right out
of the box using `searxng` + `duckduckgo` by default. Mix in any of the
others with `-e engine1,engine2,...`.

### Optional: official paid-tier APIs

Add these any time for more reliable, higher-volume results:

| Engine | Where to get a key | Free tier |
|---|---|---|
| `google` | https://programmablesearchengine.google.com/ + https://console.cloud.google.com/apis/credentials (enable "Custom Search API") | 100 queries/day free |
| `bing` | https://portal.azure.com/ → create a "Bing Search v7" resource | Free tier available |
| `brave` | https://brave.com/search/api/ | Free tier available |

Set them up with:

```bash
lxdorkpro configure
```

Or via environment variables instead (skips the config file):

```bash
export LXDORK_GOOGLE_API_KEY=xxxx
export LXDORK_GOOGLE_CX=xxxx
export LXDORK_BING_API_KEY=xxxx
export LXDORK_BRAVE_API_KEY=xxxx
export LXDORK_SEARXNG_URL=http://localhost:8888
```

## Usage

```bash
# Run a raw dork across all configured engines
lxdorkpro dork -d 'inurl:php?id= site:.in' -l 50

# Only specific engines (mix free + paid however you like)
lxdorkpro dork -d 'inurl:admin intitle:login' -e searxng,duckduckgo
lxdorkpro dork -d 'inurl:admin intitle:login' -e google,bing,google-scrape

# Google scraping needs breathing room to avoid getting blocked
lxdorkpro dork -d 'ext:sql site:example.com' -e google-scrape --delay 3

# Probe found URLs for liveness (HTTP status codes)
lxdorkpro dork -d 'inurl:admin site:example.com' --probe

# Batch: run a whole file of dorks
lxdorkpro dork --dork-file dorks.txt -e searxng

# Batch: run one preset across many targets
lxdorkpro preset exposed-files --targets-file domains.txt

# Watch mode: re-check every 30 minutes, alert on new URLs
lxdorkpro dork -d 'inurl:admin site:example.com' --watch 30

# Check engine health/connectivity
lxdorkpro doctor

# View past scans saved to history
lxdorkpro history

# Browse results interactively (paginated, view/open by number) instead
# of a static table
lxdorkpro dork -d 'inurl:admin site:example.com' --interactive

# Re-open a saved JSON export in the interactive browser later
lxdorkpro browse findings.json

# Filter / exclude noisy domains
lxdorkpro dork -d 'inurl:page= site:.in' --filter ".in" --exclude "wikipedia"

# Regex filter (e.g. only URLs with a numeric id param)
lxdorkpro dork -d 'inurl:page= site:.in' --filter-regex 'id=\d+'

# Save results
lxdorkpro dork -d 'ext:sql site:example.com' -o findings.json

# Use a built-in preset bundle against a target
lxdorkpro preset sqli-params --target example.com
lxdorkpro presets   # list all presets, grouped by category

# Run an entire category ("folder") of presets at once
lxdorkpro categories   # see all categories and how many presets each has
lxdorkpro preset --category exposure --target example.com

# Verify results actually still match the dork (reduces false positives
# from a stale search-engine index)
lxdorkpro dork -d 'inurl:admin intitle:"login"' --verify

# Detect the tech stack behind each result
lxdorkpro dork -d 'site:example.com' --fingerprint

# Screenshot every result (needs wkhtmltoimage on PATH)
lxdorkpro dork -d 'inurl:admin site:example.com' --screenshot-dir ./shots

# Just admire the banner
lxdorkpro banner
```

Run `lxdorkpro --help` or `lxdorkpro dork --help` for the full option list
and more examples.

## Interactive browser

`--interactive` (`-i`) on `dork`/`preset`, or the standalone `lxdorkpro browse results.json`,
opens a paginated browser instead of dumping a static table:

```
lx-dork-pro> h

Commands:
  <n> or v<n>   view full details for item n on this page
  o<n>          open item n's URL in your default web browser
  n / next      next page
  p / prev      previous page
  g<n>          jump to page n
  h / help      show this help
  q / quit      exit the browser
```

`browse` needs a `.json` export (from `-o results.json`) since that's the
only format that carries title/snippet detail — a `.txt`/`.csv` export
won't have enough to browse usefully.

## Accuracy verification

Search engine indexes can be stale — a page that matched a dork when it was
crawled may have since changed or been taken down. `--verify` fetches each
result and checks whether it *still* satisfies the dork's own signals
(`site:`, `inurl:`, `intitle:`, `intext:`, `ext:`/`filetype:`, quoted
phrases), giving each a confidence rating:

```bash
lxdorkpro dork -d 'inurl:admin intitle:"login"' --verify
```

- **high** — every signal from the dork confirmed on the live page
- **medium** — some signals confirmed, others didn't hold up
- **low** — none of the signals matched (likely a stale/irrelevant index hit)
- **unreachable** — the URL couldn't be fetched at all
- **unknown** — the dork had no checkable signals (e.g. no operators at all)

For batch runs (`--dork-file`, `preset`, `--category`) each result is
verified against the *specific* query that produced it, not lumped together
under one dork — this is heuristic pattern-matching against dork syntax,
not a formal parser, so treat it as a strong signal rather than ground truth.

## Tech fingerprinting

`--fingerprint` fetches each result and matches it against a signature
database (27+ technologies across CMS, web server, language, JS framework,
CDN, and analytics categories) — a lightweight, dependency-free approach
similar in spirit to Wappalyzer, using response headers, HTML markers, meta
tags, and cookies rather than a full browser:

```bash
lxdorkpro dork -d 'site:example.com' --fingerprint
```

Each detected technology is shown with the evidence that triggered it, so
results are auditable rather than a black box.

## Screenshot capture

`--screenshot-dir` renders a real PNG of every result — useful for visually
triaging a large scan without opening each URL by hand:

```bash
lxdorkpro dork -d 'inurl:admin site:example.com' --screenshot-dir ./shots
```

This uses [`wkhtmltoimage`](https://wkhtmltopdf.org/) (part of the
`wkhtmltopdf` project) rather than bundling a full headless browser like
Playwright, which would need a ~300MB browser download that can't ship
with a pip package. Install it with `apt install wkhtmltopdf` /
`brew install wkhtmltopdf` / the Windows installer on their site. If it's
not on `PATH`, LX-Dork-Pro warns clearly and skips screenshots rather than
failing the whole scan.

Trade-off worth knowing: `wkhtmltoimage`'s rendering engine doesn't execute
modern JS-heavy single-page apps the way a real browser does, so a
React/Vue-heavy site may screenshot as a blank page. For full JS rendering
you'd need a real headless browser instead.

## Webhook notifications

Get a Slack/Discord alert the moment a scan finds something genuinely new
— pairs naturally with `--watch` for unattended monitoring:

```bash
lxdorkpro dork -d 'inurl:admin site:example.com' --watch 30 \
    --webhook https://hooks.slack.com/services/...
```

Slack and Discord webhook URLs are auto-detected and formatted natively;
anything else gets a generic JSON payload (`{"job", "new_result_count",
"new_urls", ...}`) suitable for Zapier, a custom endpoint, etc. Only fires
on a genuine diff against a prior run — the first-ever scan of a new job
has no baseline to compare against, so it stays silent rather than
notifying about every result as "new."

## Docker

The included `docker-compose.yml` bundles LX-Dork-Pro with its own
self-hosted SearXNG instance, **JSON API pre-enabled** (via
`searxng/settings.yml` — a bare `docker run searxng/searxng` does NOT have
this on by default, so use the compose file rather than that alone):

```bash
git clone <this-repo> lx-dork-pro && cd lx-dork-pro
docker compose up -d searxng        # wait ~10s for the healthcheck to pass
docker compose run --rm lxdorkpro dork -d 'inurl:php?id= site:.in' -e searxng
docker compose run --rm lxdorkpro preset sqli-params --target example.com -e searxng
docker compose run --rm lxdorkpro doctor
```

Exported reports land in `./out` on your host (mounted into the
container). Config and history persist in a named Docker volume across
runs. If you only want the SearXNG piece and want to run `lxdorkpro`
natively instead, `docker compose up -d searxng` alone works fine —
LX-Dork-Pro on your host just needs `LXDORK_SEARXNG_URL=http://localhost:8888`.

## Custom engine plugins

Drop a `.py` file defining a `BaseEngine` subclass into your plugins
directory and LX-Dork-Pro picks it up automatically — no need to touch
`engines.py` at all:

```bash
mkdir -p ~/.config/lx-dork-pro/plugins
cp examples/plugins/example_echo.py ~/.config/lx-dork-pro/plugins/
lxdorkpro plugins                      # confirm it loaded
lxdorkpro dork -d 'test query' -e example-echo
```

See `examples/plugins/example_echo.py` for the minimal shape a plugin needs
(a `name` attribute and a `search(query, count)` method returning a list of
`SearchResult`). A broken plugin is reported as a warning, never crashes
the tool. Override the directory with `LXDORK_PLUGINS_DIR` if you'd rather
keep plugins elsewhere (e.g. checked into a team repo).

## HTML reports

Export to `.html` for a clean, dark-themed, clickable report instead of raw
JSON/CSV — handy for attaching to a bug bounty submission or sharing with a
teammate:

```bash
lxdorkpro dork -d 'site:example.com ext:sql' -o findings.html
```

## Running the tests

The core logic (filters, presets, history/diffing, config, engine parsing)
has a `unittest` suite with no special test runner needed:

```bash
pip install -r requirements.txt
python3 -m unittest discover -s tests -v
```

Engine tests mock the HTTP layer (`unittest.mock`) so they run without
hitting real APIs, but exercise the actual response-parsing code (including
real BeautifulSoup HTML parsing for the DuckDuckGo engine) so they catch
real regressions, not just interface changes.

## Automation-friendly output

For piping into other tools (`jq`, custom scripts, CI pipelines):

```bash
# Pure JSON on stdout, no banner/colors/progress noise
lxdorkpro dork -d 'site:example.com ext:sql' --json-stdout | jq '.[].url'

# Stream results live, one JSON object per line, as they're found -- great
# for huge --dork-file batch runs where you don't want to wait for the end
lxdorkpro dork --dork-file dorks.txt --json-lines | jq -c 'select(.engine=="searxng")'

# Disable all color/styling anywhere (also respects the NO_COLOR env var)
lxdorkpro --no-color dork -d 'inurl:admin site:example.com'
```

## Shell completion

LX-Dork-Pro is built on `click`, which supports shell completion out of the box:

```bash
# Bash — add to ~/.bashrc
eval "$(_LXDORKPRO_COMPLETE=bash_source lxdorkpro)"

# Zsh — add to ~/.zshrc
eval "$(_LXDORKPRO_COMPLETE=zsh_source lxdorkpro)"

# Fish — add to ~/.config/fish/completions/lxdorkpro.fish
_LXDORKPRO_COMPLETE=fish_source lxdorkpro | source
```

## Legal / ethical use

Only run dorks and recon against targets you are authorized to test
(your own assets, or in-scope bug bounty programs). Dorking surfaces
*publicly indexed* information — it does not access anything private on
its own — but always respect program scope and applicable law.

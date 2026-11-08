"""
LX-Dork-Pro — Advanced Multi-Engine Google Dorking Recon Tool
CLI entrypoint built with click + rich.
"""

import random
import re
import sys
import json
import time
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

import click
from urllib.parse import urlsplit

from . import __version__, __tool_name__
from . import ui
from .config import load_config, save_config, is_engine_configured
from .engines import get_engine, EngineError
from .exporter import export_results, export_via_plugin
from .presets import list_presets, get_preset_queries, PRESETS, list_categories, get_presets_by_category, get_category_queries, get_preset_description
from .probe import probe_urls
from .verify import verify_results
from .notify import notify_new_results, notify_via_plugin
from .fingerprint import fingerprint_results
from .screenshot import capture_results, is_available as screenshot_available
from . import history as historymod
from .filters import apply_filters
from . import plugins as pluginsmod
from .normalize import normalize_url
from . import tui
from .theme import list_themes
from .secrets_scan import scan_results as scan_secrets_results
from .vuln_hints import scan_results as scan_vuln_hint_results
from .findings import build_findings, sort_findings, filter_findings_by_min_score
from .presets import get_query_severity_map, normalize_target
from .async_core import run_search_blocking
from .scope import scope_from_sources
from .dorkgen import EXTLISTS, WORDLISTS, expand_dork, resolve_list, DEFAULT_MAX_QUERIES
from .fetchcache import PageCache
from . import ssrf_guard as ssrfmod

HELP_EPILOG = """
\b
EXAMPLES:

  Basic dork search across all configured engines:
    $ lxdorkpro dork -d 'inurl:php?id= site:.in' -l 50

  Restrict to specific engines:
    $ lxdorkpro dork -d 'inurl:admin intitle:login' -e searxng,duckduckgo

  Use a built-in recon preset against a target domain:
    $ lxdorkpro preset sqli-params --target example.com

  Run an entire category ("folder") of presets at once:
    $ lxdorkpro preset --category exposure --target example.com
    $ lxdorkpro categories   # see all available categories

  Run the same preset across many targets from a file:
    $ lxdorkpro preset exposed-files --targets-file domains.txt

  Run a batch of raw dorks from a file:
    $ lxdorkpro dork --dork-file dorks.txt -e searxng

  Probe found URLs for liveness (status codes) right after searching:
    $ lxdorkpro dork -d 'inurl:admin site:example.com' --probe

  Verify results actually still match the dork (catches stale index hits):
    $ lxdorkpro dork -d 'inurl:admin intitle:"login"' --verify

  Detect the tech stack behind each result (CMS, server, JS framework):
    $ lxdorkpro dork -d 'site:example.com' --fingerprint

  Capture a screenshot of every result (needs wkhtmltoimage on PATH):
    $ lxdorkpro dork -d 'inurl:admin site:example.com' --screenshot-dir ./shots

  Dig into archives/certificate logs for a domain (deep-web sources):
    $ lxdorkpro dork -d 'site:example.com' -e wayback,crtsh,commoncrawl,urlscan

  See what's NEW since the last time you ran this exact scan:
    $ lxdorkpro dork -d 'ext:sql site:example.com'   # auto-diffs vs last run

  Get a Slack/Discord alert when a --watch scan finds something new:
    $ lxdorkpro dork -d 'inurl:admin site:example.com' --watch 30 \
        --webhook https://hooks.slack.com/services/...

  Re-run a scan every N minutes and alert on new URLs (Ctrl+C to stop):
    $ lxdorkpro dork -d 'inurl:admin site:example.com' --watch 30

  Browse results interactively instead of just a static table:
    $ lxdorkpro dork -d 'inurl:admin site:example.com' --interactive

  Re-open a saved JSON export in the interactive browser later:
    $ lxdorkpro browse findings.json

  Save results to a file (format inferred from extension):
    $ lxdorkpro dork -d 'ext:sql site:example.com' -o findings.json

  Stream results live as JSON Lines for real-time pipelines (large scans):
    $ lxdorkpro dork --dork-file dorks.txt --json-lines | jq -c 'select(.engine=="searxng")'

  Filter results by keyword / TLD:
    $ lxdorkpro dork -d 'inurl:page= site:.in' --filter ".in" --exclude "wikipedia"

  Check which engines are reachable right now:
    $ lxdorkpro doctor

  View all past recon jobs saved to history:
    $ lxdorkpro history

  Configure optional paid API keys (one-time setup):
    $ lxdorkpro configure

\b
SUPPORTED ENGINES:
  Free, no API key required:
    searxng        Self-hosted/public meta search — aggregates Google,
                    Bing, Brave, DuckDuckGo & more via one JSON API
    duckduckgo     DuckDuckGo HTML endpoint (unofficial, no key)
    google-scrape  Direct Google SERP scraping (unofficial, no key,
                    most likely to get rate-limited — use a big --delay)
    yandex         Yandex SERP scraping (unofficial, no key)
    mojeek         Mojeek SERP scraping (unofficial, no key, historically
                    more tolerant of light automated use)
    startpage      Startpage SERP scraping (unofficial, no key)

  "Deep web" archival / intelligence sources — these find things live
  SERP scraping can't (removed pages, unlinked subdomains, historical
  snapshots). Query with `site:domain` or a bare domain; other dork
  operators are ignored since these aren't SERP indexes:
    wayback        Wayback Machine (archive.org) CDX API — every URL ever
                    crawled for a domain, including long-removed pages
    commoncrawl    Common Crawl's petabyte-scale web index (CDX API)
    crtsh          Certificate Transparency log search — finds subdomains
                    that were never linked anywhere public
    urlscan        urlscan.io public scan search — live pages + metadata

  Optional, official paid-tier APIs (need `lxdorkpro configure`):
    google         Google Programmable Search (Custom Search JSON API)
    bing           Bing Web Search API v7
    brave          Brave Search API

\b
THEMES:
  --theme cyan (default) | matrix | sunset — changes the banner/dashboard
  color palette. Try: lxdorkpro --theme matrix banner

\b
NOTE:
  Default engines are the free, no-key ones (searxng + duckduckgo), so
  the tool works out of the box. For best SearXNG coverage, use the
  bundled Docker setup (JSON API pre-enabled): docker compose up -d searxng
  (a bare `docker run searxng/searxng` does NOT enable JSON by default).
  Every dork/preset run is auto-logged to history so future runs can
  show you what's new. Disable with --no-history if you'd rather not.
  Run bare `lxdorkpro` (no subcommand) for a status dashboard.
"""


@click.group(
    context_settings={"help_option_names": ["-h", "--help"]},
    epilog=HELP_EPILOG,
    invoke_without_command=True,
)
@click.option("--no-color", is_flag=True, envvar="NO_COLOR", help="Disable all colored/styled output (for logs, CI, piping)")
@click.option("--theme", default=None, type=click.Choice(list_themes()), help="Color theme for the banner/dashboard")
@click.version_option(version=__version__, prog_name=__tool_name__)
@click.pass_context
def cli(ctx, no_color, theme):
    """
    \b
    ██╗     ██╗  ██╗      ██████╗   ██████╗  ██████╗  ██╗  ██╗
    ██║     ╚██╗██╔╝      ██╔══██╗ ██╔═══██╗ ██╔══██╗ ██║ ██╔╝
    ██║      ╚███╔╝ ───── ██║  ██║ ██║   ██║ ██████╔╝ █████╔╝
    ██║      ██╔██╗       ██║  ██║ ██║   ██║ ██╔══██╗ ██╔═██╗
    ███████╗██╔╝ ██╗      ██████╔╝ ╚██████╔╝ ██║  ██║ ██║  ██╗
    ╚══════╝╚═╝  ╚═╝      ╚═════╝   ╚═════╝  ╚═╝  ╚═╝ ╚═╝  ╚═╝

    LX-Dork-Pro — Advanced Multi-Engine Google Dorking Recon Tool

    Built for bug bounty hunters & pentesters to automate dork-based
    reconnaissance across multiple search backends with a clean,
    fast, colorized terminal UI.
    """
    if no_color:
        ui.set_no_color(True)
    if theme:
        ui.set_theme(theme)
    else:
        # A theme chosen in the TUI palette is saved to config; honour it here.
        saved = load_config(include_env=False).get("theme")
        if saved in list_themes():
            ui.set_theme(saved)

    # Load any custom engine/notifier/exporter plugins the user has
    # dropped in ~/.config/lx-dork-pro/plugins/
    plugin_result = pluginsmod.install_plugins_into_registry()
    for err in plugin_result.errors:
        ui.print_warning(f"Plugin issue: {err}")

    if ctx.invoked_subcommand is None:
        _show_welcome_dashboard(plugin_result.total_count)


def _show_welcome_dashboard(plugin_count: int = 0):
    """Landing screen for a bare `lxdorkpro` invocation -- what's configured,
    what's ready, and a few commands to try next.
    """
    from .engines import ENGINE_REGISTRY, API_KEY_ENGINES

    cfg = load_config()
    engine_status = [
        (name, is_engine_configured(cfg, name), "paid" if name in API_KEY_ENGINES else "free")
        for name in ENGINE_REGISTRY
    ]
    ui.welcome_dashboard(
        version=__version__,
        engine_status=engine_status,
        history_count=len(historymod.list_history()),
        plugin_count=plugin_count,
    )



def _banner_stats(cfg=None):
    """Real numbers for the boot checklist shown after the animated banner."""
    from .engines import ENGINE_REGISTRY, FREE_NO_KEY_ENGINES, API_KEY_ENGINES
    from .config import CONFIG_DIR
    return {
        "engine_count": len(ENGINE_REGISTRY),
        "free_count": len(FREE_NO_KEY_ENGINES),
        "paid_count": len(API_KEY_ENGINES),
        "config_path": str(CONFIG_DIR),
        "history_count": len(historymod.list_history()),
    }


@cli.command()
@click.option("--anim/--no-anim", default=True, help="Enable/disable the animated intro banner.")
def banner(anim):
    """Show the LX-Dork-Pro brand banner."""
    if anim and sys.stdout.isatty():
        ui.animated_banner(version=__version__, stats=_banner_stats())
    else:
        ui.static_banner(version=__version__)


@cli.command()
def configure():
    """Interactively set up optional paid API keys + SearXNG/proxy settings."""
    ui.static_banner(version=__version__)
    cfg = load_config(include_env=False)  # never persist env-supplied keys
    ui.print_info("Leave a field blank to keep the current value (or skip that engine).\n")

    cfg["google_api_key"] = click.prompt(
        "Google Custom Search API key", default=cfg.get("google_api_key", ""), show_default=False, hide_input=True
    ) or cfg.get("google_api_key", "")
    cfg["google_cx"] = click.prompt(
        "Google Programmable Search Engine ID (cx)", default=cfg.get("google_cx", ""), show_default=False
    ) or cfg.get("google_cx", "")
    cfg["bing_api_key"] = click.prompt(
        "Bing Web Search API key", default=cfg.get("bing_api_key", ""), show_default=False, hide_input=True
    ) or cfg.get("bing_api_key", "")
    cfg["brave_api_key"] = click.prompt(
        "Brave Search API key", default=cfg.get("brave_api_key", ""), show_default=False, hide_input=True
    ) or cfg.get("brave_api_key", "")

    ui.print_info(
        "\nSearXNG is FREE and needs no key. Easiest setup: `docker compose up -d searxng` "
        "from this repo (JSON API pre-enabled), or point at a public "
        "instance from https://searx.space\n"
    )
    cfg["searxng_url"] = click.prompt(
        "SearXNG base URL", default=cfg.get("searxng_url", "http://localhost:8888")
    )

    ui.print_info(
        "\nOptional: route the free scraping engines (duckduckgo/google-scrape) "
        "through an HTTP/SOCKS proxy to reduce rate-limiting. Leave blank to skip.\n"
    )
    cfg["http_proxy"] = click.prompt(
        "HTTP(S) proxy URL, e.g. http://127.0.0.1:8080", default=cfg.get("http_proxy", ""), show_default=False
    ) or cfg.get("http_proxy", "")

    save_config(cfg)
    ui.print_success("Configuration saved to ~/.config/lx-dork-pro/config.json")

    ui.console.print("\n[bold]Engine status:[/bold]")
    from .engines import ENGINE_REGISTRY, API_KEY_ENGINES
    for eng in ENGINE_REGISTRY:
        status = "[green]ready[/green]" if is_engine_configured(cfg, eng) else "[red]not configured[/red]"
        tag = "[dim](paid API)[/dim]" if eng in API_KEY_ENGINES else "[dim](free, no key)[/dim]"
        ui.console.print(f"  {eng:14s} {status:20s} {tag}")


@cli.command(name="expand")
@click.argument("base_dork")
@click.option("--target", default=None, help="Fills {target} in BASE_DORK and anchors --exclude-subdomains")
@click.option("--exts", default=None, help="Extensions to add as `ext:X` variants: pdf,doc or a set: @docs @config @backup @logs @keys (mixable: @docs,toml)")
@click.option("--words", default=None, help="Keywords to add as inurl:/intitle:/intext: variants: admin,login or a set: @admin @files @secrets @api @dev @errors")
@click.option("--ops", default="inurl,intitle,intext", show_default=True, help="Which operators --words expands into")
@click.option("--exclude-subdomains", default=None, help="Append -site:<label>.<target> to every query, e.g. www,blog (needs --target)")
@click.option("--cross", is_flag=True, help="Also emit every ext x keyword combination (grows fast)")
@click.option("--no-base", is_flag=True, help="Omit the unmodified base dork from the output")
@click.option("--max-queries", default=DEFAULT_MAX_QUERIES, show_default=True, help="Refuse to emit more than this many queries")
@click.option("-o", "--output", default=None, help="Write one query per line to this file (feed it to `dork --dork-file`) instead of printing")
def expand_cmd(base_dork, target, exts, words, ops, exclude_subdomains, cross, no_base, max_queries, output):
    """Expand one dork into a family of variants for the long tail.

    \b
    Examples:
      lxdorkpro expand 'site:{target} inurl:admin' --target example.com --exts @config
      lxdorkpro expand 'site:example.com' --words @secrets --ops intext -o dorks.txt
      lxdorkpro dork --dork-file dorks.txt --scope example.com --triage
    """
    try:
        if target:
            target = normalize_target(target)
        queries = expand_dork(
            base_dork, target=target,
            exts=resolve_list(exts, EXTLISTS), words=resolve_list(words, WORDLISTS),
            ops=[o.strip() for o in ops.split(",") if o.strip()],
            exclude_subdomains=[x for x in (exclude_subdomains or "").split(",")] if exclude_subdomains else None,
            include_base=not no_base, cross=cross, max_queries=max_queries,
        )
    except KeyError as e:
        ui.print_error(f"Unknown set {e}. Sets: ext {sorted(EXTLISTS)}, words {sorted(WORDLISTS)}")
        sys.exit(1)
    except ValueError as e:
        ui.print_error(str(e))
        sys.exit(1)

    if output:
        with open(output, "w", encoding="utf-8") as f:
            f.write("\n".join(queries) + "\n")
        ui.print_info(f"Wrote {len(queries)} dork(s) to {ui._esc(output)}")
    else:
        for q in queries:
            click.echo(q)  # plain stdout so it pipes cleanly


@cli.command(name="presets")
def presets_cmd():
    """List built-in dork presets, grouped by category (folder)."""
    ui.console.print("\n[bold cyan]Available presets:[/bold cyan]\n")
    for cat in list_categories():
        ui.console.print(f"[bold magenta]{cat}/[/bold magenta]")
        for name in get_presets_by_category(cat):
            meta = PRESETS[name]
            n_queries = len(meta["queries"])
            ui.console.print(f"  [bold yellow]{name}[/bold yellow]  [dim]({n_queries} queries)[/dim] -- {meta['description']}")
        ui.console.print()
    ui.console.print("Run a single preset: [bold]lxdorkpro preset <name> --target <domain>[/bold]")
    ui.console.print("Run a whole category: [bold]lxdorkpro preset --category <category> --target <domain>[/bold]\n")


@cli.command(name="categories")
def categories_cmd():
    """List preset categories ('folders') and how many presets/queries each has."""
    ui.console.print("\n[bold cyan]Preset categories:[/bold cyan]\n")
    for cat in list_categories():
        names = get_presets_by_category(cat)
        total_queries = sum(len(PRESETS[n]["queries"]) for n in names)
        ui.console.print(
            f"  [bold magenta]{cat}[/bold magenta]  [dim]({len(names)} presets, {total_queries} queries total)[/dim]"
        )
    ui.console.print("\nRun a whole category: [bold]lxdorkpro preset --category <category> --target <domain>[/bold]\n")


@cli.command()
@click.option("-e", "--engines", default=None, help="Comma-separated engines to check (default: all)")
def doctor(engines):
    """Test connectivity/health of each search engine right now."""
    from .engines import ENGINE_REGISTRY

    ui.print_info("Running a lightweight test query against each engine...\n")
    cfg = load_config()
    engines_list = [e.strip() for e in engines.split(",")] if engines else list(ENGINE_REGISTRY.keys())

    rows = []
    for name in engines_list:
        if not is_engine_configured(cfg, name):
            rows.append((name, False, "Not configured — run `lxdorkpro configure`", 0.0))
            continue
        engine = get_engine(name, cfg, timeout=cfg.get("timeout", 10))
        start = time.time()
        ok, message = engine.ping()
        latency_ms = (time.time() - start) * 1000
        rows.append((name, ok, message, latency_ms))

    ui.render_doctor_table(rows)


@cli.command(name="history")
def history_cmd():
    """List all past recon jobs saved to local history (for diffing)."""
    jobs = historymod.list_history()
    if not jobs:
        ui.print_info("No history yet — run a `dork` or `preset` scan first.")
        return
    ui.render_history_table(jobs)


@cli.command(name="diff")
@click.argument("job")
@click.option("--since", default="24h", show_default=True, help="Show URLs first seen within this window: 90m, 24h, 7d, 2w")
@click.option("--gone", "show_gone", is_flag=True, help="Also list URLs seen before but missing from the latest run")
@click.option("--plain", is_flag=True, help="Print only URLs, one per line (pipe-friendly); no headings")
@click.option("--json", "as_json", is_flag=True, help="Machine-readable output")
def diff_cmd(job, since, show_gone, plain, as_json):
    """What's new for a saved job? JOB is its number from `history`, or part of its key.

    \b
    Examples:
      lxdorkpro history
      lxdorkpro diff 1 --since 24h
      lxdorkpro diff example.com --since 7d --plain | httpx
    """
    try:
        seconds = historymod.parse_duration(since)
        found = historymod.find_job(job)
    except (ValueError, LookupError) as e:
        ui.print_error(str(e))
        sys.exit(1)
    cutoff = time.time() - seconds
    ch = historymod.changes_since(found["job_key"], cutoff)

    if as_json:
        click.echo(json.dumps({
            "job": found["job_key"], "last_run": ch["timestamp"], "since_seconds": seconds,
            "new": [{"url": u, "first_seen": ts} for u, ts in ch["new"]],
            "gone": [{"url": u, "first_seen": ts} for u, ts in ch["gone"]] if show_gone else None,
            "total_seen": ch["total_seen"],
        }, indent=2))
        return
    if plain:
        for u, _ in ch["new"]:
            click.echo(u)
        if show_gone:
            for u, _ in ch["gone"]:
                click.echo(u)
        return

    ui.print_info(f"Job: {ui._esc(found['job_key'])}")
    ui.print_info(f"{len(ch['new'])} URL(s) first seen in the last {ui._esc(since)} "
                  f"({ch['total_seen']} ever seen for this job).")
    for u, ts in ch["new"]:
        click.echo(f"  + {u}   ({time.strftime('%Y-%m-%d %H:%M', time.localtime(ts))})")
    if show_gone:
        ui.print_info(f"{len(ch['gone'])} URL(s) seen before but absent from the latest run:")
        for u, ts in ch["gone"]:
            click.echo(f"  - {u}")


@cli.command(name="browse")
@click.argument("results_file")
def browse_cmd(results_file):
    """Interactively browse results previously saved with -o results.json.

    Only JSON exports carry the title/snippet/engine detail the browser
    shows -- a .txt or .csv export won't have enough to browse usefully.
    """
    import json as jsonmod
    from .engines import SearchResult

    p = Path(results_file)
    if not p.exists():
        ui.print_error(f"File not found: {results_file}")
        sys.exit(1)

    try:
        data = jsonmod.loads(p.read_text(encoding="utf-8"))
    except (jsonmod.JSONDecodeError, OSError) as e:
        ui.print_error(f"Couldn't read '{results_file}' as JSON: {e}")
        sys.exit(1)

    if not isinstance(data, list):
        ui.print_error(f"'{results_file}' doesn't look like a JSON results export (expected a list).")
        sys.exit(1)

    results = [
        SearchResult(
            url=item.get("url", ""), title=item.get("title", ""),
            snippet=item.get("snippet", ""), engine=item.get("engine", "?"),
        )
        for item in data
    ]
    tui.browse(results)


@cli.command(name="ui")
@click.option("--preset", "preset_name", default=None, help="Launch straight into a running job for this preset (used with --target)")
@click.option("--target", default=None, help="Target domain for --preset")
def ui_cmd(preset_name, target):
    """Launch the full-screen Textual TUI: a live job rail, streaming
    results table, and detail inspector, with a command palette (Ctrl+P)
    for jumping to any preset/theme/action. Runs scans via the same
    async_core orchestration --async-core uses elsewhere.

    Requires the optional 'textual' package: pip install "lx-dork-pro[tui]"
    (or `pip install textual` directly) -- kept optional so the rest of
    the tool has no hard dependency on it.
    """
    if preset_name and preset_name not in PRESETS:
        ui.print_error(f"Unknown preset '{preset_name}'. Run `lxdorkpro presets` to see available presets.")
        sys.exit(1)
    if target:
        try:
            target = normalize_target(target)
        except ValueError as e:
            ui.print_error(str(e))
            sys.exit(1)
    if preset_name and not target:
        ui.print_error("--preset requires --target.")
        sys.exit(1)

    try:
        from .tui_pro.app import run_app
    except ImportError:
        ui.print_error(
            "The TUI needs the optional 'textual' package, which isn't installed.\n"
            "  Install it with:  pip install \"lx-dork-pro\\[tui]\"\n"
            "  (or directly:     pip install textual)"
        )
        sys.exit(1)

    run_app(initial_preset=preset_name, initial_target=target)


@cli.command(name="plugins")
def plugins_cmd():
    """List custom engine/notifier/exporter plugins currently loaded from
    the plugins directory.
    """
    result = pluginsmod.load_plugins()

    ui.console.print(f"\n[bold cyan]Plugins directory:[/bold cyan] {pluginsmod.PLUGINS_DIR}\n")

    if not result.total_count and not result.errors:
        ui.print_info(
            "No plugins found. Drop a .py file defining a BaseEngine, BaseNotifier, and/or "
            "BaseExporter subclass into that directory to add a custom engine/notifier/exporter "
            "-- see lxdorkpro/plugins.py for the format."
        )
        return

    sections = [
        ("Engines", result.engines, "-e/--engines"),
        ("Notifiers", result.notifiers, "--notifiers"),
        ("Exporters", result.exporters, "--export-via"),
    ]
    for label, additions, usage_hint in sections:
        if not additions:
            continue
        ui.console.print(f"[bold]{label}[/bold] [dim](use with {usage_hint})[/dim]")
        for name, cls in additions.items():
            ui.console.print(f"  [bold green]+[/bold green] [yellow]{name}[/yellow]  [dim]({cls.__module__})[/dim]")
        ui.console.print("")

    for err in result.errors:
        ui.print_warning(err)



class _RateLimiter:
    """Thread-safe per-engine rate limiter: ensures at least `delay` seconds
    pass between consecutive requests to the SAME engine, while still letting
    different engines run fully in parallel.
    """

    def __init__(self, delay: float, jitter: float = 0.0):
        self.delay = delay
        self.jitter = max(jitter, 0.0)
        self._lock = threading.Lock()
        self._last_call = {}

    def wait(self, engine_name: str):
        if not self.delay:
            return
        wait_for = 0
        with self._lock:
            last = self._last_call.get(engine_name, 0)
            now = time.time()
            # Jitter only ever lengthens the gap, so --delay remains a true minimum.
            gap = self.delay * (1.0 + random.uniform(0.0, self.jitter)) if self.jitter else self.delay  # nosec B311 -- timing jitter, not crypto
            wait_for = gap - (now - last)
            self._last_call[engine_name] = max(now, last) + max(wait_for, 0)
        if wait_for > 0:
            time.sleep(wait_for)


def _run_search(engines_list, queries, limit, cfg, delay, max_workers=8, quiet=False, on_result=None):
    """Run every (query, engine) pair concurrently via a thread pool, while
    rate-limiting requests per engine so a single engine isn't hammered.
    Returns a deduped list of SearchResult. When quiet=True, suppresses the
    progress bar and warning/error prints (used by --json-stdout/--json-lines
    so stdout stays pure JSON, safe to pipe into jq/other tools). When
    on_result is given, it's called with each new deduped SearchResult the
    moment it's found (used by --json-lines for true streaming output).
    """
    seen = {}  # normalized_url -> the SearchResult kept for it (so later duplicate hits can record corroboration)
    all_results = []
    limiter = _RateLimiter(delay, jitter=cfg.get("jitter", 0.0))

    tasks = [(q, e) for q in queries for e in engines_list]
    total = len(tasks)

    def worker(query, eng_name):
        if not is_engine_configured(cfg, eng_name):
            return eng_name, query, None, f"Skipping '{eng_name}': not configured."
        limiter.wait(eng_name)
        # The wait above paces the task's first request; this hook paces
        # every later request the engine makes inside the same search()
        # (pagination, retries) so --delay really is per-engine.
        first = [True]

        def throttle():
            if first[0]:
                first[0] = False
                return
            limiter.wait(eng_name)

        try:
            engine = get_engine(eng_name, dict(cfg, _throttle=throttle), timeout=cfg.get("timeout", 10))
            return eng_name, query, engine.search(query, limit), None
        except EngineError as e:
            return eng_name, query, None, str(e)
        except Exception as e:  # noqa: BLE001 -- a buggy engine/plugin must not abort the scan
            return eng_name, query, None, f"{eng_name} failed unexpectedly ({type(e).__name__}: {e})"

    def collect(future):
        eng_name, query, results, error = future.result()
        if error:
            if not quiet:
                if "not configured" in error:
                    ui.print_warning(error)
                else:
                    ui.print_error(ui._esc(error))  # error text can embed remote content
        elif results:
            for r in results:
                key = normalize_url(r.url)
                if key not in seen:
                    if not r.source_query:
                        r.source_query = query
                    seen[key] = r
                    all_results.append(r)
                    if on_result:
                        on_result(r)
                else:
                    # Same page, found again by a different engine (or the
                    # same engine on an overlapping page of results) -- not
                    # a new result, but record the corroboration rather
                    # than silently dropping the signal that engine N also
                    # independently surfaced this URL. findings.py uses
                    # this for cross-engine confidence scoring.
                    kept = seen[key]
                    if r.engine and r.engine != kept.engine and r.engine not in kept.also_seen_in:
                        kept.also_seen_in.append(r.engine)

    if quiet:
        with ThreadPoolExecutor(max_workers=max_workers) as pool:
            futures = [pool.submit(worker, q, e) for q, e in tasks]
            for future in as_completed(futures):
                collect(future)
    else:
        with ui.make_progress() as progress:
            task_id = progress.add_task("Dorking...", total=total)
            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                futures = [pool.submit(worker, q, e) for q, e in tasks]
                for future in as_completed(futures):
                    eng_name, query, _, _ = future.result()
                    accent = ui.current_theme()["accent"]
                    progress.update(task_id, description=f"[{accent}]{eng_name}[/{accent}] -> {query[:40]}")
                    collect(future)
                    progress.advance(task_id)

    return all_results


def _any_analysis(sc) -> bool:
    return bool(sc.probe or sc.verify or sc.fingerprint or sc.secrets or sc.check_vulns or sc.triage)


def finding_to_dict(f) -> dict:
    """Machine-readable form of a fused Finding (used by --json-stdout)."""
    return {
        "url": f.url, "title": f.title, "snippet": f.snippet,
        "engine": f.primary_engine, "also_seen_in": f.also_seen_in,
        "source_query": f.source_query,
        "score": f.confidence_score, "severity": f.severity_label,
        "score_breakdown": f.score_breakdown,
        "preset_severity": f.preset_severity,
        "verify": f.verify_confidence,
        "soft_404": f.soft_404,
        "technologies": f.technologies,
        "secrets": [{"name": s.name, "category": s.category, "redacted": s.redacted,
                     "location": s.location, "confidence": s.confidence} for s in f.secrets],
        "triage": [{"name": t.name, "kind": t.kind, "evidence": t.evidence} for t in f.triage],
        "vuln_hints": [{"name": h.name, "category": h.category, "evidence": h.evidence,
                        "location": h.location} for h in f.vuln_hints],
        "probe_status": f.probe_status, "alive": f.probe_alive,
        "protected": f.probe_protected, "probe_error_kind": f.probe_error_kind,
    }


def _quiet_analyses(results, sc):
    """Run the requested analysis passes with no rich output (stdout must stay
    pure JSON) and return the scored, sorted, --min-score-filtered Findings."""
    ap = sc.allow_private_targets
    pc = PageCache()
    probe_r = probe_urls([r.url for r in results], workers=sc.probe_workers, allow_private=ap) if sc.probe else None
    verify_r = verify_results(results, dork=None, workers=sc.verify_workers, allow_private=ap, cache=pc) if sc.verify else None
    fp_r = fingerprint_results(results, workers=sc.fingerprint_workers, allow_private=ap, cache=pc) if sc.fingerprint else None
    sec_r = scan_secrets_results(results, workers=sc.secrets_workers, allow_private=ap, cache=pc, include_js=sc.secrets_js) if sc.secrets else None
    vul_r = scan_vuln_hint_results(results, workers=sc.vuln_workers, allow_private=ap, cache=pc) if sc.check_vulns else None
    findings = sort_findings(build_findings(
        results, verify_results=verify_r, fingerprint_results=fp_r, secret_results=sec_r,
        vuln_hint_results=vul_r, probe_results=probe_r, severity_map=sc.severity_map, triage=sc.triage,
    ))
    if sc.min_score is not None:
        findings = filter_findings_by_min_score(findings, sc.min_score)
    return findings


def _print_json_stdout(results):
    """Print raw JSON to stdout only -- no rich, no color, no banner, no
    warnings mixed in. Safe to pipe: `lxdorkpro dork -d '...' --json-stdout | jq .`
    """
    payload = [{"url": r.url, "title": r.title, "snippet": r.snippet, "engine": r.engine} for r in results]
    print(json.dumps(payload, indent=2))


def _print_json_line(result):
    """Print one SearchResult as a single JSON line (JSON Lines format).
    Called live as each result is found -- used by --json-lines for
    real-time streaming into `jq -c`, log pipelines, or other tools that
    consume newline-delimited JSON without waiting for the whole scan.
    """
    line = json.dumps({"url": result.url, "title": result.title, "snippet": result.snippet, "engine": result.engine})
    print(line, flush=True)


def _apply_filters(results, filter_str, exclude_str, filter_regex=None, exclude_regex=None,
                   include_ext=None, exclude_ext=None, max_per_host=None):
    return apply_filters(results, filter_str, exclude_str, filter_regex, exclude_regex,
                         include_ext, exclude_ext, max_per_host)


def _scan_filters(sc, results):
    return _apply_filters(results, sc.filter_str, sc.exclude_str, sc.filter_regex, sc.exclude_regex,
                          sc.include_ext, sc.exclude_ext, sc.max_per_host)


def _validate_regexes(sc):
    """Fail fast with a clear message instead of a traceback after a long scan."""
    for flag, pattern in (("--filter-regex", sc.filter_regex), ("--exclude-regex", sc.exclude_regex)):
        if pattern:
            try:
                re.compile(pattern)
            except re.error as e:
                ui.print_error(f"Invalid regex for {flag}: {ui._esc(e)}")
                sys.exit(1)


def _maybe_probe(results, do_probe, workers=20, allow_private=False):
    """Returns the raw ProbeResult list (or None if skipped) in addition to
    rendering the table, so _execute_scan can feed it into build_findings
    for the fused score without re-running the probe a second time.
    """
    if not do_probe or not results:
        return None
    ui.print_info(f"Probing {len(results)} URL(s) for liveness...")
    with ui.make_progress() as progress:
        task_id = progress.add_task("Probing...", total=len(results))

        def cb(done, total):
            progress.update(task_id, completed=done)

        probe_results = probe_urls([r.url for r in results], workers=workers, progress_cb=cb, allow_private=allow_private)
    ui.render_probe_table(probe_results)
    return probe_results


def _maybe_verify(results, do_verify, workers=10, allow_private=False, cache=None):
    """Returns the raw VerifyResult list (or None if skipped) -- see
    _maybe_probe's docstring for why.
    """
    if not do_verify or not results:
        return None
    ui.print_info(f"Verifying {len(results)} result(s) against their dork's signals...")
    with ui.make_progress() as progress:
        task_id = progress.add_task("Verifying...", total=len(results))

        def cb(done, total):
            progress.update(task_id, completed=done)

        verify_results_list = verify_results(results, dork=None, workers=workers, progress_cb=cb, allow_private=allow_private, cache=cache)
    ui.render_verify_table(verify_results_list)
    return verify_results_list


def _maybe_fingerprint(results, do_fingerprint, workers=10, allow_private=False, cache=None):
    """Returns the raw FingerprintResult list (or None if skipped) -- see
    _maybe_probe's docstring for why.
    """
    if not do_fingerprint or not results:
        return None
    ui.print_info(f"Fingerprinting {len(results)} result(s) for technology stack...")
    with ui.make_progress() as progress:
        task_id = progress.add_task("Fingerprinting...", total=len(results))

        def cb(done, total):
            progress.update(task_id, completed=done)

        fp_results = fingerprint_results(results, workers=workers, progress_cb=cb, allow_private=allow_private, cache=cache)
    ui.render_fingerprint_table(fp_results)
    return fp_results


def _maybe_scan_secrets(results, do_secrets, workers=10, allow_private=False, cache=None, include_js=False):
    """Fetch + regex/entropy-scan each result for exposed credentials.
    Returns a {url: [SecretMatch, ...]} dict (or None if skipped) -- the
    exact shape findings.build_findings(secret_results=...) expects.
    """
    if not do_secrets or not results:
        return None
    ui.print_info(f"Scanning {len(results)} result(s) for exposed secrets/credentials...")
    with ui.make_progress() as progress:
        task_id = progress.add_task("Scanning for secrets...", total=len(results))

        def cb(done, total):
            progress.update(task_id, completed=done)

        secret_map = scan_secrets_results(results, workers=workers, progress_cb=cb, allow_private=allow_private, cache=cache, include_js=include_js)
    ui.render_secrets_table(secret_map, total_scanned=len(results))
    return secret_map


def _maybe_scan_vuln_hints(results, do_check_vulns, workers=10, allow_private=False, cache=None):
    """Fetch each result exactly as given (no parameters added or changed)
    and passively scan its body/headers for SQL/template-engine error
    signatures and debug-console pages -- see vuln_hints.py's module
    docstring for exactly what this does and, more importantly, doesn't
    do: it never sends an injection payload or varies a parameter, so a
    hit here means the target's own ordinary response already leaked
    something, not that this tool proved anything by poking it. Every hit
    is a "verify manually" lead, same posture as --secrets' entropy-gated
    generic matches.

    Returns a {url: [VulnHint, ...]} dict (or None if skipped) -- the
    exact shape findings.build_findings(vuln_hint_results=...) expects.
    """
    if not do_check_vulns or not results:
        return None
    ui.print_info(f"Scanning {len(results)} result(s) for SQL/template-error and debug-console disclosures...")
    with ui.make_progress() as progress:
        task_id = progress.add_task("Scanning for vuln indicators...", total=len(results))

        def cb(done, total):
            progress.update(task_id, completed=done)

        vuln_hint_map = scan_vuln_hint_results(results, workers=workers, progress_cb=cb, allow_private=allow_private, cache=cache)
    ui.render_vuln_hints_table(vuln_hint_map, total_scanned=len(results))
    return vuln_hint_map


def _maybe_screenshot(results, screenshot_dir, workers=4, allow_private=False):
    """Returns the raw ScreenshotResult list (or None if skipped/
    unavailable) -- see _maybe_probe's docstring for why.
    """
    if not screenshot_dir or not results:
        return None
    if not screenshot_available():
        ui.print_warning(
            "--screenshot-dir given but 'wkhtmltoimage' isn't installed. "
            "Install wkhtmltopdf (provides wkhtmltoimage) to enable screenshots, e.g. "
            "`apt install wkhtmltopdf` / `brew install wkhtmltopdf`."
        )
        return None
    ui.print_info(f"Capturing {len(results)} screenshot(s) to {screenshot_dir}...")
    with ui.make_progress() as progress:
        task_id = progress.add_task("Capturing...", total=len(results))

        def cb(done, total):
            progress.update(task_id, completed=done)

        shot_results = capture_results(results, screenshot_dir, workers=workers, progress_cb=cb, allow_private=allow_private)
    ui.render_screenshot_table(shot_results)
    return shot_results


def _maybe_render_findings(
    results, severity_map, probe_results, verify_results_list, fp_results, secret_map, vuln_hint_map,
    screenshot_results, min_score, triage=False,
):
    """Fuse whichever analyses actually ran into one scored Finding per
    URL and render the ranked summary -- the single "is this worth my
    time" table that replaces mentally cross-referencing four separate
    ones. Only runs at all if at least one analysis (or a preset severity
    map) produced something to fuse; a plain `dork` run with none of
    --probe/--verify/--fingerprint/--secrets/--check-vulns and no preset
    behind it has nothing to score, so this silently does nothing rather
    than rendering an empty/meaningless table.

    `screenshot_results` deliberately does NOT count toward
    have_any_signal below: a screenshot path doesn't score anything (see
    findings.Finding.screenshot_path -- it's pure display enrichment, not
    a score_breakdown component), so --screenshot-dir run by itself still
    correctly renders no findings table. But whenever the table DOES
    render for some other reason, any screenshots that were captured
    should still be attached to their matching finding rather than
    silently dropped -- that's what passing it into build_findings below
    accomplishes.

    Returns the (possibly --min-score-filtered) Finding list so callers
    that need it for something beyond the console table -- currently only
    _maybe_write_reports -- don't have to recompute it a second time.
    Returns None when there was nothing to score, so a report flag on a
    plain dork run can tell "nothing to report" apart from "reported zero
    findings" and warn instead of writing a content-free report file.
    """
    have_any_signal = any([
        severity_map, probe_results is not None, verify_results_list is not None,
        fp_results is not None, secret_map is not None, vuln_hint_map is not None, triage,
    ])
    if not have_any_signal or not results:
        if min_score is not None:
            ui.print_warning(
                "--min-score has no effect here: no --probe/--verify/--fingerprint/--secrets/"
                "--check-vulns was run and this isn't a preset/category scan, so there's nothing to score."
            )
        return None

    findings = build_findings(
        results,
        verify_results=verify_results_list,
        fingerprint_results=fp_results,
        secret_results=secret_map,
        vuln_hint_results=vuln_hint_map,
        probe_results=probe_results,
        screenshot_results=screenshot_results,
        severity_map=severity_map,
        triage=triage,
    )
    findings = sort_findings(findings)

    if min_score is not None:
        before = len(findings)
        findings = filter_findings_by_min_score(findings, min_score)
        if before and not findings:
            ui.print_warning(f"--min-score {min_score} filtered out all {before} finding(s).")

    ui.render_findings_table(findings)
    return findings


def _report_context(sc: "ScanConfig", out_of_scope_count: int = 0) -> dict:
    analyses = [n for n, on in (
        ("probe", sc.probe), ("verify", sc.verify), ("fingerprint", sc.fingerprint), ("secrets", sc.secrets),
        ("vuln-hints", sc.check_vulns), ("url-triage", sc.triage), ("screenshots", bool(sc.screenshot_dir)),
    ) if on]
    return dict(
        target=sc.report_target,
        scope_summary=sc.scope.describe() if sc.scope is not None else "",
        out_of_scope_count=out_of_scope_count,
        analyses=analyses,
    )


def _maybe_write_reports(findings, sc: "ScanConfig", out_of_scope_count: int = 0):
    """Write whichever of --report-md/--report-html/--report-pdf were
    requested. `findings` is whatever _maybe_render_findings returned --
    None means nothing was scored (no analysis flag, no preset behind
    this scan), in which case a report would be content-free, so this
    warns per requested format instead of silently writing an empty shell.
    """
    from .report import render_markdown_report, render_html_report, generate_pdf_report

    wants_report = sc.report_md or sc.report_html or sc.report_pdf
    if not wants_report:
        return
    if findings is None:
        ui.print_warning(
            "No report written: nothing was scored for this scan (run with --probe/--verify/"
            "--fingerprint/--secrets/--check-vulns, or as a preset/category scan, to have findings to report)."
        )
        return

    label = sc.export_title or sc.results_title or ""

    if sc.report_md:
        content = render_markdown_report(findings, label=label, min_score_shown=sc.min_score, **_report_context(sc, out_of_scope_count))
        Path(sc.report_md).write_text(content, encoding="utf-8")
        ui.print_success(f"Markdown report written to {sc.report_md}")

    if sc.report_html:
        content = render_html_report(findings, label=label, min_score_shown=sc.min_score, **_report_context(sc, out_of_scope_count))
        Path(sc.report_html).write_text(content, encoding="utf-8")
        ui.print_success(f"HTML report written to {sc.report_html}")

    if sc.report_pdf:
        result = generate_pdf_report(findings, sc.report_pdf, label=label, **_report_context(sc, out_of_scope_count))
        if result.success:
            ui.print_success(f"PDF report written to {sc.report_pdf}")
        else:
            ui.print_error(f"PDF report failed: {result.error}")


def _maybe_export_via_plugin(results, export_via, cfg, title="LX-Dork-Pro Results", quiet=False):
    """Push results through a registered BaseExporter plugin, if
    requested. Shared by every code path that can end a scan (the main
    table path and both --json-stdout/--json-lines quiet paths) so
    --export-via behaves identically regardless of which output mode a
    scan is running in.

    `quiet=True` (the --json-stdout/--json-lines paths) routes messages
    to stderr via plain print() instead of the rich console, which
    defaults to stdout -- those modes' entire point is a clean,
    jq-pipeable stdout stream, so nothing about a plugin export result
    can be allowed to land there, success or failure.
    """
    if not export_via:
        return
    destination, error = export_via_plugin(export_via, cfg, results, title)
    if error:
        message = f"Export via '{export_via}' failed: {error}"
        print(message, file=sys.stderr) if quiet else ui.print_warning(message)
    else:
        message = f"Exported {len(results)} result(s) via '{export_via}': {destination}"
        print(message, file=sys.stderr) if quiet else ui.print_success(message)


def _handle_history_and_output(
    results, output, job_key, no_history, show_summary, elapsed,
    title="LX-Dork-Pro Results", webhook=None, notifiers=None, export_via=None, cfg=None,
):
    if show_summary:
        ui.render_summary(results, elapsed)

    if not no_history:
        new_urls, previous_exists, previous_ts = historymod.diff_against_last(job_key, results)
        ui.render_new_urls_banner(new_urls, previous_exists, previous_ts)
        historymod.save_run(job_key, results)

        # Only notify on genuine changes since a prior run -- the very
        # first run of a job has no baseline, so everything looks "new"
        # trivially, and that's not a signal worth alerting on.
        if webhook and previous_exists and new_urls:
            error = notify_new_results(webhook, title, new_urls, job_key)
            if error:
                ui.print_warning(f"Notification failed: {error}")
            else:
                ui.print_success(f"Notified webhook of {len(new_urls)} new result(s)")

        for notifier_name in (notifiers or []):
            if previous_exists and new_urls:
                error = notify_via_plugin(notifier_name, cfg or {}, title, new_urls, job_key)
                if error:
                    ui.print_warning(f"Notifier '{notifier_name}' failed: {error}")
                else:
                    ui.print_success(f"Notified '{notifier_name}' of {len(new_urls)} new result(s)")

    if output:
        saved_path = export_results(results, output, title=title)
        ui.print_success(f"Saved {len(results)} results to {saved_path}")

    _maybe_export_via_plugin(results, export_via, cfg or {}, title)


def _load_scope(scope_file, scope_inline, extra_includes=None):
    """Build the engagement Scope. `extra_includes` (e.g. the preset's own
    targets, for --scope-to-target) are added as ordinary include entries."""
    if extra_includes:
        scope_inline = ",".join([x for x in (scope_inline, ",".join(extra_includes)) if x])
    try:
        scope = scope_from_sources(scope_file, scope_inline)
    except OSError as e:
        ui.print_error(f"Couldn't read scope file: {e}")
        sys.exit(1)
    if scope is not None and scope.is_empty:
        ui.print_error("Scope was given but contains no include entries -- it would allow nothing.")
        sys.exit(1)
    return scope


def _read_lines_file(path):
    p = Path(path)
    if not p.exists():
        ui.print_error(f"File not found: {path}")
        sys.exit(1)
    return [
        line.strip()
        for line in p.read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.strip().startswith("#")
    ]


@dataclass
class ScanConfig:
    """Everything one dork/preset scan run needs, gathered in one place so
    `dork` and `preset` can share a single execution path (_execute_scan)
    instead of maintaining two near-identical ~60-line command bodies.
    """
    queries: list
    engines_list: list
    limit: int
    cfg: dict
    delay: float
    workers: int
    job_key: str
    info_line: str                 # printed before the scan starts (non-quiet mode only)
    results_title: str             # title shown above the results table
    export_title: str              # title embedded in HTML/summary exports
    filter_str: str = None
    exclude_str: str = None
    filter_regex: str = None
    exclude_regex: str = None
    include_ext: str = None
    exclude_ext: str = None
    max_per_host: int = None
    output: str = None
    probe: bool = False
    probe_workers: int = 20
    verify: bool = False
    verify_workers: int = 10
    fingerprint: bool = False
    fingerprint_workers: int = 10
    secrets: bool = False
    secrets_workers: int = 10
    secrets_js: bool = False
    check_vulns: bool = False
    triage: bool = False
    report_target: str = ""  # shown in --report-* headers
    vuln_workers: int = 10
    screenshot_dir: str = None
    screenshot_workers: int = 4
    webhook: str = None
    no_history: bool = False
    no_summary: bool = False
    json_stdout: bool = False
    json_lines: bool = False
    interactive: bool = False
    watch: int = None
    min_score: int = None
    severity_map: dict = None  # query -> preset severity, for preset/category runs; None for raw dorks
    use_async_core: bool = False  # opt-in asyncio orchestration (async_core.py) instead of the thread-pool _run_search
    report_md: str = None
    report_html: str = None
    report_pdf: str = None
    allow_private_targets: bool = False  # bypass the SSRF guard (ssrf_guard.py) for --probe/--verify/--fingerprint/--secrets/--check-vulns/--screenshot; only for engagements whose scope deliberately includes internal address space
    notifiers: list = None  # names of registered BaseNotifier plugins to notify on new results, in addition to/instead of --webhook
    scope: object = None  # scope.Scope or None; restricts every fetch/analysis/report to in-scope hosts
    export_via: str = None  # name of a registered BaseExporter plugin to push results through, in addition to/instead of --output

    @property
    def quiet(self) -> bool:
        return self.json_stdout or self.json_lines


def _quiet_history_and_notify(results, sc: "ScanConfig"):
    """History save + diff + webhook/plugin notify for the --json-stdout/
    --json-lines paths. Mirrors _handle_history_and_output's diff-then-notify
    logic (previously these quiet paths just called save_run() directly,
    which silently discarded the diff and meant --watch + --json-lines/
    --json-stdout + --webhook never fired -- a real gap for an otherwise-
    plausible automated-monitoring combination). Any warning goes to
    stderr, never stdout, so --json-stdout's "safe to pipe into jq"
    guarantee holds even when a notification fails.
    """
    if sc.no_history:
        return
    new_urls, previous_exists, _ = historymod.diff_against_last(sc.job_key, results)
    historymod.save_run(sc.job_key, results)
    if sc.webhook and previous_exists and new_urls:
        error = notify_new_results(sc.webhook, sc.export_title, new_urls, sc.job_key)
        if error:
            print(f"Notification failed: {error}", file=sys.stderr)
    for notifier_name in (sc.notifiers or []):
        if previous_exists and new_urls:
            error = notify_via_plugin(notifier_name, sc.cfg, sc.export_title, new_urls, sc.job_key)
            if error:
                print(f"Notifier '{notifier_name}' failed: {error}", file=sys.stderr)


def _dispatch_search(sc, on_result):
    """Route to whichever orchestration path this scan was configured to
    use. Both paths dedupe, record cross-engine corroboration, and call
    on_result identically, so everything downstream (filtering, findings
    fusion, export, history) works the same regardless of which one ran --
    this function is the only place that needs to know the difference.
    """
    if not sc.use_async_core:
        return _run_search(
            sc.engines_list, sc.queries, sc.limit, sc.cfg, sc.delay,
            max_workers=sc.workers, quiet=sc.quiet, on_result=on_result,
        )

    if sc.quiet:
        return run_search_blocking(
            sc.engines_list, sc.queries, sc.limit, sc.cfg, sc.delay, on_result=on_result,
        )

    total = len(sc.queries) * len(sc.engines_list)
    with ui.make_progress() as progress:
        task_id = progress.add_task("Dorking (async)...", total=total)

        def on_progress(done, _total, desc):
            accent = ui.current_theme()["accent"]
            progress.update(task_id, completed=done, description=f"[{accent}]{desc}[/{accent}]")

        def on_warning(msg):
            if "not configured" in msg:
                ui.print_warning(msg)
            else:
                ui.print_error(msg)

        return run_search_blocking(
            sc.engines_list, sc.queries, sc.limit, sc.cfg, sc.delay,
            on_result=on_result, on_progress=on_progress, on_warning=on_warning,
        )


def _execute_scan(sc: ScanConfig):
    """Run one full scan (search -> filter -> output) per the given
    ScanConfig. Shared by both `dork` and `preset` so behavior (JSON modes,
    history/diffing, probing, interactive browsing) can't drift between them.
    """
    _validate_regexes(sc)
    if not sc.quiet:
        ui.print_info(sc.info_line)

    start = time.time()

    on_result = None
    if sc.json_lines:
        host_counts = {}

        def on_result(r):  # noqa: F811 - intentional shadow, streams matching results live
            # Stateless filters per result; --max-per-host needs running per-host counts.
            if not _apply_filters([r], sc.filter_str, sc.exclude_str, sc.filter_regex, sc.exclude_regex,
                                  sc.include_ext, sc.exclude_ext):
                return
            if sc.max_per_host:
                host = (urlsplit(r.url).hostname or "").lower()
                if host_counts.get(host, 0) >= sc.max_per_host:
                    return
                host_counts[host] = host_counts.get(host, 0) + 1
            _print_json_line(r)

    results = _dispatch_search(sc, on_result)
    results = _scan_filters(sc, results)
    elapsed = time.time() - start

    if sc.json_lines:
        if _any_analysis(sc) or sc.screenshot_dir or sc.report_md or sc.report_html or sc.report_pdf:
            print("note: --json-lines streams raw results only; analysis/report flags are ignored "
                  "(use --json-stdout for fused findings).", file=sys.stderr)
        _quiet_history_and_notify(results, sc)
        if sc.output:
            export_results(results, sc.output)
        _maybe_export_via_plugin(results, sc.export_via, sc.cfg, sc.export_title, quiet=True)
        return

    if sc.json_stdout:
        ssrfmod.set_active_scope(sc.scope)
        scoped = results
        if sc.scope is not None:
            scoped, skipped = sc.scope.partition(results)
            if skipped:
                print(f"{len(skipped)} out-of-scope result(s) excluded from analysis", file=sys.stderr)
        if _any_analysis(sc) or (sc.severity_map and sc.min_score is not None):
            print(json.dumps([finding_to_dict(f) for f in _quiet_analyses(scoped, sc)], indent=2))
        else:
            _print_json_stdout(results)
        _quiet_history_and_notify(results, sc)
        if sc.output:
            export_results(results, sc.output)
        _maybe_export_via_plugin(results, sc.export_via, sc.cfg, sc.export_title, quiet=True)
        return

    if not results:
        ui.print_warning("No results found (or all engines unconfigured/rate-limited).")
        return

    ui.render_results_table(results, sc.results_title)

    # Everything below fetches or reports on hosts. With a scope set, only
    # in-scope hits are analysed; the fetch layer also enforces it per hop.
    full_results = results
    n_out_of_scope = 0
    ssrfmod.set_active_scope(sc.scope)
    if sc.scope is not None:
        results, skipped = sc.scope.partition(full_results)
        n_out_of_scope = len(skipped)
        if skipped:
            ui.print_warning(
                f"{len(skipped)} of {len(full_results)} result(s) are OUT OF SCOPE and will not be "
                f"fetched, scanned or reported (e.g. {ui._esc(skipped[0].url)})."
            )
        if not results:
            ui.print_warning("No in-scope results to analyse.")
    page_cache = PageCache()  # one GET per URL shared by verify/fingerprint/secrets/vuln-hints
    probe_results = _maybe_probe(results, sc.probe, sc.probe_workers, sc.allow_private_targets)
    verify_results_list = _maybe_verify(results, sc.verify, sc.verify_workers, sc.allow_private_targets, cache=page_cache)
    fp_results = _maybe_fingerprint(results, sc.fingerprint, sc.fingerprint_workers, sc.allow_private_targets, cache=page_cache)
    secret_map = _maybe_scan_secrets(results, sc.secrets, sc.secrets_workers, sc.allow_private_targets, cache=page_cache, include_js=sc.secrets_js)
    vuln_hint_map = _maybe_scan_vuln_hints(results, sc.check_vulns, sc.vuln_workers, sc.allow_private_targets, cache=page_cache)
    shot_results = _maybe_screenshot(results, sc.screenshot_dir, sc.screenshot_workers, sc.allow_private_targets)
    if page_cache.hits:
        ui.print_info(f"Fetch-once: reused {page_cache.hits} page fetch(es) across analyses.")
    findings = _maybe_render_findings(
        results, sc.severity_map, probe_results, verify_results_list, fp_results, secret_map, vuln_hint_map,
        shot_results, sc.min_score, triage=sc.triage,
    )
    _maybe_write_reports(findings, sc, n_out_of_scope)
    _handle_history_and_output(
        full_results, sc.output, sc.job_key, sc.no_history, not sc.no_summary, elapsed,
        title=sc.export_title, webhook=sc.webhook, notifiers=sc.notifiers,
        export_via=sc.export_via, cfg=sc.cfg,
    )

    if sc.interactive and not sc.watch:
        tui.browse(full_results)


def _run_with_watch(run_once, watch: int, sleep=time.sleep):
    """Run once, or re-run every `watch` minutes until Ctrl+C.

    An unattended monitor must survive a bad cycle: any exception from one
    run (a flaky engine, a full disk, a plugin bug) is reported and the loop
    carries on to the next cycle instead of silently dying overnight. After
    5 consecutive failed cycles it stops, because something is persistently
    wrong and looping forever would just hammer the engines.
    """
    if not watch:
        run_once()
        return

    ui.print_info(f"Watch mode: re-running every {watch} minute(s). Press Ctrl+C to stop.\n")
    failures = 0
    try:
        while True:
            try:
                run_once()
                failures = 0
            except Exception as e:  # noqa: BLE001 -- keep the monitor alive
                failures += 1
                ui.print_error(f"Watch cycle failed ({type(e).__name__}: {ui._esc(e)}); "
                               f"{failures}/5 consecutive failures.")
                if failures >= 5:
                    ui.print_error("Stopping watch mode after 5 consecutive failed cycles.")
                    return
            ui.console.rule(f"[dim]sleeping {watch}m...[/dim]")
            sleep(watch * 60)
    except KeyboardInterrupt:
        ui.print_info("\nStopped watch mode.")


# ---------------------------------------------------------------------------
# Options shared by `dork` and `preset`. Declared once so the two commands can
# never drift apart (a flag added to one and forgotten on the other). Only the
# help text of a few options differs between them.
# ---------------------------------------------------------------------------

_SCAN_HELP = {
    "dork": {
        "engines": "Comma-separated engines (default: config default_engines)",
        "limit": "Max results per engine (default from config, usually 30)",
        "output": "Save results to file (.txt/.json/.csv)",
        "verify": "Fetch each result and confirm it still matches the dork's signals (site/inurl/intitle/intext/ext), reporting a confidence rating -- catches stale index hits",
        "min-score": "Only show fused findings scoring at least this (0-100). Requires at least one of --probe/--verify/--fingerprint/--secrets/--check-vulns, or a preset/category run, to have anything to score",
    },
    "preset": {
        "engines": "Comma-separated engines",
        "limit": "Max results per engine per query",
        "output": "Save combined results to file (.txt/.json/.csv)",
        "verify": "Fetch each result and confirm it still matches its dork's signals (site/inurl/intitle/intext/ext), reporting a confidence rating -- catches stale index hits",
        "min-score": "Only show fused findings scoring at least this (0-100)",
    },
}


def scan_options(kind: str):
    """Decorator applying every option common to `dork` and `preset`, in the
    order they appear in --help. `kind` is "dork" or "preset"."""
    h = _SCAN_HELP[kind]
    opts = [
        click.option("-e", "--engines", default=None, help=h["engines"]),
        click.option("-l", "--limit", default=None, type=int, help=h["limit"]),
        click.option("-o", "--output", default=None, help=h["output"]),
        click.option("--filter", "filter_str", default=None, help="Only keep URLs containing this substring"),
        click.option("--exclude", "exclude_str", default=None, help="Drop URLs containing this substring"),
        click.option("--filter-regex", "filter_regex", default=None, help="Only keep URLs matching this regex"),
        click.option("--exclude-regex", "exclude_regex", default=None, help="Drop URLs matching this regex"),
        click.option("--ext", "include_ext", default=None, help="Only keep URLs with these file extensions, e.g. pdf,doc,sql"),
        click.option("--exclude-ext", "exclude_ext", default=None, help="Drop URLs with these file extensions, e.g. jpg,png,css,js"),
        click.option("--max-per-host", "max_per_host", default=None, type=int, help="Keep at most N results per hostname, so one noisy host can't drown out the rest"),
        click.option("--delay", default=None, type=float, help="Delay in seconds between requests to the SAME engine"),
        click.option("--jitter", default=0.3, show_default=True, type=click.FloatRange(0.0, 5.0), help="Randomly lengthen each --delay by up to this fraction (0.3 = up to 30%% longer) so request timing isn't machine-regular. 0 disables"),
        click.option("--workers", default=8, type=int, help="Max concurrent requests across all engines/queries"),
        click.option("--probe", is_flag=True, help="Check liveness (HTTP status) of found URLs after searching"),
        click.option("--probe-workers", default=20, type=int, help="Concurrent probe threads"),
        click.option("--verify", is_flag=True, help=h["verify"]),
        click.option("--verify-workers", default=10, type=int, help="Concurrent verification threads"),
        click.option("--fingerprint", is_flag=True, help="Detect CMS/server/language/JS-framework/CDN on each result (lightweight signature matching, like a mini Wappalyzer)"),
        click.option("--fingerprint-workers", default=10, type=int, help="Concurrent fingerprinting threads"),
        click.option("--secrets", is_flag=True, help="Fetch each result and scan its body/headers for exposed API keys, tokens, and private keys (structural signatures + entropy-gated generic patterns; values are redacted in output)"),
        click.option("--secrets-workers", default=10, type=int, help="Concurrent secret-scanning threads"),
        click.option("--secrets-js", is_flag=True, help="Also fetch and scan each page's same-site <script src> files (up to 10; vendored libraries skipped). Implies --secrets. Scripts go through the same SSRF guard and --scope"),
        click.option("--triage", is_flag=True, help="Passively tag each result by URL shape (open-redirect/SSRF/LFI/IDOR/SQLi candidates, secrets in query strings, admin/debug paths, backup/config files). No requests are made; tags are leads that nudge the fused score, never evidence"),
        click.option("--check-vulns", is_flag=True, help="Fetch each result EXACTLY as given (no parameters added/changed -- no payloads sent) and passively scan its body/headers for SQL/template-engine error messages and debug-console pages already present in the response. Flags leads for manual verification; does not test or confirm exploitability"),
        click.option("--vuln-workers", default=10, type=int, help="Concurrent vuln-hint-scanning threads"),
        click.option("--allow-private-targets", is_flag=True, help="Bypass the SSRF guard for --probe/--verify/--fingerprint/--secrets/--check-vulns/--screenshot, allowing fetches to private/loopback/link-local addresses. Only use this when the engagement's scope deliberately includes internal address space"),
        click.option("--screenshot-dir", default=None, help="Capture a screenshot of each result into this directory (requires wkhtmltoimage on PATH)"),
        click.option("--screenshot-workers", default=4, type=int, help="Concurrent screenshot captures (kept low -- each spawns a real rendering process)"),
        click.option("--webhook", default=None, help="Slack/Discord/generic webhook URL to notify when new results appear (best with --watch)"),
        click.option("--notifiers", default=None, help="Comma-separated names of registered BaseNotifier plugins to notify when new results appear, in addition to/instead of --webhook (see `lxdorkpro plugins`)"),
        click.option("--export-via", default=None, help="Name of a registered BaseExporter plugin to push results through (e.g. a Jira/DefectDojo/GitHub-issue plugin), in addition to/instead of --output (see `lxdorkpro plugins`)"),
        click.option("--watch", default=None, type=int, help="Re-run every N minutes, alert on new URLs (Ctrl+C to stop)"),
        click.option("--async-core", "use_async_core", is_flag=True, help="Use the asyncio-based orchestration core instead of the thread pool -- adaptive per-engine backoff, cooperative cancellation. Opt-in while it matures; behavior (dedup/corroboration/output) is identical either way"),
        click.option("--min-score", default=None, type=int, help=h["min-score"]),
        click.option("--report-md", default=None, help="Write a bug-bounty-ready Markdown report (grouped by severity, with evidence) to this path"),
        click.option("--report-html", default=None, help="Write a styled standalone HTML report to this path"),
        click.option("--report-pdf", default=None, help="Write a PDF report to this path (requires the wkhtmltopdf binary on PATH)"),
        click.option("--scope-file", default=None, help="File of in-scope domains/CIDRs (see scope.py). Out-of-scope hits are listed but never fetched, probed, scanned, or reported"),
        click.option("--scope", "scope_inline", default=None, help="Comma-separated in-scope domains/CIDRs, e.g. example.com,!dev.example.com"),
        click.option("--no-history", is_flag=True, help="Don't save/diff this run against local history"),
        click.option("--no-summary", is_flag=True, help="Skip the end-of-run summary panel"),
        click.option("--no-banner", is_flag=True, help="Skip the banner"),
        click.option("--json-stdout", is_flag=True, help="Print results as a raw JSON array to stdout (no banner/table/color) -- for piping into jq or other tools"),
        click.option("--json-lines", is_flag=True, help="Stream each result as a JSON line the instant it's found (JSON Lines / ndjson) -- for real-time pipelines on large scans"),
        click.option("-i", "--interactive", is_flag=True, help="Launch the interactive browser (paginated, view/open by number) after the scan"),
    ]

    def decorate(func):
        for opt in reversed(opts):  # click lists the topmost decorator first
            func = opt(func)
        return func

    return decorate


@cli.command()
@click.option("-d", "--dork", default=None, help="The dork query to run, e.g. 'inurl:php?id= site:.in'")
@click.option("--dork-file", default=None, help="File with one raw dork per line -- batch mode")
@scan_options("dork")
def dork(dork, dork_file, engines, limit, output, filter_str, exclude_str, filter_regex, exclude_regex, include_ext, exclude_ext, max_per_host, delay, jitter, workers,
         probe, probe_workers, verify, verify_workers, fingerprint, fingerprint_workers,
         secrets, secrets_workers, secrets_js, check_vulns, vuln_workers, triage, allow_private_targets, screenshot_dir, screenshot_workers, webhook, notifiers, export_via, watch, use_async_core, min_score,
         report_md, report_html, report_pdf,
         scope_file, scope_inline, no_history, no_summary, no_banner, json_stdout, json_lines, interactive):
    """Run one dork (or a batch from --dork-file) across search engines."""
    cfg = load_config()

    if not dork and not dork_file:
        ui.print_error("Provide either -d/--dork or --dork-file.")
        sys.exit(1)

    quiet = json_stdout or json_lines
    if quiet:
        no_banner = True
        ui.set_no_color(True)

    if not no_banner and sys.stdout.isatty():
        ui.animated_banner(version=__version__, stats=_banner_stats())

    queries = _read_lines_file(dork_file) if dork_file else [dork]
    engines_list = [e.strip() for e in engines.split(",")] if engines else cfg.get("default_engines", ["searxng", "duckduckgo"])
    limit = limit or cfg.get("default_limit", 30)
    delay = cfg.get("request_delay", 1.5) if delay is None else delay
    identifier = dork_file if dork_file else dork
    job_key = historymod.make_job_key("dork", identifier, engines_list)

    sc = ScanConfig(
        queries=queries, engines_list=engines_list, limit=limit, cfg={**cfg, "jitter": jitter}, delay=delay, workers=workers,
        job_key=job_key,
        info_line=(
            f"{'Dork file' if dork_file else 'Dork'}: [yellow]{identifier}[/yellow] "
            f"({len(queries)} quer(ies))  |  Engines: [cyan]{', '.join(engines_list)}[/cyan]  |  Limit/engine: {limit}"
        ),
        results_title=identifier,
        export_title=f"Dork: {identifier}",
        filter_str=filter_str, exclude_str=exclude_str, filter_regex=filter_regex,
        exclude_regex=exclude_regex, include_ext=include_ext, exclude_ext=exclude_ext, max_per_host=max_per_host,
        output=output, probe=probe, probe_workers=probe_workers, verify=verify, verify_workers=verify_workers,
        fingerprint=fingerprint, fingerprint_workers=fingerprint_workers,
        secrets=(secrets or secrets_js), secrets_workers=secrets_workers, secrets_js=secrets_js,
        check_vulns=check_vulns, vuln_workers=vuln_workers, triage=triage,
        screenshot_dir=screenshot_dir, screenshot_workers=screenshot_workers,
        webhook=webhook, min_score=min_score,
        notifiers=[n.strip() for n in notifiers.split(",") if n.strip()] if notifiers else None,
        export_via=export_via,
        report_md=report_md, report_html=report_html, report_pdf=report_pdf,
        no_history=no_history, no_summary=no_summary,
        json_stdout=json_stdout, json_lines=json_lines, interactive=interactive, watch=watch,
        severity_map=None,  # raw dorks aren't backed by a preset, so there's no severity to resolve
        use_async_core=use_async_core,
        allow_private_targets=allow_private_targets,
        scope=_load_scope(scope_file, scope_inline),
    )

    _run_with_watch(lambda: _execute_scan(sc), watch)


@cli.command(name="preset")
@click.argument("preset_name", required=False)
@click.option("--category", default=None, help="Run every preset in a category (folder) at once, e.g. --category exposure. See `lxdorkpro categories`.")
@click.option("--target", default=None, help="Target domain, e.g. example.com")
@click.option("--targets-file", default=None, help="File with one target domain per line -- batch mode")
@click.option("--scope-to-target", is_flag=True, help="Restrict every fetch/analysis/report to the --target host(s) and their subdomains (shortcut for --scope <target>); other hits are listed but never touched")
@scan_options("preset")
def preset_cmd(preset_name, category, target, targets_file, scope_to_target, engines, limit, output, filter_str, exclude_str, filter_regex, exclude_regex, include_ext, exclude_ext, max_per_host,
               delay, jitter, workers, probe, probe_workers, verify, verify_workers, fingerprint, fingerprint_workers,
               secrets, secrets_workers, secrets_js, check_vulns, vuln_workers, triage, allow_private_targets, screenshot_dir, screenshot_workers, webhook, notifiers, export_via, watch, use_async_core, min_score,
               report_md, report_html, report_pdf,
               scope_file, scope_inline, no_history, no_summary, no_banner, json_stdout, json_lines, interactive):
    """Run a built-in recon preset (bundle of dorks), or a whole --category
    of presets, against one or many targets.
    """
    cfg = load_config()

    if not preset_name and not category:
        ui.print_error("Provide a preset name, or --category to run a whole folder at once. Run `lxdorkpro presets` or `lxdorkpro categories`.")
        sys.exit(1)
    if preset_name and category:
        ui.print_error("Provide either a preset name or --category, not both.")
        sys.exit(1)
    if not target and not targets_file:
        ui.print_error("Provide either --target or --targets-file.")
        sys.exit(1)

    quiet = json_stdout or json_lines
    if quiet:
        no_banner = True
        ui.set_no_color(True)

    if not no_banner and sys.stdout.isatty():
        ui.animated_banner(version=__version__, stats=_banner_stats())

    raw_targets = _read_lines_file(targets_file) if targets_file else [target]
    targets = []
    for rt in raw_targets:
        try:
            nt = normalize_target(rt)
        except ValueError as e:
            ui.print_error(str(e))
            sys.exit(1)
        if nt != rt.strip().lower():
            ui.print_info(f"Target '{ui._esc(rt)}' normalized to '{nt}'.")
        if nt not in targets:
            targets.append(nt)
    if target and not targets_file:
        target = targets[0]  # job key / history use the normalized form

    if category:
        try:
            queries = []
            severity_map = {}
            for t in targets:
                queries.extend(get_category_queries(category, t))
                names = get_presets_by_category(category)
                severity_map.update(get_query_severity_map(names, t))
        except KeyError:
            ui.print_error(f"Unknown category '{category}'. Run `lxdorkpro categories` to see available categories.")
            sys.exit(1)
        label = f"category:{category}"
    else:
        try:
            queries = []
            severity_map = {}
            for t in targets:
                queries.extend(get_preset_queries(preset_name, t))
                severity_map.update(get_query_severity_map([preset_name], t))
        except KeyError:
            ui.print_error(f"Unknown preset '{preset_name}'. Run `lxdorkpro presets` to see available presets.")
            sys.exit(1)
        label = preset_name

    engines_list = [e.strip() for e in engines.split(",")] if engines else cfg.get("default_engines", ["searxng", "duckduckgo"])
    limit = limit or cfg.get("default_limit", 30)
    delay = cfg.get("request_delay", 1.5) if delay is None else delay
    identifier = f"{label}::{targets_file or target}"
    job_key = historymod.make_job_key("preset", identifier, engines_list)

    sc = ScanConfig(
        queries=queries, engines_list=engines_list, limit=limit, cfg={**cfg, "jitter": jitter}, delay=delay, workers=workers,
        job_key=job_key,
        info_line=(
            f"{'Category' if category else 'Preset'}: [yellow]{label}[/yellow]  |  Target(s): [cyan]{', '.join(targets)}[/cyan]  |  "
            f"{len(queries)} quer(ies) total"
        ),
        results_title=f"[{label}] {', '.join(targets)}",
        report_target=", ".join(targets),
        export_title=f"{'Category' if category else 'Preset'}: {label} ({', '.join(targets)})",
        filter_str=filter_str, exclude_str=exclude_str, filter_regex=filter_regex,
        exclude_regex=exclude_regex, include_ext=include_ext, exclude_ext=exclude_ext, max_per_host=max_per_host,
        output=output, probe=probe, probe_workers=probe_workers, verify=verify, verify_workers=verify_workers,
        fingerprint=fingerprint, fingerprint_workers=fingerprint_workers,
        secrets=(secrets or secrets_js), secrets_workers=secrets_workers, secrets_js=secrets_js,
        check_vulns=check_vulns, vuln_workers=vuln_workers, triage=triage,
        screenshot_dir=screenshot_dir, screenshot_workers=screenshot_workers,
        webhook=webhook, min_score=min_score,
        notifiers=[n.strip() for n in notifiers.split(",") if n.strip()] if notifiers else None,
        export_via=export_via,
        report_md=report_md, report_html=report_html, report_pdf=report_pdf,
        no_history=no_history, no_summary=no_summary,
        json_stdout=json_stdout, json_lines=json_lines, interactive=interactive, watch=watch,
        severity_map=severity_map,
        use_async_core=use_async_core,
        allow_private_targets=allow_private_targets,
        scope=_load_scope(scope_file, scope_inline, targets if scope_to_target else None),
    )

    _run_with_watch(lambda: _execute_scan(sc), watch)


def main():
    cli()


if __name__ == "__main__":
    main()

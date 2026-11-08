"""
Terminal UI: animated banner, live search progress, and result rendering.
Built entirely on `rich` — no noisy raw prints.
"""

import time
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.live import Live
from rich.markup import escape as _rich_escape
from rich.progress import (
    Progress,
    SpinnerColumn,
    BarColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich import box

from .theme import get_theme, DEFAULT_THEME

console = Console()
_current_theme_name = DEFAULT_THEME
_theme = get_theme(DEFAULT_THEME)


def _esc(value) -> str:
    """Escape a value before it's interpolated into an f-string Rich will
    parse as console markup, or passed as a Table cell (Table cells given
    a plain str are markup-parsed the same as console.print's f-strings
    are). Every call site this wraps carries a URL, title, snippet, or
    error message that ultimately came from a dork search result, a live
    page fetch, or a subprocess run against a URL this tool doesn't
    control -- without this, a crafted title/URL/error string containing
    Rich markup (e.g. "[bold red]FAKE CRITICAL[/bold red]" reading as
    real styling, or "[link=file:///etc/passwd]click me[/link]" spoofing
    a hyperlink) renders as if it were this tool's own trusted styling,
    and an unbalanced tag like a stray "[/]" raises
    rich.errors.MarkupError and would otherwise crash the whole command
    partway through printing a results table. escape() turns a literal
    "[" into "\\[", which Rich's parser then reads back as a literal "["
    rather than the start of a tag -- the value still displays exactly as
    given, it just can't be interpreted as formatting.
    """
    return _rich_escape(str(value))


def set_no_color(flag: bool = True):
    """Reconfigure the shared console for plain, unstyled output — useful
    for CI logs, piping into other tools, or the NO_COLOR convention.
    """
    global console
    console = Console(no_color=flag, highlight=False)


def set_theme(name: str):
    """Switch the active color theme (affects the banner, dashboard, and
    accent colors used throughout). Unknown names fall back to the default
    theme rather than raising -- a typo in --theme shouldn't break the tool.
    """
    global _current_theme_name, _theme
    _current_theme_name = name
    _theme = get_theme(name)


def current_theme() -> dict:
    return _theme


# A compact "radar" glyph cycled during the boot animation -- ties the
# spinner visually to the tool's purpose (scanning) rather than being a
# generic loading indicator.
RADAR_FRAMES = ["◜ ", "◝ ", "◞ ", "◟ "]
BRAILLE_FRAMES = ["⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"]

LOGO_LINES = [
    r" _    __  __      ____             _      ____             ",
    r"| |   \ \/ /     |  _ \  ___  _ __| | __ |  _ \ _ __ ___   ",
    r"| |    \  /______| | | |/ _ \| '__| |/ / | |_) | '__/ _ \  ",
    r"| |___ /  \______| |_| | (_) | |  |   <  |  __/| | | (_) | ",
    r"|_____/_/\_\     |____/ \___/|_|  |_|\_\ |_|   |_|  \___/  ",
]


def animated_banner(subtitle: str = "Advanced Multi-Engine Dork Recon Framework", version: str = "1.0.0", stats: dict = None):
    """Multi-phase animated intro:
      1. A brief radar-spinner 'initializing' beat
      2. A left-to-right scan-line reveal of the logo (ties the visual
         language to the tool's purpose -- scanning -- rather than a
         generic fade-in)
      3. A couple of gradient shimmer passes across the fully-revealed logo
      4. A short boot checklist (engine count, config path, ready)
    Falls back gracefully to instant rendering if the terminal doesn't
    support Live updates well -- Live() no-ops harmlessly in that case.
    """
    theme = _theme
    gradient = theme["gradient"]
    width = max(len(line) for line in LOGO_LINES)

    # Phase 1: radar spin "initializing" beat.
    with Live(console=console, refresh_per_second=20, transient=True) as live:
        for i in range(12):
            frame = BRAILLE_FRAMES[i % len(BRAILLE_FRAMES)]
            live.update(Align.center(Text(f"{frame} initializing LX-Dork-Pro...", style=f"bold {theme['accent']}")))
            time.sleep(0.03)

    # Phase 2: scan-line reveal, column by column, left to right.
    with Live(console=console, refresh_per_second=30, transient=True) as live:
        steps = width + 6
        for step in range(steps):
            text = Text()
            for line in LOGO_LINES:
                for i, ch in enumerate(line):
                    if i > step:
                        text.append(" ")
                        continue
                    color = gradient[i // 3 % len(gradient)]
                    style = f"bold {color}"
                    if step - i < 3:  # a bright "scan line" trailing the reveal edge
                        style = f"bold white on {color}" if i <= step else style
                    text.append(ch, style=style)
                text.append("\n")
            live.update(Align.center(text))
            time.sleep(0.012)

    # Phase 3: gradient shimmer passes across the completed logo.
    with Live(console=console, refresh_per_second=24, transient=True) as live:
        for f in range(8):
            text = Text()
            for line in LOGO_LINES:
                for i, ch in enumerate(line):
                    color = gradient[(i // 3 + f) % len(gradient)]
                    text.append(ch, style=f"bold {color}")
                text.append("\n")
            live.update(Align.center(text))
            time.sleep(0.03)

    # Final static banner with panel + subtitle.
    final = Text()
    for line in LOGO_LINES:
        for i, ch in enumerate(line):
            color = gradient[i // 3 % len(gradient)]
            final.append(ch, style=f"bold {color}")
        final.append("\n")

    sub = Text(f"\n{subtitle}", style="italic bright_white")
    ver = Text(f"v{version}  •  by security researchers, for security researchers", style="dim")
    body = Align.center(Text.assemble(final, sub, "\n", ver))

    console.print(Panel(body, border_style=theme["border"], box=box.DOUBLE, padding=(1, 4)))

    # Phase 4: boot checklist, revealed line by line.
    _print_boot_checklist(stats)


def _print_boot_checklist(stats: dict = None):
    stats = stats or {}
    lines = [
        ("✓", f"Engines ready: {stats.get('engine_count', '?')} ({stats.get('free_count', '?')} free, {stats.get('paid_count', '?')} paid)"),
        ("✓", f"Config: {stats.get('config_path', '~/.config/lx-dork-pro')}"),
    ]
    if stats.get("history_count") is not None:
        lines.append(("✓", f"History: {stats['history_count']} saved job(s)"))
    lines.append(("✓", "Ready."))

    for mark, text in lines:
        console.print(f"  [bold {_theme['success']}]{mark}[/bold {_theme['success']}] [dim]{text}[/dim]")
        time.sleep(0.06)
    console.print()


def static_banner(subtitle: str = "Advanced Multi-Engine Dork Recon Framework", version: str = "1.0.0"):
    """Non-animated fallback (used with --no-anim / piped output)."""
    theme = _theme
    gradient = theme["gradient"]
    final = Text()
    for line in LOGO_LINES:
        for i, ch in enumerate(line):
            color = gradient[i // 3 % len(gradient)]
            final.append(ch, style=f"bold {color}")
        final.append("\n")
    sub = Text(f"\n{subtitle}", style="italic bright_white")
    ver = Text(f"v{version}", style="dim")
    body = Align.center(Text.assemble(final, sub, "\n", ver))
    console.print(Panel(body, border_style=theme["border"], box=box.DOUBLE, padding=(1, 4)))


def welcome_dashboard(version: str, engine_status: list, history_count: int = 0, plugin_count: int = 0):
    """Claude-Code-style landing screen shown when `lxdorkpro` runs with no
    subcommand: static logo, engine/config status at a glance, and a few
    ready-to-run command suggestions -- oriented so a first-time user knows
    exactly what to type next, not just what the tool is.

    engine_status: list of (name, ready: bool, kind: "free"|"paid") tuples.
    """
    theme = _theme
    static_banner(version=version)

    status_table = Table(box=box.SIMPLE, show_header=True, header_style=f"bold {theme['accent']}", expand=True)
    status_table.add_column("Engine")
    status_table.add_column("Status", justify="center")
    status_table.add_column("Type", justify="center")
    for name, ready, kind in engine_status:
        status = f"[{theme['success']}]● ready[/{theme['success']}]" if ready else f"[{theme['muted']}]○ not configured[/{theme['muted']}]"
        kind_style = theme["accent"] if kind == "free" else theme["warning"]
        status_table.add_row(name, status, f"[{kind_style}]{kind}[/{kind_style}]")

    ready_count = sum(1 for _, ready, _ in engine_status if ready)
    stats_line = (
        f"[bold]{ready_count}/{len(engine_status)}[/bold] engines ready  •  "
        f"[bold]{history_count}[/bold] saved job(s)  •  [bold]{plugin_count}[/bold] plugin(s) loaded"
    )

    quick_commands = "\n".join([
        f"  [{theme['accent']}]lxdorkpro dork[/{theme['accent']}] -d 'inurl:admin site:example.com'",
        f"  [{theme['accent']}]lxdorkpro preset[/{theme['accent']}] --category exposure --target example.com",
        f"  [{theme['accent']}]lxdorkpro categories[/{theme['accent']}]        [dim]# browse all preset folders[/dim]",
        f"  [{theme['accent']}]lxdorkpro doctor[/{theme['accent']}]            [dim]# check engine connectivity[/dim]",
        f"  [{theme['accent']}]lxdorkpro configure[/{theme['accent']}]         [dim]# add optional paid API keys[/dim]",
    ])

    console.print(Panel(status_table, title="Engine Status", border_style=theme["border"], box=box.ROUNDED))
    console.print(f"\n{stats_line}\n")
    console.print(Panel(quick_commands, title="Quick Start", border_style=theme["border"], box=box.ROUNDED))
    console.print(f"\n[dim]Run[/dim] [bold]lxdorkpro --help[/bold] [dim]for the full command reference.[/dim]\n")


def make_progress() -> Progress:
    theme = _theme
    return Progress(
        SpinnerColumn(style=theme["accent"]),
        TextColumn(f"[bold {theme['accent']}]{{task.description}}"),
        BarColumn(bar_width=30, style="grey37", complete_style=theme["accent"], finished_style=theme["success"]),
        TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
        TimeElapsedColumn(),
        console=console,
    )


ENGINE_COLORS = {
    "google": "green",
    "bing": "blue",
    "brave": "orange3",
    "searxng": "magenta",
    "duckduckgo": "yellow",
    "google-scrape": "bright_green",
    "yandex": "red",
    "mojeek": "bright_blue",
    "startpage": "purple",
    "wayback": "grey70",
    "commoncrawl": "dark_orange",
    "crtsh": "bright_magenta",
    "urlscan": "cyan",
}


def render_results_table(results, dork: str):
    table = Table(
        title=f"Results for: [bold yellow]{dork}[/bold yellow]",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold white on grey19",
        show_lines=False,
        expand=True,
    )
    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Engine", width=8)
    table.add_column("URL", style="bright_cyan", overflow="fold", ratio=3)
    table.add_column("Title", style="white", overflow="ellipsis", ratio=2)

    for i, r in enumerate(results, 1):
        engine_color = ENGINE_COLORS.get(r.engine, "white")
        table.add_row(
            str(i),
            f"[{engine_color}]{r.engine}[/{engine_color}]",
            _esc(r.url),
            _esc(r.title) if r.title else "-",
        )

    console.print(table)
    console.print(
        f"\n[bold green]✓[/bold green] [white]{len(results)}[/white] unique URL(s) found. "
        f"[dim]Use --output to save results.[/dim]\n"
    )


def print_error(message: str):
    console.print(f"[bold red]✗ ERROR:[/bold red] {message}")


def print_warning(message: str):
    console.print(f"[bold yellow]⚠ WARNING:[/bold yellow] {message}")


def print_success(message: str):
    console.print(f"[bold green]✓[/bold green] {message}")


def print_info(message: str):
    console.print(f"[bold cyan]ℹ[/bold cyan] {message}")


def render_probe_table(probe_results):
    table = Table(
        title="Liveness Probe Results",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold white on grey19",
        expand=True,
    )
    table.add_column("Status", width=8, justify="center")
    table.add_column("URL", style="bright_cyan", overflow="fold", ratio=3)
    table.add_column("Final URL (after redirects)", style="dim", overflow="fold", ratio=2)

    alive_count = 0
    protected_count = 0
    for r in probe_results:
        if r.alive:
            alive_count += 1
            status_str = f"[bold green]{r.status}[/bold green]"
        elif getattr(r, "protected", False):
            protected_count += 1
            status_str = f"[bold cyan]{r.status} \\[auth][/bold cyan]"   # exists, access-controlled
        elif r.status is not None:
            status_str = f"[bold yellow]{r.status}[/bold yellow]"
        else:
            kind = getattr(r, "error_kind", "") or r.error or "ERR"
            status_str = f"[bold red]{_esc(kind)}[/bold red]"
        final = r.final_url if r.final_url and r.final_url != r.url else "-"
        table.add_row(status_str, _esc(r.url), _esc(final))

    console.print(table)
    extra = f", [bold cyan]{protected_count}[/bold cyan] protected (401/403 -- exists, access-controlled)" if protected_count else ""
    console.print(
        f"[bold green]{alive_count}[/bold green]/{len(probe_results)} URLs alive "
        f"(status < 400){extra}\n"
    )


_CONFIDENCE_COLORS = {
    "high": "bold green",
    "medium": "bold yellow",
    "low": "bold red",
    "unreachable": "dim red",
    "unknown": "dim",
}


def render_verify_table(verify_results):
    """Render accuracy-verification results: for each URL, how many of the
    dork's signals (site/inurl/intitle/intext/ext) were actually confirmed
    on the live page, with an overall confidence rating.
    """
    table = Table(
        title="Accuracy Verification",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold white on grey19",
        expand=True,
    )
    table.add_column("Confidence", width=12, justify="center")
    table.add_column("Signals", width=10, justify="center")
    table.add_column("URL", style="bright_cyan", overflow="fold", ratio=3)
    table.add_column("Details", overflow="fold", ratio=2)

    counts = {"high": 0, "medium": 0, "low": 0, "unreachable": 0, "unknown": 0}
    for v in verify_results:
        counts[v.confidence] = counts.get(v.confidence, 0) + 1
        color = _CONFIDENCE_COLORS.get(v.confidence, "white")
        conf_str = f"[{color}]{v.confidence.upper()}[/{color}]"
        signal_str = f"{v.confirmed_count}/{v.total_count}" if v.total_count else "-"

        if v.error:
            details = f"[dim]{_esc(v.error)}[/dim]"
        else:
            parts = []
            for s in v.signals:
                mark = "[green]✓[/green]" if s.confirmed else "[red]✗[/red]"
                parts.append(f"{mark} {_esc(s.kind)}:{_esc(s.value)}")
            details = "  ".join(parts) if parts else "[dim]no checkable signals[/dim]"

        table.add_row(conf_str, signal_str, _esc(v.url), details)

    console.print(table)
    summary = "  ".join(
        f"[{_CONFIDENCE_COLORS.get(k, 'white')}]{k}: {v}[/{_CONFIDENCE_COLORS.get(k, 'white')}]"
        for k, v in counts.items() if v > 0
    )
    console.print(f"\n{summary}\n")


_TECH_CATEGORY_COLORS = {
    "cms": "magenta",
    "javascript-framework": "cyan",
    "javascript-library": "bright_cyan",
    "css-framework": "blue",
    "web-server": "green",
    "language": "yellow",
    "cdn": "orange3",
    "analytics": "grey58",
}


def render_fingerprint_table(fingerprint_results):
    """Render detected technologies per URL: CMS, server, language,
    JS framework, CDN -- grouped so a scan of many results reads like a
    tech-stack summary, not a wall of repeated headers.
    """
    table = Table(
        title="Technology Fingerprints",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold white on grey19",
        expand=True,
    )
    table.add_column("URL", style="bright_cyan", overflow="fold", ratio=2)
    table.add_column("Technologies detected", overflow="fold", ratio=3)

    tech_counter = {}
    for fp in fingerprint_results:
        if fp.error:
            table.add_row(_esc(fp.url), f"[dim]unreachable: {_esc(fp.error)}[/dim]")
            continue
        if not fp.detections:
            table.add_row(_esc(fp.url), "[dim]no known technologies detected[/dim]")
            continue
        parts = []
        for d in fp.detections:
            color = _TECH_CATEGORY_COLORS.get(d.category, "white")
            parts.append(f"[{color}]{_esc(d.name)}[/{color}]")
            tech_counter[d.name] = tech_counter.get(d.name, 0) + 1
        table.add_row(_esc(fp.url), "  ".join(parts))

    console.print(table)
    if tech_counter:
        top = sorted(tech_counter.items(), key=lambda kv: -kv[1])[:8]
        summary = "  ".join(f"{name} ({count})" for name, count in top)
        console.print(f"\n[bold]Most common:[/bold] {summary}\n")


def render_screenshot_table(screenshot_results):
    """Render screenshot capture results: which succeeded, where the
    files landed, and why any failed (e.g. wkhtmltoimage not installed).
    """
    table = Table(
        title="Screenshot Capture",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold white on grey19",
        expand=True,
    )
    table.add_column("Status", width=10, justify="center")
    table.add_column("URL", style="bright_cyan", overflow="fold", ratio=2)
    table.add_column("File / Error", overflow="fold", ratio=2)

    success_count = 0
    for s in screenshot_results:
        if s.success:
            success_count += 1
            table.add_row("[bold green]✓ OK[/bold green]", _esc(s.url), s.path)
        else:
            table.add_row("[bold red]✗ FAIL[/bold red]", _esc(s.url), f"[dim]{_esc(s.error)}[/dim]")

    console.print(table)
    console.print(f"\n[bold green]{success_count}[/bold green]/{len(screenshot_results)} screenshots captured\n")


_SECRET_CATEGORY_COLORS = {
    "cloud": "orange3",
    "vcs": "magenta",
    "generic": "yellow",
    "crypto": "red",
    "payment": "bright_red",
    "chat-ops": "cyan",
}


def render_secrets_table(secret_map, total_scanned: int = 0):
    """Render exposed-secret scan results: one row per URL that had at
    least one hit (URLs with nothing found aren't listed -- with hundreds
    of scanned results, a wall of "no secrets found" rows buries the ones
    that matter far more than a clean summary line does).
    """
    if not secret_map:
        console.print(f"\n[dim]No secrets detected across {total_scanned} scanned URL(s).[/dim]\n")
        return

    table = Table(
        title="Exposed Secrets / Credentials",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold white on grey19",
        expand=True,
    )
    table.add_column("URL", style="bright_cyan", overflow="fold", ratio=2)
    table.add_column("Secret(s) found", overflow="fold", ratio=3)

    total_matches = 0
    category_counter = {}
    for url, matches in secret_map.items():
        parts = []
        for m in matches:
            total_matches += 1
            category_counter[m.category] = category_counter.get(m.category, 0) + 1
            color = _SECRET_CATEGORY_COLORS.get(m.category, "white")
            conf_marker = "" if m.confidence == "high" else " [dim](entropy-based, verify manually)[/dim]"
            parts.append(f"[{color}]{_esc(m.name)}[/{color}]: {_esc(m.redacted)}{conf_marker}")
        table.add_row(_esc(url), "\n".join(parts))

    console.print(table)
    console.print(
        f"\n[bold red]{total_matches}[/bold red] potential secret(s) across "
        f"[bold]{len(secret_map)}[/bold]/{total_scanned} scanned URL(s). "
        f"[dim]Values are redacted -- rotate anything confirmed real.[/dim]\n"
    )


_VULN_HINT_CATEGORY_COLORS = {
    "sql_error": "bright_red",
    "template_error": "orange3",
    "stack_trace": "yellow",
    "debug_console": "magenta",
}


def render_vuln_hints_table(vuln_hint_map, total_scanned: int = 0):
    """Render passive vuln-hint scan results: one row per URL that already
    showed a SQL/template-error or debug-console signature on an
    unmodified fetch (URLs with nothing found aren't listed, same
    reasoning as render_secrets_table). Every row here is a "verify
    manually" lead, not a confirmed vulnerability -- see vuln_hints.py's
    module docstring for what this scan does and does not do (no payload
    is ever sent; a hit means the target's own ordinary response already
    leaked something).
    """
    if not vuln_hint_map:
        console.print(f"\n[dim]No SQL/template-error or debug-console signatures detected across {total_scanned} scanned URL(s).[/dim]\n")
        return

    table = Table(
        title="Passive Vulnerability Indicators (verify manually -- not confirmed exploits)",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold white on grey19",
        expand=True,
    )
    table.add_column("URL", style="bright_cyan", overflow="fold", ratio=2)
    table.add_column("Indicator(s) found", overflow="fold", ratio=3)

    total_hints = 0
    category_counter = {}
    for url, hints in vuln_hint_map.items():
        parts = []
        for h in hints:
            total_hints += 1
            category_counter[h.category] = category_counter.get(h.category, 0) + 1
            color = _VULN_HINT_CATEGORY_COLORS.get(h.category, "white")
            parts.append(f"[{color}]{_esc(h.name)}[/{color}]: {_esc(h.evidence)}")
        table.add_row(_esc(url), "\n".join(parts))

    console.print(table)
    console.print(
        f"\n[bold red]{total_hints}[/bold red] passive indicator(s) across "
        f"[bold]{len(vuln_hint_map)}[/bold]/{total_scanned} scanned URL(s). "
        f"[dim]These are leads, not confirmed vulnerabilities -- no payload was sent; "
        f"verify manually before reporting.[/dim]\n"
    )


_SEVERITY_COLORS = {
    "critical": "bold white on red3",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "cyan",
    "info": "dim white",
}


def render_findings_table(findings):
    """Render the fused, score-ranked view: one row per URL with a single
    0-100 confidence score and severity bucket combining preset severity,
    cross-engine corroboration, --verify confidence, --fingerprint tech
    detections, secret-scan hits, passive vuln-hint signatures, and
    --probe liveness -- whichever of those were actually run. This is the
    "what's actually worth my time" table that replaces mentally
    cross-referencing four separate ones.

    Findings are expected pre-sorted (see findings.sort_findings) --
    this function renders in the order given rather than re-sorting, so
    callers stay in control of ordering (e.g. after a --min-score filter).
    """
    if not findings:
        console.print("\n[dim]No findings to score (nothing survived --min-score, or nothing was found).[/dim]\n")
        return

    table = Table(
        title="Fused Findings (ranked by confidence)",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold white on grey19",
        expand=True,
    )
    table.add_column("Score", width=7, justify="center")
    table.add_column("Severity", width=10, justify="center")
    table.add_column("URL", style="bright_cyan", overflow="fold", ratio=3)
    table.add_column("Why", overflow="fold", ratio=3)

    severity_counter = {}
    for f in findings:
        severity_counter[f.severity_label] = severity_counter.get(f.severity_label, 0) + 1
        style = _SEVERITY_COLORS.get(f.severity_label, "white")

        reasons = []
        if f.preset_severity:
            reasons.append(f"preset:{f.preset_severity}")
        if f.corroboration_count > 1:
            reasons.append(f"seen by {f.corroboration_count} engines")
        if f.verify_confidence:
            reasons.append(f"verify:{f.verify_confidence}")
        if f.has_secrets:
            reasons.append(f"[bold red]{len(f.secrets)} secret(s)[/bold red]")
        if f.has_vuln_hints:
            reasons.append(f"[bold red]{len(f.vuln_hints)} vuln indicator(s)[/bold red]")
        if f.soft_404:
            reasons.append("soft-404")
        if f.triage:
            reasons.append("triage:" + ",".join(sorted({t.name for t in f.triage})[:3]))
        if f.technologies:
            reasons.append(f"tech:{','.join(f.technologies[:3])}")
        if f.probe_alive is not None:
            reasons.append("alive" if f.probe_alive else "[dim]dead[/dim]")

        table.add_row(
            str(f.confidence_score),
            f"[{style}] {f.severity_label.upper()} [/{style}]",
            _esc(f.url),
            "  ·  ".join(reasons) if reasons else "[dim]corroboration only[/dim]",
        )

    console.print(table)
    summary = "  ".join(
        f"[{_SEVERITY_COLORS.get(k, 'white')}]{k}: {v}[/{_SEVERITY_COLORS.get(k, 'white')}]"
        for k, v in sorted(severity_counter.items(), key=lambda kv: -{"critical": 4, "high": 3, "medium": 2, "low": 1, "info": 0}.get(kv[0], 0))
    )
    console.print(f"\n{summary}\n")


def render_summary(results, elapsed_seconds: float):
    """Compact end-of-run stats panel: counts per engine + top TLDs + timing."""
    from collections import Counter
    from urllib.parse import urlparse

    engine_counts = Counter(r.engine for r in results)
    tld_counts = Counter()
    for r in results:
        try:
            host = urlparse(r.url).netloc
            tld = host.split(".")[-1] if "." in host else host
            tld_counts[tld] += 1
        except Exception:
            continue

    lines = [f"[bold]{len(results)}[/bold] total unique URLs in [bold]{elapsed_seconds:.1f}s[/bold]", ""]
    lines.append("[bold]By engine:[/bold]")
    for engine, count in engine_counts.most_common():
        color = ENGINE_COLORS.get(engine, "white")
        lines.append(f"  [{color}]{engine}[/{color}]: {count}")

    if tld_counts:
        lines.append("\n[bold]Top TLDs:[/bold]")
        for tld, count in tld_counts.most_common(5):
            lines.append(f"  .{_esc(tld)}: {count}")

    console.print(Panel("\n".join(lines), title="Summary", border_style="grey50", box=box.ROUNDED))


def render_doctor_table(rows):
    """rows: list of (engine_name, ok: bool, message: str, latency_ms: float)"""
    table = Table(
        title="Engine Health Check",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold white on grey19",
        expand=True,
    )
    table.add_column("Engine", width=14)
    table.add_column("Status", width=10, justify="center")
    table.add_column("Latency", width=10, justify="right")
    table.add_column("Details", overflow="fold")

    for name, ok, message, latency_ms in rows:
        color = ENGINE_COLORS.get(name, "white")
        status = "[bold green]● UP[/bold green]" if ok else "[bold red]● DOWN[/bold red]"
        # message can embed a slice of a raw API response body (see
        # engines.EngineError call sites, e.g. "SearXNG error 500: {resp.text[:200]}")
        # -- a trusted endpoint misbehaving shouldn't be able to crash
        # `doctor` via a stray "[" any more than an indexed page can crash
        # the results table.
        table.add_row(f"[{color}]{name}[/{color}]", status, f"{latency_ms:.0f}ms", _esc(message))

    console.print(table)


def render_history_table(jobs):
    import datetime

    table = Table(
        title="Saved Recon Jobs",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold white on grey19",
        expand=True,
    )
    table.add_column("#", justify="right", width=3)
    table.add_column("Job", overflow="fold", ratio=3)
    table.add_column("Last run", width=20)
    table.add_column("URLs found", justify="right", width=12)

    for i, job in enumerate(jobs, 1):
        ts = datetime.datetime.fromtimestamp(job["timestamp"]).strftime("%Y-%m-%d %H:%M")
        # job keys embed the user's dork text; escape so a stray "[/x]" can't crash rendering
        table.add_row(str(i), _esc(job["job_key"]), ts, str(job["count"]))

    console.print(table)


def render_new_urls_banner(new_urls, previous_exists: bool, previous_timestamp):
    import datetime

    if not previous_exists:
        console.print(
            Panel(
                "[dim]First time running this exact job — nothing to diff against yet. "
                "Future runs will show what's new.[/dim]",
                border_style="grey50",
                box=box.ROUNDED,
            )
        )
        return

    if not new_urls:
        console.print(
            Panel("[dim]No new URLs since the last run of this job.[/dim]", border_style="grey50", box=box.ROUNDED)
        )
        return

    when = datetime.datetime.fromtimestamp(previous_timestamp).strftime("%Y-%m-%d %H:%M") if previous_timestamp else "?"
    body = Text()
    body.append(f"{len(new_urls)} NEW URL(s) since last run ({when}):\n\n", style="bold green")
    for u in sorted(new_urls):
        body.append("  + ", style="bold green")
        body.append(f"{u}\n", style="bright_cyan")

    console.print(Panel(body, title="🆕 New Since Last Scan", border_style="green", box=box.ROUNDED))

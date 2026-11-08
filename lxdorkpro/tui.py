"""
Interactive results browser: paginated navigation with view/open/probe
actions, instead of just a static table. The I/O loop here is intentionally
thin -- all command parsing/pagination logic lives in tui_commands.py where
it can be unit tested without mocking stdin.
"""

import webbrowser

from rich.panel import Panel
from rich.table import Table
from rich import box

from . import ui
from .ssrf_guard import check_scheme
from .tui_commands import parse_command, paginate, total_pages

PAGE_SIZE = 10

HELP_TEXT = """[bold]Commands:[/bold]
  [cyan]<n>[/cyan] or [cyan]v<n>[/cyan]   view full details for item n on this page
  [cyan]o<n>[/cyan]        open item n's URL in your default web browser
  [cyan]n[/cyan] / [cyan]next[/cyan]      next page
  [cyan]p[/cyan] / [cyan]prev[/cyan]      previous page
  [cyan]g<n>[/cyan]        jump to page n
  [cyan]h[/cyan] / [cyan]help[/cyan]      show this help
  [cyan]q[/cyan] / [cyan]quit[/cyan]      exit the browser"""


def _render_page(page_results, page, n_pages, total_count):
    table = Table(
        title=f"Results — page {page}/{n_pages} ({total_count} total)",
        box=box.ROUNDED,
        border_style="bright_black",
        header_style="bold white on grey19",
        expand=True,
    )
    table.add_column("#", width=4, justify="right")
    table.add_column("Engine", width=10)
    table.add_column("URL", style="bright_cyan", overflow="fold", ratio=3)
    table.add_column("Title", overflow="ellipsis", ratio=2)

    for i, r in enumerate(page_results, 1):
        color = ui.ENGINE_COLORS.get(r.engine, "white")
        # r.url/r.title are attacker-influenced (whatever a search engine
        # indexed) -- same Rich-markup-injection concern render_results_table
        # in ui.py guards against, and this function has its own separate
        # Table.add_row call that isn't covered by ui.py's _esc() wrapping.
        table.add_row(str(i), f"[{color}]{r.engine}[/{color}]", ui._esc(r.url), ui._esc(r.title) if r.title else "-")

    ui.console.print(table)
    ui.console.print("[dim]Type a number to view details, or 'h' for all commands.[/dim]")


def _render_detail(result, index):
    # url/title/snippet are all attacker-influenced (whatever the search
    # engine indexed) and get interpolated into a string Rich parses as
    # markup, so escape them -- same reasoning as _render_page above and
    # ui.render_results_table. engine is assigned by this tool itself
    # (which engine class produced the result), not derived from page
    # content, so it doesn't need escaping.
    body = (
        f"[bold]URL:[/bold] {ui._esc(result.url)}\n"
        f"[bold]Title:[/bold] {ui._esc(result.title) if result.title else '-'}\n"
        f"[bold]Engine:[/bold] {result.engine}\n\n"
        f"[bold]Snippet:[/bold]\n{ui._esc(result.snippet) if result.snippet else '(no snippet)'}"
    )
    ui.console.print(Panel(body, title=f"Item #{index}", border_style="cyan", box=box.ROUNDED))


def browse(results, input_fn=input):
    """Run the interactive browser loop over `results` (a list of
    SearchResult). `input_fn` is swappable for testing -- pass a fake
    generator instead of the real `input` builtin.
    """
    if not results:
        ui.print_warning("Nothing to browse — no results.")
        return

    page = 1
    n_pages = total_pages(len(results), PAGE_SIZE)

    ui.console.print(f"\n[bold cyan]Interactive browser[/bold cyan] — {len(results)} result(s). Type 'h' for help, 'q' to quit.\n")

    while True:
        page_results = paginate(results, page, PAGE_SIZE)
        _render_page(page_results, page, n_pages, len(results))

        try:
            raw = input_fn("lx-dork-pro> ")
        except (EOFError, KeyboardInterrupt):
            ui.console.print("\n[dim]Exiting browser.[/dim]")
            return

        action = parse_command(raw)

        if action.kind == "quit":
            ui.console.print("[dim]Exiting browser.[/dim]")
            return

        elif action.kind == "help":
            ui.console.print(Panel(HELP_TEXT, border_style="grey50", box=box.ROUNDED))

        elif action.kind == "next":
            if page < n_pages:
                page += 1
            else:
                ui.print_warning("Already on the last page.")

        elif action.kind == "prev":
            if page > 1:
                page -= 1
            else:
                ui.print_warning("Already on the first page.")

        elif action.kind == "goto":
            if 1 <= action.page <= n_pages:
                page = action.page
            else:
                ui.print_warning(f"Page {action.page} is out of range (1-{n_pages}).")

        elif action.kind == "view":
            if 1 <= action.index <= len(page_results):
                _render_detail(page_results[action.index - 1], action.index)
            else:
                ui.print_warning(f"No item #{action.index} on this page (1-{len(page_results)}).")

        elif action.kind == "open":
            if 1 <= action.index <= len(page_results):
                target = page_results[action.index - 1]
                # target.url is attacker-influenced (whatever got
                # indexed), and webbrowser.open() will hand it straight to
                # the OS's URI-scheme dispatch -- not just http/https, but
                # anything the OS or an installed app has registered a
                # handler for (file://, custom app schemes, etc). Same
                # scheme floor as ssrf_guard's fetch path, applied here
                # for the same reason: this tool only ever knows how to
                # safely hand off a web page, not an arbitrary URI.
                allowed, reason = check_scheme(target.url)
                if not allowed:
                    ui.print_warning(f"Refusing to open '{target.url}': {reason}")
                    continue
                try:
                    webbrowser.open(target.url)
                    ui.print_success(f"Opened {target.url}")
                except Exception as e:  # noqa: BLE001 - browser launch failures shouldn't crash the browser
                    ui.print_error(f"Couldn't open browser: {e}")
            else:
                ui.print_warning(f"No item #{action.index} on this page (1-{len(page_results)}).")

        else:
            ui.print_warning(f"Unrecognized command: '{action.raw.strip()}'. Type 'h' for help.")

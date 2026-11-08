"""
The Textual "Pro" TUI: a persistent, full-screen application (as opposed
to the CLI's one-shot commands, or tui.py's paginated post-scan browser).

Layout: a job rail on the left (every open scan, with a live status dot
and a sparkline for --watch jobs), a live results table in the center
(rows stream in as async_core.run_search_async finds them), and an
inspector panel on the right showing full detail for the selected row.
Ctrl+P opens a fuzzy-matched command palette (LXDorkCommandProvider,
backed by tui_pro.palette) for jumping to any preset, action, or theme
without memorizing keybindings.

All actual decision-making (which row is selected, what's visible after
a filter, which commands match a palette query) lives in tui_pro.state
and tui_pro.palette, which have no textual import and are unit tested
directly. This file's job is only to turn that state into widgets and
turn key presses/clicks into calls back into it -- so a change here can't
silently break the underlying logic without the covered modules changing
too, and vice versa.

Requires the optional `textual` dependency: pip install "lx-dork-pro[tui]"
(or `pip install textual` directly). Imported lazily by cli.py's `ui`
command specifically so the rest of the tool has no hard dependency on it.
"""

import asyncio
import os
import tempfile
import webbrowser
from datetime import datetime, timezone
from functools import partial
from typing import Dict, Optional

from textual import work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.command import DiscoveryHit, Hit, Hits, Provider
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.reactive import reactive
from textual.screen import ModalScreen
from textual.widgets import DataTable, Footer, Header, Input, Label, ListItem, ListView, Static
from textual.worker import Worker

from ..async_core import SearchCancelled, run_search_async
from ..config import CONFIG_DIR, load_config, save_config
from ..engines import SearchResult
from ..normalize import normalize_url
from ..exporter import export_results
from ..fingerprint import fingerprint_results
from ..presets import PRESETS, get_preset_queries, get_query_severity_map, normalize_target
from ..probe import probe_urls
from ..screenshot import capture_results, is_available as screenshot_available
from ..secrets_scan import scan_results as scan_secrets
from ..ssrf_guard import check_scheme
from ..theme import THEMES, list_themes
from ..ui import _esc, set_theme
from ..verify import verify_results
from .palette import Command, default_commands, filter_commands
from .sparkline import render_sparkline
from .state import AppState, JobState, JobStatus, new_job_id

# Rich markup styles for each severity, used where a finding's severity
# is rendered as a colored inline span inside a DataTable cell or Static
# widget body -- NOT the same thing as _SEVERITY_CSS_CLASS below, and the
# two must not be used interchangeably: Rich markup like "[bold red]x[/]"
# looks up a *Rich style* (a color name, "bold", or a registered Console
# theme style), while a Textual CSS class like "sev-critical" is a
# *widget* concept applied via add_class()/the CSS block below -- it is
# not a valid Rich style name, and previously WAS used inside an
# add_row() markup string here, which Textual (built on Rich's own markup
# parser for plain-string cell content) would fail to resolve.
_SEVERITY_RICH_STYLE = {
    "critical": "bold white on red3",
    "high": "bold red",
    "medium": "bold yellow",
    "low": "cyan",
    "info": "dim white",
}

# Real Textual CSS classes (see the CSS block below, and .job-row-active's
# use via add_class()) -- kept for genuine widget-level styling, distinct
# from _SEVERITY_RICH_STYLE above.
_SEVERITY_CSS_CLASS = {
    "critical": "sev-critical",
    "high": "sev-high",
    "medium": "sev-medium",
    "low": "sev-low",
    "info": "sev-info",
}


class LXDorkCommandProvider(Provider):
    """Bridges tui_pro.palette's plain-data Command list into Textual's
    command palette (Ctrl+P). Matching is delegated to Textual's own
    fuzzy matcher (self.matcher) for consistent highlighting/scoring with
    every other provider in the palette, rather than palette.fuzzy_match
    -- that function backs this class's *unit tests* and any non-Textual
    consumer of the same command list, not the on-screen palette itself.
    """

    async def discover(self) -> Hits:
        app: "LXDorkProApp" = self.app  # type: ignore[assignment]
        for cmd in app.palette_commands:
            yield DiscoveryHit(cmd.title, partial(app.run_command, cmd.id), help=cmd.category)

    async def search(self, query: str) -> Hits:
        app: "LXDorkProApp" = self.app  # type: ignore[assignment]
        matcher = self.matcher(query)
        for cmd in app.palette_commands:
            score = matcher.match(cmd.title)
            if score > 0:
                yield Hit(score, matcher.highlight(cmd.title), partial(app.run_command, cmd.id), help=cmd.category)


class HelpScreen(ModalScreen):
    """Full keybinding cheat sheet, dismissed with any key."""

    DEFAULT_CSS = """
    HelpScreen {
        align: center middle;
    }
    #help-panel {
        width: 60;
        height: auto;
        border: round $accent;
        padding: 1 2;
        background: $panel;
    }
    """

    def compose(self) -> ComposeResult:
        with Vertical(id="help-panel"):
            yield Label("[bold]LX-Dork-Pro -- keybindings[/bold]\n")
            yield Static(
                "j / k        move selection down / up\n"
                "g / G        jump to first / last row\n"
                "/            focus the filter box\n"
                "escape       clear filter / unfocus\n"
                "ctrl+n/b     next / previous job\n"
                "p            probe selected URL\n"
                "f            fingerprint selected URL\n"
                "s            scan selected URL for secrets\n"
                "x            screenshot selected URL\n"
                "o            open selected URL in your browser\n"
                "v            view raw response for selected URL\n"
                "ctrl+p       command palette (presets, themes, actions)\n"
                "?            this screen\n"
                "q            quit\n"
            )
            yield Label("\n[dim]press any key to close[/dim]")

    def on_key(self, event) -> None:
        self.dismiss()


class LXDorkProApp(App):
    """The main application. `run_search_async` (async_core.py) is
    used from a Textual worker so the event loop it drives is the same
    kind of asyncio loop async_core.run_search_async already targets --
    Textual apps are themselves asyncio-native, so `--async-core`'s
    orchestration layer and this TUI were built for exactly this pairing.
    """

    TITLE = "LX-Dork-Pro"
    COMMANDS = App.COMMANDS | {LXDorkCommandProvider}

    CSS = """
    Screen {
        background: $surface;
    }
    #job-rail {
        width: 28;
        border-right: solid $panel-lighten-2;
        padding: 1;
    }
    #center {
        width: 1fr;
        padding: 0 1;
    }
    #inspector {
        width: 40;
        border-left: solid $panel-lighten-2;
        padding: 1;
    }
    .job-row-active {
        background: $accent 30%;
    }
    .sev-critical { color: $error; text-style: bold; }
    .sev-high { color: $error; }
    .sev-medium { color: $warning; }
    .sev-low { color: $accent; }
    .sev-info { color: $text-muted; }
    """

    BINDINGS = [
        Binding("j", "move_down", "Down", show=False),
        Binding("k", "move_up", "Up", show=False),
        Binding("g", "select_first", "Top", show=False),
        Binding("G", "select_last", "Bottom", show=False),
        Binding("slash", "focus_filter", "Filter"),
        Binding("escape", "clear_filter_or_blur", "Clear", show=False),
        Binding("ctrl+n", "next_job", "Next job"),
        Binding("ctrl+b", "prev_job", "Prev job", show=False),
        Binding("p", "row_probe", "Probe"),
        Binding("f", "row_fingerprint", "Fingerprint"),
        Binding("s", "row_secrets", "Secrets"),
        Binding("x", "row_screenshot", "Screenshot"),
        Binding("o", "row_open", "Open"),
        Binding("v", "row_view", "View raw"),
        Binding("question_mark", "toggle_help", "Help"),
        Binding("q", "quit", "Quit", show=False),
    ]

    selected_finding_url: reactive[Optional[str]] = reactive(None)

    def __init__(self, initial_preset: Optional[str] = None, initial_target: Optional[str] = None):
        super().__init__()
        self.state = AppState()
        self.cfg = load_config()
        self.palette_commands = default_commands(list(PRESETS.keys()), list_themes())
        self._initial_preset = initial_preset
        self._initial_target = initial_target
        # job_id -> the Worker driving that job's run_job() call, so
        # job.cancel (see run_command) can cancel the *active* job
        # specifically rather than every job at once. Not stored on
        # JobState itself (state.py) since JobState is a plain-data class
        # with zero Textual dependency, tested standalone -- a Worker
        # reference doesn't belong there.
        self._job_workers: Dict[str, Worker] = {}
        # Streamed results arrive one at a time; rebuilding the whole table per
        # result is O(n^2) and resets the cursor. Coalesce into one refresh per
        # interval instead (see _schedule_results_refresh).
        self._refresh_timer = None
        # job_id -> Event that wakes a watch job early from its between-cycles sleep
        self._job_wake: Dict[str, asyncio.Event] = {}

    # -- layout ------------------------------------------------------

    def compose(self) -> ComposeResult:
        yield Header()
        with Horizontal():
            with Vertical(id="job-rail"):
                yield Label("[bold]Jobs[/bold]")
                yield ListView(id="job-list")
            with Vertical(id="center"):
                yield Input(placeholder="Type to filter (or press /)...", id="filter-input")
                yield DataTable(id="results-table")
            with VerticalScroll(id="inspector"):
                yield Static("Select a result to inspect it here.", id="inspector-body")
        yield Footer()

    def on_mount(self) -> None:
        table = self.query_one("#results-table", DataTable)
        table.cursor_type = "row"
        table.add_columns("Score", "Sev", "URL", "Why")
        if self._initial_preset and self._initial_target:
            self.start_preset_job(self._initial_preset, self._initial_target)

    # -- job management ------------------------------------------------

    def start_preset_job(self, preset_name: str, target: str, engines_list=None) -> None:
        try:
            target = normalize_target(target)
        except ValueError as e:
            self.notify(str(e), severity="error")
            return
        cfg = self.cfg
        engines_list = engines_list or cfg.get("default_engines", ["searxng", "duckduckgo"])
        queries = get_preset_queries(preset_name, target)
        severity_map = get_query_severity_map([preset_name], target)
        job = JobState(
            id=new_job_id(), label=f"{preset_name} :: {target}",
            queries=queries, engines=engines_list, severity_map=severity_map,
        )
        self._launch_job(job)

    def start_dork_job(self, dork: str, engines_list=None) -> None:
        """Run a single raw dork string with no preset behind it -- same
        shape as start_preset_job, minus the preset-derived queries/
        severity_map (a raw dork has no severity to score findings
        against, same as the CLI's plain `dork` command vs `preset`).
        """
        cfg = self.cfg
        engines_list = engines_list or cfg.get("default_engines", ["searxng", "duckduckgo"])
        job = JobState(
            id=new_job_id(), label=dork,
            queries=[dork], engines=engines_list, severity_map=None,
        )
        self._launch_job(job)

    def _launch_job(self, job: JobState) -> None:
        self.state.add_job(job)
        self.refresh_job_rail()
        self.refresh_results_table()
        self._job_workers[job.id] = self.run_job(job)

    @work(exclusive=False, thread=False)
    async def run_job(self, job: JobState) -> None:
        """Run a job once, or -- when job.watch_interval_minutes is set -- keep
        re-running it every N minutes until cancelled or switched off.

        Results accumulate across cycles; only URLs not seen before (by
        normalized URL) are added, so each cycle's `new_count` really is "new".
        A watch job survives a failed cycle and gives up after 5 in a row,
        matching the CLI's `--watch`.
        """
        job.status = JobStatus.RUNNING
        self.refresh_job_rail()
        wake = self._job_wake[job.id] = asyncio.Event()
        seen = {normalize_url(r.url) for r in job.results}
        cycle_new = 0
        cycles_done = 0
        failures = 0

        def on_result(result: SearchResult) -> None:
            # run_search_async invokes this from inside its own coroutine, i.e. on
            # the app's event-loop thread (we await it directly below instead of
            # pushing a blocking call into a thread), so widgets can be touched
            # directly -- no call_from_thread marshalling needed.
            nonlocal cycle_new
            key = normalize_url(result.url)
            if key in seen:
                return
            seen.add(key)
            cycle_new += 1
            job.add_result(result)
            if self.state.active_job_id == job.id:
                self._schedule_results_refresh()

        try:
            while True:
                cycle_new = 0
                try:
                    # Awaited ON the app's loop (not via asyncio.to_thread): Worker.cancel()
                    # raises CancelledError at this await, which run_search_async turns
                    # into SearchCancelled after cancelling its in-flight engine tasks --
                    # so cancelling a job really stops it, instead of marking it
                    # "cancelled" while a background thread keeps hitting the engines.
                    await run_search_async(
                        job.engines, job.queries, self.cfg.get("default_limit", 30),
                        self.cfg, self.cfg.get("request_delay", 1.5), on_result=on_result,
                    )
                    failures = 0
                    job.error = None
                except (asyncio.CancelledError, SearchCancelled):
                    raise
                except Exception as e:  # noqa: BLE001
                    failures += 1
                    if not job.watch_interval_minutes or failures >= 5:
                        raise               # one-shot job, or a watch job that's persistently broken
                    job.error = f"cycle failed ({e}); {failures}/5 consecutive failures"

                job.record_cycle(cycle_new)
                if cycles_done and cycle_new:
                    self.notify(f"{job.label}: {cycle_new} new result(s)")
                cycles_done += 1

                if not job.watch_interval_minutes:
                    break
                job.status = JobStatus.IDLE          # between cycles: alive, not finished
                self.refresh_job_rail()
                wake.clear()
                try:
                    await asyncio.wait_for(wake.wait(), timeout=job.watch_interval_minutes * 60)
                except asyncio.TimeoutError:
                    pass                              # interval elapsed -> next cycle
                if not job.watch_interval_minutes:
                    break                             # switched off while sleeping
                job.status = JobStatus.RUNNING
                self.refresh_job_rail()
            job.status = JobStatus.DONE
        except (asyncio.CancelledError, SearchCancelled):
            # job.cancel (see run_command) calls Worker.cancel(). Record the
            # status, then re-raise a CancelledError so Textual's worker
            # machinery still sees the cancellation (SearchCancelled is a
            # plain Exception and would otherwise be reported as a failure).
            job.status = JobStatus.CANCELLED
            job.error = "Cancelled by user"
            raise asyncio.CancelledError()
        except Exception as e:  # noqa: BLE001 -- surface the error in the rail rather than crashing the app
            job.status = JobStatus.ERROR
            job.error = str(e)
        finally:
            self._job_workers.pop(job.id, None)
            self._job_wake.pop(job.id, None)
            self._cancel_refresh_timer()
            self.refresh_job_rail()
            self.refresh_results_table()

    def set_watch(self, job: JobState, minutes: Optional[int]) -> None:
        """Turn watch mode on (every `minutes`) or off (None) for a job, whatever
        state it's in: a finished job is restarted as a watcher; a sleeping one
        is woken so it re-reads the setting; a mid-cycle one picks it up when
        the cycle ends."""
        job.watch_interval_minutes = minutes
        if job.id in self._job_workers:
            wake = self._job_wake.get(job.id)
            if wake is not None and job.status == JobStatus.IDLE:
                wake.set()
        elif minutes:
            self._job_workers[job.id] = self.run_job(job)
        self.refresh_job_rail()

    def _schedule_results_refresh(self) -> None:
        """Coalesce a burst of streamed results into one table rebuild."""
        if self._refresh_timer is None:
            self._refresh_timer = self.set_timer(0.2, self._flush_results_refresh)

    def _flush_results_refresh(self) -> None:
        self._refresh_timer = None
        self.refresh_results_table()

    def _cancel_refresh_timer(self) -> None:
        if self._refresh_timer is not None:
            try:
                self._refresh_timer.stop()
            except Exception:  # noqa: BLE001 -- timer already fired/stopped
                pass
            self._refresh_timer = None

    def refresh_job_rail(self) -> None:
        job_list = self.query_one("#job-list", ListView)
        job_list.clear()
        for job_id in self.state.job_order:
            job = self.state.jobs[job_id]
            dot = job.status_dot
            spark = render_sparkline(job.results_per_cycle, width=8) if job.watch_interval_minutes else ""
            label = f"{dot} {job.label[:18]}  {len(job.results)}  {spark}"
            item = ListItem(Label(label), name=job_id)
            if job_id == self.state.active_job_id:
                item.add_class("job-row-active")
            job_list.append(item)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "job-list" and event.item.name:
            self.state.select_job(event.item.name)
            self.refresh_job_rail()
            self.refresh_results_table()

    def action_next_job(self) -> None:
        self.state.next_job()
        self.refresh_job_rail()
        self.refresh_results_table()

    def action_prev_job(self) -> None:
        self.state.prev_job()
        self.refresh_job_rail()
        self.refresh_results_table()

    # -- results table / inspector --------------------------------------

    def refresh_results_table(self) -> None:
        table = self.query_one("#results-table", DataTable)
        table.clear()
        for f in self.state.visible_findings():
            # Rich markup style, not the Textual CSS class -- see the
            # _SEVERITY_RICH_STYLE/_SEVERITY_CSS_CLASS comment above the
            # class definition for why these are two different mappings.
            style = _SEVERITY_RICH_STYLE.get(f.severity_label, "white")
            # f.url/f.title are attacker-influenced (whatever a search
            # engine indexed) and this cell content is markup-parsed by
            # Textual the same way a Rich Table's is -- see ui._esc's
            # docstring for the full "crafted title -> fake styling or a
            # crash" reasoning this guards against.
            table.add_row(
                str(f.confidence_score), f"[{style}]{f.severity_label.upper()}[/{style}]", _esc(f.url),
                self._why_text(f), key=f.url,
            )
        # clear() resets the cursor to row 0, which fights the user while results
        # stream in -- put it back where they were (clamped to the new length).
        rows = len(self.state.visible_findings())
        if rows:
            table.move_cursor(row=min(self.state.selected_index, rows - 1))
        self.update_inspector()

    @staticmethod
    def _why_text(finding) -> str:
        parts = []
        if finding.preset_severity:
            parts.append(f"preset:{finding.preset_severity}")
        if finding.corroboration_count > 1:
            parts.append(f"{finding.corroboration_count} engines")
        if finding.verify_confidence:
            parts.append(f"verify:{finding.verify_confidence}")
        if finding.has_secrets:
            parts.append(f"{len(finding.secrets)} secret(s)")
        if finding.vuln_hints:
            parts.append(f"{len(finding.vuln_hints)} hint(s)")
        if finding.soft_404:
            parts.append("soft-404")
        if finding.triage:
            parts.append("triage:" + ",".join(sorted({t.name for t in finding.triage})[:2]))
        if finding.technologies:
            parts.append(",".join(finding.technologies[:2]))
        return "  ".join(parts) if parts else "-"

    def on_data_table_row_highlighted(self, event: DataTable.RowHighlighted) -> None:
        if event.data_table.id != "results-table":
            return
        rows = self.state.visible_findings()
        if event.cursor_row is not None and 0 <= event.cursor_row < len(rows):
            self.state.selected_index = event.cursor_row
            self.update_inspector()

    def update_inspector(self) -> None:
        body = self.query_one("#inspector-body", Static)
        f = self.state.selected_finding
        if not f:
            body.update("Select a result to inspect it here.")
            return
        # url/title/secret redactions below are all attacker-influenced or
        # derived from attacker-influenced page content -- see refresh_results_table's
        # comment above for why these must be escaped before reaching a
        # markup-parsed widget body.
        lines = [
            f"[bold]{_esc(f.url)}[/bold]", "",
            f"Score: {f.confidence_score}  ({f.severity_label.upper()})",
            f"Engine: {f.primary_engine}" + (f"  (+{len(f.also_seen_in)} more)" if f.also_seen_in else ""),
        ]
        if f.title:
            lines.append(f"Title: {_esc(f.title)}")
        if f.verify_confidence:
            lines.append(f"Verify: {f.verify_confidence} ({f.verify_confirmed_count}/{f.verify_total_count})")
        if f.technologies:
            lines.append(f"Tech: {', '.join(f.technologies)}")
        if f.secrets:
            lines.append(f"\n[bold red]Secrets found ({len(f.secrets)}):[/bold red]")
            for s in f.secrets:
                lines.append(f"  {s.name}: {_esc(s.redacted)}")
        elif "secrets" in getattr(self.state.active_job, "row_overlays", {}).get(f.url, {}):
            lines.append("\n[dim]No secrets found on this page.[/dim]")
        if f.probe_alive is not None:
            verdict = "alive" if f.probe_alive else ("protected" if f.probe_protected else "dead")
            lines.append(f"Probe: {verdict} ({f.probe_status or f.probe_error_kind or '?'})")
        if f.screenshot_path:
            lines.append(f"Screenshot: {f.screenshot_path}")
        body.update("\n".join(lines))

    # -- filter -----------------------------------------------------

    def action_focus_filter(self) -> None:
        self.query_one("#filter-input", Input).focus()

    def action_clear_filter_or_blur(self) -> None:
        filter_input = self.query_one("#filter-input", Input)
        if filter_input.has_focus:
            filter_input.value = ""
            self.state.set_filter("")
            self.refresh_results_table()
            self.query_one("#results-table", DataTable).focus()

    def on_input_changed(self, event: Input.Changed) -> None:
        if event.input.id == "filter-input":
            self.state.set_filter(event.value)
            self.refresh_results_table()

    # -- selection movement ----------------------------------------

    def action_move_down(self) -> None:
        self.state.move_selection(1)
        self._sync_table_cursor()

    def action_move_up(self) -> None:
        self.state.move_selection(-1)
        self._sync_table_cursor()

    def action_select_first(self) -> None:
        self.state.select_first()
        self._sync_table_cursor()

    def action_select_last(self) -> None:
        self.state.select_last()
        self._sync_table_cursor()

    def _sync_table_cursor(self) -> None:
        table = self.query_one("#results-table", DataTable)
        table.move_cursor(row=self.state.selected_index)
        self.update_inspector()

    # -- row actions --------------------------------------------------

    def action_row_probe(self) -> None:
        self._run_row_action(self._do_probe)

    def action_row_fingerprint(self) -> None:
        self._run_row_action(self._do_fingerprint)

    def action_row_secrets(self) -> None:
        self._run_row_action(self._do_secrets)

    def action_row_screenshot(self) -> None:
        self._run_row_action(self._do_screenshot)

    def action_row_open(self) -> None:
        f = self.state.selected_finding
        if f:
            # f.url is attacker-influenced -- see tui.py's browse() "open"
            # handler for the same check and why it's unconditional
            # (webbrowser.open hands the URL straight to the OS's URI
            # scheme dispatch, not just http/https).
            allowed, reason = check_scheme(f.url)
            if not allowed:
                self.notify(f"Refusing to open '{f.url}': {reason}", severity="error")
                return
            webbrowser.open(f.url)
            self.notify(f"Opened {f.url}")

    def action_row_view(self) -> None:
        f = self.state.selected_finding
        if f:
            body = self.query_one("#inspector-body", Static)
            body.update(f"[bold]{_esc(f.url)}[/bold]\n\n{_esc(f.snippet) if f.snippet else '[dim]no snippet available[/dim]'}")

    def _run_row_action(self, coro_factory) -> None:
        f = self.state.selected_finding
        if not f:
            self.notify("No row selected.", severity="warning")
            return
        self.run_worker(coro_factory(f), exclusive=False)

    async def _do_probe(self, finding) -> None:
        results = await asyncio.to_thread(probe_urls, [finding.url])
        self._merge_single_finding_update(finding.url, probe=results[0] if results else None)
        self.refresh_results_table()

    async def _do_fingerprint(self, finding) -> None:
        result_stub = SearchResult(url=finding.url, engine=finding.primary_engine)
        results = await asyncio.to_thread(fingerprint_results, [result_stub])
        self._merge_single_finding_update(finding.url, fingerprint=results[0] if results else None)
        self.refresh_results_table()

    async def _do_secrets(self, finding) -> None:
        result_stub = SearchResult(url=finding.url, engine=finding.primary_engine)
        secret_map = await asyncio.to_thread(scan_secrets, [result_stub])
        self._merge_single_finding_update(finding.url, secrets=secret_map.get(finding.url, []))
        self.refresh_results_table()

    async def _do_screenshot(self, finding) -> None:
        if not screenshot_available():
            self.notify("wkhtmltoimage not installed -- can't take screenshots.", severity="error")
            return
        result_stub = SearchResult(url=finding.url, engine=finding.primary_engine)
        # tempfile.gettempdir() rather than a hardcoded "/tmp": portable
        # across platforms (Windows has no /tmp), and avoids a predictable
        # shared path that's a minor race/collision risk on a multi-user
        # host -- a real (if low-severity) concern, not just a lint nag.
        screenshot_dir = os.path.join(tempfile.gettempdir(), "lxdorkpro-screenshots")
        results = await asyncio.to_thread(capture_results, [result_stub], screenshot_dir)
        if results and results[0].success:
            self.notify(f"Saved to {results[0].path}")
        self.refresh_results_table()

    def _merge_single_finding_update(self, url: str, probe=None, fingerprint=None, secrets=None) -> None:
        """A row action (p/f/s) checks just the selected URL rather than
        re-running a full batch across the whole job. Recording it via
        JobState.set_row_overlay means it's folded into JobState.findings
        (and therefore this row's fused score) the same way a full
        --probe/--fingerprint/--secrets run's results would be, not just
        shown in the inspector as a disconnected side note.
        """
        job = self.state.active_job
        if not job:
            return
        job.set_row_overlay(url, probe=probe, fingerprint=fingerprint, secrets=secrets)

    # -- command palette dispatch --------------------------------------

    def _apply_theme(self, name: str) -> None:
        """Persist the chosen theme and apply it to the Rich side (banner,
        dashboard). Saved WITHOUT env-supplied secrets (include_env=False), and
        the CLI reads it back on its next run. The TUI's own pane colours are
        not re-skinned by this."""
        if name not in THEMES:
            self.notify(f"Unknown theme '{name}'.", severity="error")
            return
        try:
            cfg = load_config(include_env=False)
            cfg["theme"] = name
            save_config(cfg)
        except OSError as e:
            self.notify(f"Couldn't save theme: {e.strerror or e}", severity="error")
            return
        set_theme(name)
        self.notify(f"Theme '{name}' saved; applies to the CLI banner/dashboard from now on "
                    f"(the TUI's own panes keep the default skin).")

    def run_command(self, command_id: str) -> None:
        if command_id == "job.next":
            self.action_next_job()
        elif command_id == "job.prev":
            self.action_prev_job()
        elif command_id == "job.close":
            if self.state.active_job_id:
                self.state.remove_job(self.state.active_job_id)
                self.refresh_job_rail()
                self.refresh_results_table()
        elif command_id == "row.probe":
            self.action_row_probe()
        elif command_id == "row.fingerprint":
            self.action_row_fingerprint()
        elif command_id == "row.secrets":
            self.action_row_secrets()
        elif command_id == "row.screenshot":
            self.action_row_screenshot()
        elif command_id == "row.open":
            self.action_row_open()
        elif command_id == "row.view":
            self.action_row_view()
        elif command_id == "view.filter_clear":
            self.query_one("#filter-input", Input).value = ""
            self.state.set_filter("")
            self.refresh_results_table()
        elif command_id == "view.help":
            self.action_toggle_help()
        elif command_id == "view.quit":
            self.exit()
        elif command_id == "job.new_dork":
            self.push_screen(_DorkPromptScreen(self.start_dork_job))
        elif command_id == "job.new_preset":
            self.push_screen(_PresetPickerScreen(list(PRESETS.keys()), self._on_preset_picked))
        elif command_id == "job.cancel":
            self._cancel_active_job()
        elif command_id == "view.export":
            self._export_active_job()
        elif command_id.startswith("preset.run:"):
            preset_name = command_id.split(":", 1)[1]
            self.push_screen(_TargetPromptScreen(preset_name, self.start_preset_job))
        elif command_id.startswith("job.watch:"):
            job = self.state.active_job
            if job is None:
                self.notify("No active job to watch.", severity="warning")
                return
            arg = command_id.split(":", 1)[1]
            self.set_watch(job, None if arg == "off" else int(arg))
            self.notify("Watch off." if arg == "off" else f"Watching '{job.label}' every {arg} min.")
        elif command_id.startswith("theme.set:"):
            theme_name = command_id.split(":", 1)[1]
            self._apply_theme(theme_name)

    def _on_preset_picked(self, preset_name: str) -> None:
        self.push_screen(_TargetPromptScreen(preset_name, self.start_preset_job))

    def _cancel_active_job(self) -> None:
        job = self.state.active_job
        if job is None:
            self.notify("No active job to cancel.", severity="warning")
            return
        if job.status != JobStatus.RUNNING:
            self.notify(f"'{job.label}' isn't running (status: {job.status.value}).", severity="warning")
            return
        worker = self._job_workers.get(job.id)
        if worker is None:
            # Shouldn't normally happen (a RUNNING job should always have
            # a live worker entry -- see _launch_job/run_job's finally),
            # but don't leave the operator stuck with no way to proceed.
            self.notify(f"No worker found for '{job.label}' -- marking it cancelled anyway.", severity="warning")
            job.status = JobStatus.CANCELLED
            job.error = "Cancelled by user"
            self.refresh_job_rail()
            return
        worker.cancel()
        self.notify(f"Cancelling '{job.label}'...")

    def _export_active_job(self) -> None:
        job = self.state.active_job
        if job is None or not job.results:
            self.notify("No results to export for the active job.", severity="warning")
            return
        export_dir = CONFIG_DIR / "exports"
        export_dir.mkdir(parents=True, exist_ok=True)
        stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        safe_label = "".join(c if c.isalnum() or c in "-_." else "_" for c in job.label)[:60]
        path = export_dir / f"{safe_label}-{stamp}.json"
        try:
            export_results(job.results, str(path))
        except Exception as e:  # noqa: BLE001 -- surface the error, don't crash the app over a failed export
            self.notify(f"Export failed: {e}", severity="error")
            return
        self.notify(f"Exported {len(job.results)} result(s) to {path}")

    def action_toggle_help(self) -> None:
        self.push_screen(HelpScreen())


class _TargetPromptScreen(ModalScreen):
    """Tiny modal for "run this preset against which target?" after
    picking a preset from the command palette.
    """

    DEFAULT_CSS = """
    _TargetPromptScreen { align: center middle; }
    #prompt-box { width: 50; height: auto; border: round $accent; padding: 1 2; background: $panel; }
    """

    def __init__(self, preset_name: str, on_submit):
        super().__init__()
        self.preset_name = preset_name
        self.on_submit = on_submit

    def compose(self) -> ComposeResult:
        with Vertical(id="prompt-box"):
            yield Label(f"Run preset [bold]{self.preset_name}[/bold] against target:")
            yield Input(placeholder="example.com", id="target-input")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        target = event.value.strip()
        self.dismiss()
        if target:
            self.on_submit(self.preset_name, target)


class _DorkPromptScreen(ModalScreen):
    """Tiny modal for "New job: raw dork" -- the equivalent of the CLI's
    `lxdorkpro dork -d "..."` from inside a running TUI session. Mirrors
    _TargetPromptScreen's shape exactly; the only difference is there's
    just the one free-text field (a full dork string already carries its
    own site:/inurl:/etc. operators, unlike a preset which needs a bare
    target domain filled into its templates).
    """

    DEFAULT_CSS = """
    _DorkPromptScreen { align: center middle; }
    #dork-prompt-box { width: 60; height: auto; border: round $accent; padding: 1 2; background: $panel; }
    """

    def __init__(self, on_submit):
        super().__init__()
        self.on_submit = on_submit

    def compose(self) -> ComposeResult:
        with Vertical(id="dork-prompt-box"):
            yield Label("New job -- raw dork query:")
            yield Input(placeholder='site:example.com inurl:admin intitle:"login"', id="dork-input")

    def on_input_submitted(self, event: Input.Submitted) -> None:
        dork = event.value.strip()
        self.dismiss()
        if dork:
            self.on_submit(dork)


class _PresetPickerScreen(ModalScreen):
    """"New job: from preset" -- a scrollable pick-list of every preset
    name. Separate from the individual `preset.run:<name>` palette
    entries (which jump straight to _TargetPromptScreen for one preset
    already chosen by fuzzy-search): this is for browsing the full list
    at a glance rather than typing a name. Selecting one still ends at
    the same _TargetPromptScreen either way.
    """

    DEFAULT_CSS = """
    _PresetPickerScreen { align: center middle; }
    #preset-picker-box {
        width: 50; height: auto; max-height: 20; border: round $accent;
        padding: 1 2; background: $panel;
    }
    """

    def __init__(self, preset_names, on_pick):
        super().__init__()
        self.preset_names = preset_names
        self.on_pick = on_pick

    def compose(self) -> ComposeResult:
        with Vertical(id="preset-picker-box"):
            yield Label("New job -- pick a preset:")
            with ListView(id="preset-list"):
                for name in self.preset_names:
                    yield ListItem(Label(name), name=name)

    def on_list_view_selected(self, event: ListView.Selected) -> None:
        if event.list_view.id == "preset-list" and event.item.name:
            preset_name = event.item.name
            self.dismiss()
            self.on_pick(preset_name)


def run_app(initial_preset: Optional[str] = None, initial_target: Optional[str] = None) -> None:
    LXDorkProApp(initial_preset=initial_preset, initial_target=initial_target).run()

"""
Pure state/logic layer for the Textual "Pro" TUI (lxdorkpro/tui_pro/app.py).

Deliberately has no `textual` import anywhere in this file, mirroring the
separation tui_commands.py already established for the original curses-
style browser: decidable logic (what should be selected, what's visible
after a filter, which job is active) lives here and is fully unit
testable without a terminal, a running event loop, or even `textual`
installed; app.py is the thin layer that turns this state into on-screen
widgets and turns key presses into calls into this module.
"""

import itertools
from dataclasses import dataclass, field
from enum import Enum
from typing import Dict, List, Optional

from ..engines import SearchResult
from ..findings import Finding, build_findings, sort_findings


class JobStatus(str, Enum):
    IDLE = "idle"
    RUNNING = "running"
    DONE = "done"
    ERROR = "error"
    CANCELLED = "cancelled"


_id_counter = itertools.count(1)


def new_job_id() -> str:
    """Monotonic, human-scannable job ids ("job-1", "job-2", ...) -- good
    enough for a single TUI session; not intended to be globally unique
    or persisted (history.py's job keys already serve that purpose).
    """
    return f"job-{next(_id_counter)}"


@dataclass
class JobState:
    """Everything the TUI tracks about one running/finished scan. Wraps
    the raw SearchResults it has collected so far; `findings` derives the
    fused, scored view on demand via findings.build_findings rather than
    keeping a second, potentially-stale copy in sync by hand.
    """
    id: str
    label: str
    queries: List[str]
    engines: List[str]
    status: JobStatus = JobStatus.IDLE
    results: List[SearchResult] = field(default_factory=list)
    severity_map: Optional[Dict[str, str]] = None
    error: Optional[str] = None
    watch_interval_minutes: Optional[int] = None
    # Count of genuinely new results found per --watch cycle, oldest
    # first, capped so the job rail's sparkline has a bounded history to
    # render rather than growing unboundedly over a long-running job.
    results_per_cycle: List[int] = field(default_factory=list)
    _MAX_CYCLE_HISTORY = 30
    # Per-URL overlay populated by single-row TUI actions (p/f/s -- probe/
    # fingerprint/secrets on just the selected row, rather than a full
    # batch run across the whole job). Declared as a real dataclass field
    # rather than a dynamically-added attribute so it's visible in the
    # type signature and testable without reaching for hasattr/setattr.
    # Shape: {url: {"probe": ProbeResult, "fingerprint": FingerprintResult, "secrets": [SecretMatch, ...]}}
    row_overlays: Dict[str, dict] = field(default_factory=dict)
    # Passive URL-shape triage is free (no requests), so the TUI always applies it,
    # matching what `--triage` gives the CLI.
    triage: bool = True
    # Derived-view cache. `findings` used to rebuild, rescore and re-sort every
    # result on EVERY access, and several things call it per keypress.
    # Invalidated by anything that changes its inputs (see _findings_key).
    _findings_cache: Optional[tuple] = field(default=None, repr=False, compare=False)
    _overlay_version: int = field(default=0, repr=False, compare=False)

    def add_result(self, result: SearchResult) -> None:
        self.results.append(result)
        self._overlay_version += 1  # explicit invalidation; don't rely on len() alone

    def reset_results(self) -> None:
        """Drop all results (e.g. before a re-run). Use this rather than
        results.clear(), which the findings cache could not see."""
        self.results.clear()
        self.row_overlays.clear()
        self._overlay_version += 1

    def record_cycle(self, new_count: int) -> None:
        self.results_per_cycle.append(new_count)
        if len(self.results_per_cycle) > self._MAX_CYCLE_HISTORY:
            self.results_per_cycle = self.results_per_cycle[-self._MAX_CYCLE_HISTORY:]

    def set_row_overlay(self, url: str, **kwargs) -> None:
        """Record a single-row action's result (probe=, fingerprint=,
        secrets=) for `url`, merged into `findings` below on the next
        access -- so a quick p/f/s check on one row actually moves that
        row's fused score, not just its inspector display.
        """
        overlay = self.row_overlays.setdefault(url, {})
        overlay.update({k: v for k, v in kwargs.items() if v is not None})
        self._overlay_version += 1  # invalidates the findings cache

    def _findings_key(self) -> tuple:
        """Everything `findings` depends on. `results` is a list that callers
        append to (or replace), so identity + length covers both; severity_map
        and the overlays are covered by identity / the overlay version."""
        return (id(self.results), len(self.results), id(self.severity_map), self._overlay_version, self.triage)

    @property
    def findings(self) -> List[Finding]:
        """Fused, scored, sorted findings. Cached until results/overlays change;
        treat the returned list as read-only (it is shared between callers)."""
        key = self._findings_key()
        if self._findings_cache is not None and self._findings_cache[0] == key:
            return self._findings_cache[1]
        built = self._build_findings()
        self._findings_cache = (key, built)
        return built

    def _build_findings(self) -> List[Finding]:
        # Row-overlay probe/fingerprint results and secret-scan results
        # are folded in alongside any full-batch --probe/--fingerprint/
        # --secrets run would have produced -- build_findings just needs
        # them in the same shape either way, so a one-off row check and a
        # full pass both land on the same, single scoring path.
        probe_results = [v["probe"] for v in self.row_overlays.values() if v.get("probe") is not None]
        fingerprint_results = [v["fingerprint"] for v in self.row_overlays.values() if v.get("fingerprint") is not None]
        secret_results = {url: v["secrets"] for url, v in self.row_overlays.items() if "secrets" in v}
        verify_results = [v["verify"] for v in self.row_overlays.values() if v.get("verify") is not None]
        vuln_hint_results = {url: v["vuln_hints"] for url, v in self.row_overlays.items() if "vuln_hints" in v}
        return sort_findings(build_findings(
            self.results,
            probe_results=probe_results or None,
            fingerprint_results=fingerprint_results or None,
            secret_results=secret_results or None,
            verify_results=verify_results or None,
            vuln_hint_results=vuln_hint_results or None,
            severity_map=self.severity_map,
            triage=self.triage,
        ))

    @property
    def is_active_looking(self) -> bool:
        """Whether the job rail should show a "live" indicator -- running,
        or a watch job that's merely between cycles (idle isn't the same
        as finished for a --watch job, which is never really "done").
        """
        return self.status == JobStatus.RUNNING or (
            self.status == JobStatus.IDLE and self.watch_interval_minutes is not None
        )

    @property
    def status_dot(self) -> str:
        """The single-character indicator the job rail shows for this
        job's current state. Pulled out as its own pure property (rather
        than left as an inline ternary in app.py) specifically so it's
        unit-testable without a Textual App instance -- see this module's
        docstring on why decision-making lives here, not in app.py.
        """
        if self.is_active_looking:
            return "●"
        if self.status == JobStatus.DONE:
            return "✓"
        if self.status == JobStatus.ERROR:
            return "✗"
        if self.status == JobStatus.CANCELLED:
            return "⊘"
        return "○"


@dataclass
class AppState:
    """Top-level TUI state: every open job, which one is active, which
    row is selected within it, and the current result filter text.
    Multiple jobs let the TUI run more than one scan concurrently in
    separate tabs, instead of the CLI's one-scan-at-a-time model.
    """
    jobs: Dict[str, JobState] = field(default_factory=dict)
    job_order: List[str] = field(default_factory=list)
    active_job_id: Optional[str] = None
    selected_index: int = 0
    filter_text: str = ""

    def add_job(self, job: JobState) -> None:
        self.jobs[job.id] = job
        self.job_order.append(job.id)
        if self.active_job_id is None:
            self.active_job_id = job.id

    def remove_job(self, job_id: str) -> None:
        if job_id not in self.jobs:
            return
        was_active = self.active_job_id == job_id
        idx = self.job_order.index(job_id)
        del self.jobs[job_id]
        self.job_order.remove(job_id)
        if was_active:
            if self.job_order:
                # Prefer the job that took this one's place in the rail
                # (or the new last one, if this was the last job) so
                # closing a job doesn't jump focus back to the very top.
                self.active_job_id = self.job_order[min(idx, len(self.job_order) - 1)]
            else:
                self.active_job_id = None
        self.selected_index = 0
        self.filter_text = ""

    @property
    def active_job(self) -> Optional[JobState]:
        return self.jobs.get(self.active_job_id) if self.active_job_id else None

    def select_job(self, job_id: str) -> None:
        if job_id in self.jobs:
            self.active_job_id = job_id
            self.selected_index = 0
            self.filter_text = ""

    def next_job(self) -> None:
        if len(self.job_order) < 2:
            return
        idx = self.job_order.index(self.active_job_id)
        self.select_job(self.job_order[(idx + 1) % len(self.job_order)])

    def prev_job(self) -> None:
        if len(self.job_order) < 2:
            return
        idx = self.job_order.index(self.active_job_id)
        self.select_job(self.job_order[(idx - 1) % len(self.job_order)])

    def visible_findings(self) -> List[Finding]:
        """The active job's findings after the current filter (a plain
        case-insensitive substring match against URL/title -- the same
        "/" -> type -> narrow interaction as less/vim's search, not a
        regex DSL users would need to learn first).
        """
        job = self.active_job
        if not job:
            return []
        findings = job.findings
        if self.filter_text:
            needle = self.filter_text.lower()
            findings = [
                f for f in findings
                if needle in f.url.lower() or needle in (f.title or "").lower()
            ]
        return findings

    def move_selection(self, delta: int) -> None:
        count = len(self.visible_findings())
        if count == 0:
            self.selected_index = 0
            return
        self.selected_index = max(0, min(count - 1, self.selected_index + delta))

    def select_first(self) -> None:
        self.selected_index = 0

    def select_last(self) -> None:
        count = len(self.visible_findings())
        self.selected_index = max(0, count - 1)

    def set_filter(self, text: str) -> None:
        """Changing the filter resets the selection -- keeping the old
        numeric index would silently point at a different (or nonexistent)
        row once the visible list has shrunk or reordered.
        """
        self.filter_text = text
        self.selected_index = 0

    @property
    def selected_finding(self) -> Optional[Finding]:
        rows = self.visible_findings()
        if not rows or self.selected_index >= len(rows):
            return None
        return rows[self.selected_index]

"""
Unified Finding model: fuses everything LX-Dork-Pro knows about a single
URL -- which engines found it, its dork's preset severity, --verify's
signal confidence, --fingerprint's tech detections, secret-scan hits,
passive vuln-hint signatures, and --probe liveness -- into one object
with a single 0-100 confidence score.

Why this exists: today a scan renders results/probe/verify/fingerprint as
four SEPARATE tables keyed loosely by URL, so a user has to mentally
cross-reference them to answer "is THIS url actually worth my time?" This
module answers that question once, in one place, so the CLI/TUI/report/
export layers can all sort, filter, and display by the same score instead
of reimplementing the cross-referencing four times.

Scoring is intentionally simple and auditable (see `score_breakdown`) --
every point is traceable to a specific signal, not a black-box ML score.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional

from .engines import SearchResult
from .presets import severity_rank
from .secrets_scan import SecretMatch
from .vuln_hints import CATEGORY_FLOOR, VulnHint
from .url_triage import TriageTag, triage_points, triage_url


# Secrets that are public by design (client-side keys, bearer-less JWT
# structure): matching them is a lead, not a confirmed credential leak, so
# they must not raise the severity floor.
from .secrets_scan import PUBLIC_BY_DESIGN as _PUBLIC_BY_DESIGN  # noqa: E402


@dataclass
class Finding:
    url: str
    title: str = ""
    snippet: str = ""
    primary_engine: str = ""
    also_seen_in: List[str] = field(default_factory=list)  # other engines that independently found this URL
    source_query: str = ""
    preset_severity: Optional[str] = None  # from presets.get_query_severity_map, if this came from a preset/category run

    # Optional per-analysis results, attached if that analysis was run.
    verify_confidence: Optional[str] = None       # "high" | "medium" | "low" | "unreachable" | "unknown"
    verify_confirmed_count: int = 0
    verify_total_count: int = 0
    soft_404: bool = False                        # host answers the same for non-existent paths
    technologies: List[str] = field(default_factory=list)
    secrets: List[SecretMatch] = field(default_factory=list)
    vuln_hints: List[VulnHint] = field(default_factory=list)
    triage: List[TriageTag] = field(default_factory=list)   # passive URL-shape tags (--triage)
    probe_status: Optional[int] = None
    probe_alive: Optional[bool] = None
    probe_protected: bool = False                 # answered 401/403: exists but access-controlled
    probe_error_kind: str = ""
    screenshot_path: str = ""

    @property
    def corroboration_count(self) -> int:
        """How many independent engines found this same URL, including the
        primary one. 1 means only one engine ever saw it.
        """
        return 1 + len(self.also_seen_in)

    @property
    def has_secrets(self) -> bool:
        return len(self.secrets) > 0

    @property
    def has_vuln_hints(self) -> bool:
        return len(self.vuln_hints) > 0

    @property
    def score_breakdown(self) -> Dict[str, int]:
        """Every point contributing to `confidence_score`, labeled, so the
        total is always explainable rather than a black box. Points are
        additive and independently capped where noted; the final score is
        clamped to [0, 100] by `confidence_score`.
        """
        points: Dict[str, int] = {}

        # Preset severity: the a-priori "how bad is a hit on this dork"
        # rating, worth up to 30 points (critical) down to 0 (info/unrated).
        if self.preset_severity:
            points["preset_severity"] = severity_rank(self.preset_severity) * 7  # 0,7,14,21,28

        # Cross-engine corroboration: independent engines agreeing this URL
        # exists is real signal that it's not a one-off indexing fluke.
        # Diminishing returns after the first couple of extra engines.
        extra_engines = max(0, self.corroboration_count - 1)
        points["corroboration"] = min(extra_engines * 8, 20)

        # --verify: the dork's own signals (site/inurl/intitle/intext/ext)
        # actually holding up on the live page.
        if self.verify_confidence == "high":
            points["verify"] = 25
        elif self.verify_confidence == "medium":
            points["verify"] = 12
        elif self.verify_confidence == "low":
            points["verify"] = -10  # actively suspicious: engine indexed it, but the dork's own signals don't hold up
        elif self.verify_confidence == "unreachable":
            points["verify"] = -15  # can't be triaged at all right now

        # Secrets found on the page are the single strongest signal
        # available -- structural (high-confidence) matches count more
        # than entropy-gated generic ones, and each additional secret adds
        # a smaller increment (finding 5 secrets isn't 5x as urgent as
        # finding 1, the page is already a confirmed problem).
        if self.secrets:
            first, *rest = self.secrets
            base = 25 if first.confidence == "high" else 15
            points["secrets"] = base + min(len(rest) * 3, 15)

        # Passive vuln_hints: the target's own unmodified response already
        # shows a SQL/template-engine error or a debug console. This is
        # evidence a live DB or template layer exists and sometimes
        # errors -- real signal, but weaker than a confirmed secret (it
        # doesn't prove exploitability, only that something's already
        # leaking). sql_error/template_error are weighted a bit higher
        # than a bare stack_trace/debug_console, since the former point
        # more specifically at an injection-relevant code path.
        if self.vuln_hints:
            first, *rest = self.vuln_hints
            # Score = confidence/ranking weight (a confirmed SQL error outranks a debug page);
            # impact for triage comes from severity_floor / CATEGORY_FLOOR instead.
            base = {"sql_error": 20, "template_error": 20, "exposed_service": 16}.get(first.category, 12)
            points["vuln_hints"] = base + min(len(rest) * 3, 12)

        # URL-shape triage: passive and capped well below real evidence
        # (a secret or error message), so it ranks a long list without
        # ever outranking something actually observed.
        if self.triage:
            points["triage"] = triage_points(self.triage)

        # Liveness: a dead URL can't be exploited right now, but it isn't
        # irrelevant either (could come back, or the archival copy still
        # matters) -- small positive/negative nudge, not a hard gate.
        if self.probe_alive is True:
            points["liveness"] = 5
        elif self.probe_protected:
            # 401/403: the server answered and the resource very likely exists --
            # an access-controlled admin panel is a lead, not a dead link.
            points["liveness"] = 2
        elif self.probe_alive is False:
            points["liveness"] = -10

        return points

    @property
    def confidence_score(self) -> int:
        """Single 0-100 score fusing every signal available for this URL.
        Higher = more worth a human's attention right now. Clamped so a
        pile of small negatives (e.g. unreachable + low verify) can't push
        a genuinely severity-rated preset hit into negative territory and
        get it filtered out of a `--min-score` pass entirely.
        """
        total = sum(self.score_breakdown.values())
        return max(0, min(100, total))

    @property
    def severity_label(self) -> str:
        """Human-facing bucket derived from the fused score, for coloring/
        sorting in the CLI table, TUI, and reports without re-deriving
        thresholds in three different places.
        """
        score = self.confidence_score
        if score >= 70:
            bucket = "critical"
        elif score >= 50:
            bucket = "high"
        elif score >= 25:
            bucket = "medium"
        elif score > 0:
            bucket = "low"
        else:
            bucket = "info"
        # Impact floor: the score measures confidence; a confirmed credential
        # is serious regardless of how few other signals were collected.
        floor = self.severity_floor
        return bucket if severity_rank(bucket) >= severity_rank(floor) else floor

    @property
    def severity_floor(self) -> str:
        """Minimum severity implied by what was found, independent of score:
        private keys -> critical; other structural credentials -> high;
        SQL/template errors -> medium. Public-by-design tokens don't count."""
        floor = "info"
        for s in self.secrets:
            if s.confidence != "high" or s.name in _PUBLIC_BY_DESIGN:
                continue
            level = "critical" if s.category == "crypto" else "high"
            if severity_rank(level) > severity_rank(floor):
                floor = level
        for h in self.vuln_hints:
            level = CATEGORY_FLOOR.get(h.category)
            if level and severity_rank(level) > severity_rank(floor):
                floor = level
        return floor


def build_findings(
    results: List[SearchResult],
    verify_results: Optional[list] = None,
    fingerprint_results: Optional[list] = None,
    secret_results: Optional[Dict[str, List[SecretMatch]]] = None,
    vuln_hint_results: Optional[Dict[str, List[VulnHint]]] = None,
    probe_results: Optional[list] = None,
    screenshot_results: Optional[list] = None,
    severity_map: Optional[Dict[str, str]] = None,
    triage: bool = False,
) -> List[Finding]:
    """Merge a batch of SearchResults with whatever optional analysis
    passes were run against them into one Finding per URL, preserving the
    original result order. Every analysis argument is optional and keyed
    by URL internally, so this works whether the caller ran --verify only,
    --fingerprint only, all of them, or none (in which case you just get
    the corroboration + preset-severity component of the score).

    `severity_map` is the query -> severity mapping from
    presets.get_query_severity_map, used to resolve each result's
    source_query to a severity for scans that came from a preset/category.
    Raw -d/--dork runs have no preset behind them, so pass None (or omit
    the query from the map) and that component of the score is simply 0.
    """
    verify_by_url = {v.url: v for v in (verify_results or [])}
    fp_by_url = {f.url: f for f in (fingerprint_results or [])}
    probe_by_url = {p.url: p for p in (probe_results or [])}
    shot_by_url = {s.url: s for s in (screenshot_results or []) if getattr(s, "success", False)}
    secrets_by_url = secret_results or {}
    vuln_hints_by_url = vuln_hint_results or {}
    severity_map = severity_map or {}

    findings: List[Finding] = []
    for r in results:
        finding = Finding(
            url=r.url,
            title=r.title,
            snippet=r.snippet,
            primary_engine=r.engine,
            also_seen_in=list(getattr(r, "also_seen_in", []) or []),
            source_query=r.source_query,
            preset_severity=severity_map.get(r.source_query),
        )

        v = verify_by_url.get(r.url)
        if v is not None:
            finding.verify_confidence = v.confidence
            finding.soft_404 = getattr(v, "soft_404", False)
            finding.verify_confirmed_count = v.confirmed_count
            finding.verify_total_count = v.total_count

        fp = fp_by_url.get(r.url)
        if fp is not None:
            finding.technologies = list(fp.technologies)

        finding.secrets = list(secrets_by_url.get(r.url, []))
        finding.vuln_hints = list(vuln_hints_by_url.get(r.url, []))
        if triage:
            finding.triage = triage_url(r.url)

        p = probe_by_url.get(r.url)
        if p is not None:
            finding.probe_status = p.status
            finding.probe_alive = p.alive
            finding.probe_protected = getattr(p, "protected", False)
            finding.probe_error_kind = getattr(p, "error_kind", "")

        shot = shot_by_url.get(r.url)
        if shot is not None:
            finding.screenshot_path = shot.path

        findings.append(finding)

    return findings


def sort_findings(findings: List[Finding], descending: bool = True) -> List[Finding]:
    """Sort findings by displayed severity first, then confidence_score, then
    preset severity rank.

    Severity leads because it includes the impact floor (a confirmed cloud
    credential is "high" even with a modest score); ordering by score alone
    would let it sort beneath a "low" row, contradicting the column beside it.
    Within a severity, higher score wins; ties fall back to the preset's
    declared severity so a critical-category preset outranks an info one.
    """
    return sorted(
        findings,
        key=lambda f: (severity_rank(f.severity_label), f.confidence_score, severity_rank(f.preset_severity or "info")),
        reverse=descending,
    )


def filter_findings_by_min_score(findings: List[Finding], min_score: int) -> List[Finding]:
    return [f for f in findings if f.confidence_score >= min_score]

"""
Bug-bounty-submission-ready report generation from a scored Finding list.

Three output forms, deliberately layered on top of each other rather than
implemented three separate times:

  - Markdown (render_markdown_report): the source of truth for content --
    every other form is a rendering of the same structure, not a parallel
    hand-maintained copy that can drift out of sync with it.
  - HTML (render_html_report): a styled, standalone page for viewing in a
    browser or attaching to a ticket. Distinct from exporter.py's
    `_render_html_report`, which is a flat results table -- this is a
    grouped, severity-sorted *report* with an executive summary, evidence,
    and a disclaimer, closer to what a client/programme expects to receive.
  - PDF (generate_pdf_report): shells out to `wkhtmltopdf` against the
    HTML above -- the sibling binary to `wkhtmltoimage`, which
    screenshot.py already uses for the same "no heavy bundled browser"
    reason. If `wkhtmltopdf` isn't installed, this fails the same
    explicit, catchable way screenshot.py does, rather than silently
    downgrading output or requiring a second heavy dependency
    (e.g. weasyprint/reportlab) just for this one feature.
"""

import html as html_escape
import os
import shutil
import subprocess
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import List, Optional

from .findings import Finding
from .presets import SEVERITY_ORDER, severity_rank

DEFAULT_PDF_BINARY = os.environ.get("LXDORK_PDF_BIN") or "wkhtmltopdf"

_SEVERITY_EMOJI = {
    "critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵", "info": "⚪",
}

# Characters render_markdown_report's own prose treats as Markdown syntax
# (bold, links/images, headings, raw-HTML passthrough, table pipes).
# f.title and f.url are attacker-influenced -- whatever text/URL actually
# got indexed -- so without escaping these, a crafted title like
# `**FAKE CRITICAL** [click](javascript:alert(1))` renders as literal bold
# text and a clickable link in the generated report, not as the inert
# string it should be, and a title/url containing a newline followed by
# `#` can inject an entirely fake heading into the document. This isn't a
# full CommonMark-spec escape -- it covers exactly the constructs this
# report's own prose emits around these two values (bold, links/images,
# headings, raw HTML, tables), not every context Markdown has.
_MD_ESCAPE_CHARS = ("\\", "`", "*", "_", "[", "]", "(", ")", "#", "<", ">", "|")


def _md_escape(text: str) -> str:
    """Escape a value destined for plain Markdown prose (not inside a
    code span -- see _url_for_heading for that case, where backslash
    escaping doesn't apply). Also collapses embedded newlines so one
    value can't span into what reads as a new line/block of the report.
    """
    if not text:
        return text
    text = text.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    for ch in _MD_ESCAPE_CHARS:
        text = text.replace(ch, "\\" + ch)
    return text


def _url_for_heading(url: str) -> str:
    r"""Make a URL safe to place inside a single-backtick Markdown code
    span used as a section heading (see the `### \`{url}\`` line below).
    A code span's contents are verbatim -- backslash-escaping (used by
    _md_escape above) does NOT apply inside one, so a literal backtick in
    the URL would prematurely close the span, and a raw newline followed
    by `#` would then read as a fresh heading once outside it. Both
    characters are technically invalid unencoded in a URL per RFC 3986
    anyway, so percent-encoding them here is a faithful, still
    copy-pasteable representation, not a mangling.
    """
    return url.replace("`", "%60").replace("\r", "%0D").replace("\n", "%0A")


@dataclass
class ReportResult:
    success: bool
    path: str = ""
    error: str = ""


def is_pdf_available(binary: str = DEFAULT_PDF_BINARY) -> bool:
    return shutil.which(binary) is not None


def _severity_counts(findings: List[Finding]) -> dict:
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity_label] = counts.get(f.severity_label, 0) + 1
    return counts


def _grouped_by_severity(findings: List[Finding]) -> List[tuple]:
    """(severity, [findings...]) pairs, most severe first, empty buckets
    omitted -- a report with zero criticals shouldn't have an empty
    "Critical" heading sitting above everything else.
    """
    buckets = {s: [] for s in SEVERITY_ORDER}
    for f in findings:
        buckets[f.severity_label].append(f)
    ordered = sorted(buckets.items(), key=lambda kv: severity_rank(kv[0]), reverse=True)
    return [(sev, items) for sev, items in ordered if items]


def _code(text: str) -> str:
    """Inline code span; a backtick inside the value (it can come from a remote URL) would end it early."""
    return "`" + str(text).replace("`", "'") + "`"


def _where(location: str) -> str:
    """Human wording for a SecretMatch.location: body | header:Name | js:/path."""
    loc = location or "body"
    if loc == "body":
        return "the page body"
    if loc.startswith("header:"):
        return f"response header {_code(loc[7:])}"
    if loc.startswith("js:"):
        return f"JavaScript file {_code(loc[3:])}"
    return _code(loc)


def _finding_evidence_lines(f: Finding) -> List[str]:
    """The same "why does this score what it scores" reasoning
    findings.Finding.score_breakdown carries, rendered as plain evidence
    bullets for someone who isn't going to read the source code -- a
    report reader needs "why is this critical," not just the number.
    """
    lines = []
    if f.preset_severity:
        lines.append(f"Matched a **{f.preset_severity}**-severity dork pattern.")
    if f.corroboration_count > 1:
        lines.append(f"Independently found by **{f.corroboration_count} search engines**.")
    if f.verify_confidence:
        lines.append(f"`--verify` confidence: **{f.verify_confidence}** "
                      f"({f.verify_confirmed_count}/{f.verify_total_count} signals confirmed live).")
    if f.soft_404:
        lines.append("**Soft-404 suspected:** the server returns the same page for non-existent paths in this directory, so the hit above is not evidence the resource exists.")
    if f.triage:
        shown = "; ".join(f"{t.name} (`{t.evidence}`)" for t in f.triage[:6])
        lines.append(f"**URL-shape triage:** {shown} -- candidates only, derived from the URL itself; nothing was sent.")
    if f.technologies:
        lines.append(f"Detected technology: {', '.join(f.technologies)}.")
    if f.has_secrets:
        names = ", ".join(sorted({s.name for s in f.secrets}))
        lines.append(f"**{len(f.secrets)} potential secret(s) found:** {names} (values redacted -- verify and rotate).")
        # WHERE it was found is the first thing a triager asks: which JS bundle, which header.
        seen, shown = set(), 0
        distinct = []
        for sec in f.secrets:
            key = (sec.name, sec.location, sec.redacted)
            if key not in seen:
                seen.add(key)
                distinct.append(sec)
        for sec in distinct[:10]:
            lines.append(f"Secret location: {sec.name} in {_where(sec.location)} ({_code(sec.redacted)}).")
        if len(distinct) > 10:
            lines.append(f"...and {len(distinct) - 10} more secret location(s) not listed here.")
    if f.has_vuln_hints:
        hint_names = ", ".join(sorted({h.name for h in f.vuln_hints}))
        lines.append(f"**{len(f.vuln_hints)} passive vulnerability indicator(s):** {hint_names} "
                      f"(already present in the unmodified response -- verify manually; no payload was sent).")
    if f.probe_alive is not None:
        if f.probe_alive:
            lines.append(f"Probed as **alive** (HTTP {f.probe_status}).")
        elif f.probe_protected:
            lines.append(f"Probed as **protected** (HTTP {f.probe_status}): the server answered, so the resource very "
                         f"likely exists, but access is restricted or this client was refused.")
        elif f.probe_status is None and f.probe_error_kind:
            lines.append(f"Probe **failed to connect** ({f.probe_error_kind.replace('_', ' ')}).")
        else:
            lines.append(f"Probed as **dead** (HTTP {f.probe_status}).")
    if f.screenshot_path:
        lines.append(f"Screenshot captured: `{f.screenshot_path}`.")
    return lines


def _context_pairs(scope_summary, out_of_scope_count, analyses):
    """(label, value) rows describing HOW this report was produced -- the
    context a triager asks for first."""
    from . import __version__
    rows = []
    if scope_summary:
        text = scope_summary
        if out_of_scope_count:
            text += f" ({out_of_scope_count} out-of-scope hit(s) were excluded and never fetched)"
        rows.append(("Engagement scope", text))
    if analyses:
        rows.append(("Analyses run", ", ".join(analyses)))
    rows.append(("Tool", f"LX-Dork-Pro {__version__} (passive recon; findings are leads for manual verification)"))
    return rows


def render_markdown_report(
    findings: List[Finding],
    target: str = "",
    label: str = "",
    generated_at: Optional[datetime] = None,
    min_score_shown: Optional[int] = None,
    scope_summary: str = "",
    out_of_scope_count: int = 0,
    analyses: Optional[List[str]] = None,
) -> str:
    """Render the full Markdown report. This is the canonical content
    representation -- render_html_report converts this same structure to
    HTML rather than building it separately, so the two can't drift.
    """
    generated_at = generated_at or datetime.now(timezone.utc)
    counts = _severity_counts(findings)
    total = len(findings)

    lines = [f"# LX-Dork-Pro Findings Report", ""]
    if target:
        lines.append(f"**Target:** {target}  ")
    if label:
        lines.append(f"**Scan:** {label}  ")
    lines.append(f"**Generated:** {generated_at.strftime('%Y-%m-%d %H:%M UTC')}  ")
    for k, v in _context_pairs(scope_summary, out_of_scope_count, analyses):
        lines.append(f"**{k}:** {v}  ")
    lines.append(f"**Total findings:** {total}")
    if min_score_shown is not None:
        lines.append(f"*(filtered to score >= {min_score_shown})*")
    lines.append("")

    lines.append("## Executive summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|---|---|")
    for sev in reversed(SEVERITY_ORDER):
        if counts.get(sev):
            lines.append(f"| {_SEVERITY_EMOJI.get(sev, '')} {sev.upper()} | {counts[sev]} |")
    lines.append("")

    secret_findings = [f for f in findings if f.has_secrets]
    if secret_findings:
        lines.append(
            f"**⚠ {len(secret_findings)} result(s) have exposed credential indicators.** "
            f"Treat these as the highest priority regardless of overall score -- "
            f"see the Secrets section of each finding below."
        )
        lines.append("")

    if total == 0:
        lines.append("_No findings to report._")
        lines.append("")
    else:
        for severity, items in _grouped_by_severity(findings):
            lines.append(f"## {_SEVERITY_EMOJI.get(severity, '')} {severity.upper()} ({len(items)})")
            lines.append("")
            for f in items:
                lines.append(f"### `{_url_for_heading(f.url)}`")
                lines.append("")
                lines.append(f"**Score:** {f.confidence_score}/100")
                if f.title:
                    lines.append(f"  \n**Title:** {_md_escape(f.title)}")
                lines.append("")
                for evidence in _finding_evidence_lines(f):
                    lines.append(f"- {evidence}")
                if not _finding_evidence_lines(f):
                    lines.append("- _Corroboration only -- no `--verify`/`--fingerprint`/`--secrets`/`--probe` run against this URL._")
                lines.append("")

    lines.append("---")
    lines.append(
        "_Generated by LX-Dork-Pro. For authorized security testing / bug-bounty engagements only. "
        "Verify every finding manually before reporting it -- scores reflect automated signal "
        "correlation, not confirmed exploitation._"
    )
    return "\n".join(lines)


def render_html_report(
    findings: List[Finding],
    target: str = "",
    label: str = "",
    generated_at: Optional[datetime] = None,
    min_score_shown: Optional[int] = None,
    scope_summary: str = "",
    out_of_scope_count: int = 0,
    analyses: Optional[List[str]] = None,
) -> str:
    """A styled, standalone HTML page rendering the same structure as
    render_markdown_report -- built directly (not via a markdown->HTML
    converter, to avoid adding a markdown-rendering dependency for what's
    a fairly fixed, simple structure) but sharing all the same derived
    data (severity buckets, evidence lines) so the two never disagree on
    content, only presentation.
    """
    e = html_escape.escape
    generated_at = generated_at or datetime.now(timezone.utc)
    counts = _severity_counts(findings)
    total = len(findings)

    severity_colors = {
        "critical": "#dc2626", "high": "#ea580c", "medium": "#ca8a04",
        "low": "#2563eb", "info": "#6b7280",
    }

    parts = [
        "<!DOCTYPE html><html><head><meta charset='utf-8'>",
        f"<title>LX-Dork-Pro Report{' - ' + e(target) if target else ''}</title>",
        "<style>",
        "body{font-family:-apple-system,Segoe UI,Roboto,sans-serif;max-width:900px;margin:2rem auto;"
        "padding:0 1rem;color:#1f2937;background:#f9fafb;}",
        "h1{border-bottom:3px solid #1f2937;padding-bottom:.5rem;}",
        "h2{margin-top:2rem;padding:.4rem .8rem;border-radius:6px;color:#fff;}",
        "table{border-collapse:collapse;margin:1rem 0;}",
        "th,td{border:1px solid #d1d5db;padding:.4rem .8rem;text-align:left;}",
        ".finding{background:#fff;border:1px solid #e5e7eb;border-radius:8px;padding:1rem;margin:1rem 0;}",
        ".finding h3{margin:0 0 .5rem 0;font-family:monospace;word-break:break-all;}",
        ".score{font-weight:bold;}",
        ".evidence{margin:.5rem 0 0 0;padding-left:1.2rem;}",
        ".warn{background:#fef2f2;border:1px solid #fecaca;border-radius:6px;padding:.75rem 1rem;margin:1rem 0;}",
        ".footer{margin-top:2rem;padding-top:1rem;border-top:1px solid #d1d5db;color:#6b7280;font-size:.85rem;}",
        "</style></head><body>",
        "<h1>LX-Dork-Pro Findings Report</h1>",
        "<p>",
    ]
    if target:
        parts.append(f"<b>Target:</b> {e(target)}<br>")
    if label:
        parts.append(f"<b>Scan:</b> {e(label)}<br>")
    parts.append(f"<b>Generated:</b> {e(generated_at.strftime('%Y-%m-%d %H:%M UTC'))}<br>")
    for k, v in _context_pairs(scope_summary, out_of_scope_count, analyses):
        parts.append(f"<b>{e(k)}:</b> {e(v)}<br>")
    parts.append(f"<b>Total findings:</b> {total}")
    if min_score_shown is not None:
        parts.append(f" <i>(filtered to score &gt;= {min_score_shown})</i>")
    parts.append("</p>")

    parts.append("<h2 style='background:#1f2937;'>Executive summary</h2><table><tr><th>Severity</th><th>Count</th></tr>")
    for sev in reversed(SEVERITY_ORDER):
        if counts.get(sev):
            parts.append(f"<tr><td style='color:{severity_colors.get(sev)};font-weight:bold;'>{e(sev.upper())}</td><td>{counts[sev]}</td></tr>")
    parts.append("</table>")

    secret_findings = [f for f in findings if f.has_secrets]
    if secret_findings:
        parts.append(
            f"<div class='warn'>⚠ <b>{len(secret_findings)} result(s) have exposed credential "
            f"indicators.</b> Treat these as highest priority regardless of overall score.</div>"
        )

    if total == 0:
        parts.append("<p><i>No findings to report.</i></p>")
    else:
        for severity, items in _grouped_by_severity(findings):
            color = severity_colors.get(severity, "#6b7280")
            parts.append(f"<h2 style='background:{color};'>{e(severity.upper())} ({len(items)})</h2>")
            for f in items:
                parts.append("<div class='finding'>")
                parts.append(f"<h3>{e(f.url)}</h3>")
                parts.append(f"<div class='score'>Score: {f.confidence_score}/100</div>")
                if f.title:
                    parts.append(f"<div>Title: {e(f.title)}</div>")
                evidence = _finding_evidence_lines(f)
                if evidence:
                    parts.append("<ul class='evidence'>")
                    for line in evidence:
                        # evidence lines use light markdown bold (**x**) --
                        # converted to <b> here since this is the one place
                        # they're rendered as HTML rather than Markdown.
                        html_line = e(line).replace("**", "<b>", 1)
                        if "<b>" in html_line:
                            html_line = html_line.replace("**", "</b>", 1)
                        parts.append(f"<li>{html_line}</li>")
                    parts.append("</ul>")
                else:
                    parts.append("<div><i>Corroboration only -- no further analysis run against this URL.</i></div>")
                parts.append("</div>")

    parts.append(
        "<div class='footer'>Generated by LX-Dork-Pro. For authorized security testing / "
        "bug-bounty engagements only. Verify every finding manually before reporting it -- "
        "scores reflect automated signal correlation, not confirmed exploitation.</div>"
    )
    parts.append("</body></html>")
    return "".join(parts)


def generate_pdf_report(
    findings: List[Finding],
    output_path: str,
    target: str = "",
    label: str = "",
    binary: str = DEFAULT_PDF_BINARY,
    timeout: float = 30.0,
    **context,
) -> ReportResult:
    """Render the HTML report to a temp file and shell out to
    `wkhtmltopdf` to convert it -- see this module's docstring for why
    that binary specifically, rather than a new Python PDF dependency.
    """
    if not is_pdf_available(binary):
        return ReportResult(
            success=False, error=(
                f"'{binary}' isn't installed. Install wkhtmltopdf, e.g. "
                f"`apt install wkhtmltopdf` / `brew install wkhtmltopdf` "
                f"(the same package screenshot.py's wkhtmltoimage comes from)."
            ),
        )

    html_content = render_html_report(findings, target=target, label=label, **context)
    tmp_html = None
    try:
        with tempfile.NamedTemporaryFile(mode="w", suffix=".html", delete=False, encoding="utf-8") as tmp:
            tmp.write(html_content)
            tmp_html = tmp.name

        result = subprocess.run(
            [binary, "--quiet", tmp_html, output_path],
            capture_output=True, timeout=timeout,
        )
        if result.returncode != 0:
            return ReportResult(success=False, error=result.stderr.decode("utf-8", errors="replace")[:500] or "wkhtmltopdf failed")
        return ReportResult(success=True, path=output_path)
    except subprocess.TimeoutExpired:
        return ReportResult(success=False, error=f"wkhtmltopdf timed out after {timeout}s")
    except OSError as e:
        return ReportResult(success=False, error=str(e))
    finally:
        if tmp_html and os.path.exists(tmp_html):
            try:
                os.unlink(tmp_html)
            except OSError:
                pass

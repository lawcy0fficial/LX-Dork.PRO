"""
Passive vulnerability-indicator scanning for fetched page bodies.

Looks for signs a page ALREADY reveals -- purely from content that's
already there, with no modified parameters and no injected payload of any
kind -- that suggest a SQL injection, server-side template injection, or
a debug/stack-trace disclosure worth a human's attention. This is
deliberately NOT an active vulnerability scanner: this module never
appends a payload to a URL, never varies a parameter, and never sends
anything a normal, unmodified GET to that exact URL wouldn't already
send -- the request itself goes through guarded_request() exactly like
probe.py/verify.py/fingerprint.py/secrets_scan.py, with no special
handling here.

Concretely: what gets flagged is already-public evidence -- a database
error message, a template-engine exception, a framework debug page --
that a search engine (or this tool's own read-only fetch) already
retrieved unmodified. A hit here means the target's *own* ordinary
behavior already leaked something, not that this tool proved anything by
poking it.

This means it will only ever catch what's already broken enough to leak
an error on an ordinary request; it cannot and does not confirm
exploitability (a matching error string is evidence an underlying query
or template exists and sometimes errors, not proof it's injectable), and
every hit here is explicitly a "verify manually" lead, same posture as
secrets_scan.py's entropy-gated generic matches. Actually confirming
SQLi/XSS/SSTI requires sending a crafted payload and observing the
target's response to it -- active testing, out of scope for this module
and for this tool, and something that requires the operator's own
verified authorization for the specific target regardless of what tool
performs it.
"""

import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import Dict, List, Optional

import requests
from requests.structures import CaseInsensitiveDict

from .ssrf_guard import SSRFGuardError, guarded_request


@dataclass
class VulnHint:
    name: str            # e.g. "MySQL Error Disclosure"
    category: str        # "sql_error" | "template_error" | "stack_trace" | "debug_console"
    evidence: str         # short, truncated, whitespace-collapsed snippet of the matched text
    location: str = "body"  # "body" | "header:X-Foo" -- where in the response this was found


def _truncate(text: str, length: int = 160) -> str:
    """Collapse whitespace/newlines into a single readable line and cap
    length -- these signatures often match inside a much longer stack
    trace or HTML debug page, and the point here is a recognizable lead
    for a human to go verify, not a dump of the whole page.
    """
    text = " ".join(text.split())
    return text if len(text) <= length else text[: length].rstrip() + "…"


# Every signature below is a passive marker of an error message or debug
# page a server already emitted on an ordinary, unmodified request -- none
# of this is triggered by this tool; it's either already indexed by a
# search engine or already present in whatever page this tool fetched
# as-is. Each entry: (name, category, compiled regex).

_SQL_ERROR_SIGNATURES = [
    ("MySQL Error Disclosure", "sql_error", re.compile(
        r"(You have an error in your SQL syntax|Warning: mysqli?_[a-z_]+\(\)|"
        r"supplied argument is not a valid MySQL)", re.I,
    )),
    ("PostgreSQL Error Disclosure", "sql_error", re.compile(
        r"(PostgreSQL query failed|pg_query\(\)\s*:|org\.postgresql\.util\.PSQLException)", re.I,
    )),
    ("MSSQL Error Disclosure", "sql_error", re.compile(
        r"(Unclosed quotation mark after the character string|"
        r"Microsoft OLE DB Provider for SQL Server|System\.Data\.SqlClient\.SqlException)", re.I,
    )),
    ("SQLite Error Disclosure", "sql_error", re.compile(
        r"(SQLite3?::(?:Exception|SQLException)|sqlite3\.OperationalError)"
    )),
    ("Oracle Error Disclosure", "sql_error", re.compile(r"\bORA-\d{4,5}\b")),
    ("Generic SQL Driver Error", "sql_error", re.compile(
        r"(ODBC (?:Microsoft Access )?Driver|SQL syntax.*?MariaDB server version)", re.I,
    )),
]

_TEMPLATE_ERROR_SIGNATURES = [
    ("Jinja2 Template Error", "template_error", re.compile(
        r"(jinja2\.exceptions\.\w+Error|TemplateSyntaxError|UndefinedError:)"
    )),
    ("Twig Template Error", "template_error", re.compile(r"(Twig\\Error\\\w+|Twig_Error_\w+)")),
    ("Smarty Template Error", "template_error", re.compile(
        r"(SmartyCompilerException|SmartyException|Warning: Smarty:)"
    )),
    ("FreeMarker Template Error", "template_error", re.compile(r"freemarker\.core\.\w*(?:Exception|Error)")),
    ("Velocity Template Error", "template_error", re.compile(r"org\.apache\.velocity\.exception\.\w+")),
    ("Thymeleaf Template Error", "template_error", re.compile(r"org\.thymeleaf\.exceptions\.\w+")),
    ("ColdFusion Template Error", "template_error", re.compile(r"coldfusion\.runtime\.\w*Exception")),
]

_STACK_TRACE_SIGNATURES = [
    ("Python Traceback", "stack_trace", re.compile(r"Traceback \(most recent call last\):")),
    ("Java Stack Trace", "stack_trace", re.compile(r"\bat [\w.$]+\([\w]+\.java:\d+\)")),
    ("PHP Fatal Error", "stack_trace", re.compile(
        r"(Fatal error|Uncaught (?:Error|Exception)):.*?on line \d+", re.I,
    )),
    (".NET Unhandled Exception", "stack_trace", re.compile(
        r"(Server Error in '/' Application|System\.\w+Exception:)"
    )),
    ("Ruby Stack Trace", "stack_trace", re.compile(r"[\w/]+\.rb:\d+:in [`']")),
    ("Node.js Stack Trace", "stack_trace", re.compile(r"at [\w.<>]+ \([\w/.\-]+:\d+:\d+\)")),
]

_DEBUG_CONSOLE_SIGNATURES = [
    ("Werkzeug/Flask Debugger", "debug_console", re.compile(
        r"(Werkzeug Debugger|The debugger caught an exception in your WSGI application)"
    )),
    ("Django Debug Page", "debug_console", re.compile(
        r"You(?:'|&#39;|&#x27;)re seeing this error because (?:you have|DEBUG = True)", re.I,
    )),
    ("Rails Debug Page", "debug_console", re.compile(r"(ActionView::Template::Error|Rails\.root:)")),
    ("PHP Xdebug Trace", "debug_console", re.compile(r"Xdebug\.")),
]

# Things that are *already visible in an unmodified response* and are a problem
# in themselves: auto-generated directory listings, a leaked config file, a
# phpinfo() page, an unauthenticated service banner or bucket listing.
# Patterns are deliberately specific -- a tutorial that merely *mentions*
# "phpinfo()" or shows a code sample must not match.
_EXPOSURE_SIGNATURES = [
    ("Directory Listing", "directory_listing", re.compile(
        r"<title>Index of /[^<]{0,200}</title>|<h1>Index of /[^<]{0,200}</h1>", re.IGNORECASE)),
    ("phpinfo() Page", "info_disclosure", re.compile(
        r"<title>phpinfo\(\)</title>|<h1 class=\"p\">PHP Version", re.IGNORECASE)),
    ("Exposed Git Config", "info_disclosure", re.compile(
        r"\[core\]\s+repositoryformatversion\s*=\s*\d", re.IGNORECASE)),
    ("Apache Server Status", "info_disclosure", re.compile(
        r"<title>Apache Status</title>|Apache Server Status for", re.IGNORECASE)),
    ("PHP Source Disclosure", "info_disclosure", re.compile(r"\A\s*<\?php\b")),
    ("GraphQL Introspection Enabled", "info_disclosure", re.compile(r'"__schema"\s*:\s*\{')),
    ("Spring Boot Actuator Index", "info_disclosure", re.compile(
        r'"_links"\s*:\s*\{\s*"self"\s*:\s*\{\s*"href"\s*:\s*"[^"]*/actuator"', re.IGNORECASE)),
    ("Open S3-style Bucket Listing", "exposed_service", re.compile(r"<ListBucketResult\b[^>]*>")),
    ("Open Azure Blob Listing", "exposed_service", re.compile(r"<EnumerationResults\b[^>]*ContainerName=")),
    ("Open Elasticsearch", "exposed_service", re.compile(r'"tagline"\s*:\s*"You Know, for Search"')),
    ("Jenkins Dashboard (anonymous)", "exposed_service", re.compile(r"<title>Dashboard \[Jenkins\]</title>", re.IGNORECASE)),
    ("Solr Admin UI", "exposed_service", re.compile(r"<title>Solr Admin</title>", re.IGNORECASE)),
]

_STACK_TRACE_SIGNATURES += [
    ("Go Panic", "stack_trace", re.compile(r"goroutine \d+ \[(?:running|runnable|chan receive|select|IO wait)\]:")),
    ("Rust Panic", "stack_trace", re.compile(r"thread '[^']{1,80}' panicked at")),
    ("Spring Whitelabel Error Page", "stack_trace", re.compile(r"Whitelabel Error Page.{0,200}no explicit mapping", re.IGNORECASE | re.DOTALL)),
    ("ASP.NET Yellow Screen of Death", "stack_trace", re.compile(r"Server Error in '/[^']*' Application", re.IGNORECASE)),
]
_DEBUG_CONSOLE_SIGNATURES += [
    ("Laravel Whoops/Ignition Debug Page", "debug_console", re.compile(r"Whoops! There was an error|facade/ignition|laravel/framework/src/Illuminate")),
    ("Symfony Profiler / Debug Toolbar", "debug_console", re.compile(r"sf-toolbar|/_wdt/|<title>[^<]*Symfony Profiler")),
    ("Spring Boot Actuator Env/Heapdump", "debug_console", re.compile(r'"propertySources"\s*:\s*\[|"activeProfiles"\s*:\s*\[')),
]

_ALL_SIGNATURE_GROUPS = (
    _SQL_ERROR_SIGNATURES + _TEMPLATE_ERROR_SIGNATURES
    + _STACK_TRACE_SIGNATURES + _DEBUG_CONSOLE_SIGNATURES + _EXPOSURE_SIGNATURES
)

# Impact of each category, used by findings.py for scoring and the severity floor.
# stack_trace is intentionally absent: a trace is information, not exposure.
CATEGORY_FLOOR = {
    "sql_error": "medium",
    "template_error": "medium",
    "directory_listing": "medium",
    "info_disclosure": "medium",
    "debug_console": "high",
    "exposed_service": "high",
}


def scan_text(text: str, location: str = "body") -> List[VulnHint]:
    """Scan a blob of text (HTML, JSON, plaintext -- anything already
    fetched) for error/debug signatures. One hint per matching signature
    per call -- the point is "this page shows a MySQL error", not every
    repeated line of the same traceback, so this uses `search()` (first
    match) rather than `finditer()` per signature.
    """
    if not text:
        return []

    hints: List[VulnHint] = []
    for name, category, pattern in _ALL_SIGNATURE_GROUPS:
        m = pattern.search(text)
        if not m:
            continue
        hints.append(VulnHint(name=name, category=category, evidence=_truncate(m.group(0)), location=location))
    return hints


def scan_response_context(body: str, headers: Optional[dict] = None) -> List[VulnHint]:
    """Convenience wrapper: scan both the body and a couple of headers
    that occasionally carry a framework/debug fingerprint. `headers` is a
    plain dict as already produced by `resp.headers` in verify.py/
    fingerprint.py/secrets_scan.py -- pass it straight through, no extra
    fetch needed.
    """
    hints = list(scan_text(body, location="body"))
    if headers:
        headers = CaseInsensitiveDict(headers)
        for header_name in ("X-Debug-Token", "X-Powered-By", "Warning"):
            value = headers.get(header_name)
            if value:
                hints.extend(scan_text(value, location=f"header:{header_name}"))
    return hints


def scan_url(url: str, timeout: float = 8.0, allow_private: bool = False, cache=None) -> List[VulnHint]:
    """Fetch one URL, exactly as given -- no parameters added, changed, or
    removed -- and scan its body + a couple of headers for error/debug
    signatures.

    Every fetch here goes through guarded_request() (ssrf_guard.py) --
    the original URL and every redirect hop are checked, and a target
    resolving to a private/loopback/link-local address at any hop is
    refused, same as probe.py/verify.py/fingerprint.py/secrets_scan.py. A
    blocked target returns an empty list here for the same reason
    secrets_scan.py does: this function has no "unreachable" state of its
    own to report, and the caller already gets that from --probe/--verify.

    Network/parse failures likewise return an empty list rather than
    raising -- a page that can't be fetched simply has nothing to report.
    """
    from .engines import USER_AGENTS  # local import avoids a circular import at module load time

    headers = {"User-Agent": random.choice(USER_AGENTS)}  # nosec B311 -- UA rotation for scraping evasion, not security/crypto-sensitive
    try:
        if cache is not None:
            resp = cache.get(url, timeout, allow_private)
        else:
            resp = guarded_request("GET", url, headers=headers, timeout=timeout, allow_private=allow_private)
    except (SSRFGuardError, requests.RequestException):
        return []

    body = resp.text if isinstance(resp.text, str) else ""
    resp_headers = {k: v for k, v in resp.headers.items()}
    return scan_response_context(body, resp_headers)


def scan_results(
    results: List, workers: int = 10, timeout: float = 8.0, progress_cb=None, allow_private: bool = False, cache=None
) -> Dict[str, List[VulnHint]]:
    """Scan a batch of SearchResults concurrently. Returns a dict keyed by
    URL (only URLs with at least one hint are included, so callers can
    treat `.get(url, [])` as "nothing found" without a bulkier per-result
    wrapper object) -- this feeds into findings.build_findings the same
    way secrets_scan.scan_results does.

    `allow_private` plumbs through to the SSRF guard each fetch runs
    through first -- see probe.probe_urls's docstring for what it does
    and why the default refuses private/loopback/link-local targets.
    """
    out: Dict[str, List[VulnHint]] = {}
    total = len(results)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_url, r.url, timeout, allow_private, cache): r for r in results}
        for i, future in enumerate(as_completed(futures), 1):
            r = futures[future]
            try:
                hints = future.result()
            except Exception:  # noqa: BLE001 -- one bad URL must not abort the whole pass
                hints = []
            if hints:
                out[r.url] = hints
            if progress_cb:
                progress_cb(i, total)
    return out

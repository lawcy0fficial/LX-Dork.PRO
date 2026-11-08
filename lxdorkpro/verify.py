"""
Accuracy verification: a search engine's index can be stale -- a page that
matched a dork when it was crawled may have since changed, been taken down,
or been misattributed by the engine. This module fetches each result and
checks whether the page still actually satisfies the signals implied by the
dork query (site, inurl, intitle, intext, ext/filetype, quoted phrases),
producing a confidence rating instead of blind trust in the search index.

This is heuristic, not a formal dork-syntax parser -- dork syntax has no
single standard grammar across engines. It extracts the operators it
recognizes and treats anything it can't parse as simply not checkable.
"""

import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup

from .engines import USER_AGENTS, SearchResult
from .soft404 import is_soft_404
from .ssrf_guard import SSRFGuardError, guarded_request
import random

_SITE_RE = re.compile(r"\bsite:(\S+)", re.IGNORECASE)
_INURL_RE = re.compile(r"\binurl:(\S+)", re.IGNORECASE)
_INTITLE_QUOTED_RE = re.compile(r'\bintitle:"([^"]+)"', re.IGNORECASE)
_INTITLE_BARE_RE = re.compile(r"\bintitle:(\S+)", re.IGNORECASE)
_INTEXT_QUOTED_RE = re.compile(r'\bintext:"([^"]+)"', re.IGNORECASE)
_INTEXT_BARE_RE = re.compile(r"\bintext:(\S+)", re.IGNORECASE)
_EXT_RE = re.compile(r"\b(?:ext|filetype):(\S+)", re.IGNORECASE)
_BARE_QUOTE_RE = re.compile(r'(?<!:)"([^"]+)"')

_EXT_CONTENT_TYPES = {
    "pdf": "application/pdf",
    "doc": "application/msword",
    "docx": "officedocument.wordprocessingml",
    "xls": "application/vnd.ms-excel",
    "xlsx": "officedocument.spreadsheetml",
    "xml": "xml",
    "json": "application/json",
    "sql": "text/plain",  # servers rarely set a real SQL content-type
    "txt": "text/plain",
}


@dataclass
class Signal:
    kind: str      # "site" | "inurl" | "intitle" | "intext" | "ext" | "phrase"
    value: str
    confirmed: bool


@dataclass
class VerifyResult:
    url: str
    confidence: str                    # "high" | "medium" | "low" | "unreachable" | "unknown"
    signals: List[Signal] = field(default_factory=list)
    error: str = ""
    soft_404: bool = False             # host serves the same page for non-existent paths (hit is not evidence)
    http_status: Optional[int] = None  # status of the verification fetch

    @property
    def confirmed_count(self) -> int:
        return sum(1 for s in self.signals if s.confirmed)

    @property
    def total_count(self) -> int:
        return len(self.signals)


def parse_dork_signals(dork: str) -> List[Signal]:
    """Extract checkable (kind, value) signals from a dork query string.
    Order of extraction matters: quoted intitle:/intext: values are pulled
    out first so the generic bare-quote pattern doesn't double-count them.
    """
    remaining = dork
    signals: List[Signal] = []

    for value in _SITE_RE.findall(remaining):
        signals.append(Signal(kind="site", value=value, confirmed=False))

    for value in _INURL_RE.findall(remaining):
        signals.append(Signal(kind="inurl", value=value, confirmed=False))

    for value in _INTITLE_QUOTED_RE.findall(remaining):
        signals.append(Signal(kind="intitle", value=value, confirmed=False))
    remaining_no_intitle_quoted = _INTITLE_QUOTED_RE.sub("", remaining)
    for value in _INTITLE_BARE_RE.findall(remaining_no_intitle_quoted):
        signals.append(Signal(kind="intitle", value=value, confirmed=False))

    for value in _INTEXT_QUOTED_RE.findall(remaining):
        signals.append(Signal(kind="intext", value=value, confirmed=False))
    remaining_no_intext_quoted = _INTEXT_QUOTED_RE.sub("", remaining)
    for value in _INTEXT_BARE_RE.findall(remaining_no_intext_quoted):
        signals.append(Signal(kind="intext", value=value, confirmed=False))

    for value in _EXT_RE.findall(remaining):
        signals.append(Signal(kind="ext", value=value.lstrip("."), confirmed=False))

    # Bare quoted phrases not already claimed by intitle:/intext: above.
    stripped = _INTITLE_QUOTED_RE.sub("", remaining)
    stripped = _INTEXT_QUOTED_RE.sub("", stripped)
    for value in _BARE_QUOTE_RE.findall(stripped):
        signals.append(Signal(kind="phrase", value=value, confirmed=False))

    return signals


def _check_signal(signal: Signal, url: str, title: str, body_text: str, content_type: str) -> bool:
    value_lower = signal.value.lower()

    if signal.kind == "site":
        # netloc can carry userinfo ("user:pass@host") and a port
        # ("host:8443") -- strip both so the comparison below is against
        # the bare hostname only.
        host = urlparse(url).netloc.lower().rsplit("@", 1)[-1].split(":", 1)[0]
        domain = value_lower.lstrip("*.")
        # Exact match or true subdomain only -- NOT a substring check.
        # `domain in host` (the old check) treats "example.com" as
        # "confirmed" against "notexample.com" and "example.com.evil.net"
        # alike, since both happen to contain that substring; a
        # dork's site: operator should mean the domain or one of its
        # subdomains, never an unrelated host that merely shares
        # characters with it.
        return host == domain or host.endswith("." + domain)

    if signal.kind == "inurl":
        return value_lower in url.lower()

    if signal.kind == "intitle":
        return value_lower in title.lower()

    if signal.kind in ("intext", "phrase"):
        return value_lower in body_text.lower()

    if signal.kind == "ext":
        path = urlparse(url).path.lower()
        if path.endswith(f".{value_lower}"):
            return True
        expected_ct = _EXT_CONTENT_TYPES.get(value_lower)
        return bool(expected_ct and expected_ct in content_type.lower())

    return False


def _confidence_from_ratio(confirmed: int, total: int) -> str:
    if total == 0:
        return "unknown"
    ratio = confirmed / total
    if ratio == 1.0:
        return "high"
    if ratio >= 0.5:
        return "medium"
    return "low"


def verify_one(result: SearchResult, dork: Optional[str] = None, timeout: float = 8.0, allow_private: bool = False, cache=None) -> VerifyResult:
    """Verify one result against a dork query's signals. If `dork` isn't
    given, falls back to `result.source_query` (set automatically by the
    CLI's search pipeline) -- this matters for batch runs (--dork-file,
    presets with multiple queries) where different results came from
    different dorks and shouldn't all be checked against the same one.
    """
    effective_dork = dork if dork is not None else result.source_query
    signals = parse_dork_signals(effective_dork)

    if not signals:
        return VerifyResult(url=result.url, confidence="unknown", signals=[])

    headers = {"User-Agent": random.choice(USER_AGENTS)}  # nosec B311 -- UA rotation for scraping evasion, not security/crypto-sensitive
    try:
        if cache is not None:
            resp = cache.get(result.url, timeout, allow_private)
        else:
            resp = guarded_request("GET", result.url, headers=headers, timeout=timeout, allow_private=allow_private)
    except SSRFGuardError as e:
        return VerifyResult(url=result.url, confidence="unreachable", signals=signals, error=f"blocked (SSRF guard): {e.reason}")
    except requests.RequestException as e:
        return VerifyResult(url=result.url, confidence="unreachable", signals=signals, error=type(e).__name__)

    final_url = resp.url
    content_type = resp.headers.get("Content-Type", "")
    title = ""
    body_text = ""

    if "text/html" in content_type or (not content_type and resp.text):
        try:
            soup = BeautifulSoup(resp.text, "html.parser")
            title = soup.title.get_text(strip=True) if soup.title else ""
            body_text = soup.get_text(" ", strip=True)
        except Exception:  # noqa: BLE001 - malformed HTML shouldn't crash verification
            body_text = resp.text
    else:
        body_text = resp.text if isinstance(resp.text, str) else ""

    checked_signals = []
    for signal in signals:
        confirmed = _check_signal(signal, final_url, title, body_text, content_type)
        checked_signals.append(Signal(kind=signal.kind, value=signal.value, confirmed=confirmed))

    confidence = _confidence_from_ratio(sum(1 for s in checked_signals if s.confirmed), len(checked_signals))

    # An error response can't verify a dork: `ext:sql` "matches" a 404 purely because
    # the URL ends in .sql, and body signals would be checked against an error page.
    # Cap confidence. 401/403 are exempt -- access control says nothing about whether
    # the URL exists, and the URL-based signals still stand.
    status = resp.status_code if isinstance(getattr(resp, "status_code", None), int) else None
    errored = status is not None and status >= 400 and status not in (401, 403)
    if errored and confidence in ("high", "medium"):
        confidence = "low"

    # A host that returns the same page for any path "confirms" every dork
    # (the URL's own text matches site:/inurl:/ext:). Needs a cache for the
    # memoized extra request, so it only runs inside the CLI pipeline.
    soft = False
    if cache is not None and confidence in ("high", "medium", "low"):
        soft = bool(is_soft_404(resp, cache, timeout, allow_private))
        if soft:
            confidence = "low"
    note = ""
    if soft:
        note = "soft-404: server returns the same page for non-existent paths"
    elif errored:
        note = f"HTTP {status}: the URL did not return content, so the dork's signals can't be confirmed"
    return VerifyResult(url=result.url, confidence=confidence, signals=checked_signals, soft_404=soft,
                        error=note, http_status=status)


def verify_results(
    results: List[SearchResult], dork: Optional[str] = None, workers: int = 10,
    timeout: float = 8.0, progress_cb=None, allow_private: bool = False, cache=None
) -> List[VerifyResult]:
    """Verify a list of results, concurrently. If `dork` is given, every
    result is checked against that single query. If omitted, each result
    is checked against its own `source_query` -- the right choice for
    batch/preset runs where results came from different dorks.

    `allow_private` plumbs through to the SSRF guard each fetch runs
    through first -- see probe.probe_urls's docstring for what it does
    and why the default refuses private/loopback/link-local targets.
    """
    out = []
    total = len(results)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(verify_one, r, dork, timeout, allow_private, cache): r for r in results}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                out.append(future.result())
            except Exception as e:  # noqa: BLE001 -- one bad URL must not abort the whole pass
                out.append(VerifyResult(url=futures[future].url, confidence="unknown", error=f"internal error: {type(e).__name__}"))
            if progress_cb:
                progress_cb(i, total)

    order = {r.url: i for i, r in enumerate(results)}
    out.sort(key=lambda v: order.get(v.url, 0))
    return out

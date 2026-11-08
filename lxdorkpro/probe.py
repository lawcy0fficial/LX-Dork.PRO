"""
Probe discovered URLs for liveness (like httpx-lite): concurrent HEAD/GET
requests that report status code, so you know which dork hits are actually
still reachable before you spend time on them manually.

Beyond a bare alive/dead bit this reports *why* (DNS vs refused vs timeout vs
TLS...), whether the target answered but is access-controlled (401/403 --
alive-but-protected is often the interesting case in recon, not a dead link),
and light response metadata (type, size, server, timing, redirect count).
"""

import random
import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from typing import List, Optional

import requests

from .engines import USER_AGENTS
from .ssrf_guard import SSRFGuardError, guarded_request

# Statuses meaning "something is there, but you need to be authorised / it
# refused this client". Distinct from dead: the resource very likely exists.
PROTECTED_STATUSES = (401, 403)
# Failure kinds worth one retry: a network blip, not a verdict about the target.
TRANSIENT_KINDS = ("timeout", "reset")


@dataclass
class ProbeResult:
    url: str
    status: Optional[int]
    alive: bool                      # status < 400 (unchanged contract)
    final_url: str = ""
    error: str = ""                  # exception class / guard reason (unchanged contract)
    # --- additive detail ---
    protected: bool = False          # answered 401/403: exists but access-controlled
    error_kind: str = ""             # dns | refused | timeout | tls | reset | redirect_loop | invalid_url | blocked | connection | other
    content_type: str = ""
    content_length: Optional[int] = None
    server: str = ""
    elapsed_ms: Optional[int] = None
    redirects: int = 0

    @property
    def state(self) -> str:
        """alive | protected | rate_limited | server_error | client_error | unreachable"""
        if self.status is None:
            return "unreachable"
        if self.alive:
            return "alive"
        if self.protected:
            return "protected"
        if self.status == 429:
            return "rate_limited"
        return "server_error" if self.status >= 500 else "client_error"


def _causes(exc: BaseException):
    """Walk an exception's cause/context/args/reason chain (requests wraps
    urllib3 which wraps socket errors) yielding every exception found."""
    seen, stack = set(), [exc]
    while stack and len(seen) < 16:
        e = stack.pop()
        if e is None or id(e) in seen:
            continue
        seen.add(id(e))
        yield e
        stack.extend([getattr(e, "__cause__", None), getattr(e, "__context__", None), getattr(e, "reason", None)])
        stack.extend(a for a in getattr(e, "args", ()) if isinstance(a, BaseException))


def classify_error(exc: BaseException) -> str:
    """Map a requests/urllib3/socket failure to a short, actionable kind."""
    if isinstance(exc, requests.exceptions.SSLError):
        return "tls"
    if isinstance(exc, (requests.exceptions.InvalidURL, requests.exceptions.MissingSchema,
                        requests.exceptions.InvalidSchema)):
        return "invalid_url"
    if isinstance(exc, requests.exceptions.TooManyRedirects):
        return "redirect_loop"
    if isinstance(exc, requests.exceptions.Timeout):
        return "timeout"
    for e in _causes(exc):
        name = type(e).__name__
        if isinstance(e, socket.gaierror) or name in ("NameResolutionError", "gaierror"):
            return "dns"
        if isinstance(e, ConnectionRefusedError):
            return "refused"
        if isinstance(e, (ConnectionResetError, BrokenPipeError)) or name in ("RemoteDisconnected", "IncompleteRead"):
            return "reset"
        if isinstance(e, (socket.timeout, TimeoutError)):
            return "timeout"
    if isinstance(exc, requests.exceptions.ConnectionError):
        return "connection"
    return "other"


def _content_length(resp) -> Optional[int]:
    raw = resp.headers.get("Content-Length")
    if raw and raw.isdigit():
        return int(raw)
    return len(resp.content) if getattr(resp, "_content", None) else None


def _request(url, headers, timeout, allow_private):
    resp = guarded_request("HEAD", url, headers=headers, timeout=timeout, allow_private=allow_private)
    # Some servers don't implement HEAD properly (405/403/501) -- fall back to GET.
    if resp.status_code in (405, 403, 501):
        resp = guarded_request("GET", url, headers=headers, timeout=timeout, allow_private=allow_private)
    return resp


def _probe_one(url: str, timeout: float, allow_private: bool = False, retries: int = 1) -> ProbeResult:
    headers = {"User-Agent": random.choice(USER_AGENTS)}  # nosec B311 -- UA rotation for scraping evasion, not security/crypto-sensitive
    for attempt in range(max(0, retries) + 1):
        started = time.monotonic()
        try:
            resp = _request(url, headers, timeout, allow_private)
        except SSRFGuardError as e:
            return ProbeResult(url=url, status=None, alive=False, error=f"blocked (SSRF guard): {e.reason}",
                               error_kind="blocked")
        except requests.RequestException as e:
            kind = classify_error(e)
            if kind in TRANSIENT_KINDS and attempt < retries:
                time.sleep(0.3 * (attempt + 1))   # one quick retry: a blip isn't a verdict
                continue
            return ProbeResult(url=url, status=None, alive=False, error=type(e).__name__, error_kind=kind)
        return ProbeResult(
            url=url, status=resp.status_code, alive=resp.status_code < 400, final_url=resp.url,
            protected=resp.status_code in PROTECTED_STATUSES,
            content_type=(resp.headers.get("Content-Type") or "").split(";")[0].strip().lower(),
            content_length=_content_length(resp), server=resp.headers.get("Server", ""),
            elapsed_ms=int((time.monotonic() - started) * 1000), redirects=len(resp.history),
        )
    # unreachable: loop always returns above
    return ProbeResult(url=url, status=None, alive=False, error="unknown", error_kind="other")  # pragma: no cover


def probe_urls(urls: List[str], workers: int = 20, timeout: float = 6.0, progress_cb=None, allow_private: bool = False) -> List[ProbeResult]:
    """Probe a list of URLs concurrently. Optional progress_cb(done, total)
    is called after each completed probe for live progress bars.

    `allow_private` plumbs through to the SSRF guard (ssrf_guard.py) that
    runs before every fetch here -- by default, a URL that resolves to a
    private/loopback/link-local address is refused rather than fetched
    (see that module's docstring for why). Pass True only when this scan's
    target scope deliberately includes internal address space.
    """
    results = []
    total = len(urls)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_probe_one, u, timeout, allow_private): u for u in urls}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                results.append(future.result())
            except Exception as e:  # noqa: BLE001 -- one bad URL must not abort the whole pass
                u = futures[future]
                results.append(ProbeResult(url=u, status=None, alive=False, error=f"internal error: {type(e).__name__}",
                                           error_kind="other"))
            if progress_cb:
                progress_cb(i, total)

    # Preserve original URL order for readability
    order = {u: i for i, u in enumerate(urls)}
    results.sort(key=lambda r: order.get(r.url, 0))
    return results

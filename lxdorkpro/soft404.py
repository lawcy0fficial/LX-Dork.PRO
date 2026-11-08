"""
Soft-404 / wildcard-response detection.

Many sites answer HTTP 200 to *every* path -- a styled "page not found", a SPA
shell, a login redirect. A dork hit on such a host "verifies" trivially: the
URL's own text matches site:/inurl:/ext: and the server happily returns a page.
That looks like a confirmed exposure and is nothing.

The test: request one path that cannot exist -- same directory, same extension,
random name -- and compare. If the server gives back essentially the same
page (or redirects both to the same place), the original response is not
evidence of anything.

Cost: one extra request per unique (scheme, host, directory, extension),
memoized on the PageCache, and only when a cache is in use.
"""

import re
import secrets
from typing import Optional
from urllib.parse import urlsplit, urlunsplit

_WORD = re.compile(r"[a-z0-9]{3,}")
SIMILARITY_THRESHOLD = 0.85


def probe_url_for(url: str) -> Optional[str]:
    """A URL under the same directory with the same extension that can't exist.
    None when there's nothing meaningful to test (a bare host or root path)."""
    try:
        p = urlsplit(url)
    except ValueError:
        return None
    path = p.path or "/"
    if path == "/":
        return None  # the site root legitimately exists; nothing to be "soft" about
    directory, _, last = path.rpartition("/")
    ext = ("." + last.rsplit(".", 1)[1]) if "." in last else ""
    return urlunsplit((p.scheme, p.netloc, f"{directory}/lxdp{secrets.token_hex(8)}{ext}", "", ""))


def _memo_key(url: str):
    p = urlsplit(url)
    directory, _, last = (p.path or "/").rpartition("/")
    ext = last.rsplit(".", 1)[1].lower() if "." in last else ""
    return ("soft404", p.scheme, p.netloc.lower(), directory, ext)


def _words(text: str) -> set:
    return set(_WORD.findall((text or "")[:50000].lower()))


def similarity(a: str, b: str) -> float:
    """Jaccard similarity of the two bodies' word sets (cheap, order-free,
    tolerant of a few dynamic tokens like timestamps or an echoed path)."""
    wa, wb = _words(a), _words(b)
    if not wa and not wb:
        return 1.0
    if not wa or not wb:
        return 0.0
    return len(wa & wb) / len(wa | wb)


def is_soft_404(original_resp, cache, timeout: float = 8.0, allow_private: bool = False) -> Optional[bool]:
    """True if the host serves the same thing for a non-existent sibling path,
    False if it behaves normally (real 404/403/different content), None if it
    couldn't be determined (probe failed, nothing to test). Never raises."""
    original_url = getattr(original_resp, "request", None) and original_resp.request.url or original_resp.url
    probe = probe_url_for(original_url)
    if probe is None or not (200 <= original_resp.status_code < 300 or original_resp.history):
        return None
    key = _memo_key(original_url)

    def compute():
        try:
            return cache.get(probe, timeout, allow_private)
        except Exception:  # noqa: BLE001 -- any failure just means "can't tell"
            return None

    probe_resp = cache.memoize(key, compute)
    if probe_resp is None:
        return None
    if not (200 <= probe_resp.status_code < 300):
        return False  # a real error status for a bogus path: the server discriminates

    # Both requests ended up at the same place (e.g. everything bounces to /login or /)
    if original_resp.history and probe_resp.history and original_resp.url == probe_resp.url:
        return True
    return similarity(original_resp.text, probe_resp.text) >= SIMILARITY_THRESHOLD

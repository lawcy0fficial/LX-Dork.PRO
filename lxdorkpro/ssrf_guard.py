"""
SSRF guard for every module that fetches a URL discovered via search-engine
dorking (probe.py, verify.py, fingerprint.py, secrets_scan.py, screenshot.py).

Why this exists: the URLs this tool fetches come from search-engine
indexes, which is attacker-influenceable input -- there is nothing
stopping a page from being crafted and indexed with a URL like
`http://169.254.169.254/latest/meta-data/iam/security-credentials/` (a
cloud metadata endpoint) or `http://localhost:6379/` (a local service),
and this tool would otherwise happily fetch it from wherever it's
running, on the scanner's own network, as a confused deputy. This module
resolves each target's hostname and refuses anything that lands on a
private, loopback, link-local, multicast, or otherwise non-public address
before any of those modules' fetch calls run.

This is opt-out, not opt-in, deliberately: the common case (running scans
against internet-facing bug-bounty/pentest targets from inside a
corporate network) should be protected by default. `--allow-private-targets`
exists for the legitimate opposite case -- an internal engagement whose
scope genuinely *is* RFC1918 space -- where a blanket block would be
wrong, not for casually working around it.

check_target() does one DNS lookup and range-check up front. That alone is
open to DNS rebinding (a hostname that resolves publicly for the check and to
an internal address for the real connection), so guarded_request() ALSO
verifies the peer address of the socket it actually connected to (see
_PeerCheckAdapter below) -- the check that cannot be raced, because it looks at
where the connection really went rather than at what DNS said earlier. That
connect-time check is skipped when the request goes through an HTTP proxy
(the peer is then the proxy, not the target) and when the caller supplies
its own Session.

Parser differential: the up-front check reads the host with Python's
urlparse(), but `requests` connects using urllib3's parser, and the two
disagree on some inputs. `http://127.0.0.1\\@example.com/` is the classic
case: urlparse() says the host is example.com (public -> allowed) while
urllib3 connects to 127.0.0.1. _parser_differential() refuses any URL the two
parsers would read differently, and any URL with a backslash or control
character in it.

Two things a single check_target() call at the top of a fetch cannot
catch, both handled below:

  - Redirects. `requests`' own `allow_redirects=True` re-sends the
    request to wherever `Location` points without re-running any of this
    module's checks -- a URL that starts on a public IP can 302 straight
    to `http://169.254.169.254/` and would otherwise be followed
    unquestioned. `guarded_request()` below re-validates every hop.
  - Non-http(s) schemes. `file:///etc/passwd` or `gopher://...` have no
    "hostname resolves to a private IP" to catch, since the guard's
    address-range logic doesn't apply. The scheme is checked separately,
    unconditionally -- unlike the address-range check, this is not
    something `--allow-private-targets` can waive, since this tool only
    ever knows how to safely handle http/https.
"""

import ipaddress
import re
import socket
import time
from typing import Optional, Tuple
from urllib.parse import urljoin, urlparse

import requests
from requests.adapters import HTTPAdapter
from urllib3.connection import HTTPConnection, HTTPSConnection
from urllib3.connectionpool import HTTPConnectionPool, HTTPSConnectionPool
from urllib3.exceptions import LocationParseError
from urllib3.response import HTTPResponse as _Urllib3Response
from urllib3.util import parse_url as _urllib3_parse_url

# Hostnames that don't resolve to a meaningfully checkable IP range via
# ipaddress but are still well-known routes to sensitive local/metadata
# services, so they're blocked by name rather than relying solely on
# whatever they happen to resolve to today.
_BLOCKED_HOSTNAMES = {
    "localhost", "metadata.google.internal", "metadata.internal",
}

# The only schemes this tool ever fetches on the operator's behalf.
# Unconditional -- not waived by --allow-private-targets (see module
# docstring): that flag is about address *scope*, not transport safety.
_ALLOWED_SCHEMES = {"http", "https"}

# RFC 6052 "Well-Known Prefix" for NAT64: an IPv6 address inside this /96
# embeds an IPv4 address in its low 32 bits. `ipaddress.IPv6Address.is_global`
# does not unwrap this -- e.g. 64:ff9b::7f00:1 (which embeds 127.0.0.1)
# reads as globally routable unless the embedded IPv4 is extracted and
# range-checked separately, so a NAT64-mapped loopback/private/metadata
# address would otherwise sail straight through.
_NAT64_WKP = ipaddress.ip_network("64:ff9b::/96")

# Hard cap on any single fetched body. A discovered URL is untrusted and
# could otherwise be an arbitrarily large or slow-drip response used to
# exhaust memory or tie up a scan's worker threads.
DEFAULT_MAX_BYTES = 5 * 1024 * 1024  # 5 MiB
DEFAULT_MAX_REDIRECTS = 5


# Active engagement scope (see scope.py), set once per scan by the CLI. Kept
# module-global rather than a ContextVar because fetches run in worker threads
# that wouldn't inherit a context. When set, EVERY fetch and EVERY redirect
# hop must land inside it -- even with --allow-private-targets.
_ACTIVE_SCOPE = None


def set_active_scope(scope) -> None:
    global _ACTIVE_SCOPE
    _ACTIVE_SCOPE = scope


class SSRFGuardError(Exception):
    """Raised by guarded_request() when the original URL or a redirect hop
    fails the guard, or when a response follows more than max_redirects
    hops. `.reason` is the same short human-readable string check_target()
    and is_target_allowed() return as their `reason` value.
    """

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


def _embedded_ipv4(ip: "ipaddress.IPv6Address") -> Optional["ipaddress.IPv4Address"]:
    """Return the IPv4 address embedded in an IPv6 address via NAT64 or
    the ::ffff:a.b.c.d "IPv4-mapped" form, or None if it's neither.
    """
    if ip in _NAT64_WKP:
        return ipaddress.IPv4Address(int(ip) & 0xFFFFFFFF)
    return ip.ipv4_mapped


def _is_public_ip(ip_str: str) -> bool:
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False

    if isinstance(ip, ipaddress.IPv6Address):
        embedded = _embedded_ipv4(ip)
        if embedded is not None and not _is_public_ip(str(embedded)):
            return False

    # is_global is (per Python's own docs) essentially `not is_private`,
    # which folds in loopback/link-local/reserved/unspecified *and*
    # correctly excludes ranges the old hand-rolled check missed, such as
    # CGNAT (100.64.0.0/10, which covers Alibaba Cloud's
    # 100.100.100.200 metadata endpoint) and the benchmarking range
    # (198.18.0.0/15). It does NOT exclude multicast, though (multicast
    # is "not private" by IANA's registry, just not a normal unicast
    # destination either) -- 224.0.0.1.is_global is True -- so that's
    # checked separately, same as the old code did explicitly.
    return ip.is_global and not ip.is_multicast


# Backslashes and control characters are where URL parsers diverge most
# (browsers/urllib3 treat "\\" like "/" in the authority section; Python's
# urlparse does not). No legitimate search-result URL needs them unencoded.
_FORBIDDEN_URL_CHARS = re.compile(r"[\x00-\x1f\x7f\\]")


def _parser_differential(url: str) -> Optional[str]:
    """Return a human-readable reason if `url` is ambiguous between Python's
    urlparse() (used by this module's checks) and urllib3's parser (used by
    `requests` to actually connect), else None.
    """
    if _FORBIDDEN_URL_CHARS.search(url):
        return "URL contains a backslash or control character (parsed differently by different URL parsers)"
    try:
        py_host = (urlparse(url).hostname or "").lower()
        u3_host = (_urllib3_parse_url(url).host or "").strip("[]").lower()
    except (ValueError, LocationParseError):
        return "URL could not be parsed consistently"
    if py_host and py_host != u3_host:  # empty py_host falls through to the "no hostname" check
        return f"URL host is read differently by different parsers ('{py_host}' vs '{u3_host}')"
    return None


def _assert_public_peer(sock) -> None:
    """Close `sock` and raise SSRFGuardError if the address it is actually
    connected to isn't public. This is the connect-time check that defeats
    DNS rebinding: it inspects the real peer, not an earlier DNS answer.
    """
    try:
        peer_ip = sock.getpeername()[0].split("%", 1)[0]
    except OSError:
        return  # not connected / can't tell -- the connection is unusable anyway
    if not _is_public_ip(peer_ip):
        try:
            sock.close()
        finally:
            raise SSRFGuardError(f"connected to non-public address {peer_ip}")


class _GuardedHTTPConnection(HTTPConnection):
    def _new_conn(self):
        sock = super()._new_conn()
        _assert_public_peer(sock)
        return sock


class _GuardedHTTPSConnection(HTTPSConnection):
    def _new_conn(self):
        sock = super()._new_conn()
        _assert_public_peer(sock)
        return sock


class _GuardedHTTPPool(HTTPConnectionPool):
    ConnectionCls = _GuardedHTTPConnection


class _GuardedHTTPSPool(HTTPSConnectionPool):
    ConnectionCls = _GuardedHTTPSConnection


class _PeerCheckAdapter(HTTPAdapter):
    """requests adapter whose connections verify the real peer address."""

    def init_poolmanager(self, *args, **kwargs):
        super().init_poolmanager(*args, **kwargs)
        self.poolmanager.pool_classes_by_scheme = {
            "http": _GuardedHTTPPool, "https": _GuardedHTTPSPool,
        }


def check_scheme(url: str) -> Tuple[bool, str]:
    """Check only the URL scheme, independent of address resolution.
    Split out so guarded_request() can reject file:// etc. even when
    allow_private=True (see module and is_target_allowed docstrings)."""
    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "could not parse URL"
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        return False, f"scheme '{scheme or '(none)'}' is not allowed (only http/https)"
    return True, ""


def check_target(url: str) -> Tuple[bool, str]:
    """Resolve and range-check a URL's hostname. Returns (is_safe, reason)
    -- reason is empty when safe, otherwise a short human-readable
    explanation suitable for surfacing directly in a result's error field.
    Does NOT check scheme -- see check_scheme()/is_target_allowed().
    """
    try:
        parsed = urlparse(url)
    except ValueError:
        return False, "could not parse URL"

    ambiguous = _parser_differential(url)
    if ambiguous:
        return False, ambiguous

    hostname = parsed.hostname
    if not hostname:
        return False, "URL has no hostname"

    if hostname.lower() in _BLOCKED_HOSTNAMES:
        return False, f"'{hostname}' is a blocked hostname"

    # A literal IP in the URL needs no DNS round trip.
    try:
        ipaddress.ip_address(hostname)
        candidate_ips = {hostname}
    except ValueError:
        try:
            candidate_ips = {info[4][0] for info in socket.getaddrinfo(hostname, None)}
        except socket.gaierror as e:
            return False, f"DNS resolution failed for '{hostname}': {e}"
        if not candidate_ips:
            return False, f"DNS resolution for '{hostname}' returned no addresses"

    for ip_str in candidate_ips:
        if not _is_public_ip(ip_str):
            return False, f"'{hostname}' resolves to non-public address {ip_str}"

    return True, ""


def is_target_allowed(url: str, allow_private: bool = False) -> Tuple[bool, str]:
    """The function every fetch call site checks before its *first*
    request. `allow_private` is the plumbed-through value of the CLI's
    --allow-private-targets flag -- when set, the address-range check is a
    deliberate no-op (the operator has explicitly told the tool this
    engagement's scope includes internal space), not a bypass discovered
    incidentally. The scheme check is not affected by allow_private: it's
    a transport-safety floor (see module docstring), not a scope decision.

    This function alone is NOT sufficient for anything that follows
    redirects -- use guarded_request() instead, which calls this per hop.
    """
    ok, reason = check_scheme(url)
    if not ok:
        return False, reason
    if _ACTIVE_SCOPE is not None and not _ACTIVE_SCOPE.contains(url):
        return False, "out of engagement scope"
    if allow_private:
        return True, ""
    return check_target(url)


DEFAULT_MAX_SECONDS = 30.0  # total wall-clock budget for reading one response body


def _iter_available(resp: "requests.Response"):
    """Yield body bytes as they arrive, returning control after EVERY network
    read. iter_content(65536) blocks until 64 KB have accumulated, which is
    exactly what a slow-drip server exploits -- the caller's deadline check
    never gets a turn. urllib3 >= 2 has read1() (one underlying read per
    call); on older urllib3 fall back to iter_content with small chunks.
    """
    raw = resp.raw
    read1 = getattr(raw, "read1", None)
    # Only trust read1 on a genuine urllib3 response (callers/tests may hand in
    # stand-ins whose attributes aren't the real thing).
    if read1 is not None and isinstance(raw, _Urllib3Response):
        while True:
            chunk = read1(65536, decode_content=True)
            if not chunk:
                return
            yield chunk
    else:
        yield from resp.iter_content(chunk_size=1024)


def _cap_body(resp: "requests.Response", max_bytes: int, max_seconds: float = DEFAULT_MAX_SECONDS) -> None:
    """Read resp's body ourselves, stopping at max_bytes, then pre-set
    resp's internal content cache so callers' existing `.text` / `.content`
    / `.json()` usage keeps working unchanged and sees only the capped
    bytes -- no call site needs to switch to manual streaming to get the
    size cap.
    """
    chunks = []
    total = 0
    truncated = False
    deadline = time.monotonic() + max_seconds
    for chunk in _iter_available(resp):
        if not chunk:
            continue
        if total + len(chunk) > max_bytes:
            chunks.append(chunk[: max_bytes - total])
            truncated = True
            break
        chunks.append(chunk)
        total += len(chunk)
        if time.monotonic() > deadline:
            # Slow-drip defence: requests' timeout is per-read, so a server
            # sending a byte every few seconds could otherwise hold a worker
            # for hours. Keep what arrived and mark the body truncated.
            truncated = True
            break
    resp._content = b"".join(chunks)
    resp._content_consumed = True
    resp.raw.close()
    resp.truncated = truncated  # not a requests.Response attribute normally; informational only


def guarded_request(
    method: str,
    url: str,
    *,
    allow_private: bool = False,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_seconds: float = DEFAULT_MAX_SECONDS,
    session: Optional["requests.Session"] = None,
    **kwargs,
) -> "requests.Response":
    """The fetch path every module that touches a discovered URL should go
    through, instead of calling requests.get/head/etc. directly with
    allow_redirects=True. Validates the SSRF guard against the original
    URL and, manually, against every redirect hop -- `requests`' built-in
    redirect following never re-checks the guard, so without this a page
    on a public IP could 302 straight into internal address space. Also
    enforces `max_bytes` on the final response body (see _cap_body) and
    refuses to follow more than `max_redirects` hops.

    Raises SSRFGuardError (never returns a response) if the original URL,
    any redirect hop, or the redirect count fails the guard -- callers
    should catch this alongside requests.RequestException, exactly where
    they previously handled is_target_allowed()'s (False, reason) case.
    kwargs are passed through to requests as-is (e.g. headers, timeout);
    allow_redirects and stream are controlled internally and rejected if
    also passed in kwargs, so callers don't silently override them.
    """
    if "allow_redirects" in kwargs or "stream" in kwargs:
        raise TypeError("guarded_request controls allow_redirects/stream internally; don't pass them")

    own_session = session is None
    sess = session or requests.Session()
    if own_session and not allow_private:
        adapter = _PeerCheckAdapter()
        sess.mount("http://", adapter)
        sess.mount("https://", adapter)
    try:
        return _guarded_request_loop(
            sess, method, url, allow_private, max_redirects, max_bytes, kwargs, max_seconds,
        )
    finally:
        if own_session:
            sess.close()


def _guarded_request_loop(sess, method, url, allow_private, max_redirects, max_bytes, kwargs, max_seconds=DEFAULT_MAX_SECONDS):
    current_url = url
    request_kwargs = dict(kwargs)
    request_kwargs["allow_redirects"] = False
    request_kwargs["stream"] = True
    history = []  # intermediate redirect responses, exposed as resp.history like requests does

    for _hop in range(max_redirects + 1):
        allowed, reason = is_target_allowed(current_url, allow_private=allow_private)
        if not allowed:
            raise SSRFGuardError(reason)

        resp = sess.request(method, current_url, **request_kwargs)

        if resp.is_redirect or resp.is_permanent_redirect:
            location = resp.headers.get("Location")
            resp.close()
            if not location:
                resp.history = history
                return resp  # redirect status with no Location -- nothing to follow
            history.append(resp)
            current_url = urljoin(current_url, location)
            continue

        _cap_body(resp, max_bytes, max_seconds)
        resp.url = current_url
        # We follow redirects by hand (to re-check every hop), so requests never
        # fills this in. Consumers -- probe's redirect count, soft-404's "both
        # requests bounced to the same place" -- need it.
        resp.history = history
        return resp

    raise SSRFGuardError(f"too many redirects (> {max_redirects} hops)")

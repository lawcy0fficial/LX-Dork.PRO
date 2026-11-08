"""
Secret/credential pattern scanning for fetched page bodies.

Deliberately does NOT perform its own HTTP fetch -- verify.py and
fingerprint.py both already fetch every result's body for their own
purposes, so this module operates on text that's already in memory
(`scan_text`) and the CLI wires it in as a third pass over the same fetch,
via `scan_body_with_context` which the async fetch layer (or cli.py's
existing fetch call sites) can call inline. This avoids tripling the
request volume against target servers just to add one more analysis.

Two kinds of indicator:
  - High-confidence structural patterns (AWS access key ID format, PEM
    private key headers, JWT structure, well-known vendor key prefixes)
    that are checked as-is.
  - Generic "labeled secret" patterns (`api_key = "..."`, `password: "..."`)
    which are additionally required to pass a Shannon-entropy threshold on
    the captured value, so `api_key = "changeme"` or `password = "1234"`
    don't fire -- entropy is what actually distinguishes a random secret
    from a placeholder/example value of similar shape.

Every match is redacted before being surfaced (only a short prefix/suffix
kept) -- this module reports that a secret-shaped string exists and where,
never the secret itself, so scan output is safe to paste into a report or
ticket without additionally leaking the credential it found.
"""

import math
import random
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import Dict, List, Optional

import requests
from requests.structures import CaseInsensitiveDict

from .ssrf_guard import SSRFGuardError, guarded_request


@dataclass
class SecretMatch:
    name: str            # e.g. "AWS Access Key ID"
    category: str        # "cloud" | "vcs" | "generic" | "crypto" | "payment" | "chat-ops"
    redacted: str         # e.g. "AKIA1234********WXYZ"
    location: str = ""    # "body" | "header:X-Foo" -- where in the response this was found
    confidence: str = "high"  # "high" | "medium" -- structural match vs. entropy-gated generic match


def _redact(value: str, keep: int = 4) -> str:
    """Keep a short prefix/suffix, mask the middle -- enough to eyeball
    'yes that's the key I rotated' without the report itself being a leak.
    """
    if len(value) <= keep * 2:
        return "*" * len(value)
    return f"{value[:keep]}{'*' * min(8, len(value) - keep * 2)}{value[-keep:]}"


def _shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    freq = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(s)
    return -sum((count / length) * math.log2(count / length) for count in freq.values())


# --- Structural signatures: distinctive format alone is enough evidence. ---
# Each entry: (name, category, compiled regex). The regex's first group (or
# the whole match if there's no group) is the value that gets redacted.
_STRUCTURAL_SIGNATURES = [
    ("AWS Access Key ID", "cloud", re.compile(r"\b((?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16})\b")),
    ("AWS Secret Access Key", "cloud", re.compile(
        r'(?i)aws_secret_access_key\s*[=:]\s*["\']?([A-Za-z0-9/+=]{40})["\']?'
    )),
    ("GCP API Key", "cloud", re.compile(r"\b(AIza[0-9A-Za-z_\-]{35})\b")),
    ("GCP Service Account Key", "cloud", re.compile(r'"type"\s*:\s*"service_account"')),
    ("Azure Storage Account Key", "cloud", re.compile(
        r'(?i)AccountKey=([A-Za-z0-9+/]{86}==)'
    )),
    ("Slack Token", "chat-ops", re.compile(r"\b(xox[baprs]-[A-Za-z0-9-]{10,72})\b")),
    ("Slack Webhook URL", "chat-ops", re.compile(
        r"(https://hooks\.slack\.com/services/T[A-Za-z0-9_/]{20,})"
    )),
    ("Discord Webhook URL", "chat-ops", re.compile(
        r"(https://(?:discord|discordapp)\.com/api/webhooks/\d+/[A-Za-z0-9_\-]+)"
    )),
    ("Stripe Live Secret Key", "payment", re.compile(r"\b(sk_live_[A-Za-z0-9]{20,})\b")),
    ("Stripe Live Publishable Key", "payment", re.compile(r"\b(pk_live_[A-Za-z0-9]{20,})\b")),
    ("GitHub Personal Access Token", "vcs", re.compile(r"\b(gh[pousr]_[A-Za-z0-9]{36,})\b")),
    ("GitLab Personal Access Token", "vcs", re.compile(r"\b(glpat-[A-Za-z0-9_\-]{20,})\b")),
    ("PEM Private Key", "crypto", re.compile(
        r"(-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----)"
    )),
    ("JSON Web Token", "generic", re.compile(
        r"\b(eyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,})\b"
    )),
    ("Google OAuth Refresh/Access Token", "cloud", re.compile(r"\b(ya29\.[0-9A-Za-z_\-]{20,})\b")),
    ("SendGrid API Key", "generic", re.compile(r"\b(SG\.[A-Za-z0-9_\-]{16,}\.[A-Za-z0-9_\-]{16,})\b")),
    ("Twilio API Key", "generic", re.compile(r"\b(SK[a-f0-9]{32})\b")),
    ("Heroku API Key", "cloud", re.compile(
        r'(?i)heroku[a-z_]*["\']?\s*[:=]\s*["\']?([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})'
    )),
    ("npm Access Token", "vcs", re.compile(r"\b(npm_[A-Za-z0-9]{36})\b")),
    ("Telegram Bot Token", "chat-ops", re.compile(r"\b(\d{8,10}:AA[A-Za-z0-9_\-]{33})\b")),
    ("Mailgun API Key", "generic", re.compile(r"\b(key-[0-9a-f]{32})\b")),
    ("Shopify Access Token", "payment", re.compile(r"\b(shp(?:at|ca|pa|ss)_[a-f0-9]{32})\b")),
    ("OpenAI API Key", "ai", re.compile(r"\b(sk-(?:proj-|svcacct-)[A-Za-z0-9_\-]{40,}|sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20})")),
    ("Anthropic API Key", "ai", re.compile(r"\b(sk-ant-(?:api|admin)\d{2}-[A-Za-z0-9_\-]{60,})")),
    ("Sentry DSN", "generic", re.compile(r"\b(https://[0-9a-f]{32}@[a-z0-9.\-]+/\d+)\b")),
    ("Docker Registry Auth", "cloud", re.compile(r'"auths"\s*:\s*\{[^}]{0,300}?"auth"\s*:\s*"([A-Za-z0-9+/=]{16,})"')),
    ("Database Connection String", "cloud", re.compile(
        r"\b((?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|redis|rediss|amqps?|mssql|sqlserver)://[^\s:/@\"'<>]+:[^\s/@\"'<>]{3,}@[^\s\"'<>]+)"
    )),
    ("Credentials in URL", "generic", re.compile(r"\b(https?://[^\s:/@\"'<>]{1,64}:[^\s/@\"'<>]{3,64}@[a-z0-9.\-]+[^\s\"'<>]*)", re.IGNORECASE)),
]

# --- Generic "labeled secret" patterns: shape alone is too common (any
# assignment statement), so the captured value must also clear an entropy
# bar before it's reported. Keeps `password = "changeme"` silent while
# still catching `password = "kQ8x!ztP2#rL9vB"`. ---
_LABELED_SECRET_RE = re.compile(
    r'(?i)\b(api[_-]?key|apikey|secret|token|passwd|password|access[_-]?key|client[_-]?secret)'
    r'\s*[=:]\s*["\']([^"\'\s]{8,100})["\']'
)
_ENTROPY_THRESHOLD = 3.2  # bits/char; typical English/placeholder text sits well below this
_MIN_LABELED_LENGTH = 8


_URL_CRED_RE = re.compile(r"^([a-z0-9+.\-]+://)([^:/@]+):([^@/]+)@", re.IGNORECASE)


def _redact_url_credentials(value: str) -> str:
    """scheme://user:pass@host/... -> scheme://***:***@host/...  The password
    (and username) never appear in output, not even partially."""
    return _URL_CRED_RE.sub(lambda m: f"{m.group(1)}***:***@", value, count=1)


_REDACTORS = {
    "Database Connection String": _redact_url_credentials,
    "Credentials in URL": _redact_url_credentials,
}

# Names whose presence is a lead, not a leaked credential (client-side by design).
PUBLIC_BY_DESIGN = {"Stripe Live Publishable Key", "GCP API Key", "JSON Web Token", "Sentry DSN"}


def _credential_url_is_placeholder(value: str) -> bool:
    """True for docs/template creds like postgres://user:password@localhost/db
    or mysql://${USER}:${PASS}@host -- the dominant false positive for URL creds."""
    m = _URL_CRED_RE.match(value)
    if not m:
        return False
    user, pw = m.group(2).lower(), m.group(3)
    if any(t in pw for t in ("${", "{{", "<", "%s", "%(", "$(")) or pw.startswith(("$", "{", "%")):
        return True
    if pw.lower() in {"password", "pass", "passwd", "secret", "changeme", "user", "pwd", "yourpassword",
                       "your_password", "your-password", "mypassword", "example", "xxxx", "****"}:
        return True
    host = value.split("@", 1)[1].split("/", 1)[0].lower()
    if user in {"user", "username", "root", "admin"} and host.startswith(("localhost", "127.0.0.1", "example")):
        return True
    return _looks_like_placeholder(pw)


def _looks_like_placeholder(value: str) -> bool:
    """Cheap denylist for the most common example/placeholder values that
    can occasionally still clear the entropy bar by coincidence (rare, but
    free to check) -- e.g. 'xxxxxxxxxxxxxxxx' style filler.
    """
    lowered = value.lower()
    if len(set(lowered)) <= 3:
        return True  # e.g. "xxxxxxxx", "00000000", "aaaaaaaa"
    # Template/config indirection: the value isn't a secret, it's a reference to one.
    if any(t in value for t in ("${", "{{", "%(", "process.env", "os.environ", "getenv", "ENV[")):
        return True
    if value.startswith(("<", "$", "{", "%", "@")) and value.endswith((">", "}", "%", ")")):
        return True
    if lowered.startswith(("your_", "your-", "your ", "my_", "my-", "insert", "replace", "enter_", "todo", "fixme")):
        return True
    placeholders = {"changeme", "your_api_key", "your-api-key", "example", "placeholder", "xxxxxxxx",
                    "insert_key_here", "password", "secret", "undefined", "null", "none", "redacted"}
    return lowered in placeholders


def scan_text(text: str, location: str = "body") -> List[SecretMatch]:
    """Scan a blob of text (HTML, JSON, plaintext -- anything) for
    secret-shaped strings. Returns SecretMatch objects with values already
    redacted; never returns the raw secret value.
    """
    if not text:
        return []

    matches: List[SecretMatch] = []
    seen_spans = set()

    for name, category, pattern in _STRUCTURAL_SIGNATURES:
        for m in pattern.finditer(text):
            value = m.group(1) if m.groups() else m.group(0)
            span = (m.start(), m.end())
            if span in seen_spans:
                continue
            if name in ("Database Connection String", "Credentials in URL") and _credential_url_is_placeholder(value):
                continue
            seen_spans.add(span)
            redactor = _REDACTORS.get(name, _redact)
            matches.append(SecretMatch(
                name=name, category=category, redacted=redactor(value), location=location, confidence="high",
            ))

    for m in _LABELED_SECRET_RE.finditer(text):
        value = m.group(2)
        span = (m.start(2), m.end(2))
        if span in seen_spans or len(value) < _MIN_LABELED_LENGTH:
            continue
        if _looks_like_placeholder(value):
            continue
        if _shannon_entropy(value) < _ENTROPY_THRESHOLD:
            continue
        seen_spans.add(span)
        label = m.group(1).replace("_", " ").replace("-", " ").title()
        matches.append(SecretMatch(
            name=f"High-entropy {label}", category="generic",
            redacted=_redact(value), location=location, confidence="medium",
        ))

    return matches


# --- linked JavaScript -----------------------------------------------------
# API keys, tokens and internal endpoints most often live in the JS bundles a
# page loads, not in its HTML. Same-site scripts are fetched through the same
# guarded/scoped/cached path as the page itself.

MAX_JS_FILES = 10

# Vendored libraries: huge, public, and never contain the site's own secrets.
_LIBRARY_JS = re.compile(
    r"(?:^|[/._-])(?:jquery|bootstrap|angular|react(?:-dom)?|vue(?:\.runtime)?|lodash|underscore|moment|"
    r"polyfills?|gtag|gtm|analytics|ga|fbevents|hotjar|modernizr|popper|axios|d3|chart|three|"
    r"swiper|slick|select2|datatables|fontawesome|recaptcha)(?:[._-]|\.js|$)", re.IGNORECASE)
_SECOND_LEVEL = {"co", "com", "org", "net", "gov", "ac", "edu"}


def _site_key(host: str) -> str:
    """Rough registrable domain (last two labels, three for co.uk-style)."""
    labels = (host or "").lower().strip(".").split(".")
    if len(labels) >= 3 and len(labels[-1]) == 2 and labels[-2] in _SECOND_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def linked_script_urls(html: str, page_url: str, limit: int = MAX_JS_FILES) -> List[str]:
    """Same-site <script src> URLs from `html`, in page order, deduplicated,
    skipping well-known vendored libraries. Never raises on malformed HTML."""
    from urllib.parse import urljoin, urlparse
    try:
        page_host = urlparse(page_url).hostname or ""
        srcs = re.findall(r"<script\b[^>]*?\bsrc\s*=\s*[\"']([^\"'>\s]+)[\"']", html or "", flags=re.IGNORECASE)
    except ValueError:
        return []
    out: List[str] = []
    for src in srcs:
        try:
            absolute = urljoin(page_url, src.strip())
            p = urlparse(absolute)
        except ValueError:
            continue
        if p.scheme not in ("http", "https") or not p.hostname:
            continue
        if _site_key(p.hostname) != _site_key(page_host):
            continue  # third-party CDN / ad / analytics script
        if _LIBRARY_JS.search(p.path.rsplit("/", 1)[-1]):
            continue
        if absolute not in out:
            out.append(absolute)
        if len(out) >= limit:
            break
    return out


def scan_url(url: str, timeout: float = 8.0, allow_private: bool = False, cache=None,
             include_js: bool = False, max_js: int = MAX_JS_FILES) -> List[SecretMatch]:
    """Fetch one URL and scan its body + relevant headers for secrets. With
    `include_js`, also fetch and scan the page's same-site <script src> files
    (up to `max_js`), labelling those matches `js:<path>`.

    Every fetch goes through guarded_request() (ssrf_guard.py) or the shared
    PageCache that wraps it: the SSRF guard, engagement scope and size/time
    caps apply to the page, to every redirect hop, and to every script.

    Network/parse failures return what was found so far (or an empty list)
    rather than raising -- a page that can't be fetched simply has nothing to
    report; the caller already gets reachability from --probe/--verify.
    """
    from .engines import USER_AGENTS  # local import avoids a circular import at module load time

    headers = {"User-Agent": random.choice(USER_AGENTS)}  # nosec B311 -- UA rotation for scraping evasion, not security/crypto-sensitive

    def fetch(u):
        if cache is not None:
            return cache.get(u, timeout, allow_private)
        return guarded_request("GET", u, headers=headers, timeout=timeout, allow_private=allow_private)

    try:
        resp = fetch(url)
    except (SSRFGuardError, requests.RequestException):
        return []

    body = resp.text if isinstance(resp.text, str) else ""
    resp_headers = {k: v for k, v in resp.headers.items()}
    matches = scan_response_context(body, resp_headers)

    if include_js:
        from urllib.parse import urlparse
        for js_url in linked_script_urls(body, resp.url or url, max_js):
            try:
                js = fetch(js_url)
            except (SSRFGuardError, requests.RequestException):
                continue  # out of scope / unreachable / blocked: skip just this script
            js_body = js.text if isinstance(js.text, str) else ""
            label = "js:" + (urlparse(js_url).path or js_url)
            for m in scan_text(js_body, location=label):
                matches.append(m)
    return matches


def scan_results(results: List, workers: int = 10, timeout: float = 8.0, progress_cb=None, allow_private: bool = False, cache=None,
                 include_js: bool = False) -> Dict[str, List[SecretMatch]]:
    """Scan a batch of SearchResults concurrently. Returns a dict keyed by
    URL (only URLs with at least one match are included, so callers can
    treat `.get(url, [])` as "no secrets found" without a bulkier
    per-result wrapper object -- this feeds straight into
    findings.build_findings(secret_results=...) which expects exactly
    this shape).

    `allow_private` plumbs through to the SSRF guard each fetch runs
    through first -- see probe.probe_urls's docstring for what it does
    and why the default refuses private/loopback/link-local targets.
    """
    out: Dict[str, List[SecretMatch]] = {}
    total = len(results)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(scan_url, r.url, timeout, allow_private, cache, include_js): r for r in results}
        for i, future in enumerate(as_completed(futures), 1):
            r = futures[future]
            try:
                matches = future.result()
            except Exception:  # noqa: BLE001 -- one bad URL must not abort the whole pass
                matches = []
            if matches:
                out[r.url] = matches
            if progress_cb:
                progress_cb(i, total)
    return out


def scan_response_context(body: str, headers: Optional[dict] = None) -> List[SecretMatch]:
    """Convenience wrapper: scan both the body and a couple of headers that
    occasionally carry leaked tokens (rare, but seen in the wild via debug
    middleware echoing config back in a response header). `headers` is a
    plain dict as already produced by `resp.headers` in verify.py/
    fingerprint.py -- pass it straight through, no extra fetch needed.
    """
    matches = list(scan_text(body, location="body"))
    if headers:
        headers = CaseInsensitiveDict(headers)
        for header_name in ("X-Debug-Token", "X-Powered-By", "Set-Cookie", "Warning"):
            value = headers.get(header_name)
            if value:
                matches.extend(scan_text(value, location=f"header:{header_name}"))
    return matches

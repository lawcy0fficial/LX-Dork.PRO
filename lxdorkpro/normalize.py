"""
URL normalization for deduplication. Different engines often return the
"same" page with cosmetic URL differences -- trailing slash, default port,
query params in a different order, tracking params, fragment identifiers.
Treated naively, these look like different URLs and inflate result counts
with near-duplicates. This module computes a canonical dedup key while
leaving the original URL untouched for display/export.
"""

from urllib.parse import urlsplit, urlunsplit, parse_qsl, urlencode

# Common tracking/session params that shouldn't affect identity for dedup
# purposes -- two URLs differing only in these are the same page.
#
# Only params that are *purely* click/campaign tracking belong here. Generic
# names like `ref`, `referrer` and `source` are deliberately NOT ignored: they
# are real inputs on many sites (`download.php?source=a.zip`, `?ref=main`), and
# treating them as noise would merge distinct pages and silently drop results.
_IGNORED_PARAMS = {
    "utm_source", "utm_medium", "utm_campaign", "utm_term", "utm_content", "utm_id",
    "fbclid", "gclid", "gclsrc", "dclid", "msclkid", "yclid", "twclid", "igshid",
    "mc_cid", "mc_eid", "_ga", "_gl", "_hsenc", "_hsmi", "mkt_tok", "vero_id",
}


def normalize_url(url: str) -> str:
    """Return a canonical form of `url` suitable as a dedup key.

    - lowercases scheme and host
    - strips default ports (:80 for http, :443 for https)
    - strips a trailing slash on the path (except root "/")
    - drops the fragment
    - drops known tracking params
    - sorts remaining query params for order-independence
    """
    if not url:
        return url

    try:
        parts = urlsplit(url)
    except ValueError:
        return url  # malformed URL -- fall back to using it as-is

    scheme = parts.scheme.lower()
    host = parts.netloc.lower()

    # Strip default ports
    if scheme == "http" and host.endswith(":80"):
        host = host[: -len(":80")]
    elif scheme == "https" and host.endswith(":443"):
        host = host[: -len(":443")]

    path = parts.path
    if path in ("", "/"):
        path = ""  # treat "no path" and "root slash" as identical
    elif path.endswith("/"):
        path = path.rstrip("/")

    query_pairs = [
        (k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True)
        if k.lower() not in _IGNORED_PARAMS
    ]
    query_pairs.sort()
    query = urlencode(query_pairs)

    return urlunsplit((scheme, host, path, query, ""))  # fragment dropped

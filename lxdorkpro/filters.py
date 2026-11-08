"""
URL filtering logic, kept separate from the CLI so it can be unit tested
without pulling in click/rich/requests.
"""

import re
from collections import defaultdict
from typing import Iterable, List, Optional, Protocol
from urllib.parse import urlsplit


class _HasUrl(Protocol):
    url: str


def _split_exts(value: Optional[str]) -> set:
    return {e.strip().lower().lstrip(".") for e in (value or "").split(",") if e.strip()}


def _url_ext(url: str) -> str:
    try:
        last = urlsplit(url).path.rsplit("/", 1)[-1]
    except ValueError:
        return ""
    return last.rsplit(".", 1)[1].lower() if "." in last else ""


def apply_filters(
    results: List[_HasUrl],
    filter_str: Optional[str] = None,
    exclude_str: Optional[str] = None,
    filter_regex: Optional[str] = None,
    exclude_regex: Optional[str] = None,
    include_ext: Optional[str] = None,
    exclude_ext: Optional[str] = None,
    max_per_host: Optional[int] = None,
) -> List[_HasUrl]:
    """Filter a list of objects with a `.url` attribute. All filters are ANDed.

    - filter_str / exclude_str: keep / drop URLs containing a substring (case-insensitive)
    - filter_regex / exclude_regex: keep / drop URLs matching a regex
    - include_ext / exclude_ext: comma-separated file extensions ("pdf,doc"); a
      URL with no extension never matches include_ext and is never dropped by exclude_ext
    - max_per_host: keep at most N results per hostname (first-seen order wins) --
      stops one noisy host (a forum, a CDN) from drowning everything else

    Raises re.error for an invalid regex so the CLI can report it up front.
    """
    filtered = results

    if filter_str:
        needle = filter_str.lower()
        filtered = [r for r in filtered if needle in r.url.lower()]

    if exclude_str:
        needle = exclude_str.lower()
        filtered = [r for r in filtered if needle not in r.url.lower()]

    if filter_regex:
        pattern = re.compile(filter_regex)
        filtered = [r for r in filtered if pattern.search(r.url)]

    if exclude_regex:
        pattern = re.compile(exclude_regex)
        filtered = [r for r in filtered if not pattern.search(r.url)]

    inc = _split_exts(include_ext)
    if inc:
        filtered = [r for r in filtered if _url_ext(r.url) in inc]

    exc = _split_exts(exclude_ext)
    if exc:
        filtered = [r for r in filtered if _url_ext(r.url) not in exc]

    if max_per_host and max_per_host > 0:
        counts = defaultdict(int)
        kept = []
        for r in filtered:
            try:
                host = (urlsplit(r.url).hostname or "").lower()
            except ValueError:
                host = ""
            if counts[host] < max_per_host:
                counts[host] += 1
                kept.append(r)
        filtered = kept

    return filtered

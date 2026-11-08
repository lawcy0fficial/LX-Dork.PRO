"""
Command parsing for the interactive results browser (lxdorkpro/tui.py).

Kept separate and side-effect-free (no I/O, no printing) so it can be unit
tested directly -- the actual browse loop is a thin wrapper around this.
"""

import re
from dataclasses import dataclass
from typing import Any, List, Optional


@dataclass
class BrowseAction:
    kind: str                      # "view" | "open" | "next" | "prev" | "goto" | "quit" | "help" | "unknown"
    index: Optional[int] = None    # 1-based index within the CURRENT PAGE, for view/open
    page: Optional[int] = None     # 1-based target page, for goto
    raw: str = ""                  # the original input, for error messages


_VIEW_RE = re.compile(r"^v\s*(\d+)$", re.IGNORECASE)
_OPEN_RE = re.compile(r"^o\s*(\d+)$", re.IGNORECASE)
_GOTO_RE = re.compile(r"^g(?:oto)?\s*(\d+)$", re.IGNORECASE)
_BARE_NUMBER_RE = re.compile(r"^\d+$")


def parse_command(raw_input: str) -> BrowseAction:
    """Parse one line of user input in the browser into a BrowseAction.

    Supported commands (case-insensitive, whitespace-tolerant):
      <n>        view item n on the current page (bare number is shorthand for 'v n')
      v<n>       view item n on the current page (full details)
      o<n>       open item n's URL in the default web browser
      n / next   next page
      p / prev   previous page
      g<n>       jump to page n
      h / help   show the command list
      q / quit   exit the browser
    Anything else -> kind="unknown" (the caller decides how to report it).
    """
    cmd = raw_input.strip()
    if not cmd:
        return BrowseAction(kind="unknown", raw=raw_input)

    lower = cmd.lower()

    if lower in ("q", "quit", "exit"):
        return BrowseAction(kind="quit", raw=raw_input)
    if lower in ("n", "next"):
        return BrowseAction(kind="next", raw=raw_input)
    if lower in ("p", "prev", "previous"):
        return BrowseAction(kind="prev", raw=raw_input)
    if lower in ("h", "help", "?"):
        return BrowseAction(kind="help", raw=raw_input)

    if _BARE_NUMBER_RE.match(cmd):
        return BrowseAction(kind="view", index=int(cmd), raw=raw_input)

    m = _VIEW_RE.match(lower)
    if m:
        return BrowseAction(kind="view", index=int(m.group(1)), raw=raw_input)

    m = _OPEN_RE.match(lower)
    if m:
        return BrowseAction(kind="open", index=int(m.group(1)), raw=raw_input)

    m = _GOTO_RE.match(lower)
    if m:
        return BrowseAction(kind="goto", page=int(m.group(1)), raw=raw_input)

    return BrowseAction(kind="unknown", raw=raw_input)


def paginate(items: List[Any], page: int, page_size: int) -> List[Any]:
    """Return the 1-based `page`'s slice of `items`. Clamps out-of-range
    pages to the nearest valid page instead of raising or returning empty.
    """
    if not items:
        return []
    total_pages = max(1, (len(items) + page_size - 1) // page_size)
    page = max(1, min(page, total_pages))
    start = (page - 1) * page_size
    return items[start : start + page_size]


def total_pages(item_count: int, page_size: int) -> int:
    if item_count == 0:
        return 1
    return (item_count + page_size - 1) // page_size

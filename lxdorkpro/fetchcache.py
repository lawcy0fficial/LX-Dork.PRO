"""
Fetch-once page cache.

verify / fingerprint / secrets / vuln-hints each need the same thing: a GET of
the result URL. Without sharing, a scan with all four sends four GETs per URL
to a target you're being careful with (and four times the chance of tripping
its WAF). A PageCache lets the first analysis do the fetch and the rest reuse
the response.

- Goes through guarded_request(), so SSRF/scope/size-cap protections apply.
- Failures are cached too (and re-raised identically), so a dead or blocked
  URL is attempted once, not once per analysis.
- Per-URL locking: concurrent callers for the same URL wait for one fetch.
- Bounded by a byte budget (LRU eviction). An evicted page is simply
  re-fetched if someone asks again; correctness never depends on a hit.
"""

import random  # nosec B311 -- UA rotation, not security-sensitive
import threading
from collections import OrderedDict
from typing import Dict, Tuple

from .engines import USER_AGENTS
from .ssrf_guard import guarded_request

DEFAULT_MAX_BYTES = 200 * 1024 * 1024


class PageCache:
    def __init__(self, max_bytes: int = DEFAULT_MAX_BYTES):
        self.max_bytes = max_bytes
        self.hits = 0
        self.misses = 0
        self._entries: "OrderedDict[Tuple[str, bool], tuple]" = OrderedDict()  # key -> (resp|None, exc|None, size)
        self._size = 0
        self._lock = threading.Lock()
        self._key_locks: Dict[Tuple[str, bool], threading.Lock] = {}
        self._memo: Dict[object, object] = {}
        self._memo_locks: Dict[object, threading.Lock] = {}

    def _key_lock(self, key):
        with self._lock:
            return self._key_locks.setdefault(key, threading.Lock())

    def get(self, url: str, timeout: float = 8.0, allow_private: bool = False):
        """Return the cached/fetched Response, or re-raise the cached error."""
        key = (url, bool(allow_private))
        with self._key_lock(key):
            with self._lock:
                entry = self._entries.get(key)
                if entry is not None:
                    self._entries.move_to_end(key)
                    self.hits += 1
            if entry is None:
                entry = self._fetch(url, timeout, allow_private)
                with self._lock:
                    self.misses += 1
                    self._entries[key] = entry
                    self._size += entry[2]
                    while self._size > self.max_bytes and len(self._entries) > 1:
                        _, (_, _, sz) = self._entries.popitem(last=False)
                        self._size -= sz
        resp, exc, _ = entry
        if exc is not None:
            raise exc
        return resp

    @staticmethod
    def _fetch(url, timeout, allow_private):
        headers = {"User-Agent": random.choice(USER_AGENTS)}  # nosec B311
        try:
            resp = guarded_request("GET", url, headers=headers, timeout=timeout, allow_private=allow_private)
        except Exception as e:  # noqa: BLE001 -- cached and re-raised to the caller unchanged
            return (None, e, 1)
        return (resp, None, len(resp.content or b"") + 1)

    def memoize(self, key, fn):
        """Compute fn() once per key (thread-safe; concurrent callers wait for
        the first). For derived per-host facts, like soft-404 behaviour."""
        with self._lock:
            lock = self._memo_locks.setdefault(key, threading.Lock())
        with lock:
            if key not in self._memo:
                self._memo[key] = fn()
            return self._memo[key]

    @property
    def requests_saved(self) -> int:
        return self.hits

    @property
    def size_bytes(self) -> int:
        return self._size

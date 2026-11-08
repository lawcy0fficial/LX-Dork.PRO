"""
Async orchestration core for running many (engine x query) searches
concurrently via asyncio, as the foundation for:

  - True result streaming: `on_result` fires the instant a result is
    deduped in, from inside the event loop -- a live UI (the planned
    Textual TUI, which is itself asyncio-native) can await this directly
    and append a row per callback instead of waiting for a batch to land.
  - Cooperative cancellation: `asyncio.CancelledError` propagates cleanly
    through `run_search_async`, so a future TUI "stop this job" action
    (or Ctrl+C via `run_search_blocking`) can cancel outstanding tasks
    immediately rather than waiting out whatever a thread pool's workers
    happen to be doing.
  - An adaptive per-engine delay that grows when an engine appears to be
    throttling/blocking and shrinks back down once it recovers, replacing
    the fixed `--delay` sleep with something that reacts to what's
    actually happening (see AdaptiveDelay's docstring for the honest
    caveat on what signal this is actually based on).

Deliberately does NOT require rewriting the 13 synchronous engine classes
onto an async HTTP client. Each engine's blocking `.search()` call runs
inside `asyncio.to_thread()`, which is exactly what asyncio recommends
for wrapping blocking I/O it doesn't control -- this gets real concurrency
today without a second, parallel set of engine implementations to keep in
sync with `engines.py`. Migrating individual engines to a native async
HTTP client later remains possible without changing this module's
interface, since `run_search_async` only depends on `engine.search()`
existing, not on how it's implemented.

This is an additive alternative orchestration path, not a replacement:
`cli._run_search` (thread-pool based) remains the default. This module is
wired in behind an opt-in flag so the well-tested existing path is never
at risk, and is meant to be exercised directly today and to become the
default once the Textual TUI (which needs an asyncio event loop to be
running anyway) lands on top of it.
"""

import asyncio
import random
import time
from typing import Callable, Dict, List, Optional

from .engines import get_engine, EngineError, SearchResult
from .config import is_engine_configured
from .normalize import normalize_url


class AdaptiveDelay:
    """Per-engine delay that grows when an engine starts returning nothing
    and shrinks back down once it recovers.

    Honest caveat: this is a heuristic, not a true 429/Retry-After-aware
    limiter. Every engine in engines.py currently catches its own HTTP
    errors internally and simply returns an empty list on failure rather
    than surfacing a status code -- so "returned nothing twice in a row"
    is the only signal available today, and is used as a proxy for "this
    engine might be throttling or blocking us." A real 429-aware limiter
    would need each engine to surface (or at least distinguish "empty
    because throttled" from "empty because no results exist"), which is a
    larger change to engines.py tracked separately, not bundled in here.
    """

    def __init__(self, base_delay: float, min_delay: float = 0.5, max_delay: float = 30.0,
                 growth: float = 1.8, decay: float = 0.85, trigger_after: int = 2, jitter: float = 0.0):
        self.jitter = max(jitter, 0.0)
        self.base_delay = max(base_delay, 0.0)
        self.current = self.base_delay
        self.min_delay = min_delay
        self.max_delay = max_delay
        self.growth = growth
        self.decay = decay
        self.trigger_after = trigger_after
        self._consecutive_empty = 0

    def record(self, got_results: bool) -> None:
        """Update the delay based on whether the last request to this
        engine returned anything. Call once per completed request.
        """
        if got_results:
            self._consecutive_empty = 0
            if self.current > self.base_delay:
                self.current = max(self.base_delay, self.current * self.decay)
        else:
            self._consecutive_empty += 1
            if self._consecutive_empty >= self.trigger_after:
                floor = max(self.current, self.base_delay, self.min_delay)
                self.current = min(self.max_delay, floor * self.growth)

    def jittered(self) -> float:
        """The delay to actually sleep: never SHORTER than `delay`, up to `jitter`
        (a fraction) longer. Perfectly regular spacing is a bot signature."""
        d = self.delay
        return d * (1.0 + random.uniform(0.0, self.jitter)) if d and self.jitter else d  # nosec B311 -- timing jitter, not crypto

    @property
    def delay(self) -> float:
        return self.current


class SearchCancelled(Exception):
    """Raised (instead of letting asyncio.CancelledError propagate raw)
    when a search is cancelled mid-flight, carrying whatever results had
    already been found so a caller can still show partial results instead
    of losing everything a cancelled scan had already turned up.
    """

    def __init__(self, partial_results: List[SearchResult]):
        super().__init__(f"Search cancelled with {len(partial_results)} result(s) already found")
        self.partial_results = partial_results


async def _search_one(engine_name: str, query: str, limit: int, cfg: dict,
                       limiters: Dict[str, AdaptiveDelay], locks: Dict[str, asyncio.Lock]):
    """Run a single (engine, query) search: wait out this engine's current
    adaptive delay, run the blocking .search() in a worker thread so it
    doesn't block the event loop, then record whether it produced results
    so the delay can adjust for the next call to this engine.
    """
    if not is_engine_configured(cfg, engine_name):
        return engine_name, query, None, f"Skipping '{engine_name}': not configured."

    limiter = limiters[engine_name]
    lock = locks[engine_name]

    # The lock serializes requests to the SAME engine (so the delay
    # between them is actually respected) while different engines still
    # run fully concurrently -- same guarantee cli._RateLimiter gives the
    # thread-pool path, just expressed with an asyncio primitive.
    async with lock:
        if limiter.delay > 0:
            await asyncio.sleep(limiter.jittered())
        try:
            first = [True]

            def throttle():
                # Runs inside the worker thread: pace every request after
                # the task's first (pagination/retries), using the
                # limiter's current adaptive delay.
                if first[0]:
                    first[0] = False
                    return
                time.sleep(limiter.jittered())

            engine = get_engine(engine_name, dict(cfg, _throttle=throttle), timeout=cfg.get("timeout", 10))
            results = await asyncio.to_thread(engine.search, query, limit)
            limiter.record(got_results=bool(results))
            return engine_name, query, results, None
        except EngineError as e:
            limiter.record(got_results=False)
            return engine_name, query, None, str(e)
        except asyncio.CancelledError:
            raise
        except KeyboardInterrupt as e:
            # A worker thread run via asyncio.to_thread doesn't receive the
            # SIGINT that produces a real user-facing KeyboardInterrupt --
            # only the main thread does -- so this can only mean an
            # engine's .search() raised it directly (deliberately or via a
            # bug). Treat it like any other engine misbehavior rather than
            # letting it propagate raw: asyncio.run()'s shutdown sequence
            # doesn't expect a BaseException surfacing from deep inside a
            # completed task and logs a confusing "unhandled exception
            # during shutdown" warning if it does.
            limiter.record(got_results=False)
            return engine_name, query, None, f"{engine_name}: unexpected error: {e}"
        except Exception as e:  # noqa: BLE001 -- an engine bug shouldn't take the whole scan down
            limiter.record(got_results=False)
            return engine_name, query, None, f"{engine_name}: unexpected error: {e}"


async def run_search_async(
    engines_list: List[str],
    queries: List[str],
    limit: int,
    cfg: dict,
    base_delay: float,
    on_result: Optional[Callable[[SearchResult], None]] = None,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
    on_warning: Optional[Callable[[str], None]] = None,
    partial_sink: Optional[List[SearchResult]] = None,
) -> List[SearchResult]:
    """Async equivalent of cli._run_search: runs every (query, engine)
    pair concurrently, deduping by normalized URL and recording
    cross-engine corroboration in `also_seen_in` exactly like the
    thread-pool path does, so findings.py's scoring works identically
    regardless of which orchestration path produced the results.

    `on_result(result)` fires the moment each new (non-duplicate) result
    is found. `on_progress(done, total, description)` fires after every
    completed (engine, query) task, whether or not it produced a new
    result -- suited for a progress bar or a live "N/total tasks done"
    indicator. `on_warning(message)` fires for skipped/misconfigured
    engines and per-task errors, letting the caller decide how (or
    whether) to display them, rather than this module printing directly.

    Raises SearchCancelled (carrying whatever was found so far) if the
    calling task is cancelled mid-run, instead of losing partial results.
    """
    seen: Dict[str, SearchResult] = {}
    all_results: List[SearchResult] = partial_sink if partial_sink is not None else []
    limiters = {name: AdaptiveDelay(base_delay, jitter=cfg.get("jitter", 0.0)) for name in engines_list}
    locks = {name: asyncio.Lock() for name in engines_list}

    tasks = [
        asyncio.ensure_future(_search_one(engine_name, query, limit, cfg, limiters, locks))
        for query in queries for engine_name in engines_list
    ]
    total = len(tasks)
    done_count = 0

    try:
        for coro in asyncio.as_completed(tasks):
            engine_name, query, results, error = await coro
            done_count += 1

            if error:
                if on_warning:
                    on_warning(error)
            elif results:
                for r in results:
                    key = normalize_url(r.url)
                    if key not in seen:
                        if not r.source_query:
                            r.source_query = query
                        seen[key] = r
                        all_results.append(r)
                        if on_result:
                            on_result(r)
                    else:
                        kept = seen[key]
                        if r.engine and r.engine != kept.engine and r.engine not in kept.also_seen_in:
                            kept.also_seen_in.append(r.engine)

            if on_progress:
                on_progress(done_count, total, f"{engine_name} -> {query[:40]}")

    except asyncio.CancelledError:
        for t in tasks:
            t.cancel()
        raise SearchCancelled(all_results)

    return all_results


def run_search_blocking(
    engines_list: List[str],
    queries: List[str],
    limit: int,
    cfg: dict,
    base_delay: float,
    on_result: Optional[Callable[[SearchResult], None]] = None,
    on_progress: Optional[Callable[[int, int, str], None]] = None,
    on_warning: Optional[Callable[[str], None]] = None,
) -> List[SearchResult]:
    """Synchronous entry point for callers (like today's cli.py) that
    aren't running inside an event loop themselves. Drives
    run_search_async to completion with asyncio.run(), and turns
    Ctrl+C (KeyboardInterrupt) during the run into a clean partial-results
    return instead of a traceback -- consistent with how --watch already
    treats KeyboardInterrupt as "stop, don't crash" elsewhere in cli.py.
    """
    sink: List[SearchResult] = []

    async def _runner():
        return await run_search_async(
            engines_list, queries, limit, cfg, base_delay,
            on_result=on_result, on_progress=on_progress, on_warning=on_warning,
            partial_sink=sink,
        )

    try:
        return asyncio.run(_runner())
    except KeyboardInterrupt:
        # asyncio.run() re-raises KeyboardInterrupt after tearing the loop
        # down, so there's no live task list left to inspect for partial
        # results here (unlike the SearchCancelled path above, which is
        # for in-loop cancellation e.g. from a future TUI). Results found
        # before the interrupt were already delivered via on_result as
        # they came in, so nothing is silently lost -- this function
        # simply returns what it can rather than propagating a traceback.
        # `sink` is the live result list, so Ctrl+C keeps everything found
        # so far for the table/history/export instead of discarding it.
        return list(sink)

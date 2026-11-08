"""
Run history: every dork/preset run is auto-logged to disk, keyed by a stable
job id (derived from the dork/preset+target + engine list). The next time you
run the same job, LX-Dork-Pro can tell you exactly which URLs are NEW since
last time — the single most useful thing for ongoing bug-bounty monitoring.
"""

import hashlib
import json
import re
import time
from pathlib import Path
from typing import List, Optional, Tuple
import os

from .engines import SearchResult
from .normalize import normalize_url

HISTORY_DIR = Path(os.environ.get("LXDORK_HOME", Path.home() / ".config" / "lx-dork-pro")) / "history"


def _job_id(job_key: str) -> str:
    return hashlib.sha256(job_key.encode("utf-8")).hexdigest()[:16]


def _job_file(job_key: str) -> Path:
    return HISTORY_DIR / f"{_job_id(job_key)}.json"


def load_last_run(job_key: str) -> Optional[dict]:
    """Return the last saved run for this job (dict with 'timestamp' and
    'urls'), or None if this job has never been run before.
    """
    f = _job_file(job_key)
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


# Cap on remembered URLs per job (oldest first-seen are dropped beyond this).
MAX_SEEN = 20000


def _seen_map(last: Optional[dict]) -> dict:
    """normalized-url -> first-seen timestamp, from any history-file version."""
    if not last:
        return {}
    if isinstance(last.get("seen"), dict):
        return dict(last["seen"])
    ts = last.get("timestamp") or 0
    keys = last.get("keys") or [normalize_url(u) for u in last.get("urls", [])]
    return {k: ts for k in keys}


def save_run(job_key: str, results: List[SearchResult]) -> str:
    """Persist this run. Besides the latest URL list, keeps a CUMULATIVE
    first-seen map so a URL that drops out of one run (engines are flaky)
    and comes back is not reported as new again -- which would otherwise
    spam --watch notifications."""
    HISTORY_DIR.mkdir(parents=True, exist_ok=True)
    now = time.time()
    keys = {normalize_url(r.url) for r in results}
    seen = _seen_map(load_last_run(job_key))
    for k in keys:
        seen.setdefault(k, now)
    if len(seen) > MAX_SEEN:
        keep = sorted(seen.items(), key=lambda kv: kv[1], reverse=True)[:MAX_SEEN]
        seen = dict(keep)
    payload = {
        "job_key": job_key,
        "timestamp": now,
        "urls": [r.url for r in results],
        "keys": sorted(keys),
        "seen": seen,
    }
    f = _job_file(job_key)
    tmp = f.with_name(f.name + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2), encoding="utf-8")
    os.replace(tmp, f)  # atomic: a crash mid-write can't corrupt the history
    return str(f)


def diff_against_last(job_key: str, results: List[SearchResult]) -> Tuple[set, bool, Optional[float]]:
    """Compare current results to everything this job has ever seen.
    Returns (new_urls: set, previous_run_exists: bool, previous_timestamp: float|None).
    Comparison is on normalized URLs (trailing slash / param order don't count).
    """
    last = load_last_run(job_key)
    current_urls = {r.url for r in results}
    if last is None:
        return current_urls, False, None
    previously_seen = set(_seen_map(last))
    new_urls = {u for u in current_urls if normalize_url(u) not in previously_seen}
    return new_urls, True, last.get("timestamp")


def make_job_key(kind: str, identifier: str, engines_list: List[str]) -> str:
    """Build a stable job key so re-running the exact same dork/preset+target
    with the exact same engine set is recognized as 'the same job' for diffing.
    """
    return f"{kind}::{identifier}::{','.join(sorted(engines_list))}"


def list_history() -> List[dict]:
    """Return metadata for all saved jobs, most recent first."""
    if not HISTORY_DIR.exists():
        return []
    jobs = []
    for f in HISTORY_DIR.glob("*.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
            jobs.append(
                {
                    "job_key": data.get("job_key", "?"),
                    "timestamp": data.get("timestamp", 0),
                    "count": len(data.get("urls", [])),
                }
            )
        except (json.JSONDecodeError, OSError):
            continue
    jobs.sort(key=lambda j: j["timestamp"], reverse=True)
    return jobs


# ---------------------------------------------------------------------------
# Time-based queries over the cumulative first-seen map
# ---------------------------------------------------------------------------

_DURATION_UNITS = {"s": 1, "m": 60, "h": 3600, "d": 86400, "w": 604800}


def parse_duration(text: str) -> float:
    """'90m' / '24h' / '7d' / '2w' / '45s' -> seconds. Raises ValueError."""
    m = re.fullmatch(r"\s*(\d+(?:\.\d+)?)\s*([smhdw])\s*", (text or "").lower())
    if not m:
        raise ValueError(f"'{text}' is not a duration; use e.g. 90m, 24h, 7d, 2w")
    return float(m.group(1)) * _DURATION_UNITS[m.group(2)]


def find_job(selector: str) -> dict:
    """Resolve a job by 1-based index (as shown by `history`), exact key, or a
    unique substring of the key. Raises LookupError with a helpful message."""
    jobs = list_history()
    if not jobs:
        raise LookupError("no history yet -- run a `dork` or `preset` scan first")
    selector = (selector or "").strip()
    if selector.isdigit():
        i = int(selector)
        if 1 <= i <= len(jobs):
            return jobs[i - 1]
        raise LookupError(f"no job #{i}; there are {len(jobs)} (see `lxdorkpro history`)")
    exact = [j for j in jobs if j["job_key"] == selector]
    if exact:
        return exact[0]
    partial = [j for j in jobs if selector.lower() in j["job_key"].lower()]
    if len(partial) == 1:
        return partial[0]
    if not partial:
        raise LookupError(f"no job matches '{selector}'")
    raise LookupError(f"'{selector}' matches {len(partial)} jobs; be more specific or use its number")


def changes_since(job_key: str, since_ts: float) -> dict:
    """What changed for a job. Returns
        {"timestamp": last-run time,
         "new":  [(url, first_seen_ts), ...]  first seen at/after since_ts, newest first,
         "gone": [(url, first_seen_ts), ...]  seen before but absent from the latest run,
         "total_seen": int}
    URLs from the latest run keep their original spelling; ones that have since
    vanished are shown in normalized form (the original wasn't kept).
    """
    last = load_last_run(job_key)
    if last is None:
        return {"timestamp": None, "new": [], "gone": [], "total_seen": 0}
    seen = _seen_map(last)
    raw_by_key = {normalize_url(u): u for u in last.get("urls", [])}
    in_last = set(raw_by_key)
    new = sorted(((raw_by_key.get(k, k), ts) for k, ts in seen.items() if ts >= since_ts),
                 key=lambda x: -x[1])
    gone = sorted(((k, ts) for k, ts in seen.items() if k not in in_last), key=lambda x: -x[1])
    return {"timestamp": last.get("timestamp"), "new": new, "gone": gone, "total_seen": len(seen)}

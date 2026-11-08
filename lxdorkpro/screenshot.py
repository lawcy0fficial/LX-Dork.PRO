"""
Screenshot capture for discovered URLs. Uses `wkhtmltoimage` (a common,
lightweight static binary -- part of the wkhtmltopdf project, often
already present on security-focused distros, otherwise a simple package
install) rather than bundling a full headless browser like Playwright,
which needs a ~300MB browser download that can't be shipped with a pip
package.

Design choice, stated plainly: this trades some rendering fidelity
(wkhtmltoimage's WebKit engine doesn't execute modern JS-heavy SPAs the
way a real browser does) for zero heavy runtime dependencies. If you need
full JS rendering, point `LXDORK_SCREENSHOT_BIN` at a wrapper script
around Playwright/Selenium instead -- capture_one() only cares that the
binary accepts `<bin> [options] <url> <output_path>`.
"""

import hashlib
import os
import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from .engines import SearchResult
from .ssrf_guard import is_target_allowed

DEFAULT_BINARY = os.environ.get("LXDORK_SCREENSHOT_BIN") or "wkhtmltoimage"


@dataclass
class ScreenshotResult:
    url: str
    success: bool
    path: str = ""
    error: str = ""


def is_available(binary: str = DEFAULT_BINARY) -> bool:
    return shutil.which(binary) is not None


def _safe_filename(url: str, ext: str = "png") -> str:
    """Turn a URL into a filesystem-safe, collision-resistant filename:
    a short readable prefix (host + path slug) plus a hash suffix so two
    different URLs never collide even if their slugs coincide.
    """
    digest = hashlib.sha256(url.encode("utf-8")).hexdigest()[:10]
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", url).strip("-").lower()
    slug = slug[:80] if slug else "page"
    return f"{slug}-{digest}.{ext}"


def capture_one(
    url: str, output_dir: str, binary: str = DEFAULT_BINARY,
    width: int = 1280, timeout: float = 20.0, allow_private: bool = False,
    extra_args: Optional[List[str]] = None,
) -> ScreenshotResult:
    """Note on scope: the SSRF guard below checks only the top-level URL
    passed in, same as probe.py/verify.py/fingerprint.py used to -- but
    unlike those (which now go through ssrf_guard.guarded_request() and
    re-check every redirect hop), this spawns a real rendering engine that
    follows redirects and loads subresources *itself*, entirely outside
    Python. A page that top-level-checks clean could still redirect, or
    embed a request via JS/CSS/img, to an internal address once
    wkhtmltoimage is driving it, and this check would not see it. Full
    protection against that would mean sandboxing/network-isolating the
    wkhtmltoimage process itself (e.g. run it in a container/netns with no
    route to internal ranges) -- an operational deployment concern, not
    something a URL check from the calling Python process can guarantee.
    Documented here rather than implied to be complete.

    Two things this function does do to narrow that gap: it refuses any
    URL whose scheme isn't http/https (so `file:///etc/passwd` can't reach
    the local filesystem through this path even with
    --allow-private-targets -- see ssrf_guard's module docstring for why
    that check is unconditional), and it always passes
    --disable-local-file-access to wkhtmltoimage itself as a second,
    independent layer, in case a redirect or a same-process quirk would
    otherwise let a page reference a local file. JS is deliberately left
    enabled by default (--javascript-delay above exists to let JS-rendered
    pages settle) -- disabling it would close the "page's own JS makes an
    internal request" sliver of this gap but at a real fidelity cost, so
    that tradeoff is left to the operator via `extra_args` rather than
    decided here.
    """
    if not is_available(binary):
        return ScreenshotResult(
            url=url, success=False,
            error=f"'{binary}' not found on PATH. Install wkhtmltopdf (provides wkhtmltoimage), "
                  f"e.g. `apt install wkhtmltopdf` / `brew install wkhtmltopdf`.",
        )

    allowed, reason = is_target_allowed(url, allow_private=allow_private)
    if not allowed:
        return ScreenshotResult(url=url, success=False, error=f"blocked (SSRF guard): {reason}")

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    filename = _safe_filename(url)
    out_path = out_dir / filename

    cmd = [
        binary, "--width", str(width), "--quiet", "--javascript-delay", "1000",
        "--disable-local-file-access",
        *(extra_args or []),  # e.g. ["--disable-javascript"] for operators who want that tradeoff
        url, str(out_path),
    ]

    try:
        proc = subprocess.run(cmd, capture_output=True, timeout=timeout)
    except subprocess.TimeoutExpired:
        return ScreenshotResult(url=url, success=False, error=f"Timed out after {timeout}s")
    except OSError as e:
        return ScreenshotResult(url=url, success=False, error=str(e))

    if proc.returncode != 0 or not out_path.exists():
        stderr = proc.stderr.decode("utf-8", errors="replace")[:200] if proc.stderr else "unknown error"
        return ScreenshotResult(url=url, success=False, error=stderr)

    return ScreenshotResult(url=url, success=True, path=str(out_path))


def capture_results(
    results: List[SearchResult], output_dir: str, binary: str = DEFAULT_BINARY,
    workers: int = 4, width: int = 1280, timeout: float = 20.0, progress_cb=None, allow_private: bool = False,
    extra_args: Optional[List[str]] = None,
) -> List[ScreenshotResult]:
    """Capture screenshots for a batch of results concurrently. `workers`
    defaults low (4) since each capture spawns a real browser-engine
    subprocess -- unlike the lightweight HTTP-only probe/verify/fingerprint
    steps, this is comparatively heavy per-item.

    `allow_private` plumbs through to the SSRF guard each capture checks
    first -- see capture_one's docstring for the scope of what that guard
    does and does not cover here specifically.
    """
    if not is_available(binary):
        # Fail fast with one clear message instead of N identical per-URL errors.
        return [
            ScreenshotResult(
                url=r.url, success=False,
                error=f"'{binary}' not found on PATH. Install wkhtmltopdf to enable screenshots.",
            )
            for r in results
        ]

    out = []
    total = len(results)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {
            pool.submit(capture_one, r.url, output_dir, binary, width, timeout, allow_private, extra_args): r
            for r in results
        }
        for i, future in enumerate(as_completed(futures), 1):
            try:
                out.append(future.result())
            except Exception as e:  # noqa: BLE001 -- one bad URL must not abort the whole pass
                out.append(ScreenshotResult(url=futures[future].url, success=False, error=f"internal error: {type(e).__name__}"))
            if progress_cb:
                progress_cb(i, total)

    order = {r.url: i for i, r in enumerate(results)}
    out.sort(key=lambda s: order.get(s.url, 0))
    return out

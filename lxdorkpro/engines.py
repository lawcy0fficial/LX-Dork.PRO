"""
Search engine backends for LX-Dork-Pro.

Three categories of backend, all sharing the same interface:

  - Official paid-tier APIs (no scraping, no ToS risk): Google Programmable
    Search, Bing Web Search API v7, Brave Search API.
  - Free SERP scraping (unofficial, no API key): SearXNG, DuckDuckGo,
    Google, Yandex, Mojeek, Startpage. Each is documented as such in its
    own class docstring below, including known fragility/rate-limit risk.
  - "Deep web" archival/intelligence sources (official free APIs, but keyed
    by domain rather than a free-text dork): Wayback Machine, Common
    Crawl, crt.sh certificate transparency, urlscan.io.

All engines expose the same interface:

    engine.search(query: str, count: int) -> list[SearchResult]
"""

from dataclasses import dataclass, field
from typing import List
import random
import re
import time
import json
import requests
from bs4 import BeautifulSoup
from urllib.parse import parse_qs, urlsplit

# Transient HTTP statuses worth retrying with backoff -- rate limiting and
# server-side hiccups, not things a retry can't fix (401/403/404 etc).
_RETRYABLE_STATUSES = {429, 500, 502, 503, 504}

# Rotate a small pool of realistic desktop user-agents for the no-key
# scraping engines (DuckDuckGo / Google). This isn't about hiding identity —
# it just avoids being trivially fingerprinted as a bare `python-requests`
# client, which gets you blocked on the very first request.
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:127.0) Gecko/20100101 Firefox/127.0",
]


def _random_headers():
    return {"User-Agent": random.choice(USER_AGENTS)}  # nosec B311 -- UA rotation for scraping evasion, not security/crypto-sensitive


def _build_proxies(cfg: dict):
    """Return a requests-style proxies dict if a proxy is configured, else None.

    Config can specify a single proxy string ('http_proxy') or a list to
    round-robin across ('proxy_pool'), which helps the no-key scraping
    engines avoid single-IP rate limiting.
    """
    pool = cfg.get("proxy_pool") or []
    single = cfg.get("http_proxy")
    proxy = random.choice(pool) if pool else single  # nosec B311 -- load-balancing pick from a config list, not security/crypto-sensitive
    if not proxy:
        return None
    return {"http": proxy, "https": proxy}


MAX_RETRY_WAIT = 60.0  # seconds; ceiling on any single retry sleep


def _parse_retry_after(value):
    """Retry-After is either delta-seconds or an HTTP-date (RFC 9110). Return
    seconds to wait, or None if absent/unparseable."""
    if not value:
        return None
    value = str(value).strip()
    try:
        return float(value)
    except ValueError:
        pass
    try:
        from email.utils import parsedate_to_datetime
        dt = parsedate_to_datetime(value)
        if dt.tzinfo is None:
            from datetime import timezone
            dt = dt.replace(tzinfo=timezone.utc)
        from datetime import datetime, timezone as _tz
        return max((dt - datetime.now(_tz.utc)).total_seconds(), 0.0)
    except (TypeError, ValueError):
        return None


def _request_with_retry(method: str, url: str, cfg: dict, max_retries: int = 3,
                         backoff_base: float = 1.0, **kwargs) -> requests.Response:
    """Thin wrapper around requests.get/post that retries transient failures
    (429/500/502/503/504, timeouts, connection errors) with exponential
    backoff + jitter, honoring a `Retry-After` header when the server sends
    one. Non-retryable errors (4xx other than 429, successful 2xx/3xx)
    return immediately. Raises the last exception if all retries are
    exhausted, or returns the final response if the server kept responding
    with a retryable status.

    `max_retries` and the backoff base can be overridden per-run via
    cfg['max_retries'] / cfg['retry_backoff_base'] so aggressive scraping
    engines can be tuned without touching call sites.
    """
    max_retries = cfg.get("max_retries", max_retries)
    backoff_base = cfg.get("retry_backoff_base", backoff_base)
    call = requests.get if method == "get" else requests.post
    # Optional per-engine pacing hook injected by the orchestrators
    # (cli._run_search / async_core). Called before EVERY HTTP attempt so
    # pagination and retries are paced too, not just a task's first request.
    throttle = cfg.get("_throttle")

    last_exc = None
    last_resp = None

    for attempt in range(max_retries + 1):
        if throttle:
            throttle()
        try:
            resp = call(url, **kwargs)
        except (requests.ConnectionError, requests.Timeout) as e:
            last_exc = e
            if attempt >= max_retries:
                raise
        else:
            if resp.status_code not in _RETRYABLE_STATUSES:
                return resp
            last_resp = resp
            if attempt >= max_retries:
                return resp  # exhausted -- let the caller handle the non-2xx status

        # Respect Retry-After if the server told us how long to wait.
        wait = None
        if last_resp is not None:
            wait = _parse_retry_after(last_resp.headers.get("Retry-After"))
        if wait is None:
            wait = backoff_base * (2 ** attempt) + random.uniform(0, 0.5)  # nosec B311 -- retry jitter timing, not security/crypto-sensitive

        # A server (hostile or just misconfigured) can send Retry-After: 86400.
        # Honour it up to a ceiling so one engine can't stall a worker for hours.
        time.sleep(min(max(wait, 0.0), cfg.get("max_retry_wait", MAX_RETRY_WAIT)))

    if last_exc:
        raise last_exc
    return last_resp


@dataclass
class SearchResult:
    url: str
    title: str = ""
    snippet: str = ""
    engine: str = ""
    source_query: str = ""  # which dork query produced this result -- used by verify.py
    also_seen_in: List[str] = field(default_factory=list)  # other engines that independently found this same URL -- populated by cli._run_search's dedup step, used by findings.py for corroboration scoring


class EngineError(Exception):
    """Raised when a backend fails (bad key, quota, network, etc.)."""


def _json_or_engine_error(resp):
    """resp.json() that fails as an EngineError. A 200 with an HTML
    captcha/maintenance/WAF page is routine; it must surface as one engine's
    error, not a ValueError traceback that aborts the whole scan."""
    try:
        return resp.json()
    except ValueError as e:
        raise EngineError("response was not valid JSON (blocked, captcha, or maintenance page?)") from e


class BaseEngine:
    name = "base"

    # The query ping() below sends to check connectivity/auth. Free-text
    # SERP engines are happy with any non-empty string; the domain-keyed
    # "deep web" engines (wayback/commoncrawl/crtsh/urlscan, below) are
    # not -- they parse the query for a site: operator or bare domain via
    # _domain_from_query() and raise EngineError for anything else, which
    # made `lxdorkpro doctor` report all four as DOWN even when perfectly
    # healthy, since "test" matches neither shape. Those four override
    # this with a real domain-shaped query instead of changing ping()
    # itself.
    PING_QUERY = "test"

    def __init__(self, cfg: dict, timeout: int = 10):
        self.cfg = cfg
        self.timeout = timeout

    def search(self, query: str, count: int) -> List[SearchResult]:
        raise NotImplementedError

    def ping(self) -> tuple:
        """Lightweight connectivity/health check used by `lxdorkpro doctor`.
        Returns (ok: bool, message: str).
        """
        try:
            results = self.search(self.PING_QUERY, 1)
            return True, f"OK ({len(results)} result(s))"
        except EngineError as e:
            return False, str(e)
        except Exception as e:  # noqa: BLE001 - surface any unexpected failure to the user
            return False, f"Unexpected error: {e}"


class GoogleEngine(BaseEngine):
    """Google Programmable Search Engine (Custom Search JSON API).

    Free tier: 100 queries/day. Each request returns up to 10 results,
    so we page through with the 'start' parameter to reach `count`.
    Requires: google_api_key + google_cx (Search engine ID) in config.
    """

    name = "google"
    ENDPOINT = "https://www.googleapis.com/customsearch/v1"

    def search(self, query: str, count: int) -> List[SearchResult]:
        api_key = self.cfg.get("google_api_key")
        cx = self.cfg.get("google_cx")
        if not api_key or not cx:
            raise EngineError("Google API key / CX not configured. Run: lxdorkpro configure")

        results: List[SearchResult] = []
        start = 1
        while len(results) < count and start <= 91:  # Google CSE caps at 100 results
            page_size = min(10, count - len(results))
            params = {
                "key": api_key,
                "cx": cx,
                "q": query,
                "num": page_size,
                "start": start,
            }
            try:
                resp = _request_with_retry("get", self.ENDPOINT, self.cfg, params=params, timeout=self.timeout)
            except requests.RequestException as e:
                raise EngineError(f"Google request failed: {e}") from e

            if resp.status_code != 200:
                raise EngineError(f"Google API error {resp.status_code}: {resp.text[:200]}")

            data = _json_or_engine_error(resp)
            items = data.get("items", [])
            if not items:
                break

            for item in items:
                results.append(
                    SearchResult(
                        url=item.get("link", ""),
                        title=item.get("title", ""),
                        snippet=item.get("snippet", ""),
                        engine=self.name,
                    )
                )
            start += page_size

        return results[:count]


class BingEngine(BaseEngine):
    """Bing Web Search API v7 (Microsoft Azure Cognitive Services).

    Requires: bing_api_key in config.
    """

    name = "bing"
    ENDPOINT = "https://api.bing.microsoft.com/v7.0/search"

    def search(self, query: str, count: int) -> List[SearchResult]:
        api_key = self.cfg.get("bing_api_key")
        if not api_key:
            raise EngineError("Bing API key not configured. Run: lxdorkpro configure")

        results: List[SearchResult] = []
        offset = 0
        headers = {"Ocp-Apim-Subscription-Key": api_key}

        while len(results) < count and offset < 200:
            page_size = min(50, count - len(results))
            params = {"q": query, "count": page_size, "offset": offset, "textDecorations": False}
            try:
                resp = _request_with_retry(
                    "get", self.ENDPOINT, self.cfg, headers=headers, params=params, timeout=self.timeout
                )
            except requests.RequestException as e:
                raise EngineError(f"Bing request failed: {e}") from e

            if resp.status_code != 200:
                raise EngineError(f"Bing API error {resp.status_code}: {resp.text[:200]}")

            data = _json_or_engine_error(resp)
            web_pages = data.get("webPages", {})
            items = web_pages.get("value", [])
            if not items:
                break

            for item in items:
                results.append(
                    SearchResult(
                        url=item.get("url", ""),
                        title=item.get("name", ""),
                        snippet=item.get("snippet", ""),
                        engine=self.name,
                    )
                )
            offset += page_size

        return results[:count]


class BraveEngine(BaseEngine):
    """Brave Search API.

    Requires: brave_api_key in config.
    """

    name = "brave"
    ENDPOINT = "https://api.search.brave.com/res/v1/web/search"

    def search(self, query: str, count: int) -> List[SearchResult]:
        api_key = self.cfg.get("brave_api_key")
        if not api_key:
            raise EngineError("Brave API key not configured. Run: lxdorkpro configure")

        results: List[SearchResult] = []
        offset = 0
        headers = {"Accept": "application/json", "X-Subscription-Token": api_key}

        while len(results) < count and offset < 9:  # Brave paginates in pages of ~20, max ~9 pages
            page_size = min(20, count - len(results))
            params = {"q": query, "count": page_size, "offset": offset}
            try:
                resp = _request_with_retry(
                    "get", self.ENDPOINT, self.cfg, headers=headers, params=params, timeout=self.timeout
                )
            except requests.RequestException as e:
                raise EngineError(f"Brave request failed: {e}") from e

            if resp.status_code != 200:
                raise EngineError(f"Brave API error {resp.status_code}: {resp.text[:200]}")

            data = _json_or_engine_error(resp)
            items = data.get("web", {}).get("results", [])
            if not items:
                break

            for item in items:
                results.append(
                    SearchResult(
                        url=item.get("url", ""),
                        title=item.get("title", ""),
                        snippet=item.get("description", ""),
                        engine=self.name,
                    )
                )
            offset += 1

        return results[:count]


class SearxngEngine(BaseEngine):
    """SearXNG — open-source meta search engine. FREE, no API key.

    Aggregates results from Google, Bing, Brave, DuckDuckGo, Yandex, etc.
    behind a single JSON endpoint, so this one engine effectively gives you
    multi-engine coverage. Works with either:
      - the bundled Docker setup (recommended — JSON API pre-enabled):
        docker compose up -d searxng   (see this repo's docker-compose.yml)
      - a public instance URL from https://searx.space (best-effort;
        some public instances disable the JSON API for abuse prevention)

    Configure via `searxng_url` in config, or LXDORK_SEARXNG_URL env var.
    Defaults to http://localhost:8888 (a local self-hosted instance).
    """

    name = "searxng"

    def search(self, query: str, count: int) -> List[SearchResult]:
        base_url = (self.cfg.get("searxng_url") or "http://localhost:8888").rstrip("/")
        results: List[SearchResult] = []
        page = 1

        while len(results) < count and page <= 10:
            params = {"q": query, "format": "json", "pageno": page}
            try:
                resp = _request_with_retry(
                    "get", f"{base_url}/search", self.cfg, params=params, headers=_random_headers(),
                    proxies=_build_proxies(self.cfg), timeout=self.timeout
                )
            except requests.RequestException as e:
                raise EngineError(
                    f"SearXNG request failed ({base_url}): {e}. "
                    "Start it with: docker compose up -d searxng"
                ) from e

            if resp.status_code != 200:
                raise EngineError(f"SearXNG error {resp.status_code} from {base_url}: {resp.text[:200]}")

            try:
                data = resp.json()
            except ValueError as e:
                raise EngineError(
                    f"SearXNG at {base_url} didn't return JSON — its JSON API may be disabled on this instance."
                ) from e

            items = data.get("results", [])
            if not items:
                break

            for item in items:
                results.append(
                    SearchResult(
                        url=item.get("url", ""),
                        title=item.get("title", ""),
                        snippet=item.get("content", ""),
                        engine=self.name,
                    )
                )
            page += 1

        return results[:count]


def _unwrap_ddg_href(href: str) -> str:
    """DuckDuckGo's HTML endpoint wraps result links as
    //duckduckgo.com/l/?uddg=<percent-encoded real URL>&rut=<token>. Return
    the real URL; leave anything else untouched. Returns "" for ad
    redirects (/y.js), which aren't organic results.
    """
    if href.startswith("//"):
        href = "https:" + href
    elif href.startswith("/"):
        href = "https://duckduckgo.com" + href
    try:
        parts = urlsplit(href)
    except ValueError:
        return href
    host = (parts.hostname or "").lower()
    if host == "duckduckgo.com" or host.endswith(".duckduckgo.com"):
        if parts.path.rstrip("/") == "/l":
            target = parse_qs(parts.query).get("uddg")
            if target:
                return target[0]
        if parts.path.startswith("/y.js"):
            return ""
    return href


class DuckDuckGoEngine(BaseEngine):
    """DuckDuckGo HTML endpoint — FREE, no API key.

    Unofficial (there's no public DDG API for web results), but the
    lightweight html.duckduckgo.com/html/ endpoint is commonly used by
    open-source recon tools and is far less aggressive about blocking
    than Google. Layout could change without notice since it's unofficial.
    """

    name = "duckduckgo"
    ENDPOINT = "https://html.duckduckgo.com/html/"

    def search(self, query: str, count: int) -> List[SearchResult]:
        results: List[SearchResult] = []
        params = {"q": query}

        try:
            resp = _request_with_retry(
                "post", self.ENDPOINT, self.cfg, data=params, headers=_random_headers(),
                proxies=_build_proxies(self.cfg), timeout=self.timeout
            )
        except requests.RequestException as e:
            raise EngineError(f"DuckDuckGo request failed: {e}") from e

        if resp.status_code != 200:
            raise EngineError(f"DuckDuckGo error {resp.status_code}")

        soup = BeautifulSoup(resp.text, "html.parser")
        for link in soup.select("a.result__a"):
            href = _unwrap_ddg_href(link.get("href", ""))
            title = link.get_text(strip=True)
            snippet_tag = link.find_parent("div", class_="result")
            snippet = ""
            if snippet_tag:
                snippet_el = snippet_tag.select_one(".result__snippet")
                snippet = snippet_el.get_text(strip=True) if snippet_el else ""
            if href:
                results.append(SearchResult(url=href, title=title, snippet=snippet, engine=self.name))
            if len(results) >= count:
                break

        return results[:count]


def _extract_generic_links(soup: BeautifulSoup, exclude_domains: List[str], limit: int) -> List[SearchResult]:
    """Fallback link extraction used when an engine's known CSS selectors
    find nothing -- likely because the site's markup changed. Grabs any
    <a href="http..."> not pointing back at the search engine's own domain
    (nav links, "settings", "about", etc.), which degrades gracefully
    instead of returning zero results the moment a selector goes stale.
    Titles come from the link text itself, which is cruder than a proper
    selector but still usable.
    """
    seen_urls = set()
    out: List[SearchResult] = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if not href.startswith("http"):
            continue
        if any(domain in href for domain in exclude_domains):
            continue
        if href in seen_urls:
            continue
        title = a.get_text(strip=True)
        if not title:
            continue  # bare icon/image links with no text are almost never real results
        seen_urls.add(href)
        out.append(SearchResult(url=href, title=title, snippet="", engine=""))
        if len(out) >= limit:
            break
    return out


class GoogleScrapeEngine(BaseEngine):
    """Direct Google SERP scraping — FREE, no API key.

    Same approach used by popular open-source dork tools (pagodo,
    dorks-eye). Google actively rate-limits and CAPTCHAs automated
    traffic, so this engine is the least reliable of the bunch — use a
    generous --delay (2-5s+) and expect occasional temporary blocks.
    For heavy/production use, prefer SearXNG or the official Custom
    Search API instead.
    """

    name = "google-scrape"
    ENDPOINT = "https://www.google.com/search"

    def search(self, query: str, count: int) -> List[SearchResult]:
        results: List[SearchResult] = []
        start = 0

        while len(results) < count and start < 100:
            params = {"q": query, "num": 10, "start": start, "hl": "en"}
            try:
                resp = _request_with_retry(
                    "get", self.ENDPOINT, self.cfg, params=params, headers=_random_headers(),
                    proxies=_build_proxies(self.cfg), timeout=self.timeout
                )
            except requests.RequestException as e:
                raise EngineError(f"Google scrape request failed: {e}") from e

            if resp.status_code == 429:
                raise EngineError("Google is rate-limiting/CAPTCHA-blocking this IP. Increase --delay and retry later.")
            if resp.status_code != 200:
                raise EngineError(f"Google scrape error {resp.status_code}")

            soup = BeautifulSoup(resp.text, "html.parser")
            blocks = soup.select("div.g")
            if not blocks:
                break

            for block in blocks:
                a_tag = block.select_one("a")
                h3_tag = block.select_one("h3")
                if not a_tag or not a_tag.get("href", "").startswith("http"):
                    continue
                snippet_el = block.select_one("div[data-sncf], .VwiC3b, .IsZvec")
                results.append(
                    SearchResult(
                        url=a_tag["href"],
                        title=h3_tag.get_text(strip=True) if h3_tag else "",
                        snippet=snippet_el.get_text(strip=True) if snippet_el else "",
                        engine=self.name,
                    )
                )
                if len(results) >= count:
                    break

            start += 10

        return results[:count]


class YandexEngine(BaseEngine):
    """Yandex SERP scraping — FREE, no API key.

    Unofficial. Yandex's markup changes periodically, so this tries known
    result-item selectors first, then falls back to generic link extraction
    if those find nothing (see _extract_generic_links).
    """

    name = "yandex"
    ENDPOINT = "https://yandex.com/search/"

    def search(self, query: str, count: int) -> List[SearchResult]:
        results: List[SearchResult] = []
        page = 0

        while len(results) < count and page < 10:
            params = {"text": query, "p": page}
            try:
                resp = _request_with_retry(
                    "get", self.ENDPOINT, self.cfg, params=params, headers=_random_headers(),
                    proxies=_build_proxies(self.cfg), timeout=self.timeout
                )
            except requests.RequestException as e:
                raise EngineError(f"Yandex request failed: {e}") from e

            if resp.status_code == 429:
                raise EngineError("Yandex is rate-limiting/CAPTCHA-blocking this IP. Increase --delay and retry later.")
            if resp.status_code != 200:
                raise EngineError(f"Yandex error {resp.status_code}")

            soup = BeautifulSoup(resp.text, "html.parser")
            blocks = soup.select("li.serp-item")
            page_results = []

            if blocks:
                for block in blocks:
                    a_tag = block.select_one("a.OrganicTitle-Link, a[href^='http']")
                    if not a_tag or not a_tag.get("href", "").startswith("http"):
                        continue
                    snippet_el = block.select_one(".OrganicText, .Organic-Text")
                    page_results.append(
                        SearchResult(
                            url=a_tag["href"],
                            title=a_tag.get_text(strip=True),
                            snippet=snippet_el.get_text(strip=True) if snippet_el else "",
                            engine=self.name,
                        )
                    )
            if not page_results:
                # Selectors likely stale -- degrade gracefully instead of erroring out.
                fallback = _extract_generic_links(soup, exclude_domains=["yandex."], limit=count - len(results))
                for r in fallback:
                    r.engine = self.name
                page_results = fallback

            if not page_results:
                break

            results.extend(page_results)
            page += 1

        return results[:count]


class MojeekEngine(BaseEngine):
    """Mojeek SERP scraping — FREE, no API key.

    Mojeek is a small independent index that's historically been more
    tolerant of light automated use than Google/Bing, though this is still
    unofficial scraping, not a documented API -- treat it accordingly
    (reasonable --delay, don't hammer it).
    """

    name = "mojeek"
    ENDPOINT = "https://www.mojeek.com/search"

    def search(self, query: str, count: int) -> List[SearchResult]:
        results: List[SearchResult] = []
        start = 0

        while len(results) < count and start < 100:
            params = {"q": query, "s": start}
            try:
                resp = _request_with_retry(
                    "get", self.ENDPOINT, self.cfg, params=params, headers=_random_headers(),
                    proxies=_build_proxies(self.cfg), timeout=self.timeout
                )
            except requests.RequestException as e:
                raise EngineError(f"Mojeek request failed: {e}") from e

            if resp.status_code != 200:
                raise EngineError(f"Mojeek error {resp.status_code}")

            soup = BeautifulSoup(resp.text, "html.parser")
            blocks = soup.select("ul.results-standard > li, li.result")
            page_results = []

            if blocks:
                for block in blocks:
                    a_tag = block.select_one("a.title, a[href^='http']")
                    if not a_tag or not a_tag.get("href", "").startswith("http"):
                        continue
                    snippet_el = block.select_one("p.s, .s")
                    page_results.append(
                        SearchResult(
                            url=a_tag["href"],
                            title=a_tag.get_text(strip=True),
                            snippet=snippet_el.get_text(strip=True) if snippet_el else "",
                            engine=self.name,
                        )
                    )
            if not page_results:
                fallback = _extract_generic_links(soup, exclude_domains=["mojeek.com"], limit=count - len(results))
                for r in fallback:
                    r.engine = self.name
                page_results = fallback

            if not page_results:
                break

            results.extend(page_results)
            start += 10

        return results[:count]


class StartpageEngine(BaseEngine):
    """Startpage SERP scraping — FREE, no API key.

    Startpage proxies Google results with added privacy protections.
    Unofficial scraping -- markup can change without notice, hence the
    generic-link fallback like the other scraping engines here.
    """

    name = "startpage"
    ENDPOINT = "https://www.startpage.com/sp/search"

    def search(self, query: str, count: int) -> List[SearchResult]:
        results: List[SearchResult] = []
        page = 1

        while len(results) < count and page <= 10:
            params = {"query": query, "page": page}
            try:
                resp = _request_with_retry(
                    "get", self.ENDPOINT, self.cfg, params=params, headers=_random_headers(),
                    proxies=_build_proxies(self.cfg), timeout=self.timeout
                )
            except requests.RequestException as e:
                raise EngineError(f"Startpage request failed: {e}") from e

            if resp.status_code != 200:
                raise EngineError(f"Startpage error {resp.status_code}")

            soup = BeautifulSoup(resp.text, "html.parser")
            blocks = soup.select(".w-gl__result, .result")
            page_results = []

            if blocks:
                for block in blocks:
                    a_tag = block.select_one("a.w-gl__result-title, a[href^='http']")
                    if not a_tag or not a_tag.get("href", "").startswith("http"):
                        continue
                    snippet_el = block.select_one(".w-gl__description, .description")
                    page_results.append(
                        SearchResult(
                            url=a_tag["href"],
                            title=a_tag.get_text(strip=True),
                            snippet=snippet_el.get_text(strip=True) if snippet_el else "",
                            engine=self.name,
                        )
                    )
            if not page_results:
                fallback = _extract_generic_links(soup, exclude_domains=["startpage.com"], limit=count - len(results))
                for r in fallback:
                    r.engine = self.name
                page_results = fallback

            if not page_results:
                break

            results.extend(page_results)
            page += 1

        return results[:count]


# ---------------------------------------------------------------------------
# "Deep web" archival / intelligence sources.
#
# Unlike the SERP engines above, these don't take a free-text dork string --
# they index historical crawl data, certificate transparency logs, or scan
# submissions keyed by DOMAIN. They still accept whatever query string the
# rest of the pipeline gives them (so presets like `site:{target}...` keep
# working transparently), but only the domain actually matters: everything
# else in the query is ignored. This surfaces URLs that live/current SERP
# scraping can't: pages removed after being crawled, subdomains that were
# never linked anywhere public, historical snapshots, etc.
# ---------------------------------------------------------------------------

# A certificate name we're willing to turn into https://<host>. crt.sh's
# name_value also carries email SANs (user@host) and other non-hostnames.
_CERT_HOST_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)+$", re.IGNORECASE)

_SITE_OP_RE = re.compile(r"site:(\S+)", re.IGNORECASE)
_BARE_DOMAIN_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$", re.IGNORECASE)


def _domain_from_query(query: str) -> str:
    """Extract a bare domain from a dork-style query for the archival
    engines below. Prefers a `site:` operator's value; falls back to
    treating the whole query as a domain if it looks like one on its own.
    Raises EngineError if no usable domain can be found.
    """
    m = _SITE_OP_RE.search(query)
    if m:
        return m.group(1).lstrip("*.")
    stripped = query.strip()
    if _BARE_DOMAIN_RE.match(stripped):
        return stripped
    raise EngineError(
        f"This engine needs a domain to look up (e.g. 'site:example.com' or just 'example.com'), "
        f"got: '{query}'"
    )


class WaybackEngine(BaseEngine):
    """Wayback Machine (archive.org) CDX API — FREE, no key, official API.

    Searches the Internet Archive's index of every URL it has ever crawled
    for a domain, including pages long since removed from the live site.
    Genuinely finds things current SERP scraping cannot.
    """

    name = "wayback"
    ENDPOINT = "http://web.archive.org/cdx/search/cdx"
    PING_QUERY = "site:example.com"  # domain-keyed engine -- see BaseEngine.PING_QUERY

    def search(self, query: str, count: int) -> List[SearchResult]:
        domain = _domain_from_query(query)
        params = {
            "url": f"{domain}/*",
            "output": "json",
            "collapse": "urlkey",
            "limit": count,
            "fl": "original,timestamp,statuscode",
        }
        try:
            resp = _request_with_retry("get", self.ENDPOINT, self.cfg, params=params, timeout=self.timeout)
        except requests.RequestException as e:
            raise EngineError(f"Wayback Machine request failed: {e}") from e

        if resp.status_code != 200:
            raise EngineError(f"Wayback Machine error {resp.status_code}")

        try:
            rows = resp.json()
        except ValueError:
            return []  # empty result set comes back as "" (not valid JSON), not an error

        if not rows or len(rows) < 2:
            return []  # first row is the header; no data rows means no archives found

        results = []
        for row in rows[1:]:
            original_url = row[0] if len(row) > 0 else ""
            timestamp = row[1] if len(row) > 1 else ""
            status = row[2] if len(row) > 2 else ""
            if not original_url:
                continue
            results.append(
                SearchResult(
                    url=original_url,
                    title=f"Archived {timestamp}" if timestamp else "Archived snapshot",
                    snippet=f"HTTP {status} at time of crawl" if status else "",
                    engine=self.name,
                )
            )
        return results[:count]


class CommonCrawlEngine(BaseEngine):
    """Common Crawl CDX API — FREE, no key, official API.

    Common Crawl publishes a URL index for every one of its petabyte-scale
    web crawls. Resolves the most recent crawl index dynamically (cached
    per-process) since Common Crawl retires old ones periodically.
    """

    name = "commoncrawl"
    COLLINFO_URL = "https://index.commoncrawl.org/collinfo.json"
    PING_QUERY = "site:example.com"  # domain-keyed engine -- see BaseEngine.PING_QUERY
    _cached_cdx_api = None  # class-level cache: resolved once per process

    def _get_latest_cdx_api(self) -> str:
        if CommonCrawlEngine._cached_cdx_api:
            return CommonCrawlEngine._cached_cdx_api
        try:
            resp = _request_with_retry("get", self.COLLINFO_URL, self.cfg, timeout=self.timeout)
        except requests.RequestException as e:
            raise EngineError(f"Common Crawl index lookup failed: {e}") from e
        if resp.status_code != 200:
            raise EngineError(f"Common Crawl index lookup error {resp.status_code}")
        collections = _json_or_engine_error(resp)
        if not collections:
            raise EngineError("Common Crawl returned no available crawl indexes")
        try:
            CommonCrawlEngine._cached_cdx_api = collections[0]["cdx-api"]
        except (KeyError, IndexError, TypeError) as e:
            raise EngineError("Common Crawl index list had an unexpected shape") from e
        return CommonCrawlEngine._cached_cdx_api

    def search(self, query: str, count: int) -> List[SearchResult]:
        domain = _domain_from_query(query)
        cdx_api = self._get_latest_cdx_api()
        params = {"url": f"{domain}/*", "output": "json", "limit": count}
        try:
            resp = _request_with_retry("get", cdx_api, self.cfg, params=params, timeout=self.timeout)
        except requests.RequestException as e:
            raise EngineError(f"Common Crawl request failed: {e}") from e

        if resp.status_code == 404:
            return []  # no captures found for this domain in the current index
        if resp.status_code != 200:
            raise EngineError(f"Common Crawl error {resp.status_code}")

        results = []
        for line in resp.text.strip().splitlines():
            if not line:
                continue
            try:
                record = json.loads(line)
            except ValueError:
                continue
            url = record.get("url", "")
            if not url:
                continue
            results.append(
                SearchResult(
                    url=url,
                    title=f"Common Crawl {record.get('timestamp', '')}".strip(),
                    snippet=f"status {record.get('status')}" if record.get("status") else "",
                    engine=self.name,
                )
            )
        return results[:count]


class CrtShEngine(BaseEngine):
    """crt.sh certificate transparency search — FREE, no key, official API.

    Searches public Certificate Transparency logs for certificates issued
    to a domain and its subdomains -- a standard, highly effective way to
    discover subdomains that were never linked anywhere public, since every
    publicly-trusted TLS certificate is logged whether or not the site is
    ever crawled by a search engine.
    """

    name = "crtsh"
    ENDPOINT = "https://crt.sh/"
    PING_QUERY = "site:example.com"  # domain-keyed engine -- see BaseEngine.PING_QUERY

    def search(self, query: str, count: int) -> List[SearchResult]:
        domain = _domain_from_query(query)
        params = {"q": f"%.{domain}", "output": "json"}
        try:
            resp = _request_with_retry("get", self.ENDPOINT, self.cfg, params=params, timeout=self.timeout)
        except requests.RequestException as e:
            raise EngineError(f"crt.sh request failed: {e}") from e

        if resp.status_code != 200:
            raise EngineError(f"crt.sh error {resp.status_code}")

        try:
            entries = resp.json()
        except ValueError:
            return []  # crt.sh returns an empty body (not valid JSON) when nothing matches

        seen_hosts = set()
        results = []
        for entry in entries:
            raw_names = entry.get("name_value", "")
            for host in raw_names.split("\n"):
                host = host.strip().lstrip("*.").lower()
                if not host or host in seen_hosts or not _CERT_HOST_RE.match(host):
                    continue
                seen_hosts.add(host)
                results.append(
                    SearchResult(
                        url=f"https://{host}",
                        title=f"Certificate: {host}",
                        snippet=f"Issuer: {entry.get('issuer_name', '?')}",
                        engine=self.name,
                    )
                )
                if len(results) >= count:
                    return results
        return results


class UrlscanEngine(BaseEngine):
    """urlscan.io public search API — FREE, no key required for search.

    Searches millions of publicly submitted URL scans (screenshots, DOM
    snapshots, requests made) for a domain -- surfaces live pages along
    with metadata about what they actually loaded at scan time.
    """

    name = "urlscan"
    ENDPOINT = "https://urlscan.io/api/v1/search/"
    PING_QUERY = "site:example.com"  # domain-keyed engine -- see BaseEngine.PING_QUERY

    def search(self, query: str, count: int) -> List[SearchResult]:
        domain = _domain_from_query(query)
        params = {"q": f"domain:{domain}", "size": min(count, 100)}
        try:
            resp = _request_with_retry("get", self.ENDPOINT, self.cfg, params=params, timeout=self.timeout)
        except requests.RequestException as e:
            raise EngineError(f"urlscan.io request failed: {e}") from e

        if resp.status_code == 429:
            raise EngineError("urlscan.io is rate-limiting this IP. Increase --delay and retry later.")
        if resp.status_code != 200:
            raise EngineError(f"urlscan.io error {resp.status_code}")

        data = _json_or_engine_error(resp)
        results = []
        for item in data.get("results", []):
            page = item.get("page", {})
            url = page.get("url", "")
            if not url:
                continue
            scan_time = item.get("task", {}).get("time", "")
            results.append(
                SearchResult(
                    url=url,
                    title=f"Scanned {scan_time}" if scan_time else "urlscan.io result",
                    snippet=f"IP: {page.get('ip', '?')}  Server: {page.get('server', '?')}",
                    engine=self.name,
                )
            )
            if len(results) >= count:
                break
        return results


ENGINE_REGISTRY = {
    "google": GoogleEngine,
    "bing": BingEngine,
    "brave": BraveEngine,
    "searxng": SearxngEngine,
    "duckduckgo": DuckDuckGoEngine,
    "google-scrape": GoogleScrapeEngine,
    "yandex": YandexEngine,
    "mojeek": MojeekEngine,
    "startpage": StartpageEngine,
    "wayback": WaybackEngine,
    "commoncrawl": CommonCrawlEngine,
    "crtsh": CrtShEngine,
    "urlscan": UrlscanEngine,
}

FREE_NO_KEY_ENGINES = [
    "searxng", "duckduckgo", "google-scrape", "yandex", "mojeek", "startpage",
    "wayback", "commoncrawl", "crtsh", "urlscan",
]
DEEP_WEB_ENGINES = ["wayback", "commoncrawl", "crtsh", "urlscan"]
API_KEY_ENGINES = ["google", "bing", "brave"]


def get_engine(name: str, cfg: dict, timeout: int = 10) -> BaseEngine:
    cls = ENGINE_REGISTRY.get(name)
    if cls is None:
        raise EngineError(f"Unknown engine: {name}")
    return cls(cfg, timeout=timeout)

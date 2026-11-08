"""
Tech fingerprinting: detect the CMS, web server, language, JS framework,
and CDN/security posture of a discovered URL from its HTTP response --
lightweight, Wappalyzer-style signature matching rather than a full browser.

Each signature is a set of independent indicators; any one matching is
enough to report the technology, with the matched indicator kept as
evidence so results are auditable rather than a black box.
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from typing import List, Optional
import re
import random

import requests
from requests.structures import CaseInsensitiveDict
from bs4 import BeautifulSoup

from .engines import USER_AGENTS, SearchResult
from .ssrf_guard import SSRFGuardError, guarded_request


@dataclass
class Detection:
    name: str
    category: str
    evidence: str


@dataclass
class FingerprintResult:
    url: str
    detections: List[Detection] = field(default_factory=list)
    server_header: str = ""
    powered_by_header: str = ""
    error: str = ""

    @property
    def technologies(self) -> List[str]:
        return [d.name for d in self.detections]


# Each signature: name, category, and a list of (kind, pattern) indicators.
# kind is one of: "header:<HeaderName>", "html", "meta:<name>", "cookie".
# Patterns are matched case-insensitively as substrings/regex.
SIGNATURES = [
    # --- CMS ---
    ("WordPress", "cms", [
        ("html", r"wp-content|wp-includes"),
        ("meta:generator", r"wordpress"),
        ("header:Link", r"wp-json"),
    ]),
    ("Joomla", "cms", [
        ("html", r"/media/jui/|/components/com_"),
        ("meta:generator", r"joomla"),
    ]),
    ("Drupal", "cms", [
        ("html", r"sites/default/files|drupal\.settings"),
        ("meta:generator", r"drupal"),
        ("header:X-Generator", r"drupal"),
    ]),
    ("Magento", "cms", [
        ("html", r"/skin/frontend/|Mage\.Cookies"),
        ("cookie", r"frontend=|adminhtml="),
    ]),
    ("Shopify", "cms", [
        ("html", r"cdn\.shopify\.com|Shopify\.theme"),
        ("header:X-Shopify-Stage", r".*"),
    ]),
    ("Wix", "cms", [
        ("html", r"wixstatic\.com"),
        ("header:X-Wix-Request-Id", r".*"),
    ]),
    ("Squarespace", "cms", [
        ("html", r"static1\.squarespace\.com|squarespace-cdn\.com|assets\.squarespace\.com"),
        ("meta:generator", r"squarespace"),
    ]),
    ("Ghost", "cms", [
        ("meta:generator", r"ghost"),
        ("html", r"ghost-sdk|/ghost/api/|ghost-portal"),
    ]),

    # --- JS frameworks ---
    ("React", "javascript-framework", [
        ("html", r"react\.production|react-dom|data-reactroot|__NEXT_DATA__"),
    ]),
    ("Next.js", "javascript-framework", [
        ("html", r"__NEXT_DATA__|/_next/static"),
    ]),
    ("Vue.js", "javascript-framework", [
        ("html", r"vue\.js|__vue__|data-v-"),
    ]),
    ("Angular", "javascript-framework", [
        ("html", r"ng-version|angular\.js|ng-app"),
    ]),
    ("jQuery", "javascript-library", [
        ("html", r"jquery(\.min)?\.js"),
    ]),
    ("Bootstrap", "css-framework", [
        ("html", r"bootstrap(\.min)?\.css|bootstrap(\.min)?\.js"),
    ]),
    ("Tailwind CSS", "css-framework", [
        ("html", r"tailwind(\.min)?\.css|tailwindcss"),
    ]),

    # --- server / language ---
    ("nginx", "web-server", [("header:Server", r"nginx")]),
    ("Apache", "web-server", [("header:Server", r"apache")]),
    ("Microsoft IIS", "web-server", [("header:Server", r"microsoft-iis")]),
    ("LiteSpeed", "web-server", [("header:Server", r"litespeed")]),
    ("PHP", "language", [("header:X-Powered-By", r"php")]),
    ("ASP.NET", "language", [
        ("header:X-Powered-By", r"asp\.net"),
        ("header:X-AspNet-Version", r".*"),
    ]),
    ("Express (Node.js)", "language", [("header:X-Powered-By", r"express")]),
    ("Django", "language", [("cookie", r"csrftoken|django")]),
    ("Laravel", "language", [("cookie", r"laravel_session")]),
    ("Ruby on Rails", "language", [
        ("header:X-Powered-By", r"phusion passenger"),
        ("cookie", r"_rails_session"),
    ]),

    # --- CDN / infra ---
    ("Cloudflare", "cdn", [
        ("header:Server", r"cloudflare"),
        ("header:CF-Ray", r".*"),
    ]),
    ("Amazon CloudFront", "cdn", [("header:X-Amz-Cf-Id", r".*"), ("header:Via", r"cloudfront")]),
    ("Fastly", "cdn", [("header:X-Served-By", r"cache-"), ("header:Via", r"fastly")]),

    # --- analytics ---
    ("Google Analytics", "analytics", [("html", r"google-analytics\.com/analytics\.js|gtag\(")]),
    ("Google Tag Manager", "analytics", [("html", r"googletagmanager\.com")]),

    # --- more CMS / commerce / static-site generators ---
    ("TYPO3", "cms", [("html", r"typo3conf/|typo3temp/"), ("meta:generator", r"typo3")]),
    ("Craft CMS", "cms", [("header:X-Powered-By", r"craft cms")]),
    ("Strapi", "cms", [("header:X-Powered-By", r"strapi")]),
    ("PrestaShop", "ecommerce", [("meta:generator", r"prestashop"), ("html", r"/modules/ps_[a-z]+/")]),
    ("BigCommerce", "ecommerce", [("html", r"cdn\d*\.bigcommerce\.com")]),
    ("Webflow", "cms", [("html", r"data-wf-(?:page|site)=")]),
    ("Gatsby", "static-site", [("meta:generator", r"gatsby")]),
    ("Hugo", "static-site", [("meta:generator", r"^hugo\b")]),
    ("Jekyll", "static-site", [("meta:generator", r"jekyll")]),

    # --- more JS frameworks ---
    ("Nuxt.js", "javascript-framework", [("html", r"window\.__NUXT__|/_nuxt/")]),
    ("SvelteKit", "javascript-framework", [("html", r"__sveltekit_|/_app/immutable/")]),
    ("htmx", "javascript-library", [("html", r"htmx(?:\.min)?\.js|\bhx-(?:get|post|trigger)=")]),

    # --- servers, proxies and app servers ---
    ("Caddy", "web-server", [("header:Server", r"^caddy")]),
    ("Envoy", "web-server", [("header:Server", r"^envoy$")]),
    ("OpenResty", "web-server", [("header:Server", r"openresty")]),
    ("Apache Tomcat", "web-server", [("header:Server", r"apache-coyote|tomcat"), ("html", r"<title>Apache Tomcat/")]),
    ("Jetty", "web-server", [("header:Server", r"jetty")]),
    ("Gunicorn", "web-server", [("header:Server", r"gunicorn")]),
    ("Uvicorn", "web-server", [("header:Server", r"uvicorn")]),
    ("Werkzeug (Flask)", "web-server", [("header:Server", r"werkzeug")]),
    ("Kestrel", "web-server", [("header:Server", r"kestrel")]),
    ("Phusion Passenger", "web-server", [("header:X-Powered-By", r"phusion passenger")]),
    ("Varnish", "cdn", [("header:Via", r"varnish"), ("header:X-Varnish", r".+")]),
    ("Akamai", "cdn", [("header:Server", r"akamaighost|akamainetstorage"), ("header:X-Akamai-Transformed", r".+")]),
    ("Vercel", "cdn", [("header:Server", r"^vercel$"), ("header:X-Vercel-Id", r".+")]),
    ("Netlify", "cdn", [("header:Server", r"^netlify$"), ("header:X-Nf-Request-Id", r".+")]),
    ("Heroku", "paas", [("header:Via", r"heroku-router")]),
    ("GitHub Pages", "paas", [("header:Server", r"^github\.com$")]),
    ("AWS Elastic Load Balancer", "cdn", [("header:Server", r"awselb"), ("cookie", r"AWSALB(?:CORS)?=")]),
    ("Azure (App Service/Front Door)", "cdn", [("header:X-Azure-Ref", r".+"), ("header:X-Ms-Request-Id", r".+")]),
    ("Sucuri WAF", "waf", [("header:Server", r"sucuri"), ("header:X-Sucuri-Id", r".+")]),
    ("Imperva Incapsula", "waf", [("cookie", r"incap_ses_|visid_incap_"), ("header:X-Iinfo", r".+")]),
    ("F5 BIG-IP", "waf", [("cookie", r"BIGipServer")]),

    # --- more back-end frameworks (cookie names are the reliable tell) ---
    ("Java (JSESSIONID)", "language", [("cookie", r"JSESSIONID=")]),
    ("ASP.NET MVC", "language", [("header:X-AspNetMvc-Version", r".+")]),
    ("Symfony", "language", [("header:X-Debug-Token", r".+"), ("cookie", r"sf_redirect=")]),
    ("CodeIgniter", "language", [("cookie", r"ci_session=")]),
    ("CakePHP", "language", [("cookie", r"CAKEPHP=")]),
    ("Yii", "language", [("cookie", r"YII_CSRF_TOKEN=|_csrf-frontend=")]),
]


def fingerprint_one(url_or_result, timeout: float = 8.0, allow_private: bool = False, cache=None) -> FingerprintResult:
    """Fetch a URL and match it against the signature database. Accepts
    either a raw URL string or a SearchResult (uses its .url).
    """
    url = url_or_result.url if isinstance(url_or_result, SearchResult) else url_or_result

    headers = {"User-Agent": random.choice(USER_AGENTS)}  # nosec B311 -- UA rotation for scraping evasion, not security/crypto-sensitive

    try:
        if cache is not None:
            resp = cache.get(url, timeout, allow_private)
        else:
            resp = guarded_request("GET", url, headers=headers, timeout=timeout, allow_private=allow_private)
    except SSRFGuardError as e:
        return FingerprintResult(url=url, error=f"blocked (SSRF guard): {e.reason}")
    except requests.RequestException as e:
        return FingerprintResult(url=url, error=type(e).__name__)

    html = resp.text if isinstance(resp.text, str) else ""
    # Case-insensitive: servers send "CF-RAY"/"cf-ray"/"Server"/"server" freely.
    resp_headers = CaseInsensitiveDict(resp.headers)
    cookie_str = "; ".join(f"{c.name}={c.value}" for c in resp.cookies) if resp.cookies else resp_headers.get("Set-Cookie", "")

    meta_generator = ""
    try:
        soup = BeautifulSoup(html, "html.parser")
        tag = soup.find("meta", attrs={"name": re.compile("generator", re.I)})
        if tag and tag.get("content"):
            meta_generator = tag["content"]
    except Exception:  # noqa: BLE001 - malformed HTML shouldn't break fingerprinting
        pass

    detections = []
    for name, category, indicators in SIGNATURES:
        for kind, pattern in indicators:
            haystack = None
            if kind == "html":
                haystack = html
            elif kind.startswith("header:"):
                header_name = kind.split(":", 1)[1]
                haystack = resp_headers.get(header_name, "")
            elif kind.startswith("meta:"):
                haystack = meta_generator
            elif kind == "cookie":
                haystack = cookie_str

            m = re.search(pattern, haystack, re.IGNORECASE) if haystack else None
            if m:
                if kind == "html":
                    # The matched text with a little context -- not the
                    # start of the page, which says nothing about why it matched.
                    lo, hi = max(0, m.start() - 20), min(len(haystack), m.end() + 40)
                    evidence = " ".join(haystack[lo:hi].split())[:100]
                else:
                    evidence = haystack
                detections.append(Detection(name=name, category=category, evidence=evidence))
                break  # one matched indicator is enough per technology

    return FingerprintResult(
        url=url,
        detections=detections,
        server_header=resp_headers.get("Server", ""),
        powered_by_header=resp_headers.get("X-Powered-By", ""),
    )


def fingerprint_results(results: List[SearchResult], workers: int = 10, timeout: float = 8.0, progress_cb=None, allow_private: bool = False, cache=None) -> List[FingerprintResult]:
    out = []
    total = len(results)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(fingerprint_one, r, timeout, allow_private, cache): r for r in results}
        for i, future in enumerate(as_completed(futures), 1):
            try:
                out.append(future.result())
            except Exception as e:  # noqa: BLE001 -- one bad URL must not abort the whole pass
                out.append(FingerprintResult(url=futures[future].url, error=f"internal error: {type(e).__name__}"))
            if progress_cb:
                progress_cb(i, total)

    order = {r.url: i for i, r in enumerate(results)}
    out.sort(key=lambda f: order.get(f.url, 0))
    return out

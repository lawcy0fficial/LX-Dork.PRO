"""
Engagement scope enforcement.

A dork returns whatever the search index holds, including hosts that are NOT
in your program's scope (third-party buckets, CDNs, paste sites). Fetching,
probing or secret-scanning those is an authorization problem, not just noise.
A Scope says which hosts this run is allowed to touch.

Scope file / --scope syntax (one entry per line; `#` comments):

    example.com          the domain and every subdomain
    =www.example.com     exactly this host, no subdomains
    !staging.example.com exclusion (wins over any include)
    10.0.0.0/8           IP range (CIDR) or a single IP
    !10.9.0.0/16         excluded range

If a scope has no include entries it allows nothing. Matching is on the URL's
real host, so `example.com.evil.net` and `notexample.com` do NOT match.
"""

import ipaddress
from dataclasses import dataclass, field
from typing import Iterable, List, Optional
from urllib.parse import urlparse


@dataclass
class Scope:
    domains: List[str] = field(default_factory=list)       # apex + subdomains
    exact_hosts: List[str] = field(default_factory=list)
    networks: List[object] = field(default_factory=list)
    ex_domains: List[str] = field(default_factory=list)
    ex_exact: List[str] = field(default_factory=list)
    ex_networks: List[object] = field(default_factory=list)

    @classmethod
    def from_lines(cls, lines: Iterable[str]) -> "Scope":
        s = cls()
        for raw in lines:
            line = raw.split("#", 1)[0].strip()
            if not line:
                continue
            exclude = line.startswith("!")
            if exclude:
                line = line[1:].strip()
            exact = line.startswith("=")
            if exact:
                line = line[1:].strip()
            line = _clean_host(line)
            if not line:
                continue
            try:
                net = ipaddress.ip_network(line, strict=False)
            except ValueError:
                net = None
            if net is not None:
                (s.ex_networks if exclude else s.networks).append(net)
            elif exact:
                (s.ex_exact if exclude else s.exact_hosts).append(line)
            else:
                (s.ex_domains if exclude else s.domains).append(line.lstrip("*."))
        return s

    @classmethod
    def from_file(cls, path: str) -> "Scope":
        with open(path, "r", encoding="utf-8") as f:
            return cls.from_lines(f.read().splitlines())

    @property
    def is_empty(self) -> bool:
        return not (self.domains or self.exact_hosts or self.networks)

    def describe(self) -> str:
        """One-line human summary for reports, e.g. 'example.com, =www.x.io, 10.0.0.0/8; excluding dev.example.com'."""
        def net(n):  # a lone IP is stored as a /32 (/128); show it as the plain address the user wrote
            return str(n.network_address) if n.num_addresses == 1 else str(n)

        inc = list(self.domains) + ["=" + h for h in self.exact_hosts] + [net(n) for n in self.networks]
        exc = list(self.ex_domains) + list(self.ex_exact) + [net(n) for n in self.ex_networks]
        text = ", ".join(inc) if inc else "(nothing)"
        return text + (f"; excluding {', '.join(exc)}" if exc else "")

    def contains_host(self, host: str) -> bool:
        host = (host or "").strip("[]").lower().rstrip(".")
        if not host:
            return False
        ip = None
        try:
            ip = ipaddress.ip_address(host)
        except ValueError:
            pass

        def hit(domains, exact, nets) -> bool:
            if ip is not None:
                return any(ip in n for n in nets if n.version == ip.version)
            if host in exact:
                return True
            return any(host == d or host.endswith("." + d) for d in domains)

        if hit(self.ex_domains, self.ex_exact, self.ex_networks):
            return False
        return hit(self.domains, self.exact_hosts, self.networks)

    def contains(self, url: str) -> bool:
        try:
            host = urlparse(url).hostname
        except ValueError:
            return False
        return self.contains_host(host or "")

    def partition(self, items: Iterable, key=lambda r: r.url):
        """Split into (in_scope, out_of_scope), preserving order."""
        inside, outside = [], []
        for it in items:
            (inside if self.contains(key(it)) else outside).append(it)
        return inside, outside


def _clean_host(entry: str) -> str:
    """Accept pasted URLs/ports: https://Example.com:8443/x -> example.com"""
    entry = entry.strip().lower()
    if "://" in entry:
        entry = urlparse(entry).hostname or ""
    elif "/" in entry and not _looks_like_cidr(entry):
        entry = entry.split("/", 1)[0]
    if ":" in entry and entry.count(":") == 1:
        entry = entry.split(":", 1)[0]
    return entry.rstrip(".")


def _looks_like_cidr(entry: str) -> bool:
    try:
        ipaddress.ip_network(entry, strict=False)
        return True
    except ValueError:
        return False


def scope_from_sources(scope_file: Optional[str], inline: Optional[str]) -> Optional[Scope]:
    """Build a Scope from --scope-file and/or --scope "a.com,b.com". None if neither given."""
    if not scope_file and not inline:
        return None
    lines: List[str] = []
    if scope_file:
        with open(scope_file, "r", encoding="utf-8") as f:
            lines += f.read().splitlines()
    if inline:
        lines += [p for p in inline.split(",")]
    return Scope.from_lines(lines)

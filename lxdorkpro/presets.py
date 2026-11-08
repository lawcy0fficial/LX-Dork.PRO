"""
Built-in dork presets for bug-bounty recon, organized into categories
("folders") so they can be browsed, listed, and run as a group.

Use {target} as a placeholder that gets substituted with --target.

Structure:
    PRESETS[name] = {
        "category": str,
        "severity": "critical" | "high" | "medium" | "low" | "info",
        "description": str,
        "queries": [str, ...],
    }

`severity` is an a-priori rating of how significant a *hit* on this preset
tends to be for the target (e.g. a `.git/config` hit is near-certainly
exploitable, an indexed subdomain is just informational) -- it is not a
confirmed finding on its own. Downstream, `findings.py` folds this together
with `--verify` confidence and cross-engine corroboration into a single
per-result score, so a preset's severity is one input among several rather
than the final word.
"""

import ipaddress
import re
from urllib.parse import urlparse
from typing import Dict, List

SEVERITY_ORDER = ["info", "low", "medium", "high", "critical"]


def severity_rank(severity: str) -> int:
    """Numeric rank for sorting/comparison (higher = more severe). Unknown
    or missing severities rank as "info" (0) rather than raising, so a
    plugin-added or malformed preset degrades gracefully instead of
    crashing anything that sorts by severity.
    """
    try:
        return SEVERITY_ORDER.index(severity)
    except ValueError:
        return 0

PRESETS: Dict[str, dict] = {
    # ---- injection -----------------------------------------------------
    "sqli-params": {
        "category": "injection",
        "severity": "high",
        "description": "URL parameters commonly vulnerable to SQL injection",
        "queries": [
            'inurl:php?id= site:{target}',
            'inurl:index.php?id= site:{target}',
            'inurl:.php?catid= site:{target}',
            'inurl:.php?item_id= site:{target}',
        ],
    },
    "xss-params": {
        "category": "injection",
        "severity": "high",
        "description": "URL parameters commonly reflected into a page without sanitization",
        "queries": [
            'inurl:search= site:{target}',
            'inurl:q= site:{target}',
            'inurl:query= site:{target}',
            'inurl:msg= site:{target}',
            'inurl:keyword= site:{target}',
        ],
    },
    "lfi-params": {
        "category": "injection",
        "severity": "high",
        "description": "URL parameters commonly vulnerable to local file inclusion",
        "queries": [
            'inurl:page= site:{target}',
            'inurl:file= site:{target}',
            'inurl:include= site:{target}',
            'inurl:load= site:{target}',
        ],
    },
    "ssti-params": {
        "category": "injection",
        "severity": "high",
        "description": "URL parameters that often feed server-side template engines",
        "queries": [
            'inurl:template= site:{target}',
            'inurl:view= site:{target}',
            'inurl:name= intext:"{{{{" site:{target}',
        ],
    },
    "xxe-endpoints": {
        "category": "injection",
        "severity": "high",
        "description": "Endpoints that commonly accept raw XML input",
        "queries": [
            'site:{target} inurl:xml intitle:"upload"',
            'site:{target} inurl:soap',
            'site:{target} filetype:xml inurl:api',
        ],
    },

    # ---- exposure (files/data that shouldn't be public) ----------------
    "exposed-files": {
        "category": "exposure",
        "severity": "critical",
        "description": "Generic sensitive file extensions (sql, db, log)",
        "queries": [
            'site:{target} ext:sql | ext:db | ext:log',
            'site:{target} ext:env "DB_PASSWORD"',
            'site:{target} filetype:xml | filetype:conf | filetype:cnf',
            'site:{target} ext:bak | ext:backup | ext:old',
        ],
    },
    "exposed-docs": {
        "category": "exposure",
        "severity": "medium",
        "description": "Publicly indexed office documents",
        "queries": [
            'site:{target} filetype:pdf',
            'site:{target} filetype:doc | filetype:docx',
            'site:{target} filetype:xls | filetype:xlsx',
        ],
    },
    "env-files": {
        "category": "exposure",
        "severity": "critical",
        "description": ".env files that may leak credentials/secrets",
        "queries": [
            'site:{target} ext:env intext:APP_KEY',
            'site:{target} inurl:.env "DB_PASSWORD"',
            'site:{target} filetype:env "AWS_SECRET"',
        ],
    },
    "git-exposure": {
        "category": "exposure",
        "severity": "critical",
        "description": "Publicly accessible .git directories/metadata",
        "queries": [
            'site:{target} inurl:".git/config"',
            'site:{target} intitle:"index of" ".git"',
            'site:{target} inurl:.git ext:git',
        ],
    },
    "terraform-state": {
        "category": "exposure",
        "severity": "critical",
        "description": "Terraform state/variable files (routinely contain cloud credentials)",
        "queries": [
            'site:{target} ext:tfstate | ext:tfvars',
            'site:{target} inurl:terraform.tfstate',
            'site:{target} intitle:"index of" "terraform.tfstate"',
        ],
    },
    "vcs-metadata": {
        "category": "exposure",
        "severity": "high",
        "description": "Exposed .svn/.hg/.DS_Store/.htpasswd metadata",
        "queries": [
            'site:{target} inurl:".svn/entries"',
            'site:{target} inurl:".DS_Store"',
            'site:{target} inurl:".htpasswd"',
            'site:{target} inurl:".npmrc" | inurl:".dockercfg"',
        ],
    },
    "backup-files": {
        "category": "exposure",
        "severity": "high",
        "description": "Backup files/archives left in web-accessible paths",
        "queries": [
            'site:{target} ext:bak OR ext:backup OR ext:old OR ext:swp',
            'site:{target} intitle:"index of" "backup"',
            'site:{target} inurl:backup filetype:zip',
        ],
    },
    "log-files": {
        "category": "exposure",
        "severity": "high",
        "description": "Application/server log files exposed to the web",
        "queries": [
            'site:{target} ext:log',
            'site:{target} intitle:"index of" "logs"',
            'site:{target} filetype:log intext:password',
        ],
    },
    "config-files": {
        "category": "exposure",
        "severity": "high",
        "description": "Configuration files that may contain secrets",
        "queries": [
            'site:{target} ext:conf OR ext:config OR ext:cnf OR ext:ini',
            'site:{target} inurl:web.config',
            'site:{target} inurl:wp-config.php.bak',
        ],
    },
    "database-dumps": {
        "category": "exposure",
        "severity": "critical",
        "description": "Indexed SQL/database dump files",
        "queries": [
            'site:{target} ext:sql intext:"INSERT INTO"',
            'site:{target} filetype:sql "SQL Dump"',
            'site:{target} ext:dump',
        ],
    },
    "session-files": {
        "category": "exposure",
        "severity": "high",
        "description": "Exposed session storage that could leak session tokens",
        "queries": [
            'site:{target} inurl:sess_ intitle:"index of"',
            'site:{target} filetype:txt inurl:sessions',
        ],
    },

    # ---- cloud -----------------------------------------------------------
    "cloud-storage": {
        "category": "cloud",
        "severity": "high",
        "description": "Cloud object storage buckets referencing the target",
        "queries": [
            'site:s3.amazonaws.com "{target}"',
            'site:blob.core.windows.net "{target}"',
            'inurl:storage.googleapis.com "{target}"',
        ],
    },
    "docker-config": {
        "category": "cloud",
        "severity": "medium",
        "description": "Docker configuration files exposed on the target",
        "queries": [
            'site:{target} inurl:docker-compose.yml',
            'site:{target} inurl:Dockerfile',
            'site:{target} ext:yml intext:"DOCKER_"',
        ],
    },
    "kubernetes-config": {
        "category": "cloud",
        "severity": "high",
        "description": "Kubernetes config/secret manifests exposed on the target",
        "queries": [
            'site:{target} inurl:kubeconfig',
            'site:{target} inurl:.kube/config',
            'site:{target} ext:yaml intext:"kind: Secret"',
        ],
    },

    # ---- devops ---------------------------------------------------------
    "ci-cd": {
        "category": "devops",
        "severity": "medium",
        "description": "CI/CD pipeline configuration files",
        "queries": [
            'site:{target} inurl:.gitlab-ci.yml',
            'site:{target} inurl:.travis.yml',
            'site:{target} inurl:.circleci/config.yml',
        ],
    },
    "jenkins": {
        "category": "devops",
        "severity": "high",
        "description": "Exposed Jenkins instances / build endpoints",
        "queries": [
            'site:{target} inurl:jenkins intitle:"Dashboard"',
            'site:{target} inurl:"/job/" intext:"Jenkins"',
            'site:{target} inurl:jenkins/script',
        ],
    },
    "spring-actuator": {
        "category": "devops",
        "severity": "high",
        "description": "Spring Boot Actuator endpoints (env/heapdump/trace leak config and secrets)",
        "queries": [
            'site:{target} inurl:"/actuator/env" | inurl:"/actuator/heapdump"',
            'site:{target} inurl:"/actuator" intext:"_links"',
            'site:{target} inurl:"/server-status" intext:"Apache Server Status"',
        ],
    },
    "monitoring-dashboards": {
        "category": "devops",
        "severity": "medium",
        "description": "Exposed Grafana/Prometheus/Kibana dashboards",
        "queries": [
            'site:{target} intitle:"Grafana" inurl:"/login"',
            'site:{target} intitle:"Prometheus Time Series"',
        ],
    },
    "elastic-kibana": {
        "category": "devops",
        "severity": "high",
        "description": "Exposed Elasticsearch/Kibana instances",
        "queries": [
            'site:{target} inurl:9200 intitle:"elasticsearch"',
            'site:{target} inurl:5601 intitle:"kibana"',
            'site:{target} inurl:_cat/indices',
        ],
    },

    # ---- access (panels, portals, remote access) -------------------------
    "admin-panels": {
        "category": "access",
        "severity": "medium",
        "description": "Common admin panel login pages",
        "queries": [
            'site:{target} inurl:admin intitle:login',
            'site:{target} inurl:wp-admin',
            'site:{target} inurl:phpmyadmin',
            'site:{target} inurl:cpanel',
        ],
    },
    "login-portals": {
        "category": "access",
        "severity": "low",
        "description": "General authentication/login entry points",
        "queries": [
            'site:{target} intitle:"login"',
            'site:{target} inurl:signin',
            'site:{target} inurl:auth',
        ],
    },
    "cpanel-webmail": {
        "category": "access",
        "severity": "medium",
        "description": "Exposed cPanel/webmail login interfaces",
        "queries": [
            'site:{target} inurl:2082 OR inurl:2083 intitle:"cpanel"',
            'site:{target} inurl:webmail intitle:"login"',
        ],
    },
    "vpn-config": {
        "category": "access",
        "severity": "high",
        "description": "VPN configuration/portal exposure",
        "queries": [
            'site:{target} filetype:ovpn',
            'site:{target} inurl:vpn intitle:"login"',
        ],
    },
    "remote-desktop": {
        "category": "access",
        "severity": "high",
        "description": "Exposed remote desktop / terminal services web portals",
        "queries": [
            'site:{target} intitle:"Remote Desktop Web Connection"',
            'site:{target} inurl:tsweb intitle:"login"',
        ],
    },

    # ---- web (general application recon) ---------------------------------
    "open-redirect": {
        "category": "web",
        "severity": "medium",
        "description": "URL parameters commonly used for redirects",
        "queries": [
            'inurl:redirect= site:{target}',
            'inurl:url= site:{target}',
            'inurl:next= site:{target}',
            'inurl:return= site:{target}',
        ],
    },
    "api-endpoints": {
        "category": "web",
        "severity": "medium",
        "description": "Discoverable API endpoints and documentation",
        "queries": [
            'site:{target} inurl:api intext:key',
            'site:{target} inurl:/v1/ | inurl:/v2/',
            'site:{target} inurl:swagger',
        ],
    },
    "error-disclosure": {
        "category": "web",
        "severity": "medium",
        "description": "Verbose error messages that leak stack traces/queries",
        "queries": [
            'site:{target} "sql syntax near"',
            'site:{target} "Warning: mysql_"',
            'site:{target} "unhandled exception"',
            'site:{target} intext:"stack trace"',
            'site:{target} "PostgreSQL query failed"',
            'site:{target} "unclosed quotation mark after the character string"',  # MSSQL
            'site:{target} "SQLite3::SQLException" | "SQLite/JDBCDriver"',
            'site:{target} "ORA-01756" | "ORA-00933"',  # Oracle
            'site:{target} "Warning: Smarty:" | "Smarty error"',
            'site:{target} "jinja2.exceptions" | "TemplateSyntaxError"',
            'site:{target} "Twig_Error" | "Twig\\Error"',
            'site:{target} "coldfusion.runtime.TemplateAccessException"',
        ],
    },
    "subdomains-indexed": {
        "category": "web",
        "severity": "info",
        "description": "Indexed subdomains of the target",
        "queries": [
            'site:*.{target} -site:www.{target}',
        ],
    },
    "directory-listing": {
        "category": "web",
        "severity": "medium",
        "description": "Directory listings left open on the web server",
        "queries": [
            'site:{target} intitle:"index of /"',
            'site:{target} intitle:"index of" "parent directory"',
        ],
    },
    "phpinfo": {
        "category": "web",
        "severity": "medium",
        "description": "Exposed phpinfo() pages (leak server configuration)",
        "queries": [
            'site:{target} inurl:phpinfo.php intitle:"phpinfo()"',
            'site:{target} inurl:info.php intext:"PHP Version"',
        ],
    },

    # ---- cms (platform-specific) -----------------------------------------
    "wordpress-specific": {
        "category": "cms",
        "severity": "medium",
        "description": "WordPress-specific exposure points",
        "queries": [
            'site:{target} inurl:wp-content/uploads',
            'site:{target} inurl:wp-json/wp/v2/users',
            'site:{target} inurl:xmlrpc.php',
        ],
    },
    "joomla-specific": {
        "category": "cms",
        "severity": "medium",
        "description": "Joomla-specific exposure points",
        "queries": [
            'site:{target} inurl:administrator intitle:"Joomla"',
            'site:{target} inurl:configuration.php~',
        ],
    },
    "drupal-specific": {
        "category": "cms",
        "severity": "medium",
        "description": "Drupal-specific exposure points",
        "queries": [
            'site:{target} inurl:user/login intitle:"Drupal"',
            'site:{target} inurl:CHANGELOG.txt intext:"Drupal"',
        ],
    },

    # ---- iot --------------------------------------------------------------
    "iot-devices": {
        "category": "iot",
        "severity": "high",
        "description": "Exposed IoT/embedded device web interfaces",
        "queries": [
            'site:{target} intitle:"Web Client" inurl:8080',
            'site:{target} inurl:ipcam intitle:"Live View"',
        ],
    },
    "webcam": {
        "category": "iot",
        "severity": "high",
        "description": "Exposed webcam / camera streaming interfaces",
        "queries": [
            'site:{target} intitle:"webcamXP"',
            'site:{target} inurl:view/view.shtml',
        ],
    },

    # ---- secrets ------------------------------------------------------------
    "code-hosting-leaks": {
        "category": "secrets",
        "severity": "high",
        "description": "Third-party code hosts mentioning the target next to credentials (hosts are usually OUT of scope -- review manually)",
        "queries": [
            'site:github.com "{target}" password | secret | token',
            'site:gitlab.com "{target}" password | secret | token',
            'site:gist.github.com "{target}"',
        ],
    },
    "paste-site-leaks": {
        "category": "secrets",
        "severity": "medium",
        "description": "Paste sites mentioning the target (hosts are out of scope; read, don't scan)",
        "queries": [
            'site:pastebin.com "{target}"',
            'site:trello.com "{target}" password',
            'site:postman.com "{target}"',
        ],
    },
    "api-secrets": {
        "category": "secrets",
        "severity": "critical",
        "description": "Indexed pages that may leak API keys/tokens/private keys",
        "queries": [
            'site:{target} intext:"api_key" ext:json',
            'site:{target} intext:"AKIA" ext:env OR ext:txt',
            'site:{target} intext:"BEGIN RSA PRIVATE KEY"',
        ],
    },
}


def list_presets() -> List[str]:
    return sorted(PRESETS.keys())


def list_categories() -> List[str]:
    return sorted({meta["category"] for meta in PRESETS.values()})


def get_presets_by_category(category: str) -> List[str]:
    return sorted(name for name, meta in PRESETS.items() if meta["category"] == category)


def get_preset_description(name: str) -> str:
    if name not in PRESETS:
        raise KeyError(name)
    return PRESETS[name]["description"]


def get_preset_category(name: str) -> str:
    if name not in PRESETS:
        raise KeyError(name)
    return PRESETS[name]["category"]


def get_preset_severity(name: str) -> str:
    """Severity rating for a preset, defaulting to 'info' for presets that
    (e.g. via a future hand-authored addition) omit the field, rather than
    raising -- only an unknown preset *name* is an error here.
    """
    if name not in PRESETS:
        raise KeyError(name)
    return PRESETS[name].get("severity", "info")


def get_query_severity_map(names: List[str], target: str) -> Dict[str, str]:
    """Map each *query string* produced by these presets back to the
    severity of the preset it came from. Used by findings.py so a result's
    `source_query` can be resolved to a severity even in batch/category
    runs that mix many presets together in one result list.
    """
    mapping: Dict[str, str] = {}
    for name in names:
        severity = get_preset_severity(name)
        for q in get_preset_queries(name, target):
            mapping[q] = severity
    return mapping


_TARGET_HOST_RE = re.compile(r"^[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?(\.[a-z0-9_]([a-z0-9_-]*[a-z0-9_])?)*$")


def normalize_target(raw: str) -> str:
    """Turn what people actually paste into a bare host for `site:` templating.

    `https://User@Example.com:8443/path?x=1` -> `example.com`; `*.example.com`
    -> `example.com`; `example.com.` -> `example.com`. IPs pass through.
    Raises ValueError for empty input or anything that isn't a hostname/IP
    (spaces, quotes, operators) -- those would silently corrupt every dork.
    """
    s = (raw or "").strip().lower()
    if "://" in s:
        s = urlparse(s).hostname or ""
    else:
        s = s.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
        if "@" in s:
            s = s.rsplit("@", 1)[1]
        if s.startswith("[") and "]" in s:
            s = s[1:s.index("]")]
        elif s.count(":") == 1 and s.rsplit(":", 1)[1].isdigit():
            s = s.rsplit(":", 1)[0]  # strip a numeric :port only
    s = s.lstrip("*.").rstrip(".")
    try:
        ipaddress.ip_address(s)
        return s
    except ValueError:
        pass
    if not s or len(s) > 253 or not _TARGET_HOST_RE.match(s):
        raise ValueError(f"'{raw}' is not a valid domain or IP")
    return s


def get_preset_queries(name: str, target: str) -> List[str]:
    if name not in PRESETS:
        raise KeyError(name)
    return [q.format(target=target) for q in PRESETS[name]["queries"]]


def get_category_queries(category: str, target: str) -> List[str]:
    """All queries across every preset in a category, for running a whole
    'folder' of dorks against a target in one shot.
    """
    names = get_presets_by_category(category)
    if not names:
        raise KeyError(category)
    queries: List[str] = []
    for name in names:
        queries.extend(get_preset_queries(name, target))
    return queries

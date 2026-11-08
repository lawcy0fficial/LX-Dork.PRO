"""
Dork expansion: turn one dork into a family of variants.

A single dork only sees what the engine ranks highest. Systematically varying
file types, keywords and exclusions surfaces the long tail -- the same idea as
running a wordlist, applied to search operators. Output is a plain list that
feeds straight into `lxdorkpro dork --dork-file`.

Pure string generation: no network, deterministic order, hard-capped so a
careless `--exts` x `--words` product can't produce a request storm.
"""

import itertools
import re
from typing import Dict, Iterable, List, Optional

# Named keyword sets for --words @name
WORDLISTS: Dict[str, List[str]] = {
    "admin": ["admin", "administrator", "login", "dashboard", "panel", "manage", "console", "cpanel", "backend"],
    "files": ["backup", "dump", "export", "database", "db", "old", "archive", "private", "confidential", "internal"],
    "secrets": ["password", "passwd", "secret", "token", "apikey", "credentials", "private_key", "access_key"],
    "api": ["api", "swagger", "graphql", "openapi", "rest", "v1", "v2", "endpoint", "webhook"],
    "dev": ["dev", "staging", "test", "uat", "qa", "sandbox", "beta", "debug", "preview"],
    "errors": ["error", "exception", "stack trace", "warning", "fatal", "traceback", "syntax error"],
}

# Named extension sets for --exts @name
EXTLISTS: Dict[str, List[str]] = {
    "docs": ["pdf", "doc", "docx", "xls", "xlsx", "ppt", "pptx", "csv", "odt", "rtf"],
    "config": ["env", "ini", "conf", "cfg", "config", "yml", "yaml", "properties", "json", "xml", "toml"],
    "backup": ["bak", "backup", "old", "orig", "swp", "sql", "dump", "db", "sqlite", "zip", "tar", "gz", "7z", "rar"],
    "logs": ["log", "txt", "out"],
    "keys": ["pem", "key", "p12", "pfx", "ppk", "kdbx", "crt", "cer"],
}

DEFAULT_MAX_QUERIES = 500
_OPS = {"inurl", "intitle", "intext"}
_SAFE_WORD = re.compile(r"^[^\"\\\n\r]+$")


def resolve_list(spec: Optional[str], named: Dict[str, List[str]]) -> List[str]:
    """'pdf,doc' -> [pdf, doc]; '@docs' -> that set; mix freely: '@docs,toml'.
    Unknown @names raise KeyError so a typo isn't silently an empty expansion."""
    out: List[str] = []
    for part in (spec or "").split(","):
        part = part.strip()
        if not part:
            continue
        if part.startswith("@"):
            out.extend(named[part[1:].lower()])
        else:
            out.append(part.lstrip(".").lower() if named is EXTLISTS else part)
    return list(dict.fromkeys(out))


def _word_clause(op: str, word: str) -> str:
    if not _SAFE_WORD.match(word):
        raise ValueError(f"keyword {word!r} contains a quote, backslash or newline")
    return f'{op}:"{word}"' if (" " in word or op == "intext") else f"{op}:{word}"


def expand_dork(
    base: str,
    *,
    target: Optional[str] = None,
    exts: Optional[Iterable[str]] = None,
    words: Optional[Iterable[str]] = None,
    ops: Iterable[str] = ("inurl", "intitle", "intext"),
    exclude_subdomains: Optional[Iterable[str]] = None,
    include_base: bool = True,
    cross: bool = False,
    max_queries: int = DEFAULT_MAX_QUERIES,
) -> List[str]:
    """Return the base dork plus variants, deduplicated, in stable order.

    exts                 -> base + ` ext:X` for each X
    words x ops          -> base + ` inurl:W` / ` intitle:W` / ` intext:"W"`
    cross=True           -> additionally every ext x word-clause combination
    exclude_subdomains   -> every query gets ` -site:<label>.<target>` appended
                            (requires target; e.g. 'www,blog' to dig past noise)
    Raises ValueError if the result would exceed max_queries -- fail loudly
    rather than silently truncate or fire thousands of searches.
    """
    base = base.strip()
    if not base:
        raise ValueError("base dork is empty")
    if "{target}" in base:
        if not target:
            raise ValueError("dork contains {target} but no --target was given")
        base = base.replace("{target}", target)
    ops = [o for o in ops if o in _OPS]
    if not ops:
        raise ValueError(f"ops must be among {sorted(_OPS)}")

    suffix = ""
    if exclude_subdomains:
        if not target:
            raise ValueError("--exclude-subdomains requires --target")
        labels = [x.strip().strip(".") for x in exclude_subdomains if x.strip()]
        suffix = "".join(f" -site:{lab}.{target}" for lab in labels)

    ext_clauses = [f"ext:{e.lstrip('.')}" for e in (exts or [])]
    word_clauses = [_word_clause(op, w) for w in (words or []) for op in ops]

    variants: List[str] = []
    if include_base:
        variants.append(base)
    variants += [f"{base} {c}" for c in ext_clauses]
    variants += [f"{base} {c}" for c in word_clauses]
    if cross:
        variants += [f"{base} {e} {w}" for e, w in itertools.product(ext_clauses, word_clauses)]

    out = list(dict.fromkeys(v + suffix for v in variants))
    if len(out) > max_queries:
        raise ValueError(
            f"expansion produced {len(out)} queries (limit {max_queries}). Narrow --exts/--words, "
            f"drop --cross, or raise --max-queries deliberately."
        )
    return out

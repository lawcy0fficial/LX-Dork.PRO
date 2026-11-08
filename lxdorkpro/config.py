"""
Configuration management for LX-Dork-Pro.
Stores API keys / settings at ~/.config/lx-dork-pro/config.json
Keys can also be supplied via environment variables, which always
take priority over the saved config file:

    LXDORK_GOOGLE_API_KEY
    LXDORK_GOOGLE_CX
    LXDORK_BING_API_KEY
    LXDORK_BRAVE_API_KEY
"""

import json
import os
from pathlib import Path

CONFIG_DIR = Path(os.environ.get("LXDORK_HOME", Path.home() / ".config" / "lx-dork-pro"))
CONFIG_FILE = CONFIG_DIR / "config.json"

DEFAULT_CONFIG = {
    "google_api_key": "",
    "google_cx": "",
    "bing_api_key": "",
    "brave_api_key": "",
    "searxng_url": "http://localhost:8888",
    "http_proxy": "",
    "proxy_pool": [],
    # Free, no-key engines are the default so the tool works out of the box.
    # Add "google", "bing", "brave" here once you've run `lxdorkpro configure`.
    "default_engines": ["searxng", "duckduckgo"],
    "default_limit": 30,
    "request_delay": 1.5,
    "timeout": 10,
}

ENV_MAP = {
    "google_api_key": "LXDORK_GOOGLE_API_KEY",
    "google_cx": "LXDORK_GOOGLE_CX",
    "bing_api_key": "LXDORK_BING_API_KEY",
    "brave_api_key": "LXDORK_BRAVE_API_KEY",
    "searxng_url": "LXDORK_SEARXNG_URL",
}


def load_config(include_env: bool = True) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if CONFIG_FILE.exists():
        try:
            with open(CONFIG_FILE, "r", encoding="utf-8") as f:
                saved = json.load(f)
            cfg.update(saved)
        except (json.JSONDecodeError, OSError):
            pass

    # Environment variables always override the saved file. `configure`
    # passes include_env=False so env-supplied keys are never written to disk.
    for key, env_name in (ENV_MAP.items() if include_env else ()):
        env_val = os.environ.get(env_name)
        if env_val:
            cfg[key] = env_val

    return cfg


def save_config(cfg: dict) -> None:
    CONFIG_DIR.mkdir(parents=True, exist_ok=True)
    # Create with 0600 from the start (no window where API keys sit in a
    # world-readable file), then atomically replace.
    tmp = CONFIG_FILE.with_name(CONFIG_FILE.name + ".tmp")
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    try:
        os.chmod(tmp, 0o600)
    except OSError:
        pass
    os.replace(tmp, CONFIG_FILE)


def is_engine_configured(cfg: dict, engine: str) -> bool:
    """Free/no-key engines (searxng, duckduckgo, google-scrape) are always
    considered 'configured' — they need no credentials to attempt a search.
    Only the official paid-tier APIs need a key check. Any other engine name
    (i.e. a custom plugin) is assumed configured — plugin authors are
    responsible for raising EngineError themselves if something's missing.
    """
    if engine == "google":
        return bool(cfg.get("google_api_key") and cfg.get("google_cx"))
    if engine == "bing":
        return bool(cfg.get("bing_api_key"))
    if engine == "brave":
        return bool(cfg.get("brave_api_key"))
    if engine in ("searxng", "duckduckgo", "google-scrape", "yandex", "mojeek", "startpage",
                  "wayback", "commoncrawl", "crtsh", "urlscan"):
        return True
    return True  # unknown engine name -> assume it's a plugin managing its own config

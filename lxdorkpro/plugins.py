"""
Plugin system: drop a .py file defining a BaseEngine, BaseNotifier, and/or
BaseExporter subclass into a plugins directory, and LX-Dork-Pro will
auto-register it -- no need to touch engines.py/notify.py/exporter.py at
all. One file can define any mix of the three; each is independently
discovered and registered under its own `.name`.

Plugin directory resolution order:
  1. LXDORK_PLUGINS_DIR env var, if set
  2. ~/.config/lx-dork-pro/plugins/ (created on first `lxdorkpro configure`
     if it doesn't exist, but you can create it yourself any time)

A minimal engine plugin looks like:

    # ~/.config/lx-dork-pro/plugins/yandex.py
    from lxdorkpro.engines import BaseEngine, SearchResult, EngineError
    import requests

    class YandexEngine(BaseEngine):
        name = "yandex"

        def search(self, query, count):
            # ... call some API or scrape a page, return a list[SearchResult]
            return []

A notifier plugin (usable via `--notifiers telegram`):

    from lxdorkpro.notify import BaseNotifier, NotifyError
    import requests

    class TelegramNotifier(BaseNotifier):
        name = "telegram"

        def notify(self, title, new_urls, job_key=""):
            token = self.cfg.get("telegram_bot_token")
            chat_id = self.cfg.get("telegram_chat_id")
            if not token or not chat_id:
                raise NotifyError("telegram_bot_token/telegram_chat_id not configured")
            text = f"{title}: {len(new_urls)} new result(s)\n" + "\n".join(new_urls[:20])
            resp = requests.post(
                f"https://api.telegram.org/bot{token}/sendMessage",
                json={"chat_id": chat_id, "text": text}, timeout=10,
            )
            if resp.status_code >= 300:
                raise NotifyError(f"Telegram API returned {resp.status_code}")

An exporter plugin (usable via `--export-via jira`):

    from lxdorkpro.exporter import BaseExporter

    class JiraExporter(BaseExporter):
        name = "jira"

        def export(self, results, title="LX-Dork-Pro Results"):
            # ... create a ticket via the Jira API using self.cfg's credentials
            return "https://your-org.atlassian.net/browse/SEC-1234"

Any class in a plugin file that subclasses one of the three base classes
(and isn't the base class itself) gets picked up automatically. Run
`lxdorkpro plugins` to see everything currently loaded, across all three
kinds.
"""

import importlib.util
import inspect
import os
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional, Dict, List, Tuple, Type

PLUGINS_DIR = Path(
    os.environ.get("LXDORK_PLUGINS_DIR")
    or (Path(os.environ.get("LXDORK_HOME", Path.home() / ".config" / "lx-dork-pro")) / "plugins")
)


@dataclass
class PluginLoadResult:
    """Everything discovered across every plugin file, split by kind so
    each registry (engines.ENGINE_REGISTRY, notify.NOTIFIER_REGISTRY,
    exporter.EXPORTER_REGISTRY) gets exactly the classes meant for it.
    """
    engines: Dict[str, type] = field(default_factory=dict)
    notifiers: Dict[str, type] = field(default_factory=dict)
    exporters: Dict[str, type] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)

    @property
    def total_count(self) -> int:
        return len(self.engines) + len(self.notifiers) + len(self.exporters)


def _unsafe_reason(path: Path) -> Optional[str]:
    """Why loading `path` would be unsafe, or None if it looks fine.

    A plugin is arbitrary Python executed with your privileges on every run,
    so whoever can write the file (or its directory) can run code as you.
    Refuse world-writable files/dirs and ones owned by another non-root user.
    POSIX only; set LXDORK_PLUGINS_INSECURE=1 to bypass deliberately.
    """
    if os.name != "posix" or os.environ.get("LXDORK_PLUGINS_INSECURE") == "1":
        return None
    me = os.geteuid()
    for what, p in (("directory", path.parent), ("file", path)):
        try:
            st = p.stat()
        except OSError as e:
            return f"cannot stat {what}: {e.strerror}"
        if st.st_mode & 0o002:
            return f"{what} is world-writable"
        if st.st_uid not in (me, 0):
            return f"{what} is owned by uid {st.st_uid}, not you or root"
    return None


def discover_plugin_files() -> List[Path]:
    if not PLUGINS_DIR.exists():
        return []
    return sorted(p for p in PLUGINS_DIR.glob("*.py") if not p.name.startswith("_"))


# Each entry: (attribute name on PluginLoadResult, a function returning the
# live base class, and a human label for error messages). Base classes are
# fetched lazily via a function (not imported at module load time) to
# avoid a circular import between plugins.py and engines.py/notify.py/
# exporter.py, exactly like the original BaseEngine-only version did.
def _plugin_kinds():
    from .engines import BaseEngine
    from .notify import BaseNotifier
    from .exporter import BaseExporter
    return [
        ("engines", BaseEngine, "engine"),
        ("notifiers", BaseNotifier, "notifier"),
        ("exporters", BaseExporter, "exporter"),
    ]


def load_plugins() -> PluginLoadResult:
    """Import every plugin file and find BaseEngine/BaseNotifier/
    BaseExporter subclasses in each, across all three kinds in one pass
    over the plugin directory. Never raises -- a broken plugin file, or a
    plugin class with no valid `.name`, is reported in `.errors` rather
    than fatal to the whole tool.
    """
    result = PluginLoadResult()
    kinds = _plugin_kinds()

    for path in discover_plugin_files():
        unsafe = _unsafe_reason(path)
        if unsafe:
            result.errors.append(
                f"{path.name}: refused ({unsafe}). Fix with `chmod go-w` / chown, or set "
                f"LXDORK_PLUGINS_INSECURE=1 if you really mean it."
            )
            continue
        module_name = f"lxdorkpro_plugin_{path.stem}"
        try:
            spec = importlib.util.spec_from_file_location(module_name, path)
            module = importlib.util.module_from_spec(spec)
            sys.modules[module_name] = module
            spec.loader.exec_module(module)
        except Exception as e:  # noqa: BLE001 - a bad plugin must not crash the CLI
            result.errors.append(f"{path.name}: failed to load ({type(e).__name__}: {e})")
            continue

        found_any = False
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if obj.__module__ != module_name:
                continue  # skip re-exported/imported classes (BaseEngine itself, requests.*, etc.)

            for attr_name, base_cls, label in kinds:
                if obj is base_cls or not issubclass(obj, base_cls):
                    continue
                found_any = True  # structurally a plugin class of this kind, even if its name turns out invalid below
                plugin_name = getattr(obj, "name", None)
                if not plugin_name or plugin_name == "base":
                    result.errors.append(f"{path.name}: {label} class {obj.__name__} has no valid `.name` attribute, skipped")
                    continue
                getattr(result, attr_name)[plugin_name] = obj
                break  # a class subclasses exactly one of the three kinds -- stop checking the others

        if not found_any:
            result.errors.append(f"{path.name}: loaded but no BaseEngine/BaseNotifier/BaseExporter subclass found")

    return result


def install_plugins_into_registry() -> PluginLoadResult:
    """Load plugins and merge them into all three live registries
    (engines.ENGINE_REGISTRY, notify.NOTIFIER_REGISTRY,
    exporter.EXPORTER_REGISTRY). Call once at CLI startup. Returns the
    full PluginLoadResult for reporting via `lxdorkpro plugins`.
    """
    from . import engines as enginesmod
    from . import notify as notifymod
    from . import exporter as exportermod

    result = load_plugins()
    enginesmod.ENGINE_REGISTRY.update(result.engines)
    notifymod.NOTIFIER_REGISTRY.update(result.notifiers)
    exportermod.EXPORTER_REGISTRY.update(result.exporters)
    return result

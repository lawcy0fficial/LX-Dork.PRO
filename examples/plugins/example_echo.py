"""
Example plugin: a custom search engine for LX-Dork-Pro.

To use this: copy this file into your plugins directory (by default
~/.config/lx-dork-pro/plugins/, or wherever LXDORK_PLUGINS_DIR points),
then run `lxdorkpro plugins` to confirm it was picked up, and reference
it like any built-in engine:

    lxdorkpro dork -d 'site:example.com' -e example-echo

This particular example doesn't call a real API — it just echoes the
query back as a single fake result, so you can see the plugin mechanism
work end-to-end before wiring up a real backend. Replace `search()` with
a real HTTP call (Yandex, Startpage, an internal search appliance, etc.)
following the same pattern as lxdorkpro/engines.py.
"""

from lxdorkpro.engines import BaseEngine, SearchResult, EngineError


class ExampleEchoEngine(BaseEngine):
    # This is the name you'll pass to -e / --engines
    name = "example-echo"

    def search(self, query, count):
        # Real plugins would call requests.get(...) here and parse a
        # response, exactly like GoogleEngine/BraveEngine/etc. do.
        # Raise EngineError(...) for any failure (bad key, timeout, etc.)
        # so the CLI reports it cleanly instead of crashing.
        if not query:
            raise EngineError("Empty query")

        return [
            SearchResult(
                url=f"https://example.invalid/search?q={query}",
                title=f"Echo result for: {query}",
                snippet="This is a placeholder result from the example plugin.",
                engine=self.name,
            )
        ][:count]

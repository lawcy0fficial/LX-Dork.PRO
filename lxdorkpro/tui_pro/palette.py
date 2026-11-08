"""
Command palette entries and the fuzzy-match filter used to narrow them.

No `textual` import here -- see state.py's module docstring for why. This
lets the matching behavior itself (the part someone will actually notice
if it's wrong -- "why didn't typing 'gitex' find git-exposure?") be tested
without spinning up a Textual App and its screen stack.
"""

from dataclasses import dataclass
from typing import List


@dataclass(frozen=True)
class Command:
    id: str          # stable identifier app.py dispatches on, e.g. "job.next"
    title: str        # what's shown in the palette, e.g. "Next job"
    category: str = "General"    # groups entries in the palette listing
    keywords: str = ""            # extra search terms beyond the title (e.g. preset names, aliases)


def fuzzy_match(query: str, text: str) -> bool:
    """Subsequence fuzzy match: every character in `query` must appear in
    `text`, in order, not necessarily contiguously -- the same matching
    style as VS Code's Ctrl+P ("gtex" matches "git-exposure"). Case
    insensitive; an empty query matches everything.

    Implementation note: `needle in iterator` consumes the iterator up to
    (and including) the first matching element and leaves it positioned
    there for the next `in` check -- so chaining this across every
    character of `query` against one shared iterator over `text` is
    exactly a subsequence test, without hand-rolling index bookkeeping.
    """
    if not query:
        return True
    it = iter(text.lower())
    return all(ch in it for ch in query.lower())


def filter_commands(commands: List[Command], query: str) -> List[Command]:
    """Commands matching `query` against title, id, or keywords, keeping
    the original relative order (no re-ranking by match quality -- with a
    palette this small, alphabetical-ish/registration order reads more
    predictably than a fuzzy score bouncing entries around as you type).
    """
    if not query:
        return list(commands)
    return [
        c for c in commands
        if fuzzy_match(query, c.title) or fuzzy_match(query, c.id) or fuzzy_match(query, c.keywords)
    ]


def default_commands(preset_names: List[str], theme_names: List[str]) -> List[Command]:
    """The palette's built-in command set. Preset/theme names are passed
    in (rather than imported here) so this module doesn't need to know
    about presets.py/theme.py's exact shape -- app.py, which already
    imports both for other reasons, supplies them.
    """
    commands = [
        Command("job.new_dork", "New job: raw dork", "Jobs", keywords="search query"),
        Command("job.new_preset", "New job: from preset", "Jobs", keywords="template category"),
        Command("job.next", "Next job", "Jobs", keywords="tab switch"),
        Command("job.prev", "Previous job", "Jobs", keywords="tab switch"),
        Command("job.close", "Close current job", "Jobs", keywords="stop cancel"),
        Command("job.cancel", "Cancel running job", "Jobs", keywords="stop abort interrupt"),
        Command("row.probe", "Probe selected URL", "Row actions", keywords="liveness alive check"),
        Command("row.fingerprint", "Fingerprint selected URL", "Row actions", keywords="tech stack wappalyzer"),
        Command("row.secrets", "Scan selected URL for secrets", "Row actions", keywords="credentials leak"),
        Command("row.screenshot", "Screenshot selected URL", "Row actions", keywords="capture image"),
        Command("row.open", "Open selected URL in browser", "Row actions", keywords="visit launch"),
        Command("row.view", "View raw response", "Row actions", keywords="source body inspect"),
        Command("job.watch:15", "Watch current job: re-run every 15 min", "Jobs", keywords="monitor repeat schedule"),
        Command("job.watch:60", "Watch current job: re-run every hour", "Jobs", keywords="monitor repeat schedule"),
        Command("job.watch:off", "Stop watching current job", "Jobs", keywords="monitor repeat unschedule"),
        Command("view.export", "Export current job's results", "View", keywords="save txt json csv html"),
        Command("view.filter_clear", "Clear result filter", "View", keywords="reset search"),
        Command("view.help", "Show keybinding help", "View", keywords="? shortcuts cheatsheet"),
        Command("view.quit", "Quit", "View", keywords="exit close"),
    ]
    for name in preset_names:
        commands.append(Command(f"preset.run:{name}", f"Run preset: {name}", "Presets", keywords=name))
    for name in theme_names:
        commands.append(Command(f"theme.set:{name}", f"Switch theme: {name}", "Appearance", keywords=name))
    return commands

"""
Color theme system for LX-Dork-Pro's terminal UI. Kept separate from ui.py
(which needs `rich`) so the palette data itself is trivially unit-testable
without pulling in rendering dependencies.
"""

from typing import Dict

THEMES: Dict[str, Dict[str, str]] = {
    "cyan": {
        "gradient": ["#00f5ff", "#00d4ff", "#00b4ff", "#0094ff", "#0074ff", "#4d4dff"],
        "accent": "cyan",
        "success": "green",
        "warning": "yellow",
        "danger": "red",
        "muted": "grey58",
        "border": "cyan",
    },
    "matrix": {
        "gradient": ["#00ff41", "#00e639", "#00cc33", "#00b32d", "#009926", "#00801f"],
        "accent": "green",
        "success": "bright_green",
        "warning": "yellow",
        "danger": "red",
        "muted": "grey50",
        "border": "green",
    },
    "sunset": {
        "gradient": ["#ff6b6b", "#ff8e53", "#ffa751", "#ffc93c", "#ff5e78", "#ff2e63"],
        "accent": "orange3",
        "success": "green",
        "warning": "gold3",
        "danger": "red3",
        "muted": "grey58",
        "border": "orange3",
    },
}

DEFAULT_THEME = "cyan"


def get_theme(name: str = None) -> Dict[str, str]:
    """Return the palette dict for a theme name, falling back to the
    default theme for unknown names rather than raising -- a typo in
    --theme shouldn't crash the whole tool over a cosmetic choice.
    """
    return THEMES.get(name, THEMES[DEFAULT_THEME])


def list_themes():
    return sorted(THEMES.keys())

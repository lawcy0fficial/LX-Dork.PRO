"""
Pure sparkline rendering: turns a list of per-cycle "new results found"
counts into a compact block-character string for the job rail, e.g.
"▁▁▃▇▂▁" -- so a long-running --watch job is legible at a glance instead
of requiring a scroll through its log to see whether it's still finding
things. No `textual` import -- see state.py's module docstring for why.
"""

from typing import List

_BLOCKS = " ▁▂▃▄▅▆▇█"  # index 0 is a literal space, used only when every value is 0


def render_sparkline(values: List[int], width: int = 12) -> str:
    """Render the last `width` values as a sparkline. All-zero or empty
    input renders as a flat line of the lowest block (not empty), so the
    job rail shows "quiet but present" distinctly from "no history yet".
    """
    if not values:
        return _BLOCKS[1] * width

    windowed = values[-width:]
    if len(windowed) < width:
        # Pad with a distinct baseline on the left so it's visually clear
        # this job hasn't run `width` cycles yet, rather than implying
        # those earlier (nonexistent) cycles were all zero.
        windowed = [0] * (width - len(windowed)) + windowed

    max_val = max(windowed)
    if max_val == 0:
        return _BLOCKS[1] * len(windowed)

    scale = (len(_BLOCKS) - 2) / max_val  # reserve index 0 (blank) for true zero-history padding only
    chars = []
    for v in windowed:
        if v <= 0:
            chars.append(_BLOCKS[1])
        else:
            level = 1 + round(v * scale)
            level = max(1, min(len(_BLOCKS) - 1, level))
            chars.append(_BLOCKS[level])
    return "".join(chars)

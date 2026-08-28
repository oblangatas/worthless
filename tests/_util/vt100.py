"""Shared VT100 screen model for terminal-effect tests.

Renders a string through a minimal terminal so a test can assert whether an
attack's escape sequence actually *mutates the screen* — the "renders inert"
proof introduced for ``scan`` in PR #376, reused across scan/lock/doctor so the
model can't drift between copies. Interprets ONLY the CSI sequences the tested
attacks use (``ESC[2J`` erase-screen, ``ESC[H`` cursor-home, ``ESC[A``
cursor-up, ``ESC[2K`` erase-line); every other escape is ignored.
"""

from __future__ import annotations

ESC = "\x1b"
BEL = "\x07"
RLO = chr(0x202E)  # RIGHT-TO-LEFT OVERRIDE, built to avoid a literal bidi char in source
# A line already on the user's screen before the command prints its output. If
# an attack fires, this line is wiped or overwritten; if the output is inert it
# survives — that survival is the assertion each terminal-effect test makes.
PRIOR_WARNING = "PRIOR_WARNING_UNPROTECTED_KEY_IN_config_py"


class VTScreen:
    """Minimal VT100 screen — interprets ONLY the CSI sequences these attacks
    use (``ESC[2J`` erase-screen, ``ESC[H`` cursor-home, ``ESC[A`` cursor-up,
    ``ESC[2K`` erase-line); other escapes are ignored. Faithful enough to show
    whether an attack's escape actually mutates the rendered screen."""

    def __init__(self, rows: int = 24, cols: int = 80) -> None:
        self.rows, self.cols = rows, cols
        self.grid = [[" "] * cols for _ in range(rows)]
        self.r = self.c = 0

    def feed(self, text: str) -> None:
        i, n = 0, len(text)
        while i < n:
            ch = text[i]
            if ch == ESC and i + 1 < n and text[i + 1] == "[":
                j = i + 2
                while j < n and text[j] in "0123456789;":
                    j += 1
                if j < n:
                    self._csi(text[i + 2 : j], text[j])
                    i = j + 1
                    continue
            if ch == ESC:
                i += 1
            elif ch == "\r":
                self.c = 0
                i += 1
            elif ch == "\n":
                self.r = min(self.r + 1, self.rows - 1)
                i += 1
            else:
                if 0 <= self.r < self.rows and 0 <= self.c < self.cols:
                    self.grid[self.r][self.c] = ch
                self.c = min(self.c + 1, self.cols - 1)
                i += 1

    def _csi(self, params: str, final: str) -> None:
        nums = [int(p) for p in params.split(";") if p]
        n0 = nums[0] if nums else 0
        if final == "J" and n0 == 2:  # erase entire screen
            self.grid = [[" "] * self.cols for _ in range(self.rows)]
        elif final == "H":  # cursor home (only the bare ESC[H form is fed)
            self.r = self.c = 0
        elif final == "A":  # cursor up
            self.r = max(0, self.r - (n0 or 1))
        elif final == "K" and n0 == 2:  # erase whole line
            self.grid[self.r] = [" "] * self.cols

    def rows_text(self) -> list[str]:
        return ["".join(row).rstrip() for row in self.grid if "".join(row).strip()]


def render(text: str) -> list[str]:
    """Feed PRIOR_WARNING + text through a fresh screen; return non-blank rows."""
    screen = VTScreen()
    screen.feed(PRIOR_WARNING + "\r\n")
    screen.feed(text.replace("\n", "\r\n"))
    return screen.rows_text()


def warning_survived(rows: list[str]) -> bool:
    return any(PRIOR_WARNING in row for row in rows)

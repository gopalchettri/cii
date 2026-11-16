"""run.ps1's windows turn QuickEdit off, so a click in one never freezes its program at its next log line."""

import base64
import re
import shutil
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
RUN_PS1 = (REPO / "run.ps1").read_text(encoding="ascii")
ENABLE_QUICK_EDIT_MODE, ENABLE_EXTENDED_FLAGS = 0x40, 0x80
POWERSHELL = shutil.which("powershell") or ""


def _quick_edit_off_script() -> str:
    """The script run.ps1 runs first in every window."""
    found = re.search(r"\$QuickEditOff = @'\n(.*?)\n'@", RUN_PS1, re.DOTALL)
    assert found, "run.ps1 has no $QuickEditOff script"
    return found.group(1)


def test_every_window_turns_quick_edit_off_before_its_program_starts() -> None:
    """Start-Window's command opens with the QuickEdit script, before the title, folder and program."""
    inner = re.search(r'\$inner = "(.*?)"', RUN_PS1)
    assert inner and inner.group(1).startswith("$QuickEditOff`n"), inner


@pytest.mark.skipif(not POWERSHELL, reason="Windows PowerShell is not installed here")
def test_the_quick_edit_script_clears_quick_edit_in_a_new_console(tmp_path: Path) -> None:
    """Run in a new hidden console, as run.ps1's windows are, the script leaves QuickEdit off."""
    out = tmp_path / "mode.txt"
    probe = (
        f"{_quick_edit_off_script()}\n"
        "$after = [uint32]0; [void][Tsg.ConsoleInput]::GetConsoleMode([Tsg.ConsoleInput]::GetStdHandle(-10), "
        f"[ref]$after); Set-Content -LiteralPath '{out}' -Value $after"
    )
    hidden = subprocess.STARTUPINFO(dwFlags=subprocess.STARTF_USESHOWWINDOW, wShowWindow=0)
    encoded = base64.b64encode(probe.encode("utf-16-le")).decode()
    subprocess.run(  # noqa: S603 - our own probe
        [POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded],
        creationflags=subprocess.CREATE_NEW_CONSOLE,
        startupinfo=hidden,
        timeout=60,
        check=True,
    )
    mode = int(out.read_text().strip())
    assert not mode & ENABLE_QUICK_EDIT_MODE, f"QuickEdit still on: mode {mode:#x}"
    assert mode & ENABLE_EXTENDED_FLAGS, f"extended flags off, so QuickEdit's bit is ignored: mode {mode:#x}"

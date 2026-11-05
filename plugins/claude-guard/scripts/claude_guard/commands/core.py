"""Core shell rules: privilege escalation, force push, recursive deletion."""

from __future__ import annotations

import re
from typing import Callable

SUDO_RE = re.compile(r"(?<![\w/])sudo(?=\s|$)", re.IGNORECASE)
FORCE_PUSH_RE = re.compile(
    r"(?<![\w/])git\s+push\b[^\n;&|]*?(?:\s--force(?:-with-lease)?(?=\s|=|$)|\s-f(?=\s|$))",
    re.IGNORECASE,
)
POWERSHELL_DELETE_RE = re.compile(
    r"(?i)\bRemove-Item\b[^\n;&|]*(?=.*?-Recurse\b)(?=.*?-Force\b)"
)
RM_OPTIONS_RE = re.compile(
    r"(?<![\w/])rm\s+((?:(?:--[a-z-]+|-[a-zA-Z]+)\s+)+)",
    re.IGNORECASE,
)


def _has_option(options: list[str], long_name: str, short_flag: str) -> bool:
    """True if `long_name` or a short-option cluster containing `short_flag` is present."""
    return any(
        option == long_name
        or (option.startswith("-") and not option.startswith("--")
            and short_flag in option[1:])
        for option in options
    )


def _is_recursive_forced_rm(command: str) -> bool:
    for match in RM_OPTIONS_RE.finditer(command):
        options = match.group(1).lower().split()
        if (_has_option(options, "--recursive", "r")
                and _has_option(options, "--force", "f")):
            return True
    return False


RULES: tuple[tuple[Callable[[str], object], str], ...] = (
    (POWERSHELL_DELETE_RE.search, "recursive forced PowerShell deletion"),
    (SUDO_RE.search, "sudo command"),
    (FORCE_PUSH_RE.search, "forced git push"),
    (_is_recursive_forced_rm, "recursive forced deletion"),
)

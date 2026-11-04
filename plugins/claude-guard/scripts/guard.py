#!/usr/bin/env python3
"""Claude Code PreToolUse guard (Python standard library only).

Exit 0: let Claude Code's normal permission checks decide.
Exit 2: deny the tool call, printing a reason to stderr.

This is a best-effort guard for direct references, not a security boundary.
"""

from __future__ import annotations

import json
import re
import sys
from typing import Any

# Templates are intentionally permitted. Extend only after reviewing risks.
SAFE_DOTENV_NAMES = frozenset({
    ".env.example", ".env.sample", ".env.template", ".env.dist"
})

# The patterns check file/path names, not arbitrary substrings like "environment".
DOTENV_RE = re.compile(
    r"(?<![A-Za-z0-9._-])\.env(?:\.[A-Za-z0-9_-]+)*(?![A-Za-z0-9._-])",
    re.IGNORECASE,
)
OTHER_SECRET_RE = re.compile(
    r"(?<![A-Za-z0-9._-])(?:\.npmrc|\.pypirc|\.netrc|"
    r"id_rsa|id_ed25519|id_ecdsa|"
    r"credentials\.json|service-account\.json|"
    r"(?:[^/\\\s\"']+\.(?:pem|p12|pfx)))(?![A-Za-z0-9._-])",
    re.IGNORECASE,
)
SECRET_DIRECTORY_RE = re.compile(
    r"(?<![A-Za-z0-9._-])(?:\.ssh(?:[/\\]|$)|"
    r"\.aws[/\\]credentials\b|\.kube[/\\]config\b|"
    r"\.config[/\\]gh[/\\]hosts\.yml\b)",
    re.IGNORECASE,
)

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

PATH_FIELD_BY_TOOL = {
    "Read": ("file_path",),
    "Write": ("file_path",),
    "Edit": ("file_path",),
    "NotebookEdit": ("notebook_path",),
    "Grep": ("path", "glob"),
    "Glob": ("path", "pattern"),
}
SHELL_TOOLS = frozenset({"Bash", "PowerShell"})


def sensitive_reference(text: str) -> str | None:
    """Return a category for direct references to common secrets."""
    normalized = text.replace("\\", "/")
    for match in DOTENV_RE.finditer(normalized):
        if match.group(0).lower() not in SAFE_DOTENV_NAMES:
            return "dotenv file"
    if SECRET_DIRECTORY_RE.search(normalized):
        return "credential directory or configuration"
    if OTHER_SECRET_RE.search(normalized):
        return "key or credential file"
    return None


def destructive_command(command: str) -> str | None:
    """Best-effort detection; this deliberately errs on the side of blocking."""
    if POWERSHELL_DELETE_RE.search(command):
        return "recursive forced PowerShell deletion"
    if SUDO_RE.search(command):
        return "sudo command"
    if FORCE_PUSH_RE.search(command):
        return "forced git push"
    for match in RM_OPTIONS_RE.finditer(command):
        options = match.group(1).lower().split()
        recursive = any(option == "--recursive" or (
            option.startswith("-") and not option.startswith("--")
            and "r" in option[1:]
        ) for option in options)
        force = any(option == "--force" or (
            option.startswith("-") and not option.startswith("--")
            and "f" in option[1:]
        ) for option in options)
        if recursive and force:
            return "recursive forced deletion"
    return None


def check_event(event: dict[str, Any]) -> str | None:
    tool = event.get("tool_name")
    args = event.get("tool_input")
    if not isinstance(tool, str) or not isinstance(args, dict):
        return "invalid hook event"

    if tool in SHELL_TOOLS:
        command = args.get("command")
        if not isinstance(command, str):
            return "invalid shell command"
        secret = sensitive_reference(command)
        if secret:
            return f"shell command refers to a {secret}"
        return destructive_command(command)

    if tool in PATH_FIELD_BY_TOOL:
        for field in PATH_FIELD_BY_TOOL[tool]:
            value = args.get(field)
            if value is None:
                continue
            if not isinstance(value, str):
                return f"invalid {tool}.{field}"
            secret = sensitive_reference(value)
            if secret:
                return f"{tool}.{field} refers to a {secret}"
        if tool in {"Read", "Write", "Edit", "NotebookEdit"}:
            required_field = PATH_FIELD_BY_TOOL[tool][0]
            if not isinstance(args.get(required_field), str):
                return f"missing {tool}.{required_field}"
        return None

    # Unexpected event: fail closed. The matcher shouldn't invoke this branch.
    return f"unsupported tool: {tool}"


def main() -> int:
    try:
        event = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise ValueError("expected JSON object")
        result = check_event(event)
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        print(f"Claude Guard: invalid hook input ({type(exc).__name__})", file=sys.stderr)
        return 2
    except Exception as exc:
        # No content is printed, to avoid leaking incoming tool inputs in logs.
        print(f"Claude Guard: policy check failed ({type(exc).__name__})", file=sys.stderr)
        return 2

    if result is not None:
        print(f"Claude Guard DENIED: {result}", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())

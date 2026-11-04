"""Dispatch of PreToolUse hook events to the relevant checks."""

from __future__ import annotations

from typing import Any

from .commands import destructive_command
from .sensitive_paths import sensitive_reference

SHELL_TOOLS = frozenset({"Bash", "PowerShell"})

# Path-like fields inspected per tool. For tools in TOOLS_REQUIRING_PATH the
# first field must be present.
PATH_FIELD_BY_TOOL: dict[str, tuple[str, ...]] = {
    "Read": ("file_path",),
    "Write": ("file_path",),
    "Edit": ("file_path",),
    "NotebookEdit": ("notebook_path",),
    "Grep": ("path", "glob"),
    "Glob": ("path", "pattern"),
}
TOOLS_REQUIRING_PATH = frozenset({"Read", "Write", "Edit", "NotebookEdit"})


def check_shell_tool(args: dict[str, Any]) -> str | None:
    command = args.get("command")
    if not isinstance(command, str):
        return "invalid shell command"
    secret = sensitive_reference(command)
    if secret:
        return f"shell command refers to a {secret}"
    return destructive_command(command)


def check_path_tool(tool: str, args: dict[str, Any]) -> str | None:
    fields = PATH_FIELD_BY_TOOL[tool]
    for field in fields:
        value = args.get(field)
        if value is None:
            continue
        if not isinstance(value, str):
            return f"invalid {tool}.{field}"
        secret = sensitive_reference(value)
        if secret:
            return f"{tool}.{field} refers to a {secret}"
    if tool in TOOLS_REQUIRING_PATH and not isinstance(args.get(fields[0]), str):
        return f"missing {tool}.{fields[0]}"
    return None


def check_event(event: dict[str, Any]) -> str | None:
    """Return a denial reason for the hook event, or None to allow it."""
    tool = event.get("tool_name")
    args = event.get("tool_input")
    if not isinstance(tool, str) or not isinstance(args, dict):
        return "invalid hook event"

    if tool in SHELL_TOOLS:
        return check_shell_tool(args)
    if tool in PATH_FIELD_BY_TOOL:
        return check_path_tool(tool, args)

    # Unexpected event: fail closed. The matcher shouldn't invoke this branch.
    return f"unsupported tool: {tool}"

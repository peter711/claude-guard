#!/usr/bin/env python3
"""Claude Code PreToolUse guard (Python standard library only).

Exit 0: let Claude Code's normal permission checks decide.
Exit 2: deny the tool call, printing a reason to stderr.

This is a best-effort guard for direct references, not a security boundary.
Policy rules live in the sibling `claude_guard` package.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

# Make the sibling package importable when loaded by path (hook or tests).
sys.path.insert(0, str(Path(__file__).resolve().parent))

from claude_guard import check_event, destructive_command, sensitive_reference  # noqa: E402

__all__ = ["check_event", "destructive_command", "sensitive_reference", "main"]

DENY_EXIT_CODE = 2


def _deny(message: str) -> int:
    print(message, file=sys.stderr)
    return DENY_EXIT_CODE


def main() -> int:
    try:
        event = json.load(sys.stdin)
        if not isinstance(event, dict):
            raise ValueError("expected JSON object")
        result = check_event(event)
    except (ValueError, TypeError, UnicodeError, RecursionError) as exc:
        return _deny(f"Claude Guard: invalid hook input ({type(exc).__name__})")
    except Exception as exc:
        # No content is printed, to avoid leaking incoming tool inputs in logs.
        return _deny(f"Claude Guard: policy check failed ({type(exc).__name__})")

    if result is not None:
        return _deny(f"Claude Guard DENIED: {result}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

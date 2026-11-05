"""Best-effort detection of destructive shell commands.

This deliberately errs on the side of blocking. Rules live in per-domain
modules (`core`, `aws`, `azure`, `vault`, `environment`); each exposes `RULES`, a tuple of
`(matcher, reason)` pairs.
"""

from __future__ import annotations

from typing import Callable

from . import aws, azure, core, environment, vault

# Checked in order; the first matching rule determines the reported reason.
# `environment` stays last so the specific AWS/Azure/Vault reasons win.
COMMAND_RULES: tuple[tuple[Callable[[str], object], str], ...] = (
    *core.RULES,
    *aws.RULES,
    *azure.RULES,
    *vault.RULES,
    *environment.RULES,
)

__all__ = ["COMMAND_RULES", "destructive_command"]


def destructive_command(command: str) -> str | None:
    """Return a reason if the command looks destructive, else None."""
    for matches, reason in COMMAND_RULES:
        if matches(command):
            return reason
    return None

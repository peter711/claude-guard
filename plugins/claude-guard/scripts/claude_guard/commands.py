"""Best-effort detection of destructive shell commands.

This deliberately errs on the side of blocking.
"""

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
# `aws [global options] <service> ...`; consumes options with optional values.
AWS_RE = r"(?<![\w/])aws\s+(?:--?[\w-]+(?:[ =]\S+)?\s+)*"
AWS_DESTRUCTIVE_RE = re.compile(
    AWS_RE + r"(?:[a-z0-9-]+\s+(?:(?:delete|terminate|purge|remove|detach|deregister)-[\w-]+"
    r"|create-access-key|put-[\w-]*policy|attach-[\w-]*policy)(?=\s|$)"
    r"|s3\s+(?:rm|rb)(?=\s|$)"
    r"|s3\s+sync\b[^\n;&|]*\s--delete(?=\s|$))",
    re.IGNORECASE,
)
AWS_SECRET_READ_RE = re.compile(
    AWS_RE + r"(?:configure\s+get\b[^\n;&|]*\baws_(?:secret_access_key|session_token|access_key_id)\b"
    r"|secretsmanager\s+get-secret-value\b"
    r"|ssm\s+get-parameters?(?:-by-path)?(?=\s)[^\n;&|]*--with-decryption\b"
    r"|kms\s+decrypt\b"
    r"|sts\s+get-(?:session|federation)-token\b)",
    re.IGNORECASE,
)
CREDENTIAL_ECHO_RE = re.compile(
    r"(?<![\w/.-])(?:printenv|env|echo|export\s+-p)\b[^\n;&]*"
    r"\bAWS_(?:SECRET_ACCESS_KEY|SESSION_TOKEN|ACCESS_KEY_ID)\b"
    r"|(?<![\w/])vault\s+(?:(?:read|write)\b[^\n;&|]*/(?:creds|sts)/|print\s+token\b)",
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


# Checked in order; the first matching rule determines the reported reason.
COMMAND_RULES: tuple[tuple[Callable[[str], object], str], ...] = (
    (POWERSHELL_DELETE_RE.search, "recursive forced PowerShell deletion"),
    (SUDO_RE.search, "sudo command"),
    (FORCE_PUSH_RE.search, "forced git push"),
    (_is_recursive_forced_rm, "recursive forced deletion"),
    (AWS_DESTRUCTIVE_RE.search, "destructive AWS CLI command"),
    (AWS_SECRET_READ_RE.search, "AWS secret read"),
    (CREDENTIAL_ECHO_RE.search, "credential echo or dynamic credential read"),
)


def destructive_command(command: str) -> str | None:
    """Return a reason if the command looks destructive, else None."""
    for matches, reason in COMMAND_RULES:
        if matches(command):
            return reason
    return None

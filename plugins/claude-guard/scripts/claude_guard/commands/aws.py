"""AWS CLI rules: destructive calls, secret reads, credential env echo."""

from __future__ import annotations

import re
from typing import Callable

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
AWS_CREDENTIAL_ECHO_RE = re.compile(
    r"(?<![\w/.-])(?:printenv|env|echo|export\s+-p)\b[^\n;&]*"
    r"\bAWS_(?:SECRET_ACCESS_KEY|SESSION_TOKEN|ACCESS_KEY_ID)\b",
    re.IGNORECASE,
)

RULES: tuple[tuple[Callable[[str], object], str], ...] = (
    (AWS_DESTRUCTIVE_RE.search, "destructive AWS CLI command"),
    (AWS_SECRET_READ_RE.search, "AWS secret read"),
    (AWS_CREDENTIAL_ECHO_RE.search, "credential echo or dynamic credential read"),
)

"""HashiCorp Vault rules: dynamic credential reads and token printing."""

from __future__ import annotations

import re
from typing import Callable

VAULT_CREDENTIAL_READ_RE = re.compile(
    r"(?<![\w/])vault\s+(?:(?:read|write)\b[^\n;&|]*/(?:creds|sts)/|print\s+token\b)",
    re.IGNORECASE,
)

RULES: tuple[tuple[Callable[[str], object], str], ...] = (
    (VAULT_CREDENTIAL_READ_RE.search, "credential echo or dynamic credential read"),
)

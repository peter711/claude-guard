"""Detection of direct references to common secret files and directories."""

from __future__ import annotations

import re

# Templates are intentionally permitted. Extend only after reviewing risks.
SAFE_DOTENV_NAMES = frozenset({
    ".env.example", ".env.sample", ".env.template", ".env.dist"
})

# The patterns check file/path names, not arbitrary substrings like "environment".
DOTENV_RE = re.compile(
    r"(?<![A-Za-z0-9._-])\.env(?:\.[A-Za-z0-9_-]+)*(?![A-Za-z0-9._-])",
    re.IGNORECASE,
)
SECRET_DIRECTORY_RE = re.compile(
    r"(?<![A-Za-z0-9._-])(?:\.ssh(?:[/\\]|$)|"
    r"\.aws[/\\]credentials\b|\.kube[/\\]config\b|"
    r"\.config[/\\]gh[/\\]hosts\.yml\b)",
    re.IGNORECASE,
)
SECRET_FILE_RE = re.compile(
    r"(?<![A-Za-z0-9._-])(?:\.npmrc|\.pypirc|\.netrc|"
    r"id_rsa|id_ed25519|id_ecdsa|"
    r"credentials\.json|service-account\.json|"
    r"(?:[^/\\\s\"']+\.(?:pem|p12|pfx)))(?![A-Za-z0-9._-])",
    re.IGNORECASE,
)

# Checked in order after dotenv files; the first match determines the category.
SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (SECRET_DIRECTORY_RE, "credential directory or configuration"),
    (SECRET_FILE_RE, "key or credential file"),
)


def _refers_to_dotenv(text: str) -> bool:
    return any(
        match.group(0).lower() not in SAFE_DOTENV_NAMES
        for match in DOTENV_RE.finditer(text)
    )


def sensitive_reference(text: str) -> str | None:
    """Return a category for direct references to common secrets."""
    normalized = text.replace("\\", "/")
    if _refers_to_dotenv(normalized):
        return "dotenv file"
    for pattern, category in SECRET_PATTERNS:
        if pattern.search(normalized):
            return category
    return None

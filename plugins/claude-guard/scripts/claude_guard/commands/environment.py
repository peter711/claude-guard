"""Environment dump rules: commands that print the whole environment or its secret-bearing variables.

Best-effort and intentionally narrow: only common whole-environment dumps are matched.
Interpreter one-liners, container exec, service managers and nested shells beyond one
`sh -c` level are out of scope.
"""

from __future__ import annotations

import re
from typing import Callable

# A command word: start of text, after a separator/subshell opener, or after a
# shell keyword; optionally preceded by `VAR=x` assignments and thin wrappers.
START = (
    r"(?:^|[;&|(`{\n]|\$\(|\b(?:then|do|else|elif|if|while|until)\s)\s*"
    r"(?:\w+=\S*\s+)*(?:(?:command|builtin|exec|time|nohup)\s+)*"
    r"(?:/usr/bin/|/bin/|\\)?"
)
# What may follow a bare command: end of text, a separator, a redirect, ")" or a comment.
END = r"(?:$|[;&|)<>`\n#])"
BARE = r"(?:\s+(?:-0|--null))*\s*" + END
# Secret-looking variable names; `_PAT` must not match `_PATH`.
NAME = (
    r"\w*(?:SECRET|TOKEN|PASSW(?:OR)?D|API_?KEY|ACCESS_?KEY|PRIVATE_?KEY|CREDENTIAL|_PAT(?![A-Za-z0-9]))\w*"
)

# Case-sensitive: shell builtins are, and prose such as "Set" in text must not match.
SHELL_DUMP_RE = re.compile(
    START + r"(?:"
    r"env" + BARE +
    r"|printenv" + BARE +
    r"|export(?:\s+-[pn]+)*\s*" + END +
    r"|set\s*" + END +
    r"|(?:declare|typeset)\s*" + END +
    # `declare -p` / `declare -px` (but not `-f`/`-F`, which print functions).
    r"|(?:declare|typeset)\s+(?:-[a-zA-Z]+\s+)*-(?![a-zA-Z]*[fF])[a-zA-Z]*p[a-zA-Z]*(?=\s|$|[;&|)<>`])"
    # `declare -x` with no assignment lists exported variables.
    r"|(?:declare|typeset)\s+-(?![a-zA-Z]*[fF])[a-zA-Z]*x[a-zA-Z]*\s*" + END +
    r")"
)
# `ps e`, `ps eww`, `ps auxe`, `ps aux -e` print each process's environment.
PS_ENVIRON_RE = re.compile(
    START + r"ps\s+(?:[a-zA-Z]*e[a-zA-Z]*|[a-zA-Z]+\s+-e)(?=$|[\s;&|)<>`])"
)
# `printenv GITHUB_TOKEN`, `printenv HOME GH_TOKEN`; the name must be an argument.
PRINTENV_SECRET_RE = re.compile(
    START + r"printenv(?:\s+[^\s;&|<>]+)*?\s+['\"]?(?i:" + NAME + r")(?![\w])"
)
POWERSHELL_ENV_RE = re.compile(
    r"(?<![\w-])(?:Get-ChildItem|Get-Item|gci|gi|dir|ls)\s+(?:-Path\s+)?['\"]?env:"
    r"[\\/]?(?:\w*\*[\w*]*)?['\"]?(?=\s|$|[;&|)])"
    r"|\[(?:System\.)?Environment\]::GetEnvironmentVariables\s*\(",
    re.IGNORECASE,
)
# Text inside `sh -c '...'` / `bash -c "..."` is inspected once as a command of its own.
INNER_SHELL_RE = re.compile(
    r"(?<![\w.-])(?:[\w./-]*/)?(?:ba|z|da|k)?sh\s+(?:-[a-zA-Z]+\s+)*-[a-zA-Z]*c\s+"
    r"(?:'([^']*)'|\"([^\"]*)\"|([^\s'\"]+))"
)

_DIRECT = (SHELL_DUMP_RE, PS_ENVIRON_RE, PRINTENV_SECRET_RE, POWERSHELL_ENV_RE)


def _direct(command: str) -> bool:
    return any(pattern.search(command) for pattern in _DIRECT)


def dumps_environment(command: str) -> bool:
    """True for a whole-environment dump, also inside one level of `sh -c '...'`."""
    if _direct(command):
        return True
    return any(
        _direct(inner)
        for match in INNER_SHELL_RE.finditer(command)
        for inner in match.groups() if inner
    )


RULES: tuple[tuple[Callable[[str], object], str], ...] = (
    (dumps_environment, "environment dump"),
)

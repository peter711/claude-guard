"""Claude Guard policy checks (Python standard library only).

This is a best-effort guard for direct references, not a security boundary.
"""

from .commands import destructive_command
from .policy import check_event
from .sensitive_paths import sensitive_reference

__all__ = ["check_event", "destructive_command", "sensitive_reference"]

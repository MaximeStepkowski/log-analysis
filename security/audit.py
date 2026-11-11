"""Lightweight execution-scope audit using globals() and locals()."""

from collections.abc import Mapping
from typing import Any


def _describe_scope(scope_name: str, values: Mapping[str, Any]) -> list[dict[str, str]]:
    """Describe scope variables without exporting their values."""
    return [
        {
            "scope": scope_name,
            "name": name,
            "type": type(value).__name__,
        }
        for name, value in sorted(values.items())
        if not name.startswith("_")
    ]


def collect_execution_audit(extra_locals: Mapping[str, Any] | None = None) -> list[dict[str, str]]:
    """Collect variable names and types from global and local scopes."""
    global_scope = globals()
    local_scope = locals()
    audit = _describe_scope("globals", global_scope)
    audit.extend(_describe_scope("locals", local_scope))
    if extra_locals is not None:
        audit.extend(_describe_scope("pipeline", extra_locals))
    return audit

"""Generic engine for applying security rules."""

from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any, Callable, TypeAlias

from log_process.brute_force import BruteForceDetector

Record: TypeAlias = dict[str, Any]
Finding: TypeAlias = dict[str, Any]
SecurityRule: TypeAlias = Callable[..., Finding | None]


@dataclass
class SecurityContext:
    """State shared by rules while processing a stream."""

    blacklist: frozenset[str] = frozenset()
    http_errors_by_ip: defaultdict[str, int] = field(
        default_factory=lambda: defaultdict(int)
    )
    alerted_http_error_ips: set[str] = field(default_factory=set)
    brute_force_detector: BruteForceDetector = field(
        default_factory=BruteForceDetector
    )


def apply_security_rules(*args: SecurityRule, **kwargs: Any) -> list[Finding] | None:
    """Apply security functions to a record.

    Rules are received as first-class functions through ``*args``.
    The record and configuration are passed to each rule through ``**kwargs``.
    Each rule returns a structured finding or ``None``.
    """
    record = kwargs.get("record")
    if not isinstance(record, dict):
        raise TypeError("apply_security_rules attend un record via record=")

    sink = kwargs.get("_sink")
    findings = [] if sink is None else None

    # The main pipeline only uses the record, context, and a prepared sink.
    # This path avoids rebuilding the same kwargs for each rule while keeping
    # the generic path available for other calls.
    if sink is not None and set(kwargs) == {"record", "context", "_sink"}:
        context = kwargs["context"]
        for rule in args:
            if not callable(rule):
                raise TypeError("Toutes les règles doivent être appelables")
            finding = rule(record=record, context=context)
            if finding is not None:
                sink.append(finding)
        return None

    for rule in args:
        if not callable(rule):
            raise TypeError("Toutes les règles doivent être appelables")
        finding = rule(**kwargs)
        if finding is not None:
            if sink is None:
                findings.append(finding)
            else:
                sink.append(finding)
    return findings

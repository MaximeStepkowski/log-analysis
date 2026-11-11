"""Generate the security module's text report."""

from collections.abc import Iterable, Mapping
from pathlib import Path
from typing import Any

from security.audit import collect_execution_audit


def format_security_report(
    findings: Iterable[Mapping[str, Any]],
    *,
    audit: Iterable[Mapping[str, str]],
) -> str:
    """Build a report that is readable in a terminal."""
    finding_list = [
        finding for finding in findings
        if finding.get("rule") != "critical_level"
    ]
    lines = [
        "=== RAPPORT DE SECURITE ===",
        f"Nombre total de regles declenchees : {len(finding_list)}",
        "",
        "--- REGLES DECLENCHEES ---",
    ]

    if not finding_list:
        lines.append("Aucune regle de securite declenchee.")
    else:
        for index, finding in enumerate(finding_list, start=1):
            lines.extend([
                f"[{index}] {finding.get('rule', 'inconnue')}",
                f"    Message : {finding.get('message', '')}",
                f"    IP      : {finding.get('ip', 'N/A')}",
                f"    Date    : {finding.get('timestamp', 'N/A')}",
            ])
            details = [
                f"{key}={value}"
                for key, value in finding.items()
                if key not in {"rule", "message", "ip", "timestamp"}
            ]
            if details:
                lines.append(f"    Details : {', '.join(details)}")

    lines.extend(["", "--- AUDIT DES PORTEES ---"])
    for variable in audit:
        lines.append(
            f"{variable['scope']:<9} | {variable['name']:<28} | "
            f"{variable['type']}"
        )
    return "\n".join(lines) + "\n"


def write_security_report(
    findings: Iterable[Mapping[str, Any]],
    output: str | Path,
    *,
    audit_context: Mapping[str, Any] | None = None,
) -> str:
    """Write and return the security report content."""
    audit = collect_execution_audit(audit_context)
    content = format_security_report(findings, audit=audit)
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(content, encoding="utf-8")
    return content

from security import SecurityContext, apply_security_rules
from security.audit import collect_execution_audit
from security.report import write_security_report
from security.rules import (
    rule_blacklisted_ip,
    rule_brute_force,
    rule_http_errors,
)


RULES = (
    rule_blacklisted_ip,
    rule_http_errors,
    rule_brute_force,
)


def security_record(status=401, level="CRITICAL"):
    return {
        "ip": "192.0.2.10",
        "status": status,
        "level": level,
        "timestamp": "2026-11-11T12:00:00+00:00",
        "payload": "login failure",
    }


def test_apply_security_rules_accepts_first_class_functions_and_kwargs():
    context = SecurityContext(blacklist=frozenset({"192.0.2.10"}))
    findings = []
    for _ in range(3):
        findings = apply_security_rules(
            *RULES,
            record=security_record(),
            context=context,
            http_error_threshold=3,
        )

    assert {finding["rule"] for finding in findings} == {
        "blacklisted_ip",
        "http_error_threshold",
        "brute_force",
    }


def test_security_report_is_text_and_contains_audit(tmp_path):
    output = tmp_path / "security" / "report.txt"
    content = write_security_report(
        [{"rule": "critical_level", "message": "critical", "ip": "192.0.2.10"}],
        output,
        audit_context={"records": 3},
    )

    assert output.read_text(encoding="utf-8") == content
    assert "critical_level" not in content
    assert "--- AUDIT DES PORTEES ---" in content
    assert "pipeline" in content


def test_audit_uses_global_and_local_scopes():
    audit = collect_execution_audit({"records": 3})
    scopes = {entry["scope"] for entry in audit}

    assert {"globals", "locals", "pipeline"} <= scopes

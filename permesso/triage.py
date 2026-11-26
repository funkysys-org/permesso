"""Triage: dedupe, ordering, and rule-based remediation summaries.

The LLM layer is a pluggable hook: `enhance(findings, llm=callable)` — in the
productized version the agent runtime (e.g. Hermes) provides the callable and
rewrites evidence/impact in customer-facing language. Rule-based triage is the
always-available fallback.
"""
from __future__ import annotations

from .findings import Finding, Severity

DEFAULT_REMEDIATION = {
    "headers": "Add the missing security header at the web server or reverse "
               "proxy level and verify with a repeat scan.",
    "tls": "Renew or reconfigure the TLS certificate; disable legacy protocols "
           "and weak ciphers.",
    "vuln": "Update the affected component and re-test to confirm the fix.",
    "ssh": "Disable weak/legacy SSH algorithms in sshd_config and re-run the audit.",
    "hardening": "Apply the hardening suggestion and re-run the audit to raise the index.",
}


def rule_remediation(finding: Finding) -> str:
    if finding.remediation:
        return finding.remediation
    return DEFAULT_REMEDIATION.get(finding.category, "Investigate and remediate, then re-scan.")


def enhance(findings: list[Finding], llm=None) -> list[Finding]:
    """Apply remediation defaults; optionally hand each finding to an LLM."""
    for f in findings:
        f.remediation = rule_remediation(f)
        if llm:
            try:
                f.remediation = llm(f) or f.remediation
            except Exception:
                pass  # LLM layer must never break a scan
    return findings


def executive_summary(counts: dict[str, int], target: str) -> str:
    critical, high = counts.get("CRITICAL", 0), counts.get("HIGH", 0)
    medium, low = counts.get("MEDIUM", 0), counts.get("LOW", 0)
    if critical:
        tone = f"{critical} critical issue(s) need attention now"
    elif high:
        tone = f"{high} high-severity issue(s) need prompt attention"
    elif medium or low:
        tone = "no critical or high-severity issues, but hardening is recommended"
    else:
        tone = "no issues detected by the enabled checks"
    return (
        f"Scan of {target} found {critical} critical, {high} high, {medium} medium "
        f"and {low} low severity findings — {tone}."
    )

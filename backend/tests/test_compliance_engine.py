"""
NetAudit AI - Phase 2-4 Integration Unit Tests for Compliance & Risk Engine
"""

import os
from backend.parsers.cisco import CiscoParser
from backend.rules.engine import ComplianceEngine
from backend.risk.scoring import RiskScoringEngine

DATASET_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../datasets/raw_configs/cisco/cisco_router_01.cfg")
)


def test_full_cisco_compliance_audit():
    with open(DATASET_PATH, "r") as f:
        content = f.read()

    # 1. Parse Config
    parser = CiscoParser()
    norm_config = parser.parse(content)

    # 2. Run Deterministic Compliance Engine
    engine = ComplianceEngine()
    findings = engine.run_audit(norm_config)

    assert len(findings) > 0, "Compliance engine returned zero findings for misconfigured router!"

    rule_ids = [f.rule_id for f in findings]

    # Verify specific critical rule detections
    assert "ACL-001" in rule_ids, "Missing ACL-001 Broad Any-to-Any Rule Finding"
    assert "ACL-002" in rule_ids, "Missing ACL-002 Unrestricted Admin SSH Finding"
    assert "ACL-003" in rule_ids, "Missing ACL-003 Unlogged Permit Rule Finding"
    assert "MGMT-001" in rule_ids, "Missing MGMT-001 Unencrypted Passwords Finding"
    assert "MGMT-002" in rule_ids, "Missing MGMT-002 Insecure HTTP Server Finding"
    assert "MGMT-003" in rule_ids, "Missing MGMT-003 Cleartext Telnet Finding"
    assert "MGMT-004" in rule_ids, "Missing MGMT-004 Insecure SNMP RW Finding"

    # 3. Calculate Risk Score
    scorer = RiskScoringEngine()
    risk = scorer.calculate_risk(findings, norm_config)

    assert risk.overall_score >= 75.0, f"Expected Critical risk (>=75), got {risk.overall_score}"
    assert risk.risk_level == "Critical"
    assert len(risk.reasons) > 0

    print(f"\n[AUDIT RESULTS SUMMARY]")
    print(f"Device Name    : {norm_config.device_name}")
    print(f"Total Findings : {len(findings)}")
    print(f"Overall Risk   : {risk.overall_score} / 100 ({risk.risk_level})")
    print(f"Finding Breakdown: {risk.finding_counts}")
    print("Top Risk Explanations:")
    for r in risk.reasons[:5]:
        print(f"  - {r}")


if __name__ == "__main__":
    print("Running Compliance & Risk Engine Integration Tests...")
    test_full_cisco_compliance_audit()
    print("[PASS] test_full_cisco_compliance_audit")
    print("\nPHASES 2-4 COMPLIANCE & RISK ENGINE TESTS PASSED!")

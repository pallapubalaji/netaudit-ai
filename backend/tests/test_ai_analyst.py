"""
NetAudit AI - Phase 8-9 AI Security Analyst & Remediation Test Suite
"""

import os
from backend.parsers.cisco import CiscoParser
from backend.rules.engine import ComplianceEngine
from backend.ai.analyst import AISecurityAnalyst
from backend.normalization.models import VendorEnum

CISCO_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../datasets/raw_configs/cisco/cisco_router_01.cfg")
)


def test_ai_security_analyst_explanation_and_remediation():
    with open(CISCO_PATH) as f:
        content = f.read()

    parser = CiscoParser()
    norm = parser.parse(content)

    engine = ComplianceEngine()
    findings = engine.run_audit(norm)

    analyst = AISecurityAnalyst()

    # 1. Test Executive Summary Generation
    exec_summary = analyst.generate_executive_summary(norm, findings)
    assert exec_summary["vendor"] == "cisco"
    assert exec_summary["total_findings"] == len(findings)
    assert exec_summary["payload_evidence_bounded"] is True

    # 2. Test Individual Finding Explanation & Multi-Vendor Remediation
    crit_finding = next(f for f in findings if f.rule_id == "ACL-001")
    exp = analyst.generate_finding_explanation(crit_finding, VendorEnum.CISCO)

    assert exp["rule_id"] == "ACL-001"
    assert "REVIEW BEFORE DEPLOYMENT" in exp["remediation"]["deployment_warning"]
    assert "no permit ip any any" in exp["remediation"]["vendor_cli"]

    # Test Fortinet remediation for same rule
    exp_forti = analyst.generate_finding_explanation(crit_finding, VendorEnum.FORTINET)
    assert "config firewall policy" in exp_forti["remediation"]["vendor_cli"]

    # Test Palo Alto remediation for same rule
    exp_pa = analyst.generate_finding_explanation(crit_finding, VendorEnum.PALO_ALTO)
    assert "set security rules" in exp_pa["remediation"]["vendor_cli"]

    print("[PASS] test_ai_security_analyst_explanation_and_remediation")


if __name__ == "__main__":
    print("Running AI Security Analyst Tests...")
    test_ai_security_analyst_explanation_and_remediation()
    print("\nALL AI ANALYST & REMEDIATION TESTS PASSED!")

"""
NetAudit AI - Multi-Vendor Parsing & Vendor-Neutral Compliance Test Suite
Tests Cisco, Fortinet, and Palo Alto parser normalization against common compliance engine.
"""

import os
from backend.parsers.detector import VendorDetector
from backend.parsers.cisco import CiscoParser
from backend.parsers.fortinet import FortinetParser
from backend.parsers.paloalto import PaloAltoParser
from backend.rules.engine import ComplianceEngine
from backend.risk.scoring import RiskScoringEngine
from backend.normalization.models import VendorEnum

CISCO_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../datasets/raw_configs/cisco/cisco_router_01.cfg")
)
FORTINET_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../datasets/raw_configs/fortinet/fortigate_01.cfg")
)
PALOALTO_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../datasets/raw_configs/paloalto/paloalto_01.xml")
)


def test_vendor_detection_all():
    with open(CISCO_PATH) as f:
        assert VendorDetector.detect_vendor(f.read()) == VendorEnum.CISCO
    with open(FORTINET_PATH) as f:
        assert VendorDetector.detect_vendor(f.read()) == VendorEnum.FORTINET
    with open(PALOALTO_PATH) as f:
        assert VendorDetector.detect_vendor(f.read()) == VendorEnum.PALO_ALTO
    print("[PASS] test_vendor_detection_all")


def test_fortinet_parsing_and_audit():
    with open(FORTINET_PATH) as f:
        content = f.read()

    parser = FortinetParser()
    norm = parser.parse(content)

    assert norm.vendor == VendorEnum.FORTINET
    assert norm.device_name == "FW-FG100E-Edge"
    assert len(norm.security_rules) == 3
    assert norm.management.http_server_enabled is True
    assert norm.management.telnet_enabled is True

    # Run Compliance Audit
    engine = ComplianceEngine()
    findings = engine.run_audit(norm)

    rule_ids = [f.rule_id for f in findings]
    assert "ACL-001" in rule_ids  # Excessive any-allow policy
    assert "ACL-002" in rule_ids  # Unrestricted SSH policy
    assert "MGMT-002" in rule_ids # Insecure HTTP port 80 enabled
    assert "MGMT-003" in rule_ids # Telnet enabled

    scorer = RiskScoringEngine()
    risk = scorer.calculate_risk(findings, norm)
    assert risk.overall_score >= 75.0
    print(f"[PASS] test_fortinet_parsing_and_audit (Risk: {risk.overall_score}/100 - {risk.risk_level})")


def test_paloalto_parsing_and_audit():
    with open(PALOALTO_PATH) as f:
        content = f.read()

    parser = PaloAltoParser()
    norm = parser.parse(content)

    assert norm.vendor == VendorEnum.PALO_ALTO
    assert norm.device_name == "PA-5220-Datacenter"
    assert len(norm.security_rules) == 3
    assert norm.management.http_server_enabled is True
    assert norm.management.telnet_enabled is True

    # Run Compliance Audit
    engine = ComplianceEngine()
    findings = engine.run_audit(norm)

    rule_ids = [f.rule_id for f in findings]
    assert "ACL-001" in rule_ids  # Excessive any-allow policy
    assert "ACL-002" in rule_ids  # Unrestricted SSH policy
    assert "MGMT-002" in rule_ids # Disable-http is no
    assert "MGMT-003" in rule_ids # Disable-telnet is no

    scorer = RiskScoringEngine()
    risk = scorer.calculate_risk(findings, norm)
    assert risk.overall_score >= 75.0
    print(f"[PASS] test_paloalto_parsing_and_audit (Risk: {risk.overall_score}/100 - {risk.risk_level})")


if __name__ == "__main__":
    print("Running Multi-Vendor Multi-Parser Tests...")
    test_vendor_detection_all()
    test_fortinet_parsing_and_audit()
    test_paloalto_parsing_and_audit()
    print("\nALL MULTI-VENDOR PARSER & COMPLIANCE TESTS PASSED!")

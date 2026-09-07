"""
NetAudit AI - Phase 1 Unit Tests for Cisco Parser and Vendor Detector
"""

import os
try:
    import pytest
except ImportError:
    pytest = None

from backend.parsers.detector import VendorDetector
from backend.parsers.cisco import CiscoParser
from backend.normalization.models import VendorEnum, ActionEnum, ProtocolEnum

# Path to sample dataset
DATASET_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../datasets/raw_configs/cisco/cisco_router_01.cfg")
)


def test_vendor_detector_cisco():
    with open(DATASET_PATH, "r") as f:
        content = f.read()

    vendor = VendorDetector.detect_vendor(content)
    assert vendor == VendorEnum.CISCO, f"Expected CISCO, got {vendor}"


def test_vendor_detector_unknown():
    sample = "invalid config content line 1\nline 2"
    vendor = VendorDetector.detect_vendor(sample)
    assert vendor == VendorEnum.UNKNOWN, f"Expected UNKNOWN, got {vendor}"


def test_cisco_parser_metadata_and_management():
    with open(DATASET_PATH, "r") as f:
        content = f.read()

    parser = CiscoParser()
    norm = parser.parse(content)

    assert norm.vendor == VendorEnum.CISCO
    assert norm.device_name == "Core-Edge-Router-01"
    assert norm.os_version == "15.6"
    assert norm.management.domain_name == "corporate.local"
    assert norm.management.http_server_enabled is True
    assert norm.management.https_server_enabled is False
    assert norm.management.password_encryption_enabled is False
    assert norm.management.aaa_enabled is False
    assert len(norm.management.snmp_communities) == 2


def test_cisco_parser_interfaces():
    with open(DATASET_PATH, "r") as f:
        content = f.read()

    parser = CiscoParser()
    norm = parser.parse(content)

    assert len(norm.interfaces) == 3
    wan_if = next((i for i in norm.interfaces if i.name == "GigabitEthernet0/0"), None)
    assert wan_if is not None
    assert wan_if.ip_address == "203.0.113.1"
    assert wan_if.inbound_acl == "OUTSIDE_IN"
    assert wan_if.outbound_acl == "OUTSIDE_OUT"


def test_cisco_parser_rules():
    with open(DATASET_PATH, "r") as f:
        content = f.read()

    parser = CiscoParser()
    norm = parser.parse(content)

    assert len(norm.security_rules) >= 6

    outside_rules = [r for r in norm.security_rules if r.rule_name == "OUTSIDE_IN"]
    assert len(outside_rules) == 4

    # Rule 1: HTTP allow log
    r1 = outside_rules[0]
    assert r1.action == ActionEnum.ALLOW
    assert r1.services[0].protocol == ProtocolEnum.TCP
    assert r1.services[0].port_range == "www"
    assert r1.logging_enabled is True

    # Rule 3: Unlogged SSH
    r3 = outside_rules[2]
    assert r3.action == ActionEnum.ALLOW
    assert r3.services[0].port_range == "22"
    assert r3.logging_enabled is False

    # Rule 4: Any-to-Any IP Allow
    r4 = outside_rules[3]
    assert r4.action == ActionEnum.ALLOW
    assert r4.sources[0].address_type == "any"
    assert r4.destinations[0].address_type == "any"
    assert r4.logging_enabled is False



if __name__ == "__main__":
    print("Running NetAudit AI Phase 1 Tests...")
    test_vendor_detector_cisco()
    print("[PASS] test_vendor_detector_cisco")
    test_vendor_detector_unknown()
    print("[PASS] test_vendor_detector_unknown")
    test_cisco_parser_metadata_and_management()
    print("[PASS] test_cisco_parser_metadata_and_management")
    test_cisco_parser_interfaces()
    print("[PASS] test_cisco_parser_interfaces")
    test_cisco_parser_rules()
    print("[PASS] test_cisco_parser_rules")
    print("\nALL PHASE 1 TESTS PASSED SUCCESSFULLY!")



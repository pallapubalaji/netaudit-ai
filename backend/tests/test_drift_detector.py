"""
NetAudit AI - Phase 10 Configuration Drift Detector Test Suite
"""

import os
from backend.parsers.cisco import CiscoParser
from backend.rules.engine import ComplianceEngine
from backend.risk.scoring import RiskScoringEngine
from backend.drift.detector import DriftDetector

V1_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../datasets/raw_configs/cisco/cisco_router_01.cfg")
)
V2_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../datasets/raw_configs/cisco/cisco_router_02_drift.cfg")
)


def test_configuration_drift_detection():
    with open(V1_PATH) as f:
        v1_text = f.read()
    with open(V2_PATH) as f:
        v2_text = f.read()

    parser = CiscoParser()
    v1_config = parser.parse(v1_text)
    v2_config = parser.parse(v2_text)

    engine = ComplianceEngine()
    v1_findings = engine.run_audit(v1_config)
    v2_findings = engine.run_audit(v2_config)

    scorer = RiskScoringEngine()
    v1_risk = scorer.calculate_risk(v1_findings, v1_config)
    v2_risk = scorer.calculate_risk(v2_findings, v2_config)

    detector = DriftDetector()
    drift = detector.compare_versions(v1_config, v2_config, v1_risk, v2_risk, v1_findings, v2_findings)

    assert drift.has_drift is True
    assert drift.hash_changed is True
    assert drift.old_hash != drift.new_hash
    assert len(drift.summary) > 0

    print("\n[DRIFT DETECTION REPORT]")
    print(drift.summary)
    print(f"Old Hash: {drift.old_hash[:12]}... -> New Hash: {drift.new_hash[:12]}...")
    print(f"Risk Shift: {drift.old_risk_score} ({drift.old_risk_level}) -> {drift.new_risk_score} ({drift.new_risk_level})")
    print(f"Added Rules: {len(drift.added_rules)}, Removed: {len(drift.removed_rules)}, Modified: {len(drift.modified_rules)}")
    print("[PASS] test_configuration_drift_detection")


if __name__ == "__main__":
    print("Running Drift Detector Tests...")
    test_configuration_drift_detection()
    print("\nALL DRIFT DETECTOR TESTS PASSED!")

"""
NetAudit AI - Phase 12 Attack Path Analysis Test Suite
"""

import os
from backend.parsers.cisco import CiscoParser
from backend.rules.engine import ComplianceEngine
from backend.attack_paths.graph import AttackPathAnalyzer

CISCO_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../datasets/raw_configs/cisco/cisco_router_01.cfg")
)


def test_attack_path_analysis():
    with open(CISCO_PATH) as f:
        content = f.read()

    parser = CiscoParser()
    norm = parser.parse(content)

    engine = ComplianceEngine()
    findings = engine.run_audit(norm)

    analyzer = AttackPathAnalyzer()
    paths = analyzer.analyze_attack_paths(norm, findings)

    assert len(paths) > 0, "Expected attack paths generated for misconfigured Cisco router"
    p1 = paths[0]

    assert p1.path_id.startswith("ATTACK-PATH-")
    assert len(p1.nodes) == 5
    assert len(p1.edges) == 4
    assert "Exploitability Not Verified" in p1.disclaimer

    print(f"\n[ATTACK PATH ANALYSIS RESULT]")
    print(f"Path ID   : {p1.path_id}")
    print(f"Title     : {p1.title}")
    print(f"Risk      : {p1.risk_level}")
    print("Steps:")
    for step in p1.path_steps:
        print(f"  --> {step}")
    print(f"Disclaimer: {p1.disclaimer}")
    print("[PASS] test_attack_path_analysis")


if __name__ == "__main__":
    print("Running Attack Path Analysis Tests...")
    test_attack_path_analysis()
    print("\nALL ATTACK PATH TESTS PASSED!")

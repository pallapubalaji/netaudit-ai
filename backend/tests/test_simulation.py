"""
NetAudit AI - Phase 13 What-If Security Simulation Test Suite
"""

import os
from backend.parsers.cisco import CiscoParser
from backend.simulation.simulator import WhatIfSimulator

CISCO_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "../../datasets/raw_configs/cisco/cisco_router_01.cfg")
)


def test_what_if_simulation():
    with open(CISCO_PATH) as f:
        content = f.read()

    parser = CiscoParser()
    norm = parser.parse(content)

    simulator = WhatIfSimulator()

    # Simulate modifying SSH rule (CISCO-OUTSIDE_IN-003)
    ssh_rule = next(r for r in norm.security_rules if any(s.port_range == "22" for s in r.services))
    target_rule = ssh_rule.rule_id
    result = simulator.simulate_rule_modification(
        original_config=norm,
        target_rule_id=target_rule,
        new_source_ip_or_subnet="192.168.1.0/24",
    )


    assert result.simulation_only is True
    assert result.raw_points_reduced > 0.0, "Expected positive raw risk points reduction after restricting SSH source"
    assert len(result.resolved_finding_ids) > 0
    assert len(result.potential_side_effects) > 0

    print(f"\n[WHAT-IF SECURITY SIMULATION RESULT]")
    print(f"Target Rule Modified : {result.rule_id_modified}")
    print(f"Proposed Change      : {result.proposed_change_summary}")
    print(f"Risk Score Before    : {result.before_risk.overall_score} ({result.before_risk.risk_level})")
    print(f"Risk Score After     : {result.after_risk.overall_score} ({result.after_risk.risk_level})")
    print(f"Raw Points Reduced   : -{result.raw_points_reduced} pts")
    print(f"Resolved Findings    : {len(result.resolved_finding_ids)}")
    print(f"Potential Side Effects: {result.potential_side_effects[0]}")
    print("[PASS] test_what_if_simulation")



if __name__ == "__main__":
    print("Running What-If Simulation Tests...")
    test_what_if_simulation()
    print("\nALL WHAT-IF SIMULATION TESTS PASSED!")

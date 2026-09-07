"""
NetAudit AI - What-If Security Simulation Engine
Allows non-destructive in-memory policy modification dry-runs to measure risk delta before deployment.
"""

import copy
from typing import List, Dict, Any
from pydantic import BaseModel, Field
from backend.normalization.models import NormalizedConfig, NetworkEndpoint
from backend.rules.engine import ComplianceEngine
from backend.risk.scoring import RiskScoringEngine, RiskBreakdown


class SimulationResult(BaseModel):
    rule_id_modified: str
    proposed_change_summary: str
    before_risk: RiskBreakdown
    after_risk: RiskBreakdown
    raw_points_reduced: float = Field(description="Total raw risk points reduced by policy change")
    risk_improvement: float = Field(description="Normalized points reduced (0-100 scale)")
    resolved_finding_ids: List[str]
    remaining_finding_ids: List[str]
    potential_side_effects: List[str]
    simulation_only: bool = True



class WhatIfSimulator:
    def simulate_rule_modification(
        self,
        original_config: NormalizedConfig,
        target_rule_id: str,
        new_source_ip_or_subnet: str,
    ) -> SimulationResult:
        # Clone normalized config for isolated dry-run
        sim_config = copy.deepcopy(original_config)

        engine = ComplianceEngine()
        scorer = RiskScoringEngine()

        # Audit original config
        orig_findings = engine.run_audit(original_config)
        orig_risk = scorer.calculate_risk(orig_findings, original_config)

        # Modify rule in simulated config
        rule_found = False
        for r in sim_config.security_rules:
            if r.rule_id == target_rule_id:
                rule_found = True
                r.sources = [
                    NetworkEndpoint(
                        raw_value=new_source_ip_or_subnet,
                        address_type="subnet" if "/" in new_source_ip_or_subnet else "host",
                        ip_or_subnet=new_source_ip_or_subnet,
                    )
                ]
                break

        if not rule_found:
            raise ValueError(f"Rule ID '{target_rule_id}' not found in configuration.")

        # Re-audit simulated config
        sim_findings = engine.run_audit(sim_config)
        sim_risk = scorer.calculate_risk(sim_findings, sim_config)

        orig_f_ids = {f.finding_id for f in orig_findings}
        sim_f_ids = {f.finding_id for f in sim_findings}

        resolved = list(orig_f_ids - sim_f_ids)
        remaining = list(sim_f_ids)
        improvement = round(orig_risk.overall_score - sim_risk.overall_score, 1)

        orig_raw = orig_risk.severity_points + orig_risk.exposure_penalty + orig_risk.asset_criticality_penalty
        sim_raw = sim_risk.severity_points + sim_risk.exposure_penalty + sim_risk.asset_criticality_penalty
        raw_reduced = round(orig_raw - sim_raw, 1)

        side_effects = []
        if new_source_ip_or_subnet != "any":
            side_effects.append(f"Legitimate traffic from sources outside '{new_source_ip_or_subnet}' will be dropped.")

        return SimulationResult(
            rule_id_modified=target_rule_id,
            proposed_change_summary=f"Restrict source in rule {target_rule_id} to '{new_source_ip_or_subnet}'",
            before_risk=orig_risk,
            after_risk=sim_risk,
            raw_points_reduced=raw_reduced,
            risk_improvement=improvement,
            resolved_finding_ids=resolved,
            remaining_finding_ids=remaining,
            potential_side_effects=side_effects,
        )


"""
NetAudit AI - Explainable 0-100 Risk Scoring Engine
Calculates reproducible risk score with step-by-step breakdown based on findings and asset exposure.
"""

from typing import List, Dict, Any
from pydantic import BaseModel, Field
from backend.rules.models import Finding, SeverityEnum
from backend.normalization.models import NormalizedConfig


class RiskBreakdown(BaseModel):
    overall_score: float = Field(description="Normalized overall risk score between 0 and 100")
    risk_level: str = Field(description="Low (0-24), Medium (25-49), High (50-74), Critical (75-100)")
    finding_counts: Dict[str, int]
    severity_points: float
    exposure_penalty: float
    asset_criticality_penalty: float
    reasons: List[str] = Field(default_factory=list)


class RiskScoringEngine:
    SEVERITY_WEIGHTS = {
        SeverityEnum.CRITICAL: 25.0,
        SeverityEnum.HIGH: 15.0,
        SeverityEnum.MEDIUM: 8.0,
        SeverityEnum.LOW: 3.0,
        SeverityEnum.INFO: 0.0,
    }

    def calculate_risk(self, findings: List[Finding], norm_config: NormalizedConfig) -> RiskBreakdown:
        severity_points = 0.0
        exposure_penalty = 0.0
        asset_criticality_penalty = 0.0
        reasons: List[str] = []

        finding_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for finding in findings:
            finding_counts[finding.severity.value] += 1
            pts = self.SEVERITY_WEIGHTS.get(finding.severity, 0.0)
            severity_points += pts

            # Exposure check: Is finding exposed to Internet / WAN interface?
            if "any" in finding.evidence.lower() or "outside_in" in finding.evidence.lower() or "0.0.0.0" in finding.evidence:
                penalty = pts * 0.4
                exposure_penalty += penalty
                reasons.append(f"[{finding.rule_id}] Exposed to external/unrestricted sources (+{penalty:.1f} pts)")

            # Asset criticality check: Is finding affecting management / line vty / WAN?
            if "Line VTY" in finding.affected_asset or "Web Management" in finding.affected_asset or "SNMP" in finding.affected_asset:
                penalty = pts * 0.3
                asset_criticality_penalty += penalty
                reasons.append(f"[{finding.rule_id}] Impacts critical administrative asset '{finding.affected_asset}' (+{penalty:.1f} pts)")

        raw_score = severity_points + exposure_penalty + asset_criticality_penalty
        overall_score = min(100.0, max(0.0, raw_score))

        if overall_score >= 75.0:
            risk_level = "Critical"
        elif overall_score >= 50.0:
            risk_level = "High"
        elif overall_score >= 25.0:
            risk_level = "Medium"
        else:
            risk_level = "Low"

        return RiskBreakdown(
            overall_score=round(overall_score, 1),
            risk_level=risk_level,
            finding_counts=finding_counts,
            severity_points=round(severity_points, 1),
            exposure_penalty=round(exposure_penalty, 1),
            asset_criticality_penalty=round(asset_criticality_penalty, 1),
            reasons=reasons[:10],  # Top 10 key drivers
        )

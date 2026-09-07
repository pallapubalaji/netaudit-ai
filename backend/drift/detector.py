"""
NetAudit AI - Configuration Drift Detector
Compares configuration versions and calculates security posture drift delta.
"""

from typing import List, Dict, Any
from pydantic import BaseModel, Field
from backend.normalization.models import NormalizedConfig
from backend.rules.models import Finding
from backend.risk.scoring import RiskBreakdown


class RuleDiff(BaseModel):
    rule_id: str
    rule_name: str
    change_type: str = Field(description="ADDED, REMOVED, MODIFIED")
    details: str
    old_raw: str = ""
    new_raw: str = ""


class DriftReport(BaseModel):
    has_drift: bool
    hash_changed: bool
    old_hash: str
    new_hash: str
    added_rules: List[RuleDiff] = Field(default_factory=list)
    removed_rules: List[RuleDiff] = Field(default_factory=list)
    modified_rules: List[RuleDiff] = Field(default_factory=list)
    old_risk_score: float
    new_risk_score: float
    risk_score_delta: float
    old_risk_level: str
    new_risk_level: str
    new_findings_count: int
    resolved_findings_count: int
    summary: str


class DriftDetector:
    def compare_versions(
        self,
        old_config: NormalizedConfig,
        new_config: NormalizedConfig,
        old_risk: RiskBreakdown,
        new_risk: RiskBreakdown,
        old_findings: List[Finding],
        new_findings: List[Finding],
    ) -> DriftReport:
        hash_changed = old_config.raw_hash != new_config.raw_hash

        old_rules_map = {f"{r.rule_name}:{r.line_number}": r for r in old_config.security_rules}
        new_rules_map = {f"{r.rule_name}:{r.line_number}": r for r in new_config.security_rules}

        added: List[RuleDiff] = []
        removed: List[RuleDiff] = []
        modified: List[RuleDiff] = []

        # Find added or modified rules
        for k_new, r_new in new_rules_map.items():
            if k_new not in old_rules_map:
                added.append(
                    RuleDiff(
                        rule_id=r_new.rule_id,
                        rule_name=r_new.rule_name,
                        change_type="ADDED",
                        details=f"New rule added to ACL {r_new.rule_name}",
                        new_raw=r_new.raw_text,
                    )
                )
            else:
                r_old = old_rules_map[k_new]
                if r_old.raw_text != r_new.raw_text:
                    modified.append(
                        RuleDiff(
                            rule_id=r_new.rule_id,
                            rule_name=r_new.rule_name,
                            change_type="MODIFIED",
                            details="Configuration directive changed",
                            old_raw=r_old.raw_text,
                            new_raw=r_new.raw_text,
                        )
                    )

        # Find removed rules
        for k_old, r_old in old_rules_map.items():
            if k_old not in new_rules_map:
                removed.append(
                    RuleDiff(
                        rule_id=r_old.rule_id,
                        rule_name=r_old.rule_name,
                        change_type="REMOVED",
                        details=f"Rule removed from ACL {r_old.rule_name}",
                        old_raw=r_old.raw_text,
                    )
                )

        old_finding_ids = {f.finding_id for f in old_findings}
        new_finding_ids = {f.finding_id for f in new_findings}

        new_findings_count = len(new_finding_ids - old_finding_ids)
        resolved_findings_count = len(old_finding_ids - new_finding_ids)

        delta = round(new_risk.overall_score - old_risk.overall_score, 1)
        has_drift = hash_changed or bool(added or removed or modified)

        summary = (
            f"Configuration Drift Detected: Score shifted from {old_risk.overall_score} ({old_risk.risk_level}) "
            f"to {new_risk.overall_score} ({new_risk.risk_level}) [Delta: {delta:+.1f}]. "
            f"Detected {len(added)} added, {len(removed)} removed, {len(modified)} modified rules."
        )

        return DriftReport(
            has_drift=has_drift,
            hash_changed=hash_changed,
            old_hash=old_config.raw_hash,
            new_hash=new_config.raw_hash,
            added_rules=added,
            removed_rules=removed,
            modified_rules=modified,
            old_risk_score=old_risk.overall_score,
            new_risk_score=new_risk.overall_score,
            risk_score_delta=delta,
            old_risk_level=old_risk.risk_level,
            new_risk_level=new_risk.risk_level,
            new_findings_count=new_findings_count,
            resolved_findings_count=resolved_findings_count,
            summary=summary,
        )

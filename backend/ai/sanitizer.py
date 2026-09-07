"""
NetAudit AI - AI Evidence Sanitizer & Prompt Guard
Strips unneeded raw context and bounds inputs to deterministic evidence only.
"""

from typing import List, Dict, Any
from backend.rules.models import Finding
from backend.normalization.models import NormalizedConfig


class AIEvidenceSanitizer:
    @staticmethod
    def prepare_analyst_payload(norm_config: NormalizedConfig, findings: List[Finding]) -> Dict[str, Any]:
        """
        Extracts ONLY verified deterministic findings and sanitized metadata for the AI prompt.
        Prevents prompt injection by stripping unparsed raw config lines.
        """
        sanitized_findings = []
        for f in findings:
            sanitized_findings.append({
                "rule_id": f.rule_id,
                "title": f.title,
                "category": f.category.value,
                "severity": f.severity.value,
                "evidence": f.evidence,
                "line_number": f.line_number,
                "affected_asset": f.affected_asset,
                "nist_csf": f.compliance_mapping.nist_csf,
                "recommendation_base": f.recommendation,
            })

        return {
            "vendor": norm_config.vendor.value,
            "device_name": norm_config.device_name,
            "os_version": norm_config.os_version or "Unknown",
            "findings_count": len(findings),
            "findings": sanitized_findings,
        }

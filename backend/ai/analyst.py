"""
NetAudit AI - AI Security Analyst Engine
Generates explainable threat summaries and vendor-specific remediation guidance over verified evidence.
"""

from typing import Dict, Any, List
from backend.normalization.models import NormalizedConfig, VendorEnum
from backend.rules.models import Finding
from backend.ai.sanitizer import AIEvidenceSanitizer


class AISecurityAnalyst:
    """
    Operates above verified deterministic findings.
    Provides structured explanations, risk impact summaries, and vendor-specific remediation.
    """

    def generate_finding_explanation(self, finding: Finding, vendor: VendorEnum) -> Dict[str, Any]:
        """Explains an individual finding with strict evidence attribution."""
        evidence_str = finding.evidence

        explanation = (
            f"Rule '{finding.title}' ({finding.rule_id}) triggered on {finding.affected_asset}. "
            f"Deterministic evidence shows: '{evidence_str}' at line {finding.line_number}."
        )

        impact = (
            f"Severity is classified as {finding.severity.value}. "
            f"This misconfiguration increases attack surface exposure and aligns with NIST CSF control {finding.compliance_mapping.nist_csf or 'N/A'}."
        )

        remediation_cli = self._generate_vendor_cli(finding.rule_id, vendor)

        return {
            "finding_id": finding.finding_id,
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.value,
            "verified_evidence": evidence_str,
            "explanation": explanation,
            "security_impact": impact,
            "remediation": {
                "summary": finding.recommendation,
                "vendor_cli": remediation_cli,
                "deployment_warning": "REVIEW BEFORE DEPLOYMENT - DO NOT AUTOMATICALLY EXECUTE ON PRODUCTION DEVICES",
            },
        }

    def generate_executive_summary(self, norm_config: NormalizedConfig, findings: List[Finding]) -> Dict[str, Any]:
        """Generates an overall security audit summary for executive & technical dashboard."""
        payload = AIEvidenceSanitizer.prepare_analyst_payload(norm_config, findings)
        crit_count = sum(1 for f in findings if f.severity.value == "CRITICAL")
        high_count = sum(1 for f in findings if f.severity.value == "HIGH")

        summary_text = (
            f"Audit completed for device '{norm_config.device_name}' ({norm_config.vendor.value.upper()}). "
            f"Identified {len(findings)} total deterministic security compliance findings ({crit_count} Critical, {high_count} High). "
            f"Primary risk drivers are unlogged/broad access control policies and unencrypted/cleartext management services."
        )

        return {
            "device_name": norm_config.device_name,
            "vendor": norm_config.vendor.value,
            "total_findings": len(findings),
            "critical_findings": crit_count,
            "high_findings": high_count,
            "executive_summary": summary_text,
            "payload_evidence_bounded": True,
        }

    def _generate_vendor_cli(self, rule_id: str, vendor: VendorEnum) -> str:
        """Generates accurate vendor-specific CLI commands for remediation."""
        cli_map = {
            "ACL-001": {
                VendorEnum.CISCO: "no permit ip any any\npermit ip 192.168.1.0 0.0.0.255 10.0.10.0 0.0.0.255 log",
                VendorEnum.FORTINET: "config firewall policy\n  edit <policy_id>\n    set srcaddr 'Corporate_LAN'\n    set dstaddr 'DMZ_Subnet'\n  next\nend",
                VendorEnum.PALO_ALTO: "set security rules <rule_name> source Corporate_LAN destination DMZ_Subnet",
            },
            "ACL-002": {
                VendorEnum.CISCO: "ip access-list extended ADMIN_ONLY\n  permit tcp 192.168.1.0 0.0.0.255 host 192.168.1.5 eq 22 log",
                VendorEnum.FORTINET: "config firewall policy\n  edit <policy_id>\n    set srcaddr 'Admin_Subnet'\n  next\nend",
                VendorEnum.PALO_ALTO: "set security rules <rule_name> source Admin_Subnet",
            },
            "MGMT-001": {
                VendorEnum.CISCO: "service password-encryption",
                VendorEnum.FORTINET: "config system admin\n  edit admin\n    set password <strong_password>\n  next\nend",
                VendorEnum.PALO_ALTO: "set mgt-config users admin password",
            },
            "MGMT-002": {
                VendorEnum.CISCO: "no ip http server\nip http secure-server",
                VendorEnum.FORTINET: "config system global\n  set admin-sport 8443\nend",
                VendorEnum.PALO_ALTO: "set deviceconfig system service disable-http yes",
            },
            "MGMT-003": {
                VendorEnum.CISCO: "line vty 0 15\n  transport input ssh",
                VendorEnum.FORTINET: "config system global\n  set admin-telnet-port 0\nend",
                VendorEnum.PALO_ALTO: "set deviceconfig system service disable-telnet yes",
            },
            "MGMT-004": {
                VendorEnum.CISCO: "no snmp-server community private RW\nsnmp-server community <secure_string> RO ADMIN_ACL",
                VendorEnum.FORTINET: "config system snmp community\n  delete 1\nend",
                VendorEnum.PALO_ALTO: "set deviceconfig system snmp-setting version v3",
            },
        }

        rule_cli = cli_map.get(rule_id, {})
        return rule_cli.get(vendor, f"# Refer to {vendor.value} documentation for rule {rule_id}")

"""
NetAudit AI - Access Control Deterministic Rules
"""

from typing import List
from backend.normalization.models import NormalizedConfig, ActionEnum, ProtocolEnum
from backend.rules.models import ComplianceRule, Finding, CategoryEnum, SeverityEnum, ComplianceMapping


class BroadAnyToAnyRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="ACL-001",
            title="Excessively Broad Any-to-Any Permit Policy",
            category=CategoryEnum.ACCESS_CONTROL,
            severity=SeverityEnum.CRITICAL,
            description="Rule permits all IP traffic from any source to any destination, exposing internal segments.",
            compliance_mapping=ComplianceMapping(
                nist_csf="PR.AC-5", cis_benchmark="CIS Cisco IOS 4.1", pci_dss="PCI-DSS 1.2.1"
            ),
            recommendation="Restrict source, destination, and specific required protocols/ports instead of permit ip any any.",
        )

    def evaluate(self, norm_config: NormalizedConfig) -> List[Finding]:
        findings = []
        for rule in norm_config.security_rules:
            if rule.action == ActionEnum.ALLOW:
                src_is_any = any(s.address_type == "any" for s in rule.sources)
                dst_is_any = any(d.address_type == "any" for d in rule.destinations)
                proto_is_any = any(s.protocol == ProtocolEnum.ANY or s.protocol == ProtocolEnum.IP for s in rule.services)

                if src_is_any and dst_is_any and proto_is_any:
                    findings.append(
                        Finding(
                            finding_id=f"FINDING-{self.rule_id}-{rule.rule_id}",
                            rule_id=self.rule_id,
                            title=self.title,
                            category=self.category,
                            severity=self.severity,
                            description=self.description,
                            evidence=f"ACL '{rule.rule_name}' line {rule.line_number}: {rule.raw_text}",
                            line_number=rule.line_number,
                            affected_asset=f"ACL {rule.rule_name}",
                            compliance_mapping=self.compliance_mapping,
                            recommendation=self.recommendation,
                        )
                    )
        return findings


class UnrestrictedAdminAccessRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="ACL-002",
            title="Unrestricted Management Access via SSH/Telnet",
            category=CategoryEnum.ACCESS_CONTROL,
            severity=SeverityEnum.HIGH,
            description="Administrative service (SSH/Telnet) is permitted from unrestricted source networks.",
            compliance_mapping=ComplianceMapping(
                nist_csf="PR.AC-3", cis_benchmark="CIS Cisco IOS 3.2", pci_dss="PCI-DSS 2.2.3"
            ),
            recommendation="Restrict SSH access to trusted administrative management subnets using strict source IP ACLs.",
        )

    def evaluate(self, norm_config: NormalizedConfig) -> List[Finding]:
        findings = []
        admin_ports = ["22", "23", "ssh", "telnet"]
        for rule in norm_config.security_rules:
            if rule.action == ActionEnum.ALLOW:
                src_is_any = any(s.address_type == "any" for s in rule.sources)
                allows_admin_port = any(
                    s.port_range in admin_ports or any(p in s.raw_value for p in admin_ports)
                    for s in rule.services
                )
                if src_is_any and allows_admin_port:
                    findings.append(
                        Finding(
                            finding_id=f"FINDING-{self.rule_id}-{rule.rule_id}",
                            rule_id=self.rule_id,
                            title=self.title,
                            category=self.category,
                            severity=self.severity,
                            description=self.description,
                            evidence=f"ACL '{rule.rule_name}' line {rule.line_number}: {rule.raw_text}",
                            line_number=rule.line_number,
                            affected_asset=f"ACL {rule.rule_name}",
                            compliance_mapping=self.compliance_mapping,
                            recommendation=self.recommendation,
                        )
                    )
        return findings


class UnloggedPermitRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="ACL-003",
            title="Permit Rule Missing Security Logging",
            category=CategoryEnum.ACCESS_CONTROL,
            severity=SeverityEnum.MEDIUM,
            description="Permit policy lacks security event logging, preventing audit trails for allowed traffic.",
            compliance_mapping=ComplianceMapping(
                nist_csf="DE.AE-3", cis_benchmark="CIS Cisco IOS 4.3", pci_dss="PCI-DSS 10.2.1"
            ),
            recommendation="Append 'log' or 'log-input' parameter to inbound permit ACL statements.",
        )

    def evaluate(self, norm_config: NormalizedConfig) -> List[Finding]:
        findings = []
        for rule in norm_config.security_rules:
            if rule.action == ActionEnum.ALLOW and not rule.logging_enabled:
                findings.append(
                    Finding(
                        finding_id=f"FINDING-{self.rule_id}-{rule.rule_id}",
                        rule_id=self.rule_id,
                        title=self.title,
                        category=self.category,
                        severity=self.severity,
                        description=self.description,
                        evidence=f"ACL '{rule.rule_name}' line {rule.line_number}: {rule.raw_text}",
                        line_number=rule.line_number,
                        affected_asset=f"ACL {rule.rule_name}",
                        compliance_mapping=self.compliance_mapping,
                        recommendation=self.recommendation,
                    )
                )
        return findings

"""
NetAudit AI - Management Security Deterministic Rules
"""

from typing import List
from backend.normalization.models import NormalizedConfig
from backend.rules.models import ComplianceRule, Finding, CategoryEnum, SeverityEnum, ComplianceMapping


class UnencryptedPasswordsRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="MGMT-001",
            title="Unencrypted Device Passwords",
            category=CategoryEnum.MANAGEMENT_SECURITY,
            severity=SeverityEnum.HIGH,
            description="Service password-encryption is disabled, leaving plaintext credentials vulnerable in configuration files.",
            compliance_mapping=ComplianceMapping(
                nist_csf="PR.AC-1", cis_benchmark="CIS Cisco IOS 1.1", pci_dss="PCI-DSS 8.2.1"
            ),
            recommendation="Enable 'service password-encryption' and configure secret passwords with strong hash algorithm.",
        )

    def evaluate(self, norm_config: NormalizedConfig) -> List[Finding]:
        findings = []
        if not norm_config.management.password_encryption_enabled:
            findings.append(
                Finding(
                    finding_id=f"FINDING-{self.rule_id}",
                    rule_id=self.rule_id,
                    title=self.title,
                    category=self.category,
                    severity=self.severity,
                    description=self.description,
                    evidence="no service password-encryption",
                    line_number=0,
                    affected_asset="System Management",
                    compliance_mapping=self.compliance_mapping,
                    recommendation=self.recommendation,
                )
            )
        return findings


class InsecureHttpServerRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="MGMT-002",
            title="Cleartext HTTP Web Management Server Enabled",
            category=CategoryEnum.MANAGEMENT_SECURITY,
            severity=SeverityEnum.HIGH,
            description="Cleartext HTTP server is enabled for device management, transmitting credentials unencrypted over network.",
            compliance_mapping=ComplianceMapping(
                nist_csf="PR.DS-2", cis_benchmark="CIS Cisco IOS 2.1", pci_dss="PCI-DSS 2.2.2"
            ),
            recommendation="Disable cleartext HTTP server ('no ip http server') and enforce HTTPS ('ip http secure-server').",
        )

    def evaluate(self, norm_config: NormalizedConfig) -> List[Finding]:
        findings = []
        if norm_config.management.http_server_enabled:
            findings.append(
                Finding(
                    finding_id=f"FINDING-{self.rule_id}",
                    rule_id=self.rule_id,
                    title=self.title,
                    category=self.category,
                    severity=self.severity,
                    description=self.description,
                    evidence="ip http server",
                    line_number=0,
                    affected_asset="Web Management Interface",
                    compliance_mapping=self.compliance_mapping,
                    recommendation=self.recommendation,
                )
            )
        return findings


class CleartextTelnetRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="MGMT-003",
            title="Cleartext Telnet Transport Enabled on Virtual Terminal Lines",
            category=CategoryEnum.MANAGEMENT_SECURITY,
            severity=SeverityEnum.HIGH,
            description="Telnet protocol is permitted on VTY lines, allowing remote session eavesdropping.",
            compliance_mapping=ComplianceMapping(
                nist_csf="PR.AC-3", cis_benchmark="CIS Cisco IOS 1.2", pci_dss="PCI-DSS 2.3"
            ),
            recommendation="Restrict VTY transport input to SSH only ('transport input ssh').",
        )

    def evaluate(self, norm_config: NormalizedConfig) -> List[Finding]:
        findings = []
        if norm_config.management.telnet_enabled:
            findings.append(
                Finding(
                    finding_id=f"FINDING-{self.rule_id}",
                    rule_id=self.rule_id,
                    title=self.title,
                    category=self.category,
                    severity=self.severity,
                    description=self.description,
                    evidence="transport input telnet",
                    line_number=0,
                    affected_asset="Line VTY",
                    compliance_mapping=self.compliance_mapping,
                    recommendation=self.recommendation,
                )
            )
        return findings


class InsecureSnmpCommunityRule(ComplianceRule):
    def __init__(self):
        super().__init__(
            rule_id="MGMT-004",
            title="Insecure / Default SNMP Community String",
            category=CategoryEnum.MANAGEMENT_SECURITY,
            severity=SeverityEnum.CRITICAL,
            description="Default or Read-Write (RW) SNMP community string configured without strict ACL restriction.",
            compliance_mapping=ComplianceMapping(
                nist_csf="PR.AC-1", cis_benchmark="CIS Cisco IOS 5.1", pci_dss="PCI-DSS 2.1"
            ),
            recommendation="Change default community strings ('public', 'private'), remove RW permissions if unneeded, and restrict via ACL.",
        )

    def evaluate(self, norm_config: NormalizedConfig) -> List[Finding]:
        findings = []
        for comm in norm_config.management.snmp_communities:
            if comm.community_string.lower() in ["public", "private"] or comm.access_mode == "RW":
                findings.append(
                    Finding(
                        finding_id=f"FINDING-{self.rule_id}-{comm.community_string}",
                        rule_id=self.rule_id,
                        title=self.title,
                        category=self.category,
                        severity=SeverityEnum.CRITICAL if comm.access_mode == "RW" else SeverityEnum.HIGH,
                        description=self.description,
                        evidence=f"snmp-server community {comm.community_string} {comm.access_mode}",
                        line_number=0,
                        affected_asset="SNMP Service",
                        compliance_mapping=self.compliance_mapping,
                        recommendation=self.recommendation,
                    )
                )
        return findings

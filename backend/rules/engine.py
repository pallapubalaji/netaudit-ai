"""
NetAudit AI - Deterministic Compliance Engine
Executes catalog of security compliance rules against normalized configuration objects.
"""

from typing import List
from backend.normalization.models import NormalizedConfig
from backend.rules.models import ComplianceRule, Finding
from backend.rules.definitions.access_control import (
    BroadAnyToAnyRule,
    UnrestrictedAdminAccessRule,
    UnloggedPermitRule,
)
from backend.rules.definitions.management import (
    UnencryptedPasswordsRule,
    InsecureHttpServerRule,
    CleartextTelnetRule,
    InsecureSnmpCommunityRule,
)


class ComplianceEngine:
    def __init__(self):
        self.rules: List[ComplianceRule] = [
            BroadAnyToAnyRule(),
            UnrestrictedAdminAccessRule(),
            UnloggedPermitRule(),
            UnencryptedPasswordsRule(),
            InsecureHttpServerRule(),
            CleartextTelnetRule(),
            InsecureSnmpCommunityRule(),
        ]

    def register_rule(self, rule: ComplianceRule):
        """Allows dynamic rule registration."""
        self.rules.append(rule)

    def run_audit(self, norm_config: NormalizedConfig) -> List[Finding]:
        """
        Executes all registered deterministic compliance rules against NormalizedConfig.
        Returns unified list of verified security findings.
        """
        all_findings: List[Finding] = []
        for rule in self.rules:
            findings = rule.evaluate(norm_config)
            all_findings.extend(findings)
        return all_findings

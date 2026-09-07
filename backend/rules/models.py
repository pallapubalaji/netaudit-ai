"""
NetAudit AI - Deterministic Rule & Finding Schemas
Defines structured compliance findings, severities, and baseline rule interfaces.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field
from backend.normalization.models import NormalizedConfig


class SeverityEnum(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


class CategoryEnum(str, Enum):
    ACCESS_CONTROL = "ACCESS_CONTROL"
    MANAGEMENT_SECURITY = "MANAGEMENT_SECURITY"
    NETWORK_SECURITY = "NETWORK_SECURITY"
    LOGGING = "LOGGING"
    RULE_QUALITY = "RULE_QUALITY"
    SECURITY_CONTROLS = "SECURITY_CONTROLS"


class ComplianceMapping(BaseModel):
    nist_csf: Optional[str] = None
    cis_benchmark: Optional[str] = None
    pci_dss: Optional[str] = None
    iso_27001: Optional[str] = None


class Finding(BaseModel):
    finding_id: str
    rule_id: str
    title: str
    category: CategoryEnum
    severity: SeverityEnum
    description: str
    evidence: str = Field(description="Exact line text or normalized configuration value causing violation")
    line_number: int = 0
    affected_asset: str = Field(default="Device Config", description="Interface, line vty, ACL, or system component")
    compliance_mapping: ComplianceMapping = Field(default_factory=ComplianceMapping)
    recommendation: str
    vendor_scope: List[str] = Field(default_factory=lambda: ["cisco", "fortinet", "paloalto"])


class ComplianceRule(BaseModel):
    rule_id: str
    title: str
    category: CategoryEnum
    severity: SeverityEnum
    description: str
    compliance_mapping: ComplianceMapping
    recommendation: str

    def evaluate(self, norm_config: NormalizedConfig) -> List[Finding]:
        """Base evaluation logic to be overridden by deterministic rules."""
        raise NotImplementedError("Rules must implement evaluate method.")

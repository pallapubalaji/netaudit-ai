"""
NetAudit AI - Common Normalized Security Model (CSM)
Vendor-neutral data structure representing network security device configurations.
"""

from enum import Enum
from typing import List, Optional, Dict, Any
from pydantic import BaseModel, Field


class VendorEnum(str, Enum):
    CISCO = "cisco"
    FORTINET = "fortinet"
    PALO_ALTO = "paloalto"
    UNKNOWN = "unknown"


class ActionEnum(str, Enum):
    ALLOW = "allow"
    DENY = "deny"
    REJECT = "reject"
    UNKNOWN = "unknown"


class ProtocolEnum(str, Enum):
    TCP = "tcp"
    UDP = "udp"
    ICMP = "icmp"
    IP = "ip"
    ANY = "any"
    UNKNOWN = "unknown"


class NetworkEndpoint(BaseModel):
    raw_value: str
    address_type: str = Field(description="host, subnet, range, any, object_group")
    ip_or_subnet: str
    mask: Optional[str] = None
    negated: bool = False


class ServiceEndpoint(BaseModel):
    protocol: ProtocolEnum = ProtocolEnum.ANY
    port_range: str = Field(default="any", description="Single port (80), range (80-443), list, or any")
    raw_value: str


class SecurityRule(BaseModel):
    rule_id: str
    vendor: VendorEnum
    rule_name: str
    source_zone: Optional[str] = "any"
    destination_zone: Optional[str] = "any"
    inbound_interface: Optional[str] = None
    outbound_interface: Optional[str] = None
    sources: List[NetworkEndpoint] = Field(default_factory=list)
    destinations: List[NetworkEndpoint] = Field(default_factory=list)
    services: List[ServiceEndpoint] = Field(default_factory=list)
    action: ActionEnum = ActionEnum.UNKNOWN
    logging_enabled: bool = False
    enabled: bool = True
    line_number: int = 0
    raw_text: str = ""
    comments: List[str] = Field(default_factory=list)
    security_profiles: List[str] = Field(default_factory=list)


class InterfaceConfig(BaseModel):
    name: str
    description: Optional[str] = None
    ip_address: Optional[str] = None
    subnet_mask: Optional[str] = None
    zone: Optional[str] = None
    inbound_acl: Optional[str] = None
    outbound_acl: Optional[str] = None
    enabled: bool = True


class SNMPCommunity(BaseModel):
    community_string: str
    access_mode: str = "RO"  # RO or RW
    access_list: Optional[str] = None


class ManagementConfig(BaseModel):
    hostname: str = "Unknown"
    domain_name: Optional[str] = None
    http_server_enabled: bool = False
    https_server_enabled: bool = False
    telnet_enabled: bool = False
    ssh_enabled: bool = False
    snmp_communities: List[SNMPCommunity] = Field(default_factory=list)
    password_encryption_enabled: bool = True
    aaa_enabled: bool = True


class NormalizedConfig(BaseModel):
    vendor: VendorEnum
    device_name: str = "Unknown Device"
    os_version: Optional[str] = None
    raw_hash: str = ""
    interfaces: List[InterfaceConfig] = Field(default_factory=list)
    security_rules: List[SecurityRule] = Field(default_factory=list)
    management: ManagementConfig = Field(default_factory=ManagementConfig)
    raw_line_count: int = 0
    metadata: Dict[str, Any] = Field(default_factory=dict)

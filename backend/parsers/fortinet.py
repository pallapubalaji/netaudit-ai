"""
NetAudit AI - Fortinet FortiOS Configuration Parser
Parses FortiOS block syntax into the Common Normalized Security Model.
"""

from typing import List, Optional
from backend.parsers.base import BaseParser
from backend.normalization.models import (
    NormalizedConfig,
    VendorEnum,
    SecurityRule,
    InterfaceConfig,
    ManagementConfig,
    ActionEnum,
    ProtocolEnum,
    NetworkEndpoint,
    ServiceEndpoint,
)


class FortinetParser(BaseParser):
    def __init__(self):
        super().__init__(vendor=VendorEnum.FORTINET)

    def parse(self, config_text: str) -> NormalizedConfig:
        lines = config_text.splitlines()
        raw_hash = self.compute_sha256(config_text)

        norm_config = NormalizedConfig(
            vendor=VendorEnum.FORTINET,
            device_name="Unknown-FortiGate",
            raw_hash=raw_hash,
            raw_line_count=len(lines),
        )

        management = ManagementConfig()
        rules: List[SecurityRule] = []

        in_system_global = False
        in_firewall_policy = False
        current_policy: Optional[dict] = None

        for idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            if not line or line.startswith("#"):
                continue

            if line == "config system global":
                in_system_global = True
                continue
            elif line == "config firewall policy":
                in_firewall_policy = True
                continue
            elif line == "end":
                in_system_global = False
                if in_firewall_policy and current_policy:
                    rule = self._policy_to_rule(current_policy, idx)
                    if rule:
                        rules.append(rule)
                    current_policy = None
                in_firewall_policy = False
                continue

            if in_system_global:
                if line.startswith("set hostname "):
                    val = line.split("set hostname ")[1].replace('"', "").strip()
                    norm_config.device_name = val
                    management.hostname = val
                elif line.startswith("set admin-sport "):
                    port = line.split()[-1].strip()
                    if port == "80":
                        management.http_server_enabled = True
                elif line.startswith("set admin-telnet-port "):
                    management.telnet_enabled = True

            elif in_firewall_policy:
                if line.startswith("edit "):
                    if current_policy:
                        rule = self._policy_to_rule(current_policy, idx)
                        if rule:
                            rules.append(rule)
                    policy_id = line.split("edit ")[1].strip()
                    current_policy = {"id": policy_id, "line_number": idx}

                elif current_policy and line.startswith("set "):
                    parts = line.split()
                    key = parts[1]
                    val_str = " ".join(parts[2:]).replace('"', "")

                    if key == "name":
                        current_policy["name"] = val_str
                    elif key == "srcintf":
                        current_policy["srcintf"] = val_str
                    elif key == "dstintf":
                        current_policy["dstintf"] = val_str
                    elif key == "srcaddr":
                        current_policy["srcaddr"] = val_str
                    elif key == "dstaddr":
                        current_policy["dstaddr"] = val_str
                    elif key == "action":
                        current_policy["action"] = val_str
                    elif key == "service":
                        current_policy["service"] = val_str
                    elif key == "logtraffic":
                        current_policy["logtraffic"] = val_str

        if current_policy:
            rule = self._policy_to_rule(current_policy, len(lines))
            if rule:
                rules.append(rule)

        norm_config.security_rules = rules
        norm_config.management = management
        return norm_config

    def _policy_to_rule(self, p: dict, line_num: int) -> Optional[SecurityRule]:
        policy_id = p.get("id", "0")
        name = p.get("name", f"Policy-{policy_id}")

        action_str = p.get("action", "accept").lower()
        action = ActionEnum.ALLOW if action_str in ["accept", "allow"] else ActionEnum.DENY

        src_raw = p.get("srcaddr", "all")
        dst_raw = p.get("dstaddr", "all")
        svc_raw = p.get("service", "ALL")

        # Process Source
        src_type = "any" if src_raw.lower() in ["all", "any"] else "subnet"
        src_endpoint = NetworkEndpoint(
            raw_value=src_raw, address_type=src_type, ip_or_subnet="0.0.0.0/0" if src_type == "any" else src_raw
        )

        # Process Destination
        dst_type = "any" if dst_raw.lower() in ["all", "any"] else "subnet"
        dst_endpoint = NetworkEndpoint(
            raw_value=dst_raw, address_type=dst_type, ip_or_subnet="0.0.0.0/0" if dst_type == "any" else dst_raw
        )

        # Process Service
        svc_lower = svc_raw.lower()
        protocol = ProtocolEnum.ANY
        port_range = "any"

        if "http" in svc_lower:
            protocol = ProtocolEnum.TCP
            port_range = "80"
        elif "ssh" in svc_lower:
            protocol = ProtocolEnum.TCP
            port_range = "22"
        elif "telnet" in svc_lower:
            protocol = ProtocolEnum.TCP
            port_range = "23"

        svc_endpoint = ServiceEndpoint(protocol=protocol, port_range=port_range, raw_value=svc_raw)

        logging_enabled = p.get("logtraffic", "").lower() in ["all", "utm"]

        return SecurityRule(
            rule_id=f"FORTI-{policy_id}",
            vendor=VendorEnum.FORTINET,
            rule_name=name,
            source_zone=p.get("srcintf", "any"),
            destination_zone=p.get("dstintf", "any"),
            sources=[src_endpoint],
            destinations=[dst_endpoint],
            services=[svc_endpoint],
            action=action,
            logging_enabled=logging_enabled,
            enabled=True,
            line_number=p.get("line_number", line_num),
            raw_text=f"config firewall policy edit {policy_id} ({name})",
        )

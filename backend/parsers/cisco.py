"""
NetAudit AI - Cisco IOS / IOS-XE Configuration Parser
Parses Cisco syntax into the Common Normalized Security Model.
"""

import re
from typing import List, Optional
from backend.parsers.base import BaseParser
from backend.normalization.models import (
    NormalizedConfig,
    VendorEnum,
    SecurityRule,
    InterfaceConfig,
    ManagementConfig,
    SNMPCommunity,
    ActionEnum,
    ProtocolEnum,
    NetworkEndpoint,
    ServiceEndpoint,
)


class CiscoParser(BaseParser):
    def __init__(self):
        super().__init__(vendor=VendorEnum.CISCO)

    def parse(self, config_text: str) -> NormalizedConfig:
        lines = config_text.splitlines()
        raw_hash = self.compute_sha256(config_text)

        norm_config = NormalizedConfig(
            vendor=VendorEnum.CISCO,
            device_name="Unknown-Cisco",
            raw_hash=raw_hash,
            raw_line_count=len(lines),
        )

        management = ManagementConfig()
        interfaces: List[InterfaceConfig] = []
        rules: List[SecurityRule] = []

        current_interface: Optional[InterfaceConfig] = None
        current_acl_name: Optional[str] = None
        current_acl_comments: List[str] = []
        rule_counter = 1

        # Pre-checks for system management settings
        no_password_encryption = False

        for idx, raw_line in enumerate(lines, start=1):
            line = raw_line.strip()

            if not line or line.startswith("!"):
                # Capture ACL comments if line starts with ! inside ACL block
                continue

            # --- System Metadata ---
            if line.startswith("hostname "):
                norm_config.device_name = line.split("hostname ")[1].strip()
                management.hostname = norm_config.device_name

            elif line.startswith("version "):
                norm_config.os_version = line.split("version ")[1].strip()

            elif line.startswith("ip domain name ") or line.startswith("ip domain-name "):
                management.domain_name = line.split()[-1].strip()

            elif line == "no service password-encryption":
                management.password_encryption_enabled = False

            elif line == "service password-encryption":
                management.password_encryption_enabled = True

            elif line == "ip http server":
                management.http_server_enabled = True

            elif line == "ip http secure-server":
                management.https_server_enabled = True

            elif line == "aaa new-model":
                management.aaa_enabled = True

            elif line == "no aaa new-model":
                management.aaa_enabled = False

            # --- SNMP Communities ---
            elif line.startswith("snmp-server community "):
                parts = line.split()
                if len(parts) >= 3:
                    comm_name = parts[2]
                    mode = "RW" if len(parts) > 3 and parts[3].upper() == "RW" else "RO"
                    acl = parts[4] if len(parts) > 4 else None
                    management.snmp_communities.append(
                        SNMPCommunity(community_string=comm_name, access_mode=mode, access_list=acl)
                    )

            # --- VTY Line Management ---
            elif line.startswith("transport input "):
                if "telnet" in line:
                    management.telnet_enabled = True
                if "ssh" in line:
                    management.ssh_enabled = True

            # --- Interfaces Parsing ---
            elif line.startswith("interface "):
                if current_interface:
                    interfaces.append(current_interface)
                if_name = line.split("interface ")[1].strip()
                current_interface = InterfaceConfig(name=if_name)

            elif current_interface and not line.startswith("ip access-list") and not line.startswith("access-list"):
                if line.startswith("description "):
                    current_interface.description = line.replace("description ", "").strip()
                elif line.startswith("ip address "):
                    ip_parts = line.split()
                    if len(ip_parts) >= 4:
                        current_interface.ip_address = ip_parts[2]
                        current_interface.subnet_mask = ip_parts[3]
                elif line.startswith("ip access-group "):
                    parts = line.split()
                    if len(parts) >= 4:
                        acl_id = parts[2]
                        direction = parts[3].lower()
                        if direction == "in":
                            current_interface.inbound_acl = acl_id
                        elif direction == "out":
                            current_interface.outbound_acl = acl_id
                elif line == "shutdown":
                    current_interface.enabled = False

            # --- Named ACL Header Parsing ---
            elif line.startswith("ip access-list extended ") or line.startswith("ip access-list standard "):
                if current_interface:
                    interfaces.append(current_interface)
                    current_interface = None

                acl_parts = line.split()
                current_acl_name = acl_parts[3] if len(acl_parts) >= 4 else acl_parts[-1]
                current_acl_comments = []

            # --- ACL Entries Parsing ---
            elif current_acl_name or line.startswith("access-list "):
                if current_interface:
                    interfaces.append(current_interface)
                    current_interface = None

                if line.startswith("remark "):
                    remark_text = line.replace("remark ", "").strip()
                    current_acl_comments.append(remark_text)
                    continue

                if line.startswith("permit ") or line.startswith("deny ") or line.startswith("access-list "):
                    rule = self._parse_cisco_acl_line(
                        line=line,
                        line_number=idx,
                        acl_name=current_acl_name or "Numbered-ACL",
                        comments=list(current_acl_comments),
                        rule_idx=rule_counter,
                    )
                    if rule:
                        rules.append(rule)
                        rule_counter += 1
                        current_acl_comments = []

        if current_interface:
            interfaces.append(current_interface)

        norm_config.interfaces = interfaces
        norm_config.security_rules = rules
        norm_config.management = management
        return norm_config

    def _parse_cisco_acl_line(
        self, line: str, line_number: int, acl_name: str, comments: List[str], rule_idx: int
    ) -> Optional[SecurityRule]:
        """Parses a single Cisco permit/deny ACL line."""
        tokens = line.split()
        if not tokens:
            return None

        # Check action
        action = ActionEnum.UNKNOWN
        if "permit" in tokens:
            action = ActionEnum.ALLOW
            start_idx = tokens.index("permit")
        elif "deny" in tokens:
            action = ActionEnum.DENY
            start_idx = tokens.index("deny")
        else:
            return None

        remaining = tokens[start_idx + 1 :]
        if not remaining:
            return None

        # Protocol
        proto_str = remaining[0].lower()
        protocol = ProtocolEnum.ANY
        if proto_str in ["tcp", "udp", "icmp", "ip"]:
            protocol = ProtocolEnum(proto_str)
            remaining = remaining[1:]

        logging_enabled = "log" in tokens or "log-input" in tokens

        # Process Sources & Destinations
        src_endpoint, remaining = self._extract_endpoint(remaining)
        dst_endpoint, remaining = self._extract_endpoint(remaining)

        # Process Port/Service
        svc_endpoint = ServiceEndpoint(protocol=protocol, port_range="any", raw_value="any")
        if remaining and remaining[0].lower() in ["eq", "gt", "lt", "range", "neq"]:
            op = remaining[0].lower()
            if op == "eq" and len(remaining) > 1:
                svc_endpoint.port_range = remaining[1]
                svc_endpoint.raw_value = f"eq {remaining[1]}"
            elif op == "range" and len(remaining) > 2:
                svc_endpoint.port_range = f"{remaining[1]}-{remaining[2]}"
                svc_endpoint.raw_value = f"range {remaining[1]}-{remaining[2]}"

        return SecurityRule(
            rule_id=f"CISCO-{acl_name}-{rule_idx:03d}",
            vendor=VendorEnum.CISCO,
            rule_name=acl_name,
            sources=[src_endpoint] if src_endpoint else [],
            destinations=[dst_endpoint] if dst_endpoint else [],
            services=[svc_endpoint],
            action=action,
            logging_enabled=logging_enabled,
            enabled=True,
            line_number=line_number,
            raw_text=line,
            comments=comments,
        )

    def _extract_endpoint(self, tokens: List[str]):
        """Extracts source or destination IP/host/subnet token sequence from Cisco ACL line."""
        if not tokens:
            return None, []

        token = tokens[0].lower()

        if token == "any":
            endpoint = NetworkEndpoint(
                raw_value="any", address_type="any", ip_or_subnet="0.0.0.0/0", mask="0.0.0.0"
            )
            return endpoint, tokens[1:]

        elif token == "host" and len(tokens) > 1:
            ip = tokens[1]
            endpoint = NetworkEndpoint(
                raw_value=f"host {ip}", address_type="host", ip_or_subnet=f"{ip}/32", mask="255.255.255.255"
            )
            return endpoint, tokens[2:]

        elif re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", token):
            ip = token
            mask = tokens[1] if len(tokens) > 1 and re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", tokens[1]) else "0.0.0.0"
            advance = 2 if mask != "0.0.0.0" else 1
            endpoint = NetworkEndpoint(
                raw_value=f"{ip} {mask}", address_type="subnet", ip_or_subnet=f"{ip} wildcard {mask}", mask=mask
            )
            return endpoint, tokens[advance:]

        else:
            endpoint = NetworkEndpoint(
                raw_value=token, address_type="object_group", ip_or_subnet=token
            )
            return endpoint, tokens[1:]

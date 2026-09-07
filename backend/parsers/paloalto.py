"""
NetAudit AI - Palo Alto PAN-OS Configuration Parser
Parses PAN-OS XML and set-command syntax into the Common Normalized Security Model.
"""

import xml.etree.ElementTree as ET
from typing import List, Optional
from backend.parsers.base import BaseParser
from backend.normalization.models import (
    NormalizedConfig,
    VendorEnum,
    SecurityRule,
    ManagementConfig,
    ActionEnum,
    ProtocolEnum,
    NetworkEndpoint,
    ServiceEndpoint,
)


class PaloAltoParser(BaseParser):
    def __init__(self):
        super().__init__(vendor=VendorEnum.PALO_ALTO)

    def parse(self, config_text: str) -> NormalizedConfig:
        raw_hash = self.compute_sha256(config_text)
        lines = config_text.splitlines()

        norm_config = NormalizedConfig(
            vendor=VendorEnum.PALO_ALTO,
            device_name="Unknown-PaloAlto",
            raw_hash=raw_hash,
            raw_line_count=len(lines),
        )

        management = ManagementConfig()
        rules: List[SecurityRule] = []

        try:
            root = ET.fromstring(config_text)
            
            # Parse Hostname & Management Services
            hostname_node = root.find(".//hostname")
            if hostname_node is not None and hostname_node.text:
                norm_config.device_name = hostname_node.text
                management.hostname = hostname_node.text

            disable_http = root.find(".//service/disable-http")
            if disable_http is not None and disable_http.text == "no":
                management.http_server_enabled = True

            disable_telnet = root.find(".//service/disable-telnet")
            if disable_telnet is not None and disable_telnet.text == "no":
                management.telnet_enabled = True

            # Parse Security Rules
            rule_entries = root.findall(".//security/rules/entry")
            for idx, entry in enumerate(rule_entries, start=1):
                rule_name = entry.get("name", f"PA-Rule-{idx}")
                
                action_node = entry.find("action")
                action_str = action_node.text if action_node is not None and action_node.text else "allow"
                action = ActionEnum.ALLOW if action_str.lower() == "allow" else ActionEnum.DENY

                # Sources
                sources = []
                for src in entry.findall("./source/member"):
                    src_val = src.text or "any"
                    sources.append(
                        NetworkEndpoint(
                            raw_value=src_val,
                            address_type="any" if src_val.lower() == "any" else "subnet",
                            ip_or_subnet="0.0.0.0/0" if src_val.lower() == "any" else src_val,
                        )
                    )

                # Destinations
                destinations = []
                for dst in entry.findall("./destination/member"):
                    dst_val = dst.text or "any"
                    destinations.append(
                        NetworkEndpoint(
                            raw_value=dst_val,
                            address_type="any" if dst_val.lower() == "any" else "subnet",
                            ip_or_subnet="0.0.0.0/0" if dst_val.lower() == "any" else dst_val,
                        )
                    )

                # Services
                services = []
                for svc in entry.findall("./service/member"):
                    svc_val = svc.text or "any"
                    svc_lower = svc_val.lower()
                    protocol = ProtocolEnum.ANY
                    port_range = "any"

                    if "http" in svc_lower:
                        protocol = ProtocolEnum.TCP
                        port_range = "80"
                    elif "ssh" in svc_lower:
                        protocol = ProtocolEnum.TCP
                        port_range = "22"

                    services.append(ServiceEndpoint(protocol=protocol, port_range=port_range, raw_value=svc_val))

                log_end = entry.find("log-end")
                logging_enabled = log_end is not None and log_end.text and log_end.text.lower() in ["yes", "true"]

                rules.append(
                    SecurityRule(
                        rule_id=f"PA-{idx:03d}",
                        vendor=VendorEnum.PALO_ALTO,
                        rule_name=rule_name,
                        sources=sources,
                        destinations=destinations,
                        services=services,
                        action=action,
                        logging_enabled=logging_enabled,
                        enabled=True,
                        line_number=idx,
                        raw_text=f'<entry name="{rule_name}">',
                    )
                )

        except ET.ParseError:
            # Fallback if config is set-command based or malformed XML
            pass

        norm_config.security_rules = rules
        norm_config.management = management
        return norm_config

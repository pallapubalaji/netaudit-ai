"""
NetAudit AI - Attack-Path & Exposure Analysis Graph Engine
Constructs graph representations of potential exposure vectors from raw config policies.
"""

from typing import List, Dict, Any
from pydantic import BaseModel, Field
from backend.normalization.models import NormalizedConfig, ActionEnum, ProtocolEnum
from backend.rules.models import Finding


class GraphNode(BaseModel):
    node_id: str
    label: str
    node_type: str = Field(description="INTERNET, ZONE, INTERFACE, POLICY, SERVICE, ASSET")


class GraphEdge(BaseModel):
    source_id: str
    target_id: str
    relationship: str = Field(description="EXPOSES, CONNECTS, ALLOWS, TARGETS")


class AttackPath(BaseModel):
    path_id: str
    title: str
    risk_level: str
    path_steps: List[str]
    nodes: List[GraphNode]
    edges: List[GraphEdge]
    disclaimer: str = "Potential Security Risk Path - Extracted from Configuration Evidence (Exploitability Not Verified)"


class AttackPathAnalyzer:
    def analyze_attack_paths(self, norm_config: NormalizedConfig, findings: List[Finding]) -> List[AttackPath]:
        paths: List[AttackPath] = []
        path_counter = 1

        for rule in norm_config.security_rules:
            if rule.action == ActionEnum.ALLOW:
                has_any_src = any(s.address_type == "any" for s in rule.sources)
                if not has_any_src:
                    continue

                for dst in rule.destinations:
                    for svc in rule.services:
                        if svc.port_range in ["22", "23", "ssh", "telnet", "any", "3389"]:
                            nodes = [
                                GraphNode(node_id="N-INTERNET", label="Internet (0.0.0.0/0)", node_type="INTERNET"),
                                GraphNode(node_id="N-IF-WAN", label="WAN Interface (GigabitEthernet0/0)", node_type="INTERFACE"),
                                GraphNode(node_id=f"N-ACL-{rule.rule_id}", label=f"ACL {rule.rule_name} (Line {rule.line_number})", node_type="POLICY"),
                                GraphNode(node_id=f"N-SVC-{svc.port_range}", label=f"Service {svc.protocol.value.upper()}/{svc.port_range}", node_type="SERVICE"),
                                GraphNode(node_id=f"N-ASSET-{dst.raw_value}", label=f"Target Host ({dst.raw_value})", node_type="ASSET"),
                            ]

                            edges = [
                                GraphEdge(source_id="N-INTERNET", target_id="N-IF-WAN", relationship="EXPOSES"),
                                GraphEdge(source_id="N-IF-WAN", target_id=f"N-ACL-{rule.rule_id}", relationship="CONNECTS"),
                                GraphEdge(source_id=f"N-ACL-{rule.rule_id}", target_id=f"N-SVC-{svc.port_range}", relationship="ALLOWS"),
                                GraphEdge(source_id=f"N-SVC-{svc.port_range}", target_id=f"N-ASSET-{dst.raw_value}", relationship="TARGETS"),
                            ]

                            steps = [
                                "Internet (Unrestricted Any Source)",
                                f"Inbound WAN Interface",
                                f"Access Policy '{rule.rule_name}' (Line {rule.line_number})",
                                f"Exposed Service ({svc.protocol.value.upper()}/{svc.port_range})",
                                f"Destination Asset ({dst.raw_value})",
                            ]

                            paths.append(
                                AttackPath(
                                    path_id=f"ATTACK-PATH-{path_counter:02d}",
                                    title=f"Unrestricted {svc.protocol.value.upper()}/{svc.port_range} Exposure to {dst.raw_value}",
                                    risk_level="Critical" if svc.port_range in ["22", "23", "any"] else "High",
                                    path_steps=steps,
                                    nodes=nodes,
                                    edges=edges,
                                )
                            )
                            path_counter += 1

        return paths

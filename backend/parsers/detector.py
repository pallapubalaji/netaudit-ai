"""
NetAudit AI - Automated Vendor Detector
Determines the vendor syntax of an uploaded configuration file deterministically.
"""

from backend.normalization.models import VendorEnum


class VendorDetector:
    @staticmethod
    def detect_vendor(config_text: str) -> VendorEnum:
        """
        Analyzes configuration content keywords to detect vendor.
        Returns VendorEnum.CISCO, VendorEnum.FORTINET, VendorEnum.PALO_ALTO, or VendorEnum.UNKNOWN.
        """
        lines = config_text.splitlines()
        sample_text = "\n".join(lines[:100]).lower()
        full_text_lower = config_text.lower()

        # Fortinet Detection Signals
        if "config firewall policy" in full_text_lower or "config system global" in full_text_lower or "set vdom" in full_text_lower:
            return VendorEnum.FORTINET

        # Palo Alto Detection Signals
        if "<config version=" in full_text_lower or ("devices {" in full_text_lower and "vsys {" in full_text_lower):
            return VendorEnum.PALO_ALTO
        if "set deviceconfig" in full_text_lower or "set rulebase security" in full_text_lower:
            return VendorEnum.PALO_ALTO

        # Cisco Detection Signals
        cisco_keywords = [
            "boot-start-marker",
            "ip access-list",
            "access-list",
            "interface gigabitethernet",
            "interface fastethernet",
            "interface tengigabitethernet",
            "line vty",
            "service password-encryption",
            "no aaa new-model"
        ]

        cisco_score = sum(1 for kw in cisco_keywords if kw in full_text_lower)
        if cisco_score >= 2 or "cisco" in sample_text or (lines and lines[0].startswith("!") and "version" in sample_text):
            return VendorEnum.CISCO

        return VendorEnum.UNKNOWN

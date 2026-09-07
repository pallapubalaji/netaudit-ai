"""
NetAudit AI - Base Configuration Parser
Abstract class interface for all vendor-specific parsers.
"""

from abc import ABC, abstractmethod
import hashlib
from backend.normalization.models import NormalizedConfig, VendorEnum


class BaseParser(ABC):
    def __init__(self, vendor: VendorEnum):
        self.vendor = vendor

    @abstractmethod
    def parse(self, config_text: str) -> NormalizedConfig:
        """
        Parses raw configuration string into NormalizedConfig.
        Must be deterministic and pure.
        """
        pass

    @staticmethod
    def compute_sha256(config_text: str) -> str:
        """Computes SHA-256 hash of configuration file for drift tracking."""
        return hashlib.sha256(config_text.encode('utf-8')).hexdigest()

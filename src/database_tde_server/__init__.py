"""
A Model Context Protocol (MCP) server for managing database Transparent Data Encryption (TDE).

This server provides tools to perform TDE operations on supported databases. Database
encryption and key management are handled by the Thales CipherTrust Application Key
Management (CAKM) connector, which is integrated with the Thales CipherTrust Data
Security Platform (CDSP).
"""

__version__ = "1.0.0"  # Fixed syntax
__author__ = "Sanyam Bassi"  # Fixed syntax

from .server import main
from .config import DatabaseTDESettings
from .models import DatabaseType, EncryptionState, KeyType

__all__ = [  # Fixed syntax
    "main",
    "DatabaseTDESettings", 
    "DatabaseType",
    "EncryptionState",
    "KeyType"
]

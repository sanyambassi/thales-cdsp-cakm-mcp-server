"""
Custom exception classes for TDE operations and error handling.

This module defines specialized exception classes for handling errors that occur
during Transparent Data Encryption (TDE) operations across different database
platforms. These exceptions provide detailed error information and context for
debugging and error handling.

Available exception classes:
- DatabaseTDEError: Base exception for all TDE-related errors
- DatabaseConnectionError: Errors related to database connectivity issues
- TDEOperationError: Errors during TDE encryption/decryption operations
- ConfigurationError: Errors in TDE configuration and setup
- KeyManagementError: Errors in cryptographic key operations
- ValidationError: Errors in input validation and parameter checking

These exceptions provide:
- Detailed error messages with context information
- Specific error types for different failure scenarios
- Consistent error handling across database platforms
- Debugging information for troubleshooting TDE issues
- Structured error reporting for logging and monitoring

All encryption and key management operations are handled by the Thales CipherTrust
Application Key Management (CAKM) connector, which is integrated with the Thales
CipherTrust Data Security Platform (CDSP).
"""

class DatabaseTDEError(Exception):
    """Base exception for Database TDE operations"""
    pass

class DatabaseConnectionError(DatabaseTDEError):
    """Raised when database connection fails"""
    pass

class TDEOperationError(DatabaseTDEError):
    """Raised when TDE operation fails"""
    pass

class ConfigurationError(DatabaseTDEError):
    """Raised when configuration is invalid"""
    pass

class KeyManagementError(DatabaseTDEError):
    """Raised when key management operation fails"""
    pass

class ValidationError(DatabaseTDEError):
    """Raised when validation fails"""
    pass

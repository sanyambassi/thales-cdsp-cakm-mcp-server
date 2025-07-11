"""
Database TDE tools package - CONSOLIDATED with unified tools

AUTO-LOGIN TOOLS CONSOLIDATION:
- All auto-login functionality is now consolidated in manage_oracle_autologin
- Removed redundant tools: enable_oracle_autologin, configure_oracle_autologin_hsm
- Use manage_oracle_autologin with appropriate operation parameter:
  * operation="setup" - Complete auto-login setup from scratch
  * operation="setup_hsm" - Setup auto-login for HSM migration
  * operation="create" - Create auto-login wallet from existing keystore
  * operation="update" - Update auto-login wallet password
  * operation="update_secret" - Update HSM credentials in auto-login wallet
  * operation="remove" - Remove auto-login wallet
"""

from .connection_tools import register_connection_tools
from .credential_tools import register_credential_tools
from .login_management_tools import register_login_management_tools
from .audit_tools import register_audit_tools
from .schedule_tools import register_schedule_tools

# Unified tools (consolidated SQL and Oracle functionality)
from .unified_encryption_tools import register_unified_encryption_tools
from .unified_key_management_tools import register_unified_key_management_tools
from .unified_monitoring_tools import register_unified_monitoring_tools
from .unified_wallet_tools import register_unified_wallet_tools

# Oracle-specific tools (remaining specialized functionality)
from .oracle_configuration_tools import register_oracle_configuration_tools
from .oracle_tde_setup_tools import register_oracle_tde_setup_tools
from .oracle_wallet_migration_tools import register_oracle_wallet_migration_tools

__all__ = [
    # Common tools
    "register_connection_tools",
    "register_credential_tools", 
    "register_login_management_tools",
    "register_audit_tools",
    "register_schedule_tools",
    
    # Unified tools (consolidated functionality)
    "register_unified_encryption_tools",      # SQL + Oracle encryption/decryption
    "register_unified_key_management_tools",  # SQL + Oracle key management
    "register_unified_monitoring_tools",      # SQL + Oracle monitoring
    "register_unified_wallet_tools",          # Oracle wallet management (consolidated auto-login)
    
    # Oracle-specific tools (specialized functionality)
    "register_oracle_configuration_tools",    # Oracle TDE configuration
    "register_oracle_tde_setup_tools",        # Oracle TDE setup (no auto-login - use unified_wallet_tools)
    "register_oracle_wallet_migration_tools"  # Oracle wallet migration (no auto-login - use unified_wallet_tools)
]
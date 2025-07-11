"""
Main MCP server for Database TDE operations - CONSOLIDATED with unified tools

AUTO-LOGIN TOOLS CONSOLIDATION:
- All auto-login functionality is now consolidated in manage_oracle_autologin
- Removed redundant tools: enable_oracle_autologin, configure_oracle_autologin_hsm
- Use manage_oracle_autologin with appropriate operation parameter for all auto-login operations
"""
import asyncio
import logging
from mcp.server.fastmcp import FastMCP
from .database_manager import DatabaseManager
from .tools import (
    # Common tools
    register_connection_tools,
    register_credential_tools,
    register_login_management_tools,
    register_audit_tools,
    register_schedule_tools,
    
    # Unified tools (consolidated SQL and Oracle functionality)
    register_unified_encryption_tools,
    register_unified_key_management_tools,
    register_unified_monitoring_tools,
    register_unified_wallet_tools,
    
    # Oracle-specific tools (remaining specialized functionality)
    register_oracle_configuration_tools,
    register_oracle_tde_setup_tools,
    register_oracle_wallet_migration_tools
)

logger = logging.getLogger(__name__)

def create_server() -> FastMCP:
    """Create and configure the Database TDE MCP server"""
    # Initialize the MCP server
    server = FastMCP("Database TDE MCP Server")
    
    # Initialize database manager
    db_manager = DatabaseManager()
    
    # Register common tools (works for both SQL Server and Oracle)
    register_connection_tools(server, db_manager)
    register_credential_tools(server, db_manager)
    register_login_management_tools(server, db_manager)
    register_audit_tools(server, db_manager)
    register_schedule_tools(server, db_manager)
    
    # Register unified tools (consolidated SQL and Oracle functionality)
    register_unified_encryption_tools(server, db_manager)      # SQL + Oracle encryption/decryption
    register_unified_key_management_tools(server, db_manager)  # SQL + Oracle key management
    register_unified_monitoring_tools(server, db_manager)      # SQL + Oracle monitoring
    register_unified_wallet_tools(server, db_manager)          # Oracle wallet management (consolidated auto-login)
    
    # Register Oracle-specific tools (specialized functionality)
    register_oracle_configuration_tools(server, db_manager)    # Oracle TDE configuration
    register_oracle_tde_setup_tools(server, db_manager)        # Oracle TDE setup (no auto-login - use unified_wallet_tools)
    register_oracle_wallet_migration_tools(server, db_manager) # Oracle wallet migration (no auto-login - use unified_wallet_tools)
    
    logger.info("Database TDE MCP Server initialized with consolidated unified tools")
    
    # Log available connections and their types
    connections = db_manager.config.connections
    sql_server_connections = [name for name, conn in connections.items() if conn.db_type.value == "sqlserver"]
    oracle_connections = [name for name, conn in connections.items() if conn.db_type.value == "oracle"]
    
    logger.info(f"SQL Server connections: {sql_server_connections}")
    logger.info(f"Oracle connections: {oracle_connections}")
    logger.info(f"Total connections loaded: {len(connections)}")
    
    return server

def main():
    """Main entry point for the Database TDE MCP Server"""
    import argparse
    
    parser = argparse.ArgumentParser(description="Database TDE MCP Server")
    parser.add_argument("--config", help="Path to configuration file")
    parser.add_argument("--test-connections", action="store_true", help="Test database connections and exit")
    
    args = parser.parse_args()
    
    if args.test_connections:
        # Test connections mode
        db_manager = DatabaseManager()
        print("Testing database connections...")
        for conn_name, conn in db_manager.config.connections.items():
            try:
                success = db_manager.test_connection(conn_name)
                db_type = conn.db_type.value
                status = "✅ SUCCESS" if success else "❌ FAILED"
                print(f"  {conn_name} ({db_type}): {status}")
            except Exception as e:
                print(f"  {conn_name}: ❌ ERROR - {e}")
        return
    
    # Normal server mode
    server = create_server()
    logger.info("Starting Database TDE MCP Server...")
    
    # Run the MCP server
    server.run()

if __name__ == "__main__":
    main()
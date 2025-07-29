"""
Manages database connections for the TDE MCP Server.

This module is responsible for creating, managing, and providing handlers for
various database types. All encryption and key management operations performed
through these handlers are secured by the Thales CipherTrust Application Key
Management (CAKM) connector and the Thales CipherTrust Data Security Platform (CDSP).
"""

import logging
from typing import Dict, Any, Tuple, Optional

from .config import ConfigurationManager, DatabaseTDESettings
from .database import DatabaseInterface, MSSQLServerDatabase, OracleDatabase  # Updated import
from .models import DatabaseType
from .utils.exceptions import DatabaseConnectionError, ConfigurationError

logger = logging.getLogger(__name__)

class DatabaseManager:
    """Manages database connections and handlers"""
    
    def __init__(self):
        self.settings = DatabaseTDESettings()
        self.config = ConfigurationManager(self.settings)
        self._handlers: Dict[str, DatabaseInterface] = {}
        self._setup_logging()
    
    def _setup_logging(self):
        """Configure logging based on settings"""
        level = getattr(logging, self.settings.log_level.upper(), logging.INFO)
        logging.getLogger().setLevel(level)
        logger.info(f"Database TDE Manager v1.0.0 starting...")
        logger.info(f"Loaded {len(self.config.connections)} database connections")
    
    def get_database_handler(self, connection_name: str) -> DatabaseInterface:
        """Get or create database handler for connection"""
        
        if connection_name in self._handlers:
            return self._handlers[connection_name]
        
        connection = self.config.get_connection(connection_name)
        
        if not connection:
            raise ConfigurationError(f"Connection '{connection_name}' not found")
        
        # Create appropriate handler based on database type
        if connection.db_type == DatabaseType.SQLSERVER:
            handler = MSSQLServerDatabase(connection, self.settings.connection_timeout)  # Updated class name
        elif connection.db_type == DatabaseType.ORACLE:
            handler = OracleDatabase(connection, self.settings.connection_timeout)
        elif connection.db_type == DatabaseType.MYSQL:
            # Future implementation
            raise NotImplementedError("MySQL support not yet implemented")
        elif connection.db_type == DatabaseType.POSTGRESQL:
            # Future implementation
            raise NotImplementedError("PostgreSQL support not yet implemented")
        else:
            raise ConfigurationError(f"Unsupported database type: {connection.db_type}")
        
        self._handlers[connection_name] = handler
        return handler
    
    async def test_connection(self, connection_name: str) -> bool:
        """Tests a database connection."""
        try:
            handler = self.get_database_handler(connection_name)
            return await handler.connect()
        except Exception as e:
            logger.error(f"Connection test failed for {connection_name}: {e}")
            return False

    async def cleanup_connections(self):
        """Clean up all database connections and pools."""
        logger.info("Cleaning up database connections...")
        for conn_name, handler in self._handlers.items():
            try:
                # Only attempt to close pools for database types that use them (like Oracle)
                if hasattr(handler, 'close_pool'):
                    if hasattr(handler, 'pool') and handler.pool:
                        await handler.close_pool()
                        logger.info(f"Closed connection pool for {conn_name}")
                    else:
                        # For database types that don't use pools (like SQL Server)
                        await handler.close_pool()
                        logger.debug(f"Cleaned up connections for {conn_name} (no pool)")
            except Exception as e:
                logger.warning(f"Error closing connection pool for {conn_name}: {e}")
        
        # Clear the handlers dictionary
        self._handlers.clear()
        logger.info("Database cleanup completed.")
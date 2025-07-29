"""
Database connection listing and management tools.

This module provides tools for viewing and managing database connections configured
in the TDE server. It allows users to list all available database connections with
their basic information (host, port, type, etc.) without requiring authentication
or connection testing.

Available tools:
- list_database_connections: Lists all configured database connections with their details

All encryption and key management operations are handled by the Thales CipherTrust
Application Key Management (CAKM) connector, which is integrated with the Thales
CipherTrust Data Security Platform (CDSP).
"""

import json
import logging
from typing import Dict, Any

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

def register_connection_tools(server: FastMCP, db_manager):
    """Register connection management tools with the MCP server"""
    
    @server.tool()
    async def list_database_connections() -> str:
        """
        List all configured database connections.
        
        Returns:
            JSON string containing list of database connections with their basic information.
        """
        try:
            connections_info = []
            for name, conn in db_manager.config.list_connections().items():
                connections_info.append({
                    "name": name,
                    "type": conn.db_type,
                    "host": conn.host,
                    "port": conn.port,
                    "instance": conn.instance
                })
            
            return json.dumps({
                "success": True,
                "connections": connections_info,
                "count": len(connections_info)
            }, indent=2)
        except Exception as e:
            logger.error(f"Error listing connections: {e}")
            return json.dumps({"success": False, "error": str(e)})


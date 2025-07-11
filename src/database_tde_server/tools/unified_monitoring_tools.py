"""
Unified monitoring tools for SQL Server and Oracle databases
"""

import json
import logging
from typing import Optional
from datetime import datetime

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

def register_unified_monitoring_tools(server: FastMCP, db_manager):
    """Register unified monitoring tools with the MCP server"""
    
    # ============================================================================
    # SQL SERVER MONITORING TOOLS
    # ============================================================================
    
    @server.tool()
    async def monitor_sql_databases(
        sql_connection: str,
        operation: str = "list_all",
        database_name: Optional[str] = None,
        encrypted_only: bool = False
    ) -> str:
        """
        Monitor SQL Server databases with various operations.
        
        Args:
            sql_connection: Name of the database connection
            operation: Operation to perform:
                - "list_all": List all databases
                - "encryption_status": Get encryption status (all or specific database)
                - "encrypted_only": List only encrypted databases
            database_name: Optional specific database name (for encryption_status operation)
            encrypted_only: If True, only return encrypted databases (for list_all operation)
        
        Returns:
            JSON string containing monitoring results.
        """
        try:
            logger.info(f"=== monitor_sql_databases called ===")
            logger.info(f"Operation: {operation}, Database: {database_name}, Encrypted only: {encrypted_only}")
            
            db_handler = db_manager.get_database_handler(sql_connection)
            
            if operation == "list_all":
                # List all databases
                databases = await db_handler.list_databases()
                
                if encrypted_only:
                    # Filter to only encrypted databases
                    encryption_status = await db_handler.check_encryption_status()
                    encrypted_db_names = {
                        status.database_name for status in encryption_status 
                        if status.is_encrypted or status.encryption_state == 3
                    }
                    databases = [db for db in databases if db["name"] in encrypted_db_names]
                
                result = {
                    "success": True,
                    "operation": "list_sql_databases",
                    "connection": sql_connection,
                    "encrypted_only": encrypted_only,
                    "databases": databases,
                    "count": len(databases),
                    "timestamp": datetime.now().isoformat()
                }
                
            elif operation == "encryption_status":
                # Get encryption status
                encryption_status = await db_handler.check_encryption_status(database_name)
                
                # Convert to dict for JSON serialization
                status_data = [
                    {
                        "database_name": status.database_name,
                        "database_id": status.database_id,
                        "is_encrypted": status.is_encrypted,
                        "encryption_state": status.encryption_state,
                        "encryption_state_desc": status.encryption_state_desc,
                        "percent_complete": status.percent_complete,
                        "key_algorithm": status.key_algorithm,
                        "key_length": status.key_length,
                        "certificate_name": status.certificate_name
                    }
                    for status in encryption_status
                ]
                
                result = {
                    "success": True,
                    "operation": "encryption_status",
                    "connection": sql_connection,
                    "database_name": database_name,
                    "encryption_status": status_data,
                    "count": len(status_data),
                    "timestamp": datetime.now().isoformat()
                }
                
            elif operation == "encrypted_only":
                # List only encrypted databases
                encryption_status = await db_handler.check_encryption_status()
                
                # Filter to only encrypted databases
                encrypted_only_list = [
                    status for status in encryption_status 
                    if status.is_encrypted or status.encryption_state == 3
                ]
                
                # Convert to dict for JSON serialization
                encrypted_data = [
                    {
                        "database_name": status.database_name,
                        "database_id": status.database_id,
                        "is_encrypted": status.is_encrypted,
                        "encryption_state": status.encryption_state,
                        "encryption_state_desc": status.encryption_state_desc,
                        "percent_complete": status.percent_complete,
                        "key_algorithm": status.key_algorithm,
                        "key_length": status.key_length,
                        "certificate_name": status.certificate_name
                    }
                    for status in encrypted_only_list
                ]
                
                result = {
                    "success": True,
                    "operation": "encrypted_only",
                    "connection": sql_connection,
                    "encrypted_databases": encrypted_data,
                    "count": len(encrypted_data),
                    "timestamp": datetime.now().isoformat()
                }
                
            else:
                return json.dumps({
                    "success": False,
                    "error": f"Invalid operation '{operation}'. Must be 'list_all', 'encryption_status', or 'encrypted_only'"
                })
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error monitoring SQL databases: {e}")
            return json.dumps({"success": False, "error": str(e)})
    
    # ============================================================================
    # ORACLE MONITORING TOOLS
    # ============================================================================
    
    @server.tool()
    async def list_oracle_containers(
        oracle_connection: str,
        include_seed: bool = False
    ) -> str:
        """
        List Oracle containers (CDB and PDBs).
        
        Args:
            oracle_connection: Oracle database connection name
            include_seed: Include seed PDB in results (default: False)
            
        Returns:
            JSON string containing container information.
        """
        try:
            logger.info(f"=== list_oracle_containers called ===")
            logger.info(f"Include seed: {include_seed}")
            
            db_handler = db_manager.get_database_handler(oracle_connection)
            
            # Debug: Test connection and privileges first
            debug_sql = """
            SELECT 
                SYS_CONTEXT('USERENV', 'SESSION_USER') as current_user,
                SYS_CONTEXT('USERENV', 'CON_NAME') as current_container,
                SYS_CONTEXT('USERENV', 'DB_NAME') as database_name,
                SYS_CONTEXT('USERENV', 'INSTANCE_NAME') as instance_name,
                SYS_CONTEXT('USERENV', 'SERVICE_NAME') as service_name
            FROM DUAL
            """
            
            debug_result = await db_handler.execute_sql(debug_sql, "CDB$ROOT")
            logger.info(f"Debug connection info: {debug_result}")
            
            # Get container information
            container_sql = """
            SELECT 
                CON_ID,
                NAME,
                OPEN_MODE,
                RESTRICTED,
                TOTAL_SIZE,
                CREATE_SCN,
                OPEN_TIME,
                RECOVERY_STATUS,
                PDB_COUNT,
                LOCAL_UNDO
            FROM V$CONTAINERS
            """
            
            if not include_seed:
                container_sql += " WHERE NAME != 'PDB$SEED'"
            
            container_sql += " ORDER BY CON_ID"
            
            container_result = await db_handler.execute_sql(container_sql, "CDB$ROOT")
            
            containers = []
            if container_result["success"] and container_result["results"][0]["data"]:
                containers = container_result["results"][0]["data"]
                
                # Convert datetime objects to strings for JSON serialization
                for container in containers:
                    if container.get("OPEN_TIME") and hasattr(container["OPEN_TIME"], "isoformat"):
                        container["OPEN_TIME"] = container["OPEN_TIME"].isoformat()
                    if container.get("UNDO_TIME") and hasattr(container["UNDO_TIME"], "isoformat"):
                        container["UNDO_TIME"] = container["UNDO_TIME"].isoformat()
                    if container.get("CREATION_TIME") and hasattr(container["CREATION_TIME"], "isoformat"):
                        container["CREATION_TIME"] = container["CREATION_TIME"].isoformat()
                    if container.get("LAST_CHANGE") and hasattr(container["LAST_CHANGE"], "isoformat"):
                        container["LAST_CHANGE"] = container["LAST_CHANGE"].isoformat()
                    if container.get("CLOSE_TIME") and hasattr(container["CLOSE_TIME"], "isoformat"):
                        container["CLOSE_TIME"] = container["CLOSE_TIME"].isoformat()
            
            # Get wallet status for each container
            wallet_status = await db_handler.get_wallet_status("v$")
            wallet_by_container = {}
            
            for status in wallet_status:
                con_id = status.get("CON_ID", 0)
                if con_id not in wallet_by_container:
                    wallet_by_container[con_id] = []
                wallet_by_container[con_id].append(status)
            
            # Combine container info with wallet status
            for container in containers:
                con_id = container["CON_ID"]
                container["wallet_status"] = wallet_by_container.get(con_id, [])
                container["wallet_open"] = any(w["STATUS"] == "OPEN" for w in container["wallet_status"])
            
            # Summary
            total_containers = len(containers)
            open_containers = len([c for c in containers if c.get("OPEN_MODE") == "READ WRITE"])
            wallets_open = len([c for c in containers if c.get("wallet_open", False)])
            
            result_data = {
                "success": True,
                "operation": "list_oracle_containers",
                "connection": oracle_connection,
                "include_seed": include_seed,
                "debug_info": debug_result.get("results", [{}])[0].get("data", [{}])[0] if debug_result.get("success") else None,
                "summary": {
                    "total_containers": total_containers,
                    "open_containers": open_containers,
                    "wallets_open": wallets_open,
                    "cdb": next((c for c in containers if c.get("CON_ID") == 1), None),
                    "pdbs": [c for c in containers if c.get("CON_ID", 0) > 1]
                },
                "containers": containers,
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== list_oracle_containers completed ===")
            return json.dumps(result_data, indent=2)
            
        except Exception as e:
            logger.error(f"Error listing containers: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    @server.tool()
    async def list_oracle_tablespaces(
        oracle_connection: str,
        container: str = "CDB$ROOT",
        encrypted_only: bool = False,
        show_details: bool = True
    ) -> str:
        """
        List Oracle tablespaces with optional encryption filtering.
        
        Args:
            oracle_connection: Oracle database connection name
            container: Container name - "CDB$ROOT" or PDB name
            encrypted_only: Show only encrypted tablespaces (default: False)
            show_details: Include detailed information (default: True)
            
        Returns:
            JSON string containing tablespace information.
        """
        try:
            logger.info(f"=== list_oracle_tablespaces called ===")
            logger.info(f"Container: {container}, Encrypted only: {encrypted_only}")
            
            db_handler = db_manager.get_database_handler(oracle_connection)
            
            # Build query - use only columns that exist in all Oracle versions
            ts_sql = """
            SELECT 
                vt.NAME AS TABLESPACE_NAME,
                CASE 
                    WHEN vet.TS# IS NOT NULL THEN 'YES'
                    ELSE 'NO'
                END AS ENCRYPTED,
                vt.CON_ID
            FROM V$TABLESPACE vt
            LEFT JOIN V$ENCRYPTED_TABLESPACES vet ON vt.TS# = vet.TS# AND vt.CON_ID = vet.CON_ID
            WHERE vt.NAME NOT IN (
                'SYSTEM', 'SYSAUX', 'TEMP', 'UNDOTBS1', 'UNDOTBS2',
                'TEMP_TBS', 'TEMP_TBS1', 'TEMP_TBS2', 'PDB$SEED'
            )
            """
            
            if encrypted_only:
                ts_sql += " AND vet.TS# IS NOT NULL"
            
            ts_sql += " ORDER BY vt.NAME"
            
            ts_result = await db_handler.execute_sql(ts_sql, container)
            
            tablespaces = []
            if ts_result["success"] and ts_result["results"][0]["data"]:
                tablespaces = ts_result["results"][0]["data"]
                
                # Convert any binary data to string representation
                for ts in tablespaces:
                    for field_name, field_value in ts.items():
                        if isinstance(field_value, bytes):
                            ts[field_name] = field_value.hex().upper()
            
            # Get additional details from DBA_TABLESPACES if show_details is True
            if show_details and tablespaces:
                # Get detailed info for each tablespace
                for ts in tablespaces:
                    ts_name = ts["TABLESPACE_NAME"]
                    detail_sql = f"""
                    SELECT 
                        TABLESPACE_NAME,
                        STATUS,
                        CONTENTS,
                        LOGGING,
                        FORCE_LOGGING,
                        EXTENT_MANAGEMENT,
                        ALLOCATION_TYPE,
                        SEGMENT_SPACE_MANAGEMENT,
                        BIGFILE
                    FROM DBA_TABLESPACES 
                    WHERE TABLESPACE_NAME = '{ts_name}'
                    """
                    
                    detail_result = await db_handler.execute_sql(detail_sql, container)
                    
                    if detail_result["success"] and detail_result["results"][0]["data"]:
                        detail = detail_result["results"][0]["data"][0]
                        ts.update({
                            "status": detail.get("STATUS"),
                            "contents": detail.get("CONTENTS"),
                            "logging": detail.get("LOGGING"),
                            "force_logging": detail.get("FORCE_LOGGING"),
                            "extent_management": detail.get("EXTENT_MANAGEMENT"),
                            "allocation_type": detail.get("ALLOCATION_TYPE"),
                            "segment_space_management": detail.get("SEGMENT_SPACE_MANAGEMENT"),
                            "bigfile": detail.get("BIGFILE")
                        })
            
            # Get space usage information
            space_sql = """
            SELECT 
                TABLESPACE_NAME,
                BYTES,
                BLOCKS,
                MAXBYTES,
                MAXBLOCKS,
                USER_BYTES,
                USER_BLOCKS
            FROM DBA_DATA_FILES
            """
            
            space_result = await db_handler.execute_sql(space_sql, container)
            
            space_by_ts = {}
            if space_result["success"] and space_result["results"][0]["data"]:
                for space in space_result["results"][0]["data"]:
                    ts_name = space["TABLESPACE_NAME"]
                    if ts_name not in space_by_ts:
                        space_by_ts[ts_name] = {
                            "total_bytes": 0,
                            "total_blocks": 0,
                            "max_bytes": 0,
                            "max_blocks": 0,
                            "user_bytes": 0,
                            "user_blocks": 0,
                            "data_files": 0
                        }
                    
                    space_by_ts[ts_name]["total_bytes"] += space["BYTES"] or 0
                    space_by_ts[ts_name]["total_blocks"] += space["BLOCKS"] or 0
                    space_by_ts[ts_name]["max_bytes"] += space["MAXBYTES"] or 0
                    space_by_ts[ts_name]["max_blocks"] += space["MAXBLOCKS"] or 0
                    space_by_ts[ts_name]["user_bytes"] += space["USER_BYTES"] or 0
                    space_by_ts[ts_name]["user_blocks"] += space["USER_BLOCKS"] or 0
                    space_by_ts[ts_name]["data_files"] += 1
            
            # Combine tablespace info with space usage
            for ts in tablespaces:
                ts_name = ts["TABLESPACE_NAME"]
                ts["space_usage"] = space_by_ts.get(ts_name, {})
            
            # Summary
            total_tablespaces = len(tablespaces)
            encrypted_tablespaces = len([ts for ts in tablespaces if ts["ENCRYPTED"] == "YES"])
            online_tablespaces = len([ts for ts in tablespaces if ts.get("status") == "ONLINE"])
            
            result_data = {
                "success": True,
                "operation": "list_oracle_tablespaces",
                "connection": oracle_connection,
                "container": container,
                "encrypted_only": encrypted_only,
                "show_details": show_details,
                "summary": {
                    "total_tablespaces": total_tablespaces,
                    "encrypted_tablespaces": encrypted_tablespaces,
                    "online_tablespaces": online_tablespaces,
                    "offline_tablespaces": total_tablespaces - online_tablespaces
                },
                "tablespaces": tablespaces,
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== list_oracle_tablespaces completed ===")
            return json.dumps(result_data, indent=2)
            
        except Exception as e:
            logger.error(f"Error listing tablespaces: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    @server.tool()
    async def assess_oracle_tde_comprehensive(
        oracle_connection: str,
        include_recommendations: bool = True,
        include_debug_info: bool = False
    ) -> str:
        """
        Comprehensive Oracle TDE assessment combining all readiness, setup, and verification checks.
        
        Args:
            oracle_connection: Oracle database connection name
            include_recommendations: Include actionable recommendations (default: True)
            include_debug_info: Include debug information for troubleshooting (default: False)
            
        Returns:
            JSON string containing comprehensive TDE assessment.
        """
        try:
            logger.info(f"=== assess_oracle_tde_comprehensive called ===")
            
            db_handler = db_manager.get_database_handler(oracle_connection)
            
            assessment = {
                "database_info": {},
                "tde_configuration": {},
                "wallet_status": {},
                "encryption_keys": {},
                "encrypted_objects": {},
                "container_status": {},
                "overall_assessment": {},
                "recommendations": []
            }
            
            # 1. Database Version and Edition
            version_sql = """
            SELECT BANNER
            FROM V$VERSION
            WHERE BANNER LIKE 'Oracle Database%'
            """
            
            version_result = await db_handler.execute_sql(version_sql, "CDB$ROOT")
            if version_result["success"] and version_result["results"][0]["data"]:
                version_info = version_result["results"][0]["data"][0]
                banner = version_info["BANNER"]
                supports_tde = (
                    "Enterprise Edition" in banner or
                    "Enterprise" in banner or
                    "EE" in banner
                )
                
                assessment["database_info"] = {
                    "banner": banner,
                    "supports_tde": supports_tde
                }
            else:
                assessment["database_info"] = {
                    "banner": "Unknown",
                    "supports_tde": False,
                    "debug_info": version_result if include_debug_info else None
                }
            
            # 2. TDE Configuration Parameters
            config_sql = """
            SELECT NAME, VALUE, ISDEFAULT, ISMODIFIED
            FROM V$PARAMETER
            WHERE NAME IN ('tde_configuration', 'wallet_root', 'encrypt_new_tablespaces', 'compatible')
            ORDER BY NAME
            """
            
            config_result = await db_handler.execute_sql(config_sql, "CDB$ROOT")
            current_config = {}
            
            if config_result["success"]:
                for row in config_result["results"][0]["data"]:
                    param_name = row["NAME"]
                    param_value = row["VALUE"]
                    is_default = row["ISDEFAULT"] == "TRUE"
                    is_modified = row["ISMODIFIED"] == "TRUE"
                    
                    effectively_configured = (
                        is_modified or
                        (param_value and not is_default) or
                        (param_name in ['wallet_root', 'tde_configuration'] and param_value)
                    )
                    
                    current_config[param_name] = {
                        "value": param_value,
                        "is_default": is_default,
                        "is_modified": is_modified,
                        "effectively_configured": effectively_configured
                    }
            
            assessment["tde_configuration"] = current_config
            
            # 3. Wallet Status
            try:
                wallet_status = await db_handler.get_wallet_status("v$", "CDB$ROOT")
                wallet_open = any(w["STATUS"] == "OPEN" for w in wallet_status)
                
                assessment["wallet_status"] = {
                    "is_open": wallet_open,
                    "total_entries": len(wallet_status),
                    "details": wallet_status
                }
            except Exception as e:
                assessment["wallet_status"] = {
                    "is_open": False,
                    "total_entries": 0,
                    "details": [],
                    "error": str(e) if include_debug_info else None
                }
            
            # 4. Encryption Keys
            mek_sql = """
            SELECT 
                COUNT(*) AS MEK_COUNT,
                MAX(ACTIVATION_TIME) AS LATEST_MEK
            FROM V$ENCRYPTION_KEYS
            """
            
            mek_result = await db_handler.execute_sql(mek_sql, "CDB$ROOT")
            mek_info = {"count": 0, "latest": None}
            
            if mek_result["success"] and mek_result["results"][0]["data"]:
                mek_data = mek_result["results"][0]["data"][0]
                mek_info["count"] = mek_data["MEK_COUNT"]
                if mek_data["LATEST_MEK"] and hasattr(mek_data["LATEST_MEK"], "isoformat"):
                    mek_info["latest"] = mek_data["LATEST_MEK"].isoformat()
            else:
                if include_debug_info:
                    mek_info["debug_info"] = mek_result
            
            assessment["encryption_keys"] = mek_info
            
            # 5. Encrypted Objects (exclude system tablespaces and PDB$SEED)
            objects_sql = """
            SELECT 
                (SELECT COUNT(*) 
                 FROM V$TABLESPACE vt
                 INNER JOIN V$ENCRYPTED_TABLESPACES vet ON vt.TS# = vet.TS# AND vt.CON_ID = vet.CON_ID
                 INNER JOIN V$CONTAINERS c ON vt.CON_ID = c.CON_ID
                 WHERE vt.NAME NOT IN ('SYSTEM', 'SYSAUX', 'TEMP', 'UNDOTBS1', 'UNDOTBS2', 'USERS')
                 AND vt.NAME NOT LIKE 'SYS%'
                 AND vt.NAME NOT LIKE 'AUX%'
                 AND vt.NAME NOT LIKE 'TEMP%'
                 AND vt.NAME NOT LIKE 'UNDO%'
                 AND vt.NAME NOT LIKE 'USERS%'
                 AND vt.NAME NOT LIKE 'PDB$SEED%'
                 AND c.OPEN_MODE = 'READ WRITE') AS ENCRYPTED_TABLESPACES,
                (SELECT COUNT(*) FROM DBA_ENCRYPTED_COLUMNS) AS ENCRYPTED_COLUMNS
            FROM DUAL
            """
            
            # Get detailed encrypted tablespace information using V$ views
            detailed_ts_sql = """
            SELECT 
                vt.NAME AS TABLESPACE_NAME,
                vt.CON_ID,
                c.NAME AS CONTAINER_NAME,
                'YES' AS ENCRYPTED,
                vet.ENCRYPTION_ALG,
                vet.ENCRYPTION_ALG_PARAM,
                vet.ENCRYPTION_ALG_SALT,
                vet.ENCRYPTION_ALG_INTEGRITY
            FROM V$TABLESPACE vt
            INNER JOIN V$ENCRYPTED_TABLESPACES vet ON vt.TS# = vet.TS# AND vt.CON_ID = vet.CON_ID
            INNER JOIN V$CONTAINERS c ON vt.CON_ID = c.CON_ID
            WHERE vt.NAME NOT IN ('SYSTEM', 'SYSAUX', 'TEMP', 'UNDOTBS1', 'UNDOTBS2', 'USERS')
            AND vt.NAME NOT LIKE 'SYS%'
            AND vt.NAME NOT LIKE 'AUX%'
            AND vt.NAME NOT LIKE 'TEMP%'
            AND vt.NAME NOT LIKE 'UNDO%'
            AND vt.NAME NOT LIKE 'USERS%'
            AND vt.NAME NOT LIKE 'PDB$SEED%'
            AND c.OPEN_MODE = 'READ WRITE'
            ORDER BY c.NAME, vt.NAME
            """
            
            objects_result = await db_handler.execute_sql(objects_sql, "CDB$ROOT")
            detailed_ts_result = await db_handler.execute_sql(detailed_ts_sql, "CDB$ROOT")
            
            encrypted_objects = {
                "tablespaces": 0, 
                "columns": 0,
                "tablespace_details": []
            }
            
            if objects_result["success"] and objects_result["results"][0]["data"]:
                obj_data = objects_result["results"][0]["data"][0]
                encrypted_objects["tablespaces"] = obj_data["ENCRYPTED_TABLESPACES"]
                encrypted_objects["columns"] = obj_data["ENCRYPTED_COLUMNS"]
            
            if detailed_ts_result["success"] and detailed_ts_result["results"][0]["data"]:
                encrypted_objects["tablespace_details"] = detailed_ts_result["results"][0]["data"]
            
            assessment["encrypted_objects"] = encrypted_objects
            
            # 6. Container Status (exclude PDB$SEED)
            container_sql = """
            SELECT COUNT(*) as container_count
            FROM V$CONTAINERS
            WHERE OPEN_MODE = 'READ WRITE'
            AND NAME != 'PDB$SEED'
            """
            
            container_result = await db_handler.execute_sql(container_sql, "CDB$ROOT")
            open_containers = 0
            if container_result["success"] and container_result["results"][0]["data"]:
                open_containers = container_result["results"][0]["data"][0]["CONTAINER_COUNT"]
            
            assessment["container_status"] = {
                "open_containers": open_containers,
                "status": "ready" if open_containers > 0 else "no_open_containers"
            }
            
            # 7. Determine Overall Assessment
            has_mek = mek_info["count"] > 0
            has_encrypted_objects = encrypted_objects["tablespaces"] > 0 or encrypted_objects["columns"] > 0
            has_wallet_config = current_config.get("tde_configuration", {}).get("value")
            has_wallet_root = current_config.get("wallet_root", {}).get("value")
            
            # Determine TDE state
            if has_mek or has_encrypted_objects:
                if wallet_open:
                    tde_state = "fully_configured"
                else:
                    tde_state = "configured_wallet_closed"
            elif has_wallet_config and has_wallet_root:
                if wallet_open:
                    tde_state = "configured_no_mek"
                else:
                    tde_state = "partially_configured"
            elif has_wallet_config or has_wallet_root:
                tde_state = "partially_configured"
            else:
                tde_state = "not_configured"
            
            # Overall readiness
            all_ready = (
                assessment["database_info"].get("supports_tde", False) and
                has_wallet_root and
                wallet_open and
                has_mek and
                open_containers > 0
            )
            
            assessment["overall_assessment"] = {
                "tde_state": tde_state,
                "supports_tde": assessment["database_info"].get("supports_tde", False),
                "needs_setup": tde_state == "not_configured",
                "needs_wallet_open": tde_state == "configured_wallet_closed",
                "ready_for_use": tde_state == "fully_configured",
                "overall_readiness": "ready" if all_ready else "not_ready",
                "summary": {
                    "parameters_configured": bool(has_wallet_root and has_wallet_config),
                    "wallet_operational": wallet_open,
                    "meks_configured": has_mek,
                    "encryption_in_use": has_encrypted_objects,
                    "containers_ready": open_containers > 0
                }
            }
            
            # 8. Generate Recommendations
            if include_recommendations:
                recommendations = []
                
                if not assessment["database_info"].get("supports_tde", False):
                    recommendations.append({
                        "priority": "CRITICAL",
                        "category": "Database Edition",
                        "recommendation": "TDE requires Oracle Enterprise Edition",
                        "action": "Upgrade to Enterprise Edition"
                    })
                
                if tde_state == "not_configured":
                    recommendations.append({
                        "priority": "HIGH",
                        "category": "TDE Setup",
                        "recommendation": "TDE is not configured. Use setup_oracle_tde_from_scratch",
                        "action": "Run complete TDE setup"
                    })
                
                if not has_wallet_root:
                    recommendations.append({
                        "priority": "HIGH",
                        "category": "Configuration",
                        "recommendation": "WALLET_ROOT parameter not set",
                        "action": "Set wallet root directory path"
                    })
                
                if not has_wallet_config:
                    recommendations.append({
                        "priority": "HIGH",
                        "category": "Configuration",
                        "recommendation": "TDE_CONFIGURATION parameter not set",
                        "action": "Configure TDE wallet type (HSM, FILE, or HSM|FILE)"
                    })
                
                if tde_state == "configured_wallet_closed":
                    recommendations.append({
                        "priority": "MEDIUM",
                        "category": "Wallet Status",
                        "recommendation": "TDE is configured but wallet is closed",
                        "action": "Open wallet using manage_oracle_wallet tool"
                    })
                
                if tde_state == "configured_no_mek":
                    recommendations.append({
                        "priority": "MEDIUM",
                        "category": "Key Management",
                        "recommendation": "TDE is configured but no Master Encryption Keys found",
                        "action": "Generate MEKs using generate_oracle_mek tool"
                    })
                
                if tde_state == "fully_configured" and current_config.get("encrypt_new_tablespaces", {}).get("value") == "MANUAL":
                    recommendations.append({
                        "priority": "LOW",
                        "category": "Auto-Encryption", 
                        "recommendation": "Consider enabling automatic tablespace encryption",
                        "action": "Set ENCRYPT_NEW_TABLESPACES to DDL or ALWAYS"
                    })
                
                assessment["recommendations"] = recommendations
            
            result_data = {
                "success": True,
                "operation": "assess_oracle_tde_comprehensive",
                "connection": oracle_connection,
                "assessment": assessment,
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== assess_oracle_tde_comprehensive completed ===")
            return json.dumps(result_data, indent=2)
            
        except Exception as e:
            logger.error(f"Error in comprehensive TDE assessment: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            }) 
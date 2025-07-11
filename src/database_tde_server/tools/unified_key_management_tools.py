"""
Unified key management tools for SQL Server and Oracle databases
"""

import json
import logging
from typing import Optional
from datetime import datetime

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

def register_unified_key_management_tools(server: FastMCP, db_manager):
    """Register unified key management tools with the MCP server"""
    
    # ============================================================================
    # SQL SERVER KEY MANAGEMENT TOOLS
    # ============================================================================
    
    @server.tool()
    async def list_sql_cryptographic_providers(sql_connection: str) -> str:
        """
        List all cryptographic providers configured on the SQL Server.
        
        Args:
            sql_connection: Name of the database connection
            
        Returns:
            JSON string containing cryptographic provider information.
        """
        try:
            db_handler = db_manager.get_database_handler(sql_connection)
            providers = await db_handler.list_cryptographic_providers()
            return json.dumps({
                "success": True,
                "providers": providers,
                "timestamp": datetime.now().isoformat()
            }, indent=2)
        except Exception as e:
            logger.error(f"Error listing cryptographic providers: {e}")
            return json.dumps({"success": False, "error": str(e)})
    
    @server.tool()
    async def create_sql_master_key(
        sql_connection: str,
        provider_name: str,
        key_name: str,
        key_type: str = "RSA",
        key_size: Optional[int] = None
    ) -> str:
        """
        Create a master key in SQL Server.
        
        Args:
            sql_connection: Database connection name
            provider_name: Cryptographic provider name
            key_name: Name of the key to create
            key_type: Key type RSA or AES (default: RSA)
            key_size: Key size in bits. If not specified, defaults to 2048 for RSA, 256 for AES
            
        Returns:
            JSON string containing key creation results.
        """
        try:
            # Set appropriate default key size based on type
            if key_size is None:
                if key_type.upper() == "RSA":
                    key_size = 2048
                else:  # AES
                    key_size = 256
            
            db_handler = db_manager.get_database_handler(sql_connection)
            
            # Check if key already exists
            existing_keys = await db_handler.list_master_keys(key_type)
            is_asymmetric = key_type.upper() == "RSA"
            key_list = existing_keys.get("asymmetric_keys" if is_asymmetric else "symmetric_keys", [])
            
            if any(k["name"] == key_name for k in key_list):
                return json.dumps({
                    "success": False,
                    "error": f"Key '{key_name}' already exists",
                    "existing_key": next(k for k in key_list if k["name"] == key_name)
                })
            
            # Create the key
            create_result = await db_handler.create_master_key(
                key_name, provider_name, key_size, key_type
            )
            
            if not create_result.get("success", False):
                return json.dumps(create_result)
            
            # Get updated key list
            updated_keys = await db_handler.list_master_keys(key_type)
            updated_key_list = updated_keys.get("asymmetric_keys" if is_asymmetric else "symmetric_keys", [])
            new_key = next((k for k in updated_key_list if k["name"] == key_name), None)
            
            result = {
                "success": True,
                "operation": "create_sql_master_key",
                "key_name": key_name,
                "key_type": key_type,
                "key_size": key_size,
                "provider_name": provider_name,
                "algorithm": create_result.get("algorithm"),
                "steps": create_result.get("steps", []),
                "new_key_info": new_key,
                "timestamp": datetime.now().isoformat()
            }
            
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error creating master key: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    @server.tool()
    async def manage_sql_master_keys(
        sql_connection: str,
        operation: str,
        key_name: Optional[str] = None,
        key_type: Optional[str] = None,
        force: bool = False,
        remove_from_provider: bool = False
    ) -> str:
        """
        List or drop SQL Server master keys.
        
        Args:
            sql_connection: Database connection name
            operation: "list" to list keys, "drop" to drop a specific key, "drop_unused" to drop unused keys
            key_name: Key name (required for "drop" operation)
            key_type: Optional filter - "RSA" or "AES", None for all types
            force: Force drop operation (for "drop" operation)
            remove_from_provider: Remove key from provider after dropping (for "drop" operations)
            
        Returns:
            JSON string containing key management results.
        """
        try:
            logger.info(f"=== manage_sql_master_keys called ===")
            logger.info(f"Operation: {operation}, Key type: {key_type}")
            
            db_handler = db_manager.get_database_handler(sql_connection)
            
            if operation == "list":
                # List master keys
                keys = await db_handler.list_master_keys(key_type)
                
                # Get key usage information
                key_usage_sql = """
                SELECT DISTINCT
                    COALESCE(ak.name, sk.name) as key_name,
                    CASE 
                        WHEN ak.name IS NOT NULL THEN 'RSA'
                        WHEN sk.name IS NOT NULL THEN 'AES'
                    END as key_type
                FROM sys.dm_database_encryption_keys dek
                LEFT JOIN master.sys.asymmetric_keys ak ON dek.encryptor_thumbprint = ak.thumbprint
                LEFT JOIN master.sys.symmetric_keys sk ON dek.encryptor_thumbprint = sk.key_guid
                WHERE COALESCE(ak.name, sk.name) IS NOT NULL
                """
                
                usage_result = await db_handler.execute_sql(key_usage_sql)
                used_keys = set()
                
                if usage_result["success"] and usage_result["results"][0]["data"]:
                    used_keys = {row["key_name"] for row in usage_result["results"][0]["data"]}
                
                # Add usage information to keys
                for key in keys.get("asymmetric_keys", []):
                    key["is_used"] = key["name"] in used_keys
                
                for key in keys.get("symmetric_keys", []):
                    key["is_used"] = key["name"] in used_keys
                
                result = {
                    "success": True,
                    "operation": "list_sql_master_keys",
                    "connection": sql_connection,
                    "key_type_filter": key_type,
                    "keys": keys,
                    "summary": {
                        "total_asymmetric_keys": len(keys.get("asymmetric_keys", [])),
                        "total_symmetric_keys": len(keys.get("symmetric_keys", [])),
                        "used_keys": len(used_keys),
                        "unused_keys": len(keys.get("asymmetric_keys", []) + keys.get("symmetric_keys", [])) - len(used_keys)
                    },
                    "timestamp": datetime.now().isoformat()
                }
                
                return json.dumps(result, indent=2)
                
            elif operation == "drop":
                # Drop specific key
                if not key_name:
                    return json.dumps({
                        "success": False,
                        "error": "key_name is required for drop operation"
                    })
                
                if not key_type:
                    return json.dumps({
                        "success": False,
                        "error": "key_type is required for drop operation"
                    })
                
                # Check if key exists and is used
                keys = await db_handler.list_master_keys(key_type)
                is_asymmetric = key_type.upper() == "RSA"
                key_list = keys.get("asymmetric_keys" if is_asymmetric else "symmetric_keys", [])
                
                if not any(k["name"] == key_name for k in key_list):
                    return json.dumps({
                        "success": False,
                        "error": f"Key '{key_name}' not found"
                    })
                
                # Check if key is in use
                key_usage_sql = """
                SELECT DISTINCT
                    COALESCE(ak.name, sk.name) as key_name
                FROM sys.dm_database_encryption_keys dek
                LEFT JOIN master.sys.asymmetric_keys ak ON dek.encryptor_thumbprint = ak.thumbprint
                LEFT JOIN master.sys.symmetric_keys sk ON dek.encryptor_thumbprint = sk.key_guid
                WHERE COALESCE(ak.name, sk.name) = ?
                """
                
                usage_result = await db_handler.execute_sql(key_usage_sql, params=[key_name])
                is_used = usage_result["success"] and usage_result["results"][0]["data"]
                
                if is_used and not force:
                    return json.dumps({
                        "success": False,
                        "error": f"Key '{key_name}' is currently in use. Use force=True to drop anyway."
                    })
                
                # Drop the key
                drop_result = await db_handler.drop_master_key(
                    key_name, key_type, force, remove_from_provider
                )
                
                if not drop_result.get("success", False):
                    return json.dumps(drop_result)
                
                result = {
                    "success": True,
                    "operation": "drop_sql_master_key",
                    "connection": sql_connection,
                    "key_name": key_name,
                    "key_type": key_type,
                    "force": force,
                    "remove_from_provider": remove_from_provider,
                    "was_used": is_used,
                    "steps": drop_result.get("steps", []),
                    "timestamp": datetime.now().isoformat()
                }
                
                return json.dumps(result, indent=2)
                
            elif operation == "drop_unused":
                # Drop unused keys
                keys = await db_handler.list_master_keys(key_type)
                
                # Get used keys
                key_usage_sql = """
                SELECT DISTINCT
                    COALESCE(ak.name, sk.name) as key_name
                FROM sys.dm_database_encryption_keys dek
                LEFT JOIN master.sys.asymmetric_keys ak ON dek.encryptor_thumbprint = ak.thumbprint
                LEFT JOIN master.sys.symmetric_keys sk ON dek.encryptor_thumbprint = sk.key_guid
                WHERE COALESCE(ak.name, sk.name) IS NOT NULL
                """
                
                usage_result = await db_handler.execute_sql(key_usage_sql)
                used_keys = set()
                
                if usage_result["success"] and usage_result["results"][0]["data"]:
                    used_keys = {row["key_name"] for row in usage_result["results"][0]["data"]}
                
                # Find unused keys
                unused_keys = []
                for key_type_name in ["asymmetric_keys", "symmetric_keys"]:
                    if key_type and key_type_name != f"{key_type.lower()}_keys":
                        continue
                    for key in keys.get(key_type_name, []):
                        if key["name"] not in used_keys:
                            unused_keys.append({
                                "name": key["name"],
                                "type": "RSA" if key_type_name == "asymmetric_keys" else "AES"
                            })
                
                if not unused_keys:
                    return json.dumps({
                        "success": True,
                        "operation": "drop_unused_sql_master_keys",
                        "connection": sql_connection,
                        "message": "No unused keys found",
                        "dropped_keys": [],
                        "timestamp": datetime.now().isoformat()
                    })
                
                # Drop unused keys
                dropped_keys = []
                failed_keys = []
                
                for key_info in unused_keys:
                    try:
                        drop_result = await db_handler.drop_master_key(
                            key_info["name"], key_info["type"], False, remove_from_provider
                        )
                        if drop_result.get("success", False):
                            dropped_keys.append(key_info["name"])
                        else:
                            failed_keys.append({
                                "name": key_info["name"],
                                "error": drop_result.get("error")
                            })
                    except Exception as e:
                        failed_keys.append({
                            "name": key_info["name"],
                            "error": str(e)
                        })
                
                result = {
                    "success": len(dropped_keys) > 0,
                    "operation": "drop_unused_sql_master_keys",
                    "connection": sql_connection,
                    "key_type_filter": key_type,
                    "remove_from_provider": remove_from_provider,
                    "summary": {
                        "total_unused": len(unused_keys),
                        "dropped": len(dropped_keys),
                        "failed": len(failed_keys)
                    },
                    "dropped_keys": dropped_keys,
                    "failed_keys": failed_keys,
                    "timestamp": datetime.now().isoformat()
                }
                
                return json.dumps(result, indent=2)
                
            else:
                return json.dumps({
                    "success": False,
                    "error": f"Invalid operation '{operation}'. Must be 'list', 'drop', or 'drop_unused'"
                })
            
        except Exception as e:
            logger.error(f"Error managing master keys: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    @server.tool()
    async def rotate_sql_database_encryption_key(
        sql_connection: str,
        database_name: str,
        algorithm: Optional[str] = None
    ) -> str:
        """
        Rotate (regenerate) the Database Encryption Key (DEK) for a SQL Server database.
        Uses the same algorithm as current DEK unless specified otherwise.
        
        Args:
            sql_connection: Database connection name
            database_name: Name of the database
            algorithm: Optional new algorithm (if not provided, uses current algorithm)
        
        Returns:
            JSON string containing key rotation results.
        """
        try:
            db_handler = db_manager.get_database_handler(sql_connection)
            
            rotation_result = await db_handler.rotate_database_encryption_key(
                database_name, algorithm
            )
            
            # Get updated status
            updated_status = await db_handler.check_encryption_status(database_name)
            
            return json.dumps({
                "success": True,
                "operation": "rotate_sql_database_encryption_key",
                "database": database_name,
                "algorithm_used": rotation_result["algorithm_used"],
                "rotation_result": rotation_result["rotation_result"],
                "updated_status": [
                    {
                        "database_name": status.database_name,
                        "encryption_state": status.encryption_state,
                        "encryption_state_desc": status.encryption_state_desc,
                        "key_algorithm": status.key_algorithm,
                        "key_length": status.key_length
                    }
                    for status in updated_status
                ],
                "timestamp": datetime.now().isoformat()
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error rotating database encryption key: {e}")
            return json.dumps({"success": False, "error": str(e)})
    
    @server.tool()
    async def rotate_sql_master_key(
        sql_connection: str,
        database_name: str,
        new_key_name: str,
        provider_name: str,
        ciphertrust_username: str,
        ciphertrust_password: str,
        ciphertrust_domain: str = "root",
        key_type: str = "RSA",
        key_size: Optional[int] = None
    ) -> str:
        """
        Rotate the master key for a SQL Server database's TDE encryption.
        This creates new infrastructure and switches the DEK to use the new master key.
        
        Args:
            sql_connection: Database connection name
            database_name: Name of the database
            new_key_name: Name of the new master key
            provider_name: Cryptographic provider name
            ciphertrust_username: CipherTrust Manager username
            ciphertrust_password: CipherTrust Manager password
            ciphertrust_domain: CipherTrust Manager domain (default: root)
            key_type: Key type RSA or AES (default: RSA)
            key_size: Key size in bits. If not specified, defaults to 2048 for RSA, 256 for AES
        
        Returns:
            JSON string containing master key rotation results.
        """
        try:
            # Set appropriate default key size based on type
            if key_size is None:
                if key_type.upper() == "RSA":
                    key_size = 2048
                else:  # AES
                    key_size = 256
            
            db_handler = db_manager.get_database_handler(sql_connection)
            
            rotation_result = await db_handler.rotate_master_key(
                database_name, new_key_name, provider_name,
                ciphertrust_username, ciphertrust_password, ciphertrust_domain,
                key_size, key_type
            )
            
            # Get updated status
            updated_status = await db_handler.check_encryption_status(database_name)
            
            return json.dumps({
                "success": True,
                "operation": "rotate_sql_master_key",
                "database": database_name,
                "new_key_name": new_key_name,
                "algorithm": rotation_result["algorithm"],
                "steps": rotation_result["steps"],
                "updated_status": [
                    {
                        "database_name": status.database_name,
                        "encryption_state": status.encryption_state,
                        "encryption_state_desc": status.encryption_state_desc,
                        "key_algorithm": status.key_algorithm,
                        "key_length": status.key_length
                    }
                    for status in updated_status
                ],
                "timestamp": datetime.now().isoformat()
            }, indent=2)
            
        except Exception as e:
            logger.error(f"Error rotating master key: {e}")
            return json.dumps({"success": False, "error": str(e)})
    
    # ============================================================================
    # ORACLE KEY MANAGEMENT TOOLS - OPERATIONAL ONLY
    # ============================================================================
    # 
    # NOTE: MEK generation and activation are handled by workflow-based tools:
    # - setup_oracle_tde_from_scratch: For new TDE implementations 
    # - migrate_tde: For wallet migrations (includes key migration)
    # - rotate_oracle_mek: For key rotation (includes activation)
    # 
    # These operational tools focus on post-setup maintenance:
    
    @server.tool()
    async def rotate_oracle_mek(
        oracle_connection: str,
        container: str,
        wallet_password: str,
        backup_tag: Optional[str] = None,
        force: bool = False
    ) -> str:
        """
        Rotate Oracle Master Encryption Key for operational maintenance.
        
        Args:
            oracle_connection: Oracle database connection name
            container: Container name - "CDB$ROOT", "ALL", or specific PDB name
            wallet_password: Wallet password in format "domain::username:password" or "username:password"
            backup_tag: Optional backup identifier (auto-generated if not provided)
            force: Force rotation using FORCE KEYSTORE option
            
        Returns:
            JSON string containing MEK rotation results.
        """
        try:
            logger.info(f"=== rotate_oracle_mek called ===")
            logger.info(f"Container: {container}, Force: {force}")
            
            db_handler = db_manager.get_database_handler(oracle_connection)
            
            # Generate backup tag if not provided
            if not backup_tag:
                timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
                backup_tag = f"mek_rotation_{container}_{timestamp}"
            
            # Ensure wallet is open
            open_result = await db_handler.open_wallet(container, wallet_password)
            if not open_result.get("success", False):
                logger.warning("Failed to open wallet, it might already be open")
            
            # Get current MEK info before rotation
            old_mek_sql = """
            SELECT 
                KEY_ID,
                HEX_MKID,
                TAG,
                ACTIVATION_TIME
            FROM V$ENCRYPTION_KEYS
            WHERE ROWNUM = 1
            ORDER BY ACTIVATION_TIME DESC
            """
            
            old_mek_result = await db_handler.execute_sql(old_mek_sql, container)
            old_mek_info = None
            if old_mek_result["success"] and old_mek_result["results"][0]["data"]:
                old_mek_info = old_mek_result["results"][0]["data"][0]
                if old_mek_info.get("ACTIVATION_TIME") and hasattr(old_mek_info["ACTIVATION_TIME"], "isoformat"):
                    old_mek_info["ACTIVATION_TIME"] = old_mek_info["ACTIVATION_TIME"].isoformat()
                
                # Convert binary data to string representation
                if old_mek_info.get("HEX_MKID") and isinstance(old_mek_info["HEX_MKID"], bytes):
                    old_mek_info["HEX_MKID"] = old_mek_info["HEX_MKID"].hex().upper()
                
                # Convert any other binary fields
                for field_name, field_value in old_mek_info.items():
                    if isinstance(field_value, bytes):
                        old_mek_info[field_name] = field_value.hex().upper()
            
            # Build rotation command with proper CONTAINER clause
            if container.upper() in ["CDB$ROOT", "ALL"]:
                # Use CONTAINER=ALL for CDB-wide operations
                if force:
                    rotate_sql = f"""
                    ADMINISTER KEY MANAGEMENT SET KEY 
                    FORCE KEYSTORE 
                    IDENTIFIED BY "{wallet_password}" 
                    WITH BACKUP USING '{backup_tag}'
                    CONTAINER = ALL
                    """
                else:
                    rotate_sql = f"""
                    ADMINISTER KEY MANAGEMENT SET KEY 
                    IDENTIFIED BY "{wallet_password}" 
                    WITH BACKUP USING '{backup_tag}'
                    CONTAINER = ALL
                    """
            else:
                # Use specific container for PDB operations
                if force:
                    rotate_sql = f"""
                    ADMINISTER KEY MANAGEMENT SET KEY 
                    FORCE KEYSTORE 
                    IDENTIFIED BY "{wallet_password}" 
                    WITH BACKUP USING '{backup_tag}'
                    """
                else:
                    rotate_sql = f"""
                    ADMINISTER KEY MANAGEMENT SET KEY 
                    IDENTIFIED BY "{wallet_password}" 
                    WITH BACKUP USING '{backup_tag}'
                    """
            
            # Execute rotation
            rotate_result = await db_handler.execute_sql(rotate_sql, container)
            
            if not rotate_result.get("success", False):
                return json.dumps({
                    "success": False,
                    "error": f"MEK rotation failed: {rotate_result.get('error')}"
                })
            
            # Get new MEK info after rotation
            new_mek_sql = """
            SELECT 
                KEY_ID,
                HEX_MKID,
                TAG,
                ACTIVATION_TIME
            FROM V$ENCRYPTION_KEYS
            WHERE ACTIVATION_TIME >= SYSDATE - INTERVAL '5' MINUTE
            ORDER BY ACTIVATION_TIME DESC
            """
            
            new_mek_result = await db_handler.execute_sql(new_mek_sql, container)
            
            new_mek_info = None
            if new_mek_result["success"] and new_mek_result["results"][0]["data"]:
                new_mek_info = new_mek_result["results"][0]["data"][0]
                if new_mek_info.get("ACTIVATION_TIME") and hasattr(new_mek_info["ACTIVATION_TIME"], "isoformat"):
                    new_mek_info["ACTIVATION_TIME"] = new_mek_info["ACTIVATION_TIME"].isoformat()
                
                # Convert binary data to string representation
                if new_mek_info.get("HEX_MKID") and isinstance(new_mek_info["HEX_MKID"], bytes):
                    new_mek_info["HEX_MKID"] = new_mek_info["HEX_MKID"].hex().upper()
                
                # Convert any other binary fields
                for field_name, field_value in new_mek_info.items():
                    if isinstance(field_value, bytes):
                        new_mek_info[field_name] = field_value.hex().upper()
            
            result_data = {
                "success": True,
                "operation": "rotate_oracle_mek",
                "connection": oracle_connection,
                "container": container,
                "backup_tag": backup_tag,
                "force_rotation": force,
                "previous_mek": old_mek_info,
                "new_mek": new_mek_info,
                "rotation_command": rotate_sql,
                "summary": {
                    "rotation_successful": new_mek_info is not None,
                    "new_key_id": new_mek_info["KEY_ID"] if new_mek_info else None,
                    "container_scope": "ALL" if container.upper() in ["CDB$ROOT", "ALL"] else container
                },
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== rotate_oracle_mek completed ===")
            return json.dumps(result_data, indent=2)
            
        except Exception as e:
            logger.error(f"Error rotating MEK: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    @server.tool()
    async def list_oracle_encryption_keys(
        oracle_connection: str,
        container: Optional[str] = None,
        key_id_filter: Optional[str] = None,
        active_only: bool = True,
        include_history: bool = False
    ) -> str:
        """
        List Oracle encryption keys from v$encryption_keys view.
        
        Args:
            oracle_connection: Oracle database connection name
            container: Optional container filter (CDB$ROOT or PDB name)
            key_id_filter: Optional key ID filter
            active_only: Show only active keys (default: True)
            include_history: Include historical keys (default: False)
            
        Returns:
            JSON string containing encryption key information.
        """
        try:
            logger.info(f"=== list_oracle_encryption_keys called ===")
            logger.info(f"Container: {container}, Active only: {active_only}")
            
            db_handler = db_manager.get_database_handler(oracle_connection)
            
            # Build query using the correct V$ENCRYPTION_KEYS view with proper columns
            keys_sql = """
            SELECT 
                KEY_ID,
                HEX_MKID,
                TAG,
                CREATION_TIME,
                ACTIVATION_TIME,
                CREATOR,
                CREATOR_ID,
                USER,
                USER_ID,
                KEY_USE,
                KEYSTORE_TYPE,
                ORIGIN,
                BACKED_UP,
                CREATOR_DBNAME,
                CREATOR_DBID,
                CREATOR_INSTANCE_NAME,
                CREATOR_INSTANCE_NUMBER,
                CREATOR_INSTANCE_SERIAL,
                CREATOR_PDBNAME,
                CREATOR_PDBID,
                CREATOR_PDBUID,
                CREATOR_PDBGUID,
                ACTIVATING_DBNAME,
                ACTIVATING_DBID,
                ACTIVATING_INSTANCE_NAME,
                ACTIVATING_INSTANCE_NUMBER,
                ACTIVATING_INSTANCE_SERIAL,
                ACTIVATING_PDBNAME,
                ACTIVATING_PDBID,
                ACTIVATING_PDBUID,
                ACTIVATING_PDBGUID,
                CON_ID
            FROM V$ENCRYPTION_KEYS
            """
            
            where_conditions = []
            
            if key_id_filter:
                where_conditions.append(f"KEY_ID = '{key_id_filter}'")
            
            if active_only:
                # For Oracle, we consider keys as active if they have an ACTIVATION_TIME
                where_conditions.append("ACTIVATION_TIME IS NOT NULL")
            
            if where_conditions:
                keys_sql += " WHERE " + " AND ".join(where_conditions)
            
            keys_sql += " ORDER BY ACTIVATION_TIME DESC"
            
            keys_result = await db_handler.execute_sql(keys_sql, container or "CDB$ROOT")
            
            keys = []
            if keys_result["success"] and keys_result["results"][0]["data"]:
                for key in keys_result["results"][0]["data"]:
                    # Convert datetime objects to strings
                    if key.get("CREATION_TIME") and hasattr(key["CREATION_TIME"], "isoformat"):
                        key["CREATION_TIME"] = key["CREATION_TIME"].isoformat()
                    if key.get("ACTIVATION_TIME") and hasattr(key["ACTIVATION_TIME"], "isoformat"):
                        key["ACTIVATION_TIME"] = key["ACTIVATION_TIME"].isoformat()
                    
                    # Convert binary data to string representation
                    if key.get("HEX_MKID") and isinstance(key["HEX_MKID"], bytes):
                        key["HEX_MKID"] = key["HEX_MKID"].hex().upper()
                    
                    # Convert any other binary fields
                    for field_name, field_value in key.items():
                        if isinstance(field_value, bytes):
                            key[field_name] = field_value.hex().upper()
                    
                    keys.append(key)
            
            # Group keys by creator PDB
            keys_by_pdb = {}
            for key in keys:
                pdb_name = key.get("CREATOR_PDBNAME", "CDB$ROOT")
                if pdb_name not in keys_by_pdb:
                    keys_by_pdb[pdb_name] = []
                keys_by_pdb[pdb_name].append(key)
            
            # Summary
            active_keys = [k for k in keys if k.get("ACTIVATION_TIME") is not None]
            
            result_data = {
                "success": True,
                "operation": "list_oracle_encryption_keys",
                "connection": oracle_connection,
                "container_filter": container,
                "key_id_filter": key_id_filter,
                "active_only": active_only,
                "include_history": include_history,
                "summary": {
                    "total_keys": len(keys),
                    "active_keys": len(active_keys),
                    "containers_with_keys": len(keys_by_pdb),
                    "latest_activation": keys[0]["ACTIVATION_TIME"] if keys and keys[0].get("ACTIVATION_TIME") else None
                },
                "keys_by_container": keys_by_pdb,
                "all_keys": keys,
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== list_oracle_encryption_keys completed ===")
            return json.dumps(result_data, indent=2)
            
        except Exception as e:
            logger.error(f"Error listing encryption keys: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            }) 
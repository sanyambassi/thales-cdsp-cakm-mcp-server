"""
Unified encryption and decryption tools for SQL Server and Oracle databases
"""

import json
import logging
import asyncio
from typing import Optional, List
from datetime import datetime

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

def register_unified_encryption_tools(server: FastMCP, db_manager):
    """Register unified encryption and decryption tools with the MCP server"""
    
    # ============================================================================
    # SQL SERVER ENCRYPTION TOOLS
    # ============================================================================
    
    @server.tool()
    async def encrypt_sql_databases(
        database_names: str,
        sql_connection: str,
        provider_name: str,
        ciphertrust_username: str,
        ciphertrust_password: str,
        key_name: str,
        ciphertrust_domain: str = "root",
        key_type: str = "RSA",
        key_size: Optional[int] = None
    ) -> str:
        """
        Encrypt one or more SQL Server databases with TDE using CAKM EKM provider.

        Args:
            database_names: Name of database(s) to encrypt. Can be:
                - Single database name (e.g., "MyDatabase")
                - Comma-separated list (e.g., "DB1,DB2,DB3")
                - "all databases" to encrypt all user databases
            sql_connection: Database connection name
            provider_name: Cryptographic provider name
            ciphertrust_username: CipherTrust Manager username
            ciphertrust_password: CipherTrust Manager password
            key_name: Master key name (will create if doesn't exist)
            ciphertrust_domain: CipherTrust Manager domain (default: root)
            key_type: Key type RSA or AES (default: RSA)
            key_size: Key size in bits. If not specified, defaults to 2048 for RSA, 256 for AES

        Returns:
            JSON string containing encryption operation results.
        """
        try:
            logger.info(f"=== encrypt_sql_databases called ===")
            logger.info(f"database_names: '{database_names}'")
            logger.info(f"sql_connection: '{sql_connection}'")
            logger.info(f"provider_name: '{provider_name}'")
            logger.info(f"key_name: '{key_name}'")
            
            # Set appropriate default key size based on type
            if key_size is None:
                if key_type.upper() == "RSA":
                    key_size = 2048
                else:  # AES
                    key_size = 256
            
            db_handler = db_manager.get_database_handler(sql_connection)

            # Parse database list
            if "all databases" in database_names.lower():
                # Get all user databases
                databases_sql = """
                SELECT name FROM sys.databases 
                WHERE database_id > 4 
                AND state_desc = 'ONLINE'
                AND name NOT IN ('master', 'tempdb', 'model', 'msdb')
                ORDER BY name
                """
                result = await db_handler.execute_sql(databases_sql)
                if not result["success"]:
                    return json.dumps({
                        "success": False,
                        "error": f"Failed to get database list: {result.get('error')}"
                    })
                target_databases = [row["name"] for row in result["results"][0]["data"]]
            else:
                # Parse comma-separated list
                target_databases = [db.strip() for db in database_names.split(",") if db.strip()]

            if not target_databases:
                return json.dumps({
                    "success": False,
                    "error": "No valid databases specified"
                })

            # Step 1: Check if cryptographic provider exists
            logger.info(f"Step 1: Checking if provider '{provider_name}' exists")
            providers = await db_handler.list_cryptographic_providers()
            provider_exists = any(p["name"] == provider_name for p in providers)
            logger.info(f"Provider exists: {provider_exists}")

            if not provider_exists:
                logger.error(f"Cryptographic provider '{provider_name}' not found")
                return json.dumps({
                    "success": False,
                    "error": f"Cryptographic provider '{provider_name}' not found. Please create it first."
                })

            # Step 2: Create TDE infrastructure (will use existing key or create new)
            logger.info(f"Step 2: Creating TDE infrastructure for key: '{key_name}'")
            infrastructure_result = await db_handler.create_tde_infrastructure(
                key_name, provider_name, ciphertrust_username, ciphertrust_password,
                ciphertrust_domain, key_size, key_type
            )
            
            # Check if infrastructure creation failed
            if not infrastructure_result.get("success", True):
                logger.error(f"Infrastructure creation failed: {infrastructure_result.get('error')}")
                return json.dumps({
                    "success": False,
                    "error": infrastructure_result.get("error"),
                    "existing_credential": infrastructure_result.get("existing_credential"),
                    "attempted_credential": infrastructure_result.get("attempted_credential")
                })
            
            logger.info(f"Infrastructure result: key_existed={infrastructure_result.get('key_existed', False)}")

            # Step 3: Process each database
            results = []
            successful_encryptions = 0
            
            for database_name in target_databases:
                logger.info(f"Processing database: {database_name}")
                
                # Check if database already encrypted
                encryption_status = await db_handler.check_encryption_status(database_name)
                if encryption_status and encryption_status[0].is_encrypted:
                    logger.warning(f"Database '{database_name}' is already encrypted")
                    results.append({
                        "database": database_name,
                        "success": False,
                        "error": f"Database '{database_name}' is already encrypted"
                    })
                    continue

                # Encrypt the database
                logger.info(f"Encrypting database '{database_name}' with key '{key_name}'")
                encryption_result = await db_handler.encrypt_database(
                    database_name, key_name, infrastructure_result["is_asymmetric"]
                )
                
                # Get final status
                final_status = await db_handler.check_encryption_status(database_name)
                
                # Check if encryption was successful
                encryption_success = False
                if final_status and len(final_status) > 0:
                    state = final_status[0].encryption_state
                    # State 3 means encrypted, state 2 means encryption in progress
                    encryption_success = state in [2, 3]
                
                if encryption_success:
                    successful_encryptions += 1
                
                results.append({
                    "database": database_name,
                    "success": encryption_success,
                    "encryption_steps": encryption_result["steps"],
                    "final_status": [
                        {
                            "database_name": status.database_name,
                            "encryption_state": status.encryption_state,
                            "encryption_state_desc": status.encryption_state_desc,
                            "percent_complete": status.percent_complete
                        }
                        for status in final_status
                    ]
                })

            result = {
                "success": successful_encryptions > 0,
                "operation": "encrypt_sql_databases",
                "connection": sql_connection,
                "key_name": key_name,
                "key_existed": infrastructure_result.get("key_existed", False),
                "algorithm": infrastructure_result["algorithm"],
                "infrastructure_steps": infrastructure_result["steps"],
                "total_databases": len(target_databases),
                "successful_encryptions": successful_encryptions,
                "failed_encryptions": len(target_databases) - successful_encryptions,
                "database_results": results,
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== encrypt_sql_databases completed with {successful_encryptions}/{len(target_databases)} successful ===")
            return json.dumps(result, indent=2)

        except Exception as e:
            logger.error(f"Error encrypting databases: {e}", exc_info=True)
            return json.dumps({"success": False, "error": str(e)})
    
    @server.tool()
    async def decrypt_sql_databases(
        sql_connection: str,
        database_names: str
    ) -> str:
        """
        Decrypt one or more SQL Server databases with TDE.
        
        Args:
            sql_connection: Database connection name
            database_names: Name of database(s) to decrypt. Can be:
                - Single database name (e.g., "MyDatabase")
                - Comma-separated list (e.g., "DB1,DB2,DB3")
                - "all databases" to decrypt all encrypted databases
        
        Returns:
            JSON string containing decryption operation results.
        """
        try:
            logger.info(f"=== decrypt_sql_databases called ===")
            logger.info(f"database_names: '{database_names}'")
            logger.info(f"sql_connection: '{sql_connection}'")
            
            db_handler = db_manager.get_database_handler(sql_connection)
            
            # Parse database list
            if "all databases" in database_names.lower():
                # Get all encrypted databases
                encrypted_dbs_sql = """
                SELECT DISTINCT d.name
                FROM sys.databases d
                INNER JOIN sys.dm_database_encryption_keys dek ON d.database_id = dek.database_id
                WHERE d.database_id > 4
                AND d.state_desc = 'ONLINE'
                AND d.name NOT IN ('master', 'tempdb', 'model', 'msdb')
                ORDER BY d.name
                """
                result = await db_handler.execute_sql(encrypted_dbs_sql)
                if not result["success"]:
                    return json.dumps({
                        "success": False,
                        "error": f"Failed to get encrypted database list: {result.get('error')}"
                    })
                target_databases = [row["name"] for row in result["results"][0]["data"]]
            else:
                # Parse comma-separated list
                target_databases = [db.strip() for db in database_names.split(",") if db.strip()]

            if not target_databases:
                return json.dumps({
                    "success": False,
                    "error": "No valid databases specified"
                })

            # Process each database
            results = []
            successful_decryptions = 0
            failed_count = 0
            in_progress_count = 0
            not_encrypted = []
            
            for database_name in target_databases:
                logger.info(f"Processing database: {database_name}")
                
                # Check if database is encrypted
                encryption_status = await db_handler.check_encryption_status(database_name)
                if not encryption_status or not encryption_status[0].is_encrypted:
                    logger.warning(f"Database '{database_name}' is not encrypted")
                    not_encrypted.append(database_name)
                    results.append({
                        "database": database_name,
                        "success": False,
                        "error": "Database is not encrypted",
                        "skipped": True
                    })
                    continue

                # Check if decryption is already in progress
                state = encryption_status[0].encryption_state
                if state == 1:  # Decryption in progress
                    logger.info(f"Database '{database_name}' decryption already in progress")
                    in_progress_count += 1
                    results.append({
                        "database": database_name,
                        "success": False,
                        "error": "Decryption already in progress",
                        "in_progress": True
                    })
                    continue

                # Decrypt the database
                logger.info(f"Decrypting database '{database_name}'")
                decryption_result = await db_handler.decrypt_database(database_name)
                
                if decryption_result.get("success", False):
                    successful_decryptions += 1
                else:
                    failed_count += 1
                
                results.append({
                    "database": database_name,
                    "success": decryption_result.get("success", False),
                    "steps": decryption_result.get("steps", []),
                    "error": decryption_result.get("error") if not decryption_result.get("success", False) else None
                })

            # Get final status for all databases
            all_final_status = await db_handler.check_encryption_status()
            
            result = {
                "success": successful_decryptions > 0,
                "operation": "decrypt_sql_databases",
                "connection": sql_connection,
                "total_databases": len(target_databases),
                "successful_decryptions": successful_decryptions,
                "failed_decryptions": failed_count,
                "in_progress": in_progress_count,
                "not_encrypted": len(not_encrypted),
                "database_results": results,
                "final_status": [
                    {
                        "database_name": status.database_name,
                        "is_encrypted": status.is_encrypted,
                        "encryption_state": status.encryption_state,
                        "encryption_state_desc": status.encryption_state_desc,
                        "percent_complete": status.percent_complete
                    }
                    for status in all_final_status
                ],
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== decrypt_sql_databases completed with {successful_decryptions}/{len(target_databases)} successful ===")
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error decrypting databases: {e}", exc_info=True)
            return json.dumps({"success": False, "error": str(e)})
    
    # ============================================================================
    # ORACLE ENCRYPTION TOOLS
    # ============================================================================
    
    @server.tool()
    async def encrypt_oracle_tablespace(
        oracle_connection: str,
        container: str,
        tablespace_names: str,
        method: str = "online"
    ) -> str:
        """
        Encrypt Oracle tablespaces using AES256 encryption.
        
        Args:
            oracle_connection: Oracle database connection name
            container: Container name - "CDB$ROOT" or PDB name
            tablespace_names: Comma-separated list of tablespace names
            method: Encryption method - "online" | "offline" (default: online, falls back to offline)
            
        Returns:
            JSON string containing encryption results.
        """
        try:
            logger.info(f"=== encrypt_oracle_tablespace called ===")
            logger.info(f"Container: {container}, Tablespaces: {tablespace_names}")
            
            db_handler = db_manager.get_database_handler(oracle_connection)
            
            # Parse tablespace names
            tablespaces = [ts.strip() for ts in tablespace_names.split(',')]
            
            # Check wallet status first
            wallet_status = await db_handler.get_wallet_status("v$", container)
            
            wallet_open = False
            if wallet_status and len(wallet_status) > 0:
                wallet_open = any(w["STATUS"] == "OPEN" for w in wallet_status)
            
            if not wallet_open:
                return json.dumps({
                    "success": False,
                    "error": "Wallet is not open. Open the wallet first or configure auto-login."
                })
            
            results = []
            successful_count = 0
            failed_count = 0
            
            for tablespace_name in tablespaces:
                # Check current encryption status
                check_sql = f"""
                SELECT TABLESPACE_NAME, ENCRYPTED, STATUS, BIGFILE
                FROM DBA_TABLESPACES
                WHERE TABLESPACE_NAME = '{tablespace_name}'
                """
                
                check_result = await db_handler.execute_sql(check_sql, container)
                
                if not (check_result["success"] and check_result["results"][0]["data"]):
                    results.append({
                        "tablespace": tablespace_name,
                        "success": False,
                        "error": "Tablespace not found"
                    })
                    failed_count += 1
                    continue
                
                ts_info = check_result["results"][0]["data"][0]
                
                if ts_info["ENCRYPTED"] == "YES":
                    results.append({
                        "tablespace": tablespace_name,
                        "success": False,
                        "error": "Tablespace is already encrypted",
                        "skipped": True
                    })
                    continue
                
                # Encrypt the tablespace (Oracle automatically uses AES256)
                encrypt_result = await db_handler.encrypt_tablespace(
                    container,
                    tablespace_name,
                    "AES256",  # Fixed to AES256 for Oracle
                    method == "online"
                )
                
                if encrypt_result["success"]:
                    successful_count += 1
                else:
                    failed_count += 1
                
                results.append({
                    "tablespace": tablespace_name,
                    "success": encrypt_result["success"],
                    "algorithm": "AES256",  # Always AES256 for Oracle
                    "method": encrypt_result.get("method", method),
                    "steps": encrypt_result.get("steps", []),
                    "error": encrypt_result.get("error") if not encrypt_result["success"] else None
                })
            
            # Get final encryption status
            final_status_sql = """
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
            
            final_result = await db_handler.execute_sql(final_status_sql, container)
            
            encrypted_tablespaces = []
            if final_result["success"] and final_result["results"][0]["data"]:
                encrypted_tablespaces = [ts["TABLESPACE_NAME"] for ts in final_result["results"][0]["data"]]
            
            result_data = {
                "success": successful_count > 0,
                "operation": "encrypt_oracle_tablespace",
                "connection": oracle_connection,
                "container": container,
                "algorithm": "AES256",  # Always AES256 for Oracle
                "summary": {
                    "requested": len(tablespaces),
                    "successful": successful_count,
                    "failed": failed_count,
                    "skipped": len([r for r in results if r.get("skipped", False)])
                },
                "results": results,
                "total_encrypted_tablespaces": len(encrypted_tablespaces),
                "encrypted_tablespaces": encrypted_tablespaces,
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== encrypt_oracle_tablespace completed ===")
            return json.dumps(result_data, indent=2)
            
        except Exception as e:
            logger.error(f"Error encrypting tablespace: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    @server.tool()
    async def list_oracle_encrypted_objects(
        oracle_connection: str,
        container: Optional[str] = None,
        object_type: str = "tablespace"
    ) -> str:
        """
        List encrypted objects in Oracle database.
        
        Args:
            oracle_connection: Oracle database connection name
            container: Optional container filter (CDB$ROOT or PDB name)
            object_type: Type of objects - "tablespace" | "table" | "column"
            
        Returns:
            JSON string containing encrypted objects information.
        """
        try:
            logger.info(f"=== list_oracle_encrypted_objects called ===")
            logger.info(f"Container: {container}, Type: {object_type}")
            
            db_handler = db_manager.get_database_handler(oracle_connection)
            
            results = {}
            
            if object_type in ["tablespace", "all"]:
                # List encrypted tablespaces using V$ views
                ts_sql = """
                SELECT 
                    vt.NAME AS TABLESPACE_NAME,
                    CASE 
                        WHEN vet.TS# IS NOT NULL THEN 'YES'
                        ELSE 'NO'
                    END AS ENCRYPTED,
                    vt.CON_ID
                FROM V$TABLESPACE vt
                INNER JOIN V$ENCRYPTED_TABLESPACES vet ON vt.TS# = vet.TS# AND vt.CON_ID = vet.CON_ID
                WHERE vt.NAME NOT IN (
                    'SYSTEM', 'SYSAUX', 'TEMP', 'UNDOTBS1', 'UNDOTBS2',
                    'TEMP_TBS', 'TEMP_TBS1', 'TEMP_TBS2', 'PDB$SEED'
                )
                ORDER BY vt.NAME
                """
                
                ts_result = await db_handler.execute_sql(ts_sql, container or "CDB$ROOT")
                
                if ts_result["success"] and ts_result["results"][0]["data"]:
                    encrypted_tablespaces = ts_result["results"][0]["data"]
                    
                    # Convert any binary data to string representation
                    for ts in encrypted_tablespaces:
                        for field_name, field_value in ts.items():
                            if isinstance(field_value, bytes):
                                ts[field_name] = field_value.hex().upper()
                    
                    results["encrypted_tablespaces"] = encrypted_tablespaces
                else:
                    results["encrypted_tablespaces"] = []
            
            if object_type in ["table", "all"]:
                # List tables in encrypted tablespaces
                table_sql = """
                SELECT 
                    t.OWNER,
                    t.TABLE_NAME,
                    t.TABLESPACE_NAME,
                    ts.ENCRYPTED,
                    t.NUM_ROWS,
                    t.BLOCKS,
                    t.LAST_ANALYZED
                FROM DBA_TABLES t
                JOIN DBA_TABLESPACES ts ON t.TABLESPACE_NAME = ts.TABLESPACE_NAME
                WHERE ts.ENCRYPTED = 'YES'
                AND ts.TABLESPACE_NAME NOT IN (
                    'SYSTEM', 'SYSAUX', 'TEMP', 'UNDOTBS1', 'UNDOTBS2',
                    'TEMP_TBS', 'TEMP_TBS1', 'TEMP_TBS2',
                    'USERS', 'EXAMPLE', 'PDB$SEED',
                    'SYSTEM', 'SYSTEMAUX', 'TEMP', 'UNDO', 'UNDOTBS',
                    'TEMP_TBS', 'USERS', 'EXAMPLE'
                )
                AND ts.CONTENTS NOT IN ('UNDO', 'TEMPORARY')
                AND t.OWNER NOT IN ('SYS', 'SYSTEM', 'OUTLN', 'DIP', 'ORACLE_OCM', 'APPQOSSYS', 'DBSNMP', 'CTXSYS', 'XDB', 'ANONYMOUS', 'EXFSYS', 'MDDATA', 'DBSFWUSER', 'REMOTE_SCHEDULER_AGENT', 'SI_INFORMTN_SCHEMA', 'ORDDATA', 'ORDSYS', 'MDSYS', 'OLAPSYS', 'WMSYS', 'APEX_040000', 'APEX_PUBLIC_USER', 'FLOWS_FILES', 'MDDATA', 'ORACLE_OCM', 'SPATIAL_CSW_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR', 'APEX_040000', 'APEX_PUBLIC_USER', 'FLOWS_FILES', 'MDDATA', 'ORACLE_OCM', 'SPATIAL_CSW_ADMIN_USR', 'SPATIAL_WFS_ADMIN_USR')
                ORDER BY t.OWNER, t.TABLE_NAME
                """
                
                table_result = await db_handler.execute_sql(table_sql, container or "CDB$ROOT")
                
                if table_result["success"] and table_result["results"][0]["data"]:
                    results["encrypted_tables"] = table_result["results"][0]["data"]
                else:
                    results["encrypted_tables"] = []
            
            if object_type in ["column", "all"]:
                # List encrypted columns
                column_sql = """
                SELECT 
                    c.OWNER,
                    c.TABLE_NAME,
                    c.COLUMN_NAME,
                    c.ENCRYPTION_ALG,
                    c.SALT,
                    c.INTEGRITY_ALG
                FROM DBA_ENCRYPTED_COLUMNS c
                ORDER BY c.OWNER, c.TABLE_NAME, c.COLUMN_NAME
                """
                
                column_result = await db_handler.execute_sql(column_sql, container or "CDB$ROOT")
                
                if column_result["success"] and column_result["results"][0]["data"]:
                    results["encrypted_columns"] = column_result["results"][0]["data"]
                else:
                    results["encrypted_columns"] = []
            
            # Summary
            summary = {
                "encrypted_tablespaces": len(results.get("encrypted_tablespaces", [])),
                "encrypted_tables": len(results.get("encrypted_tables", [])),
                "encrypted_columns": len(results.get("encrypted_columns", []))
            }
            
            result_data = {
                "success": True,
                "operation": "list_oracle_encrypted_objects",
                "connection": oracle_connection,
                "container": container,
                "object_type": object_type,
                "summary": summary,
                "results": results,
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== list_oracle_encrypted_objects completed ===")
            return json.dumps(result_data, indent=2)
            
        except Exception as e:
            logger.error(f"Error listing encrypted objects: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    @server.tool()
    async def check_oracle_tablespace_encryption_status(
        oracle_connection: str,
        container: str,
        tablespace_name: str
    ) -> str:
        """
        Check encryption status of a specific Oracle tablespace.
        
        Args:
            oracle_connection: Oracle database connection name
            container: Container name - "CDB$ROOT" or PDB name
            tablespace_name: Name of the tablespace to check
            
        Returns:
            JSON string containing tablespace encryption status.
        """
        try:
            logger.info(f"=== check_oracle_tablespace_encryption_status called ===")
            logger.info(f"Container: {container}, Tablespace: {tablespace_name}")
            
            db_handler = db_manager.get_database_handler(oracle_connection)
            
            # Check tablespace encryption status
            status_sql = f"""
            SELECT 
                TABLESPACE_NAME,
                ENCRYPTED,
                STATUS,
                BIGFILE,
                ENCRYPTION_ALGORITHM,
                ENCRYPTION_KEY_ID
            FROM DBA_TABLESPACES
            WHERE TABLESPACE_NAME = '{tablespace_name}'
            """
            
            status_result = await db_handler.execute_sql(status_sql, container)
            
            if not (status_result["success"] and status_result["results"][0]["data"]):
                return json.dumps({
                    "success": False,
                    "error": f"Tablespace '{tablespace_name}' not found"
                })
            
            ts_info = status_result["results"][0]["data"][0]
            
            # Get encryption progress if encryption is in progress
            progress_info = None
            if ts_info["ENCRYPTED"] == "ENCRYPTING":
                progress_sql = f"""
                SELECT 
                    TABLESPACE_NAME,
                    ENCRYPTION_PROGRESS,
                    ENCRYPTION_STATUS
                FROM V$ENCRYPTION_PROGRESS
                WHERE TABLESPACE_NAME = '{tablespace_name}'
                """
                
                progress_result = await db_handler.execute_sql(progress_sql, container)
                if progress_result["success"] and progress_result["results"][0]["data"]:
                    progress_info = progress_result["results"][0]["data"][0]
            
            result_data = {
                "success": True,
                "operation": "check_oracle_tablespace_encryption_status",
                "connection": oracle_connection,
                "container": container,
                "tablespace_name": tablespace_name,
                "encryption_status": {
                    "is_encrypted": ts_info["ENCRYPTED"] == "YES",
                    "encryption_state": ts_info["ENCRYPTED"],
                    "status": ts_info["STATUS"],
                    "algorithm": ts_info.get("ENCRYPTION_ALGORITHM"),
                    "key_id": ts_info.get("ENCRYPTION_KEY_ID"),
                    "is_bigfile": ts_info["BIGFILE"] == "YES"
                },
                "encryption_progress": progress_info,
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== check_oracle_tablespace_encryption_status completed ===")
            return json.dumps(result_data, indent=2)
            
        except Exception as e:
            logger.error(f"Error checking tablespace encryption status: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            }) 
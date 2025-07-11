"""
Oracle wallet migration tools for complex TDE migration scenarios
"""

import json
import logging
from typing import Optional, Dict, Any
from datetime import datetime

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

def register_oracle_wallet_migration_tools(server: FastMCP, db_manager):
    """Register Oracle wallet migration tools with the MCP server"""
    
    @server.tool()
    async def migrate_tde(
        oracle_connection: str,
        ciphertrust_username: str,
        ciphertrust_password: str,
        software_wallet_password: str,
        software_wallet_location: str = None,
        ciphertrust_domain: str = "root",
        skip_file_operations: bool = False,
        skip_database_restart: bool = False
    ) -> str:
        """
        Migrate Oracle TDE from software wallet to HSM (CipherTrust Manager).
        Supports both single HSM and dual wallet scenarios, auto-detected from current configuration.
        Operates at CDB level, affecting all containers (CDB + PDBs).
        
        Args:
            oracle_connection: Oracle database connection name
            ciphertrust_username: CipherTrust Manager username
            ciphertrust_password: CipherTrust Manager password
            software_wallet_password: Source software wallet password
            software_wallet_location: Source software wallet directory (auto-detected from config if not provided)
            ciphertrust_domain: CipherTrust Manager domain (default: root)
            skip_file_operations: Skip manual file operations (use when cwallet.sso has been renamed manually)
            skip_database_restart: Skip database restart (use when manual restart is preferred)
            
        Returns:
            JSON string containing migration results.
        """
        try:
            logger.info(f"=== migrate_tde called ===")
            
            db_handler = db_manager.get_database_handler(oracle_connection)
            steps = []
            
            # Get enhanced configuration from database handler's connection
            enhanced_config = {
                "ssh": db_handler.connection.ssh_config.dict() if db_handler.connection.ssh_config else None,
                "oracle": db_handler.connection.oracle_config.dict() if db_handler.connection.oracle_config else None
            }
            ssh_manager = None
            ssh_connected = False
            
            if enhanced_config and enhanced_config.get("ssh"):
                try:
                    from ..utils.ssh_utils import OracleSSHManager
                    ssh_config = enhanced_config["ssh"]
                    ssh_manager = OracleSSHManager(
                        host=ssh_config["host"],
                        username=ssh_config["username"],
                        password=ssh_config["password"],
                        timeout=30,
                        allow_agent=True
                    )
                    ssh_connected = ssh_manager.connect()
                    steps.append({
                        "step": "ssh_connect",
                        "success": ssh_connected,
                        "host": ssh_config["host"]
                    })
                except Exception as e:
                    logger.warning(f"SSH initialization failed: {e}")
                    steps.append({
                        "step": "ssh_connect",
                        "success": False,
                        "error": str(e)
                    })
                    ssh_manager = None
            
            # Auto-detect software wallet location from enhanced configuration if not provided
            if not software_wallet_location and enhanced_config.get("oracle"):
                oracle_config = enhanced_config["oracle"]
                if oracle_config.get("wallet_root"):
                    software_wallet_location = oracle_config["wallet_root"]
                    logger.info(f"Auto-detected software wallet location from config: {software_wallet_location}")
                else:
                    # Fallback to default location
                    software_wallet_location = "$ORACLE_BASE/admin/$ORACLE_SID/wallet"
                    logger.info(f"Using default software wallet location: {software_wallet_location}")
            
            # Get Oracle SID from enhanced configuration for SSH operations
            oracle_sid = None
            if enhanced_config.get("oracle"):
                oracle_sid = enhanced_config["oracle"].get("oracle_sid")
                logger.info(f"Using Oracle SID from config: {oracle_sid}")
            
            # Construct HSM credentials from CipherTrust parameters
            if ciphertrust_domain == "root":
                hsm_credentials = f"{ciphertrust_username}:{ciphertrust_password}"
            else:
                hsm_credentials = f"{ciphertrust_domain}::{ciphertrust_username}:{ciphertrust_password}"
            
            # Auto-generate backup tag
            backup_tag = f"migrate_to_hsm_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Step 1: Detect current wallet type
            wallet_detection_sql = """
            SELECT WRL_TYPE, WALLET_TYPE, STATUS, CON_ID
            FROM V$ENCRYPTION_WALLET
            ORDER BY CON_ID, WRL_TYPE
            """
            
            wallet_result = await db_handler.execute_sql(wallet_detection_sql, "CDB$ROOT")
            
            if not wallet_result["success"] or not wallet_result["results"][0]["data"]:
                return json.dumps({
                    "success": False,
                    "error": "Unable to detect current wallet configuration",
                    "operation": "migrate_tde"
                })
            
            wallet_info = wallet_result["results"][0]["data"]
            
            # Determine wallet type
            is_manual_wallet = any(w.get("WALLET_TYPE") == "PASSWORD" and w.get("STATUS") == "OPEN" for w in wallet_info)
            is_autologin_wallet = any(w.get("WRL_TYPE") == "FILE" and w.get("WALLET_TYPE") == "AUTOLOGIN" and w.get("STATUS") == "OPEN" for w in wallet_info)
            
            steps.append({
                "step": "detect_wallet_type",
                "wallet_info": wallet_info,
                "is_manual": is_manual_wallet,
                "is_autologin": is_autologin_wallet
            })
            
            if not is_manual_wallet and not is_autologin_wallet:
                return json.dumps({
                    "success": False,
                    "error": "Unsupported wallet type. Only manual (PASSWORD) and auto-login (FILE/AUTOLOGIN) wallets are supported.",
                    "operation": "migrate_tde",
                    "detected_wallet_info": wallet_info
                })
            
            # Get current TDE configuration
            config_sql = "SELECT VALUE FROM V$PARAMETER WHERE NAME = 'tde_configuration'"
            config_result = await db_handler.execute_sql(config_sql, "CDB$ROOT")
            current_tde_config = None
            if config_result["success"] and config_result["results"][0]["data"]:
                current_tde_config = config_result["results"][0]["data"][0]["VALUE"]
            
            steps.append({
                "step": "check_current_config",
                "tde_configuration": current_tde_config
            })
            
            if is_manual_wallet:
                # Scenario 1: Manual/Password Software to HSM
                logger.info("Migrating manual/password software wallet to HSM")
                
                # Step 1a: Update TDE configuration to HSM|FILE
                tde_sql = "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=HSM|FILE' SCOPE=BOTH"
                tde_result = await db_handler.execute_sql(tde_sql, "CDB$ROOT")
                steps.append({
                    "step": "update_tde_config_to_hsm_file",
                    "command": tde_sql,
                    "success": tde_result.get("success", False)
                })
                
                # Step 1b: Migrate the key
                migrate_sql = f"""
                ADMINISTER KEY MANAGEMENT SET ENCRYPTION KEY 
                IDENTIFIED BY "{hsm_credentials}" 
                FORCE KEYSTORE MIGRATE USING "{software_wallet_password}" 
                WITH BACKUP USING '{backup_tag}'
                """
                
                migrate_result = await db_handler.execute_sql(migrate_sql, "CDB$ROOT")
                steps.append({
                    "step": "migrate_key_to_hsm",
                    "command": migrate_sql,
                    "success": migrate_result.get("success", False),
                    "result": migrate_result
                })
                
                # Step 1c: Update TDE configuration to HSM only
                tde_hsm_sql = "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=HSM' SCOPE=BOTH"
                tde_hsm_result = await db_handler.execute_sql(tde_hsm_sql, "CDB$ROOT")
                steps.append({
                    "step": "update_tde_config_to_hsm_only",
                    "command": tde_hsm_sql,
                    "success": tde_hsm_result.get("success", False)
                })
            
            elif is_autologin_wallet:
                # Scenario 2: Auto-login Software to HSM
                logger.info("Migrating auto-login software wallet to HSM")
                
                # Step 2a: Rename cwallet.sso file
                wallet_root_sql = "SELECT VALUE FROM V$PARAMETER WHERE NAME = 'wallet_root'"
                wallet_root_result = await db_handler.execute_sql(wallet_root_sql, "CDB$ROOT")
                
                if not wallet_root_result["success"] or not wallet_root_result["results"][0]["data"]:
                    return json.dumps({
                        "success": False,
                        "error": "Unable to determine wallet root location",
                        "operation": "migrate_tde"
                    })
                
                wallet_root = wallet_root_result["results"][0]["data"][0]["VALUE"]
                cwallet_path = f"{wallet_root}/tde/cwallet.sso"
                cwallet_backup_path = f"{wallet_root}/tde/cwallet.sso.bak"
                
                if not skip_file_operations:
                    if ssh_manager:
                        # Use SSH for file operations
                        rename_result = ssh_manager.rename_cwallet_file(f"{wallet_root}/tde")
                        steps.append({
                            "step": "rename_cwallet_via_ssh",
                            "success": rename_result.get("success", False),
                            "stdout": rename_result.get("stdout", ""),
                            "stderr": rename_result.get("stderr", ""),
                            "verification": rename_result.get("verification", "")
                        })
                        
                        if not rename_result.get("success", False):
                            return json.dumps({
                                "success": False,
                                "error": f"SSH file operation failed: {rename_result.get('error', 'Unknown error')}",
                                "operation": "migrate_tde",
                                "steps": steps
                            })
                    else:
                        steps.append({
                            "step": "rename_cwallet_failed",
                            "error": "Failed to rename cwallet.sso file",
                            "manual_instructions": [
                                f"1. Connect to the Oracle server as oracle user",
                                f"2. Navigate to wallet directory: cd {wallet_root}/tde",
                                f"3. Rename the auto-login file: mv cwallet.sso cwallet.sso.bak",
                                f"4. Verify the file is renamed: ls -la cwallet.sso*",
                                f"5. Re-run this migration tool"
                            ]
                        })
                        
                        return json.dumps({
                            "success": False,
                            "error": "Failed to rename cwallet.sso file. Manual intervention required.",
                            "operation": "migrate_tde",
                            "steps": steps,
                            "manual_instructions": steps[-1]["manual_instructions"]
                        })
                else:
                    steps.append({
                        "step": "file_operation_skipped",
                        "message": "File operation skipped - assuming cwallet.sso has been renamed manually",
                        "file_path": cwallet_path,
                        "backup_path": cwallet_backup_path
                    })
                
                # Step 2b: Restart database with SSH support
                logger.info("Restarting database after file rename...")
                
                if ssh_manager:
                    # Use SSH for database restart
                    restart_result = ssh_manager.restart_oracle_database(oracle_sid)
                    steps.append({
                        "step": "restart_database_after_rename",
                        "method": "ssh",
                        "success": restart_result.get("success", False),
                        "stdout": restart_result.get("stdout", ""),
                        "stderr": restart_result.get("stderr", "")
                    })
                    
                    if not restart_result.get("success", False):
                        return json.dumps({
                            "success": False,
                            "error": f"SSH database restart failed: {restart_result.get('error', 'Unknown error')}",
                            "operation": "migrate_tde",
                            "steps": steps
                        })
                else:
                    # Fallback to SQL restart
                    logger.info("Using SQL commands for database restart (SSH not available)...")
                    shutdown_result = await db_handler.execute_sql("SHUTDOWN IMMEDIATE", "CDB$ROOT")
                    steps.append({
                        "step": "shutdown_database",
                        "method": "sql",
                        "success": shutdown_result.get("success", False)
                    })
                    
                    # Wait and try to reconnect
                    import asyncio
                    await asyncio.sleep(10)
                    
                    startup_success = False
                    for attempt in range(3):
                        try:
                            startup_result = await db_handler.execute_sql("STARTUP", "CDB$ROOT")
                            if startup_result.get("success", False):
                                startup_success = True
                                break
                            await asyncio.sleep(10)
                        except Exception as e:
                            logger.warning(f"Startup attempt {attempt + 1} failed: {e}")
                            if attempt < 2:  # Don't sleep after last attempt
                                await asyncio.sleep(10)
                    
                    steps.append({
                        "step": "startup_database",
                        "method": "sql",
                        "success": startup_success,
                        "attempts": 3
                    })
                    
                    if not startup_success:
                        return json.dumps({
                            "success": False,
                            "error": "Failed to restart database after 3 attempts",
                            "operation": "migrate_tde",
                            "steps": steps
                        })
                
                # Step 2c: Open password wallet
                open_software_sql = f"""
                ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN 
                IDENTIFIED BY "{software_wallet_password}"
                CONTAINER = ALL
                """
                
                open_software_result = await db_handler.execute_sql(open_software_sql, "CDB$ROOT")
                steps.append({
                    "step": "open_software_wallet",
                    "command": open_software_sql,
                    "success": open_software_result.get("success", False)
                })
                
                # Step 2d: Add CipherTrust credentials as secret
                add_secret_sql = f"""
                ADMINISTER KEY MANAGEMENT ADD SECRET '{hsm_credentials}' 
                FOR CLIENT 'HSM_PASSWORD' 
                IDENTIFIED BY "{software_wallet_password}" 
                WITH BACKUP
                """
                
                secret_result = await db_handler.execute_sql(add_secret_sql, "CDB$ROOT")
                steps.append({
                    "step": "add_hsm_secret",
                    "command": add_secret_sql,
                    "success": secret_result.get("success", False)
                })
                
                # Step 2e: Create new auto-login keystore
                create_autologin_sql = f"""
                ADMINISTER KEY MANAGEMENT CREATE AUTO_LOGIN KEYSTORE FROM KEYSTORE
                IDENTIFIED BY "{software_wallet_password}"
                """
                
                autologin_result = await db_handler.execute_sql(create_autologin_sql, "CDB$ROOT")
                steps.append({
                    "step": "create_autologin_keystore",
                    "command": create_autologin_sql,
                    "success": autologin_result.get("success", False)
                })
                
                # Step 2f: Restart database again with SSH support
                logger.info("Restarting database again...")
                
                if ssh_manager:
                    # Use SSH for database restart
                    restart_result2 = ssh_manager.restart_oracle_database(oracle_sid)
                    steps.append({
                        "step": "restart_database_second",
                        "method": "ssh",
                        "success": restart_result2.get("success", False),
                        "stdout": restart_result2.get("stdout", ""),
                        "stderr": restart_result2.get("stderr", "")
                    })
                    
                    if not restart_result2.get("success", False):
                        return json.dumps({
                            "success": False,
                            "error": f"SSH database restart (second) failed: {restart_result2.get('error', 'Unknown error')}",
                            "operation": "migrate_tde",
                            "steps": steps
                        })
                else:
                    # Fallback to SQL restart
                    logger.info("Using SQL commands for second database restart (SSH not available)...")
                    shutdown2_result = await db_handler.execute_sql("SHUTDOWN IMMEDIATE", "CDB$ROOT")
                    steps.append({
                        "step": "shutdown_database_second",
                        "method": "sql",
                        "success": shutdown2_result.get("success", False)
                    })
                    
                    await asyncio.sleep(10)
                    
                    startup2_success = False
                    for attempt in range(3):
                        try:
                            startup2_result = await db_handler.execute_sql("STARTUP", "CDB$ROOT")
                            if startup2_result.get("success", False):
                                startup2_success = True
                                break
                            await asyncio.sleep(10)
                        except Exception as e:
                            logger.warning(f"Second startup attempt {attempt + 1} failed: {e}")
                            if attempt < 2:
                                await asyncio.sleep(10)
                    
                    steps.append({
                        "step": "startup_database_second",
                        "method": "sql",
                        "success": startup2_success,
                        "attempts": 3
                    })
                    
                    if not startup2_success:
                        return json.dumps({
                            "success": False,
                            "error": "Failed to restart database second time after 3 attempts",
                            "operation": "migrate_tde",
                            "steps": steps
                        })
                
                # Step 2g: Update TDE configuration
                tde_config_sql = "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=HSM|FILE' SCOPE=BOTH"
                tde_config_result = await db_handler.execute_sql(tde_config_sql, "CDB$ROOT")
                steps.append({
                    "step": "update_tde_configuration",
                    "command": tde_config_sql,
                    "success": tde_config_result.get("success", False)
                })
                
                # Step 2h: Migrate the key
                migrate_autologin_sql = f"""
                ADMINISTER KEY MANAGEMENT SET ENCRYPTION KEY 
                IDENTIFIED BY "{hsm_credentials}" 
                MIGRATE USING "{software_wallet_password}" 
                WITH BACKUP USING '{backup_tag}'
                """
                
                migrate_autologin_result = await db_handler.execute_sql(migrate_autologin_sql, "CDB$ROOT")
                steps.append({
                    "step": "migrate_key_autologin",
                    "command": migrate_autologin_sql,
                    "success": migrate_autologin_result.get("success", False),
                    "result": migrate_autologin_result
                })
            
            # Final verification
            final_wallet_sql = """
            SELECT WRL_TYPE, WALLET_TYPE, STATUS, CON_ID
            FROM V$ENCRYPTION_WALLET
            ORDER BY CON_ID, WRL_TYPE
            """
            
            final_wallet_result = await db_handler.execute_sql(final_wallet_sql, "CDB$ROOT")
            
            if not final_wallet_result["success"] or not final_wallet_result["results"][0]["data"]:
                return json.dumps({
                    "success": False,
                    "error": "Unable to verify final wallet status",
                    "operation": "migrate_tde",
                    "steps": steps
                })
            
            final_wallet_info = final_wallet_result["results"][0]["data"]
            
            # Verify migration success
            migration_success = False
            verification_details = {}
            
            if is_manual_wallet:
                # For manual migration: verify only HSM wallet is present and open
                hsm_wallets = [w for w in final_wallet_info if w.get("WRL_TYPE") == "HSM" and w.get("WALLET_TYPE") == "HSM"]
                hsm_open = all(w.get("STATUS") == "OPEN" for w in hsm_wallets)
                migration_success = len(hsm_wallets) > 0 and hsm_open
                
                verification_details = {
                    "expected": "Only HSM wallet present and open",
                    "found_hsm_wallets": len(hsm_wallets),
                    "hsm_wallets_open": hsm_open,
                    "wallet_details": hsm_wallets
                }
                
            elif is_autologin_wallet:
                # For auto-login migration: verify both wallets are present
                file_wallets = [w for w in final_wallet_info if w.get("WRL_TYPE") == "FILE" and w.get("WALLET_TYPE") == "AUTOLOGIN"]
                hsm_wallets = [w for w in final_wallet_info if w.get("WRL_TYPE") == "HSM" and w.get("WALLET_TYPE") == "HSM"]
                
                file_open = all(w.get("STATUS") in ["OPEN", "OPEN_NO_MASTER_KEY"] for w in file_wallets)
                hsm_open = all(w.get("STATUS") == "OPEN" for w in hsm_wallets)
                
                migration_success = len(file_wallets) > 0 and len(hsm_wallets) > 0 and file_open and hsm_open
                
                verification_details = {
                    "expected": "Both FILE (AUTOLOGIN) and HSM wallets present and open",
                    "found_file_wallets": len(file_wallets),
                    "found_hsm_wallets": len(hsm_wallets),
                    "file_wallets_open": file_open,
                    "hsm_wallets_open": hsm_open,
                    "file_wallet_details": file_wallets,
                    "hsm_wallet_details": hsm_wallets
                }
            
            result_data = {
                "success": migration_success,
                "operation": "migrate_tde",
                "connection": oracle_connection,
                "wallet_type_detected": "manual" if is_manual_wallet else "autologin",
                "backup_tag": backup_tag,
                "hsm_credentials_used": hsm_credentials,
                "steps": steps,
                "final_wallet_status": final_wallet_info,
                "verification": verification_details,
                "post_migration_notes": [
                    "Verify HSM connectivity",
                    "Test encryption operations",
                    "Backup the migrated configuration",
                    "Update documentation"
                ],
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== migrate_tde completed ===")
            if ssh_manager and ssh_connected:
                ssh_manager.disconnect()
            return json.dumps(result_data, indent=2)
            
        except Exception as e:
            logger.error(f"Error migrating TDE to HSM: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation": "migrate_tde"
            })
    
    @server.tool()
    async def reverse_migrate_tde(
        oracle_connection: str,
        ciphertrust_username: str,
        ciphertrust_password: str,
        software_wallet_password: str,
        software_wallet_location: str = None,
        ciphertrust_domain: str = "root",
        skip_file_operations: bool = False,
        skip_database_restart: bool = False
    ) -> str:
        """
        Reverse migrate Oracle TDE from HSM (CipherTrust Manager) to software wallet.
        Supports both single HSM and dual wallet scenarios, auto-detected from current configuration.
        Operates at CDB level, affecting all containers (CDB + PDBs).
        
        Args:
            oracle_connection: Oracle database connection name
            ciphertrust_username: CipherTrust Manager username
            ciphertrust_password: CipherTrust Manager password
            software_wallet_password: Target software wallet password
            software_wallet_location: Target software wallet directory (auto-detected from config if not provided)
            ciphertrust_domain: CipherTrust Manager domain (default: root)
            skip_file_operations: Skip manual file operations (use when cwallet.sso has been renamed manually)
            skip_database_restart: Skip database restart (use when manual restart is preferred)
            
        Returns:
            JSON string containing reverse migration results.
        """
        try:
            logger.info(f"=== reverse_migrate_tde called ===")
            
            db_handler = db_manager.get_database_handler(oracle_connection)
            steps = []
            
            # Get enhanced configuration from database handler's connection
            enhanced_config = {
                "ssh": db_handler.connection.ssh_config.dict() if db_handler.connection.ssh_config else None,
                "oracle": db_handler.connection.oracle_config.dict() if db_handler.connection.oracle_config else None
            }
            ssh_manager = None
            ssh_connected = False
            
            if enhanced_config and enhanced_config.get("ssh"):
                try:
                    from ..utils.ssh_utils import OracleSSHManager
                    ssh_config = enhanced_config["ssh"]
                    ssh_manager = OracleSSHManager(
                        host=ssh_config["host"],
                        username=ssh_config["username"],
                        password=ssh_config["password"],
                        timeout=30,
                        allow_agent=True
                    )
                    ssh_connected = ssh_manager.connect()
                    steps.append({
                        "step": "ssh_connect",
                        "success": ssh_connected,
                        "host": ssh_config["host"]
                    })
                except Exception as e:
                    logger.warning(f"SSH initialization failed: {e}")
                    steps.append({
                        "step": "ssh_connect",
                        "success": False,
                        "error": str(e)
                    })
                    ssh_manager = None
            
            # Auto-detect software wallet location from enhanced configuration if not provided
            if not software_wallet_location and enhanced_config.get("oracle"):
                oracle_config = enhanced_config["oracle"]
                if oracle_config.get("wallet_root"):
                    software_wallet_location = oracle_config["wallet_root"]
                    logger.info(f"Auto-detected software wallet location from config: {software_wallet_location}")
                else:
                    # Fallback to default location
                    software_wallet_location = "$ORACLE_BASE/admin/$ORACLE_SID/wallet"
                    logger.info(f"Using default software wallet location: {software_wallet_location}")
            
            # Get Oracle SID from enhanced configuration for SSH operations
            oracle_sid = None
            if enhanced_config.get("oracle"):
                oracle_sid = enhanced_config["oracle"].get("oracle_sid")
                logger.info(f"Using Oracle SID from config: {oracle_sid}")
            
            # Construct HSM credentials from CipherTrust parameters
            if ciphertrust_domain == "root":
                hsm_credentials = f"{ciphertrust_username}:{ciphertrust_password}"
            else:
                hsm_credentials = f"{ciphertrust_domain}::{ciphertrust_username}:{ciphertrust_password}"
            
            # Auto-generate backup tag
            backup_tag = f"reverse_migrate_to_software_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Step 1: Detect current wallet configuration
            wallet_detection_sql = """
            SELECT WRL_TYPE, WALLET_TYPE, STATUS, CON_ID
            FROM V$ENCRYPTION_WALLET
            ORDER BY CON_ID, WRL_TYPE
            """
            
            wallet_result = await db_handler.execute_sql(wallet_detection_sql, "CDB$ROOT")
            
            if not wallet_result["success"] or not wallet_result["results"][0]["data"]:
                return json.dumps({
                    "success": False,
                    "error": "Unable to detect current wallet configuration",
                    "operation": "reverse_migrate_tde"
                })
            
            wallet_info = wallet_result["results"][0]["data"]
            
            # Determine scenario
            hsm_wallets = [w for w in wallet_info if w.get("WRL_TYPE") == "HSM" and w.get("WALLET_TYPE") == "HSM"]
            file_wallets = [w for w in wallet_info if w.get("WRL_TYPE") == "FILE"]
            
            is_single_hsm = len(hsm_wallets) > 0 and len(file_wallets) == 0
            is_dual_wallets = len(hsm_wallets) > 0 and len(file_wallets) > 0
            
            steps.append({
                "step": "detect_wallet_scenario",
                "wallet_info": wallet_info,
                "hsm_wallets": len(hsm_wallets),
                "file_wallets": len(file_wallets),
                "is_single_hsm": is_single_hsm,
                "is_dual_wallets": is_dual_wallets
            })
            
            if not is_single_hsm and not is_dual_wallets:
                return json.dumps({
                    "success": False,
                    "error": "Unsupported wallet configuration. Only single HSM wallet or dual wallets (FILE + HSM) are supported for reverse migration.",
                    "operation": "reverse_migrate_tde",
                    "detected_wallet_info": wallet_info
                })
            
            # Get current TDE configuration
            config_sql = "SELECT VALUE FROM V$PARAMETER WHERE NAME = 'tde_configuration'"
            config_result = await db_handler.execute_sql(config_sql, "CDB$ROOT")
            current_tde_config = None
            if config_result["success"] and config_result["results"][0]["data"]:
                current_tde_config = config_result["results"][0]["data"][0]["VALUE"]
            
            steps.append({
                "step": "check_current_config",
                "tde_configuration": current_tde_config
            })
            
            if is_single_hsm:
                # Scenario 1: Single HSM to Manual Software
                logger.info("Reverse migrating single HSM wallet to manual software wallet")
                
                # Step 1a: Update TDE configuration to FILE|HSM
                tde_sql = "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=FILE|HSM' SCOPE=BOTH"
                tde_result = await db_handler.execute_sql(tde_sql, "CDB$ROOT")
                steps.append({
                    "step": "update_tde_config_to_file_hsm",
                    "command": tde_sql,
                    "success": tde_result.get("success", False)
                })
                
                # Step 1b: Create software wallet if it doesn't exist
                create_wallet_sql = f"""
                ADMINISTER KEY MANAGEMENT CREATE KEYSTORE 
                IDENTIFIED BY "{software_wallet_password}"
                """
                
                create_wallet_result = await db_handler.execute_sql(create_wallet_sql, "CDB$ROOT")
                steps.append({
                    "step": "create_software_wallet",
                    "command": create_wallet_sql,
                    "success": create_wallet_result.get("success", False),
                    "result": create_wallet_result
                })
                
                # Step 1c: Open the software wallet
                open_wallet_sql = f"""
                ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN 
                IDENTIFIED BY "{software_wallet_password}"
                CONTAINER = ALL
                """
                
                open_wallet_result = await db_handler.execute_sql(open_wallet_sql, "CDB$ROOT")
                steps.append({
                    "step": "open_software_wallet",
                    "command": open_wallet_sql,
                    "success": open_wallet_result.get("success", False),
                    "result": open_wallet_result
                })
                
                # Step 1d: Reverse migrate the key
                reverse_migrate_sql = f"""
                ADMINISTER KEY MANAGEMENT SET ENCRYPTION KEY 
                IDENTIFIED BY "{software_wallet_password}" 
                FORCE KEYSTORE REVERSE MIGRATE USING "{hsm_credentials}" 
                WITH BACKUP USING '{backup_tag}'
                """
                
                reverse_migrate_result = await db_handler.execute_sql(reverse_migrate_sql, "CDB$ROOT")
                steps.append({
                    "step": "reverse_migrate_key",
                    "command": reverse_migrate_sql,
                    "success": reverse_migrate_result.get("success", False),
                    "result": reverse_migrate_result
                })
                
                if not reverse_migrate_result.get("success", False):
                    return json.dumps({
                        "success": False,
                        "error": f"Reverse migration failed: {reverse_migrate_result.get('error', 'Unknown error')}",
                        "operation": "reverse_migrate_tde",
                        "steps": steps
                    })
                
                # Step 1e: Update TDE configuration to FILE only
                tde_file_sql = "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=FILE' SCOPE=BOTH"
                tde_file_result = await db_handler.execute_sql(tde_file_sql, "CDB$ROOT")
                steps.append({
                    "step": "update_tde_config_to_file_only",
                    "command": tde_file_sql,
                    "success": tde_file_result.get("success", False)
                })
                
                # Step 1f: Restart database after configuration change
                if not skip_database_restart:
                    # Check SSH availability with better logging
                    ssh_available = ssh_manager is not None and ssh_connected
                    
                    logger.info(f"SSH restart check: ssh_manager={ssh_manager is not None}, ssh_connected={ssh_connected}")
                    
                    if ssh_available:
                        # Use SSH for database restart
                        logger.info("Restarting database via SSH...")
                        restart_result = ssh_manager.restart_oracle_database(oracle_sid)
                        steps.append({
                            "step": "restart_database_via_ssh",
                            "success": restart_result.get("success", False),
                            "stdout": restart_result.get("stdout", ""),
                            "stderr": restart_result.get("stderr", "")
                        })
                        
                        if not restart_result.get("success", False):
                            return json.dumps({
                                "success": False,
                                "error": f"SSH database restart failed: {restart_result.get('error', 'Unknown error')}",
                                "operation": "reverse_migrate_tde",
                                "steps": steps
                            })
                    else:
                        # Log why SSH restart is not being used
                        ssh_reason = []
                        if not ssh_available:
                            ssh_reason.append("SSH not available")
                        
                        logger.warning(f"SSH restart skipped: {'; '.join(ssh_reason)}")
                        
                        # Fallback to SQL restart (may fail)
                        logger.info("Restarting database after TDE configuration update...")
                        shutdown_result = await db_handler.execute_sql("SHUTDOWN IMMEDIATE", "CDB$ROOT")
                        steps.append({
                            "step": "shutdown_database_after_config",
                            "success": shutdown_result.get("success", False),
                            "note": "Manual restart may be required if SQL shutdown fails",
                            "ssh_skip_reason": '; '.join(ssh_reason) if ssh_reason else "None"
                        })
                        
                        # Wait and try to reconnect
                        import asyncio
                        await asyncio.sleep(10)
                        
                        startup_success = False
                        for attempt in range(3):
                            try:
                                startup_result = await db_handler.execute_sql("STARTUP", "CDB$ROOT")
                                if startup_result.get("success", False):
                                    startup_success = True
                                    break
                                await asyncio.sleep(10)
                            except Exception as e:
                                logger.warning(f"Startup attempt {attempt + 1} failed: {e}")
                                if attempt < 2:  # Don't sleep after last attempt
                                    await asyncio.sleep(10)
                        
                        steps.append({
                            "step": "startup_database_after_config",
                            "success": startup_success,
                            "attempts": 3
                        })
                        
                        if not startup_success:
                            steps.append({
                                "step": "manual_restart_required",
                                "message": "Database restart failed via SQL. Manual restart required.",
                                "manual_instructions": [
                                    "1. Connect to the Oracle server as oracle user",
                                    "2. Connect to the database: sqlplus / as sysdba",
                                    "3. Shutdown the database: SHUTDOWN IMMEDIATE",
                                    "4. Start the database: STARTUP",
                                    "5. Open PDBs: ALTER PLUGGABLE DATABASE ALL OPEN READ WRITE",
                                    "6. Re-run this reverse migration tool with skip_database_restart=true"
                                ]
                            })
                            
                            return json.dumps({
                                "success": False,
                                "error": "Database restart failed. Manual intervention required.",
                                "operation": "reverse_migrate_tde",
                                "steps": steps,
                                "manual_instructions": steps[-1]["manual_instructions"],
                                "note": "After manual restart, re-run this tool with skip_database_restart=true to continue the migration."
                            })
                else:
                    steps.append({
                        "step": "database_restart_skipped",
                        "message": "Database restart skipped - assuming manual restart completed"
                    })
                
                # Step 1g: Open software wallet
                open_software_sql = f"""
                ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN 
                IDENTIFIED BY "{software_wallet_password}"
                CONTAINER = ALL
                """
                
                open_result = await db_handler.execute_sql(open_software_sql, "CDB$ROOT")
                steps.append({
                    "step": "open_software_wallet",
                    "command": open_software_sql,
                    "success": open_result.get("success", False)
                })
                
            elif is_dual_wallets:
                # Scenario 2: Dual Wallets (Auto-login + HSM) to Auto-login Software
                logger.info("Reverse migrating dual wallets (auto-login + HSM) to auto-login software wallet")
                
                # Step 2a: Rename cwallet.sso file
                wallet_root_sql = "SELECT VALUE FROM V$PARAMETER WHERE NAME = 'wallet_root'"
                wallet_root_result = await db_handler.execute_sql(wallet_root_sql, "CDB$ROOT")
                
                if not wallet_root_result["success"] or not wallet_root_result["results"][0]["data"]:
                    return json.dumps({
                        "success": False,
                        "error": "Unable to determine wallet root location",
                        "operation": "reverse_migrate_tde"
                    })
                
                wallet_root = wallet_root_result["results"][0]["data"][0]["VALUE"]
                cwallet_path = f"{wallet_root}/tde/cwallet.sso"
                cwallet_backup_path = f"{wallet_root}/tde/cwallet.sso.bak"
                
                if not skip_file_operations:
                    if ssh_manager:
                        # Use SSH for file operations
                        rename_result = ssh_manager.rename_cwallet_file(f"{wallet_root}/tde")
                        steps.append({
                            "step": "rename_cwallet_via_ssh",
                            "success": rename_result.get("success", False),
                            "stdout": rename_result.get("stdout", ""),
                            "stderr": rename_result.get("stderr", ""),
                            "verification": rename_result.get("verification", "")
                        })
                        
                        if not rename_result.get("success", False):
                            return json.dumps({
                                "success": False,
                                "error": f"SSH file operation failed: {rename_result.get('error', 'Unknown error')}",
                                "operation": "reverse_migrate_tde",
                                "steps": steps
                            })
                    else:
                        # Note: File operations must be done manually on the Oracle server
                        # SQL cannot directly manipulate files on the filesystem
                        steps.append({
                            "step": "file_operation_required",
                            "message": "Manual file operation required before proceeding",
                            "file_path": cwallet_path,
                            "backup_path": cwallet_backup_path,
                            "manual_instructions": [
                                f"1. Connect to the Oracle server as oracle user",
                                f"2. Navigate to wallet directory: cd {wallet_root}/tde",
                                f"3. Rename the auto-login file: mv cwallet.sso cwallet.sso.bak",
                                f"4. Verify the file is renamed: ls -la cwallet.sso*",
                                f"5. Re-run this reverse migration tool with skip_file_operations=true"
                            ]
                        })
                        
                        return json.dumps({
                            "success": False,
                            "error": "Manual file operation required. Cannot rename cwallet.sso file via SQL.",
                            "operation": "reverse_migrate_tde",
                            "steps": steps,
                            "manual_instructions": steps[-1]["manual_instructions"],
                            "note": "After completing the manual file operation, re-run this tool with skip_file_operations=true to continue the migration."
                        })
                else:
                    # File operation has been completed manually, proceed with migration
                    steps.append({
                        "step": "file_operation_skipped",
                        "message": "File operation skipped - assuming cwallet.sso has been renamed manually",
                        "file_path": cwallet_path,
                        "backup_path": cwallet_backup_path
                    })
                
                # Step 2b: Restart database (FIRST RESTART - after file rename)
                logger.info("Restarting database after file rename...")
                
                if ssh_manager:
                    # Use SSH for database restart
                    restart_result = ssh_manager.restart_oracle_database(oracle_sid)
                    steps.append({
                        "step": "restart_database_after_rename",
                        "method": "ssh",
                        "success": restart_result.get("success", False),
                        "stdout": restart_result.get("stdout", ""),
                        "stderr": restart_result.get("stderr", "")
                    })
                    
                    if not restart_result.get("success", False):
                        return json.dumps({
                            "success": False,
                            "error": f"SSH database restart failed: {restart_result.get('error', 'Unknown error')}",
                            "operation": "reverse_migrate_tde",
                            "steps": steps
                        })
                else:
                    # Fallback to SQL restart
                    logger.info("Using SQL commands for database restart (SSH not available)...")
                    shutdown_result = await db_handler.execute_sql("SHUTDOWN IMMEDIATE", "CDB$ROOT")
                    steps.append({
                        "step": "shutdown_database",
                        "method": "sql",
                        "success": shutdown_result.get("success", False)
                    })
                    
                    # Wait and try to reconnect
                    import asyncio
                    await asyncio.sleep(10)
                    
                    startup_success = False
                    for attempt in range(3):
                        try:
                            startup_result = await db_handler.execute_sql("STARTUP", "CDB$ROOT")
                            if startup_result.get("success", False):
                                startup_success = True
                                break
                            await asyncio.sleep(10)
                        except Exception as e:
                            logger.warning(f"Startup attempt {attempt + 1} failed: {e}")
                            if attempt < 2:  # Don't sleep after last attempt
                                await asyncio.sleep(10)
                    
                    steps.append({
                        "step": "startup_database",
                        "method": "sql",
                        "success": startup_success,
                        "attempts": 3
                    })
                    
                    if not startup_success:
                        steps.append({
                            "step": "manual_restart_required",
                            "message": "Database restart failed via SQL. Manual restart required.",
                            "manual_instructions": [
                                "1. Connect to the Oracle server as oracle user",
                                "2. Connect to the database: sqlplus / as sysdba",
                                "3. Shutdown the database: SHUTDOWN IMMEDIATE",
                                "4. Start the database: STARTUP",
                                "5. Open PDBs: ALTER PLUGGABLE DATABASE ALL OPEN READ WRITE",
                                "6. Re-run this reverse migration tool with skip_database_restart=true"
                            ]
                        })
                            
                        return json.dumps({
                            "success": False,
                            "error": "Database restart failed. Manual intervention required.",
                            "operation": "reverse_migrate_tde",
                            "steps": steps,
                            "manual_instructions": steps[-1]["manual_instructions"],
                            "note": "After manual restart, re-run this tool with skip_database_restart=true to continue the migration."
                        })
                
                # Step 2c: Set TDE configuration to HSM only (before opening HSM wallet)
                tde_hsm_only_sql = "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=HSM' SCOPE=BOTH"
                tde_hsm_only_result = await db_handler.execute_sql(tde_hsm_only_sql, "CDB$ROOT")
                steps.append({
                    "step": "set_tde_configuration_to_hsm",
                    "command": tde_hsm_only_sql,
                    "success": tde_hsm_only_result.get("success", False)
                })
                
                # Step 2d: Open HSM wallet
                open_hsm_sql = f"""
                ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN 
                IDENTIFIED BY "{hsm_credentials}"
                CONTAINER = ALL
                """
                
                open_hsm_result = await db_handler.execute_sql(open_hsm_sql, "CDB$ROOT")
                steps.append({
                    "step": "open_hsm_wallet",
                    "command": open_hsm_sql,
                    "success": open_hsm_result.get("success", False)
                })
                
                # Step 2e: Update TDE configuration to FILE|HSM
                tde_config_sql = "ALTER SYSTEM SET TDE_CONFIGURATION='KEYSTORE_CONFIGURATION=FILE|HSM' SCOPE=BOTH"
                tde_config_result = await db_handler.execute_sql(tde_config_sql, "CDB$ROOT")
                steps.append({
                    "step": "update_tde_configuration",
                    "command": tde_config_sql,
                    "success": tde_config_result.get("success", False)
                })
                
                # Step 2f: Reverse migrate the key
                reverse_migrate_dual_sql = f"""
                ADMINISTER KEY MANAGEMENT SET ENCRYPTION KEY 
                IDENTIFIED BY "{software_wallet_password}" 
                FORCE KEYSTORE REVERSE MIGRATE USING "{hsm_credentials}" 
                WITH BACKUP USING '{backup_tag}'
                """
                
                reverse_migrate_dual_result = await db_handler.execute_sql(reverse_migrate_dual_sql, "CDB$ROOT")
                steps.append({
                    "step": "reverse_migrate_key_dual",
                    "command": reverse_migrate_dual_sql,
                    "success": reverse_migrate_dual_result.get("success", False),
                    "result": reverse_migrate_dual_result
                })
                
                # Step 2g: Create new auto-login keystore
                create_autologin_sql = f"""
                ADMINISTER KEY MANAGEMENT CREATE AUTO_LOGIN KEYSTORE FROM KEYSTORE
                IDENTIFIED BY "{software_wallet_password}"
                """
                
                autologin_result = await db_handler.execute_sql(create_autologin_sql, "CDB$ROOT")
                steps.append({
                    "step": "create_autologin_keystore",
                    "command": create_autologin_sql,
                    "success": autologin_result.get("success", False)
                })
                
                # Step 2h: Check current TDE configuration
                config_check_sql = "SELECT VALUE FROM V$PARAMETER WHERE NAME = 'tde_configuration'"
                config_check_result = await db_handler.execute_sql(config_check_sql, "CDB$ROOT")
                current_tde_config = None
                if config_check_result["success"] and config_check_result["results"][0]["data"]:
                    current_tde_config = config_check_result["results"][0]["data"][0]["VALUE"]
                
                steps.append({
                    "step": "check_final_tde_configuration",
                    "tde_configuration": current_tde_config,
                    "message": f"TDE configuration after reverse migration: {current_tde_config}"
                })
                
                # Step 2i: Final database restart for verification
                logger.info("Performing final database restart for verification...")
                
                if ssh_manager:
                    # Use SSH for database restart
                    restart_result2 = ssh_manager.restart_oracle_database(oracle_sid)
                    steps.append({
                        "step": "restart_database_final",
                        "method": "ssh",
                        "success": restart_result2.get("success", False),
                        "stdout": restart_result2.get("stdout", ""),
                        "stderr": restart_result2.get("stderr", "")
                    })
                    
                    if not restart_result2.get("success", False):
                        return json.dumps({
                            "success": False,
                            "error": f"SSH database restart (final) failed: {restart_result2.get('error', 'Unknown error')}",
                            "operation": "reverse_migrate_tde",
                            "steps": steps
                        })
                else:
                    # Fallback to SQL restart
                    logger.info("Using SQL commands for final database restart (SSH not available)...")
                    shutdown2_result = await db_handler.execute_sql("SHUTDOWN IMMEDIATE", "CDB$ROOT")
                    steps.append({
                        "step": "shutdown_database_final",
                        "method": "sql",
                        "success": shutdown2_result.get("success", False)
                    })
                    
                    await asyncio.sleep(10)
                    
                    startup2_success = False
                    for attempt in range(3):
                        try:
                            startup2_result = await db_handler.execute_sql("STARTUP", "CDB$ROOT")
                            if startup2_result.get("success", False):
                                startup2_success = True
                                break
                            await asyncio.sleep(10)
                        except Exception as e:
                            logger.warning(f"Final startup attempt {attempt + 1} failed: {e}")
                            if attempt < 2:
                                await asyncio.sleep(10)
                    
                    steps.append({
                        "step": "startup_database_final",
                        "method": "sql",
                        "success": startup2_success,
                        "attempts": 3
                    })
                    
                    if not startup2_success:
                        return json.dumps({
                            "success": False,
                            "error": "Failed to restart database for final verification",
                            "operation": "reverse_migrate_tde",
                            "steps": steps
                        })
                
                # Step 2j: Verify wallet status after restart
                verification_sql = """
                SELECT WRL_TYPE, WALLET_TYPE, STATUS, CON_ID
                FROM V$ENCRYPTION_WALLET
                ORDER BY CON_ID, WRL_TYPE
                """
                
                verification_result = await db_handler.execute_sql(verification_sql, "CDB$ROOT")
                
                if verification_result["success"] and verification_result["results"][0]["data"]:
                    verification_wallet_info = verification_result["results"][0]["data"]
                    steps.append({
                        "step": "verify_wallet_status_after_restart",
                        "wallet_status": verification_wallet_info,
                        "message": "Wallet status verified after final restart"
                    })
                else:
                    steps.append({
                        "step": "verify_wallet_status_after_restart",
                        "success": False,
                        "error": "Unable to verify wallet status after restart"
                    })
            
            # Final verification
            final_wallet_sql = """
            SELECT WRL_TYPE, WALLET_TYPE, STATUS, CON_ID
            FROM V$ENCRYPTION_WALLET
            ORDER BY CON_ID, WRL_TYPE
            """
            
            final_wallet_result = await db_handler.execute_sql(final_wallet_sql, "CDB$ROOT")
            
            if not final_wallet_result["success"] or not final_wallet_result["results"][0]["data"]:
                return json.dumps({
                    "success": False,
                    "error": "Unable to verify final wallet status",
                    "operation": "reverse_migrate_tde",
                    "steps": steps
                })
            
            final_wallet_info = final_wallet_result["results"][0]["data"]
            
            # Verify migration success
            migration_success = False
            verification_details = {}
            
            if is_single_hsm:
                # For single HSM migration: verify only FILE wallet is present and open
                file_wallets = [w for w in final_wallet_info if w.get("WRL_TYPE") == "FILE" and w.get("WALLET_TYPE") == "PASSWORD"]
                file_open = all(w.get("STATUS") == "OPEN" for w in file_wallets)
                migration_success = len(file_wallets) > 0 and file_open
                
                verification_details = {
                    "expected": "Only FILE wallet present and open (WALLET_TYPE = PASSWORD)",
                    "found_file_wallets": len(file_wallets),
                    "file_wallets_open": file_open,
                    "wallet_details": file_wallets
                }
                
            elif is_dual_wallets:
                # For dual wallets migration: verify only FILE auto-login wallet is present
                file_wallets = [w for w in final_wallet_info if w.get("WRL_TYPE") == "FILE" and w.get("WALLET_TYPE") == "AUTOLOGIN"]
                file_open = all(w.get("STATUS") == "OPEN" for w in file_wallets)
                migration_success = len(file_wallets) > 0 and file_open
                
                verification_details = {
                    "expected": "Only FILE wallet present and open (WALLET_TYPE = AUTOLOGIN)",
                    "found_file_wallets": len(file_wallets),
                    "file_wallets_open": file_open,
                    "wallet_details": file_wallets
                }
            
            result_data = {
                "success": migration_success,
                "operation": "reverse_migrate_tde",
                "connection": oracle_connection,
                "scenario_detected": "single_hsm" if is_single_hsm else "dual_wallets",
                "backup_tag": backup_tag,
                "hsm_credentials_used": hsm_credentials,
                "steps": steps,
                "final_wallet_status": final_wallet_info,
                "verification": verification_details,
                "post_migration_notes": [
                    "Remove HSM configuration if no longer needed",
                    "Update sqlnet.ora if required",
                    "Test encryption operations with software wallet",
                    "Secure the software wallet files"
                ],
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== reverse_migrate_tde completed ===")
            if ssh_manager and ssh_connected:
                ssh_manager.disconnect()
            return json.dumps(result_data, indent=2)
            
        except Exception as e:
            logger.error(f"Error reverse migrating TDE to software: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__,
                "operation": "reverse_migrate_tde"
            })
    
    # End of register_oracle_wallet_migration_tools function
    logger.info("Oracle wallet migration tools registered successfully")
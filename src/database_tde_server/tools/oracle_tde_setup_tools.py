"""
Oracle TDE brand new setup tool for configuring TDE from scratch - ENHANCED
"""

import json
import logging
from typing import Optional
from datetime import datetime

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

def register_oracle_tde_setup_tools(server: FastMCP, db_manager):
    """Register Oracle TDE setup tools with the MCP server"""
    
    @server.tool()
    async def setup_oracle_tde_from_scratch(
        oracle_connection: str,
        ciphertrust_user: str,
        ciphertrust_password: str,
        tde_configuration: str = "HSM",
        ciphertrust_domain: str = "root",
        auto_restart: bool = False,
        enable_autologin: bool = False,
        software_keystore_password: str = None,
        wallet_root_path: str = None
    ) -> str:
        """
        Configure Oracle TDE from scratch on a brand new database server.
        ENHANCED VERSION: SSH, Oracle, and wallet details are automatically retrieved from database configuration.
        
        Args:
            oracle_connection: Oracle database connection name (SSH and Oracle config auto-filled)
            ciphertrust_user: CipherTrust user for HSM access
            ciphertrust_password: CipherTrust user password
            tde_configuration: TDE configuration type - "HSM" only (default: HSM)
            ciphertrust_domain: CipherTrust domain (default: root)
            auto_restart: If True, attempts database restart via SSH (uses config SSH settings)
            enable_autologin: If True, enables auto-login after TDE setup
            software_keystore_password: Password for software keystore (required if enable_autologin=True)
            wallet_root_path: Wallet root directory path (optional, uses config if not specified)
            
        Returns:
            JSON string containing complete TDE setup results.
        """
        try:
            logger.info(f"=== setup_oracle_tde_from_scratch called for {oracle_connection} ===")
            
            # Validate auto-login parameters
            if enable_autologin and not software_keystore_password:
                return json.dumps({
                    "success": False,
                    "error": "software_keystore_password is required when enable_autologin=True",
                    "operation": "setup_oracle_tde_from_scratch"
                })
            
            db_handler = db_manager.get_database_handler(oracle_connection)
            setup_steps = []
            
            # Validate TDE configuration - only HSM is supported
            if tde_configuration != "HSM":
                return json.dumps({
                    "success": False,
                    "error": f"Only HSM configuration is supported. Received: {tde_configuration}",
                    "operation": "setup_oracle_tde_from_scratch"
                })
            
            # Initialize SSH manager from database configuration
            ssh_manager = None
            ssh_connected = False
            try:
                from ..utils.ssh_utils import OracleSSHManager
                ssh_manager = OracleSSHManager.from_database_config(oracle_connection)
                
                if ssh_manager:
                    ssh_connected = ssh_manager.connect()
                    setup_steps.append({
                        "step": "ssh_connect",
                        "success": ssh_connected,
                        "host": ssh_manager.host,
                        "user": ssh_manager.username
                    })
                    logger.info(f"SSH connected to {ssh_manager.host} as {ssh_manager.username}")
                else:
                    logger.warning(f"No SSH configuration found for {oracle_connection}")
                    setup_steps.append({
                        "step": "ssh_connect",
                        "success": False,
                        "error": "No SSH configuration found in database config"
                    })
                    
            except Exception as e:
                logger.warning(f"SSH initialization failed: {e}")
                setup_steps.append({
                    "step": "ssh_connect",
                    "success": False,
                    "error": str(e)
                })
                ssh_manager = None
            
            # Get Oracle environment from configuration
            oracle_env = {}
            if ssh_manager:
                oracle_env = ssh_manager.get_oracle_environment(oracle_connection)
                logger.info(f"Oracle environment: {oracle_env}")
            
            # Get wallet root path from configuration if not specified
            if not wallet_root_path:
                from ..config import get_config
                config = get_config()
                oracle_config = config.get_oracle_config(oracle_connection)
                if oracle_config and oracle_config.wallet_root:
                    wallet_root_path = oracle_config.wallet_root
                    logger.info(f"Using wallet_root from config: {wallet_root_path}")
                else:
                    return json.dumps({
                        "success": False,
                        "error": "wallet_root_path not specified and not found in configuration",
                        "operation": "setup_oracle_tde_from_scratch"
                    })
            else:
                logger.info(f"Using provided wallet_root_path: {wallet_root_path}")
            
            # Step 1: Check current TDE state to verify it's a new database
            logger.info("Step 1: Checking current TDE state...")
            
            # Check TDE configuration parameters
            current_config_sql = """
            SELECT 
                NAME,
                VALUE,
                ISDEFAULT
            FROM V$PARAMETER
            WHERE NAME IN ('tde_configuration', 'wallet_root')
            ORDER BY NAME
            """
            
            config_result = await db_handler.execute_sql(current_config_sql, "CDB$ROOT")
            current_config = {}
            
            if config_result["success"]:
                for row in config_result["results"][0]["data"]:
                    current_config[row["NAME"]] = {
                        "value": row["VALUE"],
                        "is_default": row["ISDEFAULT"] == "TRUE"
                    }
            
            # Check for existing MEKs
            existing_meks_sql = """
            SELECT COUNT(*) AS MEK_COUNT
            FROM V$ENCRYPTION_KEYS
            """
            
            mek_result = await db_handler.execute_sql(existing_meks_sql, "CDB$ROOT")
            existing_mek_count = 0
            
            if mek_result["success"] and mek_result["results"][0]["data"]:
                existing_mek_count = mek_result["results"][0]["data"][0]["MEK_COUNT"]
            
            # Check for encrypted tablespaces
            encrypted_ts_sql = """
            SELECT COUNT(*) AS ENCRYPTED_TS_COUNT
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
            """
            
            ts_result = await db_handler.execute_sql(encrypted_ts_sql, "CDB$ROOT")
            encrypted_ts_count = 0
            
            if ts_result["success"] and ts_result["results"][0]["data"]:
                encrypted_ts_count = ts_result["results"][0]["data"][0]["ENCRYPTED_TS_COUNT"]
            
            setup_steps.append({
                "step": "assess_current_state",
                "current_config": current_config,
                "existing_meks": existing_mek_count,
                "encrypted_tablespaces": encrypted_ts_count,
                "is_brand_new": existing_mek_count == 0 and encrypted_ts_count == 0,
                "oracle_env": oracle_env,
                "wallet_root_path": wallet_root_path
            })
            
            # Verify this is a new database (no TDE configuration)
            if current_config.get("tde_configuration", {}).get("value"):
                return json.dumps({
                    "success": False,
                    "error": f"TDE is already configured. Current configuration: {current_config.get('tde_configuration', {}).get('value')}",
                    "operation": "setup_oracle_tde_from_scratch",
                    "current_config": current_config
                })
            
            if existing_mek_count > 0:
                return json.dumps({
                    "success": False,
                    "error": f"MEKs already exist ({existing_mek_count}). This database already has TDE configured.",
                    "operation": "setup_oracle_tde_from_scratch",
                    "existing_meks": existing_mek_count
                })
            
            # Step 2: Set WALLET_ROOT parameter before restart
            logger.info("Step 2: Setting WALLET_ROOT...")
            
            wallet_root_sql = f"ALTER SYSTEM SET WALLET_ROOT = '{wallet_root_path}' SCOPE=SPFILE"
            wallet_root_result = await db_handler.execute_sql(wallet_root_sql, "CDB$ROOT")
            
            setup_steps.append({
                "step": "set_wallet_root",
                "parameter": "WALLET_ROOT",
                "value": wallet_root_path,
                "scope": "SPFILE",
                "success": wallet_root_result["success"]
            })
            
            if not wallet_root_result.get("success", False):
                return json.dumps({
                    "success": False,
                    "error": f"Failed to set WALLET_ROOT: {wallet_root_result.get('error', 'Unknown error')}",
                    "operation": "setup_oracle_tde_from_scratch",
                    "steps": setup_steps
                })
            
            # Step 3: Database restart via SSH (following manual steps)
            if auto_restart and ssh_manager and ssh_connected:
                logger.info("Step 3: Restarting database...")
                
                # Get Oracle SID from configuration
                oracle_sid = oracle_env.get('ORACLE_SID')
                if not oracle_sid:
                    return json.dumps({
                        "success": False,
                        "error": "Oracle SID not found in configuration",
                        "operation": "setup_oracle_tde_from_scratch",
                        "steps": setup_steps
                    })
                
                restart_result = ssh_manager.restart_oracle_database(
                    oracle_sid=oracle_sid,
                    oracle_home=oracle_env.get('ORACLE_HOME'),
                    reuse_connection=True
                )
                
                setup_steps.append({
                    "step": "restart_database",
                    "oracle_sid": oracle_sid,
                    "oracle_home": oracle_env.get('ORACLE_HOME'),
                    "success": restart_result.get("success", False),
                    "details": restart_result
                })
                
                if not restart_result.get("success", False):
                    return json.dumps({
                        "success": False,
                        "error": f"Database restart failed: {restart_result.get('error', 'Unknown error')}",
                        "operation": "setup_oracle_tde_from_scratch",
                        "steps": setup_steps
                    })
                
                # Wait for database to be ready
                import time
                time.sleep(10)
            else:
                setup_steps.append({
                    "step": "restart_skipped",
                    "note": "Database restart skipped (auto_restart=false or SSH not available)",
                    "manual_restart_required": True
                })
            
            # Step 4: Set TDE_CONFIGURATION parameter (following manual format)
            logger.info("Step 4: Setting TDE_CONFIGURATION...")
            
            # Set TDE configuration based on auto-login setting
            if enable_autologin:
                tde_config_value = "KEYSTORE_CONFIGURATION=HSM|FILE"
            else:
                tde_config_value = "KEYSTORE_CONFIGURATION=HSM"
            
            tde_config_sql = f'ALTER SYSTEM SET TDE_CONFIGURATION="{tde_config_value}" SCOPE=BOTH'
            tde_config_result = await db_handler.execute_sql(tde_config_sql, "CDB$ROOT")
            
            setup_steps.append({
                "step": "set_tde_configuration",
                "parameter": "TDE_CONFIGURATION",
                "value": tde_config_value,
                "scope": "BOTH",
                "autologin_enabled": enable_autologin,
                "sql": tde_config_sql,
                "result": tde_config_result.get("success", False)
            })
            
            if not tde_config_result.get("success", False):
                return json.dumps({
                    "success": False,
                    "error": f"Failed to set TDE_CONFIGURATION: {tde_config_result.get('error', 'Unknown error')}",
                    "operation": "setup_oracle_tde_from_scratch",
                    "steps": setup_steps
                })
            
            # Step 5: Check PDB status and open if needed
            logger.info("Step 5: Checking and opening PDBs...")
            
            pdb_status_sql = "SHOW PDBS"
            pdb_result = await db_handler.execute_sql(pdb_status_sql, "CDB$ROOT")
            
            setup_steps.append({
                "step": "check_pdb_status",
                "sql": pdb_status_sql,
                "result": pdb_result.get("success", False),
                "pdb_info": pdb_result.get("results", [])
            })
            
            # Open all PDBs
            open_pdbs_sql = "ALTER PLUGGABLE DATABASE ALL OPEN READ WRITE"
            open_pdbs_result = await db_handler.execute_sql(open_pdbs_sql, "CDB$ROOT")
            
            setup_steps.append({
                "step": "open_all_pdbs",
                "sql": open_pdbs_sql,
                "result": open_pdbs_result.get("success", False)
            })
            
            # Step 6: Format CipherTrust credentials correctly
            if ciphertrust_domain and ciphertrust_domain != "root":
                hsm_credentials = f"{ciphertrust_domain}::{ciphertrust_user}:{ciphertrust_password}"
            else:
                hsm_credentials = f"{ciphertrust_user}:{ciphertrust_password}"
            
            # Step 7: Open keystore (following manual steps)
            logger.info("Step 7: Opening keystore...")
            
            open_keystore_sql = f"""
            ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN 
            IDENTIFIED BY "{hsm_credentials}" 
            CONTAINER = ALL
            """
            
            open_result = await db_handler.execute_sql(open_keystore_sql, "CDB$ROOT")
            
            setup_steps.append({
                "step": "open_keystore",
                "sql": open_keystore_sql,
                "result": open_result.get("success", False)
            })
            
            if not open_result.get("success", False):
                return json.dumps({
                    "success": False,
                    "error": f"Failed to open keystore: {open_result.get('error', 'Unknown error')}",
                    "operation": "setup_oracle_tde_from_scratch",
                    "steps": setup_steps
                })
            
            # Step 8: Check wallet status after opening
            logger.info("Step 8: Checking wallet status after opening...")
            
            wallet_status_sql = "SELECT * FROM V$ENCRYPTION_WALLET"
            wallet_status_result = await db_handler.execute_sql(wallet_status_sql, "CDB$ROOT")
            
            setup_steps.append({
                "step": "check_wallet_status_after_open",
                "sql": wallet_status_sql,
                "result": wallet_status_result.get("success", False),
                "wallet_status": wallet_status_result.get("results", [])
            })
            
            # Step 9: Generate MEKs (following manual steps)
            logger.info("Step 9: Generating MEKs...")
            
            generate_mek_sql = f"""
            ADMINISTER KEY MANAGEMENT SET KEY 
            IDENTIFIED BY "{hsm_credentials}" 
            CONTAINER = ALL
            """
            
            mek_generation_result = await db_handler.execute_sql(generate_mek_sql, "CDB$ROOT")
            
            setup_steps.append({
                "step": "generate_meks_all_containers",
                "sql": generate_mek_sql,
                "container": "ALL",
                "result": mek_generation_result.get("success", False)
            })
            
            if not mek_generation_result.get("success", False):
                return json.dumps({
                    "success": False,
                    "error": f"Failed to generate MEKs: {mek_generation_result.get('error', 'Unknown error')}",
                    "operation": "setup_oracle_tde_from_scratch",
                    "steps": setup_steps
                })
            
            # Step 10: Enable auto-login if requested
            if enable_autologin:
                logger.info("Step 10: Setting up auto-login...")
                
                if not software_keystore_password:
                    return json.dumps({
                        "success": False,
                        "error": "software_keystore_password is required when enable_autologin=true",
                        "operation": "setup_oracle_tde_from_scratch",
                        "steps": setup_steps
                    })
                
                # Implement auto-login setup directly
                autologin_steps = []
                
                # Step 10a: Check current wallet status
                logger.info("Step 10a: Checking current wallet status...")
                wallet_status_sql = "SELECT * FROM V$ENCRYPTION_WALLET"
                wallet_status_result = await db_handler.execute_sql(wallet_status_sql, "CDB$ROOT")
                autologin_steps.append({
                    "step": "check_current_wallet_status",
                    "sql": wallet_status_sql,
                    "result": wallet_status_result.get("success", False),
                    "wallet_status": wallet_status_result.get("results", [])
                })
                
                # Check if any wallet is currently open
                has_open_wallet = False
                open_wallet_types = []
                has_autologin_wallet = False
                if wallet_status_result["success"] and wallet_status_result["results"][0]["data"]:
                    for wallet in wallet_status_result["results"][0]["data"]:
                        if wallet.get("STATUS") in ["OPEN", "OPEN_NO_MASTER_KEY"]:
                            has_open_wallet = True
                            wallet_type = wallet.get("WALLET_TYPE", "UNKNOWN")
                            open_wallet_types.append(wallet_type)
                            if wallet.get("WALLET_TYPE") == "AUTOLOGIN":
                                has_autologin_wallet = True
                
                # Step 10b: Close any open wallets if necessary
                if has_open_wallet:
                    logger.info("Step 10b: Closing open wallets...")
                    
                    # Determine which password to use based on wallet types
                    if has_autologin_wallet:
                        # Auto-login wallets don't require password to close
                        close_wallet_sql = "ADMINISTER KEY MANAGEMENT SET KEYSTORE CLOSE"
                    else:
                        # HSM wallets require CipherTrust credentials
                        close_password = hsm_credentials  # This is already in domain::user:password format
                        close_wallet_sql = f"""
                        ADMINISTER KEY MANAGEMENT SET KEYSTORE CLOSE 
                        IDENTIFIED BY "{close_password}"
                        """
                    
                    close_wallet_result = await db_handler.execute_sql(close_wallet_sql, "CDB$ROOT")
                    autologin_steps.append({
                        "step": "close_open_wallets",
                        "sql": close_wallet_sql,
                        "open_wallet_types": open_wallet_types,
                        "has_autologin_wallet": has_autologin_wallet,
                        "password_used": "autologin" if has_autologin_wallet else "hsm_credentials",
                        "result": close_wallet_result.get("success", False)
                    })
                    
                    if not close_wallet_result.get("success", False):
                        return json.dumps({
                            "success": False,
                            "error": f"Failed to close open wallets: {close_wallet_result.get('error', 'Unknown error')}",
                            "operation": "setup_oracle_tde_from_scratch",
                            "steps": setup_steps + autologin_steps
                        })
                
                # Step 10c: Set TDE configuration to FILE
                logger.info("Step 10c: Setting TDE configuration to FILE...")
                tde_file_sql = 'ALTER SYSTEM SET TDE_CONFIGURATION="KEYSTORE_CONFIGURATION=FILE" SCOPE=BOTH'
                tde_file_result = await db_handler.execute_sql(tde_file_sql, "CDB$ROOT")
                autologin_steps.append({
                    "step": "set_tde_configuration_to_file",
                    "sql": tde_file_sql,
                    "result": tde_file_result.get("success", False)
                })
                
                if not tde_file_result.get("success", False):
                    return json.dumps({
                        "success": False,
                        "error": f"Failed to set TDE configuration to FILE: {tde_file_result.get('error', 'Unknown error')}",
                        "operation": "setup_oracle_tde_from_scratch",
                        "steps": setup_steps + autologin_steps
                    })
                
                # Step 10d: Create a new software wallet
                logger.info("Step 10d: Creating new software wallet...")
                create_wallet_sql = f"""
                ADMINISTER KEY MANAGEMENT CREATE KEYSTORE 
                IDENTIFIED BY "{software_keystore_password}"
                """
                create_wallet_result = await db_handler.execute_sql(create_wallet_sql, "CDB$ROOT")
                autologin_steps.append({
                    "step": "create_software_wallet",
                    "sql": create_wallet_sql,
                    "result": create_wallet_result.get("success", False)
                })
                
                if not create_wallet_result.get("success", False):
                    return json.dumps({
                        "success": False,
                        "error": f"Failed to create software wallet: {create_wallet_result.get('error', 'Unknown error')}",
                        "operation": "setup_oracle_tde_from_scratch",
                        "steps": setup_steps + autologin_steps
                    })
                
                # Step 10e: Open the software wallet
                logger.info("Step 10e: Opening software wallet...")
                open_wallet_sql = f"""
                ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN 
                IDENTIFIED BY "{software_keystore_password}"
                """
                open_wallet_result = await db_handler.execute_sql(open_wallet_sql, "CDB$ROOT")
                autologin_steps.append({
                    "step": "open_software_wallet",
                    "sql": open_wallet_sql,
                    "result": open_wallet_result.get("success", False)
                })
                
                if not open_wallet_result.get("success", False):
                    return json.dumps({
                        "success": False,
                        "error": f"Failed to open software wallet: {open_wallet_result.get('error', 'Unknown error')}",
                        "operation": "setup_oracle_tde_from_scratch",
                        "steps": setup_steps + autologin_steps
                    })
                
                # Step 10f: Add CipherTrust credentials to the keystore
                logger.info("Step 10f: Adding CipherTrust credentials to keystore...")
                add_secret_sql = f"""
                ADMINISTER KEY MANAGEMENT ADD SECRET '{hsm_credentials}' 
                FOR CLIENT 'HSM_PASSWORD' 
                IDENTIFIED BY "{software_keystore_password}" 
                WITH BACKUP
                """
                add_secret_result = await db_handler.execute_sql(add_secret_sql, "CDB$ROOT")
                autologin_steps.append({
                    "step": "add_hsm_secret",
                    "sql": add_secret_sql,
                    "result": add_secret_result.get("success", False)
                })
                
                if not add_secret_result.get("success", False):
                    return json.dumps({
                        "success": False,
                        "error": f"Failed to add HSM secret: {add_secret_result.get('error', 'Unknown error')}",
                        "operation": "setup_oracle_tde_from_scratch",
                        "steps": setup_steps + autologin_steps
                    })
                
                # Step 10g: Create auto-login keystore
                logger.info("Step 10g: Creating auto-login keystore...")
                create_autologin_sql = f"""
                ADMINISTER KEY MANAGEMENT CREATE AUTO_LOGIN KEYSTORE FROM KEYSTORE
                IDENTIFIED BY "{software_keystore_password}"
                """
                create_autologin_result = await db_handler.execute_sql(create_autologin_sql, "CDB$ROOT")
                autologin_steps.append({
                    "step": "create_autologin_keystore",
                    "sql": create_autologin_sql,
                    "result": create_autologin_result.get("success", False)
                })
                
                if not create_autologin_result.get("success", False):
                    return json.dumps({
                        "success": False,
                        "error": f"Failed to create auto-login keystore: {create_autologin_result.get('error', 'Unknown error')}",
                        "operation": "setup_oracle_tde_from_scratch",
                        "steps": setup_steps + autologin_steps
                    })
                
                # Step 10h: Update TDE configuration to HSM|FILE
                logger.info("Step 10h: Updating TDE configuration to HSM|FILE...")
                tde_hsm_file_sql = 'ALTER SYSTEM SET TDE_CONFIGURATION="KEYSTORE_CONFIGURATION=HSM|FILE" SCOPE=BOTH'
                tde_hsm_file_result = await db_handler.execute_sql(tde_hsm_file_sql, "CDB$ROOT")
                autologin_steps.append({
                    "step": "set_tde_configuration_to_hsm_file",
                    "sql": tde_hsm_file_sql,
                    "result": tde_hsm_file_result.get("success", False)
                })
                
                if not tde_hsm_file_result.get("success", False):
                    return json.dumps({
                        "success": False,
                        "error": f"Failed to set TDE configuration to HSM|FILE: {tde_hsm_file_result.get('error', 'Unknown error')}",
                        "operation": "setup_oracle_tde_from_scratch",
                        "steps": setup_steps + autologin_steps
                    })
                
                setup_steps.append({
                    "step": "autologin_setup",
                    "success": True,
                    "autologin_steps": autologin_steps,
                    "note": "Auto-login setup completed successfully"
                })
                
                # Step 10i: Restart database to activate auto-login
                if ssh_manager and ssh_connected:
                    logger.info("Step 10i: Restarting database to activate auto-login...")
                    try:
                        # Get Oracle SID from configuration
                        oracle_sid = None
                        if oracle_env.get("ORACLE_SID"):
                            oracle_sid = oracle_env["ORACLE_SID"]
                        else:
                            # Fallback to extracting from connection name
                            oracle_sid = oracle_connection.split("_")[-1].upper()
                        
                        restart_result = ssh_manager.restart_oracle_database(
                            oracle_sid=oracle_sid,
                            oracle_home=oracle_env.get("ORACLE_HOME")
                        )
                        
                        setup_steps.append({
                            "step": "restart_for_autologin",
                            "oracle_sid": oracle_sid,
                            "oracle_home": oracle_env.get("ORACLE_HOME"),
                            "success": restart_result.get("success", False),
                            "details": restart_result
                        })
                        
                        if not restart_result.get("success", False):
                            logger.warning(f"Database restart for auto-login failed: {restart_result.get('error', 'Unknown error')}")
                            # Continue anyway as auto-login might still work
                        else:
                            logger.info("Database restarted successfully for auto-login activation")
                            
                    except Exception as e:
                        logger.warning(f"Database restart for auto-login failed: {e}")
                        setup_steps.append({
                            "step": "restart_for_autologin",
                            "success": False,
                            "error": str(e)
                        })
                else:
                    setup_steps.append({
                        "step": "restart_for_autologin",
                        "success": False,
                        "note": "SSH not available for database restart"
                    })
            else:
                setup_steps.append({
                    "step": "autologin_skipped",
                    "note": "Auto-login not requested"
                })
            
            # Step 11: Final verification
            logger.info("Step 11: Final verification...")
            
            # Check final wallet status
            final_wallet_sql = "SELECT * FROM V$ENCRYPTION_WALLET"
            final_wallet_result = await db_handler.execute_sql(final_wallet_sql, "CDB$ROOT")
            
            # Check final MEK count
            final_mek_result = await db_handler.execute_sql(existing_meks_sql, "CDB$ROOT")
            final_mek_count = 0
            
            if final_mek_result["success"] and final_mek_result["results"][0]["data"]:
                final_mek_count = final_mek_result["results"][0]["data"][0]["MEK_COUNT"]
            
            # Check final TDE configuration and wallet_root
            final_config_result = await db_handler.execute_sql(current_config_sql, "CDB$ROOT")
            final_config = {}
            
            if final_config_result["success"]:
                for row in final_config_result["results"][0]["data"]:
                    final_config[row["NAME"]] = row["VALUE"]
            
            # Verify final wallet_root
            final_wallet_root_verified = final_config.get("wallet_root") == wallet_root_path
            
            # Verify final TDE configuration based on auto-login setting
            expected_tde_config = "KEYSTORE_CONFIGURATION=HSM|FILE" if enable_autologin else "KEYSTORE_CONFIGURATION=HSM"
            final_tde_config_verified = final_config.get("tde_configuration") == expected_tde_config
            
            setup_steps.append({
                "step": "final_verification",
                "final_config": final_config,
                "final_mek_count": final_mek_count,
                "final_wallet_status": final_wallet_result.get("results", []),
                "parameter_verification": {
                    "wallet_root": {
                        "expected": wallet_root_path,
                        "actual": final_config.get("wallet_root"),
                        "verified": final_wallet_root_verified
                    },
                    "tde_configuration": {
                        "expected": expected_tde_config,
                        "actual": final_config.get("tde_configuration"),
                        "verified": final_tde_config_verified
                    }
                },
                "all_parameters_verified": final_wallet_root_verified and final_tde_config_verified
            })
            
            # Determine overall success
            setup_success = (
                final_mek_count > 0 and
                final_wallet_root_verified and
                final_tde_config_verified
            )
            
            result_data = {
                "success": setup_success,
                "operation": "setup_oracle_tde_from_scratch",
                "connection": oracle_connection,
                "configuration": {
                    "tde_configuration": expected_tde_config,
                    "wallet_root_path": wallet_root_path,
                    "ciphertrust_user": ciphertrust_user,
                    "ciphertrust_domain": ciphertrust_domain,
                    "hsm_credentials_used": hsm_credentials,
                    "autologin_enabled": enable_autologin
                },
                "setup_summary": {
                    "was_brand_new": existing_mek_count == 0 and encrypted_ts_count == 0,
                    "ssh_restart_used": auto_restart and ssh_manager is not None,
                    "final_mek_count": final_mek_count,
                    "setup_completed": setup_success,
                    "autologin_configured": enable_autologin
                },
                "setup_steps": setup_steps,
                "next_actions": [
                    "Test TDE by encrypting a tablespace",
                    "Backup wallet files",
                    "Document TDE configuration",
                    "Set up key rotation schedule"
                ] if setup_success else [
                    "Verify wallet configuration",
                    "Check Oracle error logs",
                    "Verify CipherTrust connectivity"
                ],
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== setup_oracle_tde_from_scratch completed ===")
            if ssh_manager and ssh_connected:
                ssh_manager.disconnect()
            return json.dumps(result_data, indent=2)
            
        except Exception as e:
            logger.error(f"Error setting up Oracle TDE: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    # End of register_oracle_tde_setup_tools function
    logger.info("Oracle TDE setup tools registered successfully")
"""
Oracle implementation for TDE operations - ENHANCED CONFIGURATION
"""

import oracledb
import logging
import asyncio
import os
from typing import Dict, Any, List, Optional, Tuple
from datetime import datetime

from .base import DatabaseInterface
from ..models import DatabaseConnection, EncryptionStatusInfo
from ..utils.exceptions import DatabaseConnectionError, TDEOperationError

logger = logging.getLogger(__name__)

class OracleDatabase(DatabaseInterface):
    """Oracle implementation of TDE operations with enhanced configuration support"""

    def __init__(self, connection: DatabaseConnection, connection_timeout: int = 30):
        super().__init__(connection)
        self.connection_timeout = connection_timeout
        self.current_container = None
        self.oracle_version = None
        
        # Set Oracle environment variables from enhanced configuration
        self._setup_oracle_environment()

    def _setup_oracle_environment(self):
        """Set Oracle environment variables from enhanced configuration"""
        try:
            if hasattr(self.connection, 'oracle_config') and self.connection.oracle_config:
                oracle_config = self.connection.oracle_config
                
                # Set ORACLE_HOME
                if oracle_config.oracle_home:
                    os.environ['ORACLE_HOME'] = oracle_config.oracle_home
                    logger.info(f"Set ORACLE_HOME: {oracle_config.oracle_home}")
                
                # Set ORACLE_SID
                if oracle_config.oracle_sid:
                    os.environ['ORACLE_SID'] = oracle_config.oracle_sid
                    logger.info(f"Set ORACLE_SID: {oracle_config.oracle_sid}")
                
                # Set TNS_ADMIN
                if oracle_config.tns_admin:
                    os.environ['TNS_ADMIN'] = oracle_config.tns_admin
                    logger.info(f"Set TNS_ADMIN: {oracle_config.tns_admin}")
                elif oracle_config.oracle_home:
                    # Auto-detect TNS_ADMIN from ORACLE_HOME
                    tns_admin = f"{oracle_config.oracle_home}/network/admin"
                    os.environ['TNS_ADMIN'] = tns_admin
                    logger.info(f"Auto-detected TNS_ADMIN: {tns_admin}")
                
                logger.info(f"Oracle environment configured for {self.connection.name}")
            else:
                logger.warning(f"No Oracle configuration found for {self.connection.name}")
                
        except Exception as e:
            logger.error(f"Error setting up Oracle environment: {e}")

    def _get_connection_params(self) -> Dict[str, Any]:
        """Generate Oracle connection parameters with enhanced configuration support"""
        if self.connection.connection_string:
            # Use provided connection string
            return {"dsn": self.connection.connection_string}
        
        # Build connection parameters
        additional_params = getattr(self.connection, 'additional_params', {})
        
        # Use enhanced oracle_config if available, otherwise fall back to additional_params
        service_name = None
        mode = None
        
        if hasattr(self.connection, 'oracle_config') and self.connection.oracle_config:
            # Use enhanced configuration
            oracle_config = self.connection.oracle_config
            service_name = oracle_config.service_name
            mode = oracle_config.mode
            logger.info(f"Using enhanced Oracle config: service_name={service_name}, mode={mode}")
        else:
            # Fall back to additional_params
            service_name = additional_params.get('service_name')
            mode = additional_params.get('mode', '').upper()
            logger.info(f"Using additional_params: service_name={service_name}, mode={mode}")
        
        # Build DSN
        if service_name:
            dsn = f"{self.connection.host}:{self.connection.port}/{service_name}"
        elif self.connection.instance:
            dsn = f"{self.connection.host}:{self.connection.port}/{self.connection.instance}"
        else:
            dsn = f"{self.connection.host}:{self.connection.port}"
        
        # Check if we need SYSDBA mode for SYS user
        connection_params = {
            "user": self.connection.username,
            "password": self.connection.password,
            "dsn": dsn
        }
        
        # Add SYSDBA mode for SYS user or if specified in configuration
        if self.connection.username.upper() == 'SYS' or mode == 'SYSDBA':
            connection_params["mode"] = oracledb.AUTH_MODE_SYSDBA
        elif mode == 'SYSOPER':
            connection_params["mode"] = oracledb.AUTH_MODE_SYSOPER
        
        logger.info(f"Oracle connection params: {connection_params}")
        return connection_params

    async def connect(self) -> bool:
        """Test database connectivity with enhanced configuration"""
        try:
            params = self._get_connection_params()
            with oracledb.connect(**params) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT 1 FROM DUAL")
                # Get Oracle version while we're connected
                await self._detect_oracle_version(cursor)
                return True
        except Exception as e:
            logger.error(f"Connection test failed: {e}")
            return False

    async def _detect_oracle_version(self, cursor) -> None:
        """Detect Oracle version for compatibility"""
        try:
            cursor.execute("SELECT VERSION, VERSION_FULL FROM V$INSTANCE")
            result = cursor.fetchone()
            if result:
                version_str = result[0]  # e.g., "19.0.0.0.0"
                version_full = result[1]  # e.g., "Oracle Database 19c Enterprise Edition"
                
                # Parse major version
                major_version = int(version_str.split('.')[0])
                self.oracle_version = {
                    "major": major_version,
                    "version_string": version_str,
                    "version_full": version_full
                }
                logger.info(f"Detected Oracle version: {version_full}")
        except Exception as e:
            logger.warning(f"Could not detect Oracle version: {e}")
            # Default to safe assumptions
            self.oracle_version = {"major": 12, "version_string": "12.0.0.0.0", "version_full": "Unknown"}

    async def _switch_container(self, cursor, target_container: str) -> bool:
        """Safely switch container with verification"""
        if not target_container:
            return True
            
        # Normalize container names
        if target_container.upper() in ["CDB$ROOT", "CDB"]:
            target_container = "CDB$ROOT"
        
        if target_container == self.current_container:
            return True
        
        try:
            cursor.execute(f"ALTER SESSION SET CONTAINER = {target_container}")
            
            # Verify the switch
            cursor.execute("SELECT SYS_CONTEXT('USERENV', 'CON_NAME') FROM DUAL")
            result = cursor.fetchone()
            actual_container = result[0] if result else None
            
            if actual_container == target_container:
                self.current_container = target_container
                logger.debug(f"Successfully switched to container: {target_container}")
                return True
            else:
                logger.error(f"Container switch failed: expected {target_container}, got {actual_container}")
                return False
                
        except Exception as e:
            logger.error(f"Failed to switch to container {target_container}: {e}")
            return False

    async def execute_sql(self, sql: str, container: Optional[str] = None) -> Dict[str, Any]:
        """Execute SQL command on Oracle"""
        try:
            params = self._get_connection_params()
            
            with oracledb.connect(**params) as conn:
                cursor = conn.cursor()
                
                # Detect version if not already done
                if not self.oracle_version:
                    await self._detect_oracle_version(cursor)
                
                # Switch container if specified
                if container:
                    if not await self._switch_container(cursor, container):
                        return {
                            "success": False, 
                            "error": f"Failed to switch to container {container}"
                        }
                
                # Parse SQL into statements (split by ; but not within strings)
                statements = self._split_sql_statements(sql)
                results = []
                
                for statement in statements:
                    statement = statement.strip()
                    if not statement:
                        continue
                    
                    cursor.execute(statement)
                    
                    # Check if it's a SELECT query
                    if statement.upper().startswith(('SELECT', 'SHOW', 'WITH')):
                        columns = [col[0] for col in cursor.description] if cursor.description else []
                        rows = cursor.fetchall()
                        results.append({
                            "data": [dict(zip(columns, row)) for row in rows],
                            "row_count": len(rows)
                        })
                    else:
                        # For DML/DDL, commit the transaction
                        conn.commit()
                        results.append({"rows_affected": cursor.rowcount})
                
                return {"success": True, "results": results}
                
        except Exception as e:
            logger.error(f"SQL execution error: {e}")
            logger.error(f"Failed SQL: {sql}")
            return {"success": False, "error": str(e)}

    def _split_sql_statements(self, sql: str) -> List[str]:
        """Split SQL into individual statements, handling quotes properly"""
        statements = []
        current = []
        in_quote = False
        quote_char = None
        
        for i, char in enumerate(sql):
            if char in ("'", '"') and (i == 0 or sql[i-1] != '\\'):
                if not in_quote:
                    in_quote = True
                    quote_char = char
                elif char == quote_char:
                    in_quote = False
            
            if char == ';' and not in_quote:
                statements.append(''.join(current).strip())
                current = []
            else:
                current.append(char)
        
        if current:
            statements.append(''.join(current).strip())
        
        return [s for s in statements if s]

    async def check_encryption_status(self, database_name: Optional[str] = None) -> List[EncryptionStatusInfo]:
        """Check encryption status of Oracle databases (PDBs)"""
        # For Oracle, we check wallet status and encrypted tablespaces
        if database_name:
            container = database_name
        else:
            container = "CDB$ROOT"
        
        # Get wallet status
        wallet_sql = """
        SELECT 
            CON_ID,
            WRL_TYPE,
            WRL_PARAMETER,
            STATUS,
            WALLET_TYPE
        FROM V$ENCRYPTION_WALLET
        """
        
        result = await self.execute_sql(wallet_sql, container)
        
        encryption_status = []
        if result["success"] and result["results"][0]["data"]:
            for row in result["results"][0]["data"]:
                # Create a status entry
                status = EncryptionStatusInfo(
                    database_name=container,
                    database_id=row["CON_ID"],
                    is_encrypted=row["STATUS"] == "OPEN",
                    encryption_state=3 if row["STATUS"] == "OPEN" else 0,
                    encryption_state_desc=f"Wallet {row['STATUS']}",
                    percent_complete=100.0 if row["STATUS"] == "OPEN" else 0.0,
                    key_algorithm="AES",
                    key_length=256,
                    certificate_name=row["WALLET_TYPE"]
                )
                encryption_status.append(status)
        
        return encryption_status

    async def list_cryptographic_providers(self) -> List[Dict[str, Any]]:
        """List cryptographic providers (HSM info for Oracle)"""
        # Query for HSM configuration
        sql = """
        SELECT 
            LIBRARY,
            STATUS
        FROM V$ENCRYPTION_WALLET
        WHERE WRL_TYPE = 'HSM'
        """
        
        result = await self.execute_sql(sql)
        
        if result["success"]:
            providers = result["results"][0]["data"]
            
            # Convert any binary data to string representation
            for provider in providers:
                for field_name, field_value in provider.items():
                    if isinstance(field_value, bytes):
                        provider[field_name] = field_value.hex().upper()
            
            return providers
        else:
            return []

    async def list_master_keys(self, key_type: Optional[str] = None) -> Dict[str, List[Dict[str, Any]]]:
        """List master keys in Oracle"""
        # Oracle uses MEKs (Master Encryption Keys)
        mek_sql = """
        SELECT 
            KEY_ID,
            HEX_MKID,
            TAG,
            CREATION_TIME,
            ACTIVATION_TIME,
            CREATOR,
            CREATOR_PDBNAME,
            ACTIVATING_PDBNAME,
            KEYSTORE_TYPE,
            ORIGIN,
            BACKED_UP,
            CON_ID
        FROM V$ENCRYPTION_KEYS
        ORDER BY ACTIVATION_TIME DESC
        """
        
        result = await self.execute_sql(mek_sql)
        
        meks = []
        if result["success"] and result["results"][0]["data"]:
            for row in result["results"][0]["data"]:
                # Convert datetime objects to strings
                if row.get("CREATION_TIME") and hasattr(row["CREATION_TIME"], "isoformat"):
                    row["CREATION_TIME"] = row["CREATION_TIME"].isoformat()
                if row.get("ACTIVATION_TIME") and hasattr(row["ACTIVATION_TIME"], "isoformat"):
                    row["ACTIVATION_TIME"] = row["ACTIVATION_TIME"].isoformat()
                
                # Convert binary data to string representation
                if row.get("HEX_MKID") and isinstance(row["HEX_MKID"], bytes):
                    row["HEX_MKID"] = row["HEX_MKID"].hex().upper()
                
                # Convert any other binary fields
                for field_name, field_value in row.items():
                    if isinstance(field_value, bytes):
                        row[field_name] = field_value.hex().upper()
                
                meks.append(row)
        
        # Oracle doesn't have asymmetric/symmetric distinction like SQL Server
        return {"master_encryption_keys": meks}

    async def list_databases(self) -> List[Dict[str, Any]]:
        """List all PDBs in Oracle with version-aware column selection"""
        # Base columns that exist in all Oracle versions
        base_columns = [
            "CON_ID",
            "NAME", 
            "OPEN_MODE",
            "RESTRICTED"
        ]
        
        # Additional columns based on version
        additional_columns = []
        if self.oracle_version and self.oracle_version["major"] >= 12:
            additional_columns.extend(["CREATION_TIME"])
            
        # Some columns may not exist in older versions
        if self.oracle_version and self.oracle_version["major"] >= 19:
            additional_columns.extend(["TOTAL_SIZE"])
        
        # Build the SQL dynamically
        all_columns = base_columns + additional_columns
        pdbs_sql = f"""
        SELECT {', '.join(all_columns)}
        FROM V$PDBS
        ORDER BY CON_ID
        """
        
        result = await self.execute_sql(pdbs_sql, "CDB$ROOT")
        
        if result["success"]:
            pdbs = result["results"][0]["data"]
            # Convert datetime objects to strings
            for pdb in pdbs:
                if pdb.get("CREATION_TIME") and hasattr(pdb["CREATION_TIME"], "isoformat"):
                    pdb["CREATION_TIME"] = pdb["CREATION_TIME"].isoformat()
            return pdbs
        else:
            raise TDEOperationError(f"Failed to list PDBs: {result['error']}")

    async def get_tde_configuration(self) -> Dict[str, Any]:
        """Get current TDE configuration parameters"""
        sql = """
        SELECT 
            NAME,
            VALUE,
            ISDEFAULT,
            ISMODIFIED,
            ISADJUSTED,
            DESCRIPTION
        FROM V$PARAMETER
        WHERE NAME IN ('wallet_root', 'encrypt_new_tablespaces', 'compatible')
        ORDER BY NAME
        """
        
        result = await self.execute_sql(sql, "CDB$ROOT")
        
        if result["success"]:
            params = {}
            for row in result["results"][0]["data"]:
                params[row["NAME"]] = {
                    "value": row["VALUE"],
                    "is_default": row["ISDEFAULT"] == "TRUE",
                    "is_modified": row["ISMODIFIED"] == "TRUE",
                    "description": row.get("DESCRIPTION", "")
                }
            return params
        else:
            raise TDEOperationError(f"Failed to get TDE configuration: {result['error']}")

    async def set_tde_configuration(self, value: str = "DDL") -> Dict[str, Any]:
        """Set TDE configuration parameter with correct valid values"""
        # Validate the value
        valid_values = ["DDL", "ALWAYS", "CLOUD_ONLY"]
        if value.upper() not in valid_values:
            return {
                "success": False,
                "error": f"Invalid value '{value}'. Valid values are: {', '.join(valid_values)}"
            }
        
        sql = f"ALTER SYSTEM SET ENCRYPT_NEW_TABLESPACES = {value.upper()} SCOPE=BOTH"
        
        result = await self.execute_sql(sql, "CDB$ROOT")
        
        return {
            "success": result.get("success", False),
            "parameter": "ENCRYPT_NEW_TABLESPACES",
            "value": value.upper(),
            "scope": "BOTH",
            "valid_values": valid_values,
            "result": result
        }

    async def set_wallet_root(self, wallet_path: str) -> Dict[str, Any]:
        """Set wallet_root system parameter"""
        sql = f"ALTER SYSTEM SET WALLET_ROOT = '{wallet_path}' SCOPE=SPFILE"
        
        result = await self.execute_sql(sql, "CDB$ROOT")
        
        return {
            "success": result.get("success", False),
            "parameter": "WALLET_ROOT",
            "value": wallet_path,
            "scope": "SPFILE",
            "result": result,
            "note": "Database restart required for this parameter to take effect"
        }

    def _parse_wallet_password(self, password: str) -> Dict[str, str]:
        """Parse CipherTrust wallet password format with better error handling"""
        # Handle different password formats:
        # 1. "username:password" -> domain="root"
        # 2. "domain::username:password"
        
        parts = password.split(':')
        
        if len(parts) == 2:
            # Simple format: username:password
            return {
                "domain": "root",
                "username": parts[0],
                "password": parts[1]
            }
        elif len(parts) >= 3 and "::" in password:
            # Complex format: domain::username:password
            try:
                domain_part, rest = password.split("::", 1)
                if ":" in rest:
                    username, pwd = rest.split(":", 1)
                    return {
                        "domain": domain_part,
                        "username": username,
                        "password": pwd
                    }
            except ValueError:
                pass
        
        raise ValueError(
            f"Invalid wallet password format. Expected 'username:password' or 'domain::username:password', got: {password[:10]}..."
        )

    async def generate_mek(
        self,
        scope: str,
        wallet_password: str,
        target: Optional[str] = None,
        force: bool = False
    ) -> Dict[str, Any]:
        """Generate Master Encryption Key(s)"""
        results = []
        
        # Parse wallet password
        try:
            pwd_parts = self._parse_wallet_password(wallet_password)
            # Reconstruct in Oracle format
            if pwd_parts["domain"] == "root":
                wallet_pwd = f"{pwd_parts['username']}:{pwd_parts['password']}"
            else:
                wallet_pwd = f"{pwd_parts['domain']}::{pwd_parts['username']}:{pwd_parts['password']}"
        except ValueError as e:
            return {"success": False, "error": str(e)}
        
        if scope == "cdb_all":
            # Generate MEK for CDB and all PDBs
            # First check PDB states
            pdb_check_sql = """
            SELECT NAME, OPEN_MODE 
            FROM V$PDBS 
            WHERE NAME != 'PDB$SEED'
            ORDER BY CON_ID
            """
            
            pdb_result = await self.execute_sql(pdb_check_sql, "CDB$ROOT")
            
            pdb_states = []
            skipped_pdbs = []
            
            if pdb_result["success"] and pdb_result["results"][0]["data"]:
                for pdb in pdb_result["results"][0]["data"]:
                    pdb_states.append({
                        "name": pdb["NAME"],
                        "open_mode": pdb["OPEN_MODE"],
                        "can_generate_mek": pdb["OPEN_MODE"] == "READ WRITE"
                    })
                    
                    if pdb["OPEN_MODE"] != "READ WRITE":
                        skipped_pdbs.append({
                            "name": pdb["NAME"],
                            "reason": f"PDB is in {pdb['OPEN_MODE']} mode"
                        })
            
            # Generate MEK with CONTAINER=ALL
            mek_sql = f"""
            ADMINISTER KEY MANAGEMENT SET KEY
            IDENTIFIED BY "{wallet_pwd}"
            WITH BACKUP USING 'cdb_all_mek_backup'
            CONTAINER = ALL
            """
            
            mek_result = await self.execute_sql(mek_sql, "CDB$ROOT")
            results.append({
                "step": "generate_mek_cdb_all",
                "container": "ALL",
                "result": mek_result,
                "pdb_states": pdb_states,
                "skipped_pdbs": skipped_pdbs
            })
            
        elif scope == "cdb_only":
            # Generate MEK for CDB only
            mek_sql = f"""
            ADMINISTER KEY MANAGEMENT SET KEY
            IDENTIFIED BY "{wallet_pwd}"
            WITH BACKUP USING 'cdb_only_mek_backup'
            """
            
            mek_result = await self.execute_sql(mek_sql, "CDB$ROOT")
            results.append({
                "step": "generate_mek_cdb_only",
                "container": "CDB$ROOT",
                "result": mek_result
            })
            
        elif scope == "pdb":
            # Generate MEK for specific PDBs
            if not target:
                return {"success": False, "error": "Target PDB(s) must be specified for scope='pdb'"}
            
            pdb_names = [pdb.strip() for pdb in target.split(',')]
            
            for pdb_name in pdb_names:
                # Check if PDB is in READ WRITE mode
                check_sql = f"""
                SELECT OPEN_MODE 
                FROM V$PDBS 
                WHERE NAME = '{pdb_name}'
                """
                
                check_result = await self.execute_sql(check_sql, "CDB$ROOT")
                
                if check_result["success"] and check_result["results"][0]["data"]:
                    open_mode = check_result["results"][0]["data"][0]["OPEN_MODE"]
                    
                    if open_mode != "READ WRITE" and not force:
                        results.append({
                            "step": f"check_pdb_{pdb_name}",
                            "container": pdb_name,
                            "skipped": True,
                            "reason": f"PDB is in {open_mode} mode"
                        })
                        continue
                
                # Generate MEK for this PDB
                mek_sql = f"""
                ADMINISTER KEY MANAGEMENT SET KEY
                IDENTIFIED BY "{wallet_pwd}"
                WITH BACKUP USING '{pdb_name}_mek_backup'
                """
                
                mek_result = await self.execute_sql(mek_sql, pdb_name)
                results.append({
                    "step": f"generate_mek_{pdb_name}",
                    "container": pdb_name,
                    "result": mek_result
                })
        
        else:
            return {"success": False, "error": f"Invalid scope: {scope}"}
        
        # Check overall success
        success = all(
            r.get("result", {}).get("success", False) or r.get("skipped", False)
            for r in results
        )
        
        return {
            "success": success,
            "scope": scope,
            "target": target,
            "steps": results
        }

    async def rotate_mek(
        self,
        container: str,
        wallet_password: str,
        backup_identifier: Optional[str] = None
    ) -> Dict[str, Any]:
        """Rotate Master Encryption Key"""
        # Parse wallet password
        try:
            pwd_parts = self._parse_wallet_password(wallet_password)
            if pwd_parts["domain"] == "root":
                wallet_pwd = f"{pwd_parts['username']}:{pwd_parts['password']}"
            else:
                wallet_pwd = f"{pwd_parts['domain']}::{pwd_parts['username']}:{pwd_parts['password']}"
        except ValueError as e:
            return {"success": False, "error": str(e)}
        
        if not backup_identifier:
            backup_identifier = f"{container}_mek_rotation_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        
        # Rotate MEK
        rotate_sql = f"""
        ADMINISTER KEY MANAGEMENT SET KEY
        IDENTIFIED BY "{wallet_pwd}"
        WITH BACKUP USING '{backup_identifier}'
        """
        
        result = await self.execute_sql(rotate_sql, container)
        
        return {
            "success": result.get("success", False),
            "container": container,
            "backup_identifier": backup_identifier,
            "result": result
        }

    async def create_autologin_wallet(
        self,
        wallet_password: str,
        wallet_location: Optional[str] = None
    ) -> Dict[str, Any]:
        """Create auto-login wallet"""
        # Parse wallet password
        try:
            pwd_parts = self._parse_wallet_password(wallet_password)
            if pwd_parts["domain"] == "root":
                wallet_pwd = f"{pwd_parts['username']}:{pwd_parts['password']}"
            else:
                wallet_pwd = f"{pwd_parts['domain']}::{pwd_parts['username']}:{pwd_parts['password']}"
        except ValueError as e:
            return {"success": False, "error": str(e)}
        
        # Create auto-login wallet
        if wallet_location:
            sql = f"""
            ADMINISTER KEY MANAGEMENT CREATE AUTO_LOGIN KEYSTORE FROM KEYSTORE '{wallet_location}'
            IDENTIFIED BY "{wallet_pwd}"
            """
        else:
            sql = f"""
            ADMINISTER KEY MANAGEMENT CREATE AUTO_LOGIN KEYSTORE FROM KEYSTORE
            IDENTIFIED BY "{wallet_pwd}"
            """
        
        result = await self.execute_sql(sql, "CDB$ROOT")
        
        return {
            "success": result.get("success", False),
            "wallet_location": wallet_location,
            "result": result
        }

    async def update_autologin_secret(
        self,
        old_password: str,
        new_password: str,
        wallet_location: Optional[str] = None
    ) -> Dict[str, Any]:
        """Update auto-login wallet secret"""
        # Parse passwords
        try:
            old_parts = self._parse_wallet_password(old_password)
            new_parts = self._parse_wallet_password(new_password)
            
            if old_parts["domain"] == "root":
                old_wallet_pwd = f"{old_parts['username']}:{old_parts['password']}"
            else:
                old_wallet_pwd = f"{old_parts['domain']}::{old_parts['username']}:{old_parts['password']}"
                
            if new_parts["domain"] == "root":
                new_wallet_pwd = f"{new_parts['username']}:{new_parts['password']}"
            else:
                new_wallet_pwd = f"{new_parts['domain']}::{new_parts['username']}:{new_parts['password']}"
                
        except ValueError as e:
            return {"success": False, "error": str(e)}
        
        results = []
        
        # First, close the wallet if auto-login is active
        close_sql = "ADMINISTER KEY MANAGEMENT SET KEYSTORE CLOSE"
        close_result = await self.execute_sql(close_sql, "CDB$ROOT")
        results.append({"step": "close_wallet", "result": close_result})
        
        # Change the password
        change_sql = f"""
        ADMINISTER KEY MANAGEMENT ALTER KEYSTORE PASSWORD
        IDENTIFIED BY "{old_wallet_pwd}"
        SET "{new_wallet_pwd}"
        """
        
        if wallet_location:
            change_sql += f" KEYSTORE '{wallet_location}'"
        
        change_result = await self.execute_sql(change_sql, "CDB$ROOT")
        results.append({"step": "change_password", "result": change_result})
        
        # Recreate auto-login with new password
        auto_result = await self.create_autologin_wallet(new_password, wallet_location)
        results.append({"step": "recreate_autologin", "result": auto_result})
        
        return {
            "success": all(r.get("result", {}).get("success", False) for r in results),
            "steps": results
        }

    async def open_wallet(
        self,
        container: str,
        wallet_password: str
    ) -> Dict[str, Any]:
        """Open Oracle wallet"""
        # Parse wallet password
        try:
            pwd_parts = self._parse_wallet_password(wallet_password)
            if pwd_parts["domain"] == "root":
                wallet_pwd = f"{pwd_parts['username']}:{pwd_parts['password']}"
            else:
                wallet_pwd = f"{pwd_parts['domain']}::{pwd_parts['username']}:{pwd_parts['password']}"
        except ValueError as e:
            return {"success": False, "error": str(e)}
        
        sql = f'ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY "{wallet_pwd}"'
        
        result = await self.execute_sql(sql, container)
        
        return {
            "success": result.get("success", False),
            "container": container,
            "auto_login": False,
            "result": result
        }

    async def close_wallet(
        self,
        container: str
    ) -> Dict[str, Any]:
        """Close Oracle wallet"""
        sql = "ADMINISTER KEY MANAGEMENT SET KEYSTORE CLOSE"
        
        result = await self.execute_sql(sql, container)
        
        return {
            "success": result.get("success", False),
            "container": container,
            "result": result
        }

    async def get_wallet_status(
        self,
        view_type: str = "v$",
        container: Optional[str] = None,
        node_filter: Optional[int] = None
    ) -> List[Dict[str, Any]]:
        """Get wallet status from v$ or gv$ views"""
        base_query = f"""
        SELECT 
            {('INST_ID,' if view_type == 'gv$' else '')}
            CON_ID,
            WRL_TYPE,
            WRL_PARAMETER,
            STATUS,
            WALLET_TYPE,
            WALLET_ORDER,
            FULLY_BACKED_UP
        FROM {view_type}ENCRYPTION_WALLET
        """
        
        if view_type == "gv$" and node_filter is not None:
            base_query += f" WHERE INST_ID = {node_filter}"
        
        base_query += " ORDER BY CON_ID"
        
        result = await self.execute_sql(base_query, container or "CDB$ROOT")
        
        if result["success"]:
            wallet_data = result["results"][0]["data"]
            
            # Convert any binary data to string representation
            for wallet in wallet_data:
                for field_name, field_value in wallet.items():
                    if isinstance(field_value, bytes):
                        wallet[field_name] = field_value.hex().upper()
            
            return wallet_data
        else:
            raise TDEOperationError(f"Failed to get wallet status: {result['error']}")

    async def list_tablespaces(
        self,
        container: str,
        encrypted_only: bool = False
    ) -> List[Dict[str, Any]]:
        """List tablespaces with encryption status"""
        sql = """
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
            sql += " AND vet.TS# IS NOT NULL"
        
        sql += " ORDER BY vt.NAME"
        
        result = await self.execute_sql(sql, container)
        
        if result["success"]:
            tablespaces = result["results"][0]["data"]
            
            # Convert any binary data to string representation
            for ts in tablespaces:
                for field_name, field_value in ts.items():
                    if isinstance(field_value, bytes):
                        ts[field_name] = field_value.hex().upper()
            
            return tablespaces
        else:
            raise TDEOperationError(f"Failed to list tablespaces: {result['error']}")

    async def encrypt_tablespace(
        self,
        container: str,
        tablespace_name: str,
        algorithm: str = "AES256",
        online: bool = True
    ) -> Dict[str, Any]:
        """Encrypt a tablespace"""
        results = []
        
        # Check if tablespace exists and is not already encrypted
        check_sql = f"""
        SELECT ENCRYPTED, STATUS 
        FROM DBA_TABLESPACES 
        WHERE TABLESPACE_NAME = '{tablespace_name}'
        """
        
        check_result = await self.execute_sql(check_sql, container)
        
        if check_result["success"] and check_result["results"][0]["data"]:
            ts_info = check_result["results"][0]["data"][0]
            if ts_info["ENCRYPTED"] == "YES":
                return {
                    "success": False,
                    "error": f"Tablespace {tablespace_name} is already encrypted"
                }
        else:
            return {
                "success": False,
                "error": f"Tablespace {tablespace_name} not found"
            }
        
        # Attempt online encryption first if requested
        if online:
            encrypt_sql = f"""
            ALTER TABLESPACE {tablespace_name} 
            ENCRYPTION ONLINE 
            USING '{algorithm}' 
            ENCRYPT
            """
            
            encrypt_result = await self.execute_sql(encrypt_sql, container)
            
            if encrypt_result["success"]:
                results.append({
                    "step": "encrypt_online",
                    "method": "ONLINE",
                    "result": encrypt_result
                })
                
                return {
                    "success": True,
                    "tablespace": tablespace_name,
                    "container": container,
                    "algorithm": algorithm,
                    "method": "ONLINE",
                    "steps": results
                }
            else:
                # Online failed, try offline
                results.append({
                    "step": "encrypt_online_failed",
                    "method": "ONLINE",
                    "result": encrypt_result
                })
        
        # Offline encryption
        # First, take tablespace offline
        offline_sql = f"ALTER TABLESPACE {tablespace_name} OFFLINE"
        offline_result = await self.execute_sql(offline_sql, container)
        results.append({
            "step": "tablespace_offline",
            "result": offline_result
        })
        
        if offline_result["success"]:
            # Encrypt offline
            encrypt_sql = f"""
            ALTER TABLESPACE {tablespace_name} 
            ENCRYPTION OFFLINE 
            USING '{algorithm}' 
            ENCRYPT
            """
            
            encrypt_result = await self.execute_sql(encrypt_sql, container)
            results.append({
                "step": "encrypt_offline",
                "method": "OFFLINE",
                "result": encrypt_result
            })
            
            # Bring tablespace back online
            online_sql = f"ALTER TABLESPACE {tablespace_name} ONLINE"
            online_result = await self.execute_sql(online_sql, container)
            results.append({
                "step": "tablespace_online",
                "result": online_result
            })
        
        success = all(r.get("result", {}).get("success", False) for r in results[-3:])
        
        return {
            "success": success,
            "tablespace": tablespace_name,
            "container": container,
            "algorithm": algorithm,
            "method": "OFFLINE",
            "steps": results
        }

    async def migrate_wallet_to_hsm(
        self,
        hsm_provider: str,
        wallet_password: str,
        hsm_credentials: Dict[str, str]
    ) -> Dict[str, Any]:
        """Migrate software wallet to HSM"""
        # Implementation would follow Thales documentation
        # This is a placeholder for the complex migration process
        return {
            "success": False,
            "error": "HSM migration implementation pending",
            "documentation": "https://thalesdocs.com/ctp/con/cakm/cakm-oracle-tde/latest/admin/tde-integrating_19c/index.html#migrating-from-software-wallet-to-hsm-wallet"
        }

    async def migrate_wallet_to_software(
        self,
        wallet_password: str,
        software_location: str
    ) -> Dict[str, Any]:
        """Migrate HSM wallet to software"""
        # Reverse migration process
        return {
            "success": False,
            "error": "Software migration implementation pending"
        }

    async def merge_wallets(
        self,
        source_wallet: str,
        target_wallet: str,
        wallet_password: str
    ) -> Dict[str, Any]:
        """Merge two Oracle wallets"""
        # Parse wallet password
        try:
            pwd_parts = self._parse_wallet_password(wallet_password)
            if pwd_parts["domain"] == "root":
                wallet_pwd = f"{pwd_parts['username']}:{pwd_parts['password']}"
            else:
                wallet_pwd = f"{pwd_parts['domain']}::{pwd_parts['username']}:{pwd_parts['password']}"
        except ValueError as e:
            return {"success": False, "error": str(e)}
        
        merge_sql = f"""
        ADMINISTER KEY MANAGEMENT MERGE KEYSTORE '{source_wallet}'
        INTO EXISTING KEYSTORE '{target_wallet}'
        IDENTIFIED BY "{wallet_pwd}"
        """
        
        result = await self.execute_sql(merge_sql, "CDB$ROOT")
        
        return {
            "success": result.get("success", False),
            "source_wallet": source_wallet,
            "target_wallet": target_wallet,
            "result": result
        }


    async def migrate_keystore_to_hsm(
        self,
        software_wallet_password: str,
        hsm_credentials: str,
        container: str = "ALL",
        backup_tag: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Migrate keystore from software to HSM using Oracle MIGRATE command.
        
        Args:
            software_wallet_password: Current software wallet password
            hsm_credentials: HSM credentials in format "domain::user:password"
            container: Container scope - "ALL" | "CDB$ROOT" | specific PDB name
            backup_tag: Optional backup identifier
            
        Returns:
            Dictionary containing migration results
        """
        try:
            if not backup_tag:
                backup_tag = f"migrate_to_hsm_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Oracle MIGRATE command
            migrate_sql = f"""
            ADMINISTER KEY MANAGEMENT MIGRATE KEYSTORE
            TO HSM
            IDENTIFIED BY "{software_wallet_password}"
            USING "{hsm_credentials}"
            WITH BACKUP USING '{backup_tag}'
            CONTAINER = {container}
            """
            
            result = await self.execute_sql(migrate_sql, "CDB$ROOT")
            
            return {
                "success": result.get("success", False),
                "container": container,
                "backup_tag": backup_tag,
                "migration_command": migrate_sql,
                "result": result
            }
            
        except Exception as e:
            logger.error(f"HSM migration error: {e}")
            return {
                "success": False,
                "error": str(e)
            }

    async def reverse_migrate_keystore_from_hsm(
        self,
        hsm_credentials: str,
        software_wallet_password: str,
        software_wallet_location: str,
        container: str = "ALL",
        backup_tag: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        Reverse migrate keystore from HSM to software using Oracle REVERSE MIGRATE command.
        
        Args:
            hsm_credentials: HSM credentials in format "domain::user:password"
            software_wallet_password: Target software wallet password
            software_wallet_location: Target software wallet location
            container: Container scope - "ALL" | "CDB$ROOT" | specific PDB name
            backup_tag: Optional backup identifier
            
        Returns:
            Dictionary containing reverse migration results
        """
        try:
            if not backup_tag:
                backup_tag = f"reverse_migrate_to_software_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
            
            # Oracle REVERSE MIGRATE command
            reverse_migrate_sql = f"""
            ADMINISTER KEY MANAGEMENT REVERSE MIGRATE KEYSTORE
            FROM HSM
            TO '{software_wallet_location}'
            IDENTIFIED BY "{hsm_credentials}"
            USING "{software_wallet_password}"
            WITH BACKUP USING '{backup_tag}'
            CONTAINER = {container}
            """
            
            result = await self.execute_sql(reverse_migrate_sql, "CDB$ROOT")
            
            return {
                "success": result.get("success", False),
                "container": container,
                "software_wallet_location": software_wallet_location,
                "backup_tag": backup_tag,
                "migration_command": reverse_migrate_sql,
                "result": result
            }
            
        except Exception as e:
            logger.error(f"Reverse migration error: {e}")
            return {
                "success": False,
                "error": str(e)
            }
    # Implement abstract methods from base class
    async def create_tde_infrastructure(self, *args, **kwargs) -> Dict[str, Any]:
        """Not applicable for Oracle - use generate_mek instead"""
        return {"success": False, "error": "Use generate_mek for Oracle TDE"}

    async def encrypt_database(self, *args, **kwargs) -> Dict[str, Any]:
        """Not applicable for Oracle - use encrypt_tablespace instead"""
        return {"success": False, "error": "Use encrypt_tablespace for Oracle TDE"}

    async def rotate_database_encryption_key(self, *args, **kwargs) -> Dict[str, Any]:
        """Not applicable for Oracle - use rotate_mek instead"""
        return {"success": False, "error": "Use rotate_mek for Oracle TDE"}

    async def rotate_master_key(self, *args, **kwargs) -> Dict[str, Any]:
        """Not applicable for Oracle - use rotate_mek instead"""
        return {"success": False, "error": "Use rotate_mek for Oracle TDE"}
        
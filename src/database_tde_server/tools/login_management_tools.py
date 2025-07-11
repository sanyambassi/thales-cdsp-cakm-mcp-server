"""
Login management tools for SQL Server
"""

import json
import logging
from typing import Optional
from datetime import datetime

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

def register_login_management_tools(server: FastMCP, db_manager):
    """Register login management tools with the MCP server"""
    
    @server.tool()
    async def manage_sql_logins(
        sql_connection: str,
        operation: str = "list",
        login_name: Optional[str] = None,
        include_system: bool = False,
        tde_only: bool = False,
        force: bool = False,
        unused_only: bool = True
    ) -> str:
        """
        Manage SQL Server logins: list, drop, or drop TDE logins.
        Args:
            sql_connection: Database connection name
            operation: 'list', 'drop', or 'drop_tde'
            login_name: Login name (for drop)
            include_system: Include system logins (for list)
            tde_only: Only TDE logins (for list)
            force: Force removal of credential mappings (for drop)
            unused_only: Only drop unused TDE logins (for drop_tde)
        Returns:
            JSON string with operation results.
        """
        try:
            db_handler = db_manager.get_database_handler(sql_connection)
            if operation == "list":
                # List logins (original logic)
                all_logins = await db_handler.list_logins()
                for login in all_logins:
                    if login["credential_count"] > 0:
                        cred_sql = f"""
                        SELECT 
                            c.name as credential_name,
                            c.credential_identity,
                            cp.name as provider_name
                        FROM sys.server_principal_credentials pc
                        JOIN sys.server_principals p ON pc.principal_id = p.principal_id
                        JOIN sys.credentials c ON pc.credential_id = c.credential_id
                        LEFT JOIN sys.cryptographic_providers cp ON c.target_id = cp.provider_id
                        WHERE p.name = '{login["name"]}'
                        """
                        cred_result = await db_handler.execute_sql(cred_sql)
                        if cred_result["success"] and cred_result["results"][0]["data"]:
                            login["credentials"] = cred_result["results"][0]["data"]
                        else:
                            login["credentials"] = []
                    else:
                        login["credentials"] = []
                filtered_logins = all_logins
                if not include_system:
                    filtered_logins = [
                        login for login in filtered_logins
                        if not (login["name"].startswith("##") or 
                               login["name"] in ["sa", "public", "sysadmin", "guest"])
                    ]
                if tde_only:
                    filtered_logins = [
                        login for login in filtered_logins
                        if login["is_tde_login"] or login["name"].startswith("TDE_Login_")
                    ]
                categorized = {
                    "sql_logins": [],
                    "windows_logins": [],
                    "certificate_logins": [],
                    "tde_logins": []
                }
                for login in filtered_logins:
                    if login["is_tde_login"]:
                        categorized["tde_logins"].append(login)
                    elif login["type_desc"] == "SQL_LOGIN":
                        categorized["sql_logins"].append(login)
                    elif login["type_desc"] == "WINDOWS_LOGIN":
                        categorized["windows_logins"].append(login)
                    elif login["type_desc"] == "CERTIFICATE_MAPPED_LOGIN":
                        categorized["certificate_logins"].append(login)
                result = {
                    "success": True,
                    "operation": "list_logins",
                    "connection": sql_connection,
                    "filters": {
                        "include_system": include_system,
                        "tde_only": tde_only
                    },
                    "summary": {
                        "total_logins": len(filtered_logins),
                        "sql_logins": len(categorized["sql_logins"]),
                        "windows_logins": len(categorized["windows_logins"]),
                        "certificate_logins": len(categorized["certificate_logins"]),
                        "tde_logins": len(categorized["tde_logins"]),
                        "logins_with_credentials": sum(1 for l in filtered_logins if l["credential_count"] > 0)
                    },
                    "logins": categorized,
                    "timestamp": datetime.now().isoformat()
                }
                return json.dumps(result, indent=2)
            elif operation == "drop":
                # Drop login (original logic)
                if not login_name:
                    return json.dumps({"success": False, "error": "login_name is required for drop"})
                drop_result = await db_handler.drop_login(
                    login_name=login_name,
                    force=force
                )
                if not drop_result.get("success", False):
                    return json.dumps(drop_result)
                verification_sql = f"""
                SELECT name FROM sys.server_principals WHERE name = '{login_name}'
                """
                verify_result = await db_handler.execute_sql(verification_sql)
                login_still_exists = False
                if verify_result["success"] and verify_result["results"][0]["data"]:
                    login_still_exists = True
                result = {
                    "success": True,
                    "operation": "drop_login",
                    "login_name": login_name,
                    "login_type": drop_result.get("login_type"),
                    "was_disabled": drop_result.get("was_disabled", False),
                    "credentials_unmapped": drop_result.get("credentials_unmapped", []),
                    "database_users_orphaned": drop_result.get("database_users_orphaned", []),
                    "steps": drop_result.get("steps", []),
                    "verification": {
                        "login_dropped": not login_still_exists,
                        "login_still_exists": login_still_exists
                    },
                    "timestamp": datetime.now().isoformat()
                }
                if drop_result.get("database_users_orphaned"):
                    result["warning"] = f"Orphaned database users in: {', '.join(drop_result['database_users_orphaned'])}"
                return json.dumps(result, indent=2)
            elif operation == "drop_tde":
                # Drop TDE logins (original logic)
                all_logins = await db_handler.list_logins()
                tde_logins = [
                    login for login in all_logins 
                    if login["name"].startswith("TDE_Login_") or login["is_tde_login"]
                ]
                if not tde_logins:
                    return json.dumps({
                        "success": True,
                        "operation": "drop_tde_logins",
                        "message": "No TDE logins found",
                        "timestamp": datetime.now().isoformat()
                    })
                logins_to_drop = tde_logins
                if unused_only:
                    key_usage_sql = """
                    SELECT DISTINCT
                        ak.name as key_name
                    FROM sys.dm_database_encryption_keys dek
                    INNER JOIN master.sys.asymmetric_keys ak ON dek.encryptor_thumbprint = ak.thumbprint
                    """
                    usage_result = await db_handler.execute_sql(key_usage_sql)
                    used_keys = set()
                    if usage_result["success"] and usage_result["results"][0]["data"]:
                        used_keys = {row["key_name"] for row in usage_result["results"][0]["data"]}
                    logins_to_drop = []
                    for login in tde_logins:
                        if login["name"].startswith("TDE_Login_"):
                            key_name = login["name"].replace("TDE_Login_", "")
                            if key_name not in used_keys:
                                logins_to_drop.append(login)
                        elif login["asymmetric_key_name"] and login["asymmetric_key_name"] not in used_keys:
                            logins_to_drop.append(login)
                if not logins_to_drop:
                    return json.dumps({
                        "success": True,
                        "operation": "drop_tde_logins",
                        "message": "No unused TDE logins found",
                        "total_tde_logins": len(tde_logins),
                        "timestamp": datetime.now().isoformat()
                    })
                drop_results = []
                successful_drops = 0
                failed_drops = 0
                for login in logins_to_drop:
                    try:
                        drop_result = await db_handler.drop_login(
                            login_name=login["name"],
                            force=True
                        )
                        if drop_result.get("success", False):
                            successful_drops += 1
                        else:
                            failed_drops += 1
                        drop_results.append({
                            "login_name": login["name"],
                            "asymmetric_key": login.get("asymmetric_key_name"),
                            "success": drop_result.get("success", False),
                            "error": drop_result.get("error") if not drop_result.get("success", False) else None,
                            "credentials_unmapped": drop_result.get("credentials_unmapped", [])
                        })
                    except Exception as e:
                        failed_drops += 1
                        drop_results.append({
                            "login_name": login["name"],
                            "success": False,
                            "error": str(e)
                        })
                result = {
                    "success": True,
                    "operation": "drop_tde_logins",
                    "unused_only": unused_only,
                    "summary": {
                        "total_tde_logins": len(tde_logins),
                        "logins_to_drop": len(logins_to_drop),
                        "successful_drops": successful_drops,
                        "failed_drops": failed_drops
                    },
                    "drop_results": drop_results,
                    "timestamp": datetime.now().isoformat()
                }
                return json.dumps(result, indent=2)
            else:
                return json.dumps({"success": False, "error": f"Invalid operation: {operation}"})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})
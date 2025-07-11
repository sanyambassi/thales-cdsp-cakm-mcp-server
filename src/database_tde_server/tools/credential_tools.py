"""
Credential management tools for TDE operations
"""

import json
import logging
from typing import Optional
from datetime import datetime

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

def register_credential_tools(server: FastMCP, db_manager):
    """Register credential management tools with the MCP server"""
    
    @server.tool()
    async def manage_sql_credentials(
        sql_connection: str,
        operation: str = "list",
        credential_name: Optional[str] = None,
        new_password: Optional[str] = None,
        ciphertrust_username: Optional[str] = None,
        ciphertrust_domain: Optional[str] = None,
        force: bool = False,
        show_mappings: bool = True,
        login_name: Optional[str] = None
    ) -> str:
        """
        Manage SQL Server credentials: list, update, drop, or fix mappings.
        Args:
            sql_connection: Database connection name
            operation: 'list', 'update', 'drop', or 'fix_mappings'
            credential_name: Credential name (for filter, update, drop, or fix)
            new_password: New password (for update)
            ciphertrust_username: Username for identity (for update)
            ciphertrust_domain: Domain for identity (for update)
            force: Force removal of mappings (for drop)
            show_mappings: Show login mappings (for list)
            login_name: Login name (for fix_mappings)
        Returns:
            JSON string with operation results.
        """
        try:
            db_handler = db_manager.get_database_handler(sql_connection)
            if operation == "list":
                # List credentials (original logic)
                credential_sql = """
                SELECT 
                    c.credential_id,
                    c.name as credential_name,
                    c.create_date,
                    c.modify_date,
                    c.target_type,
                    c.target_id,
                    cp.name as cryptographic_provider
                FROM master.sys.credentials c
                LEFT JOIN master.sys.cryptographic_providers cp 
                    ON c.target_id = cp.provider_id AND c.target_type = 'CRYPTOGRAPHIC PROVIDER'
                """
                if credential_name:
                    credential_sql += f" WHERE c.name = '{credential_name}'"
                credential_sql += " ORDER BY c.name"
                credential_result = await db_handler.execute_sql(credential_sql)
                if not credential_result["success"]:
                    return json.dumps({
                        "success": False,
                        "error": f"Failed to list credentials: {credential_result['error']}"
                    })
                credentials = credential_result["results"][0]["data"]
                for cred in credentials:
                    if cred.get("create_date") and hasattr(cred["create_date"], "isoformat"):
                        cred["create_date"] = cred["create_date"].isoformat()
                    if cred.get("modify_date") and hasattr(cred["modify_date"], "isoformat"):
                        cred["modify_date"] = cred["modify_date"].isoformat()
                if show_mappings:
                    mapping_sql = """
                    SELECT 
                        c.name as credential_name,
                        p.name as login_name,
                        p.type_desc as principal_type,
                        p.is_disabled as login_disabled
                    FROM sys.server_principal_credentials pc
                    JOIN sys.server_principals p ON pc.principal_id = p.principal_id
                    JOIN sys.credentials c ON pc.credential_id = c.credential_id
                    """
                    if credential_name:
                        mapping_sql += f" WHERE c.name = '{credential_name}'"
                    mapping_sql += " ORDER BY c.name, p.name"
                    mapping_result = await db_handler.execute_sql(mapping_sql)
                    mappings = {}
                    if mapping_result["success"] and mapping_result["results"][0]["data"]:
                        for row in mapping_result["results"][0]["data"]:
                            cred_name = row["credential_name"]
                            if cred_name not in mappings:
                                mappings[cred_name] = []
                            mappings[cred_name].append({
                                "login_name": row["login_name"],
                                "principal_type": row["principal_type"],
                                "is_disabled": bool(row["login_disabled"])
                            })
                    for cred in credentials:
                        cred["mapped_logins"] = mappings.get(cred["credential_name"], [])
                categorized = {
                    "master_credentials": [],
                    "tde_credentials": [],
                    "other_credentials": []
                }
                for cred in credentials:
                    cred_name = cred["credential_name"]
                    if "_master_cred" in cred_name:
                        categorized["master_credentials"].append(cred)
                    elif "_TDE_Login_" in cred_name and "_cred" in cred_name:
                        categorized["tde_credentials"].append(cred)
                    else:
                        categorized["other_credentials"].append(cred)
                result = {
                    "success": True,
                    "operation": "list_credentials",
                    "connection": sql_connection,
                    "filter": credential_name,
                    "summary": {
                        "total_credentials": len(credentials),
                        "master_credentials": len(categorized["master_credentials"]),
                        "tde_credentials": len(categorized["tde_credentials"]),
                        "other_credentials": len(categorized["other_credentials"])
                    },
                    "credentials": categorized,
                    "timestamp": datetime.now().isoformat()
                }
                return json.dumps(result, indent=2)
            elif operation == "update":
                # Update credential (original logic)
                if not credential_name or not new_password:
                    return json.dumps({"success": False, "error": "credential_name and new_password are required for update"})
                check_sql = f"""
                SELECT 
                    c.name,
                    c.credential_identity,
                    cp.name as provider_name
                FROM master.sys.credentials c
                LEFT JOIN master.sys.cryptographic_providers cp 
                    ON c.target_id = cp.provider_id AND c.target_type = 'CRYPTOGRAPHIC PROVIDER'
                WHERE c.name = '{credential_name}'
                """
                check_result = await db_handler.execute_sql(check_sql)
                if not check_result["success"] or not check_result["results"][0]["data"]:
                    return json.dumps({"success": False, "error": f"Credential '{credential_name}' not found"})
                current_cred = check_result["results"][0]["data"][0]
                if ciphertrust_username:
                    identity = f"{ciphertrust_domain}||{ciphertrust_username}" if ciphertrust_domain and ciphertrust_domain != "root" else ciphertrust_username
                else:
                    identity = current_cred["credential_identity"]
                update_sql = f"""
                ALTER CREDENTIAL [{credential_name}]
                WITH IDENTITY = '{identity}',
                SECRET = '{new_password}'
                """
                update_result = await db_handler.execute_sql(update_sql)
                if not update_result["success"]:
                    return json.dumps({"success": False, "error": f"Failed to update credential: {update_result['error']}"})
                mapping_sql = f"""
                SELECT 
                    p.name as login_name,
                    p.type_desc as principal_type
                FROM sys.server_principal_credentials pc
                JOIN sys.server_principals p ON pc.principal_id = p.principal_id
                JOIN sys.credentials c ON pc.credential_id = c.credential_id
                WHERE c.name = '{credential_name}'
                """
                mapping_result = await db_handler.execute_sql(mapping_sql)
                affected_logins = []
                if mapping_result["success"] and mapping_result["results"][0]["data"]:
                    affected_logins = [row["login_name"] for row in mapping_result["results"][0]["data"]]
                result = {
                    "success": True,
                    "operation": "update_credential",
                    "credential_name": credential_name,
                    "identity_used": identity,
                    "identity_changed": ciphertrust_username is not None,
                    "provider": current_cred["provider_name"],
                    "affected_logins": affected_logins,
                    "timestamp": datetime.now().isoformat()
                }
                return json.dumps(result, indent=2)
            elif operation == "drop":
                # Drop credential (original logic)
                if not credential_name:
                    return json.dumps({"success": False, "error": "credential_name is required for drop"})
                check_sql = f"""
                SELECT 
                    c.credential_id,
                    c.name as credential_name,
                    p.name as login_name,
                    p.principal_id
                FROM master.sys.credentials c
                LEFT JOIN sys.server_principal_credentials pc ON c.credential_id = pc.credential_id
                LEFT JOIN sys.server_principals p ON pc.principal_id = p.principal_id
                WHERE c.name = '{credential_name}'
                """
                check_result = await db_handler.execute_sql(check_sql)
                if not check_result["success"] or not check_result["results"][0]["data"]:
                    return json.dumps({"success": False, "error": f"Credential '{credential_name}' not found"})
                mappings = check_result["results"][0]["data"]
                mapped_logins = [m["login_name"] for m in mappings if m["login_name"]]
                if mapped_logins and not force:
                    return json.dumps({
                        "success": False,
                        "error": f"Credential is mapped to logins: {', '.join(mapped_logins)}. Use force=true to remove mappings and drop.",
                        "mapped_logins": mapped_logins
                    })
                results = []
                if mapped_logins and force:
                    for login in mapped_logins:
                        remove_mapping_sql = f"""
                        ALTER LOGIN [{login}] DROP CREDENTIAL [{credential_name}]
                        """
                        remove_result = await db_handler.execute_sql(remove_mapping_sql)
                        results.append({
                            "step": "remove_mapping",
                            "login": login,
                            "success": remove_result["success"],
                            "error": remove_result.get("error")
                        })
                drop_sql = f"DROP CREDENTIAL [{credential_name}]"
                drop_result = await db_handler.execute_sql(drop_sql)
                if not drop_result["success"]:
                    return json.dumps({
                        "success": False,
                        "error": f"Failed to drop credential: {drop_result['error']}",
                        "removal_steps": results
                    })
                result = {
                    "success": True,
                    "operation": "drop_credential",
                    "credential_name": credential_name,
                    "mappings_removed": mapped_logins if force else [],
                    "removal_steps": results,
                    "timestamp": datetime.now().isoformat()
                }
                return json.dumps(result, indent=2)
            elif operation == "fix_mappings":
                # Fix credential mappings (original logic)
                if not login_name:
                    return json.dumps({"success": False, "error": "login_name is required for fix_mappings"})
                check_login_sql = f"""
                SELECT 
                    name,
                    type_desc,
                    is_disabled
                FROM sys.server_principals
                WHERE name = '{login_name}'
                """
                login_result = await db_handler.execute_sql(check_login_sql)
                if not login_result["success"] or not login_result["results"][0]["data"]:
                    return json.dumps({"success": False, "error": f"Login '{login_name}' not found"})
                login_info = login_result["results"][0]["data"][0]
                current_mappings_sql = f"""
                SELECT 
                    c.name as credential_name,
                    c.credential_identity
                FROM sys.server_principal_credentials pc
                JOIN sys.server_principals p ON pc.principal_id = p.principal_id
                JOIN sys.credentials c ON pc.credential_id = c.credential_id
                WHERE p.name = '{login_name}'
                """
                current_result = await db_handler.execute_sql(current_mappings_sql)
                current_mappings = []
                if current_result["success"] and current_result["results"][0]["data"]:
                    current_mappings = [row["credential_name"] for row in current_result["results"][0]["data"]]
                results = []
                if credential_name:
                    if credential_name not in current_mappings:
                        check_cred_sql = f"SELECT name FROM master.sys.credentials WHERE name = '{credential_name}'"
                        cred_result = await db_handler.execute_sql(check_cred_sql)
                        if not cred_result["success"] or not cred_result["results"][0]["data"]:
                            return json.dumps({"success": False, "error": f"Credential '{credential_name}' not found"})
                        add_mapping_sql = f"ALTER LOGIN [{login_name}] ADD CREDENTIAL [{credential_name}]"
                        add_result = await db_handler.execute_sql(add_mapping_sql)
                        results.append({
                            "action": "add_mapping",
                            "credential": credential_name,
                            "success": add_result["success"],
                            "error": add_result.get("error")
                        })
                    else:
                        results.append({
                            "action": "mapping_exists",
                            "credential": credential_name,
                            "message": "Mapping already exists"
                        })
                else:
                    if login_name.startswith("TDE_Login_"):
                        key_name = login_name.replace("TDE_Login_", "")
                        find_tde_creds_sql = f"""
                        SELECT name 
                        FROM master.sys.credentials 
                        WHERE name LIKE '%_TDE_Login_{key_name}_cred'
                        """
                        tde_creds_result = await db_handler.execute_sql(find_tde_creds_sql)
                        if tde_creds_result["success"] and tde_creds_result["results"][0]["data"]:
                            for row in tde_creds_result["results"][0]["data"]:
                                cred_name = row["name"]
                                if cred_name not in current_mappings:
                                    add_mapping_sql = f"ALTER LOGIN [{login_name}] ADD CREDENTIAL [{cred_name}]"
                                    add_result = await db_handler.execute_sql(add_mapping_sql)
                                    results.append({
                                        "action": "add_mapping",
                                        "credential": cred_name,
                                        "success": add_result["success"],
                                        "error": add_result.get("error")
                                    })
                    else:
                        find_master_creds_sql = """
                        SELECT name 
                        FROM master.sys.credentials 
                        WHERE name LIKE '%_master_cred'
                        """
                        master_creds_result = await db_handler.execute_sql(find_master_creds_sql)
                        if master_creds_result["success"] and master_creds_result["results"][0]["data"]:
                            for row in master_creds_result["results"][0]["data"]:
                                cred_name = row["name"]
                                if cred_name not in current_mappings:
                                    add_mapping_sql = f"ALTER LOGIN [{login_name}] ADD CREDENTIAL [{cred_name}]"
                                    add_result = await db_handler.execute_sql(add_mapping_sql)
                                    results.append({
                                        "action": "add_mapping",
                                        "credential": cred_name,
                                        "success": add_result["success"],
                                        "error": add_result.get("error")
                                    })
                final_result = await db_handler.execute_sql(current_mappings_sql)
                final_mappings = []
                if final_result["success"] and final_result["results"][0]["data"]:
                    final_mappings = [row["credential_name"] for row in final_result["results"][0]["data"]]
                result = {
                    "success": True,
                    "operation": "fix_credential_mappings",
                    "login_name": login_name,
                    "login_type": login_info["type_desc"],
                    "initial_mappings": current_mappings,
                    "final_mappings": final_mappings,
                    "actions": results,
                    "timestamp": datetime.now().isoformat()
                }
                return json.dumps(result, indent=2)
            else:
                return json.dumps({"success": False, "error": f"Invalid operation: {operation}"})
        except Exception as e:
            return json.dumps({"success": False, "error": str(e)})
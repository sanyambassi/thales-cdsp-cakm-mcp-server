"""
Audit and compliance tools for Database TDE
"""

import json
import logging
from datetime import datetime
from typing import Optional, Dict, Any

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

def register_audit_tools(server: FastMCP, db_manager):
    """Register audit and compliance tools with the MCP server"""
    
    @server.tool()
    async def generate_tde_compliance_report(
        sql_connection: str,
        include_recommendations: bool = True
    ) -> str:
        """
        Generate a comprehensive TDE compliance report for auditors.
        
        Args:
            sql_connection: Database connection name
            include_recommendations: Include security recommendations
            
        Returns:
            JSON string containing full compliance report.
        """
        try:
            logger.info(f"=== generate_tde_compliance_report called ===")
            
            db_handler = db_manager.get_database_handler(sql_connection)
            
            # Get comprehensive compliance data
            compliance_data = await db_handler.get_tde_compliance_data()
            
            # Calculate compliance score
            total_score = 100
            deductions = []
            
            # Check encryption coverage
            overview = compliance_data.get("encryption_overview", {})
            total_user_dbs = (overview.get("total_databases", 0) - 
                            overview.get("system_databases", 0))
            unencrypted_user_dbs = overview.get("unencrypted_user_databases", 0)
            
            if total_user_dbs > 0 and unencrypted_user_dbs > 0:
                coverage_penalty = (unencrypted_user_dbs / total_user_dbs) * 30
                total_score -= coverage_penalty
                deductions.append({
                    "category": "Encryption Coverage",
                    "points": coverage_penalty,
                    "reason": f"{unencrypted_user_dbs} user databases are not encrypted"
                })
            
            # Check for security warnings
            warnings = compliance_data.get("security_warnings", [])
            high_severity_warnings = [w for w in warnings if w.get("severity") == "HIGH"]
            medium_severity_warnings = [w for w in warnings if w.get("severity") == "MEDIUM"]
            
            if high_severity_warnings:
                penalty = len(high_severity_warnings) * 10
                total_score -= penalty
                deductions.append({
                    "category": "Security Issues",
                    "points": penalty,
                    "reason": f"{len(high_severity_warnings)} high severity security issues found"
                })
            
            if medium_severity_warnings:
                penalty = len(medium_severity_warnings) * 5
                total_score -= penalty
                deductions.append({
                    "category": "Security Issues",
                    "points": penalty,
                    "reason": f"{len(medium_severity_warnings)} medium severity security issues found"
                })
            
            # Ensure score doesn't go below 0
            total_score = max(0, total_score)
            
            # Generate recommendations
            recommendations = []
            
            if unencrypted_user_dbs > 0:
                recommendations.append({
                    "priority": "HIGH",
                    "category": "Encryption Coverage",
                    "recommendation": "Encrypt all user databases with TDE",
                    "impact": "Protects data at rest from unauthorized access",
                    "effort": "Medium"
                })
            
            for warning in high_severity_warnings:
                if warning["type"] == "WEAK_KEY_SIZE":
                    recommendations.append({
                        "priority": "HIGH",
                        "category": "Key Management",
                        "recommendation": f"Upgrade key '{warning['details']['name']}' to at least 2048-bit RSA",
                        "impact": "Significantly improves encryption strength",
                        "effort": "High (requires key rotation)"
                    })
            
            for warning in medium_severity_warnings:
                if warning["type"] == "WEAK_ENCRYPTION_ALGORITHM":
                    recommendations.append({
                        "priority": "MEDIUM",
                        "category": "Encryption Standards",
                        "recommendation": f"Rotate DEK for database '{warning['details']['database_name']}' to AES_256",
                        "impact": "Aligns with current encryption best practices",
                        "effort": "Low (use rotate_database_encryption_key)"
                    })
            
            # Build the report
            report = {
                "success": True,
                "operation": "generate_tde_compliance_report",
                "connection": sql_connection,
                "report_date": datetime.now().isoformat(),
                "executive_summary": {
                    "compliance_score": round(total_score, 1),
                    "score_deductions": deductions,
                    "encryption_coverage": {
                        "total_databases": overview.get("total_databases", 0),
                        "encrypted_databases": overview.get("encrypted_databases", 0),
                        "unencrypted_user_databases": unencrypted_user_dbs,
                        "coverage_percentage": round(
                            (overview.get("encrypted_databases", 0) / total_user_dbs * 100) 
                            if total_user_dbs > 0 else 0, 1
                        )
                    },
                    "security_issues": {
                        "high_severity": len(high_severity_warnings),
                        "medium_severity": len(medium_severity_warnings),
                        "low_severity": len(warnings) - len(high_severity_warnings) - len(medium_severity_warnings)
                    }
                },
                "detailed_findings": {
                    "encryption_overview": compliance_data["encryption_overview"],
                    "key_management": compliance_data["key_details"],
                    "certificates": compliance_data["certificate_info"],
                    "providers": compliance_data["provider_info"],
                    "credentials": compliance_data["credential_info"],
                    "security_warnings": compliance_data["security_warnings"]
                }
            }
            
            if include_recommendations:
                report["recommendations"] = sorted(
                    recommendations, 
                    key=lambda x: {"HIGH": 0, "MEDIUM": 1, "LOW": 2}.get(x["priority"], 3)
                )
            
            logger.info(f"=== generate_tde_compliance_report completed ===")
            return json.dumps(report, indent=2)
            
        except Exception as e:
            logger.error(f"Error generating compliance report: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    @server.tool()
    async def check_tde_best_practices(
        sql_connection: str
    ) -> str:
        """
        Check TDE configuration against security best practices.
        
        Args:
            sql_connection: Database connection name
            
        Returns:
            JSON string containing best practices evaluation.
        """
        try:
            logger.info(f"=== check_tde_best_practices called ===")
            
            db_handler = db_manager.get_database_handler(sql_connection)
            
            # Get compliance data
            compliance_data = await db_handler.get_tde_compliance_data()
            
            # Define best practices checks
            checks = []
            
            # 1. All user databases should be encrypted
            overview = compliance_data.get("encryption_overview", {})
            unencrypted_user_dbs = overview.get("unencrypted_user_databases", 0)
            
            checks.append({
                "practice": "All user databases encrypted",
                "category": "Encryption Coverage",
                "passed": unencrypted_user_dbs == 0,
                "details": f"{unencrypted_user_dbs} user databases are not encrypted" if unencrypted_user_dbs > 0 else "All user databases are encrypted",
                "severity": "HIGH" if unencrypted_user_dbs > 0 else "INFO"
            })
            
            # 2. Use strong key sizes (2048-bit or higher for RSA)
            master_keys = compliance_data.get("key_details", {}).get("master_keys", {})
            weak_rsa_keys = []
            
            for key in master_keys.get("asymmetric_keys", []):
                if key.get("key_length", 0) < 2048:
                    weak_rsa_keys.append(key["name"])
            
            checks.append({
                "practice": "Use strong RSA key sizes (≥2048 bits)",
                "category": "Key Management",
                "passed": len(weak_rsa_keys) == 0,
                "details": f"Weak RSA keys found: {', '.join(weak_rsa_keys)}" if weak_rsa_keys else "All RSA keys use strong key sizes",
                "severity": "HIGH" if weak_rsa_keys else "INFO"
            })
            
            # 3. Use AES-256 for database encryption
            algo_dist = compliance_data.get("key_details", {}).get("algorithm_distribution", [])
            non_aes256_dbs = []
            
            for algo in algo_dist:
                if algo.get("key_algorithm") != "AES" or algo.get("key_length") != 256:
                    non_aes256_dbs.extend(algo.get("databases", "").split(", "))
            
            checks.append({
                "practice": "Use AES-256 for database encryption keys",
                "category": "Encryption Standards",
                "passed": len(non_aes256_dbs) == 0,
                "details": f"Databases not using AES-256: {', '.join(non_aes256_dbs)}" if non_aes256_dbs else "All databases use AES-256",
                "severity": "MEDIUM" if non_aes256_dbs else "INFO"
            })
            
            # 4. Separate credentials per user/purpose
            cred_info = compliance_data.get("credential_info", {})
            master_creds = cred_info.get("master_credentials", 0) or 0
            tde_creds = cred_info.get("tde_credentials", 0) or 0
            
            checks.append({
                "practice": "Use separate credentials for different purposes",
                "category": "Access Control",
                "passed": master_creds > 0 and tde_creds > 0,
                "details": f"Master credentials: {master_creds}, TDE credentials: {tde_creds}",
                "severity": "LOW" if master_creds == 0 or tde_creds == 0 else "INFO"
            })
            
            # 5. Regular key rotation (check if multiple keys exist suggesting rotation)
            total_asymmetric = len(master_keys.get("asymmetric_keys", []))
            total_symmetric = len(master_keys.get("symmetric_keys", []))
            
            checks.append({
                "practice": "Evidence of key rotation",
                "category": "Key Management",
                "passed": (total_asymmetric + total_symmetric) > 1,
                "details": f"Total keys found: {total_asymmetric + total_symmetric}. Multiple keys suggest rotation practice.",
                "severity": "LOW" if (total_asymmetric + total_symmetric) <= 1 else "INFO"
            })
            
            # 6. No orphaned credentials or logins
            # This would require additional queries to check for unused credentials/logins
            
            # Calculate overall compliance
            total_checks = len(checks)
            passed_checks = sum(1 for check in checks if check["passed"])
            high_severity_failures = sum(1 for check in checks if not check["passed"] and check["severity"] == "HIGH")
            medium_severity_failures = sum(1 for check in checks if not check["passed"] and check["severity"] == "MEDIUM")
            
            result = {
                "success": True,
                "operation": "check_tde_best_practices",
                "connection": sql_connection,
                "summary": {
                    "total_checks": total_checks,
                    "passed": passed_checks,
                    "failed": total_checks - passed_checks,
                    "compliance_percentage": round((passed_checks / total_checks) * 100, 1),
                    "high_severity_failures": high_severity_failures,
                    "medium_severity_failures": medium_severity_failures
                },
                "checks": checks,
                "overall_assessment": {
                    "status": "COMPLIANT" if high_severity_failures == 0 else "NON_COMPLIANT",
                    "message": "All critical security practices are followed" if high_severity_failures == 0 else f"{high_severity_failures} critical security issues need attention"
                },
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== check_tde_best_practices completed ===")
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error checking best practices: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    @server.tool()
    async def list_encryption_history(
        sql_connection: str,
        database_name: Optional[str] = None
    ) -> str:
        """
        Show encryption state history for databases.
        Note: Shows current state as SQL Server doesn't maintain historical TDE state by default.
        
        Args:
            sql_connection: Database connection name
            database_name: Optional specific database to check
            
        Returns:
            JSON string containing encryption history information.
        """
        try:
            logger.info(f"=== list_encryption_history called ===")
            
            db_handler = db_manager.get_database_handler(sql_connection)
            
            # Get current encryption states (as history)
            history = await db_handler.get_encryption_history()
            
            # Filter by database if specified
            if database_name:
                history = [h for h in history if h.get("database_name") == database_name]
            
            # Group by database
            history_by_db = {}
            for event in history:
                db_name = event["database_name"]
                if db_name not in history_by_db:
                    history_by_db[db_name] = []
                history_by_db[db_name].append(event)
            
            result = {
                "success": True,
                "operation": "list_encryption_history",
                "connection": sql_connection,
                "filter": database_name,
                "note": "Shows current encryption state. For detailed history, enable SQL Server auditing.",
                "history_by_database": history_by_db,
                "total_events": len(history),
                "databases_tracked": len(history_by_db),
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== list_encryption_history completed ===")
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error listing encryption history: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    @server.tool()
    async def export_tde_configuration(
        sql_connection: str,
        format: str = "json"
    ) -> str:
        """
        Export current TDE configuration for documentation or backup.
        
        Args:
            sql_connection: Database connection name
            format: Export format - "json" or "summary"
            
        Returns:
            JSON string containing complete TDE configuration.
        """
        try:
            logger.info(f"=== export_tde_configuration called ===")
            
            db_handler = db_manager.get_database_handler(sql_connection)
            
            # Gather all configuration data
            config_data = {
                "export_date": datetime.now().isoformat(),
                "server_info": {
                    "connection_name": sql_connection,
                    "host": db_handler.connection.host,
                    "instance": db_handler.connection.instance,
                    "port": db_handler.connection.port
                },
                "encryption_status": [],
                "master_keys": {},
                "cryptographic_providers": [],
                "credentials": [],
                "logins": []
            }
            
            # 1. Get encryption status for all databases
            all_status = await db_handler.check_encryption_status()
            config_data["encryption_status"] = [
                {
                    "database_name": status.database_name,
                    "is_encrypted": status.is_encrypted,
                    "encryption_state": status.encryption_state,
                    "encryption_state_desc": status.encryption_state_desc,
                    "key_algorithm": status.key_algorithm,
                    "key_length": status.key_length
                }
                for status in all_status
            ]
            
            # 2. Get master keys
            config_data["master_keys"] = await db_handler.list_master_keys()
            
            # 3. Get providers
            config_data["cryptographic_providers"] = await db_handler.list_cryptographic_providers()
            
            # 4. Get credentials (summary only for security)
            cred_sql = """
            SELECT 
                name,
                credential_id,
                create_date,
                modify_date,
                target_type
            FROM sys.credentials
            WHERE target_type = 'CRYPTOGRAPHIC PROVIDER'
            ORDER BY name
            """
            
            cred_result = await db_handler.execute_sql(cred_sql)
            if cred_result["success"]:
                credentials = cred_result["results"][0]["data"]
                for cred in credentials:
                    if cred.get("create_date") and hasattr(cred["create_date"], "isoformat"):
                        cred["create_date"] = cred["create_date"].isoformat()
                    if cred.get("modify_date") and hasattr(cred["modify_date"], "isoformat"):
                        cred["modify_date"] = cred["modify_date"].isoformat()
                config_data["credentials"] = credentials
            
            # 5. Get TDE-related logins
            all_logins = await db_handler.list_logins()
            tde_logins = [
                {
                    "name": login["name"],
                    "type": login["type_desc"],
                    "is_disabled": login["is_disabled"],
                    "asymmetric_key_name": login.get("asymmetric_key_name"),
                    "credential_count": login["credential_count"]
                }
                for login in all_logins 
                if login.get("is_tde_login") or login["name"].startswith("TDE_Login_")
            ]
            config_data["logins"] = tde_logins
            
            if format == "summary":
                # Create a summary version
                summary = {
                    "export_date": config_data["export_date"],
                    "server": f"{config_data['server_info']['host']}\\{config_data['server_info']['instance']}",
                    "statistics": {
                        "total_databases": len(config_data["encryption_status"]),
                        "encrypted_databases": sum(1 for db in config_data["encryption_status"] if db["is_encrypted"]),
                        "cryptographic_providers": len(config_data["cryptographic_providers"]),
                        "master_keys": {
                            "asymmetric": len(config_data["master_keys"].get("asymmetric_keys", [])),
                            "symmetric": len(config_data["master_keys"].get("symmetric_keys", []))
                        },
                        "credentials": len(config_data["credentials"]),
                        "tde_logins": len(config_data["logins"])
                    },
                    "encrypted_databases": [
                        db["database_name"] 
                        for db in config_data["encryption_status"] 
                        if db["is_encrypted"]
                    ]
                }
                
                result = {
                    "success": True,
                    "operation": "export_tde_configuration",
                    "format": "summary",
                    "configuration": summary
                }
            else:
                # Full JSON export
                result = {
                    "success": True,
                    "operation": "export_tde_configuration",
                    "format": "json",
                    "configuration": config_data
                }
            
            logger.info(f"=== export_tde_configuration completed ===")
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error exporting TDE configuration: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    @server.tool()
    async def validate_tde_setup(
        sql_connection: str,
        database_name: str
    ) -> str:
        """
        Validate that a database is properly configured for TDE.
        
        Args:
            sql_connection: Database connection name
            database_name: Database to validate
            
        Returns:
            JSON string containing validation results.
        """
        try:
            logger.info(f"=== validate_tde_setup called ===")
            
            db_handler = db_manager.get_database_handler(sql_connection)
            
            validation_results = []
            all_valid = True
            
            # 1. Check if database exists
            db_check_sql = f"SELECT name FROM sys.databases WHERE name = '{database_name}'"
            db_result = await db_handler.execute_sql(db_check_sql)
            
            if not (db_result["success"] and db_result["results"][0]["data"]):
                return json.dumps({
                    "success": False,
                    "error": f"Database '{database_name}' not found"
                })
            
            # 2. Check encryption status
            enc_status = await db_handler.check_encryption_status(database_name)
            
            if enc_status and enc_status[0].is_encrypted:
                validation_results.append({
                    "check": "Database Encryption",
                    "status": "PASS",
                    "details": f"Database is encrypted (state: {enc_status[0].encryption_state_desc})"
                })
                
                # 3. Check DEK algorithm
                if enc_status[0].key_algorithm == "AES" and enc_status[0].key_length == 256:
                    validation_results.append({
                        "check": "DEK Algorithm",
                        "status": "PASS",
                        "details": "Using recommended AES-256 encryption"
                    })
                else:
                    validation_results.append({
                        "check": "DEK Algorithm",
                        "status": "WARNING",
                        "details": f"Using {enc_status[0].key_algorithm}_{enc_status[0].key_length} instead of recommended AES_256"
                    })
                    all_valid = False
                
                # 4. Check master key
                master_key_sql = f"""
                SELECT 
                    COALESCE(ak.name, sk.name) as key_name,
                    CASE 
                        WHEN ak.name IS NOT NULL THEN 'ASYMMETRIC'
                        WHEN sk.name IS NOT NULL THEN 'SYMMETRIC'
                    END as key_type,
                    COALESCE(ak.algorithm_desc, sk.algorithm_desc) as algorithm,
                    COALESCE(ak.key_length, sk.key_length) as key_length
                FROM sys.dm_database_encryption_keys dek
                LEFT JOIN master.sys.asymmetric_keys ak ON dek.encryptor_thumbprint = ak.thumbprint
                LEFT JOIN master.sys.symmetric_keys sk ON dek.encryptor_thumbprint = sk.key_guid
                WHERE dek.database_id = DB_ID('{database_name}')
                """
                
                key_result = await db_handler.execute_sql(master_key_sql)
                
                if key_result["success"] and key_result["results"][0]["data"]:
                    key_info = key_result["results"][0]["data"][0]
                    validation_results.append({
                        "check": "Master Key",
                        "status": "PASS",
                        "details": f"Protected by {key_info['key_type']} key '{key_info['key_name']}' ({key_info['algorithm']})"
                    })
                    
                    # Check key strength
                    if key_info["key_type"] == "ASYMMETRIC" and key_info["key_length"] < 2048:
                        validation_results.append({
                            "check": "Master Key Strength",
                            "status": "WARNING",
                            "details": f"RSA key size {key_info['key_length']} is below recommended 2048 bits"
                        })
                        all_valid = False
                    else:
                        validation_results.append({
                            "check": "Master Key Strength",
                            "status": "PASS",
                            "details": "Key size meets security requirements"
                        })
            else:
                validation_results.append({
                    "check": "Database Encryption",
                    "status": "FAIL",
                    "details": "Database is not encrypted with TDE"
                })
                all_valid = False
            
            # 5. Check for required credentials and logins
            if enc_status and enc_status[0].is_encrypted:
                # This check would be more complex in reality
                validation_results.append({
                    "check": "Credentials and Logins",
                    "status": "INFO",
                    "details": "Use list_credentials and list_logins to verify proper access control"
                })
            
            result = {
                "success": True,
                "operation": "validate_tde_setup",
                "database": database_name,
                "validation_passed": all_valid,
                "validation_results": validation_results,
                "summary": {
                    "total_checks": len(validation_results),
                    "passed": sum(1 for r in validation_results if r["status"] == "PASS"),
                    "warnings": sum(1 for r in validation_results if r["status"] == "WARNING"),
                    "failed": sum(1 for r in validation_results if r["status"] == "FAIL")
                },
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== validate_tde_setup completed ===")
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error validating TDE setup: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            })
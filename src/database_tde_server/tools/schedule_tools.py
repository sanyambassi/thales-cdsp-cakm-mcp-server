"""
Schedule generation tools for key rotation
"""

import json
import logging
from datetime import datetime, timedelta
from typing import Optional, List

from mcp.server.fastmcp import FastMCP

logger = logging.getLogger(__name__)

def register_schedule_tools(server: FastMCP, db_manager):
    """Register schedule generation tools with the MCP server"""
    
    @server.tool()
    async def generate_rotation_schedule(
        sql_connection: str,
        rotation_interval_days: int = 90,
        include_master_keys: bool = True,
        include_dek_keys: bool = True,
        scheduler_type: str = "cron"
    ) -> str:
        """
        Generate a key rotation schedule with commands for external schedulers.
        
        Args:
            sql_connection: Database connection name
            rotation_interval_days: Days between rotations (default: 90)
            include_master_keys: Include master key rotation in schedule
            include_dek_keys: Include database encryption key rotation in schedule  
            scheduler_type: Type of scheduler - "cron", "windows_task", or "commands"
            
        Returns:
            JSON string containing rotation schedule and commands.
        """
        try:
            logger.info(f"=== generate_rotation_schedule called ===")
            
            db_handler = db_manager.get_database_handler(sql_connection)
            
            # Get current encryption status
            encryption_status = await db_handler.check_encryption_status()
            encrypted_databases = [
                status.database_name 
                for status in encryption_status 
                if status.is_encrypted
            ]
            
            if not encrypted_databases:
                return json.dumps({
                    "success": False,
                    "error": "No encrypted databases found"
                })
            
            # Get master keys
            master_keys = await db_handler.list_master_keys()
            all_master_keys = []
            
            for key in master_keys.get("asymmetric_keys", []):
                all_master_keys.append({
                    "name": key["name"],
                    "type": "RSA",
                    "algorithm": key["algorithm_desc"]
                })
            
            for key in master_keys.get("symmetric_keys", []):
                all_master_keys.append({
                    "name": key["name"],
                    "type": "AES",
                    "algorithm": key["algorithm_desc"]
                })
            
            # Generate schedule
            schedule_items = []
            base_date = datetime.now()
            
            # Schedule DEK rotations
            if include_dek_keys:
                for i, db_name in enumerate(encrypted_databases):
                    # Stagger rotations to avoid all at once
                    rotation_date = base_date + timedelta(days=(i * 7) % rotation_interval_days)
                    
                    schedule_items.append({
                        "type": "DEK_ROTATION",
                        "database": db_name,
                        "next_rotation": rotation_date.isoformat(),
                        "interval_days": rotation_interval_days,
                        "command": f"rotate_database_encryption_key --sql_connection {sql_connection} --database_name {db_name}"
                    })
            
            # Schedule master key rotations
            if include_master_keys and all_master_keys:
                for i, key in enumerate(all_master_keys):
                    # Master keys rotate less frequently
                    rotation_date = base_date + timedelta(days=(i * 30) % (rotation_interval_days * 2))
                    
                    # Find databases using this key
                    key_usage_sql = f"""
                    SELECT db.name as database_name
                    FROM sys.dm_database_encryption_keys dek
                    INNER JOIN sys.databases db ON dek.database_id = db.database_id
                    LEFT JOIN master.sys.asymmetric_keys ak ON dek.encryptor_thumbprint = ak.thumbprint
                    LEFT JOIN master.sys.symmetric_keys sk ON dek.encryptor_thumbprint = sk.key_guid
                    WHERE ak.name = '{key["name"]}' OR sk.name = '{key["name"]}'
                    """
                    
                    usage_result = await db_handler.execute_sql(key_usage_sql)
                    databases_using_key = []
                    
                    if usage_result["success"] and usage_result["results"][0]["data"]:
                        databases_using_key = [row["database_name"] for row in usage_result["results"][0]["data"]]
                    
                    if databases_using_key:
                        schedule_items.append({
                            "type": "MASTER_KEY_ROTATION",
                            "key_name": key["name"],
                            "key_type": key["type"],
                            "databases_affected": databases_using_key,
                            "next_rotation": rotation_date.isoformat(),
                            "interval_days": rotation_interval_days * 2,
                            "command": f"rotate_master_key --sql_connection {sql_connection} --database_name {databases_using_key[0]} --new_key_name {key['name']}_ROTATE_{{DATE}} --key_type {key['type']}"
                        })
            
            # Generate scheduler-specific output
            scheduler_config = {}
            
            if scheduler_type == "cron":
                # Generate cron entries
                cron_entries = []
                for item in schedule_items:
                    # Simple daily check that runs command if date matches
                    cron_entries.append({
                        "schedule": "0 2 * * *",  # Daily at 2 AM
                        "command": f"/path/to/mcp-client {item['command']} --check-date {item['next_rotation']}",
                        "comment": f"{item['type']} for {item.get('database', item.get('key_name'))}"
                    })
                scheduler_config["cron_entries"] = cron_entries
                
            elif scheduler_type == "windows_task":
                # Generate Windows Task Scheduler XML snippets
                task_configs = []
                for item in schedule_items:
                    task_configs.append({
                        "name": f"TDE_{item['type']}_{item.get('database', item.get('key_name'))}",
                        "trigger_date": item['next_rotation'],
                        "interval": f"P{item['interval_days']}D",  # ISO 8601 duration
                        "action": f"C:\\path\\to\\mcp-client.exe {item['command']}",
                        "description": f"Automated {item['type']} for {item.get('database', item.get('key_name'))}"
                    })
                scheduler_config["windows_tasks"] = task_configs
                
            else:  # commands
                # Just list the commands with dates
                scheduler_config["manual_commands"] = [
                    {
                        "run_date": item['next_rotation'],
                        "command": item['command'],
                        "description": f"{item['type']} for {item.get('database', item.get('key_name'))}"
                    }
                    for item in schedule_items
                ]
            
            # Calculate summary statistics
            next_rotation = min(item['next_rotation'] for item in schedule_items) if schedule_items else None
            
            result = {
                "success": True,
                "operation": "generate_rotation_schedule",
                "connection": sql_connection,
                "schedule_summary": {
                    "total_items": len(schedule_items),
                    "dek_rotations": sum(1 for item in schedule_items if item['type'] == 'DEK_ROTATION'),
                    "master_key_rotations": sum(1 for item in schedule_items if item['type'] == 'MASTER_KEY_ROTATION'),
                    "rotation_interval_days": rotation_interval_days,
                    "next_rotation_due": next_rotation
                },
                "schedule_items": schedule_items,
                "scheduler_config": scheduler_config,
                "implementation_notes": {
                    "cron": "Add cron entries to system crontab. Implement date checking in wrapper script.",
                    "windows_task": "Import tasks using Task Scheduler GUI or schtasks command.",
                    "commands": "Run commands manually or integrate with your preferred scheduler."
                },
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== generate_rotation_schedule completed ===")
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error generating rotation schedule: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            })
    
    @server.tool()
    async def estimate_rotation_impact(
        sql_connection: str,
        rotation_type: str,
        target: str
    ) -> str:
        """
        Estimate the impact of a key rotation operation.
        
        Args:
            sql_connection: Database connection name
            rotation_type: Type of rotation - "DEK" or "MASTER_KEY"
            target: Database name (for DEK) or key name (for master key)
            
        Returns:
            JSON string containing impact analysis.
        """
        try:
            logger.info(f"=== estimate_rotation_impact called ===")
            
            db_handler = db_manager.get_database_handler(sql_connection)
            
            impact_analysis = {
                "rotation_type": rotation_type,
                "target": target,
                "estimated_duration": "Unknown",
                "performance_impact": "Unknown",
                "availability_impact": "Online - No downtime required",
                "recommendations": []
            }
            
            if rotation_type.upper() == "DEK":
                # Get database size
                size_sql = f"""
                SELECT 
                    DB_NAME(database_id) as database_name,
                    SUM(size * 8.0 / 1024) as size_mb
                FROM sys.master_files
                WHERE database_id = DB_ID('{target}')
                GROUP BY database_id
                """
                
                size_result = await db_handler.execute_sql(size_sql)
                
                if size_result["success"] and size_result["results"][0]["data"]:
                    size_mb = size_result["results"][0]["data"][0]["size_mb"]
                    
                    # Rough estimates based on size
                    if size_mb < 1000:  # < 1 GB
                        impact_analysis["estimated_duration"] = "< 5 minutes"
                        impact_analysis["performance_impact"] = "Minimal"
                    elif size_mb < 10000:  # < 10 GB
                        impact_analysis["estimated_duration"] = "5-30 minutes"
                        impact_analysis["performance_impact"] = "Low to Moderate"
                    elif size_mb < 100000:  # < 100 GB
                        impact_analysis["estimated_duration"] = "30 minutes - 2 hours"
                        impact_analysis["performance_impact"] = "Moderate"
                        impact_analysis["recommendations"].append("Schedule during maintenance window")
                    else:  # > 100 GB
                        impact_analysis["estimated_duration"] = "> 2 hours"
                        impact_analysis["performance_impact"] = "High"
                        impact_analysis["recommendations"].append("Schedule during maintenance window")
                        impact_analysis["recommendations"].append("Monitor progress closely")
                    
                    impact_analysis["database_size_mb"] = size_mb
                
                # Check current activity
                activity_sql = f"""
                SELECT COUNT(*) as active_connections
                FROM sys.dm_exec_sessions
                WHERE database_id = DB_ID('{target}')
                AND session_id > 50  -- User sessions only
                """
                
                activity_result = await db_handler.execute_sql(activity_sql)
                if activity_result["success"] and activity_result["results"][0]["data"]:
                    active_connections = activity_result["results"][0]["data"][0]["active_connections"]
                    impact_analysis["current_active_connections"] = active_connections
                    
                    if active_connections > 10:
                        impact_analysis["recommendations"].append(f"High activity detected ({active_connections} connections)")
                
            else:  # MASTER_KEY rotation
                # Find affected databases
                usage_sql = f"""
                SELECT 
                    db.name as database_name,
                    SUM(mf.size * 8.0 / 1024) as size_mb
                FROM sys.dm_database_encryption_keys dek
                INNER JOIN sys.databases db ON dek.database_id = db.database_id
                INNER JOIN sys.master_files mf ON db.database_id = mf.database_id
                LEFT JOIN master.sys.asymmetric_keys ak ON dek.encryptor_thumbprint = ak.thumbprint
                LEFT JOIN master.sys.symmetric_keys sk ON dek.encryptor_thumbprint = sk.key_guid
                WHERE ak.name = '{target}' OR sk.name = '{target}'
                GROUP BY db.name
                """
                
                usage_result = await db_handler.execute_sql(usage_sql)
                
                if usage_result["success"] and usage_result["results"][0]["data"]:
                    affected_databases = usage_result["results"][0]["data"]
                    total_size_mb = sum(db["size_mb"] for db in affected_databases)
                    
                    impact_analysis["affected_databases"] = [db["database_name"] for db in affected_databases]
                    impact_analysis["total_size_mb"] = total_size_mb
                    
                    # Master key rotation is more complex
                    impact_analysis["estimated_duration"] = "Varies by database count and size"
                    impact_analysis["performance_impact"] = "Moderate to High"
                    impact_analysis["recommendations"].append("Requires creating new key infrastructure")
                    impact_analysis["recommendations"].append("Test in non-production first")
                    
                    if len(affected_databases) > 5:
                        impact_analysis["recommendations"].append(f"Affects {len(affected_databases)} databases - consider phased approach")
            
            # General recommendations
            impact_analysis["recommendations"].extend([
                "Ensure recent backup exists before rotation",
                "Monitor encryption_percent_complete during operation",
                "Have rollback plan ready"
            ])
            
            result = {
                "success": True,
                "operation": "estimate_rotation_impact",
                "connection": sql_connection,
                "impact_analysis": impact_analysis,
                "timestamp": datetime.now().isoformat()
            }
            
            logger.info(f"=== estimate_rotation_impact completed ===")
            return json.dumps(result, indent=2)
            
        except Exception as e:
            logger.error(f"Error estimating rotation impact: {e}", exc_info=True)
            return json.dumps({
                "success": False,
                "error": str(e),
                "error_type": type(e).__name__
            })
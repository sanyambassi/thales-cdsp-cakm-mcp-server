# Testing Guide

## Overview

This guide covers testing the Database TDE MCP Server functionality. Currently, the project focuses on **manual testing procedures** through MCP client interactions and direct database verification.

**Current Status:**
- ✅ Manual testing procedures documented
- ✅ MCP server connection testing available
- ⚠️ Automated test suite not yet implemented
- ⚠️ Unit/integration tests to be added in future releases

This guide provides both current testing approaches.

## Manual Testing

### 1. Connection Testing

```bash
# Test database connections
uv run python -m database_tde_server --test-connections

# Expected output:
# ✓ prod_sql: Connection successful
# ✓ oracle_cdb1: Connection successful
```

### 2. MCP Server Testing

#### Start the Server

```bash
# Start MCP server
uv run python -m database_tde_server

# Server should output:
# Database TDE MCP Server starting...
# Loaded X database connections
# Server ready for requests
```

#### JSON-RPC Manual Testing (stdio)

Test the MCP server directly using JSON-RPC commands via stdio communication.

**Prerequisites for JSON-RPC Testing:**
- Ensure `.env` file is configured with your database connections
- MCP server must be able to connect to your databases
- For encryption tests, CAKM providers must be installed and configured

**Testing Process:**

**1. Initialize the MCP Session**

```json
{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "capabilities": {"roots": {"listChanged": true}}, "clientInfo": {"name": "test-client", "version": "1.0.0"}}}
```

Expected response:
```json
{"jsonrpc": "2.0", "id": 1, "result": {"protocolVersion": "2024-11-05", "capabilities": {"tools": {}, "resources": {}}, "serverInfo": {"name": "Database TDE MCP Server", "version": "1.0.0"}}}
```

**2. Send Initialized Notification (Server does not respond to this)**

```json
{"jsonrpc": "2.0", "method": "notifications/initialized"}
```

**3. List Available Tools**

```json
{"jsonrpc": "2.0", "id": 2, "method": "tools/list"}
```

Expected response includes tools like:
```json
{"jsonrpc": "2.0", "id": 2, "result": {"tools": [{"name": "list_database_connections", "description": "List all configured database connections."}, {"name": "encrypt_sql_databases", "description": "Encrypt one or more SQL Server databases with TDE using CAKM EKM provider."}, ...]}}
```

**4. Test Connection Listing**

```json
{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_database_connections", "arguments": {}}}
```

**5. Test SQL Server Cryptographic Providers**

```json
{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "list_sql_cryptographic_providers", "arguments": {"sql_connection": "prod_sql"}}}
```

**6. Test SQL Server Database Monitoring**

```json
{"jsonrpc": "2.0", "id": 5, "method": "tools/call", "params": {"name": "monitor_sql_databases", "arguments": {"sql_connection": "prod_sql", "operation": "list_all", "encrypted_only": false}}}
```

**7. Test Oracle Wallet Status**

```json
{"jsonrpc": "2.0", "id": 6, "method": "tools/call", "params": {"name": "manage_oracle_wallet", "arguments": {"oracle_connection": "oracle_cdb1", "operation": "status", "container": "CDB$ROOT"}}}
```

**8. Test SQL Server Database Encryption**

```json
{"jsonrpc": "2.0", "id": 7, "method": "tools/call", "params": {"name": "encrypt_sql_databases", "arguments": {"database_names": "test_tde_db", "sql_connection": "prod_sql", "provider_name": "CipherTrustEKM", "ciphertrust_username": "admin", "ciphertrust_password": "password", "key_name": "test-key-001", "ciphertrust_domain": "root", "key_type": "RSA"}}}
```

**9. Test TDE Compliance Report**

```json
{"jsonrpc": "2.0", "id": 8, "method": "tools/call", "params": {"name": "generate_tde_compliance_report", "arguments": {"sql_connection": "prod_sql", "include_recommendations": true}}}
```

**10. Test Oracle TDE Assessment**

```json
{"jsonrpc": "2.0", "id": 9, "method": "tools/call", "params": {"name": "assess_oracle_tde_comprehensive", "arguments": {"oracle_connection": "oracle_cdb1", "include_recommendations": true, "include_debug_info": false}}}
```

#### Note on HTTP Transport

**This MCP server is stdio-only and does not support HTTP transport directly.** 
If you need HTTP-like testing, use **MCP Inspector** which provides a web interface that communicates with the stdio server internally.

#### Test MCP Tools via AI Assistant

Use an MCP client or AI assistant to test tools. **For comprehensive example prompts, see [EXAMPLE_PROMPTS.md](EXAMPLE_PROMPTS.md)** which contains ready-to-use testing scenarios for both SQL Server and Oracle.

#### Comprehensive Tool Testing Examples

**Connection Management Tools:**
```json
{"jsonrpc": "2.0", "id": 10, "method": "tools/call", "params": {"name": "list_database_connections", "arguments": {}}}
```

**SQL Server Key Management:**
```json
{"jsonrpc": "2.0", "id": 11, "method": "tools/call", "params": {"name": "manage_sql_master_keys", "arguments": {"sql_connection": "prod_sql", "operation": "list"}}}
```

**SQL Server Credential Management:**
```json
{"jsonrpc": "2.0", "id": 12, "method": "tools/call", "params": {"name": "manage_sql_credentials", "arguments": {"sql_connection": "prod_sql", "operation": "list", "show_mappings": true}}}
```

**SQL Server Login Management:**
```json
{"jsonrpc": "2.0", "id": 13, "method": "tools/call", "params": {"name": "manage_sql_logins", "arguments": {"sql_connection": "prod_sql", "operation": "list", "tde_only": true}}}
```

**Oracle Configuration:**
```json
{"jsonrpc": "2.0", "id": 14, "method": "tools/call", "params": {"name": "get_oracle_tde_configuration", "arguments": {"oracle_connection": "oracle_cdb1"}}}
```

**Oracle TDE Setup from Scratch:**
```json
{"jsonrpc": "2.0", "id": 15, "method": "tools/call", "params": {"name": "setup_oracle_tde_from_scratch", "arguments": {"oracle_connection": "oracle_cdb1", "ciphertrust_user": "admin", "ciphertrust_password": "password", "tde_configuration": "HSM", "auto_restart": true, "enable_autologin": false}}}
```

**Oracle Wallet Migration:**
```json
{"jsonrpc": "2.0", "id": 16, "method": "tools/call", "params": {"name": "migrate_tde", "arguments": {"oracle_connection": "oracle_cdb1", "ciphertrust_username": "admin", "ciphertrust_password": "password", "software_wallet_password": "wallet_password", "skip_database_restart": false}}}
```

**Audit and Compliance:**
```json
{"jsonrpc": "2.0", "id": 17, "method": "tools/call", "params": {"name": "generate_tde_compliance_report", "arguments": {"sql_connection": "prod_sql", "include_recommendations": true}}}
```

#### Testing with Python Script

Create a simple test script for automated JSON-RPC testing via stdio:

```python
# test_mcp_server.py
import json
import subprocess
import sys

def test_mcp_tool(tool_name, arguments=None):
    """Test an MCP tool using JSON-RPC"""
    if arguments is None:
        arguments = {}
    
    # Initialize
    init_msg = {
        "jsonrpc": "2.0", 
        "id": 1, 
        "method": "initialize", 
        "params": {
            "protocolVersion": "2024-11-05", 
            "capabilities": {}, 
            "clientInfo": {"name": "test-script", "version": "1.0.0"}
        }
    }
    
    # Initialized notification
    initialized_msg = {"jsonrpc": "2.0", "method": "notifications/initialized"}
    
    # Tool call
    tool_msg = {
        "jsonrpc": "2.0", 
        "id": 2, 
        "method": "tools/call", 
        "params": {"name": tool_name, "arguments": arguments}
    }
    
    # Run MCP server and send commands
    proc = subprocess.Popen(
        ["uv", "run", "python", "-m", "database_tde_server"],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True
    )
    
    input_data = "\n".join([
        json.dumps(init_msg),
        json.dumps(initialized_msg),
        json.dumps(tool_msg)
    ])
    
    try:
        stdout, stderr = proc.communicate(input=input_data, timeout=30)
        print(f"Testing {tool_name}:")
        print(f"STDOUT: {stdout}")
        if stderr:
            print(f"STDERR: {stderr}")
    except subprocess.TimeoutExpired:
        proc.kill()
        print(f"Test timed out for {tool_name}")

# Example usage
if __name__ == "__main__":
    # Test connection listing
    test_mcp_tool("list_database_connections")
    
    # Test SQL monitoring
    test_mcp_tool("monitor_sql_databases", {
        "sql_connection": "prod_sql", 
        "operation": "list_all"
    })
```

Run the test script:
```bash
python test_mcp_server.py
```

#### Testing with MCP Inspector

MCP Inspector is a debugging tool that provides a web interface for testing MCP servers.

**Installation:**
```bash
npx @modelcontextprotocol/inspector uv run python -m database_tde_server
```

**Usage:**
1. The inspector will start your MCP server and open a web interface (typically `http://localhost:5173`)
2. **Connect to Server**: Click "Connect to Server" to establish connection
3. **Browse Tools**: View all available tools in the left sidebar
4. **Test Tools**: Click on any tool to see its parameters and test it
5. **Real-time Testing**: Enter parameters and execute tools directly from the web interface

**Benefits of MCP Inspector:**
- **Visual Interface**: Easy-to-use web UI for testing
- **Parameter Validation**: Shows required/optional parameters for each tool
- **Response Viewer**: Formatted JSON responses with syntax highlighting
- **Debug Mode**: Shows raw JSON-RPC communication
- **Tool Documentation**: Displays tool descriptions and parameter details

**Example Inspector Workflow:**
1. Open inspector: `npx @modelcontextprotocol/inspector uv run python -m database_tde_server`
2. Click "Connect to Server"
3. Browse available tools in the sidebar
4. Click "list_database_connections" → Run Tool
5. Click "monitor_sql_databases" → Fill parameters → Execute
6. View formatted responses in the inspector

**Inspector vs Other Methods:**
- **Inspector**: Best for interactive testing and exploration (provides web UI for stdio server)
- **JSON-RPC Direct (stdio)**: Best for automation and scripting  
- **AI Assistant**: Best for natural language testing
- **Note**: This server is **stdio-only** - no native HTTP transport available

### 3. Database-Specific Testing

#### SQL Server TDE Testing

```bash
# Test encryption using MCP tools through AI assistant:
# "Encrypt test_tde_db on prod_sql with key test-key-001"

# Manual verification via SQL:
sqlcmd -S your-server -Q "
SELECT 
    db.name AS database_name,
    dek.encryption_state,
    dek.percent_complete
FROM sys.databases db
LEFT JOIN sys.dm_database_encryption_keys dek ON db.database_id = dek.database_id
WHERE db.name = 'test_tde_db'
"
```

#### Oracle TDE Testing

```bash
# Test encryption using MCP tools through AI assistant:
# "Encrypt test_tde_pdb on oracle_cdb1 with key test-oracle-key"

# Manual verification via SQL:
sqlplus / as sysdba "
SELECT 
    wallet_type, 
    status 
FROM v$encryption_wallet;
"
```

## Test Scenarios

### Scenario 1: Basic Encryption

1. **Setup**: Clean test database
2. **Execute**: Encrypt database with a new key
3. **Verify**: 
   - Database is encrypted
   - Performance is acceptable
   - Data is accessible

### Scenario 2: Key Rotation

1. **Setup**: Encrypted database
2. **Execute**: Rotate encryption key
3. **Verify**:
   - New key is in use
   - Old key is properly retired
   - Data integrity maintained

### Scenario 3: Multi-Database Operations

1. **Setup**: Multiple test databases
2. **Execute**: Encrypt multiple databases
3. **Verify**:
   - All databases encrypted
   - Operations completed successfully
   - No resource conflicts

### Scenario 4: Error Handling

1. **Setup**: Invalid configurations
2. **Execute**: Attempt operations
3. **Verify**:
   - Proper error messages
   - Graceful failure handling
   - System stability maintained

## Performance Testing

### Database Performance Impact

```bash
# Manual performance testing approach:
# 1. Run database queries before encryption and record timing
# 2. Encrypt database using MCP tools
# 3. Run same queries after encryption and compare timing
# 4. Monitor database performance metrics

# Example SQL Server performance check:
sqlcmd -S your-server -Q "SELECT * FROM sys.dm_db_encryption_keys"

# Example Oracle performance check:
sqlplus sys/password@database "SELECT * FROM v\$encryption_wallet"
```

## Test Data Management

### Test Database Cleanup

```bash
# Manual cleanup approach:
# SQL Server
sqlcmd -S your-server -Q "DROP DATABASE test_tde_db"

# Oracle
sqlplus sys/password@database "DROP PLUGGABLE DATABASE test_tde_pdb INCLUDING DATAFILES"

```

## Troubleshooting Test Issues

### Common Test Failures

1. **Connection Failures**
   - Check database server status
   - Verify network connectivity
   - Validate credentials

2. **Permission Errors**
   - Ensure test user has required permissions
   - Check database-specific privilege requirements
   - Verify service account configuration

3. **Environment Issues**
   - Validate environment variables
   - Check Python version compatibility
   - Verify dependency installations

## Future: Implementing Automated Tests


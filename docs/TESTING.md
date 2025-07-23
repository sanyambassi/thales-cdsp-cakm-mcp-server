# Database TDE MCP Server - Testing Guide

## Starting the Server

```bash
# Start the server for manual testing
uv run python -m database_tde_server

# Test all database connections defined in config
uv run python -m database_tde_server --test-connections
```

## MCP Inspector Testing

```bash
# MCP Inspector UI testing (opens browser)
npx @modelcontextprotocol/inspector uv run python -m database_tde_server

# MCP Inspector CLI (handles protocol flow automatically)
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/list
```

## Correct MCP Protocol Flow

When testing with raw JSON-RPC, you must follow this exact sequence:

```json
// Step 1: Initialize the server with protocol information
{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "clientInfo": {"name": "test-client", "version": "1.0.0"}, "capabilities": {"tools": {}}}}

// Step 2: Send initialized notification (Server does not respond)
{"jsonrpc": "2.0", "method": "notifications/initialized"}

// Step 3: Now you can list available tools
{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}

// Step 4: Call a specific tool
{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "list_database_connections", "arguments": {}}}
```

## Testing SQL Server Tools

```bash
# NOTE: MCP Inspector CLI automatically handles the protocol initialization flow

# Test 'manage_sql_keys' to list keys
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name manage_sql_keys \
  --tool-args '{"operation": "list", "sql_connection": "prod_sql"}'

# Test 'status_tde_ekm' to assess a SQL database
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name status_tde_ekm \
  --tool-args '{"operation": "assess_sql", "connection_name": "prod_sql", "database_name": "Db01"}'
```

## Testing Oracle TDE Features

### General Oracle TDE Testing

```bash
# Test Oracle TDE comprehensive assessment
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name status_tde_ekm \
  --tool-args '{"operation": "assess_oracle", "connection_name": "oracle_cdb1"}'

# Test Oracle wallet status
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name manage_oracle_wallet \
  --tool-args '{"operation": "status", "oracle_connection": "oracle_cdb1", "container": "CDB$ROOT"}'

# Test Oracle container listing
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name status_tde_ekm \
  --tool-args '{"operation": "list_containers", "connection_name": "oracle_cdb1"}'

# Test Oracle encryption status per container
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name status_tde_ekm \
  --tool-args '{"operation": "list_tablespaces", "connection_name": "oracle_cdb1", "database_name": "CDB$ROOT", "encrypted_only": true}'

# Test Oracle MEK listing (filtered by database)
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name manage_oracle_keys \
  --tool-args '{"operation": "list", "oracle_connection": "oracle_cdb1", "container": "CDB$ROOT"}'

# Test Oracle TDE configuration parameters
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name manage_oracle_configuration \
  --tool-args '{"operation": "get", "oracle_connection": "oracle_cdb1"}'
```

### Test Oracle Tablespace Encryption

```bash
# Test Oracle tablespace encryption status
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name manage_oracle_tablespace_encryption \
  --tool-args '{"operation": "status", "oracle_connection": "oracle_cdb1", "tablespace_name": "PLAIN_TS", "container": "PDB1"}'

# Test Oracle tablespace encryption
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name manage_oracle_tablespace_encryption \
  --tool-args '{"operation": "encrypt", "oracle_connection": "oracle_cdb1", "tablespaces": "PLAIN_TS", "container": "PDB1"}'
```

### Test Oracle Wallet-Aware Key Rotation

```bash
# Test Oracle MEK rotation with auto-login/HSM wallet (no password required)
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name manage_oracle_keys \
  --tool-args '{"operation": "rotate", "oracle_connection": "oracle_cdb1", "container": "CDB$ROOT", "backup_tag": "auto_login_rotation_test"}'

# Test Oracle MEK rotation with password-protected wallet
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name manage_oracle_keys \
  --tool-args '{"operation": "rotate", "oracle_connection": "oracle_cdb1", "container": "CDB$ROOT", "wallet_password": "your_wallet_password", "backup_tag": "password_protected_rotation_test"}'
```

### Test Oracle TDE Deployment

```bash
# Test Oracle TDE HSM-only setup
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name manage_oracle_tde_deployment \
  --tool-args '{"operation": "setup_hsm_only", "oracle_connection": "oracle_cdb1", "ciphertrust_username": "admin", "ciphertrust_password": "password", "ciphertrust_domain": "root"}'

# Test Oracle TDE setup with HSM and auto-login
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name manage_oracle_tde_deployment \
  --tool-args '{"operation": "setup_hsm_with_autologin", "oracle_connection": "oracle_cdb1", "ciphertrust_username": "admin", "ciphertrust_password": "password", "software_wallet_password": "wallet_pass", "ciphertrust_domain": "root"}'

# Test adding auto-login to existing TDE
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name manage_oracle_tde_deployment \
  --tool-args '{"operation": "add_autologin", "oracle_connection": "oracle_cdb1", "ciphertrust_username": "admin", "ciphertrust_password": "password", "software_wallet_password": "wallet_pass", "ciphertrust_domain": "root"}'

# Test migration from software wallet to HSM
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name manage_oracle_tde_deployment \
  --tool-args '{"operation": "migrate_software_to_hsm", "oracle_connection": "oracle_cdb1", "ciphertrust_username": "admin", "ciphertrust_password": "password", "software_wallet_password": "wallet_pass", "ciphertrust_domain": "root"}'

# Test TDE status check
npx @modelcontextprotocol/inspector --cli \
  uv run python -m database_tde_server \
  --method tools/call \
  --tool-name manage_oracle_tde_deployment \
  --tool-args '{"operation": "get_tde_status", "oracle_connection": "oracle_cdb1"}'
```

## Testing with Raw JSON-RPC

To manually test the new enhancements with raw JSON-RPC, follow this sequence:

```json
// Step 1: Initialize the server
{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {"protocolVersion": "2024-11-05", "clientInfo": {"name": "test-client", "version": "1.0.0"}, "capabilities": {"tools": {}}}}

// Step 2: Send initialized notification
{"jsonrpc": "2.0", "method": "notifications/initialized"}

// Step 3: List available tools
{"jsonrpc": "2.0", "id": 2, "method": "tools/list", "params": {}}

// Step 4: Test wallet-aware key rotation on an auto-login wallet
{"jsonrpc": "2.0", "id": 3, "method": "tools/call", "params": {"name": "manage_oracle_keys", "arguments": {"operation": "rotate", "oracle_connection": "oracle_cdb1", "container": "CDB$ROOT", "backup_tag": "auto_login_test"}}}

// Step 5: Test database-filtered key listing 
{"jsonrpc": "2.0", "id": 4, "method": "tools/call", "params": {"name": "manage_oracle_keys", "arguments": {"operation": "list", "oracle_connection": "oracle_cdb1", "container": "CDB$ROOT"}}}
```

## Oracle TDE Scenarios Reference

These scenarios can be verified with the testing commands above:

1. **HSM-only TDE:**
   - V$ENCRYPTION_WALLET: HSM wallet OPEN (WALLET_ORDER='SINGLE')
   - TDE_CONFIGURATION: 'KEYSTORE_CONFIGURATION=HSM' 
   - Assessment: "HSM-only TDE (SINGLE wallet)", migration_status: "hsm_only"

2. **HSM with Auto-login (Forward Migrated):**
   - V$ENCRYPTION_WALLET: HSM wallet OPEN (WALLET_ORDER='PRIMARY'), AUTOLOGIN wallet OPEN (WALLET_ORDER='SECONDARY')
   - TDE_CONFIGURATION: 'KEYSTORE_CONFIGURATION=HSM|FILE'
   - Assessment: "HSM TDE with auto-login (forward migrated)", migration_status: "forward_migrated"

3. **HSM with Auto-login (Not Migrated):**
   - V$ENCRYPTION_WALLET: HSM wallet OPEN (WALLET_ORDER='PRIMARY'), AUTOLOGIN wallet OPEN_NO_MASTER_KEY (WALLET_ORDER='SECONDARY')
   - TDE_CONFIGURATION: 'KEYSTORE_CONFIGURATION=HSM|FILE'
   - Assessment: "HSM TDE with auto-login (not migrated)", migration_status: "hsm_with_autologin"

4. **FILE wallet TDE:**
   - V$ENCRYPTION_WALLET: PASSWORD wallet OPEN (WALLET_ORDER='SINGLE')
   - TDE_CONFIGURATION: 'KEYSTORE_CONFIGURATION=FILE'
   - Assessment: "FILE wallet TDE (password-based)", migration_status: "file_only"

5. **FILE with Auto-login (Reverse Migrated):**
   - V$ENCRYPTION_WALLET: PASSWORD wallet OPEN (WALLET_ORDER='PRIMARY'), AUTOLOGIN wallet OPEN (WALLET_ORDER='SECONDARY')
   - TDE_CONFIGURATION: 'KEYSTORE_CONFIGURATION=FILE|HSM'
   - Assessment: "FILE wallet TDE with auto-login (reverse migrated)", migration_status: "reverse_migrated"

6. **FILE with Auto-login (Standard):**
   - V$ENCRYPTION_WALLET: PASSWORD wallet OPEN (WALLET_ORDER='PRIMARY'), AUTOLOGIN wallet OPEN (WALLET_ORDER='SECONDARY')
   - TDE_CONFIGURATION: 'KEYSTORE_CONFIGURATION=FILE'
   - Assessment: "FILE wallet TDE (PRIMARY/SECONDARY config)", migration_status: "file_primary_secondary"

7. **Misconfiguration Detection:**
   - V$ENCRYPTION_WALLET: FILE wallet PRIMARY but TDE_CONFIGURATION='HSM|FILE'
   - Assessment: "Misconfigured: HSM|FILE config but non-HSM primary", migration_status: "misconfigured"

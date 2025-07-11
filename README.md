# Thales CIpherTrust Data Security Platform CAKM MCP Server

A Model Context Protocol (MCP) server for Database EKM/TDE operations using CipherTrust Application Key Management (CAKM).

## 🔑 Features

- **Database TDE Operations**: Encrypt, decrypt, and manage TDE on multiple database types
- **CipherTrust Integration**: Seamless integration with CipherTrust Manager via CAKM EKM
- **Multi-Database Support**: SQL Server and Oracle Database
- **Key Rotation**: Automated encryption key rotation with key management on Thales CipherTrust Manager

## 🚀 Quick Start

### Installation

```bash
# Install dependencies
uv venv && source .venv/bin/activate  # Linux/Mac
uv add "mcp[cli]" pydantic pydantic-settings pyodbc

# Configure
cp .env.example .env
# Edit .env with your database connections

# Test
uv run python -m database_tde_server --test-connections
```

### Usage

```bash
# Start the MCP server
uv run python -m database_tde_server
```

## 🔧 Available Tools

### Connection Management
- `list_database_connections()` - Show configured database connections with type and host info

### SQL Server Operations
- `encrypt_sql_databases()` - Encrypt one or more SQL Server databases with CAKM EKM provider
- `monitor_sql_databases()` - Monitor SQL Server databases (list, encryption status, encrypted only)
- `list_sql_cryptographic_providers()` - List all cryptographic providers on SQL Server
- `manage_sql_master_keys()` - Manage SQL Server master keys (list, create, drop RSA/AES keys)
- `manage_sql_credentials()` - Manage SQL Server credentials (list, update, drop, fix mappings)
- `manage_sql_logins()` - Manage SQL Server logins (list, drop, drop TDE logins)

### Oracle Operations
- `get_oracle_tde_configuration()` - Get current Oracle TDE configuration parameters
- `setup_oracle_tde_from_scratch()` - Complete Oracle TDE setup from scratch with auto-restart
- `migrate_tde()` - Migrate Oracle TDE from software wallet to HSM (CipherTrust Manager)
- `reverse_migrate_tde()` - Reverse migrate Oracle TDE from HSM back to software wallet
- `manage_oracle_wallet()` - Comprehensive Oracle wallet operations (open, close, status)
- `assess_oracle_tde_comprehensive()` - Comprehensive Oracle TDE assessment and readiness check

### Audit & Compliance
- `generate_tde_compliance_report()` - Generate comprehensive TDE compliance reports for auditors
- `generate_rotation_schedule()` - Generate key rotation schedules with cron jobs/commands

### Unified Tools (SQL Server + Oracle)
- **Encryption Tools**: Database encryption and decryption operations
- **Key Management**: Master key operations and lifecycle management  
- **Monitoring Tools**: Database status monitoring and encryption verification
- **Wallet Tools**: Oracle wallet management with auto-login capabilities

### Advanced Features
- **Auto-Restart**: Oracle database restart via SSH when needed for TDE changes
- **SSH Integration**: Seamless SSH connectivity for Oracle operations
- **Multi-Container**: Support for Oracle CDB and PDB operations
- **Key Rotation**: Automated rotation for both master keys and database encryption keys
- **Migration Support**: Complete wallet migration between software and HSM configurations

## 🤖 AI Assistant Integration

Add to your AI assistant configuration:

### Claude Desktop
```json
{
  "mcpServers": {
    "database-tde": {
      "command": "/path/to/.venv/bin/database-tde-mcp-server",
      "env": {
        "DB_TDE_SERVER_NAME": "database-tde-mcp",
        "DB_TDE_LOG_LEVEL": "INFO",
        "DB_TDE_DATABASE_CONNECTIONS": "[{\"name\":\"prod_sql\",\"db_type\":\"sqlserver\",\"host\":\"sql-prod.company.com\",\"port\":1433,\"username\":\"tde_admin\",\"password\":\"secure_password\"},{\"name\":\"oracle_cdb1\",\"db_type\":\"oracle\",\"host\":\"oracle-prod.company.com\",\"port\":1521,\"username\":\"sys\",\"password\":\"oracle_password\",\"oracle_config\":{\"oracle_home\":\"/u01/app/oracle/product/21.0.0/dbhome_1\",\"oracle_sid\":\"cdb1\",\"service_name\":\"orcl\",\"mode\":\"SYSDBA\",\"wallet_root\":\"/opt/oracle/wallet\"},\"ssh_config\":{\"host\":\"oracle-prod.company.com\",\"username\":\"oracle\",\"private_key_path\":\"/path/to/private-key.pem\",\"port\":22,\"timeout\":30}}]"
      }
    }
  }
}
```

### Cursor AI (mcp.json)
```json
{
  "mcpServers": {
    "database-tde": {
      "command": "/path/to/.venv/bin/database-tde-mcp-server",
      "env": {
        "DB_TDE_SERVER_NAME": "database-tde-mcp",
        "DB_TDE_LOG_LEVEL": "INFO",
        "DB_TDE_DATABASE_CONNECTIONS": "[{\"name\":\"prod_sql\",\"db_type\":\"sqlserver\",\"host\":\"sql-prod.company.com\",\"port\":1433,\"username\":\"tde_admin\",\"password\":\"secure_password\"},{\"name\":\"oracle_cdb1\",\"db_type\":\"oracle\",\"host\":\"oracle-prod.company.com\",\"port\":1521,\"username\":\"sys\",\"password\":\"oracle_password\",\"oracle_config\":{\"oracle_home\":\"/u01/app/oracle/product/21.0.0/dbhome_1\",\"oracle_sid\":\"cdb1\",\"service_name\":\"orcl\",\"mode\":\"SYSDBA\",\"wallet_root\":\"/opt/oracle/wallet\"},\"ssh_config\":{\"host\":\"oracle-prod.company.com\",\"username\":\"oracle\",\"private_key_path\":\"/path/to/private-key.pem\",\"port\":22,\"timeout\":30}}]"
      }
    }
  }
}
```

### Architecture Overview
```
MCP Server ↔ Database Server ↔ CAKM Provider/Library ↔ CipherTrust Manager
```

**Note**: This MCP server communicates only with database servers. The CAKM providers installed on database servers handle all communication with CipherTrust Manager.

### Example Prompts
```
"Encrypt CustomerDB on prod_sql with key prod-db-key using CipherTrustEKM provider"
"Encrypt all databases on oracle_cdb1 using shared-dev-key"
"Rotate database encryption key for OrdersDB on prod_sql"
"Encrypt database with automatic restart on oracle_cdb1"
```

### Important Notes
- **Automatic Database Restarts**: When specified in prompts, MCP tools can automatically restart Oracle databases as part of TDE operations
- **SSH Authentication**: Oracle connections support both private key and password authentication
  - Private key: Use `"private_key_path": "/path/to/key.pem"` in ssh_config
  - Password: Use `"password": "your_ssh_password"` in ssh_config (instead of private_key_path)
- **Supported Databases**: Microsoft SQL Server and Oracle Database are supported

## 📚 Documentation

- [Prerequisites](PREREQUISITES.md) - System requirements and setup
- [Testing Guide](TESTING.md) - Comprehensive testing procedures
- [Example Prompts](EXAMPLE_PROMPTS.md) - Ready-to-use testing prompts for SQL Server and Oracle

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Ensure all tests pass
6. Submit a pull request

## 📄 License

MIT License

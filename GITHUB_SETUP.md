# GitHub Setup Guide

## Step-by-Step Publishing Process

### 1. Prepare Your Local Repository

```bash
# Navigate to your project directory
cd /path/to/your/cakm-mcp-server

# Initialize git repository (if not already done)
git init

# Add all files except those in .gitignore
git add .

# Create initial commit
git commit -m "Initial commit: Database TDE MCP Server"
```

### 2. Clean Up Sensitive Files

**IMPORTANT:** Before publishing, ensure these files are removed or not tracked:

```bash
# Remove sensitive config files (they're already in .gitignore)
git rm --cached config/cursor_mcp_final.json
git rm --cached config/cursor_mcp_updated.json
git rm --cached config/cursor_mcp.json
git rm --cached config/claude_desktop_config.json
git rm --cached uv.lock

# Remove any .env files
git rm --cached .env

# Commit the cleanup
git commit -m "Remove sensitive configuration files"
```

### 3. Create GitHub Repository

1. **Go to GitHub.com** and sign in
2. **Click "New repository"** (green button)
3. **Fill in repository details:**
   - Repository name: `thales-cakm-mcp-server`
   - Description: `Database TDE MCP Server for CipherTrust CAKM Integration`
   - Set to **Public** (for open source)
   - **DON'T** initialize with README (you already have one)
4. **Click "Create repository"**

### 4. Connect Local Repository to GitHub

```bash
# Add the remote repository
git remote add origin https://github.com/YOUR_USERNAME/thales-cakm-mcp-server.git

# Push to GitHub
git branch -M main
git push -u origin main
```

### 5. Configure Repository Settings

1. **Go to your repository on GitHub**
2. **Click "Settings" tab**
3. **Configure these sections:**

#### General Settings
- Set repository visibility to "Public"
- Enable "Issues" and "Projects" for community contributions
- Enable "Wiki" for additional documentation

#### Security Settings
- Enable "Private vulnerability reporting"
- Set up "Dependabot alerts" for security updates

#### Pages (Optional)
- Enable GitHub Pages for documentation hosting
- Source: Deploy from a branch → main → /docs

### 6. Create GitHub Templates

Create these files in `.github/` directory:

```bash
mkdir -p .github/ISSUE_TEMPLATE
mkdir -p .github/workflows
```

**Issue Template** (`.github/ISSUE_TEMPLATE/bug_report.md`):
```markdown
---
name: Bug report
about: Create a report to help us improve
title: ''
labels: 'bug'
assignees: ''
---

**Describe the bug**
A clear and concise description of what the bug is.

**To Reproduce**
Steps to reproduce the behavior:
1. Go to '...'
2. Click on '....'
3. Scroll down to '....'
4. See error

**Expected behavior**
A clear and concise description of what you expected to happen.

**Environment:**
- OS: [e.g. Windows 10, Ubuntu 20.04]
- Python version: [e.g. 3.11.5]
- Database: [e.g. SQL Server 2019, Oracle 21c]

**Additional context**
Add any other context about the problem here.
```

### 7. Set up CI/CD (Optional)

Create `.github/workflows/ci.yml`:
```yaml
name: CI

on:
  push:
    branches: [ main ]
  pull_request:
    branches: [ main ]

jobs:
  test:
    runs-on: ubuntu-latest
    strategy:
      matrix:
        python-version: [3.11, 3.12]

    steps:
    - uses: actions/checkout@v3
    
    - name: Set up Python ${{ matrix.python-version }}
      uses: actions/setup-python@v3
      with:
        python-version: ${{ matrix.python-version }}
    
    - name: Install dependencies
      run: |
        python -m pip install --upgrade pip
        pip install uv
        uv sync --all-extras
    
    - name: Run tests
      run: |
        uv run pytest --cov=database_tde_server
    
    - name: Upload coverage reports to Codecov
      uses: codecov/codecov-action@v3
```

### 8. Create Release

1. **Create a new release:**
   - Go to your repository → Releases → "Create a new release"
   - Tag version: `v1.0.0`
   - Release title: `Database TDE MCP Server v1.0.0`
   - Describe the release features

2. **Create release notes:**
   ```markdown
   ## Features
   - Multi-database TDE support (SQL Server, Oracle)
   - CipherTrust CAKM integration
   - MCP server implementation
   - Automated key rotation
   
   ## Installation
   See [README.md](README.md) for installation instructions.
   
   ## Requirements
   See [PREREQUISITES.md](PREREQUISITES.md) for system requirements.
   ```

### 9. Update Project Metadata

Update `pyproject.toml`:
```toml
[project]
name = "thales-cakm-mcp-server"
version = "1.0.0"
description = "Database TDE MCP Server for CipherTrust CAKM Integration"
authors = [
    {name = "Your Organization", email = "your-email@company.com"},
]
license = {text = "MIT"}
homepage = "https://github.com/YOUR_USERNAME/thales-cakm-mcp-server"
repository = "https://github.com/YOUR_USERNAME/thales-cakm-mcp-server"
documentation = "https://github.com/YOUR_USERNAME/thales-cakm-mcp-server/wiki"
```

### 10. Add Badges to README

Add these badges to the top of your README.md:

```markdown
[![CI](https://github.com/YOUR_USERNAME/thales-cakm-mcp-server/workflows/CI/badge.svg)](https://github.com/YOUR_USERNAME/thales-cakm-mcp-server/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Code style: black](https://img.shields.io/badge/code%20style-black-000000.svg)](https://github.com/psf/black)
```

### 11. Final Steps

```bash
# Add all new files
git add .

# Commit changes
git commit -m "Add GitHub setup and CI/CD configuration"

# Push to GitHub
git push origin main
```

### 12. Community Setup

1. **Enable Discussions** (Repository Settings → General → Features)
2. **Create contributing guidelines** (CONTRIBUTING.md)
3. **Set up code of conduct** (GitHub can generate this)
4. **Create project boards** for issue tracking

## Post-Publication Checklist

- [ ] Repository is public and accessible
- [ ] All sensitive data removed
- [ ] CI/CD pipeline working
- [ ] Documentation complete
- [ ] License file present
- [ ] Contributing guidelines available
- [ ] Security policy defined
- [ ] Release created
- [ ] Package published to PyPI (optional)

## Marketing Your Open Source Project

1. **Share on social media**
2. **Submit to relevant directories**
3. **Announce on forums/communities**
4. **Create documentation website**
5. **Engage with the community**

## Maintenance

1. **Regular updates** and security patches
2. **Respond to issues** and pull requests
3. **Keep dependencies updated**
4. **Maintain documentation**
5. **Release new versions** regularly 
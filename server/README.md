# MCP Server with OAuth 2.1 Authentication

A Model Context Protocol (MCP) server implementation with OAuth 2.1/OIDC authentication support. Works with any OAuth provider including Asgardeo, Auth0, Keycloak, Okta, AWS Cognito, and more.

## Features

- ✅ **Optional Authentication**: Clients can connect with or without authentication
- ✅ **Scope-Based Tools**: Tools demonstrate scope checking (informational)
- ✅ **Generic OAuth Support**: Works with any OAuth 2.1 / OIDC provider
- ✅ **RS256 & HS256**: Supports both JWT signature algorithms
- ✅ **Streamable HTTP Transport**: Full MCP protocol support

## Prerequisites

- Python 3.11 or higher
- pip (Python package manager)

## Setup Instructions

### 1. Create Python Virtual Environment

```bash
# Navigate to the server directory
cd server

# Create a virtual environment
python3 -m venv .venv

# Activate the virtual environment
# On macOS/Linux:
source .venv/bin/activate

# On Windows:
# .venv\Scripts\activate
```

### 2. Install Dependencies

```bash
# Make sure virtual environment is activated (you should see (.venv) in your prompt)
pip install --upgrade pip
pip install -r requirements.txt
```

If you don't have a `requirements.txt` file, install these packages:

```bash
pip install fastmcp python-dotenv pyjwt[crypto] cryptography pydantic fastapi uvicorn starlette
```

### 3. Configure Environment Variables

Create a `.env` file in the server directory:

```bash
# Copy from example or create new
cp .env.example .env
```

Edit `.env` with your OAuth provider settings:

```env
# Authentication (set to false to disable auth completely)
ENABLE_AUTH=true

# OAuth Provider Settings
AUTH_ISSUER=https://your-auth-provider.com
CLIENT_ID=your-client-id
CLIENT_SECRET=your-client-secret-if-needed

# JWKS endpoint (for RS256 algorithm)
JWKS_URL=https://your-auth-provider.com/.well-known/jwks.json

# JWT Algorithm (RS256 or HS256)
JWT_ALGORITHM=RS256

# Server Settings
MCP_SERVER_URL=http://localhost:8000

# Optional: OAuth Scopes (space-separated)
REQUIRED_SCOPES=openid email profile

# Optional: Validation Settings
VALIDATE_AUDIENCE=true
VALIDATE_ISSUER=true

# SSL Verification (set to false for self-signed certificates in development)
SSL_VERIFY=true
```

### 4. Run the Server

```bash
# Make sure virtual environment is activated
python mcp_server.py
```

The server will start on `http://localhost:8000`

You should see output like:
```
============================================================
MCP Server Configuration
============================================================
Authentication: ENABLED
Server URL: http://localhost:8000
Auth Issuer: https://your-auth-provider.com
Client ID: your_client_id
Algorithm: RS256
Required Scopes: ['openid', 'email', 'profile']
============================================================
🚀 Starting MCP Server with OAuth 2.1 authentication
   Transport: streamable-http
   Port: 8000
```

## Available Tools

1. **`get_server_info()`**
   - Returns information about the MCP server
   - Shows your authentication status
   - Works for everyone

2. **`calculate(expression)`**
   - Performs mathematical calculations
   - Example: `calculate("2 + 2")` → `{"result": "4"}`
   - Works for everyone

3. **`get_email()`**
   - Requires `email` scope in access token
   - Returns user's email address and verification status
   - Returns informational message if not authenticated

4. **`get_name()`**
   - Requires `profile` scope in access token
   - Returns user's name information (name, given_name, family_name, etc.)
   - Returns informational message if not authenticated


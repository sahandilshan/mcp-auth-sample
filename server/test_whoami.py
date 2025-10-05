"""
Test script to verify whoami tool works with x-mcp-token header
"""
import requests
import json
import os
from dotenv import load_dotenv

load_dotenv()

# Get a test token (you'll need to provide this)
# For testing, we'll create a mock token or use an actual one
TEST_TOKEN = os.getenv("TEST_TOKEN", "")

if not TEST_TOKEN:
    print("⚠️  No TEST_TOKEN found in .env file")
    print("Please add a valid access token to test:")
    print("TEST_TOKEN=your_access_token_here")
    exit(1)

# MCP Server endpoint
MCP_SERVER = "http://localhost:8000"

# Test 1: Call whoami tool with x-mcp-token header
print("=" * 60)
print("Testing whoami tool with x-mcp-token header")
print("=" * 60)

headers = {
    "x-mcp-token": TEST_TOKEN,
    "Content-Type": "application/json"
}

# MCP tool call format
payload = {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {
        "name": "whoami",
        "arguments": {}
    }
}

try:
    response = requests.post(
        f"{MCP_SERVER}/mcp/v1/messages",
        headers=headers,
        json=payload
    )

    print(f"\nStatus Code: {response.status_code}")
    print(f"Response Headers: {dict(response.headers)}")
    print(f"\nResponse Body:")
    print(json.dumps(response.json(), indent=2))

except Exception as e:
    print(f"❌ Error: {e}")

print("\n" + "=" * 60)


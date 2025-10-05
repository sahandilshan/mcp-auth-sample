"""
Simple test to check if context.access_token is available in tools
"""
from mcp.server.fastmcp import FastMCP
import inspect

# Check FastMCP's Context class
from mcp.server.fastmcp import Context

print("Context class attributes:")
print([attr for attr in dir(Context) if not attr.startswith('_')])

# Check the signature
print("\nContext init signature:")
print(inspect.signature(Context.__init__))


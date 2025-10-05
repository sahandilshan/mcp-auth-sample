"""
Check RequestContext structure to find where access_token is stored
"""
from mcp.server.fastmcp import Context
import inspect

# Check if we can inspect RequestContext
try:
    # Get the type hint for request_context
    import typing
    annotations = Context.__annotations__
    print("Context annotations:")
    for key, value in annotations.items():
        print(f"  {key}: {value}")
    
    # Try to access RequestContext
    from mcp.server import RequestContext
    print("\nRequestContext attributes:")
    print([attr for attr in dir(RequestContext) if not attr.startswith('_')])
except Exception as e:
    print(f"Error: {e}")


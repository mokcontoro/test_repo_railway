"""
MCP Server with Supabase Authentication using FastMCP
For use with Claude.ai client
"""

import os
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth.providers.supabase import SupabaseProvider
from starlette.routing import Route
from starlette.responses import JSONResponse

load_dotenv()

# Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
PORT = int(os.getenv("PORT", "8000"))
HOST = os.getenv("HOST", "0.0.0.0")

# Railway provides this automatically
RAILWAY_DOMAIN = os.getenv("RAILWAY_PUBLIC_DOMAIN", f"localhost:{PORT}")
BASE_URL = f"https://{RAILWAY_DOMAIN}" if "localhost" not in RAILWAY_DOMAIN else f"http://{RAILWAY_DOMAIN}"

# Initialize Supabase auth provider
auth = SupabaseProvider(
    project_url=SUPABASE_URL,
    base_url=BASE_URL
)

# Create MCP server with Supabase authentication
mcp = FastMCP("Claude MCP Server", auth=auth)


# Health check endpoint for Railway
@mcp.custom_route("/health", methods=["GET"])
async def health(request):
    return JSONResponse({"status": "healthy", "service": "mcp-server"})


@mcp.tool()
def hello(name: str) -> str:
    """Say hello to someone"""
    return f"Hello, {name}! Welcome to the MCP server."


@mcp.tool()
def get_time() -> str:
    """Get the current server time"""
    from datetime import datetime
    return datetime.now().isoformat()


@mcp.tool()
def calculate(expression: str) -> str:
    """Evaluate a mathematical expression safely"""
    allowed_chars = set("0123456789+-*/(). ")
    if not all(c in allowed_chars for c in expression):
        return "Error: Invalid characters in expression"
    try:
        result = eval(expression, {"__builtins__": {}}, {})
        return str(result)
    except Exception as e:
        return f"Error: {str(e)}"


@mcp.resource("info://server")
def get_server_info() -> str:
    """Get server information"""
    import json
    return json.dumps({
        "name": "Claude MCP Server",
        "version": "1.0.0",
        "auth_provider": "Supabase"
    })


if __name__ == "__main__":
    print(f"Starting MCP Server at {BASE_URL}")
    print(f"Using Supabase project: {SUPABASE_URL}")
    mcp.run(transport="http", host=HOST, port=PORT)

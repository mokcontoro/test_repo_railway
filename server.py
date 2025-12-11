"""
MCP Server with Supabase Authentication using FastMCP
For use with Claude.ai client

Implements proper OAuth discovery at root level for Claude.ai compatibility.
"""

import os
import httpx
import uvicorn
from dotenv import load_dotenv
from fastmcp import FastMCP
from fastmcp.server.auth.providers.supabase import SupabaseProvider
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.responses import JSONResponse, HTMLResponse, RedirectResponse
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware

load_dotenv()

# Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
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


# MCP Tools
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


# Custom endpoints
async def health(request):
    """Health check endpoint for Railway"""
    return JSONResponse({"status": "healthy", "service": "mcp-server"})


async def oauth_consent(request):
    """
    OAuth consent endpoint for Supabase OAuth Server.
    Supabase redirects here with authorization_id, we show consent screen,
    then approve/deny and redirect back.
    """
    authorization_id = request.query_params.get("authorization_id")

    if not authorization_id:
        return HTMLResponse(
            "<h1>Error</h1><p>Missing authorization_id</p>",
            status_code=400
        )

    # For POST requests (form submission), handle approval/denial
    if request.method == "POST":
        form = await request.form()
        action = form.get("action")
        auth_id = form.get("authorization_id")

        if action == "approve":
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{SUPABASE_URL}/auth/v1/oauth/authorize",
                    headers={
                        "apikey": SUPABASE_ANON_KEY,
                        "Content-Type": "application/json"
                    },
                    json={
                        "authorization_id": auth_id,
                        "consent": "approve"
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    redirect_to = data.get("redirect_to")
                    if redirect_to:
                        return RedirectResponse(redirect_to, status_code=302)

                return HTMLResponse(
                    f"<h1>Error</h1><p>Failed to approve: {response.text}</p>",
                    status_code=500
                )

        elif action == "deny":
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{SUPABASE_URL}/auth/v1/oauth/authorize",
                    headers={
                        "apikey": SUPABASE_ANON_KEY,
                        "Content-Type": "application/json"
                    },
                    json={
                        "authorization_id": auth_id,
                        "consent": "deny"
                    }
                )

                if response.status_code == 200:
                    data = response.json()
                    redirect_to = data.get("redirect_to")
                    if redirect_to:
                        return RedirectResponse(redirect_to, status_code=302)

                return HTMLResponse(
                    "<h1>Access Denied</h1><p>You denied the authorization request.</p>"
                )

    # GET request - show consent form
    async with httpx.AsyncClient() as client:
        response = await client.get(
            f"{SUPABASE_URL}/auth/v1/oauth/authorize",
            headers={"apikey": SUPABASE_ANON_KEY},
            params={"authorization_id": authorization_id}
        )

        if response.status_code != 200:
            return HTMLResponse(
                f"<h1>Error</h1><p>Failed to fetch authorization details: {response.text}</p>",
                status_code=400
            )

        auth_details = response.json()

    client_name = auth_details.get("client", {}).get("name", "Unknown Application")
    scopes = auth_details.get("scopes", [])

    consent_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>Authorize Access - MCP Server</title>
        <style>
            body {{
                font-family: system-ui, -apple-system, sans-serif;
                max-width: 500px;
                margin: 80px auto;
                padding: 20px;
                background: #f5f5f5;
            }}
            .card {{
                background: white;
                border-radius: 12px;
                padding: 32px;
                box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            }}
            h1 {{ margin-top: 0; color: #333; }}
            .app-name {{ font-weight: 600; color: #5046e5; }}
            .scopes {{
                background: #f8f8f8;
                border-radius: 8px;
                padding: 16px;
                margin: 16px 0;
            }}
            .scopes li {{ margin: 8px 0; }}
            .buttons {{ display: flex; gap: 12px; margin-top: 24px; }}
            button {{
                flex: 1;
                padding: 12px 24px;
                border: none;
                border-radius: 8px;
                font-size: 16px;
                cursor: pointer;
            }}
            .approve {{ background: #5046e5; color: white; }}
            .deny {{ background: #e5e5e5; color: #333; }}
        </style>
    </head>
    <body>
        <div class="card">
            <h1>Authorize Access</h1>
            <p><span class="app-name">{client_name}</span> wants to access your MCP Server.</p>
            <div class="scopes">
                <strong>This application will be able to:</strong>
                <ul>
                    {"".join(f"<li>{scope}</li>" for scope in scopes) if scopes else "<li>Access MCP tools and resources</li>"}
                </ul>
            </div>
            <form method="POST">
                <input type="hidden" name="authorization_id" value="{authorization_id}">
                <div class="buttons">
                    <button type="submit" name="action" value="deny" class="deny">Deny</button>
                    <button type="submit" name="action" value="approve" class="approve">Approve</button>
                </div>
            </form>
        </div>
    </body>
    </html>
    """

    return HTMLResponse(consent_html)


# OAuth protected resource metadata at ROOT level (RFC 9728)
async def oauth_protected_resource(request):
    """Protected Resource Metadata pointing to Supabase as auth server"""
    return JSONResponse({
        "resource": BASE_URL,
        "authorization_servers": [f"{SUPABASE_URL}/auth/v1"],
        "scopes_supported": [],
        "bearer_methods_supported": ["header"],
    })


# Build the application
# Get MCP HTTP app at /mcp path
mcp_app = mcp.http_app(path="/mcp")

# Root level routes
routes = [
    Route("/health", health, methods=["GET"]),
    Route("/oauth/consent", oauth_consent, methods=["GET", "POST"]),
    # RFC 9728 - Protected Resource Metadata at ROOT level
    Route("/.well-known/oauth-protected-resource", oauth_protected_resource, methods=["GET"]),
    # Mount the MCP app
    Mount("/", app=mcp_app),
]

middleware = [
    Middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
]

app = Starlette(routes=routes, middleware=middleware)


if __name__ == "__main__":
    print(f"Starting MCP Server at {BASE_URL}")
    print(f"Using Supabase project: {SUPABASE_URL}")
    print(f"MCP endpoint: {BASE_URL}/mcp")
    print(f"OAuth discovery: {BASE_URL}/.well-known/oauth-protected-resource")
    uvicorn.run(app, host=HOST, port=PORT)

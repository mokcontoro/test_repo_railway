"""
MCP Server with OAuth 2.1 Authentication using Supabase
For use with Claude.ai client
"""

import os
import secrets
import hashlib
import base64
import time
import json
from typing import Optional
from urllib.parse import urlencode, parse_qs

from dotenv import load_dotenv
from starlette.applications import Starlette
from starlette.routing import Route, Mount
from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, HTMLResponse
from starlette.middleware import Middleware
from starlette.middleware.cors import CORSMiddleware
import uvicorn
from supabase import create_client, Client
import jwt

from mcp.server.fastmcp import FastMCP
from mcp.server.sse import SseServerTransport
from sse_starlette.sse import EventSourceResponse
import anyio

load_dotenv()

# Configuration
SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_ANON_KEY = os.getenv("SUPABASE_ANON_KEY")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")
OAUTH_CLIENT_ID = os.getenv("OAUTH_CLIENT_ID", "claude-mcp-client")
OAUTH_CLIENT_SECRET = os.getenv("OAUTH_CLIENT_SECRET")
HOST = os.getenv("HOST", "0.0.0.0")
PORT = int(os.getenv("PORT", "8000"))

# Railway provides this automatically
RAILWAY_DOMAIN = os.getenv("RAILWAY_PUBLIC_DOMAIN", f"localhost:{PORT}")
BASE_URL = f"https://{RAILWAY_DOMAIN}" if "localhost" not in RAILWAY_DOMAIN else f"http://{RAILWAY_DOMAIN}"

# Initialize Supabase client
supabase: Client = create_client(SUPABASE_URL, SUPABASE_ANON_KEY)

# In-memory stores (use Redis/database in production)
authorization_codes: dict = {}
access_tokens: dict = {}
refresh_tokens: dict = {}
pkce_challenges: dict = {}
registered_clients: dict = {}  # For dynamic client registration


# OAuth 2.1 Helper Functions
def generate_code() -> str:
    return secrets.token_urlsafe(32)


def generate_token() -> str:
    return secrets.token_urlsafe(64)


def hash_code_verifier(verifier: str) -> str:
    """SHA256 hash for PKCE code challenge verification"""
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def verify_pkce(code_verifier: str, code_challenge: str, method: str = "S256") -> bool:
    """Verify PKCE code challenge - OAuth 2.1 requires S256"""
    if method != "S256":
        return False  # OAuth 2.1 requires S256 only
    return hash_code_verifier(code_verifier) == code_challenge


# OAuth 2.1 Endpoints

async def oauth_protected_resource_metadata(request: Request) -> JSONResponse:
    """Protected Resource Metadata (RFC 9728) - Required for Claude.ai"""
    return JSONResponse({
        "resource": BASE_URL,
        "authorization_servers": [BASE_URL],
        "scopes_supported": ["mcp:read", "mcp:write", "mcp:admin"],
        "bearer_methods_supported": ["header"],
    })


async def oauth_metadata(request: Request) -> JSONResponse:
    """OAuth 2.1 Authorization Server Metadata (RFC 8414)"""
    return JSONResponse({
        "issuer": BASE_URL,
        "authorization_endpoint": f"{BASE_URL}/oauth/authorize",
        "token_endpoint": f"{BASE_URL}/oauth/token",
        "token_endpoint_auth_methods_supported": ["client_secret_post", "none"],
        "registration_endpoint": f"{BASE_URL}/oauth/register",  # Dynamic Client Registration
        "revocation_endpoint": f"{BASE_URL}/oauth/revoke",
        "response_types_supported": ["code"],
        "grant_types_supported": ["authorization_code", "refresh_token"],
        "code_challenge_methods_supported": ["S256"],  # OAuth 2.1 requires S256
        "scopes_supported": ["mcp:read", "mcp:write", "mcp:admin"],
    })


async def register_client(request: Request) -> JSONResponse:
    """Dynamic Client Registration (RFC 7591) - Required for Claude.ai"""
    try:
        body = await request.json()
    except:
        return JSONResponse(
            {"error": "invalid_request", "error_description": "Invalid JSON body"},
            status_code=400
        )

    # Generate client credentials
    client_id = f"client_{secrets.token_urlsafe(16)}"
    client_secret = secrets.token_urlsafe(32)
    issued_at = int(time.time())

    # Store client registration
    registered_clients[client_id] = {
        "client_id": client_id,
        "client_secret": client_secret,
        "client_name": body.get("client_name", "Unknown Client"),
        "redirect_uris": body.get("redirect_uris", []),
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "response_types": body.get("response_types", ["code"]),
        "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "client_secret_post"),
        "issued_at": issued_at,
    }

    return JSONResponse({
        "client_id": client_id,
        "client_secret": client_secret,
        "client_id_issued_at": issued_at,
        "client_secret_expires_at": 0,  # Never expires
        "client_name": body.get("client_name", "Unknown Client"),
        "redirect_uris": body.get("redirect_uris", []),
        "grant_types": body.get("grant_types", ["authorization_code"]),
        "response_types": body.get("response_types", ["code"]),
        "token_endpoint_auth_method": body.get("token_endpoint_auth_method", "client_secret_post"),
    }, status_code=201)


async def authorize(request: Request) -> HTMLResponse | RedirectResponse:
    """OAuth 2.1 Authorization Endpoint with PKCE (required)"""
    params = dict(request.query_params)

    client_id = params.get("client_id")
    redirect_uri = params.get("redirect_uri")
    response_type = params.get("response_type")
    state = params.get("state")
    scope = params.get("scope", "mcp:read")
    code_challenge = params.get("code_challenge")
    code_challenge_method = params.get("code_challenge_method")

    # OAuth 2.1 requires PKCE
    if not code_challenge or code_challenge_method != "S256":
        return JSONResponse(
            {"error": "invalid_request", "error_description": "PKCE with S256 is required"},
            status_code=400
        )

    if response_type != "code":
        return JSONResponse(
            {"error": "unsupported_response_type"},
            status_code=400
        )

    # Store PKCE challenge
    session_id = generate_code()
    pkce_challenges[session_id] = {
        "code_challenge": code_challenge,
        "code_challenge_method": code_challenge_method,
        "client_id": client_id,
        "redirect_uri": redirect_uri,
        "scope": scope,
        "state": state,
    }

    # Return login page that redirects to Supabase Auth
    login_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>MCP Server - Login</title>
        <style>
            body {{ font-family: system-ui, sans-serif; max-width: 400px; margin: 100px auto; padding: 20px; }}
            .btn {{ background: #5046e5; color: white; padding: 12px 24px; border: none; border-radius: 6px; cursor: pointer; width: 100%; font-size: 16px; }}
            .btn:hover {{ background: #4338ca; }}
            h1 {{ text-align: center; }}
        </style>
    </head>
    <body>
        <h1>MCP Server Login</h1>
        <p>Sign in to authorize access to the MCP server.</p>
        <form action="{BASE_URL}/oauth/login" method="post">
            <input type="hidden" name="session_id" value="{session_id}">
            <input type="email" name="email" placeholder="Email" required style="width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box;">
            <input type="password" name="password" placeholder="Password" required style="width: 100%; padding: 10px; margin: 10px 0; box-sizing: border-box;">
            <button type="submit" class="btn">Sign In</button>
        </form>
        <p style="text-align: center; margin-top: 20px; color: #666;">
            Powered by Supabase Auth
        </p>
    </body>
    </html>
    """
    return HTMLResponse(login_html)


async def login(request: Request) -> RedirectResponse | JSONResponse:
    """Handle login form submission"""
    form = await request.form()
    session_id = form.get("session_id")
    email = form.get("email")
    password = form.get("password")

    if session_id not in pkce_challenges:
        return JSONResponse({"error": "invalid_session"}, status_code=400)

    session_data = pkce_challenges[session_id]

    try:
        # Authenticate with Supabase
        auth_response = supabase.auth.sign_in_with_password({
            "email": email,
            "password": password
        })

        user = auth_response.user

        # Generate authorization code
        auth_code = generate_code()
        authorization_codes[auth_code] = {
            "user_id": user.id,
            "email": user.email,
            "client_id": session_data["client_id"],
            "redirect_uri": session_data["redirect_uri"],
            "scope": session_data["scope"],
            "code_challenge": session_data["code_challenge"],
            "code_challenge_method": session_data["code_challenge_method"],
            "expires_at": time.time() + 600,  # 10 minute expiry
            "used": False,
        }

        # Clean up PKCE session
        del pkce_challenges[session_id]

        # Redirect back to client with auth code
        redirect_params = {"code": auth_code}
        if session_data["state"]:
            redirect_params["state"] = session_data["state"]

        redirect_url = f"{session_data['redirect_uri']}?{urlencode(redirect_params)}"
        return RedirectResponse(redirect_url, status_code=302)

    except Exception as e:
        return HTMLResponse(f"""
        <!DOCTYPE html>
        <html>
        <head><title>Login Failed</title></head>
        <body style="font-family: system-ui; max-width: 400px; margin: 100px auto; padding: 20px;">
            <h1>Login Failed</h1>
            <p>Invalid email or password. Please try again.</p>
            <a href="{BASE_URL}/oauth/authorize?{urlencode({
                'client_id': session_data['client_id'],
                'redirect_uri': session_data['redirect_uri'],
                'response_type': 'code',
                'scope': session_data['scope'],
                'state': session_data['state'] or '',
                'code_challenge': session_data['code_challenge'],
                'code_challenge_method': session_data['code_challenge_method'],
            })}">Try Again</a>
        </body>
        </html>
        """)


async def token(request: Request) -> JSONResponse:
    """OAuth 2.1 Token Endpoint"""
    form = await request.form()
    grant_type = form.get("grant_type")

    if grant_type == "authorization_code":
        code = form.get("code")
        redirect_uri = form.get("redirect_uri")
        client_id = form.get("client_id")
        code_verifier = form.get("code_verifier")

        if code not in authorization_codes:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Invalid authorization code"},
                status_code=400
            )

        auth_data = authorization_codes[code]

        # Check if code was already used (OAuth 2.1 requirement)
        if auth_data["used"]:
            # Revoke all tokens issued with this code
            del authorization_codes[code]
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Authorization code already used"},
                status_code=400
            )

        # Check expiration
        if time.time() > auth_data["expires_at"]:
            del authorization_codes[code]
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Authorization code expired"},
                status_code=400
            )

        # Verify PKCE
        if not verify_pkce(code_verifier, auth_data["code_challenge"], auth_data["code_challenge_method"]):
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Invalid code_verifier"},
                status_code=400
            )

        # Verify redirect_uri matches
        if redirect_uri != auth_data["redirect_uri"]:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "redirect_uri mismatch"},
                status_code=400
            )

        # Mark code as used
        auth_data["used"] = True

        # Generate tokens
        access_token = generate_token()
        refresh_token_value = generate_token()

        token_data = {
            "user_id": auth_data["user_id"],
            "email": auth_data["email"],
            "scope": auth_data["scope"],
            "client_id": client_id,
            "expires_at": time.time() + 3600,  # 1 hour
        }

        access_tokens[access_token] = token_data
        refresh_tokens[refresh_token_value] = {
            "user_id": auth_data["user_id"],
            "email": auth_data["email"],
            "scope": auth_data["scope"],
            "client_id": client_id,
            "expires_at": time.time() + 86400 * 30,  # 30 days
        }

        return JSONResponse({
            "access_token": access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": refresh_token_value,
            "scope": auth_data["scope"],
        })

    elif grant_type == "refresh_token":
        refresh_token_value = form.get("refresh_token")

        if refresh_token_value not in refresh_tokens:
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Invalid refresh token"},
                status_code=400
            )

        refresh_data = refresh_tokens[refresh_token_value]

        if time.time() > refresh_data["expires_at"]:
            del refresh_tokens[refresh_token_value]
            return JSONResponse(
                {"error": "invalid_grant", "error_description": "Refresh token expired"},
                status_code=400
            )

        # Rotate refresh token (OAuth 2.1 recommendation)
        del refresh_tokens[refresh_token_value]

        new_access_token = generate_token()
        new_refresh_token = generate_token()

        access_tokens[new_access_token] = {
            "user_id": refresh_data["user_id"],
            "email": refresh_data["email"],
            "scope": refresh_data["scope"],
            "client_id": refresh_data["client_id"],
            "expires_at": time.time() + 3600,
        }

        refresh_tokens[new_refresh_token] = {
            "user_id": refresh_data["user_id"],
            "email": refresh_data["email"],
            "scope": refresh_data["scope"],
            "client_id": refresh_data["client_id"],
            "expires_at": time.time() + 86400 * 30,
        }

        return JSONResponse({
            "access_token": new_access_token,
            "token_type": "Bearer",
            "expires_in": 3600,
            "refresh_token": new_refresh_token,
            "scope": refresh_data["scope"],
        })

    return JSONResponse(
        {"error": "unsupported_grant_type"},
        status_code=400
    )


async def revoke(request: Request) -> JSONResponse:
    """OAuth 2.1 Token Revocation Endpoint (RFC 7009)"""
    form = await request.form()
    token_value = form.get("token")
    token_type_hint = form.get("token_type_hint")

    # Try to revoke as access token
    if token_value in access_tokens:
        del access_tokens[token_value]

    # Try to revoke as refresh token
    if token_value in refresh_tokens:
        del refresh_tokens[token_value]

    # Always return 200 per RFC 7009
    return JSONResponse({})


def validate_token(token: str) -> Optional[dict]:
    """Validate access token and return user data"""
    if token not in access_tokens:
        return None

    token_data = access_tokens[token]

    if time.time() > token_data["expires_at"]:
        del access_tokens[token]
        return None

    return token_data


# MCP Server Setup
mcp = FastMCP("Claude MCP Server")

# SSE Transport for MCP
sse_transport = SseServerTransport("/message")


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
    return json.dumps({
        "name": "Claude MCP Server",
        "version": "1.0.0",
        "oauth": "2.1",
        "auth_provider": "Supabase"
    })


# Helper for 401 responses with proper WWW-Authenticate header (RFC 9728)
def unauthorized_response(error_description: str) -> JSONResponse:
    """Return 401 with WWW-Authenticate header pointing to resource metadata"""
    return JSONResponse(
        {"error": "unauthorized", "error_description": error_description},
        status_code=401,
        headers={
            "WWW-Authenticate": f'Bearer resource_metadata="{BASE_URL}/.well-known/oauth-protected-resource"'
        }
    )


# HTTP Endpoints for MCP-over-HTTP with auth
async def mcp_sse(request: Request):
    """MCP SSE endpoint with OAuth authentication"""
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return unauthorized_response("Missing or invalid Authorization header")

    token_value = auth_header[7:]  # Remove "Bearer " prefix
    token_data = validate_token(token_value)

    if not token_data:
        return unauthorized_response("Invalid or expired token")

    # Connect SSE transport and run MCP server
    async with sse_transport.connect_sse(
        request.scope, request.receive, request._send
    ) as streams:
        await mcp._mcp_server.run(
            streams[0], streams[1], mcp._mcp_server.create_initialization_options()
        )


async def mcp_message(request: Request):
    """MCP message endpoint with OAuth authentication"""
    auth_header = request.headers.get("Authorization", "")

    if not auth_header.startswith("Bearer "):
        return unauthorized_response("Missing or invalid Authorization header")

    token_value = auth_header[7:]
    token_data = validate_token(token_value)

    if not token_data:
        return unauthorized_response("Invalid or expired token")

    # Handle POST message
    await sse_transport.handle_post_message(request.scope, request.receive, request._send)


async def health(request: Request) -> JSONResponse:
    """Health check endpoint"""
    return JSONResponse({"status": "healthy", "service": "mcp-server"})


# Application Setup
routes = [
    Route("/health", health),
    # OAuth discovery endpoints (RFC 8414, RFC 9728)
    Route("/.well-known/oauth-authorization-server", oauth_metadata),
    Route("/.well-known/oauth-protected-resource", oauth_protected_resource_metadata),
    # OAuth endpoints
    Route("/oauth/authorize", authorize),
    Route("/oauth/login", login, methods=["POST"]),
    Route("/oauth/token", token, methods=["POST"]),
    Route("/oauth/register", register_client, methods=["POST"]),  # Dynamic Client Registration
    Route("/oauth/revoke", revoke, methods=["POST"]),
    # MCP endpoints at root level for Claude.ai compatibility
    Route("/sse", mcp_sse),
    Route("/message", mcp_message, methods=["POST"]),
    # Also keep /mcp/* paths for compatibility
    Route("/mcp/sse", mcp_sse),
    Route("/mcp/message", mcp_message, methods=["POST"]),
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
    print(f"OAuth Authorization: {BASE_URL}/oauth/authorize")
    print(f"OAuth Token: {BASE_URL}/oauth/token")
    print(f"MCP SSE: {BASE_URL}/mcp/sse")
    uvicorn.run(app, host=HOST, port=PORT)

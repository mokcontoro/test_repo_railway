# MCP Server with OAuth 2.1 + Supabase

A Python MCP (Model Context Protocol) server with OAuth 2.1 authentication using Supabase, deployable to Railway.

## Features

- **OAuth 2.1 Compliant** - PKCE required (S256), refresh token rotation
- **Supabase Auth** - User authentication via Supabase
- **MCP Tools** - Example tools: hello, get_time, calculate
- **Railway Ready** - One-click deployment

## Quick Start

### 1. Set up Supabase

1. Create a project at [supabase.com](https://supabase.com)
2. Go to Project Settings > API
3. Copy your **Project URL** and **anon public** key
4. Create a test user in Authentication > Users

### 2. Configure Environment

```bash
cp .env.example .env
```

Edit `.env`:
```env
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_ANON_KEY=your-anon-key
OAUTH_CLIENT_ID=claude-mcp-client
OAUTH_CLIENT_SECRET=your-secret-here
```

### 3. Run Locally

```bash
# Create virtual environment
python -m venv venv

# Activate (Windows)
venv\Scripts\activate

# Activate (Unix/Mac)
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Run server
python server.py
```

Server runs at `http://localhost:8000`

### 4. Deploy to Railway

1. Push to GitHub:
```bash
git add .
git commit -m "Initial commit"
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPO.git
git push -u origin main
```

2. Go to [railway.app](https://railway.app)
3. New Project > Deploy from GitHub repo
4. Add environment variables in Settings > Variables:
   - `SUPABASE_URL`
   - `SUPABASE_ANON_KEY`
   - `OAUTH_CLIENT_ID`
   - `OAUTH_CLIENT_SECRET`

Railway auto-provides `RAILWAY_PUBLIC_DOMAIN`.

## OAuth 2.1 Flow

### Authorization URL
```
GET /oauth/authorize
  ?client_id=claude-mcp-client
  &redirect_uri=https://your-callback
  &response_type=code
  &scope=mcp:read
  &code_challenge=BASE64URL(SHA256(code_verifier))
  &code_challenge_method=S256
  &state=random-state
```

### Token Exchange
```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code
&code=AUTH_CODE
&redirect_uri=https://your-callback
&client_id=claude-mcp-client
&code_verifier=ORIGINAL_VERIFIER
```

### Refresh Token
```
POST /oauth/token
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&refresh_token=REFRESH_TOKEN
&client_id=claude-mcp-client
```

## API Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Health check |
| `GET /.well-known/oauth-authorization-server` | OAuth metadata |
| `GET /oauth/authorize` | Authorization endpoint |
| `POST /oauth/token` | Token endpoint |
| `POST /oauth/revoke` | Token revocation |
| `GET /mcp/sse` | MCP SSE endpoint (requires auth) |
| `POST /mcp/message` | MCP message endpoint (requires auth) |

## MCP Tools

- **hello(name)** - Returns a greeting
- **get_time()** - Returns current server time
- **calculate(expression)** - Evaluates math expressions

## Using with Claude.ai

Configure Claude.ai to use your MCP server:

1. Get your deployed URL from Railway
2. In Claude.ai MCP settings, add:
   - Server URL: `https://your-app.railway.app/mcp/sse`
   - Auth type: OAuth 2.1
   - Authorization URL: `https://your-app.railway.app/oauth/authorize`
   - Token URL: `https://your-app.railway.app/oauth/token`

## License

MIT

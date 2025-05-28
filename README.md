# mcp-front

Simple OAuth 2.1 + GCP IAM authentication for multiple MCP servers on GCP. Makes MCP deployment effortless.

```
Claude.ai
    │
    │ HTTPS
    ▼
┌─────────────────────────────┐
│             GCP             │
│                             │
│       Cloud Armor           │
│            │                │
│            ▼                │
│      Load Balancer          │
│            │                │
│            ▼                │
│        mcp-front            │
│    (OAuth + Routing)        │
│            │                │
│            ▼                │
│     ┌─────────────┐         │
│     │ mcp-notion  │         │
│     └─────────────┘         │
│     ┌─────────────┐         │
│     │mcp-postgres │         │
│     └─────────────┘         │
│     ┌─────────────┐         │
│     │  mcp-git    │         │
│     └─────────────┘         │
│                             │
└─────────────────────────────┘
```

## How it works

mcp-front sits between Claude.ai and your MCP servers, handling OAuth 2.1 authentication with PKCE and GCP IAM domain validation. Claude.ai connects to multiple MCP servers through a single authenticated endpoint.

When Claude.ai first connects, users authenticate via Google OAuth. mcp-front validates their domain against your allowed list and issues tokens for accessing MCP servers. Subsequent requests use bearer tokens, eliminating repeated authentication.

## Configuration

Create `config.json` based on `config-oauth.json`:

```json
{
  "mcpProxy": {
    "baseURL": "https://mcp.yourcompany.com", 
    "addr": ":8080",
    "name": "Company MCP Front",
    "version": "1.0.0"
  },
  "oauth": {
    "issuer": "https://mcp.yourcompany.com",
    "gcp_project": "your-gcp-project",
    "allowed_domains": ["yourcompany.com"],
    "token_ttl": "1h",
    "google_client_id": "${GOOGLE_CLIENT_ID}",
    "google_client_secret": "${GOOGLE_CLIENT_SECRET}", 
    "google_redirect_uri": "https://mcp.yourcompany.com/oauth/callback"
  },
  "mcpServers": {
    "notion": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "mcp/notion:latest"],
      "env": {"NOTION_TOKEN": "${NOTION_TOKEN}"}
    },
    "postgres": {
      "command": "docker", 
      "args": ["run", "--rm", "-i", "mcp/postgres:latest"],
      "env": {"DATABASE_URL": "${DATABASE_URL}"}
    },
    "external": {
      "url": "https://api.example.com/mcp",
      "headers": {"Authorization": "Bearer ${API_TOKEN}"}
    }
  }
}
```

## Environment setup

Set these environment variables:

```bash
export GOOGLE_CLIENT_ID="your-oauth-client-id"
export GOOGLE_CLIENT_SECRET="your-oauth-client-secret"
export NOTION_TOKEN="your-notion-token"
export DATABASE_URL="postgresql://..."
```

## Google OAuth setup

1. Go to [Google Cloud Console](https://console.cloud.google.com/) → APIs & Services → Credentials
2. Create OAuth 2.0 Client ID (Web application)
3. Add authorized redirect URI: `https://mcp.yourcompany.com/oauth/callback`
4. Note the Client ID and Secret for your environment variables

## Running

Local development:
```bash
git clone https://github.com/dgellow/mcp-front.git
cd mcp-front
go build .
./mcp-front -config config.json
```

Docker:
```bash
docker-compose up -d
```

## Claude.ai integration

Add these MCP server URLs to Claude.ai:
```
https://mcp.yourcompany.com/notion/sse
https://mcp.yourcompany.com/postgres/sse
https://mcp.yourcompany.com/external/sse
```

Claude.ai will discover the OAuth endpoints automatically and prompt for authentication on first use.

## GCP deployment

Build and deploy to Google Cloud Run or Compute Engine:

```bash
# Build image
docker build -t gcr.io/${PROJECT_ID}/mcp-front .
docker push gcr.io/${PROJECT_ID}/mcp-front

# Deploy to Cloud Run
gcloud run deploy mcp-front \
  --image gcr.io/${PROJECT_ID}/mcp-front \
  --platform managed \
  --allow-unauthenticated \
  --port 8080
```

For production, use a load balancer with HTTPS termination and mount Docker socket for stdio-based MCP servers.

## OAuth endpoints

- `/.well-known/oauth-authorization-server` - Server metadata discovery
- `/authorize` - Authorization code flow with PKCE
- `/token` - Token exchange and refresh
- `/oauth/callback` - Google OAuth callback
- `/register` - Dynamic client registration

## Security

All authorization flows require PKCE. Users must belong to Google Workspace domains in the `allowed_domains` list. Tokens are scoped to MCP endpoints and expire based on `token_ttl` configuration.
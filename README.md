# mcp-front

Simple OAuth 2.1 + GCP IAM authentication for multiple MCP servers on GCP. Built to make MCP deployment effortless.

## Features

- **OAuth 2.1 Authorization Server** with PKCE support
- **GCP IAM Integration** for domain-based user validation
- **Multiple MCP Server Support** via stdio and HTTP transports  
- **Docker Integration** for containerized MCP servers
- **SSE Streaming** compatible with Claude.ai
- **Dynamic Client Registration** (RFC 7591)
- **Path-based Routing** (`/notion/*` → notion-mcp-server)

## Quick Start

1. **Clone and build:**
   ```bash
   git clone https://github.com/dgellow/mcp-front.git
   cd mcp-front
   go build .
   ```

2. **Configure OAuth:**
   ```bash
   cp .env.example .env
   # Edit .env with your Google OAuth credentials
   ```

3. **Set up Google OAuth:**
   - Go to [Google Cloud Console](https://console.cloud.google.com/)
   - Create OAuth 2.0 client ID
   - Add redirect URI: `https://your-domain.com/oauth/callback`

4. **Run with Docker:**
   ```bash
   docker-compose up -d
   ```

## Configuration

### OAuth Settings

```json
{
  "oauth": {
    "issuer": "https://mcp-internal.yourcompany.org",
    "gcp_project": "your-gcp-project-id", 
    "allowed_domains": ["yourcompany.com"],
    "token_ttl": "3600s",
    "storage": "memory",
    "google_client_id": "${GOOGLE_CLIENT_ID}",
    "google_client_secret": "${GOOGLE_CLIENT_SECRET}",
    "google_redirect_uri": "https://mcp-internal.yourcompany.org/oauth/callback"
  }
}
```

### MCP Server Configuration

**Stdio-based (Docker containers):**
```json
{
  "notion": {
    "command": "docker",
    "args": ["run", "--rm", "-i", "mcp/notion:latest"],
    "env": {
      "NOTION_TOKEN": "${NOTION_TOKEN}"
    }
  }
}
```

**HTTP-based (External servers):**
```json
{
  "external-api": {
    "url": "https://external-mcp-server.example.com/sse",
    "headers": {
      "Authorization": "Bearer ${EXTERNAL_API_TOKEN}"
    }
  }
}
```

## OAuth 2.1 Endpoints

- `/.well-known/oauth-authorization-server` - Server metadata
- `/authorize` - Authorization endpoint (with PKCE)
- `/token` - Token endpoint  
- `/register` - Dynamic client registration
- `/oauth/callback` - Google OAuth callback

## Claude.ai Integration

1. **Add MCP servers to Claude.ai:**
   ```
   https://mcp-internal.yourcompany.org/notion/sse
   https://mcp-internal.yourcompany.org/postgres/sse
   https://mcp-internal.yourcompany.org/git/sse
   ```

2. **Authentication flow:**
   - Claude.ai discovers OAuth server metadata
   - Initiates OAuth 2.1 with PKCE
   - User redirected to Google sign-in
   - Domain validated against allowed list
   - Token issued for all MCP endpoints

## Deployment

### GCE Deployment

```bash
# Build and push
docker build -t gcr.io/${PROJECT_ID}/mcp-front:latest .
docker push gcr.io/${PROJECT_ID}/mcp-front:latest

# Deploy instance template
gcloud compute instance-templates create mcp-proxy-template \\
    --machine-type=e2-standard-2 \\
    --image-family=cos-stable \\
    --image-project=cos-cloud \\
    --container-image=gcr.io/${PROJECT_ID}/mcp-front:latest \\
    --tags=mcp-proxy

# Create managed instance group
gcloud compute instance-groups managed create mcp-proxy-group \\
    --template=mcp-proxy-template \\
    --size=2 \\
    --zone=us-central1-a
```

### Load Balancer Setup

```bash
# Create health check
gcloud compute health-checks create http mcp-proxy-health \\
    --port=8080 \\
    --request-path="/.well-known/oauth-authorization-server"

# Create backend service
gcloud compute backend-services create mcp-proxy-backend \\
    --protocol=HTTP \\
    --health-checks=mcp-proxy-health \\
    --global

# Add instance group to backend
gcloud compute backend-services add-backend mcp-proxy-backend \\
    --instance-group=mcp-proxy-group \\
    --instance-group-zone=us-central1-a \\
    --global
```

## Security

- **PKCE Required**: All authorization code flows must use PKCE
- **Domain Validation**: Users must belong to configured Google Workspace domains
- **TLS Required**: All production deployments should use HTTPS
- **Token Scoping**: Tokens are scoped to specific MCP endpoints

## Environment Variables

| Variable | Description | Required |
|----------|-------------|----------|
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | Yes |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | Yes |
| `GCP_PROJECT_ID` | GCP project for IAM validation | Yes |
| `NOTION_TOKEN` | Notion integration token | Optional |
| `DATABASE_URL` | PostgreSQL connection string | Optional |

## Troubleshooting

### Common Issues

1. **OAuth callback mismatch:**
   - Ensure redirect URI in Google Console matches `google_redirect_uri` in config

2. **Domain validation failing:**
   - Check that users belong to Google Workspace with configured domain
   - Verify `allowed_domains` configuration

3. **Docker permission denied:**
   - Ensure proxy has access to Docker socket: `/var/run/docker.sock`

### Debugging

Enable debug logging:
```json
{
  "mcpServers": {
    "server-name": {
      "options": {
        "logEnabled": true
      }
    }
  }
}
```

## Architecture

```
Claude.ai → HTTPS → Load Balancer → MCP Auth Proxy
                                    ├── OAuth 2.1 Server
                                    ├── /notion/* → Docker Container
                                    ├── /postgres/* → Docker Container  
                                    └── /external/* → HTTP MCP Server
```


# mcp-front: OAuth 2.1 Authenticated MCP Proxy

## Objective

A secure proxy server that provides OAuth 2.1 authentication for multiple MCP (Model Context Protocol) servers, enabling Claude.ai to access company resources through authenticated connections.

## Core Features

- **OAuth 2.1 Authorization Server**: Complete implementation with PKCE support
- **Dynamic Client Registration**: RFC 7591 compliant for Claude.ai integration
- **Path-based MCP Routing**: Multiple MCP servers behind authenticated endpoints
- **SSE Transport**: Server-Sent Events for real-time Claude.ai communication
- **Docker Container Support**: Execute MCP servers in isolated containers
- **Google OAuth Integration**: Enterprise domain validation
- **Health Monitoring**: Built-in health check endpoint

## Architecture

```
Claude.ai → OAuth Discovery → Client Registration → Authentication Flow
    │                                                      │
    └── Authenticated Requests ──────────────────────────────┘
                    │
                    ▼
            mcp-front (OAuth + Proxy)
                    │
        ┌───────────┼───────────┐
        ▼           ▼           ▼
   /notion/sse  /postgres/sse  /git/sse
        │           │           │
        ▼           ▼           ▼
   notion-mcp   postgres-mcp   git-mcp
   (Docker)     (Docker)       (Docker)
```

## Configuration

The server uses JSON configuration with OAuth and MCP server definitions:

```json
{
  "mcpProxy": {
    "baseURL": "https://mcp.yourcompany.com",
    "addr": ":8080",
    "name": "Company MCP Front"
  },
  "oauth": {
    "issuer": "https://mcp.yourcompany.com",
    "gcp_project": "your-gcp-project",
    "allowed_domains": ["yourcompany.com"],
    "token_ttl": "1h",
    "storage": "memory",
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
    }
  }
}
```

## OAuth Implementation

### OAuth 2.1 Endpoints

- `/.well-known/oauth-authorization-server` - Server metadata discovery
- `/authorize` - Authorization code flow with PKCE
- `/token` - Token exchange and refresh
- `/oauth/callback` - Google OAuth callback handler
- `/register` - Dynamic client registration (RFC 7591)

### Authentication Flow

1. **Claude.ai Discovery**: Discovers OAuth endpoints via metadata
2. **Client Registration**: Dynamically registers with required scopes
3. **Authorization**: User redirected to Google OAuth with PKCE
4. **Domain Validation**: Verifies user belongs to allowed domains
5. **Token Issuance**: Returns OAuth tokens for MCP access
6. **MCP Access**: All MCP requests authenticated with bearer tokens

## Implementation Details

### Package Structure

```
mcp-front/
├── main.go              # Application entry point
├── config.go            # Configuration management
├── validation.go        # Config validation
├── http.go              # HTTP server and routing
├── client.go            # MCP client management
├── oauth/               # OAuth 2.1 implementation
│   ├── oauth.go         # Server and handlers
│   ├── storage.go       # Thread-safe client storage
│   ├── auth.go          # Google OAuth integration
│   ├── session.go       # Session management
│   └── oauth_test.go    # OAuth tests
├── integration/         # Integration tests
└── README.md
```

### Security Features

- **PKCE Required**: All authorization flows use PKCE
- **Domain Validation**: Google Workspace domain membership required
- **Token Scoping**: Tokens scoped to specific MCP endpoints
- **CORS Support**: Proper CORS headers for Claude.ai
- **Health Checks**: Built-in monitoring endpoint at `/health`
- **Environment Secrets**: JWT secrets from environment variables

### MCP Transport

The server bridges between Claude.ai's SSE transport and MCP servers:

- **SSE → stdio**: HTTP Server-Sent Events to Docker container stdin/stdout
- **JSON-RPC**: Maintains MCP protocol compatibility
- **Process Management**: Graceful container lifecycle management
- **Error Handling**: Proper error propagation through SSE

## Deployment

### Local Development

```bash
# Set environment variables
export GOOGLE_CLIENT_ID="your-oauth-client-id"
export GOOGLE_CLIENT_SECRET="your-oauth-client-secret"
export JWT_SECRET="your-jwt-secret-32-bytes-long"

# Build and run
go build -o mcp-front .
./mcp-front -config config.json
```

### Docker Deployment

```bash
# Build container
docker build -t mcp-front .

# Run with OAuth
docker run -p 8080:8080 \
  -e GOOGLE_CLIENT_ID="$GOOGLE_CLIENT_ID" \
  -e GOOGLE_CLIENT_SECRET="$GOOGLE_CLIENT_SECRET" \
  -e JWT_SECRET="$JWT_SECRET" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  mcp-front
```

### Google Cloud Platform

```bash
# Deploy to Cloud Run
gcloud run deploy mcp-front \
  --image gcr.io/${PROJECT_ID}/mcp-front \
  --platform managed \
  --allow-unauthenticated \
  --port 8080 \
  --set-env-vars="JWT_SECRET=${JWT_SECRET}"
```

## Claude.ai Integration

Add MCP server URLs to Claude.ai:

```
https://mcp.yourcompany.com/notion/sse
https://mcp.yourcompany.com/postgres/sse
https://mcp.yourcompany.com/git/sse
```

Claude.ai will automatically:
1. Discover OAuth endpoints
2. Register as a client
3. Initiate user authentication
4. Use tokens for subsequent MCP requests

## Testing

### Unit Tests

```bash
# Run all tests
go test ./...

# Run OAuth tests specifically  
go test ./oauth -v
```

### Integration Tests

```bash
# Complete integration test suite
cd integration && ./run_tests.sh
```

The integration tests validate:
- End-to-end MCP communication
- OAuth 2.1 flow compatibility with Claude.ai
- Security scenarios and bypass protection
- CORS headers and client registration
- Health check functionality

## Important Development Rules

- **NEVER delete files as the first step when making changes.** First implement the new solution, verify it works, THEN clean up old files if needed.
- **ALWAYS understand the existing code structure and context before making changes.** Read the implementation and tests thoroughly.
- **When adding tests, integrate them into the existing test framework** rather than creating separate test files and runners.
- **Think like an experienced engineer:** understand the use cases, read the docs, plan properly, then execute.
- **Security First**: Never commit secrets or use hardcoded credentials
- **Claude.ai Compatibility**: Maintain scope format and CORS requirements
# mcp-front: OAuth 2.1 Authenticated MCP Proxy

## Objective

A secure proxy server that provides OAuth 2.1 authentication for multiple MCP (Model Context Protocol) servers, enabling Claude.ai to access company resources through authenticated connections.

## Core Features

- **OAuth 2.1 Authorization Server**: Complete implementation with PKCE support using fosite
- **Dynamic Client Registration**: RFC 7591 compliant for Claude.ai and MCP Inspector integration
- **Public Client Support**: Handles clients without secrets for testing and development
- **Environment-Based Configuration**: Development vs production security modes
- **Flexible Storage**: Memory (development) and Firestore (production) storage backends
- **Structured Logging**: Production-ready logging using Go's standard slog package
- **Path-based MCP Routing**: Multiple MCP servers behind authenticated endpoints
- **SSE Transport**: Server-Sent Events for real-time Claude.ai communication
- **Docker Container Support**: Execute MCP servers in isolated containers
- **Google OAuth Integration**: Enterprise domain validation with Workspace integration
- **Comprehensive Testing**: OAuth integration test suite with security validation
- **Health Monitoring**: Built-in health check endpoint

## Architecture

```
Claude.ai/MCP Inspector → OAuth Discovery → Dynamic Client Registration → PKCE Auth Flow
    │                                                                           │
    └── Authenticated Requests (Bearer Tokens) ──────────────────────────────────┘
                              │
                              ▼
                    mcp-front (OAuth + Proxy)
                    │ Structured Logging │
                    │ JWT Validation     │
                    │ Domain Validation  │
                    │                    │
            ┌───────┼───────────┼────────┐
            ▼       ▼           ▼        ▼
       /notion/sse /postgres/sse /git/sse /health
            │       │           │        │
            ▼       ▼           ▼        ▼
       notion-mcp postgres-mcp git-mcp Health Check
       (Docker)   (Docker)    (Docker)  (Status)
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
    "storage": "firestore",
    "firestore_collection": "custom_oauth_clients",  // Optional, defaults to "mcp_front_oauth_clients"
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
├── http.go              # HTTP server with structured logging and routing
├── client.go            # MCP client management
├── internal/            # Internal packages
│   └── logging.go       # Centralized structured logging with slog
├── oauth/               # OAuth 2.1 implementation
│   ├── oauth.go         # OAuth server with fosite and environment-based config
│   ├── storage.go       # Thread-safe client storage with public client support
│   ├── auth.go          # Google OAuth integration with domain validation
│   ├── session.go       # Session management
│   └── oauth_test.go    # OAuth unit tests
├── integration/         # Comprehensive integration test suite
│   ├── integration_test.go     # Main MCP integration tests
│   ├── oauth_test.go           # OAuth flow integration tests
│   ├── security_test.go        # Security scenario validation
│   ├── helpers.go              # Test utilities
│   └── config/                 # Test configurations
│       ├── config.oauth-test.json
│       ├── docker-compose.test.yml
│       └── schema.sql/
└── README.md
```

### Security Features

- **PKCE Required**: All authorization flows use PKCE (Proof Key for Code Exchange)
- **JWT Secret Validation**: Enforces 32-byte minimum length for HMAC-SHA512/256 signing
- **State Parameter Entropy**: Configurable per environment (strict in production, relaxed in development)
- **Domain Validation**: Google Workspace domain membership required with allowed_domains list
- **Public Client Support**: Secure handling of clients without secrets (MCP Inspector compatibility)
- **Token Scoping**: Tokens scoped to specific MCP endpoints with TTL configuration
- **Environment-Based Security**: Different security policies for development vs production
- **Thread-Safe Storage**: Mutex-protected client storage preventing race conditions
- **CORS Support**: Proper CORS headers for browser-based OAuth clients
- **Health Checks**: Built-in monitoring endpoint at `/health`
- **Environment Secrets**: All sensitive configuration from environment variables
- **Security Testing**: Comprehensive test suite validating bypass protection

⚠️ **Security Boundary**: mcp-front provides OAuth authentication and proxying but does **NOT** validate or sanitize data sent to individual MCP servers. SQL injection, command injection, and other application-layer attacks are the responsibility of each MCP server implementation. Deploy only trusted MCP servers and ensure they follow secure coding practices.

### Storage Architecture

OAuth client data is stored using a pluggable storage architecture:

#### Memory Storage (Default)
- **Use Case**: Development and testing
- **Characteristics**: Fast, no external dependencies, data lost on restart
- **Thread Safety**: Mutex-protected concurrent access
- **Configuration**: `"storage": "memory"` (default)

#### Firestore Storage (Production)
- **Use Case**: Production deployments requiring persistence
- **Architecture**: Hybrid design with Firestore persistence + in-memory cache
- **Performance**: Sub-millisecond access via memory cache, Firestore for durability
- **Authentication**: Automatic via GCP service accounts or Application Default Credentials
- **Scalability**: Handles thousands of OAuth clients with minimal cost
- **Configuration**: `"storage": "firestore"` + `"gcp_project": "your-project"`
- **Collection**: Stores client entities in `mcp_front_oauth_clients` collection by default (configurable via `firestoreCollection` in config)
- **Startup**: Automatically loads existing clients into memory cache

### MCP Transport

The server bridges between Claude.ai's SSE transport and MCP servers:

- **SSE → stdio**: HTTP Server-Sent Events to Docker container stdin/stdout
- **JSON-RPC**: Maintains MCP protocol compatibility
- **Process Management**: Graceful container lifecycle management
- **Error Handling**: Proper error propagation through SSE

## Deployment

### Local Development

```bash
# Set required environment variables
export GOOGLE_CLIENT_ID="your-oauth-client-id"
export GOOGLE_CLIENT_SECRET="your-oauth-client-secret"
export JWT_SECRET="your-32-byte-jwt-secret-for-oauth!"  # Must be exactly 32 bytes

# Optional: Configure development mode and logging
export MCP_FRONT_ENV="development"  # Enables relaxed OAuth validation
export LOG_LEVEL="debug"            # debug, info, warn, error
export LOG_FORMAT="text"            # json (production) or text (development)

# Build and run
go build -o mcp-front ./cmd/mcp-front
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

# Run specific OAuth integration tests
go test -v -run TestOAuthFlowIntegration

# Run specific security tests
go test -v -run TestSecurity
```

The integration tests validate:
- **OAuth 2.1 Flows**: JWT secret validation, dynamic client registration, PKCE flows
- **Security Testing**: Authentication bypass protection, state parameter handling
- **Environment Configuration**: Development vs production mode differences
- **Client Compatibility**: Claude.ai and MCP Inspector OAuth flows
- **MCP Communication**: End-to-end stdio and SSE transport
- **Domain Validation**: Google Workspace integration and allowed domains
- **Error Handling**: Proper error responses and logging
- **CORS Headers**: Browser compatibility for OAuth flows
- **Health Monitoring**: `/health` endpoint validation
- **Database Integration**: Test database setup and cleanup

## Environment Variables

### Required
- `GOOGLE_CLIENT_ID`: Google OAuth client ID from Cloud Console
- `GOOGLE_CLIENT_SECRET`: Google OAuth client secret
- `JWT_SECRET`: 32-byte minimum secret for JWT signing (HMAC-SHA512/256)

### Optional
- `MCP_FRONT_ENV`: Set to "development" for relaxed OAuth validation
- `LOG_LEVEL`: Logging level (debug, info, warn, error) - default: info
- `LOG_FORMAT`: Log format (json, text) - default: json in production, text in development

## OAuth Client Types

### Public Clients (MCP Inspector)
- No client secret required
- Registered dynamically via `/register` endpoint
- Uses PKCE for security
- Suitable for testing and development tools

### Confidential Clients (Claude.ai)
- Client secret provided during registration
- Enhanced security for production integrations
- Full OAuth 2.1 compliance with all grants

## Development vs Production

### Development Mode (`MCP_FRONT_ENV=development`)
- Relaxed state parameter entropy (MinParameterEntropy: 0)
- Generates state parameters for buggy clients
- Text-based logging by default
- Enhanced debug logging

### Production Mode (default)
- Strict state parameter entropy (MinParameterEntropy: 8)
- JSON structured logging
- Enhanced security validation
- Domain restrictions enforced

## Important Development Rules

- **NEVER delete files as the first step when making changes.** First implement the new solution, verify it works, THEN clean up old files if needed.
- **ALWAYS understand the existing code structure and context before making changes.** Read the implementation and tests thoroughly.
- **When adding tests, integrate them into the existing test framework** rather than creating separate test files and runners.
- **Think like an experienced engineer:** understand the use cases, read the docs, plan properly, then execute.
- **Security First**: Never commit secrets or use hardcoded credentials
- **Testing First**: All OAuth changes must include integration tests
- **Environment Awareness**: Respect development vs production configuration differences
- **Claude.ai Compatibility**: Maintain scope format and CORS requirements
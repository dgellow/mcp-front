# mcp-front

> **This project is a work in progress and should not be considered production ready.**
> Though I'm fairly confident the overall architecture is sound, and I myself rely on the implementation — so it _should work :tm:_.
> But it's definitely alpha software :)
>
> Also, don't rely too much on the docs, they drift fairly quickly, I do not always keep them updated when doing changes or adding/removing features. They are mostly here to anchor me and help me stay focus on my initial vision.

OAuth 2.1 proxy for MCP (Model Context Protocol) servers. Authenticate once with Google, access all your MCP tools in Claude.

<div align="center">

![mcp-front Architecture](docs/architecture.svg)

</div>

## What is mcp-front?

mcp-front is an authentication proxy that sits between Claude.ai and your MCP servers. It provides:

- **Single sign-on** via Google OAuth for all MCP tools
- **Domain validation** to restrict access to your organization
- **Token management** for secure MCP server access
- **Session isolation** so multiple users can share infrastructure

## Why use mcp-front?

Without mcp-front, each MCP server needs its own authentication. With mcp-front:

- Users authenticate once with their Google account
- Access is restricted to your company domain
- MCP servers can run in secure environments (databases, internal APIs)
- Sessions are isolated between users

## How it works

1. Claude.ai connects to `https://your-domain.com/<service>/sse`
2. mcp-front validates the user's OAuth token
3. If valid, it proxies requests to the configured MCP server
4. For stdio servers, each user gets an isolated process

## Quick start

1. Create `config.json`:

```json
{
  "proxy": {
    "baseURL": "https://mcp.yourcompany.com",
    "auth": {
      "kind": "oauth",
      "allowedDomains": ["yourcompany.com"],
      "googleClientId": {"$env": "GOOGLE_CLIENT_ID"},
      "googleClientSecret": {"$env": "GOOGLE_CLIENT_SECRET"},
      "googleRedirectUri": "https://mcp.yourcompany.com/oauth/callback",
      "jwtSecret": {"$env": "JWT_SECRET"},
      "encryptionKey": {"$env": "ENCRYPTION_KEY"}
    }
  },
  "mcpServers": {
    "postgres": {
      "command": "docker",
      "args": ["run", "--rm", "-i", "mcp/postgres:latest"],
      "env": { "DATABASE_URL": "${DATABASE_URL}" }
    }
  }
}
```

2. Set environment variables:

```bash
export GOOGLE_CLIENT_ID="your-oauth-client-id"
export GOOGLE_CLIENT_SECRET="your-oauth-client-secret"
export JWT_SECRET="your-32-byte-jwt-secret-for-oauth!"
export ENCRYPTION_KEY="your-32-byte-encryption-key-here!"
```

3. Run mcp-front:

```bash
docker run -d -p 8080:8080 \
  -e GOOGLE_CLIENT_ID -e GOOGLE_CLIENT_SECRET \
  -e JWT_SECRET -e ENCRYPTION_KEY \
  -v $(pwd)/config.json:/app/config.json \
  dgellow/mcp-front:latest
```

4. Add to Claude.ai: `https://mcp.yourcompany.com/postgres/sse`

## Endpoints

### MCP endpoints
- `/<service>/sse` - Server-sent events for MCP communication
- `/<service>/message` - Message handling for MCP requests

### User endpoints  
- `/my/tokens` - Browser-based token management
- `/my/clients` - OAuth client management

### OAuth endpoints
- `/.well-known/oauth-authorization-server` - OAuth discovery
- `/authorize` - OAuth authorization 
- `/token` - Token exchange
- `/oauth/callback` - Google OAuth callback
- `/register` - Dynamic client registration

## Configuration

### Google OAuth setup

1. Create OAuth client in [Google Cloud Console](https://console.cloud.google.com/)
2. Set redirect URI: `https://your-domain.com/oauth/callback`
3. Save Client ID and Secret

### Full configuration example

See [config-oauth.json](config-oauth.json) for a complete example with multiple MCP servers.

## Security

- OAuth 2.1 with PKCE required for all flows
- Google Workspace domain validation
- Encrypted session cookies (AES-256-GCM) 
- Per-user session isolation for stdio servers

⚠️ **Note**: mcp-front handles authentication only. Each MCP server is responsible for its own input validation and security.

## Storage options

- **Memory** (default): Fast, data lost on restart
- **Firestore**: Persistent storage for production

See [config-oauth.json](config-oauth.json) for Firestore configuration.

## Development

```bash
# Run tests
cd integration && go test -v

# Development mode (relaxed OAuth validation)
export MCP_FRONT_ENV=development
```

## License

Copyright 2025 Samuel "dgellow" El-Borai

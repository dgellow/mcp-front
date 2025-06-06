---
title: Bearer Token Authentication
description: Configure simple bearer token authentication for development
---

import { Aside, Code } from '@astrojs/starlight/components';

Bearer token authentication provides a simple way to secure MCP Front during development or for internal use cases.

## Configuration

```json
{
  "proxy": {
    "auth": {
      "kind": "bearer_token",
      "tokens": {
        "development": "dev-token-123",
        "production": "prod-token-456",
        "staging": "stage-token-789"
      }
    }
  }
}
```

## Configuration Fields

| Field | Description | Required |
|-------|-------------|----------|
| `kind` | Must be `"bearer_token"` | Yes |
| `tokens` | Map of token names to token values | Yes |

## Token Management

### Defining Tokens

Tokens are defined as key-value pairs where:
- **Key**: A descriptive name for the token (e.g., "development", "production")
- **Value**: The actual token string

```json
{
  "tokens": {
    "alice": "token-for-alice",
    "bob": "token-for-bob",
    "ci": "token-for-ci-system"
  }
}
```

<Aside type="tip">
  Use descriptive names for tokens to make access logs more meaningful.
</Aside>

### Using Environment Variables

Store tokens in environment variables for security:

```json
{
  "tokens": {
    "development": "$env:DEV_TOKEN",
    "production": "$env:PROD_TOKEN|default-token"
  }
}
```

The syntax `$env:VARIABLE|default` provides a fallback value.

## Server Authorization

### Associating Tokens with Servers

Use the `authTokens` field to specify which tokens can access each MCP server:

```json
{
  "mcpServers": {
    "database": {
      "url": "http://postgres-mcp:3000/sse",
      "authTokens": ["production", "development"]
    },
    "sensitive-data": {
      "url": "http://sensitive-mcp:3000/sse",
      "authTokens": ["production"]
    },
    "public-data": {
      "url": "http://public-mcp:3000/sse"
      // No authTokens = accessible by any valid token
    }
  }
}
```

### Authorization Rules

1. **With `authTokens`**: Only listed tokens can access the server
2. **Without `authTokens`**: Any valid token can access the server
3. **Invalid token**: Returns 401 Unauthorized

## Client Configuration

### Using Bearer Tokens in Claude.ai

When adding MCP Front as a server in Claude.ai:

1. **Server URL**: `https://your-domain.com/sse`
2. **Authentication**: Bearer Token
3. **Token**: Your assigned token (e.g., `dev-token-123`)

### Using Bearer Tokens with curl

```bash
# Basic request
curl -H "Authorization: Bearer dev-token-123" \
     -H "Accept: text/event-stream" \
     https://your-domain.com/sse

# Server-specific endpoint
curl -H "Authorization: Bearer prod-token-456" \
     -H "Accept: text/event-stream" \
     https://your-domain.com/database/sse
```

## Security Best Practices

### 1. Generate Strong Tokens

Use cryptographically secure random tokens:

```bash
# Generate a secure token
openssl rand -base64 32
# Output: 7K9X2L5p8M3n6Q1w4R7t0Y5u8I2o5P8a1S4d7F0g3H6j=
```

### 2. Rotate Tokens Regularly

Implement a token rotation schedule:

```json
{
  "tokens": {
    "api-2024-01": "old-token",     // Remove after migration
    "api-2024-02": "current-token",  // Active token
    "api-2024-03": "new-token"       // Pre-staged for next rotation
  }
}
```

### 3. Use HTTPS Only

<Aside type="danger">
  Never use bearer tokens over HTTP in production. Tokens are sent in plain text and can be intercepted.
</Aside>

### 4. Limit Token Scope

Create separate tokens for different environments and access levels:

```json
{
  "tokens": {
    "dev-full": "token-with-all-access",
    "dev-readonly": "token-with-limited-access",
    "ci-deploy": "token-for-ci-only"
  }
}
```

## Monitoring and Logging

MCP Front logs token usage for security monitoring:

```json
{
  "time": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "msg": "Authenticated request",
  "token_name": "development",
  "server": "database",
  "method": "POST"
}
```

<Aside type="tip">
  Token values are never logged - only token names appear in logs.
</Aside>

## Migration from Bearer to OAuth

When ready to move to production, you can migrate from bearer tokens to OAuth:

1. **Enable OAuth** alongside bearer tokens
2. **Migrate clients** one by one
3. **Remove bearer tokens** after migration

```json
{
  "auth": {
    "kind": "oauth",  // Switch from "bearer_token"
    "issuer": "https://your-domain.com",
    // ... OAuth config
  }
}
```

## Troubleshooting

### "401 Unauthorized" Errors

Check:
1. Token is correctly formatted: `Authorization: Bearer <token>`
2. Token exists in configuration
3. Token name is authorized for the requested server

### Token Not Working

Verify:
1. No extra spaces in token value
2. Environment variable is set (if using `$env:`)
3. Configuration file has been reloaded

### Access Denied to Specific Server

Ensure:
1. Token name is listed in server's `authTokens` array
2. No typos in token name
3. Server name in URL matches configuration

## Example: Development Setup

Complete example for development environment:

<Code code={`{
  "version": "1.0",
  "proxy": {
    "name": "Development MCP Proxy",
    "baseUrl": "http://localhost:8080",
    "addr": ":8080",
    "auth": {
      "kind": "bearer_token",
      "tokens": {
        "dev": "$env:DEV_TOKEN|dev-token-123",
        "test": "$env:TEST_TOKEN|test-token-456"
      }
    }
  },
  "mcpServers": {
    "database": {
      "url": "http://postgres-mcp:3000/sse",
      "authTokens": ["dev", "test"],
      "env": {
        "DATABASE_URL": "$env:DATABASE_URL"
      }
    },
    "files": {
      "command": "node",
      "args": ["/app/file-server.js"],
      "authTokens": ["dev"]
    }
  }
}`} lang="json" title="config.dev.json" />

Run with:
```bash
export DEV_TOKEN=my-secure-dev-token
export DATABASE_URL=postgresql://localhost/devdb
./mcp-front -config config.dev.json
```

## Next Steps

- Set up [MCP Servers](/mcp-front/config/mcp-servers/) to proxy
- Configure [Environment Variables](/mcp-front/config/environment/)
- Upgrade to [OAuth 2.1](/mcp-front/config/oauth/) for production
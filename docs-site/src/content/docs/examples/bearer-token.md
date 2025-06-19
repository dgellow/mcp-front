---
title: Bearer Token Example
description: Static token authentication for development and alternative clients
---

Bearer tokens are static authentication tokens configured in your MCP Front config. They're perfect for development environments and alternative MCP clients (not Claude.ai, which only supports OAuth).

## How bearer tokens work

An MCP client can connect to MCP Front with a bearer token. MCP Front validates this token against its configured tokens, then proxies the request to your MCP servers.

**Note:** Claude.ai only supports OAuth authentication. Use bearer tokens for development, testing, or alternative MCP clients.

![Bearer Token Authentication Flow](/mcp-front/bearer-token-flow.svg)

## Basic setup

```json
{
  "version": "1.0",
  "proxy": {
    "name": "Dev Proxy",
    "addr": ":8080",
    "auth": {
      "kind": "bearer_token",
      "tokens": {
        "dev": "dev-token-123",
        "staging": "staging-token-456"
      }
    }
  },
  "mcpServers": {
    "database": {
      "url": "http://postgres-mcp:3000/sse",
      "authTokens": ["dev", "staging"]
    }
  }
}
```

## Using environment variables

Never commit tokens to git. Use environment variables to keep them secure:

```json
{
  "auth": {
    "kind": "bearer_token",
    "tokens": {
      "dev": { "$env": "DEV_TOKEN" },
      "prod": { "$env": "PROD_TOKEN" }
    }
  }
}
```

Then set the environment:

```bash
export DEV_TOKEN="my-dev-token"
export PROD_TOKEN="my-prod-token"
docker run -p 8080:8080 \
  -e DEV_TOKEN -e PROD_TOKEN \
  -v $(pwd)/config.json:/config.json \
  ghcr.io/dgellow/mcp-front:latest
```

## Multiple MCP servers

You can use different tokens to control access to different MCP servers. This creates a simple permission system:

```json
{
  "auth": {
    "kind": "bearer_token",
    "tokens": {
      "db-read": "read-only-token",
      "db-write": "read-write-token",
      "files": "file-access-token"
    }
  },
  "mcpServers": {
    "database-read": {
      "url": "http://postgres-mcp:3000/sse",
      "authTokens": ["db-read"]
    },
    "database-write": {
      "url": "http://postgres-mcp:3000/sse",
      "authTokens": ["db-write"]
    },
    "filesystem": {
      "command": "npx",
      "args": ["-y", "@modelcontextprotocol/server-filesystem", "/data"],
      "authTokens": ["files"]
    }
  }
}
```

## Rotating tokens

Bearer tokens should be rotated regularly. Here's how to do it without downtime:

### Step 1: Add the new token

Update your config to include both old and new tokens:

```json
{
  "tokens": {
    "old-token": "abc123",
    "new-token": "xyz789" // Add new token
  }
}
```

### Step 2: Deploy and test

Deploy the updated config. Both tokens now work.

### Step 3: Update clients

Update all Claude clients to use the new token.

### Step 4: Remove old token

Once all clients are updated, remove the old token:

```json
{
  "tokens": {
    "new-token": "xyz789" // Old token removed
  }
}
```

## Security best practices

### Generate secure tokens

Use cryptographically secure random tokens:

```bash
# Generate a 32-byte token
openssl rand -base64 32
# Output: 7J+sX9Zr3mK8pN2qL5vW4hT6gY1aE0cR/bD+fU==
```

### Environment isolation

Use different tokens for each environment:

```json
{
  "tokens": {
    "dev": { "$env": "DEV_TOKEN" }, // Development
    "staging": { "$env": "STAGING_TOKEN" }, // Staging
    "prod": { "$env": "PROD_TOKEN" } // Production
  }
}
```

### Access monitoring

Monitor token usage in logs:

```bash
# See who's using which token
docker logs mcp-front | grep "auth successful"
# 2024-01-15T10:30:45Z INFO auth successful token=dev client_ip=10.0.0.5
```

### Token lifecycle

1. **Generate**: Use strong random tokens
2. **Store**: Environment variables, never in code
3. **Rotate**: Every 90 days or after employee departure
4. **Revoke**: Remove immediately when compromised

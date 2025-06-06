---
title: Getting Started
description: Quick start guide for MCP Front
---

import { Steps, Tabs, TabItem } from '@astrojs/starlight/components';

Get MCP Front up and running in minutes with this quick start guide.

## Prerequisites

Before you begin, ensure you have:

- Docker and Docker Compose installed (or Go 1.21+ for building from source)
- A Google Cloud project with OAuth 2.0 credentials (for OAuth mode)
- Access to MCP servers you want to proxy

## Quick Start with Docker

<Steps>

1. **Create a configuration file**

   Create a `config.json` file:

   <Tabs>
   <TabItem label="Bearer Token Auth">
   ```json
   {
     "version": "1.0",
     "proxy": {
       "name": "My MCP Proxy",
       "baseUrl": "https://your-domain.com",
       "addr": ":8080",
       "auth": {
         "kind": "bearer_token",
         "tokens": {
           "development": "dev-token-123",
           "production": "prod-token-456"
         }
       }
     },
     "mcpServers": {
       "database": {
         "url": "http://postgres-mcp:3000/sse"
       },
       "files": {
         "command": "docker",
         "args": ["run", "--rm", "-i", "mcp/file-server"],
         "authTokens": ["development"]
       }
     }
   }
   ```
   </TabItem>
   <TabItem label="OAuth 2.1 Auth">
   ```json
   {
     "version": "1.0",
     "proxy": {
       "name": "My MCP Proxy",
       "baseUrl": "https://your-domain.com",
       "addr": ":8080",
       "auth": {
         "kind": "oauth",
         "issuer": "https://your-domain.com",
         "allowedDomains": ["your-company.com"],
         "tokenTTL": "24h",
         "storage": "firestore",
         "gcpProject": "your-project-id"
       }
     },
     "mcpServers": {
       "database": {
         "url": "http://postgres-mcp:3000/sse"
       }
     }
   }
   ```
   </TabItem>
   </Tabs>

2. **Set environment variables**

   Create a `.env` file:

   ```bash
   # For OAuth mode
   GOOGLE_CLIENT_ID=your-client-id
   GOOGLE_CLIENT_SECRET=your-client-secret
   JWT_SECRET=your-secure-jwt-secret-at-least-32-bytes
   
   # Optional
   LOG_LEVEL=info
   LOG_FORMAT=json
   ```

3. **Run with Docker Compose**

   Create a `docker-compose.yml`:

   ```yaml
   version: '3.8'
   
   services:
     mcp-front:
       image: ghcr.io/dgellow/mcp-front:latest
       ports:
         - "8080:8080"
       volumes:
         - ./config.json:/config.json
       env_file:
         - .env
       healthcheck:
         test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
         interval: 30s
         timeout: 10s
         retries: 3
   ```

   Start the service:

   ```bash
   docker-compose up -d
   ```

4. **Verify the installation**

   Check the health endpoint:

   ```bash
   curl http://localhost:8080/health
   # Output: {"status":"ok","service":"mcp-front"}
   ```

   For OAuth mode, check the discovery endpoint:

   ```bash
   curl http://localhost:8080/.well-known/oauth-authorization-server
   ```

</Steps>

## Configure Claude.ai

<Steps>

1. **Add MCP Front as a server in Claude.ai**

   In Claude.ai settings, add a new MCP server:

   <Tabs>
   <TabItem label="Bearer Token">
   ```
   URL: https://your-domain.com/sse
   Auth: Bearer Token
   Token: dev-token-123
   ```
   </TabItem>
   <TabItem label="OAuth 2.1">
   ```
   URL: https://your-domain.com/sse
   Auth: OAuth
   ```
   </TabItem>
   </Tabs>

2. **Test the connection**

   Ask Claude to list available tools:

   ```
   What MCP tools do you have access to?
   ```

</Steps>

## Building from Source

If you prefer to build from source:

```bash
# Clone the repository
git clone https://github.com/dgellow/mcp-front.git
cd mcp-front

# Build the binary
go build -o mcp-front ./cmd/mcp-front

# Run with your config
./mcp-front -config config.json
```

## Next Steps

- [Configure authentication](/mcp-front/config/overview/) for your environment
- [Set up MCP servers](/mcp-front/config/mcp-servers/) to proxy
- [Deploy to production](/mcp-front/deployment/production/) with best practices
- [Integrate with Google Workspace](/mcp-front/oauth/google-workspace/) for enterprise SSO

## Troubleshooting

### Connection refused

If you get "connection refused" errors:

1. Check that MCP Front is running: `docker ps`
2. Verify the port mapping: `docker port mcp-front`
3. Check firewall rules allow connections on port 8080

### OAuth errors

For OAuth-related issues:

1. Verify your Google OAuth credentials are correct
2. Check that redirect URIs match your configuration
3. Ensure JWT_SECRET is at least 32 bytes
4. Review logs: `docker logs mcp-front`

### MCP server connection issues

If MCP servers aren't accessible:

1. Verify the MCP server URLs are correct
2. Check network connectivity between containers
3. Ensure authentication tokens match
4. Review server logs for errors

For more help, see our [troubleshooting guide](/mcp-front/troubleshooting/) or [open an issue](https://github.com/dgellow/mcp-front/issues).
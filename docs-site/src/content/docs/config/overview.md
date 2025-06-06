---
title: Configuration Overview
description: Understanding MCP Front configuration structure
---

import { Aside, Code } from '@astrojs/starlight/components';

MCP Front uses a JSON configuration file to define proxy settings, authentication methods, and MCP server connections.

## Configuration File Structure

The configuration file has three main sections:

```json
{
  "version": "1.0",
  "proxy": {
    // Proxy server settings and authentication
  },
  "mcpServers": {
    // MCP server definitions
  }
}
```

## Complete Example

Here's a complete configuration example with all options:

<Code code={`{
  "version": "1.0",
  "proxy": {
    "name": "Production MCP Proxy",
    "baseUrl": "https://mcp.company.com",
    "addr": ":8080",
    "auth": {
      "kind": "oauth",
      "issuer": "https://mcp.company.com",
      "allowedDomains": ["company.com"],
      "tokenTTL": "24h",
      "storage": "firestore",
      "gcpProject": "my-project-123",
      "firestoreDatabase": "(default)",
      "firestoreCollection": "mcp_oauth_clients"
    }
  },
  "mcpServers": {
    "postgres": {
      "url": "http://postgres-mcp:3000/sse",
      "env": {
        "DATABASE_URL": "postgresql://user:pass@db:5432/mydb"
      }
    },
    "github": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-e", "GITHUB_TOKEN",
        "mcp/github-server"
      ],
      "env": {
        "GITHUB_TOKEN": "$env:GITHUB_TOKEN"
      }
    },
    "files": {
      "command": "/usr/local/bin/file-mcp",
      "args": ["--root", "/data"],
      "authTokens": ["production"],
      "toolFilter": {
        "mode": "allow",
        "tools": ["read_file", "list_directory"]
      }
    }
  }
}`} lang="json" title="config.json" />

## Version Field

The `version` field specifies the configuration format version. Currently only `"1.0"` is supported.

<Aside type="caution">
  Always include the version field. Future versions may introduce breaking changes.
</Aside>

## Proxy Section

The proxy section configures the MCP Front server itself:

### Basic Settings

| Field | Description | Required | Default |
|-------|-------------|----------|---------|
| `name` | Human-readable proxy name | Yes | - |
| `baseUrl` | Public URL of your proxy | Yes | - |
| `addr` | Listen address | No | `:8080` |

### Authentication Configuration

The `auth` object configures how clients authenticate with MCP Front:

```json
{
  "auth": {
    "kind": "bearer_token" | "oauth",
    // Additional fields based on kind
  }
}
```

See detailed configuration for:
- [Bearer Token Authentication](/mcp-front/config/bearer-token/)
- [OAuth 2.1 Authentication](/mcp-front/config/oauth/)

## MCP Servers Section

The `mcpServers` object defines the MCP servers that clients can access through the proxy:

```json
{
  "mcpServers": {
    "server-name": {
      // Server configuration
    }
  }
}
```

Each server is identified by a unique name (e.g., "postgres", "github") that becomes part of the SSE endpoint URL.

See [MCP Servers Configuration](/mcp-front/config/mcp-servers/) for detailed options.

## Environment Variable Substitution

Configuration values can reference environment variables using the `$env:` prefix:

```json
{
  "env": {
    "API_KEY": "$env:MY_API_KEY",
    "DATABASE_URL": "$env:DATABASE_URL|postgresql://localhost/dev"
  }
}
```

The syntax is `$env:VARIABLE_NAME` or `$env:VARIABLE_NAME|default_value`.

## Configuration Validation

MCP Front validates the configuration on startup and will exit with an error if:

- Required fields are missing
- Field values are invalid (e.g., malformed URLs)
- Referenced environment variables are missing (without defaults)
- Authentication configuration is incomplete

Example validation error:
```
Configuration validation failed:
- proxy.baseUrl: must be a valid URL
- proxy.auth.tokenTTL: must be a valid duration (e.g., "24h")
- mcpServers.database.url: missing required field
```

## Loading Configuration

### From File

By default, MCP Front looks for `config.json` in the current directory:

```bash
./mcp-front
```

Specify a different path with the `-config` flag:

```bash
./mcp-front -config /etc/mcp-front/production.json
```

### From Environment

For containerized deployments, you can mount the config file:

```yaml
volumes:
  - ./config.json:/config.json
```

Or use ConfigMaps in Kubernetes:

```yaml
volumeMounts:
  - name: config
    mountPath: /config.json
    subPath: config.json
```

## Configuration Best Practices

1. **Use Environment Variables for Secrets**
   ```json
   {
     "env": {
       "API_KEY": "$env:API_KEY"
     }
   }
   ```

2. **Separate Dev and Production Configs**
   ```bash
   mcp-front -config config.dev.json
   mcp-front -config config.prod.json
   ```

3. **Validate Before Deployment**
   ```bash
   mcp-front -config config.json -validate
   ```

4. **Use Descriptive Server Names**
   ```json
   {
     "mcpServers": {
       "company-database": { ... },  // Good
       "db1": { ... }                // Avoid
     }
   }
   ```

5. **Document Custom Settings**
   ```json
   {
     "mcpServers": {
       "custom-tool": {
         "url": "http://tool:8080/sse",
         "// comment": "Custom tool for invoice processing"
       }
     }
   }
   ```

## Next Steps

- Configure [Bearer Token Auth](/mcp-front/config/bearer-token/) for development
- Set up [OAuth 2.1](/mcp-front/config/oauth/) for production
- Define your [MCP Servers](/mcp-front/config/mcp-servers/)
- Review [Environment Variables](/mcp-front/config/environment/) reference
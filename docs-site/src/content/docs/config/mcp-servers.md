---
title: MCP Servers Configuration
description: Configure Model Context Protocol servers for proxying
---

import { Aside, Code, Tabs, TabItem } from '@astrojs/starlight/components';

MCP servers are the backend services that MCP Front proxies to. Each server can be either HTTP-based or stdio-based (command execution).

## Server Types

### HTTP Servers

HTTP servers are standalone services that implement the MCP protocol over Server-Sent Events (SSE):

```json
{
  "mcpServers": {
    "database": {
      "url": "http://postgres-mcp:3000/sse",
      "env": {
        "DATABASE_URL": "postgresql://user:pass@db:5432/mydb"
      }
    }
  }
}
```

### Stdio Servers

Stdio servers are executables that communicate via standard input/output:

```json
{
  "mcpServers": {
    "files": {
      "command": "node",
      "args": ["/app/file-server.js", "--root", "/data"],
      "env": {
        "NODE_ENV": "production"
      }
    }
  }
}
```

## Configuration Fields

| Field | Description | Required | Default |
|-------|-------------|----------|---------|
| `url` | HTTP endpoint URL (for HTTP servers) | If HTTP | - |
| `command` | Executable command (for stdio servers) | If stdio | - |
| `args` | Command arguments | No | `[]` |
| `env` | Environment variables | No | `{}` |
| `authTokens` | Authorized bearer tokens | No | All tokens |
| `toolFilter` | Tool access restrictions | No | No filter |

<Aside type="caution">
  A server must have either `url` (HTTP) or `command` (stdio), but not both.
</Aside>

## Server Naming

Server names become part of the SSE endpoint URL:

```json
{
  "mcpServers": {
    "my-database": { ... },    // Access via /my-database/sse
    "github": { ... },         // Access via /github/sse
    "internal-api": { ... }    // Access via /internal-api/sse
  }
}
```

<Aside type="tip">
  Use descriptive, URL-safe names without spaces or special characters.
</Aside>

## Environment Variables

### Static Values

```json
{
  "env": {
    "API_KEY": "sk-123456",
    "LOG_LEVEL": "info"
  }
}
```

### Dynamic Values

Reference environment variables with `$env:`:

```json
{
  "env": {
    "DATABASE_URL": "$env:DATABASE_URL",
    "API_KEY": "$env:API_KEY|default-key"
  }
}
```

### Common Patterns

<Tabs>
<TabItem label="Database Connection">
```json
{
  "database": {
    "url": "http://postgres-mcp:3000/sse",
    "env": {
      "DATABASE_URL": "$env:DATABASE_URL",
      "DB_POOL_SIZE": "10",
      "DB_TIMEOUT": "30s"
    }
  }
}
```
</TabItem>
<TabItem label="API Service">
```json
{
  "api": {
    "url": "http://api-mcp:8080/sse",
    "env": {
      "API_BASE_URL": "$env:API_BASE_URL",
      "API_KEY": "$env:API_KEY",
      "RATE_LIMIT": "100"
    }
  }
}
```
</TabItem>
<TabItem label="File System">
```json
{
  "files": {
    "command": "mcp-server-files",
    "args": ["--root", "/data"],
    "env": {
      "FILE_PERMISSIONS": "readonly",
      "MAX_FILE_SIZE": "10MB"
    }
  }
}
```
</TabItem>
</Tabs>

## Docker-based Servers

For stdio servers using Docker:

```json
{
  "mcpServers": {
    "python-tools": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--network", "mcp-network",
        "-e", "PYTHONUNBUFFERED=1",
        "my-python-mcp:latest"
      ],
      "env": {
        "PYTHON_PATH": "/app"
      }
    }
  }
}
```

<Aside type="tip">
  Use the `docker-client` variant of MCP Front when running Docker commands.
</Aside>

## Authorization

### Bearer Token Authorization

Restrict server access to specific tokens:

```json
{
  "mcpServers": {
    "public-data": {
      "url": "http://public-api:3000/sse"
      // No authTokens - accessible by any valid token
    },
    "internal-data": {
      "url": "http://internal-api:3000/sse",
      "authTokens": ["production", "admin"]
    },
    "sensitive-data": {
      "url": "http://sensitive-api:3000/sse",
      "authTokens": ["admin"]
    }
  }
}
```

### OAuth Authorization

With OAuth, all authenticated users can access all servers (domain-based):

```json
{
  "proxy": {
    "auth": {
      "kind": "oauth",
      "allowedDomains": ["company.com"]
    }
  },
  "mcpServers": {
    // All servers accessible to company.com users
  }
}
```

## Tool Filtering

Control which MCP tools are exposed:

### Allow Mode

Only specified tools are available:

```json
{
  "toolFilter": {
    "mode": "allow",
    "tools": ["query_database", "list_tables"]
  }
}
```

### Deny Mode

All tools except specified ones are available:

```json
{
  "toolFilter": {
    "mode": "deny",
    "tools": ["delete_database", "drop_table"]
  }
}
```

## Advanced Configurations

### Load Balancing

For multiple instances of the same service:

```json
{
  "mcpServers": {
    "database-1": {
      "url": "http://postgres-1:3000/sse"
    },
    "database-2": {
      "url": "http://postgres-2:3000/sse"
    }
  }
}
```

### Timeouts and Retries

Configure connection parameters:

```json
{
  "mcpServers": {
    "slow-service": {
      "url": "http://slow-api:3000/sse",
      "env": {
        "TIMEOUT": "300s",
        "MAX_RETRIES": "3",
        "RETRY_DELAY": "5s"
      }
    }
  }
}
```

### Resource Limits

For stdio servers, control resource usage:

```json
{
  "mcpServers": {
    "compute-heavy": {
      "command": "computation-server",
      "env": {
        "MAX_MEMORY": "2GB",
        "MAX_CPU_TIME": "60s",
        "NICE_LEVEL": "10"
      }
    }
  }
}
```

## Monitoring and Health

### Health Checks

MCP Front doesn't perform health checks on servers, but you can implement them:

```json
{
  "mcpServers": {
    "api": {
      "url": "http://api:3000/sse",
      "env": {
        "HEALTH_CHECK_PATH": "/health",
        "HEALTH_CHECK_INTERVAL": "30s"
      }
    }
  }
}
```

### Logging

Server interactions are logged:

```json
{
  "time": "2024-01-15T10:30:00Z",
  "level": "INFO",
  "msg": "Proxying request to MCP server",
  "server": "database",
  "method": "tools/list"
}
```

## Examples

### Complete PostgreSQL Setup

<Code code={`{
  "mcpServers": {
    "postgres": {
      "url": "http://postgres-mcp:3000/sse",
      "authTokens": ["production", "development"],
      "env": {
        "DATABASE_URL": "$env:DATABASE_URL",
        "PGPOOL_SIZE": "20",
        "PGSTATEMENT_TIMEOUT": "30000",
        "PGIDLE_IN_TRANSACTION_SESSION_TIMEOUT": "60000"
      },
      "toolFilter": {
        "mode": "deny",
        "tools": ["drop_database", "create_user"]
      }
    }
  }
}`} lang="json" title="PostgreSQL Configuration" />

### Complete GitHub Integration

<Code code={`{
  "mcpServers": {
    "github": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "--memory", "512m",
        "--cpus", "0.5",
        "mcp/github-server:latest"
      ],
      "env": {
        "GITHUB_TOKEN": "$env:GITHUB_TOKEN",
        "GITHUB_ORG": "my-company",
        "GITHUB_REPO_FILTER": "^(backend-|frontend-)",
        "CACHE_TTL": "300"
      },
      "authTokens": ["developers", "ci"]
    }
  }
}`} lang="json" title="GitHub Configuration" />

## Troubleshooting

### Server Not Accessible

1. Check server name in URL matches configuration
2. Verify network connectivity (for HTTP servers)
3. Ensure executable exists (for stdio servers)
4. Check authorization (authTokens)

### Environment Variables Not Working

1. Verify `$env:VARIABLE` syntax
2. Check environment variable is set
3. Use default values: `$env:VAR|default`

### Stdio Server Crashes

1. Check command and arguments
2. Verify executable permissions
3. Review server logs
4. Test command manually

### Tool Filtering Issues

1. Verify tool names match exactly
2. Check filter mode (allow vs deny)
3. Test with no filter first

## Best Practices

1. **Use Environment Variables** for sensitive data
2. **Implement Tool Filtering** for security
3. **Set Resource Limits** for stdio servers
4. **Use Descriptive Names** for servers
5. **Document Server Purpose** in comments
6. **Test Configurations** before deployment

## Next Steps

- Configure [Environment Variables](/mcp-front/config/environment/)
- Set up [Docker deployment](/mcp-front/deployment/docker/)
- Review [Security Best Practices](/mcp-front/oauth/security/)
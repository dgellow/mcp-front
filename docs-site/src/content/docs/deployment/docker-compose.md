---
title: Docker Compose Deployment
description: Deploy MCP Front using Docker Compose
---

import { Aside, Code, Tabs, TabItem } from '@astrojs/starlight/components';

Docker Compose provides an easy way to deploy MCP Front with all its dependencies.

## Quick Start

### Basic Setup

<Code code={`version: '3.8'

services:
  mcp-front:
    image: dgellow/mcp-front:latest
    ports:
      - "8080:8080"
    environment:
      - MCP_FRONT_ENV=production
      - LOG_LEVEL=info
    volumes:
      - ./config.json:/config/config.json
    command: ["-config", "/config/config.json"]
    restart: unless-stopped`} lang="yaml" title="docker-compose.yml" />

Start with:
```bash
docker-compose up -d
```

## Complete Examples

### OAuth with Firestore

<Code code={`version: '3.8'

services:
  mcp-front:
    image: dgellow/mcp-front:latest
    ports:
      - "443:8080"
    environment:
      # OAuth configuration
      - GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
      - GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}
      - JWT_SECRET=${JWT_SECRET}
      
      # Firestore configuration
      - FIRESTORE_PROJECT_ID=${GCP_PROJECT_ID}
      - FIRESTORE_DATABASE=production
      - GOOGLE_APPLICATION_CREDENTIALS=/secrets/gcp-key.json
      
      # Application settings
      - MCP_FRONT_ENV=production
      - LOG_LEVEL=info
      - LOG_FORMAT=json
    volumes:
      - ./config/oauth-config.json:/config/config.json:ro
      - ./secrets/gcp-key.json:/secrets/gcp-key.json:ro
    command: ["-config", "/config/config.json"]
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
  
  # Example MCP server
  postgres-mcp:
    image: postgres-mcp-server:latest
    environment:
      - DATABASE_URL=postgresql://postgres:password@db:5432/mydb
    depends_on:
      - db
    restart: unless-stopped
  
  db:
    image: postgres:16-alpine
    environment:
      - POSTGRES_PASSWORD=password
      - POSTGRES_DB=mydb
    volumes:
      - postgres_data:/var/lib/postgresql/data
    restart: unless-stopped

volumes:
  postgres_data:

networks:
  default:
    name: mcp-network`} lang="yaml" title="docker-compose.oauth.yml" />

### Bearer Token Authentication

<Code code={`version: '3.8'

services:
  mcp-front:
    image: dgellow/mcp-front:latest
    ports:
      - "8080:8080"
    environment:
      # Bearer token configuration
      - DEV_TOKEN=${DEV_TOKEN:-dev-token-123}
      - PROD_TOKEN=${PROD_TOKEN:-prod-token-456}
      
      # Application settings
      - MCP_FRONT_ENV=development
      - LOG_LEVEL=debug
      - LOG_FORMAT=text
    volumes:
      - ./config/bearer-config.json:/config/config.json:ro
    command: ["-config", "/config/config.json"]
    restart: unless-stopped
  
  # HTTP-based MCP server
  api-mcp:
    image: api-mcp-server:latest
    environment:
      - API_KEY=${API_KEY}
      - PORT=3000
    restart: unless-stopped
  
  # Stdio-based MCP server (using docker-client variant)
  files-mcp:
    image: dgellow/mcp-front:docker-client-latest
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./data:/data:ro
    command: ["docker", "run", "--rm", "-i", "file-mcp-server:latest"]
    restart: unless-stopped`} lang="yaml" title="docker-compose.bearer.yml" />

## Docker Client Variant

For running Docker-based MCP servers:

<Code code={`version: '3.8'

services:
  mcp-front:
    image: dgellow/mcp-front:docker-client-latest
    ports:
      - "8080:8080"
    environment:
      - MCP_FRONT_ENV=production
    volumes:
      - ./config.json:/config/config.json:ro
      - /var/run/docker.sock:/var/run/docker.sock
    command: ["-config", "/config/config.json"]
    group_add:
      - "999"  # Docker group ID
    restart: unless-stopped`} lang="yaml" title="docker-compose.docker-client.yml" />

<Aside type="tip">
  The docker-client variant includes the Docker CLI for spawning MCP servers as containers.
</Aside>

## Configuration Files

### OAuth Configuration

<Code code={`{
  "version": "1.0",
  "proxy": {
    "name": "Company MCP Proxy",
    "baseUrl": "https://mcp.company.com",
    "addr": ":8080",
    "auth": {
      "kind": "oauth",
      "issuer": "https://mcp.company.com",
      "allowedDomains": ["company.com"],
      "jwtSecret": "$env:JWT_SECRET",
      "googleClientId": "$env:GOOGLE_CLIENT_ID",
      "googleClientSecret": "$env:GOOGLE_CLIENT_SECRET",
      "storage": "firestore",
      "firestoreProjectId": "$env:FIRESTORE_PROJECT_ID",
      "firestoreDatabase": "$env:FIRESTORE_DATABASE|(default)",
      "firestoreCollection": "oauth_clients"
    }
  },
  "mcpServers": {
    "database": {
      "url": "http://postgres-mcp:3000/sse"
    }
  }
}`} lang="json" title="config/oauth-config.json" />

### Bearer Token Configuration

<Code code={`{
  "version": "1.0",
  "proxy": {
    "name": "Dev MCP Proxy",
    "baseUrl": "http://localhost:8080",
    "addr": ":8080",
    "auth": {
      "kind": "bearer_token",
      "tokens": {
        "dev": "$env:DEV_TOKEN",
        "prod": "$env:PROD_TOKEN"
      }
    }
  },
  "mcpServers": {
    "api": {
      "url": "http://api-mcp:3000/sse",
      "authTokens": ["dev", "prod"]
    },
    "files": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "/data:/data:ro",
        "file-mcp-server:latest"
      ],
      "authTokens": ["dev"]
    }
  }
}`} lang="json" title="config/bearer-config.json" />

## Environment Files

### Production Environment

```bash
# .env.production
GOOGLE_CLIENT_ID=123456.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-...
JWT_SECRET=your-production-jwt-secret-minimum-32-bytes
GCP_PROJECT_ID=my-company-project
FIRESTORE_DATABASE=production
```

### Development Environment

```bash
# .env.development
DEV_TOKEN=dev-token-123
PROD_TOKEN=prod-token-456
API_KEY=test-api-key
LOG_LEVEL=debug
```

<Aside type="danger">
  Never commit `.env` files to version control. Add them to `.gitignore`.
</Aside>

## Networking

### Custom Network

```yaml
networks:
  mcp-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/16

services:
  mcp-front:
    networks:
      mcp-network:
        ipv4_address: 172.20.0.10
```

### Service Discovery

Services can communicate using container names:

```json
{
  "mcpServers": {
    "database": {
      "url": "http://postgres-mcp:3000/sse"
    },
    "api": {
      "url": "http://api-mcp:8080/sse"
    }
  }
}
```

## Volumes and Persistence

### Configuration Volume

```yaml
volumes:
  - ./config:/config:ro                    # Read-only config
  - ./secrets:/secrets:ro                  # Read-only secrets
  - /var/run/docker.sock:/var/run/docker.sock  # Docker socket
```

### Named Volumes

```yaml
volumes:
  config_data:
    driver: local
  secrets_data:
    driver: local
    driver_opts:
      type: none
      o: bind
      device: /secure/secrets
```

## Health Checks

### Basic Health Check

```yaml
healthcheck:
  test: ["CMD", "curl", "-f", "http://localhost:8080/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 10s
```

### Advanced Health Check

```yaml
healthcheck:
  test: |
    curl -f http://localhost:8080/health && 
    curl -f http://localhost:8080/oauth/.well-known/openid-configuration
  interval: 60s
  timeout: 30s
  retries: 5
  start_period: 30s
```

## Scaling

### Horizontal Scaling

```yaml
services:
  mcp-front:
    image: dgellow/mcp-front:latest
    deploy:
      replicas: 3
      update_config:
        parallelism: 1
        delay: 10s
      restart_policy:
        condition: on-failure
        delay: 5s
        max_attempts: 3
```

### Load Balancing

<Code code={`version: '3.8'

services:
  nginx:
    image: nginx:alpine
    ports:
      - "80:80"
      - "443:443"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./certs:/etc/nginx/certs:ro
    depends_on:
      - mcp-front
    restart: unless-stopped
  
  mcp-front:
    image: dgellow/mcp-front:latest
    deploy:
      replicas: 3
    environment:
      - MCP_FRONT_ENV=production
    volumes:
      - ./config.json:/config/config.json:ro
    command: ["-config", "/config/config.json"]
    restart: unless-stopped`} lang="yaml" title="docker-compose.scaled.yml" />

## Security Hardening

### Read-Only Root Filesystem

```yaml
services:
  mcp-front:
    image: dgellow/mcp-front:latest
    read_only: true
    tmpfs:
      - /tmp
    volumes:
      - ./config.json:/config/config.json:ro
    security_opt:
      - no-new-privileges:true
```

### User Namespace Remapping

```yaml
services:
  mcp-front:
    image: dgellow/mcp-front:latest
    user: "1000:1000"
    cap_drop:
      - ALL
    cap_add:
      - NET_BIND_SERVICE
```

### Secrets Management

```yaml
secrets:
  jwt_secret:
    external: true
  google_oauth:
    file: ./secrets/google-oauth.json

services:
  mcp-front:
    secrets:
      - jwt_secret
      - google_oauth
    environment:
      - JWT_SECRET_FILE=/run/secrets/jwt_secret
```

## Monitoring

### Prometheus Integration

```yaml
services:
  mcp-front:
    image: dgellow/mcp-front:latest
    labels:
      - "prometheus.io/scrape=true"
      - "prometheus.io/port=8080"
      - "prometheus.io/path=/metrics"
  
  prometheus:
    image: prom/prometheus
    volumes:
      - ./prometheus.yml:/etc/prometheus/prometheus.yml
      - prometheus_data:/prometheus
    command:
      - '--config.file=/etc/prometheus/prometheus.yml'
      - '--storage.tsdb.path=/prometheus'
    ports:
      - "9090:9090"

volumes:
  prometheus_data:
```

### Logging

```yaml
services:
  mcp-front:
    image: dgellow/mcp-front:latest
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"
        labels: "service=mcp-front"
    labels:
      - "com.company.service=mcp-front"
      - "com.company.environment=production"
```

## Troubleshooting

### Container Logs

```bash
# View logs
docker-compose logs -f mcp-front

# View last 100 lines
docker-compose logs --tail=100 mcp-front

# Save logs to file
docker-compose logs mcp-front > mcp-front.log
```

### Debug Mode

```yaml
services:
  mcp-front:
    image: dgellow/mcp-front:latest
    environment:
      - MCP_FRONT_ENV=development
      - LOG_LEVEL=debug
      - LOG_FORMAT=text
    command: ["-config", "/config/config.json", "-debug"]
```

### Shell Access

```bash
# Execute shell in running container
docker-compose exec mcp-front sh

# Run one-off command
docker-compose run --rm mcp-front env
```

### Common Issues

#### Port Already in Use

```bash
# Find process using port
lsof -i :8080

# Use different port
ports:
  - "8081:8080"
```

#### Permission Denied (Docker Socket)

```yaml
# Add user to docker group
group_add:
  - "999"  # Docker group ID

# Or run as root (not recommended)
user: root
```

#### Environment Variables Not Loading

```bash
# Verify environment
docker-compose run --rm mcp-front env | grep MCP

# Check .env file
docker-compose config
```

## Production Checklist

- [ ] Use specific image tags (not `latest`)
- [ ] Configure health checks
- [ ] Set up logging with rotation
- [ ] Use secrets management
- [ ] Configure restart policies
- [ ] Set resource limits
- [ ] Use read-only volumes where possible
- [ ] Configure TLS/SSL
- [ ] Set up monitoring
- [ ] Plan for backups

## Next Steps

- Deploy to [Cloud Run](/mcp-front/deployment/cloud-run/)
- Configure [Production settings](/mcp-front/deployment/production/)
- Set up [Monitoring and logging](/mcp-front/deployment/monitoring/)
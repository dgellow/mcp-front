---
title: Docker Deployment
description: Deploy MCP Front using Docker
---

import { Aside, Code, Tabs, TabItem } from '@astrojs/starlight/components';

MCP Front provides official Docker images for easy deployment.

## Docker Images

### Standard Image

The standard image includes MCP Front binary:

```bash
docker pull ghcr.io/dgellow/mcp-front:latest
```

**Tags:**
- `latest` - Latest stable release
- `main-{sha}` - Specific commit from main branch
- `v1.0.0` - Specific version tags

### Docker Client Image

For MCP servers that need to spawn Docker containers:

```bash
docker pull ghcr.io/dgellow/mcp-front:docker-client-latest
```

**Includes:**
- MCP Front binary
- Docker CLI
- Proper permissions for Docker socket

<Aside type="tip">
  Use the docker-client variant when your MCP servers use `command: "docker"`.
</Aside>

## Basic Docker Run

### Minimal Example

```bash
docker run -d \
  --name mcp-front \
  -p 8080:8080 \
  -v $(pwd)/config.json:/config.json \
  -e GOOGLE_CLIENT_ID=your-client-id \
  -e GOOGLE_CLIENT_SECRET=your-secret \
  -e JWT_SECRET=your-jwt-secret \
  ghcr.io/dgellow/mcp-front:latest
```

### With Docker Socket

For MCP servers that spawn Docker containers:

```bash
docker run -d \
  --name mcp-front \
  -p 8080:8080 \
  -v $(pwd)/config.json:/config.json \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -e GOOGLE_CLIENT_ID=your-client-id \
  -e GOOGLE_CLIENT_SECRET=your-secret \
  -e JWT_SECRET=your-jwt-secret \
  ghcr.io/dgellow/mcp-front:docker-client-latest
```

## Docker Compose

### Basic Setup

<Code code={`version: '3.8'

services:
  mcp-front:
    image: ghcr.io/dgellow/mcp-front:latest
    container_name: mcp-front
    ports:
      - "8080:8080"
    volumes:
      - ./config.json:/config.json
    environment:
      - GOOGLE_CLIENT_ID=\${GOOGLE_CLIENT_ID}
      - GOOGLE_CLIENT_SECRET=\${GOOGLE_CLIENT_SECRET}
      - JWT_SECRET=\${JWT_SECRET}
      - LOG_LEVEL=info
      - LOG_FORMAT=json
    healthcheck:
      test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
      interval: 30s
      timeout: 10s
      retries: 3
      start_period: 10s
    restart: unless-stopped`} lang="yaml" title="docker-compose.yml" />

### With MCP Servers

Complete stack with MCP servers:

<Code code={`version: '3.8'

services:
  mcp-front:
    image: ghcr.io/dgellow/mcp-front:docker-client-latest
    container_name: mcp-front
    ports:
      - "8080:8080"
    volumes:
      - ./config.json:/config.json
      - /var/run/docker.sock:/var/run/docker.sock
    environment:
      - GOOGLE_CLIENT_ID=\${GOOGLE_CLIENT_ID}
      - GOOGLE_CLIENT_SECRET=\${GOOGLE_CLIENT_SECRET}
      - JWT_SECRET=\${JWT_SECRET}
    networks:
      - mcp-network
    depends_on:
      - postgres-mcp
    restart: unless-stopped

  postgres-mcp:
    image: mcp/postgres-server:latest
    container_name: postgres-mcp
    environment:
      - DATABASE_URL=postgresql://user:pass@postgres:5432/mydb
    networks:
      - mcp-network
    restart: unless-stopped

  postgres:
    image: postgres:16-alpine
    container_name: postgres
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
      - POSTGRES_DB=mydb
    volumes:
      - postgres-data:/var/lib/postgresql/data
    networks:
      - mcp-network
    restart: unless-stopped

networks:
  mcp-network:
    driver: bridge

volumes:
  postgres-data:`} lang="yaml" title="docker-compose.yml" />

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `GOOGLE_CLIENT_ID` | OAuth client ID | `123456789.apps.googleusercontent.com` |
| `GOOGLE_CLIENT_SECRET` | OAuth client secret | `GOCSPX-abc123...` |
| `JWT_SECRET` | JWT signing secret (32+ bytes) | `your-very-long-secret-key...` |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `LOG_LEVEL` | Logging level | `info` |
| `LOG_FORMAT` | Log format (`json` or `text`) | `json` |
| `MCP_FRONT_ENV` | Environment mode | `production` |
| `GOOGLE_APPLICATION_CREDENTIALS` | Path to service account JSON | - |

## Volume Mounts

### Configuration File

```yaml
volumes:
  - ./config.json:/config.json
  # Or specify custom path
  - ./configs/prod.json:/etc/mcp-front/config.json
```

Then run with:
```bash
docker run ... ghcr.io/dgellow/mcp-front:latest -config /etc/mcp-front/config.json
```

### Docker Socket

For Docker client variant:
```yaml
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```

<Aside type="warning">
  Mounting the Docker socket gives container access to Docker daemon. Only use with trusted configurations.
</Aside>

### Service Account (Firestore)

```yaml
volumes:
  - ./service-account.json:/app/service-account.json
environment:
  - GOOGLE_APPLICATION_CREDENTIALS=/app/service-account.json
```

## Networking

### Port Mapping

Default port is 8080:
```yaml
ports:
  - "8080:8080"    # Host:Container
  # Or custom port
  - "443:8080"     # HTTPS on host
```

### Container Networks

For MCP server communication:
```yaml
networks:
  mcp-network:
    driver: bridge
    ipam:
      config:
        - subnet: 172.28.0.0/16
```

### DNS Resolution

MCP Front uses container names for internal communication:
```json
{
  "mcpServers": {
    "database": {
      "url": "http://postgres-mcp:3000/sse"
    }
  }
}
```

## Health Checks

### Docker Health Check

```yaml
healthcheck:
  test: ["CMD", "wget", "--no-verbose", "--tries=1", "--spider", "http://localhost:8080/health"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 10s
```

### Custom Health Check

```dockerfile
HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1
```

## Security Considerations

### Non-Root User

The Docker image runs as non-root user:
```dockerfile
USER 65532:65532
```

### Read-Only Filesystem

For additional security:
```yaml
security_opt:
  - no-new-privileges:true
read_only: true
tmpfs:
  - /tmp
```

### Resource Limits

Prevent resource exhaustion:
```yaml
deploy:
  resources:
    limits:
      cpus: '1.0'
      memory: 512M
    reservations:
      cpus: '0.5'
      memory: 256M
```

## Logging

### View Logs

```bash
# Follow logs
docker logs -f mcp-front

# Last 100 lines
docker logs --tail 100 mcp-front

# With timestamps
docker logs -t mcp-front
```

### Log Drivers

Configure log rotation:
```yaml
logging:
  driver: "json-file"
  options:
    max-size: "10m"
    max-file: "3"
```

Or use external logging:
```yaml
logging:
  driver: "syslog"
  options:
    syslog-address: "tcp://192.168.0.42:123"
```

## Troubleshooting

### Container Won't Start

Check logs:
```bash
docker logs mcp-front
```

Common issues:
- Missing environment variables
- Invalid config.json
- Port already in use

### Can't Connect to MCP Servers

1. Check network connectivity:
   ```bash
   docker exec mcp-front ping postgres-mcp
   ```

2. Verify DNS resolution:
   ```bash
   docker exec mcp-front nslookup postgres-mcp
   ```

3. Test from inside container:
   ```bash
   docker exec mcp-front curl http://postgres-mcp:3000/health
   ```

### Permission Denied on Docker Socket

For docker-client variant:
```bash
# Check socket permissions
ls -la /var/run/docker.sock

# Add user to docker group (not recommended for production)
sudo usermod -aG docker $USER
```

## Production Best Practices

1. **Use Specific Tags**
   ```yaml
   image: ghcr.io/dgellow/mcp-front:v1.0.0
   ```

2. **Enable Restart Policy**
   ```yaml
   restart: unless-stopped
   ```

3. **Configure Logging**
   ```yaml
   logging:
     driver: "json-file"
     options:
       max-size: "10m"
       max-file: "3"
   ```

4. **Set Resource Limits**
   ```yaml
   deploy:
     resources:
       limits:
         memory: 512M
   ```

5. **Use Secrets Management**
   ```yaml
   secrets:
     jwt_secret:
       external: true
   ```

## Next Steps

- Set up [Docker Compose](/mcp-front/deployment/docker-compose/) for complete stack
- Deploy to [Google Cloud Run](/mcp-front/deployment/cloud-run/)
- Configure [production settings](/mcp-front/deployment/production/)
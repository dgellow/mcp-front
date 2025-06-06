---
title: Environment Variables
description: Configure MCP Front using environment variables
---

import { Aside, Code, Tabs, TabItem } from '@astrojs/starlight/components';

Environment variables provide flexible configuration for MCP Front across different deployment environments.

## Core Environment Variables

### Application Settings

| Variable | Description | Default | Example |
|----------|-------------|---------|----------|
| `MCP_FRONT_ENV` | Environment mode | `production` | `development` |
| `LOG_LEVEL` | Logging verbosity | `info` | `debug`, `warn`, `error` |
| `LOG_FORMAT` | Log output format | `json` | `text` |
| `PORT` | Server port | `8080` | `3000` |
| `HOST` | Server host | `0.0.0.0` | `localhost` |

### OAuth Configuration

| Variable | Description | Required | Example |
|----------|-------------|----------|----------|
| `GOOGLE_CLIENT_ID` | Google OAuth client ID | Yes (OAuth) | `123456.apps.googleusercontent.com` |
| `GOOGLE_CLIENT_SECRET` | Google OAuth client secret | Yes (OAuth) | `GOCSPX-...` |
| `JWT_SECRET` | JWT signing secret (32+ bytes) | Yes (OAuth) | `your-256-bit-secret-key` |
| `OAUTH_REDIRECT_URL` | OAuth callback URL | No | `https://mcp.company.com/oauth/callback` |

<Aside type="danger">
  `JWT_SECRET` must be at least 32 bytes for HMAC-SHA512/256. Generate with: `openssl rand -base64 32`
</Aside>

### Firestore Configuration

| Variable | Description | Default | Example |
|----------|-------------|---------|----------|
| `FIRESTORE_PROJECT_ID` | GCP project ID | - | `my-project-123` |
| `FIRESTORE_DATABASE` | Database name | `(default)` | `mcp-production` |
| `FIRESTORE_COLLECTION` | Collection name | `mcp_front_oauth_clients` | `oauth_clients` |
| `GOOGLE_APPLICATION_CREDENTIALS` | Service account key path | - | `/secrets/gcp-key.json` |

## Setting Environment Variables

### Local Development

Create a `.env` file:

```bash
# .env
MCP_FRONT_ENV=development
LOG_LEVEL=debug
LOG_FORMAT=text

# OAuth
GOOGLE_CLIENT_ID=your-dev-client-id
GOOGLE_CLIENT_SECRET=your-dev-secret
JWT_SECRET=your-development-jwt-secret-minimum-32-bytes

# Bearer tokens
DEV_TOKEN=dev-token-123
TEST_TOKEN=test-token-456
```

Load with:
```bash
source .env
./mcp-front -config config.json
```

### Docker Compose

```yaml
services:
  mcp-front:
    image: mcp-front:latest
    environment:
      - MCP_FRONT_ENV=production
      - LOG_LEVEL=info
      - GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
      - GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}
      - JWT_SECRET=${JWT_SECRET}
      - FIRESTORE_PROJECT_ID=${GCP_PROJECT_ID}
    env_file:
      - .env.production
```

### Kubernetes

<Tabs>
<TabItem label="ConfigMap">
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: mcp-front-config
data:
  MCP_FRONT_ENV: "production"
  LOG_LEVEL: "info"
  LOG_FORMAT: "json"
  FIRESTORE_DATABASE: "mcp-production"
```
</TabItem>
<TabItem label="Secret">
```yaml
apiVersion: v1
kind: Secret
metadata:
  name: mcp-front-secrets
type: Opaque
stringData:
  GOOGLE_CLIENT_ID: "your-client-id"
  GOOGLE_CLIENT_SECRET: "your-client-secret"
  JWT_SECRET: "your-jwt-secret-minimum-32-bytes"
```
</TabItem>
<TabItem label="Deployment">
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-front
spec:
  template:
    spec:
      containers:
      - name: mcp-front
        envFrom:
        - configMapRef:
            name: mcp-front-config
        - secretRef:
            name: mcp-front-secrets
```
</TabItem>
</Tabs>

## Environment-Specific Behavior

### Development Mode

When `MCP_FRONT_ENV=development`:

- Relaxed OAuth validation
- Lower state parameter entropy (0 bits)
- Detailed error messages
- CORS restrictions may be relaxed
- Token expiry warnings in logs

```bash
export MCP_FRONT_ENV=development
export LOG_LEVEL=debug
./mcp-front -config config.dev.json
```

### Production Mode

When `MCP_FRONT_ENV=production` (default):

- Strict OAuth validation
- High state parameter entropy (8+ bytes)
- Generic error messages
- Strict CORS policy
- Performance optimizations enabled

```bash
export MCP_FRONT_ENV=production
export LOG_LEVEL=info
export LOG_FORMAT=json
./mcp-front -config config.prod.json
```

## Dynamic Configuration

### Using Environment Variables in Config

Reference environment variables with `$env:` syntax:

```json
{
  "proxy": {
    "auth": {
      "tokens": {
        "dev": "$env:DEV_TOKEN",
        "prod": "$env:PROD_TOKEN|default-token"
      }
    }
  },
  "mcpServers": {
    "database": {
      "env": {
        "DATABASE_URL": "$env:DATABASE_URL",
        "API_KEY": "$env:API_KEY|default-key"
      }
    }
  }
}
```

### Default Values

Provide fallbacks with `|` separator:

```json
{
  "env": {
    "PORT": "$env:PORT|8080",
    "HOST": "$env:HOST|0.0.0.0",
    "TIMEOUT": "$env:TIMEOUT|30s"
  }
}
```

## Cloud Provider Integration

### Google Cloud Run

```yaml
apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: mcp-front
spec:
  template:
    metadata:
      annotations:
        run.googleapis.com/cpu-throttling: "false"
    spec:
      containers:
      - image: gcr.io/PROJECT/mcp-front
        env:
        - name: MCP_FRONT_ENV
          value: "production"
        - name: GOOGLE_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: oauth-config
              key: client-id
```

### AWS ECS

```json
{
  "family": "mcp-front",
  "containerDefinitions": [{
    "name": "mcp-front",
    "environment": [
      {"name": "MCP_FRONT_ENV", "value": "production"},
      {"name": "LOG_FORMAT", "value": "json"}
    ],
    "secrets": [
      {
        "name": "GOOGLE_CLIENT_ID",
        "valueFrom": "arn:aws:secretsmanager:region:account:secret:oauth-config:client-id::"
      }
    ]
  }]
}
```

### Azure Container Instances

```yaml
apiVersion: 2021-09-01
location: eastus
name: mcp-front
properties:
  containers:
  - name: mcp-front
    properties:
      environmentVariables:
      - name: MCP_FRONT_ENV
        value: production
      - name: GOOGLE_CLIENT_ID
        secureValue: <from-key-vault>
```

## Security Best Practices

### 1. Never Commit Secrets

<Aside type="danger">
  Never commit `.env` files or secrets to version control. Add to `.gitignore`:
  ```
  .env
  .env.*
  !.env.example
  ```
</Aside>

### 2. Use Secret Management

<Tabs>
<TabItem label="Google Secret Manager">
```bash
# Store secret
gcloud secrets create jwt-secret \
  --data-file=- <<< "your-secret-value"

# Reference in Cloud Run
gcloud run deploy mcp-front \
  --update-secrets JWT_SECRET=jwt-secret:latest
```
</TabItem>
<TabItem label="AWS Secrets Manager">
```bash
# Store secret
aws secretsmanager create-secret \
  --name mcp-front/jwt-secret \
  --secret-string "your-secret-value"

# Reference in ECS
"secrets": [{
  "name": "JWT_SECRET",
  "valueFrom": "arn:aws:secretsmanager:..."
}]
```
</TabItem>
<TabItem label="Kubernetes Secrets">
```bash
# Create secret
kubectl create secret generic mcp-secrets \
  --from-literal=JWT_SECRET="your-secret-value"

# Mount in pod
envFrom:
- secretRef:
    name: mcp-secrets
```
</TabItem>
</Tabs>

### 3. Rotate Secrets Regularly

Implement secret rotation:

```bash
# Generate new JWT secret
NEW_SECRET=$(openssl rand -base64 32)

# Update in stages
1. Add new secret alongside old
2. Deploy with both secrets
3. Migrate clients to new secret
4. Remove old secret
```

### 4. Audit Environment Access

```bash
# Log environment variable access
export LOG_LEVEL=debug
export AUDIT_ENV_ACCESS=true
```

## Troubleshooting

### Missing Environment Variables

```bash
# Check if variable is set
if [ -z "$GOOGLE_CLIENT_ID" ]; then
  echo "ERROR: GOOGLE_CLIENT_ID not set"
  exit 1
fi

# List all MCP_FRONT variables
env | grep MCP_FRONT
```

### Variable Not Loading

1. Check spelling and case sensitivity
2. Verify `.env` file location
3. Ensure proper quoting for special characters
4. Check for trailing spaces

### Docker Environment Issues

```bash
# Debug environment in container
docker run --rm mcp-front:latest env | sort

# Pass environment file
docker run --env-file .env mcp-front:latest
```

## Example Configurations

### Minimal Development

```bash
export MCP_FRONT_ENV=development
export LOG_LEVEL=debug
export DEV_TOKEN=test-123
./mcp-front -config config.json
```

### Full Production

<Code code={`#!/bin/bash
# production.sh

# Core settings
export MCP_FRONT_ENV=production
export LOG_LEVEL=info
export LOG_FORMAT=json
export PORT=8080
export HOST=0.0.0.0

# OAuth configuration
export GOOGLE_CLIENT_ID="123456.apps.googleusercontent.com"
export GOOGLE_CLIENT_SECRET="GOCSPX-..."
export JWT_SECRET="$(cat /secrets/jwt-secret)"
export OAUTH_REDIRECT_URL="https://mcp.company.com/oauth/callback"

# Firestore configuration
export FIRESTORE_PROJECT_ID="my-project"
export FIRESTORE_DATABASE="production"
export FIRESTORE_COLLECTION="oauth_clients"
export GOOGLE_APPLICATION_CREDENTIALS="/secrets/gcp-key.json"

# Start server
exec ./mcp-front -config /config/production.json`} lang="bash" title="production.sh" />

## Next Steps

- Configure [MCP Servers](/mcp-front/config/mcp-servers/)
- Set up [Docker deployment](/mcp-front/deployment/docker-compose/)
- Review [Security best practices](/mcp-front/oauth/security/)
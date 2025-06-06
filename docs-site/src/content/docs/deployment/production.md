---
title: Production Deployment Guide
description: Best practices for deploying MCP Front in production
---

import { Aside, Code, Tabs, TabItem } from '@astrojs/starlight/components';

This guide covers best practices and requirements for deploying MCP Front in production environments.

## Production Checklist

### Security Requirements

- [ ] **OAuth 2.1 Authentication** configured (not bearer tokens)
- [ ] **HTTPS/TLS** enabled with valid certificates
- [ ] **JWT Secret** is at least 32 bytes
- [ ] **Firestore** configured for persistent storage
- [ ] **Environment variables** stored securely
- [ ] **CORS** properly configured
- [ ] **Rate limiting** implemented
- [ ] **Security headers** configured

### Infrastructure Requirements

- [ ] **High availability** with multiple instances
- [ ] **Load balancing** configured
- [ ] **Health checks** implemented
- [ ] **Monitoring** and alerting set up
- [ ] **Logging** centralized and searchable
- [ ] **Backup strategy** implemented
- [ ] **Disaster recovery** plan documented
- [ ] **Auto-scaling** configured

### Performance Requirements

- [ ] **Resource limits** defined
- [ ] **Connection pooling** configured
- [ ] **Caching strategy** implemented
- [ ] **CDN** for static assets
- [ ] **Compression** enabled
- [ ] **Keep-alive** connections configured

## Security Configuration

### OAuth 2.1 Setup

<Code code={`{
  "proxy": {
    "auth": {
      "kind": "oauth",
      "issuer": "https://mcp.company.com",
      "allowedDomains": ["company.com"],
      "jwtSecret": "$env:JWT_SECRET",
      "googleClientId": "$env:GOOGLE_CLIENT_ID",
      "googleClientSecret": "$env:GOOGLE_CLIENT_SECRET",
      "storage": "firestore",
      "firestoreProjectId": "$env:GCP_PROJECT_ID",
      "firestoreDatabase": "production",
      "firestoreCollection": "oauth_clients",
      "sessionTimeout": "8h",
      "refreshTokenTimeout": "30d"
    }
  }
}`} lang="json" title="Production OAuth Configuration" />

<Aside type="danger">
  Never use bearer token authentication in production. It's only suitable for development.
</Aside>

### TLS/SSL Configuration

#### Nginx Reverse Proxy

<Code code={`server {
    listen 443 ssl http2;
    server_name mcp.company.com;
    
    # SSL Configuration
    ssl_certificate /etc/ssl/certs/mcp.company.com.crt;
    ssl_certificate_key /etc/ssl/private/mcp.company.com.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers HIGH:!aNULL:!MD5;
    ssl_prefer_server_ciphers on;
    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    
    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:;" always;
    
    # Proxy Configuration
    location / {
        proxy_pass http://mcp-front:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_cache_bypass $http_upgrade;
        
        # Timeouts
        proxy_connect_timeout 60s;
        proxy_send_timeout 60s;
        proxy_read_timeout 60s;
    }
    
    # SSE Configuration
    location ~ /(.+)/sse$ {
        proxy_pass http://mcp-front:8080;
        proxy_http_version 1.1;
        proxy_set_header Connection '';
        proxy_set_header Cache-Control 'no-cache';
        proxy_set_header X-Accel-Buffering 'no';
        proxy_buffering off;
        proxy_read_timeout 86400s;
        keepalive_timeout 86400s;
    }
}`} lang="nginx" title="/etc/nginx/sites-available/mcp-front" />

### Security Headers

Ensure these headers are set:

```nginx
# HSTS
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# Prevent clickjacking
X-Frame-Options: DENY

# Prevent MIME sniffing
X-Content-Type-Options: nosniff

# XSS Protection
X-XSS-Protection: 1; mode=block

# Referrer Policy
Referrer-Policy: strict-origin-when-cross-origin

# Content Security Policy
Content-Security-Policy: default-src 'self';
```

## High Availability Setup

### Multi-Region Deployment

<Tabs>
<TabItem label="Google Cloud">
```bash
# Deploy to multiple regions
for region in us-central1 europe-west1 asia-northeast1; do
  gcloud run deploy mcp-front \
    --image gcr.io/PROJECT/mcp-front:latest \
    --region $region \
    --platform managed
done

# Set up Global Load Balancer
gcloud compute url-maps create mcp-front-lb \
  --default-service mcp-front-neg
```
</TabItem>
<TabItem label="AWS">
```bash
# Deploy to multiple regions
for region in us-east-1 eu-west-1 ap-northeast-1; do
  aws ecs create-service \
    --cluster mcp-cluster \
    --service-name mcp-front \
    --task-definition mcp-front:latest \
    --desired-count 3 \
    --region $region
done

# Configure Route 53
aws route53 create-hosted-zone \
  --name mcp.company.com
```
</TabItem>
<TabItem label="Kubernetes">
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-front
  labels:
    app: mcp-front
spec:
  replicas: 3
  selector:
    matchLabels:
      app: mcp-front
  template:
    metadata:
      labels:
        app: mcp-front
    spec:
      affinity:
        podAntiAffinity:
          requiredDuringSchedulingIgnoredDuringExecution:
          - labelSelector:
              matchExpressions:
              - key: app
                operator: In
                values:
                - mcp-front
            topologyKey: kubernetes.io/hostname
      containers:
      - name: mcp-front
        image: mcp-front:latest
        resources:
          requests:
            memory: "512Mi"
            cpu: "500m"
          limits:
            memory: "1Gi"
            cpu: "1000m"
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 30
        readinessProbe:
          httpGet:
            path: /ready
            port: 8080
          initialDelaySeconds: 5
          periodSeconds: 10
```
</TabItem>
</Tabs>

### Database Configuration

#### Firestore Production Setup

```bash
# Create production database
gcloud firestore databases create \
  --database=production \
  --location=nam5 \
  --type=firestore-native

# Enable point-in-time recovery
gcloud firestore databases update production \
  --enable-pitr

# Set up automated backups
gcloud firestore backups schedules create \
  --database=production \
  --recurrence=daily \
  --retention=7d
```

#### Connection Pooling

```go
// Internal configuration for connection pooling
firestoreClient.Settings = firestore.Settings{
    MaxConns:           100,
    MaxIdleConns:       10,
    ConnMaxLifetime:    time.Hour,
    ConnMaxIdleTime:    time.Minute * 10,
}
```

## Monitoring and Observability

### Prometheus Metrics

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'mcp-front'
    static_configs:
      - targets: ['mcp-front:8080']
    metrics_path: '/metrics'
```

### Grafana Dashboard

<Code code={`{
  "dashboard": {
    "title": "MCP Front Production",
    "panels": [
      {
        "title": "Request Rate",
        "targets": [{
          "expr": "rate(http_requests_total[5m])"
        }]
      },
      {
        "title": "Error Rate",
        "targets": [{
          "expr": "rate(http_requests_total{status=~\"5..\|4..\"}[5m])"
        }]
      },
      {
        "title": "Response Time",
        "targets": [{
          "expr": "histogram_quantile(0.95, http_request_duration_seconds_bucket)"
        }]
      },
      {
        "title": "Active OAuth Sessions",
        "targets": [{
          "expr": "oauth_active_sessions"
        }]
      }
    ]
  }
}`} lang="json" title="grafana-dashboard.json" />

### Logging Configuration

```json
{
  "logging": {
    "level": "info",
    "format": "json",
    "outputs": [
      {
        "type": "stdout",
        "format": "json"
      },
      {
        "type": "file",
        "path": "/var/log/mcp-front/app.log",
        "rotate": true,
        "maxSize": "100MB",
        "maxAge": "7d",
        "compress": true
      }
    ],
    "fields": [
      "timestamp",
      "level",
      "message",
      "request_id",
      "user_id",
      "method",
      "path",
      "status",
      "duration",
      "error"
    ]
  }
}
```

### Alerting Rules

<Code code={`groups:
  - name: mcp-front
    interval: 30s
    rules:
      - alert: HighErrorRate
        expr: rate(http_requests_total{status=~"5.."}[5m]) > 0.05
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "High error rate detected"
          description: "Error rate is {{ $value }} errors per second"
      
      - alert: HighResponseTime
        expr: histogram_quantile(0.95, http_request_duration_seconds_bucket) > 1
        for: 5m
        labels:
          severity: warning
        annotations:
          summary: "High response time detected"
          description: "95th percentile response time is {{ $value }} seconds"
      
      - alert: LowAvailability
        expr: up{job="mcp-front"} < 0.9
        for: 5m
        labels:
          severity: critical
        annotations:
          summary: "Service availability below 90%"
          description: "Only {{ $value }} instances are up"`} lang="yaml" title="alerting-rules.yml" />

## Performance Optimization

### Caching Strategy

```nginx
# Static asset caching
location /static/ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}

# API response caching
location /api/ {
    proxy_cache api_cache;
    proxy_cache_valid 200 1m;
    proxy_cache_valid 404 1m;
    proxy_cache_use_stale error timeout updating;
    add_header X-Cache-Status $upstream_cache_status;
}
```

### Resource Limits

```yaml
# Kubernetes resource limits
resources:
  requests:
    memory: "512Mi"
    cpu: "500m"
    ephemeral-storage: "1Gi"
  limits:
    memory: "1Gi"
    cpu: "1000m"
    ephemeral-storage: "2Gi"
```

### Connection Pooling

```json
{
  "server": {
    "maxConnections": 10000,
    "keepAliveTimeout": "120s",
    "readTimeout": "60s",
    "writeTimeout": "60s",
    "idleTimeout": "120s"
  }
}
```

## Disaster Recovery

### Backup Strategy

<Tabs>
<TabItem label="Firestore Backups">
```bash
# Daily backups
gcloud firestore backups schedules create daily-backup \
  --database=production \
  --recurrence="0 2 * * *" \
  --retention=30d

# Weekly backups
gcloud firestore backups schedules create weekly-backup \
  --database=production \
  --recurrence="0 3 * * 0" \
  --retention=90d

# Monthly backups
gcloud firestore backups schedules create monthly-backup \
  --database=production \
  --recurrence="0 4 1 * *" \
  --retention=365d
```
</TabItem>
<TabItem label="Configuration Backups">
```bash
#!/bin/bash
# backup-config.sh

BACKUP_DIR="/backups/mcp-front/$(date +%Y%m%d)"
mkdir -p $BACKUP_DIR

# Backup configurations
cp /config/*.json $BACKUP_DIR/

# Backup secrets (encrypted)
gcloud secrets versions access latest --secret="jwt-secret" | \
  gpg --encrypt -r backup@company.com > $BACKUP_DIR/jwt-secret.gpg

# Upload to cloud storage
gsutil -m cp -r $BACKUP_DIR gs://company-backups/mcp-front/
```
</TabItem>
</Tabs>

### Recovery Procedures

1. **Service Recovery**
   ```bash
   # Restore from backup
   kubectl apply -f backup/deployment.yaml
   kubectl rollout status deployment/mcp-front
   ```

2. **Database Recovery**
   ```bash
   # Restore Firestore
   gcloud firestore import gs://backups/firestore/2024-01-15
   ```

3. **Configuration Recovery**
   ```bash
   # Restore secrets
   kubectl create secret generic mcp-secrets \
     --from-file=backup/secrets/
   ```

## Compliance and Auditing

### Audit Logging

```json
{
  "audit": {
    "enabled": true,
    "events": [
      "auth.login",
      "auth.logout",
      "auth.token.create",
      "auth.token.revoke",
      "client.register",
      "client.update",
      "client.delete",
      "server.access"
    ],
    "storage": "firestore",
    "retention": "90d"
  }
}
```

### Compliance Checks

- [ ] GDPR compliance for EU users
- [ ] SOC 2 Type II certification
- [ ] HIPAA compliance (if handling health data)
- [ ] PCI DSS compliance (if handling payment data)
- [ ] Regular security audits
- [ ] Penetration testing

## Maintenance Procedures

### Rolling Updates

```bash
# Kubernetes rolling update
kubectl set image deployment/mcp-front \
  mcp-front=mcp-front:v2.0.0 \
  --record

# Monitor rollout
kubectl rollout status deployment/mcp-front

# Rollback if needed
kubectl rollout undo deployment/mcp-front
```

### Health Checks

```go
// Health check endpoint
GET /health
{
  "status": "healthy",
  "version": "1.0.0",
  "uptime": "48h32m15s",
  "checks": {
    "database": "ok",
    "oauth": "ok",
    "memory": "ok"
  }
}

// Readiness check
GET /ready
{
  "ready": true,
  "initialized": true,
  "dependencies": {
    "firestore": "connected",
    "oauth_provider": "reachable"
  }
}
```

## Production Environment Variables

<Code code={`# Required
export MCP_FRONT_ENV=production
export LOG_LEVEL=info
export LOG_FORMAT=json

# OAuth
export GOOGLE_CLIENT_ID="${GOOGLE_CLIENT_ID}"
export GOOGLE_CLIENT_SECRET="${GOOGLE_CLIENT_SECRET}"
export JWT_SECRET="${JWT_SECRET}"  # Must be 32+ bytes

# Firestore
export FIRESTORE_PROJECT_ID="${GCP_PROJECT_ID}"
export FIRESTORE_DATABASE=production
export FIRESTORE_COLLECTION=oauth_clients
export GOOGLE_APPLICATION_CREDENTIALS=/secrets/gcp-sa.json

# Performance
export GOMAXPROCS=4
export GOMEMLIMIT=900MiB

# Security
export ALLOWED_ORIGINS="https://mcp.company.com"
export SESSION_SECURE=true
export SESSION_HTTPONLY=true
export SESSION_SAMESITE=strict`} lang="bash" title="production.env" />

## Next Steps

- Set up [Monitoring and Alerting](/mcp-front/deployment/monitoring/)
- Review [Security Best Practices](/mcp-front/oauth/security/)
- Configure [Backup and Recovery](/mcp-front/deployment/backup/)
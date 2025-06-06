---
title: Firestore Storage Configuration
description: Configure Google Firestore for OAuth session storage
---

import { Aside, Code, Tabs, TabItem } from '@astrojs/starlight/components';

MCP Front uses Google Firestore as the primary storage backend for OAuth sessions and client data in production environments.

## Why Firestore?

- **Fully managed**: No infrastructure to maintain
- **Scalable**: Handles millions of sessions automatically
- **Real-time**: Instant session updates across instances
- **Secure**: Built-in encryption and IAM integration
- **Cost-effective**: Pay only for what you use

<Aside type="tip">
  Firestore is recommended for production. Use memory storage only for development.
</Aside>

## Setup Guide

### Step 1: Enable Firestore

```bash
# Enable Firestore API
gcloud services enable firestore.googleapis.com

# Create Firestore database (if not exists)
gcloud firestore databases create \
  --location=us-central \
  --type=firestore-native
```

### Step 2: Create Custom Database (Optional)

For better isolation, create a dedicated database:

```bash
# Create custom database for MCP Front
gcloud firestore databases create \
  --database=mcp-production \
  --location=us-central \
  --type=firestore-native
```

### Step 3: Configure MCP Front

<Code code={`{
  "proxy": {
    "auth": {
      "storage": "firestore",
      "firestoreProjectId": "$env:GOOGLE_CLOUD_PROJECT",
      "firestoreDatabase": "mcp-production",
      "firestoreCollection": "oauth_clients"
    }
  }
}`} lang="json" title="Firestore Configuration" />

## Configuration Options

| Field | Description | Default | Example |
|-------|-------------|---------|----------|
| `storage` | Storage type | `"memory"` | `"firestore"` |
| `firestoreProjectId` | GCP project ID | Current project | `"my-project-123"` |
| `firestoreDatabase` | Database name | `"(default)"` | `"mcp-production"` |
| `firestoreCollection` | Collection name | `"mcp_front_oauth_clients"` | `"oauth_sessions"` |

## Authentication Methods

### Application Default Credentials (Recommended)

<Tabs>
<TabItem label="Google Cloud Run">
```bash
# Automatic authentication via metadata service
# No configuration needed - uses service account attached to Cloud Run
gcloud run deploy mcp-front \
  --service-account mcp-front-sa@PROJECT.iam.gserviceaccount.com
```
</TabItem>
<TabItem label="Google Compute Engine">
```bash
# Uses instance service account
gcloud compute instances create mcp-front-vm \
  --service-account mcp-front-sa@PROJECT.iam.gserviceaccount.com \
  --scopes https://www.googleapis.com/auth/datastore
```
</TabItem>
<TabItem label="Local Development">
```bash
# Authenticate with gcloud
gcloud auth application-default login

# Or use service account key
export GOOGLE_APPLICATION_CREDENTIALS="/path/to/key.json"
```
</TabItem>
</Tabs>

### Service Account Setup

Create a dedicated service account:

```bash
# Create service account
gcloud iam service-accounts create mcp-front-sa \
  --display-name="MCP Front Service Account"

# Grant Firestore permissions
gcloud projects add-iam-policy-binding PROJECT_ID \
  --member="serviceAccount:mcp-front-sa@PROJECT_ID.iam.gserviceaccount.com" \
  --role="roles/datastore.user"

# Create key (only for local development)
gcloud iam service-accounts keys create key.json \
  --iam-account=mcp-front-sa@PROJECT_ID.iam.gserviceaccount.com
```

## Data Structure

### OAuth Clients Collection

```json
{
  "client_id": "abc123",
  "client_secret_hash": "$2a$10$...",
  "client_name": "Claude Desktop",
  "redirect_uris": [
    "http://localhost:3000/callback",
    "claude://callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scopes": ["openid", "profile", "email"],
  "created_at": "2024-01-15T10:00:00Z",
  "updated_at": "2024-01-15T10:00:00Z",
  "metadata": {
    "owner": "admin@company.com",
    "environment": "production"
  }
}
```

### Sessions Collection

```json
{
  "session_id": "sess_xyz789",
  "client_id": "abc123",
  "user_id": "user_456",
  "email": "user@company.com",
  "access_token_hash": "$2a$10$...",
  "refresh_token_hash": "$2a$10$...",
  "expires_at": "2024-01-15T18:00:00Z",
  "created_at": "2024-01-15T10:00:00Z",
  "last_accessed": "2024-01-15T14:30:00Z",
  "ip_address": "203.0.113.45",
  "user_agent": "Claude/1.0",
  "scopes": ["openid", "profile", "email"]
}
```

## Security Configuration

### Firestore Security Rules

<Code code={`rules_version = '2';
service cloud.firestore {
  match /databases/{database}/documents {
    // Deny all direct access
    match /{document=**} {
      allow read, write: if false;
    }
    
    // Only service accounts can access
    match /mcp_front_oauth_clients/{document=**} {
      allow read, write: if request.auth != null 
        && request.auth.token.email.matches(".*@.*\.iam\.gserviceaccount\.com$");
    }
  }
}`} lang="javascript" title="firestore.rules" />

### Encryption

Firestore provides encryption at rest and in transit:

1. **At Rest**: AES256 encryption by default
2. **In Transit**: TLS 1.2+ for all connections
3. **Additional**: Application-level encryption for sensitive fields

```go
// Tokens are hashed before storage
hashedToken := bcrypt.GenerateFromPassword(token, bcrypt.DefaultCost)
```

## Performance Optimization

### Indexes

Create composite indexes for common queries:

<Code code={`// firestore.indexes.json
{
  "indexes": [
    {
      "collectionGroup": "oauth_sessions",
      "queryScope": "COLLECTION",
      "fields": [
        { "fieldPath": "email", "order": "ASCENDING" },
        { "fieldPath": "created_at", "order": "DESCENDING" }
      ]
    },
    {
      "collectionGroup": "oauth_sessions",
      "queryScope": "COLLECTION",
      "fields": [
        { "fieldPath": "expires_at", "order": "ASCENDING" },
        { "fieldPath": "client_id", "order": "ASCENDING" }
      ]
    }
  ]
}`} lang="json" title="firestore.indexes.json" />

Deploy indexes:
```bash
gcloud firestore indexes create --file=firestore.indexes.json
```

### Batch Operations

MCP Front uses batch operations for efficiency:

```go
// Internal batch cleanup of expired sessions
batch := client.Batch()
for _, doc := range expiredDocs {
    batch.Delete(doc.Ref)
}
batch.Commit(ctx)
```

### Connection Pooling

Firestore client automatically manages connection pooling:

```go
// Configured internally
client.Settings = firestore.Settings{
    MaxConns:        100,
    MaxIdleConns:    10,
    ConnMaxLifetime: time.Hour,
}
```

## Monitoring

### Metrics to Track

1. **Operation Metrics**
   - Read/Write operations per second
   - Document count growth
   - Storage usage

2. **Performance Metrics**
   - Query latency (p50, p95, p99)
   - Transaction success rate
   - Connection pool utilization

3. **Cost Metrics**
   - Daily read/write operations
   - Storage costs
   - Network egress

### Cloud Monitoring Dashboard

```json
{
  "displayName": "MCP Front Firestore",
  "dashboardFilters": [
    {
      "filterType": "RESOURCE_LABEL",
      "labelKey": "database_id",
      "templateVariable": "DATABASE"
    }
  ],
  "widgets": [
    {
      "title": "Document Reads/Writes",
      "xyChart": {
        "dataSets": [{
          "timeSeriesQuery": {
            "timeSeriesFilter": {
              "filter": "metric.type=\"firestore.googleapis.com/document/read_count\""
            }
          }
        }]
      }
    }
  ]
}
```

### Alerts

```yaml
alertPolicy:
  displayName: "High Firestore Error Rate"
  conditions:
    - displayName: "Error rate > 1%"
      conditionThreshold:
        filter: |
          resource.type="firestore_database"
          metric.type="firestore.googleapis.com/api/request_count"
          metric.label."status"!="OK"
        comparison: COMPARISON_GT
        thresholdValue: 0.01
        duration: 300s
```

## Backup and Recovery

### Automated Backups

```bash
# Create backup schedule
gcloud firestore backups schedules create \
  --database=mcp-production \
  --recurrence=daily \
  --retention=7d

# Manual backup
gcloud firestore export gs://my-bucket/firestore-backup \
  --database=mcp-production \
  --collection-ids=mcp_front_oauth_clients
```

### Point-in-Time Recovery

Enable PITR for disaster recovery:

```bash
gcloud firestore databases update mcp-production \
  --enable-pitr
```

Restore to specific time:
```bash
gcloud firestore databases restore \
  --source-database=mcp-production \
  --destination-database=mcp-restored \
  --snapshot-time="2024-01-15T10:00:00Z"
```

## Cost Optimization

### Estimate Costs

| Operation | Free Tier | Price After |
|-----------|-----------|-------------|
| Document reads | 50K/day | $0.06 per 100K |
| Document writes | 20K/day | $0.18 per 100K |
| Document deletes | 20K/day | $0.02 per 100K |
| Storage | 1 GB | $0.18 per GB/month |

### Cost Reduction Strategies

1. **TTL for Sessions**
   ```go
   // Automatically delete expired sessions
   expiresAt := time.Now().Add(8 * time.Hour)
   ```

2. **Efficient Queries**
   ```go
   // Use projections to reduce data transfer
   query.Select("email", "expires_at")
   ```

3. **Batch Operations**
   ```go
   // Batch writes reduce operation count
   batch.Set(doc1, data1)
   batch.Set(doc2, data2)
   batch.Commit()
   ```

## Troubleshooting

### Permission Denied

```
rpc error: code = PermissionDenied desc = Missing or insufficient permissions
```

**Solutions**:
1. Check service account has `roles/datastore.user`
2. Verify project ID is correct
3. Ensure Firestore API is enabled

### Database Not Found

```
firestore: database "mcp-production" not found
```

**Solutions**:
1. Create database: `gcloud firestore databases create`
2. Check database name spelling
3. Verify region matches

### Connection Timeout

```
context deadline exceeded
```

**Solutions**:
1. Check network connectivity
2. Verify firewall rules
3. Increase timeout settings

## Migration from Memory Storage

### Step 1: Export Existing Data

```go
// Export in-memory sessions to JSON
data := memoryStore.ExportAll()
json.NewEncoder(file).Encode(data)
```

### Step 2: Import to Firestore

```bash
# Use import tool
mcp-migrate \
  --from memory \
  --to firestore \
  --project my-project \
  --database mcp-production
```

### Step 3: Update Configuration

```json
{
  "storage": "firestore",
  "firestoreProjectId": "my-project",
  "firestoreDatabase": "mcp-production"
}
```

### Step 4: Verify Migration

```bash
# Check document count
gcloud firestore operations list \
  --database=mcp-production
```

## Best Practices

1. **Use Dedicated Database** for MCP Front
2. **Enable PITR** for disaster recovery
3. **Set Up Monitoring** before issues arise
4. **Regular Backups** with tested restore process
5. **Index Optimization** for common queries
6. **Cost Alerts** to prevent surprises
7. **Security Rules** to prevent direct access
8. **Regional Deployment** for low latency

## Next Steps

- Review [Security Best Practices](/mcp-front/oauth/security/)
- Set up [Monitoring and Alerts](/mcp-front/deployment/monitoring/)
- Configure [Production Deployment](/mcp-front/deployment/production/)
---
title: Google Cloud Run Deployment
description: Deploy MCP Front to Google Cloud Run
---

import { Aside, Code, Tabs, TabItem } from '@astrojs/starlight/components';

Google Cloud Run provides a fully managed serverless platform for deploying MCP Front with automatic scaling and high availability.

## Prerequisites

- Google Cloud Project with billing enabled
- [gcloud CLI](https://cloud.google.com/sdk/docs/install) installed and configured
- Docker installed locally (for building images)
- Firestore API enabled (for OAuth storage)

```bash
# Enable required APIs
gcloud services enable run.googleapis.com
gcloud services enable firestore.googleapis.com
gcloud services enable secretmanager.googleapis.com
gcloud services enable artifactregistry.googleapis.com
```

## Quick Deploy

### 1. Build and Push Image

```bash
# Configure Docker for Artifact Registry
gcloud auth configure-docker REGION-docker.pkg.dev

# Build image
docker build -t REGION-docker.pkg.dev/PROJECT-ID/mcp-front/app:latest .

# Push to Artifact Registry
docker push REGION-docker.pkg.dev/PROJECT-ID/mcp-front/app:latest
```

### 2. Create Secrets

```bash
# OAuth secrets
echo -n "your-google-client-id" | gcloud secrets create google-client-id --data-file=-
echo -n "your-google-client-secret" | gcloud secrets create google-client-secret --data-file=-
echo -n "your-jwt-secret-minimum-32-bytes" | gcloud secrets create jwt-secret --data-file=-
```

### 3. Deploy to Cloud Run

```bash
gcloud run deploy mcp-front \
  --image REGION-docker.pkg.dev/PROJECT-ID/mcp-front/app:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --set-env-vars "MCP_FRONT_ENV=production,LOG_FORMAT=json" \
  --set-secrets "GOOGLE_CLIENT_ID=google-client-id:latest,GOOGLE_CLIENT_SECRET=google-client-secret:latest,JWT_SECRET=jwt-secret:latest" \
  --service-account mcp-front-sa@PROJECT-ID.iam.gserviceaccount.com
```

## Complete Deployment Guide

### Step 1: Service Account Setup

<Code code={`# Create service account
gcloud iam service-accounts create mcp-front-sa \
  --display-name="MCP Front Service Account"

# Grant Firestore permissions
gcloud projects add-iam-policy-binding PROJECT-ID \
  --member="serviceAccount:mcp-front-sa@PROJECT-ID.iam.gserviceaccount.com" \
  --role="roles/datastore.user"

# Grant Secret Manager permissions
gcloud projects add-iam-policy-binding PROJECT-ID \
  --member="serviceAccount:mcp-front-sa@PROJECT-ID.iam.gserviceaccount.com" \
  --role="roles/secretmanager.secretAccessor"`} lang="bash" title="setup-service-account.sh" />

### Step 2: Firestore Setup

```bash
# Create Firestore database (if not exists)
gcloud firestore databases create \
  --location=us-central \
  --type=firestore-native

# Create custom database for MCP Front
gcloud firestore databases create \
  --location=us-central \
  --type=firestore-native \
  --database=mcp-production
```

### Step 3: Configuration File

Create a configuration file for Cloud Run:

<Code code={`{
  "version": "1.0",
  "proxy": {
    "name": "Company MCP Proxy",
    "baseUrl": "https://mcp-front-xyz123-uc.a.run.app",
    "addr": ":8080",
    "auth": {
      "kind": "oauth",
      "issuer": "https://mcp-front-xyz123-uc.a.run.app",
      "allowedDomains": ["company.com"],
      "jwtSecret": "$env:JWT_SECRET",
      "googleClientId": "$env:GOOGLE_CLIENT_ID",
      "googleClientSecret": "$env:GOOGLE_CLIENT_SECRET",
      "storage": "firestore",
      "firestoreProjectId": "$env:GOOGLE_CLOUD_PROJECT",
      "firestoreDatabase": "mcp-production",
      "firestoreCollection": "oauth_clients"
    }
  },
  "mcpServers": {
    "database": {
      "url": "https://postgres-mcp-xyz456-uc.a.run.app/sse"
    }
  }
}`} lang="json" title="config/cloud-run.json" />

### Step 4: Advanced Deployment

<Code code={`# Build with Cloud Build
gcloud builds submit \
  --tag REGION-docker.pkg.dev/PROJECT-ID/mcp-front/app:latest

# Deploy with all configurations
gcloud run deploy mcp-front \
  --image REGION-docker.pkg.dev/PROJECT-ID/mcp-front/app:latest \
  --platform managed \
  --region us-central1 \
  --allow-unauthenticated \
  --service-account mcp-front-sa@PROJECT-ID.iam.gserviceaccount.com \
  --set-env-vars "MCP_FRONT_ENV=production,LOG_FORMAT=json,LOG_LEVEL=info" \
  --set-secrets "GOOGLE_CLIENT_ID=google-client-id:latest,GOOGLE_CLIENT_SECRET=google-client-secret:latest,JWT_SECRET=jwt-secret:latest" \
  --max-instances 10 \
  --min-instances 1 \
  --cpu 1 \
  --memory 512Mi \
  --timeout 300 \
  --concurrency 1000 \
  --cpu-throttling \
  --execution-environment gen2`} lang="bash" title="deploy-production.sh" />

## Cloud Run Service Configuration

### Using service.yaml

<Code code={`apiVersion: serving.knative.dev/v1
kind: Service
metadata:
  name: mcp-front
  annotations:
    run.googleapis.com/launch-stage: BETA
spec:
  template:
    metadata:
      annotations:
        run.googleapis.com/execution-environment: gen2
        run.googleapis.com/cpu-throttling: "true"
        run.googleapis.com/startup-cpu-boost: "true"
    spec:
      serviceAccountName: mcp-front-sa@PROJECT-ID.iam.gserviceaccount.com
      containerConcurrency: 1000
      timeoutSeconds: 300
      containers:
      - image: REGION-docker.pkg.dev/PROJECT-ID/mcp-front/app:latest
        ports:
        - containerPort: 8080
        env:
        - name: MCP_FRONT_ENV
          value: "production"
        - name: LOG_FORMAT
          value: "json"
        - name: LOG_LEVEL
          value: "info"
        - name: GOOGLE_CLOUD_PROJECT
          value: "PROJECT-ID"
        - name: GOOGLE_CLIENT_ID
          valueFrom:
            secretKeyRef:
              name: google-client-id
              key: latest
        - name: GOOGLE_CLIENT_SECRET
          valueFrom:
            secretKeyRef:
              name: google-client-secret
              key: latest
        - name: JWT_SECRET
          valueFrom:
            secretKeyRef:
              name: jwt-secret
              key: latest
        resources:
          limits:
            cpu: "2"
            memory: "1Gi"
          requests:
            cpu: "1"
            memory: "512Mi"
        startupProbe:
          httpGet:
            path: /health
            port: 8080
          periodSeconds: 10
          failureThreshold: 3
        livenessProbe:
          httpGet:
            path: /health
            port: 8080
          periodSeconds: 30
        volumeMounts:
        - name: config
          mountPath: /config
          readOnly: true
      volumes:
      - name: config
        secret:
          secretName: mcp-front-config
  traffic:
  - percent: 100
    latestRevision: true`} lang="yaml" title="service.yaml" />

Deploy with:
```bash
gcloud run services replace service.yaml --region us-central1
```

## Custom Domain Setup

### 1. Map Custom Domain

```bash
# Add domain mapping
gcloud run domain-mappings create \
  --service mcp-front \
  --domain mcp.company.com \
  --region us-central1
```

### 2. Update DNS Records

Add the provided DNS records to your domain:

```
Type: A
Name: mcp
Value: [IP addresses from Cloud Run]

Type: AAAA  
Name: mcp
Value: [IPv6 addresses from Cloud Run]
```

### 3. Update Configuration

Update `baseUrl` and `issuer` in your config:

```json
{
  "proxy": {
    "baseUrl": "https://mcp.company.com",
    "auth": {
      "issuer": "https://mcp.company.com"
    }
  }
}
```

## CI/CD with Cloud Build

### cloudbuild.yaml

<Code code={`steps:
  # Build the Docker image
  - name: 'gcr.io/cloud-builders/docker'
    args: ['build', '-t', 'REGION-docker.pkg.dev/$PROJECT_ID/mcp-front/app:$COMMIT_SHA', '.']
  
  # Push to Artifact Registry
  - name: 'gcr.io/cloud-builders/docker'
    args: ['push', 'REGION-docker.pkg.dev/$PROJECT_ID/mcp-front/app:$COMMIT_SHA']
  
  # Deploy to Cloud Run
  - name: 'gcr.io/google.com/cloudsdktool/cloud-sdk'
    entrypoint: gcloud
    args:
    - 'run'
    - 'deploy'
    - 'mcp-front'
    - '--image'
    - 'REGION-docker.pkg.dev/$PROJECT_ID/mcp-front/app:$COMMIT_SHA'
    - '--region'
    - 'us-central1'
    - '--platform'
    - 'managed'

# Store images in Artifact Registry
images:
  - 'REGION-docker.pkg.dev/$PROJECT_ID/mcp-front/app:$COMMIT_SHA'
  - 'REGION-docker.pkg.dev/$PROJECT_ID/mcp-front/app:latest'

# Timeout for the entire build
timeout: '1200s'`} lang="yaml" title="cloudbuild.yaml" />

### GitHub Actions Integration

<Code code={`name: Deploy to Cloud Run

on:
  push:
    branches: [main]

env:
  PROJECT_ID: your-project-id
  REGION: us-central1
  SERVICE: mcp-front

jobs:
  deploy:
    runs-on: ubuntu-latest
    
    permissions:
      contents: read
      id-token: write
    
    steps:
    - uses: actions/checkout@v4
    
    - id: auth
      uses: google-github-actions/auth@v2
      with:
        workload_identity_provider: ${{ secrets.WIF_PROVIDER }}
        service_account: ${{ secrets.WIF_SERVICE_ACCOUNT }}
    
    - name: Set up Cloud SDK
      uses: google-github-actions/setup-gcloud@v2
    
    - name: Configure Docker
      run: gcloud auth configure-docker ${{ env.REGION }}-docker.pkg.dev
    
    - name: Build and Push
      run: |
        docker build -t ${{ env.REGION }}-docker.pkg.dev/${{ env.PROJECT_ID }}/mcp-front/app:${{ github.sha }} .
        docker push ${{ env.REGION }}-docker.pkg.dev/${{ env.PROJECT_ID }}/mcp-front/app:${{ github.sha }}
    
    - name: Deploy to Cloud Run
      run: |
        gcloud run deploy ${{ env.SERVICE }} \
          --image ${{ env.REGION }}-docker.pkg.dev/${{ env.PROJECT_ID }}/mcp-front/app:${{ github.sha }} \
          --region ${{ env.REGION }} \
          --platform managed`} lang="yaml" title=".github/workflows/deploy-cloud-run.yml" />

## Monitoring and Logging

### View Logs

```bash
# Stream logs
gcloud logging read "resource.type=cloud_run_revision \
  AND resource.labels.service_name=mcp-front" \
  --limit 50 \
  --format json

# View in Cloud Console
gcloud run services logs read mcp-front --region us-central1
```

### Set Up Alerts

```bash
# Create alert policy for errors
gcloud alpha monitoring policies create \
  --notification-channels=CHANNEL_ID \
  --display-name="MCP Front Error Rate" \
  --condition="{...}"
```

### Export Metrics

```bash
# Enable Cloud Run metrics
gcloud services enable monitoring.googleapis.com

# View metrics
gcloud monitoring dashboards create --config-from-file=dashboard.yaml
```

## Security Best Practices

### 1. Enable Binary Authorization

```bash
gcloud container binauthz policy import policy.yaml
```

### 2. Configure VPC Connector

```bash
# Create VPC connector
gcloud compute networks vpc-access connectors create mcp-connector \
  --network default \
  --region us-central1 \
  --range 10.8.0.0/28

# Update service
gcloud run services update mcp-front \
  --vpc-connector mcp-connector \
  --region us-central1
```

### 3. Enable Cloud Armor

```bash
# Create security policy
gcloud compute security-policies create mcp-front-policy \
  --description "Security policy for MCP Front"

# Add rules
gcloud compute security-policies rules create 1000 \
  --security-policy mcp-front-policy \
  --expression "origin.region_code == 'US'"
  --action "allow"
```

## Cost Optimization

### 1. Set Maximum Instances

```bash
gcloud run services update mcp-front \
  --max-instances 5 \
  --region us-central1
```

### 2. Configure CPU Allocation

```bash
gcloud run services update mcp-front \
  --cpu-throttling \
  --cpu 1 \
  --memory 512Mi \
  --region us-central1
```

### 3. Use Minimum Instances Wisely

```bash
# Set to 0 for development
gcloud run services update mcp-front-dev \
  --min-instances 0 \
  --region us-central1

# Keep 1 for production
gcloud run services update mcp-front \
  --min-instances 1 \
  --region us-central1
```

## Troubleshooting

### Service Not Starting

```bash
# Check deployment status
gcloud run services describe mcp-front --region us-central1

# View revision logs
gcloud run revisions logs read --service mcp-front --region us-central1
```

### Authentication Issues

1. Verify secrets are accessible:
```bash
gcloud secrets versions access latest --secret="jwt-secret"
```

2. Check service account permissions:
```bash
gcloud projects get-iam-policy PROJECT-ID \
  --flatten="bindings[].members" \
  --filter="bindings.members:mcp-front-sa@"
```

### Performance Issues

1. Check cold start times:
```bash
gcloud logging read "textPayload:\"Cold start\"" --limit 10
```

2. Increase resources:
```bash
gcloud run services update mcp-front \
  --cpu 2 \
  --memory 1Gi \
  --region us-central1
```

<Aside type="tip">
  Use `--cpu-boost` flag for faster cold starts in production.
</Aside>

## Next Steps

- Configure [Production settings](/mcp-front/deployment/production/)
- Set up [Monitoring](/mcp-front/deployment/monitoring/)
- Review [Security best practices](/mcp-front/oauth/security/)
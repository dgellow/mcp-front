---
title: Google Workspace Integration
description: Configure Google OAuth for your organization
---

import { Aside, Code } from '@astrojs/starlight/components';

MCP Front integrates with Google Workspace to provide seamless authentication for your organization's users.

## Prerequisites

- Google Workspace admin access
- Verified domain ownership
- Google Cloud Project with billing enabled

## Setup Guide

<Aside type="danger" title="CRITICAL: Manual OAuth Client Creation Required">
  **You MUST create the OAuth 2.0 client manually in the Google Cloud Console.**
  
  This is the ONLY way to get the OAuth web flow (SSO) working properly. Do NOT try to:
  - Create OAuth clients programmatically via API
  - Use service accounts for user authentication  
  - Use Application Default Credentials
  - Generate credentials via gcloud CLI
  
  Google requires manual OAuth client creation through their web console for the authorization code flow with user consent.
</Aside>

### Step 1: Create Google Cloud Project

1. Go to [Google Cloud Console](https://console.cloud.google.com)
2. Create a new project or select existing
3. Enable required APIs:

```bash
gcloud services enable iap.googleapis.com
gcloud services enable oauth2.googleapis.com
gcloud services enable cloudidentity.googleapis.com
```

### Step 2: Configure OAuth Consent Screen

1. Navigate to **APIs & Services > OAuth consent screen**
2. Select **Internal** for organization-only access
3. Fill in the application details:

| Field | Value |
|-------|-------|
| App name | MCP Front |
| User support email | it@company.com |
| App domain | mcp.company.com |
| Authorized domains | company.com |
| Developer contact | dev@company.com |

4. Add scopes:
   - `openid`
   - `email`
   - `profile`

<Aside type="tip">
  Choose "Internal" app type to restrict access to your organization only.
</Aside>

### Step 3: Create OAuth Client (MANUAL PROCESS REQUIRED)

<Aside type="caution">
  This step MUST be done manually in the Google Cloud Console web interface. There is no way around this requirement for OAuth web applications.
</Aside>

1. Go to **APIs & Services > Credentials**
2. Click **Create Credentials > OAuth client ID**
3. Configure the client:

```
Application type: Web application
Name: MCP Front Production

Authorized JavaScript origins:
- https://mcp.company.com

Authorized redirect URIs:
- https://mcp.company.com/oauth/callback
- https://mcp.company.com/oauth/authorize/callback
```

4. Save the client ID and secret

### Step 4: Configure MCP Front

Update your configuration:

<Code code={`{
  "proxy": {
    "auth": {
      "kind": "oauth",
      "issuer": "https://mcp.company.com",
      "allowedDomains": ["company.com"],
      "googleClientId": "123456789.apps.googleusercontent.com",
      "googleClientSecret": "GOCSPX-...",
      "jwtSecret": "your-32-byte-minimum-secret",
      "storage": "firestore",
      "firestoreProjectId": "company-mcp-project"
    }
  }
}`} lang="json" title="config.json" />

## Domain Restrictions

### Single Domain

Restrict access to your primary domain:

```json
{
  "allowedDomains": ["company.com"]
}
```

### Multiple Domains

Support multiple domains or subsidiaries:

```json
{
  "allowedDomains": [
    "company.com",
    "subsidiary.com",
    "contractors.company.com"
  ]
}
```

### Domain Validation

MCP Front validates the email domain during authentication:

```go
// Internal validation logic
if !isAllowedDomain(userEmail) {
    return error("Access denied: unauthorized domain")
}
```

## Google Workspace Settings

### Configure SAML App (Optional)

For additional security, configure as SAML app:

1. In Google Admin Console, go to **Apps > Web and mobile apps**
2. Click **Add app > Add custom SAML app**
3. Configure SAML settings:

```
ACS URL: https://mcp.company.com/saml/acs
Entity ID: https://mcp.company.com
Start URL: https://mcp.company.com
```

### Set Organization Policies

1. **Enforce 2-Step Verification**
   ```
   Security > Authentication > 2-Step Verification
   ✓ Enforce 2-Step Verification
   ```

2. **Configure Session Length**
   ```
   Security > Google session control
   Web session duration: 8 hours
   ```

3. **Set Access Restrictions**
   ```
   Apps > Additional Google services
   MCP Front: ON for selected organizational units
   ```

## Advanced Configurations

### Organizational Unit Restrictions

Limit access to specific OUs:

<Code code={`{
  "proxy": {
    "auth": {
      "allowedDomains": ["company.com"],
      "allowedOUs": [
        "/Engineering",
        "/DataScience",
        "/IT/DevOps"
      ]
    }
  }
}`} lang="json" title="OU-based restrictions" />

### Group-Based Access

Restrict to Google Groups:

<Code code={`{
  "proxy": {
    "auth": {
      "allowedDomains": ["company.com"],
      "allowedGroups": [
        "mcp-users@company.com",
        "engineering@company.com"
      ],
      "groupCheckInterval": "5m"
    }
  }
}`} lang="json" title="Group-based restrictions" />

### Custom Claims

Add custom claims to JWT tokens:

<Code code={`{
  "proxy": {
    "auth": {
      "customClaims": {
        "department": "${user.department}",
        "manager": "${user.manager}",
        "cost_center": "${user.costCenter}"
      }
    }
  }
}`} lang="json" title="Custom JWT claims" />

## User Management

### Provisioning Users

Users are automatically provisioned on first login:

1. User authenticates with Google
2. MCP Front validates domain
3. Session created in Firestore
4. Access granted to MCP servers

### Deprovisioning Users

When users are suspended in Google Workspace:

1. Authentication fails immediately
2. Existing sessions remain valid until expiry
3. Refresh tokens stop working

To force logout suspended users:

```bash
# Implement session revocation webhook
POST /admin/revoke-sessions
{
  "email": "suspended-user@company.com"
}
```

### Admin Controls

<Code code={`{
  "proxy": {
    "auth": {
      "adminUsers": [
        "admin@company.com",
        "security@company.com"
      ],
      "adminFeatures": {
        "viewAllSessions": true,
        "revokeAnySessions": true,
        "manageClients": true,
        "viewAuditLogs": true
      }
    }
  }
}`} lang="json" title="Admin configuration" />

## Security Best Practices

### 1. IP Restrictions

Limit access to corporate networks:

```json
{
  "proxy": {
    "auth": {
      "allowedIPs": [
        "203.0.113.0/24",
        "198.51.100.0/24"
      ],
      "allowVPN": true
    }
  }
}
```

### 2. Device Policies

Require managed devices:

```json
{
  "proxy": {
    "auth": {
      "requireManagedDevice": true,
      "deviceTrustProvider": "beyond-corp"
    }
  }
}
```

### 3. Context-Aware Access

Implement additional checks:

```json
{
  "proxy": {
    "auth": {
      "contextChecks": {
        "requireCorpNetwork": true,
        "blockCountries": ["XX", "YY"],
        "requireUpdatedOS": true
      }
    }
  }
}
```

## Monitoring Integration

### Google Workspace Audit Logs

MCP Front events appear in Google Workspace audit logs:

```
Event: Login to third-party application
Application: MCP Front
User: user@company.com
IP Address: 203.0.113.45
Result: Success
```

### Export to BigQuery

1. Enable audit log export in Google Admin
2. Configure BigQuery dataset
3. Query MCP Front usage:

```sql
SELECT
  email,
  COUNT(*) as login_count,
  ARRAY_AGG(DISTINCT ip_address) as ip_addresses
FROM `project.audit_logs.activity`
WHERE
  application_name = 'MCP Front'
  AND time > TIMESTAMP_SUB(CURRENT_TIMESTAMP(), INTERVAL 7 DAY)
GROUP BY email
ORDER BY login_count DESC
```

## Common Pitfalls to Avoid

<Aside type="danger" title="Why Manual OAuth Client Creation is Required">
  Many developers waste hours trying to automate OAuth client creation. Here's why it doesn't work:
  
  1. **Google's Security Model**: Web application OAuth clients that use the authorization code flow (for SSO/user login) can ONLY be created through the Console UI
  2. **API Limitations**: The Google APIs for creating OAuth clients are limited to service-to-service auth, not user auth flows
  3. **Consent Screen Requirements**: The OAuth consent screen configuration is tightly coupled with manual client creation
  4. **Domain Verification**: Authorized redirect URIs for web apps require manual verification through the Console
  
  Save yourself time: Always create OAuth 2.0 web application clients manually in the Console.
</Aside>

## Troubleshooting

### "Access Denied" Errors

1. **Check domain spelling** in allowedDomains
2. **Verify user's primary email** domain
3. **Confirm OAuth consent screen** is approved
4. **Check organizational policies** in Google Admin

### Redirect URI Mismatch

```
Error: redirect_uri_mismatch
```

**Solution**:
1. Exact match required (including https://)
2. No trailing slashes
3. Update in Google Cloud Console
4. Wait 5 minutes for propagation

### Token Refresh Failures

If refresh tokens stop working:

1. Check Google Workspace session policies
2. Verify user is still active
3. Confirm OAuth client hasn't been deleted
4. Review token expiration settings

### Rate Limiting

Google enforces rate limits:

| Limit | Value | Scope |
|-------|-------|-------|
| Token requests | 10,000/day | Per client |
| User info requests | 1,000/hour | Per user |
| Authorization requests | 50/minute | Per IP |

## Migration Guide

### From Google Apps Script

1. Export user permissions
2. Create OAuth client in same project
3. Update configuration to OAuth
4. Migrate users in batches

### From Service Account

1. Audit current service account usage
2. Create OAuth flow for user consent
3. Implement domain-wide delegation if needed
4. Phase out service account access

## Compliance Considerations

### GDPR Compliance

- User consent via OAuth flow
- Data minimization (only required scopes)
- Right to deletion (session cleanup)
- Audit trail for access

### SOC 2 Requirements

- Enforce MFA via Google Workspace
- Session timeout configuration
- Access logging and monitoring
- Regular access reviews

## Next Steps

- Configure [Firestore Storage](/mcp-front/oauth/firestore/)
- Review [Security Best Practices](/mcp-front/oauth/security/)
- Set up [Monitoring and Alerts](/mcp-front/deployment/monitoring/)
---
title: OAuth 2.1 Configuration
description: Configure OAuth 2.1 authentication with Google Workspace
---

import { Aside, Steps } from '@astrojs/starlight/components';

OAuth 2.1 authentication provides enterprise-grade security for production deployments. MCP Front implements the OAuth 2.1 specification with PKCE for maximum security.

## OAuth Configuration

```json
{
  "proxy": {
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
  }
}
```

## Configuration Fields

| Field | Description | Required | Default |
|-------|-------------|----------|---------|
| `kind` | Must be `"oauth"` | Yes | - |
| `issuer` | OAuth issuer URL (your proxy's base URL) | Yes | - |
| `allowedDomains` | List of allowed email domains | Yes | - |
| `tokenTTL` | Token lifetime (e.g., "24h", "7d") | No | `"24h"` |
| `storage` | Storage backend (`"memory"` or `"firestore"`) | No | `"memory"` |
| `gcpProject` | Google Cloud project ID (for Firestore) | If storage="firestore" | - |
| `firestoreDatabase` | Firestore database name | No | `"(default)"` |
| `firestoreCollection` | Firestore collection name | No | `"mcp_oauth_clients"` |

<Aside type="warning">
  Never use `storage: "memory"` in production. OAuth clients will be lost on restart.
</Aside>

## Environment Variables

OAuth requires these environment variables:

```bash
# Required
GOOGLE_CLIENT_ID=your-oauth-client-id
GOOGLE_CLIENT_SECRET=your-oauth-client-secret
JWT_SECRET=your-secure-jwt-secret-at-least-32-bytes

# Optional
MCP_FRONT_ENV=development  # Relaxes some OAuth validations
```

<Aside type="caution">
  The `JWT_SECRET` must be at least 32 bytes long for security. Generate one with:
  ```bash
  openssl rand -base64 32
  ```
</Aside>

## Google OAuth Setup

<Steps>

1. **Create OAuth 2.0 Credentials**

   In [Google Cloud Console](https://console.cloud.google.com/):
   - Go to APIs & Services → Credentials
   - Click "Create Credentials" → "OAuth 2.0 Client ID"
   - Choose "Web application"
   - Name: "MCP Front Production"

2. **Configure Authorized Redirect URIs**

   Add these URIs (replace with your domain):
   ```
   https://mcp.company.com/callback
   https://mcp.company.com/oauth/callback
   ```

3. **Configure OAuth Consent Screen**

   - User Type: Internal (for Google Workspace)
   - App name: "MCP Front"
   - Support email: your-email@company.com
   - Authorized domains: company.com
   - Scopes: email, profile, openid

4. **Enable Required APIs**

   Enable these APIs in your project:
   - Google+ API (for user info)
   - Cloud Firestore API (if using Firestore storage)

</Steps>

## Firestore Setup

For production deployments, use Firestore to persist OAuth clients:

<Steps>

1. **Enable Firestore**

   In Google Cloud Console:
   - Go to Firestore
   - Click "Create Database"
   - Choose "Native mode"
   - Select your region

2. **Set up Authentication**

   For Google Cloud Run/GKE:
   ```yaml
   # Service account automatically provided
   ```

   For other environments:
   ```bash
   export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
   ```

3. **Configure Firestore in MCP Front**

   ```json
   {
     "storage": "firestore",
     "gcpProject": "my-project-123",
     "firestoreDatabase": "mcp-production",
     "firestoreCollection": "oauth_clients"
   }
   ```

</Steps>

## Domain Restrictions

The `allowedDomains` field restricts who can authenticate:

```json
{
  "allowedDomains": ["company.com", "subsidiary.com"]
}
```

Only users with email addresses from these domains can access MCP Front.

<Aside type="tip">
  For Google Workspace, this provides automatic SSO for all employees.
</Aside>

## Token Configuration

### Token TTL

Configure how long JWT tokens remain valid:

```json
{
  "tokenTTL": "24h"  // Examples: "30m", "2h", "7d"
}
```

Shorter TTLs are more secure but require more frequent re-authentication.

### Token Security

MCP Front uses JWT tokens with:
- HMAC-SHA256 signing (HS256)
- Issuer validation
- Expiration checking
- Domain validation in claims

## OAuth Endpoints

MCP Front provides these OAuth endpoints:

| Endpoint | Description |
|----------|-------------|
| `/.well-known/oauth-authorization-server` | OAuth 2.1 discovery |
| `/authorize` | Authorization endpoint |
| `/token` | Token endpoint |
| `/register` | Dynamic client registration |
| `/introspect` | Token introspection |
| `/revoke` | Token revocation |

## Security Best Practices

1. **Use HTTPS in Production**
   ```json
   {
     "issuer": "https://mcp.company.com"  // Always HTTPS
   }
   ```

2. **Rotate JWT Secret Regularly**
   ```bash
   # Generate new secret
   export JWT_SECRET=$(openssl rand -base64 32)
   
   # Restart with new secret (invalidates existing tokens)
   docker-compose restart
   ```

3. **Monitor Failed Authentications**
   ```bash
   # Check logs for auth failures
   docker logs mcp-front | grep "auth failed"
   ```

4. **Use Short Token TTLs**
   ```json
   {
     "tokenTTL": "4h"  // Balance security and usability
   }
   ```

## Development Mode

For local development, you can relax some OAuth requirements:

```bash
export MCP_FRONT_ENV=development
```

This:
- Allows `http://` issuers (localhost only)
- Reduces state parameter entropy requirements
- Enables debug logging

<Aside type="danger">
  Never use development mode in production. It significantly reduces security.
</Aside>

## Troubleshooting

### "Invalid redirect URI"

Ensure your redirect URIs in Google Console exactly match the callback URL, including:
- Protocol (`https://`)
- Domain
- Port (if non-standard)
- Path (`/callback`)

### "JWT secret too short"

The JWT secret must be at least 32 bytes:
```bash
# This will fail
export JWT_SECRET="short"

# This works
export JWT_SECRET="this-is-a-very-long-secret-key-with-at-least-32-bytes"
```

### "Domain not allowed"

Check that:
1. User's email domain is in `allowedDomains`
2. Google Workspace user exists
3. No typos in domain configuration

### Token expiration issues

If tokens expire too quickly:
1. Increase `tokenTTL`
2. Check server time synchronization
3. Verify JWT_SECRET hasn't changed

## Next Steps

- Set up [Google Workspace integration](/mcp-front/oauth/google-workspace/)
- Configure [Firestore storage](/mcp-front/oauth/firestore/)
- Review [OAuth security best practices](/mcp-front/oauth/security/)
- Deploy to [production](/mcp-front/deployment/production/)
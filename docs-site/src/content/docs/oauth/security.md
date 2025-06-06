---
title: OAuth Security Best Practices
description: Security guidelines for MCP Front OAuth implementation
---

import { Aside, Code, Tabs, TabItem } from '@astrojs/starlight/components';

This guide covers security best practices for deploying and maintaining MCP Front with OAuth 2.1 authentication.

## Security Checklist

### Essential Security Measures

- [ ] **HTTPS only** - Never run OAuth over HTTP
- [ ] **Strong JWT secret** - Minimum 32 bytes
- [ ] **PKCE enforced** - Required for all flows
- [ ] **State validation** - Prevent CSRF attacks
- [ ] **Token rotation** - Implement refresh token rotation
- [ ] **Session limits** - Maximum sessions per user
- [ ] **Domain restrictions** - Allowlist authorized domains
- [ ] **Audit logging** - Track all authentication events
- [ ] **Rate limiting** - Prevent brute force attacks
- [ ] **Security headers** - HSTS, CSP, etc.

## JWT Security

### Secret Requirements

<Aside type="danger">
  JWT secrets MUST be at least 32 bytes (256 bits) for HMAC-SHA512/256. Shorter secrets will be rejected.
</Aside>

#### Generate Strong Secrets

<Tabs>
<TabItem label="OpenSSL">
```bash
# Generate 32-byte secret
openssl rand -base64 32

# Generate 64-byte secret (recommended)
openssl rand -base64 64
```
</TabItem>
<TabItem label="Go">
```go
package main

import (
    "crypto/rand"
    "encoding/base64"
    "fmt"
)

func generateSecret() string {
    bytes := make([]byte, 32)
    rand.Read(bytes)
    return base64.StdEncoding.EncodeToString(bytes)
}
```
</TabItem>
<TabItem label="Node.js">
```javascript
const crypto = require('crypto');

// Generate 32-byte secret
const secret = crypto.randomBytes(32).toString('base64');
console.log(secret);
```
</TabItem>
</Tabs>

### Secret Rotation

Implement regular secret rotation:

<Code code={`#!/bin/bash
# rotate-jwt-secret.sh

# Generate new secret
NEW_SECRET=$(openssl rand -base64 32)

# Store in secret manager
gcloud secrets create jwt-secret-v2 --data-file=- <<< "$NEW_SECRET"

# Update application to accept both secrets
gcloud run services update mcp-front \
  --set-env-vars "JWT_SECRET=$NEW_SECRET,JWT_SECRET_OLD=$OLD_SECRET"

# After all tokens expire (8 hours), remove old secret
echo "Schedule removal of JWT_SECRET_OLD after token expiry"`} lang="bash" title="rotate-jwt-secret.sh" />

### Token Security

```json
{
  "token": {
    "accessTokenLifetime": "1h",
    "refreshTokenLifetime": "30d",
    "reuseRefreshTokens": false,
    "rotateRefreshTokens": true,
    "includeJTI": true,
    "audienceValidation": true
  }
}
```

## PKCE Implementation

### Why PKCE is Mandatory

PKCE prevents:
- Authorization code interception
- Code injection attacks
- Token replay attacks

### Secure PKCE Flow

```javascript
// Client implementation
class PKCEFlow {
  generateVerifier() {
    // 43-128 characters
    const array = new Uint8Array(32);
    crypto.getRandomValues(array);
    return base64url(array);
  }
  
  generateChallenge(verifier) {
    const encoder = new TextEncoder();
    const data = encoder.encode(verifier);
    return crypto.subtle.digest('SHA-256', data)
      .then(buffer => base64url(new Uint8Array(buffer)));
  }
  
  async startAuth() {
    const verifier = this.generateVerifier();
    const challenge = await this.generateChallenge(verifier);
    
    // Store verifier securely
    sessionStorage.setItem('pkce_verifier', verifier);
    
    // Use challenge in auth request
    window.location.href = `/oauth/authorize?
      code_challenge=${challenge}&
      code_challenge_method=S256&...`;
  }
}
```

## State Parameter Security

### Implementation

```javascript
// Generate cryptographically secure state
function generateState() {
  const array = new Uint8Array(32);
  crypto.getRandomValues(array);
  return base64url(array);
}

// Store with expiration
function storeState(state) {
  const data = {
    state: state,
    expires: Date.now() + 600000 // 10 minutes
  };
  sessionStorage.setItem('oauth_state', JSON.stringify(data));
}

// Validate on callback
function validateState(receivedState) {
  const stored = JSON.parse(sessionStorage.getItem('oauth_state'));
  
  if (!stored || stored.state !== receivedState) {
    throw new Error('Invalid state parameter');
  }
  
  if (Date.now() > stored.expires) {
    throw new Error('State parameter expired');
  }
  
  // Clear after validation
  sessionStorage.removeItem('oauth_state');
}
```

### Entropy Requirements

| Environment | Minimum Entropy | Bytes | Characters |
|-------------|----------------|-------|------------|
| Development | 0 bits | 0 | 0 (optional) |
| Production | 64 bits | 8 | 11+ |
| High Security | 128 bits | 16 | 22+ |

## Session Security

### Session Configuration

<Code code={`{
  "session": {
    "timeout": "8h",
    "absoluteTimeout": "24h",
    "idleTimeout": "30m",
    "maxConcurrentSessions": 5,
    "bindToIP": true,
    "bindToUserAgent": true,
    "regenerateOnLogin": true
  }
}`} lang="json" title="Session Security Settings" />

### Session Validation

MCP Front validates sessions on each request:

1. **Token signature** verification
2. **Expiration** check
3. **Domain** validation
4. **IP binding** (optional)
5. **User agent** matching (optional)

### Session Revocation

Implement immediate revocation:

```go
// Admin endpoint to revoke sessions
POST /admin/sessions/revoke
{
  "user_email": "compromised@company.com",
  "reason": "Account compromise",
  "revoke_all": true
}
```

## Network Security

### TLS Configuration

<Code code={`server {
    listen 443 ssl http2;
    
    # Modern TLS configuration
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers 'ECDHE-RSA-AES128-GCM-SHA256:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-RSA-CHACHA20-POLY1305';
    ssl_prefer_server_ciphers off;
    
    # OCSP Stapling
    ssl_stapling on;
    ssl_stapling_verify on;
    
    # Session resumption
    ssl_session_timeout 1d;
    ssl_session_cache shared:SSL:10m;
    ssl_session_tickets off;
    
    # HSTS
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload" always;
}`} lang="nginx" title="TLS Configuration" />

### Security Headers

```nginx
# Security headers
add_header X-Frame-Options "DENY" always;
add_header X-Content-Type-Options "nosniff" always;
add_header X-XSS-Protection "1; mode=block" always;
add_header Referrer-Policy "strict-origin-when-cross-origin" always;
add_header Permissions-Policy "geolocation=(), microphone=(), camera=()" always;

# Content Security Policy
add_header Content-Security-Policy "
  default-src 'self';
  script-src 'self' 'unsafe-inline';
  style-src 'self' 'unsafe-inline';
  img-src 'self' data: https:;
  font-src 'self';
  connect-src 'self' https://accounts.google.com;
  frame-ancestors 'none';
  base-uri 'self';
  form-action 'self';
" always;
```

## Rate Limiting

### Nginx Rate Limiting

```nginx
# Define rate limit zones
limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;
limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;

# Apply to auth endpoints
location /oauth/ {
    limit_req zone=auth burst=10 nodelay;
    limit_req_status 429;
    proxy_pass http://mcp-front:8080;
}

# Apply to API endpoints
location / {
    limit_req zone=api burst=200 nodelay;
    limit_req_status 429;
    proxy_pass http://mcp-front:8080;
}
```

### Application-Level Rate Limiting

```json
{
  "rateLimiting": {
    "enabled": true,
    "rules": [
      {
        "path": "/oauth/token",
        "method": "POST",
        "limit": 5,
        "window": "1m",
        "keyBy": "ip"
      },
      {
        "path": "/oauth/authorize",
        "method": "GET",
        "limit": 10,
        "window": "1m",
        "keyBy": "ip"
      }
    ]
  }
}
```

## Audit Logging

### Critical Events to Log

```json
{
  "auditEvents": [
    "auth.login.success",
    "auth.login.failure",
    "auth.logout",
    "token.create",
    "token.refresh",
    "token.revoke",
    "session.create",
    "session.expire",
    "client.register",
    "client.update",
    "client.delete",
    "admin.action"
  ]
}
```

### Log Format

```json
{
  "timestamp": "2024-01-15T10:30:45.123Z",
  "event": "auth.login.success",
  "user": {
    "id": "user_123",
    "email": "user@company.com",
    "domain": "company.com"
  },
  "client": {
    "id": "client_456",
    "name": "Claude Desktop"
  },
  "request": {
    "ip": "203.0.113.45",
    "user_agent": "Mozilla/5.0...",
    "country": "US",
    "asn": "AS15169"
  },
  "risk": {
    "score": 0.2,
    "factors": ["new_device"]
  }
}
```

### Log Retention

| Log Type | Retention | Storage | Encryption |
|----------|-----------|---------|------------|
| Auth events | 90 days | Firestore | Yes |
| Access logs | 30 days | Cloud Storage | Yes |
| Error logs | 7 days | Cloud Logging | Yes |
| Debug logs | 24 hours | Local only | No |

## Input Validation

### OAuth Parameters

```go
// Validation rules (internal)
var parameterRules = map[string]ValidationRule{
    "client_id": {
        Required: true,
        MaxLength: 255,
        Pattern: "^[a-zA-Z0-9-_]+$",
    },
    "redirect_uri": {
        Required: true,
        MaxLength: 2048,
        Validator: validateRedirectURI,
    },
    "state": {
        Required: true,
        MinLength: 8,
        MaxLength: 512,
    },
    "code_challenge": {
        Required: true,
        Length: 43,
        Pattern: "^[A-Za-z0-9-_]+$",
    },
}
```

### Redirect URI Validation

```go
func validateRedirectURI(uri string) error {
    // Parse URI
    parsed, err := url.Parse(uri)
    if err != nil {
        return err
    }
    
    // Production requirements
    if production {
        // Must be HTTPS (except localhost)
        if parsed.Scheme != "https" && parsed.Hostname() != "localhost" {
            return errors.New("HTTPS required")
        }
        
        // No wildcards
        if strings.Contains(parsed.Host, "*") {
            return errors.New("Wildcards not allowed")
        }
    }
    
    // Validate against registered URIs
    if !isRegisteredURI(uri) {
        return errors.New("Unregistered redirect URI")
    }
    
    return nil
}
```

## Vulnerability Prevention

### Common Vulnerabilities

1. **Authorization Code Injection**
   - Mitigated by: PKCE, state validation
   
2. **Token Replay**
   - Mitigated by: JTI tracking, short expiry
   
3. **Session Fixation**
   - Mitigated by: Session regeneration
   
4. **CSRF**
   - Mitigated by: State parameter, SameSite cookies
   
5. **Open Redirect**
   - Mitigated by: Strict redirect URI validation

### Security Testing

```bash
# Test for common vulnerabilities
./security-test.sh

# OWASP ZAP scan
docker run -t owasp/zap2docker-stable zap-baseline.py \
  -t https://mcp.company.com

# OAuth specific tests
oauth-security-tester \
  --target https://mcp.company.com \
  --client-id test-client \
  --tests all
```

## Incident Response

### Security Incident Checklist

1. **Immediate Actions**
   - [ ] Revoke compromised sessions
   - [ ] Rotate JWT secrets
   - [ ] Block suspicious IPs
   - [ ] Enable emergency rate limits

2. **Investigation**
   - [ ] Review audit logs
   - [ ] Identify affected users
   - [ ] Determine attack vector
   - [ ] Check for data exfiltration

3. **Remediation**
   - [ ] Patch vulnerabilities
   - [ ] Force password resets
   - [ ] Update security rules
   - [ ] Notify affected users

### Emergency Procedures

<Code code={`#!/bin/bash
# emergency-lockdown.sh

# 1. Revoke all sessions
gcloud firestore import gs://backups/empty-sessions

# 2. Rotate secrets
NEW_SECRET=$(openssl rand -base64 64)
gcloud secrets create jwt-secret-emergency --data-file=- <<< "$NEW_SECRET"

# 3. Update configuration
gcloud run services update mcp-front \
  --set-env-vars "JWT_SECRET=$NEW_SECRET,EMERGENCY_MODE=true"

# 4. Clear CDN cache
gcloud compute url-maps invalidate-cdn-cache mcp-front-lb \
  --path "/*"

# 5. Alert team
./send-alert.sh "Security incident - MCP Front in emergency mode"`} lang="bash" title="emergency-lockdown.sh" />

## Compliance

### OWASP Top 10 Coverage

| Risk | Mitigation | Implementation |
|------|------------|----------------|
| Injection | Input validation | ✓ Parameterized queries |
| Broken Authentication | OAuth 2.1 | ✓ PKCE, state validation |
| Sensitive Data Exposure | Encryption | ✓ TLS, token hashing |
| XXE | N/A | ✓ JSON only |
| Broken Access Control | Domain restrictions | ✓ Allowlist domains |
| Security Misconfiguration | Security headers | ✓ HSTS, CSP |
| XSS | Content-Type validation | ✓ JSON responses |
| Insecure Deserialization | Input validation | ✓ Structured validation |
| Insufficient Logging | Audit logs | ✓ Comprehensive logging |
| Known Vulnerabilities | Dependency scanning | ✓ Regular updates |

## Security Monitoring

### Key Metrics

```yaml
metrics:
  - name: failed_auth_rate
    query: rate(auth_failures_total[5m])
    threshold: 0.1
    
  - name: new_client_registrations
    query: increase(oauth_clients_total[1h])
    threshold: 10
    
  - name: token_refresh_anomaly
    query: rate(token_refresh_total[5m]) > 2 * avg_over_time(rate(token_refresh_total[5m])[1h:5m])
    
  - name: geographic_anomaly
    query: count by (country) (auth_success_total) > 0 unless count by (country) (auth_success_total offset 1d)
```

### Security Dashboard

- Failed authentication attempts
- Successful logins by country
- Token refresh patterns
- Session duration distribution
- Client usage statistics
- Anomaly detection alerts

## Next Steps

- Implement [Monitoring and Alerts](/mcp-front/deployment/monitoring/)
- Review [Production Deployment](/mcp-front/deployment/production/)
- Set up [Incident Response Plan](/mcp-front/security/incident-response/)
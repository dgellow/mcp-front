---
title: Authentication API Reference
description: API endpoints for OAuth 2.1 authentication
---

import { Aside, Code } from '@astrojs/starlight/components';

MCP Front provides OAuth 2.1 compliant authentication endpoints for secure access to MCP servers.

## OAuth Discovery

### OpenID Configuration

<div class="api-endpoint">
  <span class="api-method get">GET</span>
  <code>/oauth/.well-known/openid-configuration</code>
</div>

Returns OAuth 2.1 server metadata for automatic client configuration.

**Response**
```json
{
  "issuer": "https://mcp.company.com",
  "authorization_endpoint": "https://mcp.company.com/oauth/authorize",
  "token_endpoint": "https://mcp.company.com/oauth/token",
  "userinfo_endpoint": "https://mcp.company.com/oauth/userinfo",
  "jwks_uri": "https://mcp.company.com/oauth/jwks",
  "registration_endpoint": "https://mcp.company.com/oauth/register",
  "scopes_supported": ["openid", "profile", "email", "offline_access"],
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post",
    "none"
  ],
  "revocation_endpoint": "https://mcp.company.com/oauth/revoke",
  "introspection_endpoint": "https://mcp.company.com/oauth/introspect"
}
```

## Authorization Flow

### Authorization Request

<div class="api-endpoint">
  <span class="api-method get">GET</span>
  <code>/oauth/authorize</code>
</div>

Initiates the OAuth 2.1 authorization code flow.

**Query Parameters**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `client_id` | Yes | The client identifier |
| `redirect_uri` | Yes | Callback URL (must match registered URI) |
| `response_type` | Yes | Must be `code` |
| `scope` | Yes | Space-separated scopes (e.g., `openid profile email`) |
| `state` | Yes | CSRF protection token |
| `code_challenge` | Yes | PKCE challenge (base64url encoded) |
| `code_challenge_method` | Yes | Must be `S256` |
| `nonce` | No | OpenID Connect nonce |
| `prompt` | No | `none`, `login`, or `consent` |

**Example Request**
```bash
GET /oauth/authorize?
  client_id=abc123&
  redirect_uri=https%3A%2F%2Fclaude.ai%2Fcallback&
  response_type=code&
  scope=openid%20profile%20email&
  state=xyz789&
  code_challenge=E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM&
  code_challenge_method=S256
```

**Success Response**
```
HTTP/1.1 302 Found
Location: https://accounts.google.com/o/oauth2/v2/auth?...
```

**Error Response**
```
HTTP/1.1 302 Found
Location: https://claude.ai/callback?
  error=invalid_request&
  error_description=Missing%20required%20parameter%3A%20code_challenge&
  state=xyz789
```

### Authorization Callback

<div class="api-endpoint">
  <span class="api-method get">GET</span>
  <code>/oauth/callback</code>
</div>

Handles the callback from Google OAuth.

**Query Parameters**

| Parameter | Description |
|-----------|-------------|
| `code` | Google authorization code |
| `state` | State parameter for validation |
| `error` | Error code if authorization failed |
| `error_description` | Human-readable error message |

**Success Response**
```
HTTP/1.1 302 Found
Location: {registered_redirect_uri}?
  code=AUTH_CODE_HERE&
  state=xyz789
```

## Token Management

### Token Exchange

<div class="api-endpoint">
  <span class="api-method post">POST</span>
  <code>/oauth/token</code>
</div>

Exchanges authorization code for access tokens.

**Headers**
```
Content-Type: application/x-www-form-urlencoded
Authorization: Basic {base64(client_id:client_secret)}
```

**Request Body**

| Parameter | Required | Description |
|-----------|----------|-------------|
| `grant_type` | Yes | `authorization_code` or `refresh_token` |
| `code` | If auth code | The authorization code |
| `redirect_uri` | If auth code | Must match authorize request |
| `code_verifier` | If auth code | PKCE verifier |
| `refresh_token` | If refresh | The refresh token |
| `client_id` | If public client | Client identifier |

**Example: Authorization Code Exchange**
<Code code={`POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic YWJjMTIzOnNlY3JldDQ1Ng==

grant_type=authorization_code&
code=SplxlOBeZQQYbYS6WxSbIA&
redirect_uri=https%3A%2F%2Fclaude.ai%2Fcallback&
code_verifier=dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk`} lang="http" />

**Example: Refresh Token**
<Code code={`POST /oauth/token
Content-Type: application/x-www-form-urlencoded
Authorization: Basic YWJjMTIzOnNlY3JldDQ1Ng==

grant_type=refresh_token&
refresh_token=xRxGGEpVawiUak6He367W3oeOfh+3irw+1G1h1jY`} lang="http" />

**Success Response**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
  "token_type": "Bearer",
  "expires_in": 3600,
  "refresh_token": "xRxGGEpVawiUak6He367W3oeOfh+3irw+1G1h1jY",
  "scope": "openid profile email",
  "id_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."
}
```

**Error Response**
```json
{
  "error": "invalid_grant",
  "error_description": "Authorization code is invalid or expired"
}
```

### Token Revocation

<div class="api-endpoint">
  <span class="api-method post">POST</span>
  <code>/oauth/revoke</code>
</div>

Revokes access or refresh tokens.

**Request Body**
```
token={token_to_revoke}&
token_type_hint=refresh_token
```

**Response**
```
HTTP/1.1 200 OK
```

### Token Introspection

<div class="api-endpoint">
  <span class="api-method post">POST</span>
  <code>/oauth/introspect</code>
</div>

Validates and returns token metadata.

**Request Body**
```
token={token_to_introspect}&
token_type_hint=access_token
```

**Response**
```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "abc123",
  "username": "user@company.com",
  "exp": 1675876062
}
```

## User Information

### UserInfo Endpoint

<div class="api-endpoint">
  <span class="api-method get">GET</span>
  <code>/oauth/userinfo</code>
</div>

Returns authenticated user information.

**Headers**
```
Authorization: Bearer {access_token}
```

**Response**
```json
{
  "sub": "user_123",
  "email": "user@company.com",
  "email_verified": true,
  "name": "John Doe",
  "picture": "https://lh3.googleusercontent.com/...",
  "locale": "en",
  "hd": "company.com"
}
```

## Client Registration

### Dynamic Registration

<div class="api-endpoint">
  <span class="api-method post">POST</span>
  <code>/oauth/register</code>
</div>

Registers a new OAuth client dynamically.

<Aside type="caution">
  Client registration typically requires admin authentication.
</Aside>

**Headers**
```
Content-Type: application/json
Authorization: Bearer {admin_token}
```

**Request Body**
```json
{
  "client_name": "Claude Desktop App",
  "redirect_uris": [
    "http://localhost:3000/callback",
    "claude://callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "client_secret_basic",
  "application_type": "native",
  "contacts": ["dev@company.com"],
  "logo_uri": "https://example.com/logo.png",
  "policy_uri": "https://example.com/privacy",
  "tos_uri": "https://example.com/terms"
}
```

**Success Response (201 Created)**
```json
{
  "client_id": "def456",
  "client_secret": "secret789",
  "client_id_issued_at": 1675876062,
  "client_secret_expires_at": 0,
  "registration_access_token": "reg.token.here",
  "registration_client_uri": "https://mcp.company.com/oauth/register/def456",
  "client_name": "Claude Desktop App",
  "redirect_uris": [
    "http://localhost:3000/callback",
    "claude://callback"
  ],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "openid profile email",
  "token_endpoint_auth_method": "client_secret_basic"
}
```

### Client Management

<div class="api-endpoint">
  <span class="api-method get">GET</span>
  <code>/oauth/register/{client_id}</code>
</div>

Retrieves client configuration.

**Headers**
```
Authorization: Bearer {registration_access_token}
```

<div class="api-endpoint">
  <span class="api-method put">PUT</span>
  <code>/oauth/register/{client_id}</code>
</div>

Updates client configuration.

<div class="api-endpoint">
  <span class="api-method delete">DELETE</span>
  <code>/oauth/register/{client_id}</code>
</div>

Deletes a client registration.

## JWKS Endpoint

### JSON Web Key Set

<div class="api-endpoint">
  <span class="api-method get">GET</span>
  <code>/oauth/jwks</code>
</div>

Returns public keys for token verification.

**Response**
```json
{
  "keys": [
    {
      "kty": "RSA",
      "use": "sig",
      "kid": "2024-01-15",
      "alg": "RS256",
      "n": "xjlKRBqy...",
      "e": "AQAB"
    }
  ]
}
```

## Error Responses

### OAuth Error Format

```json
{
  "error": "invalid_request",
  "error_description": "The request is missing a required parameter",
  "error_uri": "https://docs.mcp-front.com/errors/invalid_request"
}
```

### Common Error Codes

| Error | Description |
|-------|-------------|
| `invalid_request` | Missing or invalid parameter |
| `invalid_client` | Client authentication failed |
| `invalid_grant` | Invalid authorization code or refresh token |
| `unauthorized_client` | Client not authorized for grant type |
| `unsupported_grant_type` | Grant type not supported |
| `invalid_scope` | Requested scope is invalid |
| `insufficient_scope` | Token lacks required scope |
| `access_denied` | User denied authorization |
| `server_error` | Internal server error |
| `temporarily_unavailable` | Service temporarily unavailable |

## Security Considerations

### PKCE Requirements

- Code verifier: 43-128 characters
- Code challenge: SHA256(verifier) base64url encoded
- Required for all clients (public and confidential)

### State Parameter

- Minimum 8 bytes of entropy in production
- Must be cryptographically random
- Single use only
- 10-minute expiration

### Token Security

- Access tokens expire in 1 hour
- Refresh tokens expire in 30 days
- Tokens are JWT signed with HMAC-SHA256
- Refresh token rotation enabled

## Rate Limits

| Endpoint | Limit | Window |
|----------|-------|--------|
| `/oauth/authorize` | 10 requests | 1 minute |
| `/oauth/token` | 5 requests | 1 minute |
| `/oauth/userinfo` | 100 requests | 1 minute |
| `/oauth/register` | 5 requests | 1 hour |

Exceeding rate limits returns:
```json
{
  "error": "rate_limit_exceeded",
  "error_description": "Too many requests",
  "retry_after": 60
}
```

## Next Steps

- Explore [SSE Protocol](/mcp-front/api/sse-protocol/) for MCP communication
- Review [Security Best Practices](/mcp-front/oauth/security/)
- See [Client Libraries](/mcp-front/dev/client-libraries/)
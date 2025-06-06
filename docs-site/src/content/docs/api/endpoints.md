---
title: API Endpoints
description: Complete API reference for MCP Front
---

import { Aside } from '@astrojs/starlight/components';

MCP Front exposes several endpoints for health checks, OAuth flows, and MCP protocol communication.

## Core Endpoints

### Health Check

<div class="api-endpoint">
  <span class="api-method get">GET</span>
  <code>/health</code>
</div>

Returns the health status of the proxy server.

**Response:**
```json
{
  "status": "ok",
  "service": "mcp-front"
}
```

**Status Codes:**
- `200 OK` - Service is healthy
- `503 Service Unavailable` - Service is unhealthy

**Example:**
```bash
curl https://mcp.company.com/health
```

### SSE Endpoint

<div class="api-endpoint">
  <span class="api-method get">GET</span>
  <code>/sse</code>
</div>

Main Server-Sent Events endpoint for MCP protocol communication.

**Headers:**
- `Authorization: Bearer <token>` - Required authentication token
- `Accept: text/event-stream` - Required for SSE

**Query Parameters:**
- `server` - Target MCP server name (optional, can be in path)

**Response:** SSE stream with MCP protocol messages

**Example:**
```bash
curl -H "Authorization: Bearer ${TOKEN}" \
     -H "Accept: text/event-stream" \
     https://mcp.company.com/sse?server=database
```

### Server-Specific SSE

<div class="api-endpoint">
  <span class="api-method get">GET</span>
  <code>/{server}/sse</code>
</div>

Alternative SSE endpoint with server name in path.

**Parameters:**
- `{server}` - MCP server name from configuration

**Example:**
```bash
curl -H "Authorization: Bearer ${TOKEN}" \
     -H "Accept: text/event-stream" \
     https://mcp.company.com/database/sse
```

## OAuth 2.1 Endpoints

### Discovery

<div class="api-endpoint">
  <span class="api-method get">GET</span>
  <code>/.well-known/oauth-authorization-server</code>
</div>

OAuth 2.1 server metadata discovery endpoint ([RFC 8414](https://tools.ietf.org/html/rfc8414)).

**Response:**
```json
{
  "issuer": "https://mcp.company.com",
  "authorization_endpoint": "https://mcp.company.com/authorize",
  "token_endpoint": "https://mcp.company.com/token",
  "registration_endpoint": "https://mcp.company.com/register",
  "introspection_endpoint": "https://mcp.company.com/introspect",
  "revocation_endpoint": "https://mcp.company.com/revoke",
  "response_types_supported": ["code"],
  "grant_types_supported": ["authorization_code", "refresh_token"],
  "code_challenge_methods_supported": ["S256"],
  "token_endpoint_auth_methods_supported": ["none"],
  "service_documentation": "https://github.com/dgellow/mcp-front"
}
```

### Authorization

<div class="api-endpoint">
  <span class="api-method get">GET</span>
  <code>/authorize</code>
</div>

OAuth 2.1 authorization endpoint. Redirects to Google for authentication.

**Query Parameters:**
- `response_type` - Must be `code`
- `client_id` - OAuth client ID
- `redirect_uri` - Callback URL
- `state` - CSRF protection (required in production)
- `code_challenge` - PKCE challenge (required)
- `code_challenge_method` - Must be `S256`
- `scope` - Requested scopes (optional)

**Example:**
```
https://mcp.company.com/authorize?
  response_type=code&
  client_id=abc123&
  redirect_uri=https://claude.ai/callback&
  state=random-state&
  code_challenge=challenge&
  code_challenge_method=S256
```

### Token Exchange

<div class="api-endpoint">
  <span class="api-method post">POST</span>
  <code>/token</code>
</div>

Exchange authorization code for access token.

**Content-Type:** `application/x-www-form-urlencoded`

**Body Parameters:**
- `grant_type` - `authorization_code` or `refresh_token`
- `code` - Authorization code (for authorization_code)
- `redirect_uri` - Must match authorize request
- `client_id` - OAuth client ID
- `code_verifier` - PKCE verifier
- `refresh_token` - For refresh_token grant

**Response:**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIs...",
  "token_type": "Bearer",
  "expires_in": 86400,
  "refresh_token": "refresh-token-here"
}
```

### Client Registration

<div class="api-endpoint">
  <span class="api-method post">POST</span>
  <code>/register</code>
</div>

Dynamic client registration endpoint ([RFC 7591](https://tools.ietf.org/html/rfc7591)).

**Content-Type:** `application/json`

**Body:**
```json
{
  "redirect_uris": ["https://claude.ai/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "read write",
  "token_endpoint_auth_method": "none"
}
```

**Response:**
```json
{
  "client_id": "generated-client-id",
  "client_id_issued_at": 1642000000,
  "redirect_uris": ["https://claude.ai/callback"],
  "grant_types": ["authorization_code", "refresh_token"],
  "response_types": ["code"],
  "scope": "read write",
  "token_endpoint_auth_method": "none"
}
```

<Aside type="note">
  Public clients (like Claude.ai) use `token_endpoint_auth_method: "none"` and don't receive a client_secret.
</Aside>

### Token Introspection

<div class="api-endpoint">
  <span class="api-method post">POST</span>
  <code>/introspect</code>
</div>

Check if a token is active and get metadata ([RFC 7662](https://tools.ietf.org/html/rfc7662)).

**Body:**
```json
{
  "token": "access-token-here",
  "token_type_hint": "access_token"
}
```

**Response:**
```json
{
  "active": true,
  "scope": "read write",
  "client_id": "abc123",
  "exp": 1642086400,
  "iat": 1642000000
}
```

### Token Revocation

<div class="api-endpoint">
  <span class="api-method post">POST</span>
  <code>/revoke</code>
</div>

Revoke an access or refresh token ([RFC 7009](https://tools.ietf.org/html/rfc7009)).

**Body:**
```json
{
  "token": "token-to-revoke",
  "token_type_hint": "refresh_token"
}
```

**Response:** `200 OK` (always succeeds)

## Debug Endpoints

<Aside type="warning">
  Debug endpoints should be disabled in production or protected with additional authentication.
</Aside>

### List OAuth Clients

<div class="api-endpoint">
  <span class="api-method get">GET</span>
  <code>/debug/clients</code>
</div>

Lists all registered OAuth clients (development only).

**Response:**
```json
{
  "clients": {
    "client-id-1": {
      "redirect_uris": ["https://example.com/callback"],
      "created_at": "2024-01-15T10:00:00Z"
    }
  },
  "total_clients": 1
}
```

## Error Responses

All endpoints return consistent error responses:

```json
{
  "error": "invalid_request",
  "error_description": "The request is missing a required parameter"
}
```

### Common Error Codes

| Code | Description |
|------|-------------|
| `invalid_request` | Missing or invalid parameters |
| `invalid_client` | Unknown or invalid client |
| `invalid_grant` | Invalid authorization code or refresh token |
| `unauthorized_client` | Client not authorized for grant type |
| `unsupported_grant_type` | Grant type not supported |
| `invalid_scope` | Requested scope is invalid |
| `server_error` | Internal server error |

## CORS Headers

All endpoints include CORS headers for browser compatibility:

```http
Access-Control-Allow-Origin: https://claude.ai
Access-Control-Allow-Methods: GET, POST, OPTIONS
Access-Control-Allow-Headers: Authorization, Content-Type
Access-Control-Max-Age: 3600
```

## Rate Limiting

MCP Front doesn't implement rate limiting by default, but you can add it with a reverse proxy:

```nginx
# Nginx example
limit_req_zone $binary_remote_addr zone=api:10m rate=10r/s;

location / {
    limit_req zone=api burst=20;
    proxy_pass http://mcp-front:8080;
}
```

## Authentication

### Bearer Token

For bearer token authentication:

```bash
curl -H "Authorization: Bearer your-token-here" \
     https://mcp.company.com/sse
```

### OAuth 2.1

For OAuth authentication:

1. Register a client via `/register`
2. Direct user to `/authorize`
3. Exchange code for token at `/token`
4. Use token in Authorization header

## WebSocket Alternative

While MCP Front uses SSE by default, you can implement WebSocket support:

```javascript
// Not implemented in default MCP Front
const ws = new WebSocket('wss://mcp.company.com/ws');
ws.send(JSON.stringify({
  jsonrpc: '2.0',
  method: 'tools/list',
  id: 1
}));
```

## Next Steps

- Learn about [Authentication](/mcp-front/api/authentication/) methods
- Understand the [SSE Protocol](/mcp-front/api/sse-protocol/)
- Review [Security Best Practices](/mcp-front/oauth/security/)
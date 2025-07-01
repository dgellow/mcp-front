---
title: API Reference
description: HTTP endpoints and authentication
---

## Core endpoints

### Health check

```
GET /health
```

Returns service health status. Use this for monitoring and load balancer health checks.

**Response:**

```json
{ "status": "ok", "service": "mcp-front" }
```

**Status codes:**

- `200` - Service is healthy
- `503` - Service is unhealthy

### SSE endpoint

```
GET /sse
GET /{server}/sse

Authorization: Bearer <token>
Accept: text/event-stream
```

Main endpoint for MCP protocol communication over Server-Sent Events.

**Request routing:**

![Request Routing and Proxying](/mcp-front/request-routing.svg)

The request flow:

1. Claude connects via SSE
2. MCP Front validates auth token
3. MCP Front connects to MCP server
4. Bidirectional message streaming

**Server selection:**

- `/sse` - Uses first server in config
- `/{server}/sse` - Uses named server
- `/sse?server={name}` - Alternative syntax

**Example stream:**

```
event: message
data: {"jsonrpc":"2.0","method":"tools/list","id":1}

event: message
data: {"jsonrpc":"2.0","result":{"tools":[...]},"id":1}
```

## OAuth endpoints

Only available when using OAuth auth:

### Discovery

```
GET /.well-known/oauth-authorization-server
```

OAuth 2.1 metadata for client configuration.

### Authorization

```
GET /authorize?
  response_type=code&
  client_id={client_id}&
  redirect_uri={uri}&
  state={state}&
  code_challenge={challenge}&
  code_challenge_method=S256
```

Redirects to Google for authentication.

### Token exchange

```
POST /token
Content-Type: application/x-www-form-urlencoded

grant_type=authorization_code&
code={code}&
redirect_uri={uri}&
client_id={client_id}&
code_verifier={verifier}
```

Returns:

```json
{
  "access_token": "jwt-token",
  "token_type": "Bearer",
  "expires_in": 86400,
  "refresh_token": "refresh-token"
}
```

### Client registration

```
POST /register
Content-Type: application/json

{
  "redirect_uris": ["https://claude.ai/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"],
  "token_endpoint_auth_method": "none"
}
```

Returns:

```json
{
  "client_id": "generated-id",
  "redirect_uris": ["https://claude.ai/callback"],
  "grant_types": ["authorization_code"],
  "response_types": ["code"]
}
```

## Authentication

### Bearer token

```
Authorization: Bearer your-token-here
```

Token must match one configured in `auth.tokens`.

### OAuth 2.1

1. Register client via `/register`
2. Direct user to `/authorize`
3. Exchange code for token at `/token`
4. Use token in Authorization header

PKCE is required for all OAuth flows.

## Errors

All errors follow OAuth 2.1 format:

```json
{
  "error": "invalid_request",
  "error_description": "Missing required parameter"
}
```

Common errors:

- `invalid_request` - Bad parameters
- `invalid_client` - Unknown client
- `invalid_grant` - Bad auth code
- `unauthorized_client` - Client can't use grant type
- `server_error` - Internal error

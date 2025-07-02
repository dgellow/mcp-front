# OAuth User Authentication for MCP Servers

## Overview

Add OAuth authentication support for MCP servers with automatic flow chaining, allowing users to complete both Google OAuth and MCP server OAuth in a single seamless flow from Claude.ai.

## User Flow

```
1. Claude.ai → User clicks "Connect" on Stainless MCP integration
2. → Redirected to mcp-front Google OAuth with server parameter
3. → User completes Google OAuth
4. → mcp-front automatically redirects to Stainless OAuth
5. → User completes Stainless OAuth  
6. → mcp-front stores tokens and redirects back to Claude.ai
7. → Complete! User never leaves the flow
```

## Config Structure

### OAuth Authentication

```json
{
  "mcpServers": {
    "stainless": {
      "transportType": "stdio",
      "command": "stainless",
      "args": ["mcp"],
      "env": {
        "STAINLESS_API_TOKEN": {"$userToken": "{{token}}"}
      },
      "requiresUserToken": true,
      "userAuthentication": {
        "type": "oauth",
        "displayName": "Stainless",
        "clientId": {"$env": "STAINLESS_OAUTH_CLIENT_ID"},
        "clientSecret": {"$env": "STAINLESS_OAUTH_CLIENT_SECRET"},
        "authorizationUrl": "https://api.stainless.com/oauth/authorize",
        "tokenUrl": "https://api.stainless.com/oauth/token",
        "scopes": ["mcp:read", "mcp:write"],
        "tokenFormat": "Bearer {{token}}"
      }
    }
  }
}
```

### Manual Token Authentication

```json
{
  "mcpServers": {
    "notion": {
      "transportType": "stdio",
      "command": "notion-mcp",
      "args": [],
      "env": {
        "NOTION_API_KEY": {"$userToken": "{{token}}"}
      },
      "requiresUserToken": true,
      "userAuthentication": {
        "type": "manual",
        "displayName": "Notion API Token",
        "instructions": "Get your token from https://notion.so/my-integrations",
        "helpUrl": "https://developers.notion.com/docs/authorization",
        "tokenFormat": "{{token}}",
        "validation": "^secret_[a-zA-Z0-9]{43}$"
      }
    }
  }
}
```

## Implementation Details

### 1. OAuth Flow Chaining

The key insight is to pass the target MCP server in the initial OAuth request and chain the flows:

```go
// Initial Claude.ai request includes target server
// GET /authorize?client_id=claude&redirect_uri=...&state=...&server=stainless

// In GoogleCallbackHandler:
func (s *Server) GoogleCallbackHandler(w http.ResponseWriter, r *http.Request) {
    // ... complete Google OAuth ...
    
    // Check if there's a target server that needs OAuth
    serverName := r.URL.Query().Get("server")
    if serverName != "" {
        serverConfig := s.config.MCPServers[serverName]
        if serverConfig != nil && serverConfig.UserAuthentication != nil && 
           serverConfig.UserAuthentication.Type == UserAuthTypeOAuth {
            // Redirect to MCP server OAuth flow
            redirectURL := fmt.Sprintf("/servers/%s/oauth/authorize?return_to=%s", 
                serverName, url.QueryEscape(originalRedirectURI))
            http.Redirect(w, r, redirectURL, http.StatusFound)
            return
        }
    }
    
    // Otherwise redirect back to Claude.ai
    http.Redirect(w, r, originalRedirectURI, http.StatusFound)
}
```

### 2. MCP Server OAuth Endpoints

```go
// GET /servers/{serverName}/oauth/authorize
func (h *OAuthHandler) AuthorizeHandler(w http.ResponseWriter, r *http.Request) {
    serverName := chi.URLParam(r, "serverName")
    serverConfig := h.config.MCPServers[serverName]
    
    // Generate state with return URL
    state := generateState()
    returnTo := r.URL.Query().Get("return_to")
    h.storeState(state, StateData{
        ServerName: serverName,
        ReturnTo:   returnTo,
        UserEmail:  getUserEmail(r),
    })
    
    // Build authorization URL
    authURL := buildAuthURL(serverConfig.UserAuthentication, state)
    http.Redirect(w, r, authURL, http.StatusFound)
}

// GET /servers/{serverName}/oauth/callback
func (h *OAuthHandler) CallbackHandler(w http.ResponseWriter, r *http.Request) {
    code := r.URL.Query().Get("code")
    state := r.URL.Query().Get("state")
    
    // Verify state and get data
    stateData, err := h.verifyState(state)
    if err != nil {
        // Handle error
        return
    }
    
    // Exchange code for tokens
    tokens, err := h.exchangeCode(stateData.ServerName, code)
    if err != nil {
        // Handle error
        return
    }
    
    // Store tokens
    h.storage.SetUserToken(ctx, stateData.UserEmail, stateData.ServerName, tokens)
    
    // Redirect to final destination (Claude.ai)
    http.Redirect(w, r, stateData.ReturnTo, http.StatusFound)
}
```

### 3. Enhanced Config Types

```go
type UserAuthType string

const (
    UserAuthTypeManual UserAuthType = "manual"
    UserAuthTypeOAuth  UserAuthType = "oauth"
)

type UserAuthentication struct {
    Type        UserAuthType `json:"type"`
    DisplayName string       `json:"displayName"`
    
    // For OAuth
    ClientID         json.RawMessage `json:"clientId,omitempty"`
    ClientSecret     json.RawMessage `json:"clientSecret,omitempty"`
    AuthorizationURL string          `json:"authorizationUrl,omitempty"`
    TokenURL         string          `json:"tokenUrl,omitempty"`
    Scopes           []string        `json:"scopes,omitempty"`
    
    // For Manual  
    Instructions string `json:"instructions,omitempty"`
    HelpURL      string `json:"helpUrl,omitempty"`
    Validation   string `json:"validation,omitempty"`
    
    // Common
    TokenFormat string `json:"tokenFormat,omitempty"`
    
    // Resolved values (not in JSON)
    ResolvedClientID     string `json:"-"`
    ResolvedClientSecret string `json:"-"`
    CompiledValidation   *regexp.Regexp `json:"-"`
}
```

### 4. Token Storage with OAuth Metadata

```go
type OAuthTokenData struct {
    AccessToken  string    `json:"access_token"`
    RefreshToken string    `json:"refresh_token"`
    TokenType    string    `json:"token_type"`
    ExpiresAt    time.Time `json:"expires_at"`
    Scopes       []string  `json:"scopes"`
}

type StoredUserToken struct {
    Type      UserAuthType    `json:"type"`
    Token     string          `json:"token,omitempty"`     // For manual
    OAuthData *OAuthTokenData `json:"oauth,omitempty"`     // For OAuth
    UpdatedAt time.Time       `json:"updated_at"`
}
```

### 5. Automatic Token Refresh

```go
func (h *MCPHandler) getUserTokenIfAvailable(ctx context.Context, userEmail string) (string, error) {
    stored, err := h.storage.GetUserToken(ctx, userEmail, h.serverName)
    if err != nil {
        return "", err
    }
    
    if stored.Type == UserAuthTypeOAuth && stored.OAuthData != nil {
        // Check if token needs refresh
        if time.Now().After(stored.OAuthData.ExpiresAt.Add(-5 * time.Minute)) {
            // Refresh token
            client := NewOAuthClient(h.serverConfig.UserAuthentication)
            newTokens, err := client.RefreshToken(ctx, stored.OAuthData.RefreshToken)
            if err != nil {
                return "", fmt.Errorf("token refresh failed: %w", err)
            }
            
            // Update storage
            stored.OAuthData = newTokens
            stored.UpdatedAt = time.Now()
            h.storage.SetUserToken(ctx, userEmail, h.serverName, stored)
        }
        
        // Format token
        return formatToken(h.serverConfig.UserAuthentication.TokenFormat, 
                         stored.OAuthData.AccessToken), nil
    }
    
    // Manual token
    return formatToken(h.serverConfig.UserAuthentication.TokenFormat, stored.Token), nil
}
```

### 6. Routes Configuration

```go
// In server setup
mux.Handle("/servers/{serverName}/oauth/authorize", 
    chainMiddleware(oauthHandler.AuthorizeHandler, authMiddlewares...))
mux.Handle("/servers/{serverName}/oauth/callback", 
    chainMiddleware(oauthHandler.CallbackHandler, authMiddlewares...))

// Token management UI (for manual setup or re-auth)
mux.Handle("/my/tokens", 
    chainMiddleware(tokenHandlers.ListTokensHandler, authMiddlewares...))
```

## Benefits

1. **Seamless UX**: Single flow from Claude.ai through all OAuth steps
2. **No Manual Steps**: Users never need to copy/paste tokens
3. **Automatic Refresh**: Tokens refreshed transparently
4. **Secure**: OAuth best practices with state parameter
5. **Flexible**: Supports both OAuth and manual tokens

## Security Considerations

1. State parameter prevents CSRF attacks
2. OAuth secrets encrypted at rest
3. Tokens automatically refreshed before expiry
4. Each server has isolated OAuth configuration
5. Return URLs validated against whitelist

## Example: Complete Flow

1. User in Claude.ai clicks "Connect Stainless MCP"
2. Claude.ai redirects to: `https://mcp-front.com/authorize?client_id=claude&redirect_uri=https://claude.ai/callback&state=abc123&server=stainless`
3. User completes Google OAuth
4. mcp-front redirects to: `https://api.stainless.com/oauth/authorize?client_id=...&redirect_uri=https://mcp-front.com/servers/stainless/oauth/callback&state=xyz789`
5. User approves Stainless access
6. Stainless redirects back to mcp-front with code
7. mcp-front exchanges code for tokens, stores them
8. mcp-front redirects to: `https://claude.ai/callback?code=...&state=abc123`
9. Complete! Stainless MCP is now connected
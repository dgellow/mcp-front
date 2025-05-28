# mcp-front: MCP Servers on GCP Made Simple

## Objective

Fork/adapt TBXark/mcp-proxy to create OAuth 2.1 + GCP IAM authenticated proxy for multiple dockerized MCP servers, deployable on GCE.

## Research Phase

1. **Study TBXark/mcp-proxy codebase**

   - Existing routing and backend management patterns
   - SSE transport implementation details
   - Configuration structure and request handling

2. **Analyze MCP Authorization Spec 2025-03-26**

   - Required OAuth 2.1 authorization server endpoints
   - PKCE implementation requirements
   - Dynamic Client Registration (RFC7591) patterns

3. **Review MCP Python SDK simple-auth example**

   - OAuth server integration with MCP protocol
   - Token handling and validation patterns
   - Client registration and metadata discovery

4. **Evaluate OAuth 2.1 Libraries**
   - ory/fosite for Go (supports OAuth 2.1 with PKCE)
   - Storage adapters for token persistence
   - GCP IAM integration patterns

## Implementation Requirements

### Core Features

- **Single binary**: Combined MCP proxy + OAuth 2.1 server
- **Path-based routing**: `/notion/*` → notion-mcp-server, `/db/*` → db-mcp-server
- **OAuth 2.1 Authorization Server**: Single server for all MCP endpoints
- **Required OAuth endpoints**:
  - `/.well-known/oauth-authorization-server` - Server metadata
  - `/authorize` - Authorization code flow with PKCE
  - `/token` - Token exchange & refresh
  - `/register` - Dynamic client registration
- **SSE transport**: Maintain streaming capability for Claude.ai
- **stdio bridge**: Execute Docker containers and translate stdio ↔ SSE
- **GCP IAM validation**: Verify users belong to allowed domains

### Authentication Flow

```
Claude.ai → HTTPS → GCP LB → MCP Proxy (OAuth 2.1 + Routing)
                                 ├── OAuth endpoints
                                 ├── /notion/* → notion container
                                 └── /db/* → postgres container
```

### Configuration Structure

```yaml
oauth:
  issuer: "https://mcp-internal.domain.org"
  gcp_project: "your-gcp-project"
  allowed_domains: ["yourcompany.com"]
  token_ttl: 3600
  storage: "memory" # or "redis" for distributed

routes:
  - path: "/notion"
    type: "http"
    backend: "http://notion-mcp:9090"

  - path: "/db"
    type: "stdio"
    command: ["docker", "run", "--rm", "-i", "mcp/postgres:latest"]
    environment:
      DATABASE_URL: "${DATABASE_URL}"
    timeout: "5m"

  - path: "/git"
    type: "stdio"
    command:
      [
        "docker",
        "run",
        "--rm",
        "-i",
        "mcp/git:latest",
        "-v",
        "/repos:/repos:ro",
      ]
    timeout: "30s"

server:
  port: 8080
  health_path: "/health"
```

## Technical Implementation

### 1. Fork TBXark/mcp-proxy and Extend

```go
// main.go
type MCPProxy struct {
    oauth    fosite.OAuth2Provider
    storage  *GCPIAMStorage
    routes   map[string]Handler
    iamClient *iam.Service
}

func main() {
    // Initialize OAuth 2.1 provider with ory/fosite
    config := &fosite.Config{
        RequirePKCEForPublicClients: true,
        EnforcePKCE: true,
        AllowedPromptValues: []string{"none", "login", "consent"},
    }

    storage := NewGCPIAMStorage(gcpProject, allowedDomains)
    oauth := fosite.NewOAuth2Provider(storage, config)

    proxy := &MCPProxy{
        oauth: oauth,
        storage: storage,
        routes: loadRoutes(config),
    }

    // Register OAuth endpoints
    http.HandleFunc("/.well-known/oauth-authorization-server", proxy.Metadata)
    http.HandleFunc("/authorize", proxy.Authorize)
    http.HandleFunc("/token", proxy.Token)
    http.HandleFunc("/register", proxy.Register)

    // Register MCP routes
    for path, handler := range proxy.routes {
        http.Handle(path + "/", handler)
    }
}
```

### 2. GCP IAM Integration with Fosite Storage

```go
// storage.go
type GCPIAMStorage struct {
    *storage.MemoryStore  // Fosite's in-memory storage
    gcpProject     string
    allowedDomains []string
    iamClient      *iam.Service
    googleOAuth    *oauth2.Config  // Google OAuth config
}

func (s *GCPIAMStorage) AuthorizeUser(w http.ResponseWriter, r *http.Request) {
    // 1. Validate PKCE from Claude.ai
    ar, err := s.oauth.NewAuthorizeRequest(r.Context(), r)

    // 2. Redirect to Google OAuth
    state := generateState(ar)
    s.stateCache.Set(state, ar)

    googleURL := s.googleOAuth.AuthCodeURL(state)
    http.Redirect(w, r, googleURL, http.StatusFound)
}

func (s *GCPIAMStorage) GoogleCallback(w http.ResponseWriter, r *http.Request) {
    // 1. Exchange Google code for token
    token, err := s.googleOAuth.Exchange(r.Context(), r.FormValue("code"))

    // 2. Get user info
    client := s.googleOAuth.Client(r.Context(), token)
    resp, err := client.Get("https://www.googleapis.com/oauth2/v2/userinfo")

    var userInfo struct {
        Email string `json:"email"`
        HD    string `json:"hd"`  // Hosted domain
    }
    json.NewDecoder(resp.Body).Decode(&userInfo)

    // 3. Validate domain
    if !contains(s.allowedDomains, userInfo.HD) {
        http.Error(w, "Unauthorized domain", http.StatusForbidden)
        return
    }

    // 4. Complete OAuth 2.1 flow back to Claude.ai
    ar := s.stateCache.Get(state)
    resp := s.oauth.NewAuthorizeResponse(r.Context(), ar, session)
    s.oauth.WriteAuthorizeResponse(w, ar, resp)
}
```

### 3. stdio ↔ SSE Bridge Implementation

```go
// stdio_handler.go
type StdioHandler struct {
    command []string
    env     []string
    timeout time.Duration
}

func (h *StdioHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
    // Validate OAuth token
    token, err := h.oauth.ValidationBearer(r.Context(), r)
    if err != nil {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }

    // Setup SSE
    w.Header().Set("Content-Type", "text/event-stream")
    w.Header().Set("Cache-Control", "no-cache")

    // Create context with timeout
    ctx, cancel := context.WithTimeout(r.Context(), h.timeout)
    defer cancel()

    // Start process
    cmd := exec.CommandContext(ctx, h.command[0], h.command[1:]...)
    cmd.Env = append(os.Environ(), h.env...)

    stdin, _ := cmd.StdinPipe()
    stdout, _ := cmd.StdoutPipe()
    stderr, _ := cmd.StderrPipe()

    if err := cmd.Start(); err != nil {
        fmt.Fprintf(w, "event: error\ndata: %s\n\n", err.Error())
        return
    }

    // Cleanup on exit
    defer func() {
        stdin.Close()
        cmd.Process.Kill()
        cmd.Wait()
    }()

    // Handle stderr → SSE errors
    go h.streamErrors(stderr, w)

    // Main loop: HTTP body → stdin, stdout → SSE
    go h.forwardInput(r.Body, stdin)
    h.streamOutput(stdout, w)
}

func (h *StdioHandler) streamOutput(stdout io.Reader, w http.ResponseWriter) {
    scanner := bufio.NewScanner(stdout)
    for scanner.Scan() {
        // Parse JSON-RPC from stdout
        var msg json.RawMessage
        if err := json.Unmarshal(scanner.Bytes(), &msg); err != nil {
            continue
        }

        // Send as SSE
        fmt.Fprintf(w, "data: %s\n\n", msg)
        w.(http.Flusher).Flush()
    }
}

func (h *StdioHandler) streamErrors(stderr io.Reader, w http.ResponseWriter) {
    scanner := bufio.NewScanner(stderr)
    for scanner.Scan() {
        log.Printf("stderr: %s", scanner.Text())
        fmt.Fprintf(w, "event: error\ndata: {\"error\": \"%s\"}\n\n",
            scanner.Text())
        w.(http.Flusher).Flush()
    }
}
```

### 4. Process Lifecycle Management

```go
// lifecycle.go
type ProcessManager struct {
    activeProcesses sync.Map
}

func (pm *ProcessManager) Shutdown(ctx context.Context) error {
    var wg sync.WaitGroup

    pm.activeProcesses.Range(func(key, value interface{}) bool {
        wg.Add(1)
        go func(cmd *exec.Cmd) {
            defer wg.Done()

            // Graceful shutdown
            cmd.Process.Signal(syscall.SIGTERM)

            // Wait for graceful exit or timeout
            done := make(chan error)
            go func() { done <- cmd.Wait() }()

            select {
            case <-done:
                // Process exited gracefully
            case <-time.After(5 * time.Second):
                // Force kill
                cmd.Process.Kill()
            }
        }(value.(*exec.Cmd))
        return true
    })

    wg.Wait()
    return nil
}
```

## Deployment

### Docker Compose

```yaml
version: "3.8"
services:
  mcp-proxy:
    build: .
    ports:
      - "8080:8080"
    environment:
      - GCP_PROJECT_ID=${GCP_PROJECT_ID}
      - OAUTH_ISSUER=https://mcp-internal.domain.org
      - GOOGLE_CLIENT_ID=${GOOGLE_CLIENT_ID}
      - GOOGLE_CLIENT_SECRET=${GOOGLE_CLIENT_SECRET}
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock:ro
      - ./config.yaml:/config.yaml:ro

  # Only for HTTP-based MCP servers
  notion-mcp:
    image: mcp/notion:latest
    environment:
      - NOTION_TOKEN=${NOTION_TOKEN}
```

### GCE Deployment

```bash
# Build and push
docker build -t gcr.io/${PROJECT_ID}/mcp-proxy:latest .
docker push gcr.io/${PROJECT_ID}/mcp-proxy:latest

# Deploy with managed instance group for scaling
gcloud compute instance-templates create mcp-proxy-template \
    --machine-type=e2-standard-2 \
    --image-family=cos-stable \
    --image-project=cos-cloud \
    --container-image=gcr.io/${PROJECT_ID}/mcp-proxy:latest \
    --tags=mcp-proxy

# Create instance group
gcloud compute instance-groups managed create mcp-proxy-group \
    --template=mcp-proxy-template \
    --size=2 \
    --zone=us-central1-a
```

## Claude.ai Integration

1. **Add each MCP server to Claude.ai**:

   ```
   https://mcp-internal.domain.org/notion/sse
   https://mcp-internal.domain.org/db/sse
   https://mcp-internal.domain.org/git/sse
   ```

2. **First connection triggers OAuth flow**:

   - Claude.ai discovers `/.well-known/oauth-authorization-server`
   - Initiates OAuth 2.1 with PKCE
   - User redirected to Google sign-in
   - Domain validated against allowed list
   - Token issued for all MCP endpoints

3. **Subsequent connections use same token**

## Success Metrics

- OAuth 2.1 compliance verified with MCP test suite
- Sub-100ms latency for SSE streaming
- Zero zombie processes after 24h operation
- Successful authentication for all @company.com users
- Proper timeout handling for long-running commands

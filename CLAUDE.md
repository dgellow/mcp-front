# mcp-front: Agent Instructions for OAuth 2.1 Authenticated MCP Proxy

## Project Overview

mcp-front is a Go-based OAuth 2.1 proxy server for MCP (Model Context Protocol) servers. It provides authentication and authorization for Claude.ai to access company resources.

## Critical Rules for Agents

### 🚨 Security First

- **NEVER** commit secrets or hardcode credentials
- **NEVER** update git config
- **NEVER** push to remote unless explicitly asked
- **ALWAYS** use environment variables for sensitive data
- **ALWAYS** validate JWT secrets are at least 32 bytes

### 📁 File Handling

- **NEVER** delete files as the first step when making changes
- **ALWAYS** read existing code before modifying
- **ALWAYS** prefer editing existing files over creating new ones
- **NEVER** create documentation files (\*.md) unless explicitly requested
- **ALWAYS** understand the existing code structure before making changes

### 🧪 Testing Requirements

- **ALWAYS** run tests after making changes
- **ALWAYS** run staticcheck before committing
- **ALWAYS** ensure OAuth integration tests pass
- **NEVER** assume test frameworks - check README or codebase first

### 🔧 Code Standards

- **NEVER** add comments unless explicitly requested
- **ALWAYS** follow existing code conventions in the file
- **ALWAYS** check if a library exists before importing it
- **ALWAYS** use structured logging with slog at INFO level
- **ALWAYS** handle errors properly - no ignored errors

## Technical Excellence

### 🔐 Security

- **ALWAYS** encrypt sensitive data at rest (OAuth secrets, bearer tokens)
- **NEVER** store plaintext secrets in Firestore
- **ALWAYS** use AES-256-GCM for encryption
- **NEVER** log secrets

### 🏗️ Go Idioms

- Write simple, idiomatic Go - no Java patterns
- Use interfaces, not inheritance
- Handle errors explicitly
- Prefer flat structures over nested hierarchies

## Key Technical Context

### OAuth Implementation

- Uses fosite library for OAuth 2.1
- PKCE required for all flows
- Supports both public and confidential clients
- JWT secrets must be 32+ bytes for HMAC-SHA512/256
- State parameter entropy varies by environment (0 for dev, 8 for prod)

### Storage Options

1. **Memory** (default): Development only, data lost on restart
2. **Firestore**: Production, with configurable database and collection names
   - Default database: "(default)"
   - Default collection: "mcp_front_oauth_clients"

### Environment Variables

```bash
# Required
GOOGLE_CLIENT_ID="..."
GOOGLE_CLIENT_SECRET="..."
JWT_SECRET="..." # Must be 32+ bytes

# Optional
MCP_FRONT_ENV="development"  # Relaxes OAuth validation
LOG_LEVEL="debug"           # debug, info, warn, error
LOG_FORMAT="text"           # json or text
```

### Common Tasks

#### Adding a new MCP server

1. Check existing servers in config
2. Add to mcpServers section
3. Configure auth tokens if using bearer auth
4. Test the SSE endpoint

#### Updating OAuth scopes

1. Check `internal/oauth/auth.go` for current scopes
2. Use standard OpenID Connect scopes (not Google-specific URLs)
3. Update tests to verify new scopes work

#### Fixing CI issues

1. Check staticcheck version in `.github/workflows/ci.yml`
2. Run `go test ./...` locally first
3. Ensure Docker tags include both `latest` and `main-<sha>`

### Project Structure

```
internal/
├── config/      # Configuration parsing and validation
├── oauth/       # OAuth 2.1 implementation with fosite
├── server/      # HTTP server and middleware
├── client/      # MCP client management
└── logging.go   # Structured logging setup

integration/     # Integration tests (OAuth, security, scenarios)
cmd/mcp-front/   # Main application entry point
```

### Testing Guidance

- Unit tests: `go test ./internal/...`
- Integration tests: `cd integration && ./run_tests.sh`
- OAuth tests specifically: `go test ./internal/oauth -v`
- Security tests: `go test ./integration -run TestSecurity`

### Common Pitfalls to Avoid

1. Don't use `find` or `grep` commands - use Grep/Glob tools instead
2. Don't assume library availability - check go.mod first
3. Don't create new auth patterns - use existing OAuth or bearer token auth
4. Don't modify git configuration
5. Don't create README files proactively

### When Working on Features

1. Use TodoWrite tool to plan complex tasks
2. Read relevant code thoroughly before starting
3. Check existing patterns in similar files
4. Run tests incrementally as you work
5. Verify with `go build` before committing

### Security Boundaries

- mcp-front handles OAuth authentication only
- Does NOT validate/sanitize data sent to MCP servers
- Each MCP server is responsible for its own security
- SQL injection, command injection protection is MCP server's responsibility

## Quick Reference Commands

```bash
# Build
go build -o mcp-front ./cmd/mcp-front

# Test
go test ./...
go test ./integration -v

# Lint
staticcheck ./...

# Run locally
./mcp-front -config config.json
```

Remember: Think like an experienced engineer - understand the use cases, read the docs, plan properly, then execute.

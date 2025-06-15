---
title: Testing Guide
description: How to test MCP Front effectively
---

import { Aside, Code } from '@astrojs/starlight/components';

This guide covers testing strategies and practices for MCP Front development.

## Test Structure

### Test Organization

```
.
├── internal/
│   ├── config/
│   │   ├── config_test.go
│   │   └── validation_test.go
│   ├── oauth/
│   │   ├── oauth_test.go
│   │   └── firestore_test.go
│   └── server/
│       └── server_test.go
└── integration/
    ├── integration_test.go
    ├── oauth_test.go
    └── security_test.go
```

## Unit Testing

### Basic Test Structure

<Code code={`package config

import (
    "testing"
)

func TestValidateJWTSecret(t *testing.T) {
    tests := []struct {
        name    string
        secret  string
        wantErr bool
    }{
        {
            name:    "valid 32-byte secret",
            secret:  "12345678901234567890123456789012",
            wantErr: false,
        },
        {
            name:    "too short secret",
            secret:  "short",
            wantErr: true,
        },
        {
            name:    "empty secret",
            secret:  "",
            wantErr: true,
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            err := ValidateJWTSecret(tt.secret)
            if (err != nil) != tt.wantErr {
                t.Errorf("ValidateJWTSecret() error = %v, wantErr %v", err, tt.wantErr)
            }
        })
    }
}`} lang="go" title="config/validation_test.go" />

### Table-Driven Tests

Use table-driven tests for comprehensive coverage:

<Code code={`func TestParseConfig(t *testing.T) {
    tests := []struct {
        name      string
        jsonData  string
        want      *Config
        wantErr   bool
        errString string
    }{
        {
            name: "valid OAuth config",
            jsonData: \`{
                "version": "1.0",
                "proxy": {
                    "auth": {
                        "kind": "oauth",
                        "jwtSecret": "12345678901234567890123456789012"
                    }
                }
            }\`,
            want: &Config{
                Version: "1.0",
                Proxy: ProxyConfig{
                    Auth: AuthConfig{
                        Kind:      "oauth",
                        JWTSecret: "12345678901234567890123456789012",
                    },
                },
            },
            wantErr: false,
        },
        {
            name: "invalid JSON",
            jsonData: \`{invalid json}\`,
            wantErr: true,
            errString: "invalid character",
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            got, err := ParseConfig([]byte(tt.jsonData))
            
            if (err != nil) != tt.wantErr {
                t.Errorf("ParseConfig() error = %v, wantErr %v", err, tt.wantErr)
                return
            }
            
            if tt.wantErr && tt.errString != "" {
                if !strings.Contains(err.Error(), tt.errString) {
                    t.Errorf("ParseConfig() error = %v, want error containing %v", err, tt.errString)
                }
                return
            }
            
            if !reflect.DeepEqual(got, tt.want) {
                t.Errorf("ParseConfig() = %v, want %v", got, tt.want)
            }
        })
    }
}`} lang="go" title="config/config_test.go" />

### Mocking Dependencies

<Code code={`// Mock Firestore client for testing
type mockFirestoreClient struct {
    getFunc    func(ctx context.Context, docRef *firestore.DocumentRef) (*firestore.DocumentSnapshot, error)
    setFunc    func(ctx context.Context, docRef *firestore.DocumentRef, data interface{}) (*firestore.WriteResult, error)
    deleteFunc func(ctx context.Context, docRef *firestore.DocumentRef) (*firestore.WriteResult, error)
}

func (m *mockFirestoreClient) Get(ctx context.Context, docRef *firestore.DocumentRef) (*firestore.DocumentSnapshot, error) {
    if m.getFunc != nil {
        return m.getFunc(ctx, docRef)
    }
    return nil, errors.New("not implemented")
}

func TestFirestoreStorage_GetClient(t *testing.T) {
    mock := &mockFirestoreClient{
        getFunc: func(ctx context.Context, docRef *firestore.DocumentRef) (*firestore.DocumentSnapshot, error) {
            // Return mock data
            data := map[string]interface{}{
                "client_id":     "test-client",
                "client_secret": "hashed-secret",
                "redirect_uris": []string{"http://localhost:3000/callback"},
            }
            return &firestore.DocumentSnapshot{
                Ref:        docRef,
                CreateTime: time.Now(),
                UpdateTime: time.Now(),
                ReadTime:   time.Now(),
                Exists:     true,
                Data:       data,
            }, nil
        },
    }
    
    storage := &FirestoreStorage{client: mock}
    client, err := storage.GetClient(context.Background(), "test-client")
    
    if err != nil {
        t.Fatalf("GetClient() error = %v", err)
    }
    
    if client.GetID() != "test-client" {
        t.Errorf("GetClient() ID = %v, want %v", client.GetID(), "test-client")
    }
}`} lang="go" title="oauth/firestore_test.go" />

## Integration Testing

### Test Environment Setup

<Code code={`// integration/test_utils.go
package integration

import (
    "context"
    "testing"
    "time"
    
    "github.com/testcontainers/testcontainers-go"
    "github.com/testcontainers/testcontainers-go/wait"
)

func setupTestEnvironment(t *testing.T) *TestEnv {
    ctx := context.Background()
    
    // Start Firestore emulator
    firestoreContainer, err := testcontainers.GenericContainer(ctx, testcontainers.GenericContainerRequest{
        ContainerRequest: testcontainers.ContainerRequest{
            Image:        "gcr.io/google.com/cloudsdktool/cloud-sdk:emulators",
            ExposedPorts: []string{"8080/tcp"},
            Cmd:          []string{"gcloud", "emulators", "firestore", "start", "--host-port=0.0.0.0:8080"},
            WaitingFor:   wait.ForLog("Dev App Server is now running").WithStartupTimeout(30 * time.Second),
        },
        Started: true,
    })
    if err != nil {
        t.Fatalf("Failed to start Firestore emulator: %v", err)
    }
    
    // Get container details
    host, err := firestoreContainer.Host(ctx)
    if err != nil {
        t.Fatalf("Failed to get container host: %v", err)
    }
    
    port, err := firestoreContainer.MappedPort(ctx, "8080")
    if err != nil {
        t.Fatalf("Failed to get container port: %v", err)
    }
    
    // Set emulator environment
    t.Setenv("FIRESTORE_EMULATOR_HOST", fmt.Sprintf("%s:%s", host, port.Port()))
    
    return &TestEnv{
        FirestoreContainer: firestoreContainer,
        FirestoreHost:      fmt.Sprintf("%s:%s", host, port.Port()),
    }
}`} lang="go" title="integration/test_utils.go" />

### OAuth Flow Testing

<Code code={`func TestOAuthAuthorizationFlow(t *testing.T) {
    env := setupTestEnvironment(t)
    defer env.Cleanup()
    
    // Start MCP Front server
    srv := startTestServer(t, &config.Config{
        Proxy: config.ProxyConfig{
            Auth: config.AuthConfig{
                Kind:             "oauth",
                JWTSecret:       generateTestSecret(),
                GoogleClientID:  "test-client-id",
                GoogleClientSecret: "test-client-secret",
                Storage:         "firestore",
                FirestoreProjectID: "test-project",
            },
        },
    })
    defer srv.Close()
    
    // Test authorization request
    t.Run("authorization request", func(t *testing.T) {
        req := httptest.NewRequest("GET", "/oauth/authorize", nil)
        q := req.URL.Query()
        q.Set("client_id", "test-client")
        q.Set("redirect_uri", "http://localhost:3000/callback")
        q.Set("response_type", "code")
        q.Set("scope", "openid profile email")
        q.Set("state", "test-state")
        q.Set("code_challenge", "test-challenge")
        q.Set("code_challenge_method", "S256")
        req.URL.RawQuery = q.Encode()
        
        w := httptest.NewRecorder()
        srv.Handler.ServeHTTP(w, req)
        
        if w.Code != http.StatusFound {
            t.Errorf("Expected status %d, got %d", http.StatusFound, w.Code)
        }
        
        location := w.Header().Get("Location")
        if !strings.Contains(location, "accounts.google.com") {
            t.Errorf("Expected redirect to Google, got %s", location)
        }
    })
    
    // Test callback handling
    t.Run("callback handling", func(t *testing.T) {
        // Simulate Google callback
        req := httptest.NewRequest("GET", "/oauth/callback", nil)
        q := req.URL.Query()
        q.Set("code", "google-auth-code")
        q.Set("state", "test-state")
        req.URL.RawQuery = q.Encode()
        
        w := httptest.NewRecorder()
        srv.Handler.ServeHTTP(w, req)
        
        if w.Code != http.StatusFound {
            t.Errorf("Expected status %d, got %d", http.StatusFound, w.Code)
        }
    })
}`} lang="go" title="integration/oauth_test.go" />

### Security Testing

<Code code={`func TestSecurityHeaders(t *testing.T) {
    srv := startTestServer(t, testConfig)
    defer srv.Close()
    
    tests := []struct {
        name       string
        path       string
        wantHeaders map[string]string
    }{
        {
            name: "OAuth endpoints have security headers",
            path: "/oauth/authorize",
            wantHeaders: map[string]string{
                "X-Frame-Options":        "DENY",
                "X-Content-Type-Options": "nosniff",
                "X-XSS-Protection":      "1; mode=block",
                "Referrer-Policy":       "strict-origin-when-cross-origin",
            },
        },
        {
            name: "SSE endpoints have CORS headers",
            path: "/sse",
            wantHeaders: map[string]string{
                "Access-Control-Allow-Origin": "*",
                "Cache-Control":              "no-cache",
            },
        },
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            resp, err := http.Get(srv.URL + tt.path)
            if err != nil {
                t.Fatalf("Request failed: %v", err)
            }
            defer resp.Body.Close()
            
            for header, want := range tt.wantHeaders {
                got := resp.Header.Get(header)
                if got != want {
                    t.Errorf("Header %s = %q, want %q", header, got, want)
                }
            }
        })
    }
}`} lang="go" title="integration/security_test.go" />

## Performance Testing

### Benchmark Tests

<Code code={`func BenchmarkJWTGeneration(b *testing.B) {
    secret := generateTestSecret()
    claims := &jwt.StandardClaims{
        Subject:   "user@example.com",
        ExpiresAt: time.Now().Add(time.Hour).Unix(),
        IssuedAt:  time.Now().Unix(),
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
        _, err := token.SignedString([]byte(secret))
        if err != nil {
            b.Fatal(err)
        }
    }
}

func BenchmarkFirestoreRead(b *testing.B) {
    ctx := context.Background()
    client := setupFirestoreClient(b)
    
    // Prepare test data
    docRef := client.Collection("test").Doc("benchmark")
    _, err := docRef.Set(ctx, map[string]interface{}{
        "field1": "value1",
        "field2": "value2",
    })
    if err != nil {
        b.Fatal(err)
    }
    
    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        _, err := docRef.Get(ctx)
        if err != nil {
            b.Fatal(err)
        }
    }
}`} lang="go" title="internal/oauth/bench_test.go" />

### Load Testing

<Code code={`func TestHighConcurrentRequests(t *testing.T) {
    srv := startTestServer(t, testConfig)
    defer srv.Close()
    
    concurrency := 100
    requestsPerClient := 10
    
    var wg sync.WaitGroup
    errors := make(chan error, concurrency*requestsPerClient)
    
    for i := 0; i < concurrency; i++ {
        wg.Add(1)
        go func(clientID int) {
            defer wg.Done()
            
            client := &http.Client{
                Timeout: 10 * time.Second,
            }
            
            for j := 0; j < requestsPerClient; j++ {
                req, _ := http.NewRequest("GET", srv.URL+"/health", nil)
                req.Header.Set("Authorization", "Bearer test-token")
                
                resp, err := client.Do(req)
                if err != nil {
                    errors <- err
                    continue
                }
                
                if resp.StatusCode != http.StatusOK {
                    errors <- fmt.Errorf("unexpected status: %d", resp.StatusCode)
                }
                
                resp.Body.Close()
            }
        }(i)
    }
    
    wg.Wait()
    close(errors)
    
    var errorCount int
    for err := range errors {
        errorCount++
        t.Logf("Error: %v", err)
    }
    
    if errorCount > 0 {
        t.Errorf("Got %d errors out of %d requests", errorCount, concurrency*requestsPerClient)
    }
}`} lang="go" title="integration/load_test.go" />

## Test Coverage

### Running Coverage

```bash
# Generate coverage report
go test -coverprofile=coverage.out ./...

# View coverage in browser
go tool cover -html=coverage.out

# View coverage summary
go tool cover -func=coverage.out
```

### Coverage Requirements

- Aim for >80% coverage
- Critical paths should have >90%
- Security functions should have 100%

## Testing Best Practices

### 1. Test Naming

Use descriptive test names:

```go
// Good
func TestOAuthConfig_ValidateJWTSecret_RejectsShortSecrets(t *testing.T)

// Bad  
func TestValidate(t *testing.T)
```

### 2. Test Independence

Tests should not depend on each other:

```go
// Good - each test sets up its own data
func TestCreateClient(t *testing.T) {
    storage := setupTestStorage(t)
    // ... test logic
}

// Bad - relies on previous test
func TestUpdateClient(t *testing.T) {
    // Assumes TestCreateClient ran first
}
```

### 3. Test Data

Use test fixtures and helpers:

<Code code={`// testdata/fixtures.go
package testdata

var ValidOAuthConfig = \`{
    "version": "1.0",
    "proxy": {
        "auth": {
            "kind": "oauth",
            "jwtSecret": "test-secret-at-least-32-bytes-long"
        }
    }
}\`

var InvalidOAuthConfig = \`{
    "version": "1.0",
    "proxy": {
        "auth": {
            "kind": "oauth",
            "jwtSecret": "too-short"
        }
    }
}\``} lang="go" title="testdata/fixtures.go" />

### 4. Error Testing

Always test error cases:

```go
func TestParseConfig_ErrorCases(t *testing.T) {
    tests := []struct {
        name  string
        input string
        want  string // expected error message
    }{
        {"empty input", "", "unexpected end of JSON"},
        {"invalid JSON", "{invalid}", "invalid character"},
        {"missing required field", "{}", "missing required field"},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            _, err := ParseConfig([]byte(tt.input))
            if err == nil {
                t.Fatal("expected error, got nil")
            }
            if !strings.Contains(err.Error(), tt.want) {
                t.Errorf("error = %v, want containing %v", err, tt.want)
            }
        })
    }
}
```

## Continuous Integration

### GitHub Actions Workflow

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v4
    
    - name: Set up Go
      uses: actions/setup-go@v4
      with:
        go-version: '1.21'
    
    - name: Run unit tests
      run: go test -v -race -coverprofile=coverage.out ./...
    
    - name: Run integration tests
      run: |
        cd integration
        go test -v -timeout 2m
    
    - name: Upload coverage
      uses: codecov/codecov-action@v3
      with:
        file: ./coverage.out
```

<Aside type="tip">
  Always run tests with the `-race` flag to detect race conditions.
</Aside>

## Next Steps

- Review [Architecture Decisions](/mcp-front/dev/architecture-decisions/)
- Learn about [Contributing](/mcp-front/dev/contributing/)
- Explore [API Reference](/mcp-front/api/authentication/)
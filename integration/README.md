# Integration Tests

## Run Tests

```bash
# Complete test suite (CI/fresh env)
./run_tests.sh

# Quick test (assumes binary exists)
go test -v
```

## Run Demo

```bash
./run_demo.sh
```

The demo starts:
- PostgreSQL test database on port 15432
- Mock OAuth server on port 9090  
- mcp-front on port 8080

Connect Claude.ai to: `http://localhost:8080/postgres/sse`

## Files

- `integration_test.go` - End-to-end tests
- `security_test.go` - Security tests  
- `test_utils.go` - Test utilities
- `config/config.test.json` - Test config
- `config/config.demo.json` - Demo config
- `config/docker-compose.test.yml` - Test database  
- `fixtures/schema.sql` - Test data
- `run_tests.sh` - CI-ready test runner
- `run_demo.sh` - Demo environment
#!/bin/bash

# Integration test runner for CI and fresh dev environments
# Builds binary, sets up environment, runs tests, cleans up

set -e

echo "🧪 mcp-front Integration Test Runner"
echo "==================================="
echo ""

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Change to integration directory
cd "$(dirname "$0")"

# Function for cleanup
cleanup() {
    echo ""
    echo -e "${YELLOW}🧹 Cleaning up test environment...${NC}"
    docker-compose -f config/docker-compose.test.yml down -v 2>/dev/null || true
    pkill -f mcp-front 2>/dev/null || true
    echo "✅ Cleanup complete"
}

# Set up cleanup on exit
trap cleanup EXIT

echo "📋 Pre-flight checks..."

# Check required tools
echo -n "  - Docker: "
if ! command -v docker &> /dev/null; then
    echo -e "${RED}❌ Docker not found${NC}"
    exit 1
fi
echo "✅"

echo -n "  - Docker Compose: "
if ! command -v docker-compose &> /dev/null; then
    echo -e "${RED}❌ Docker Compose not found${NC}"
    exit 1
fi
echo "✅"

echo -n "  - Go: "
if ! command -v go &> /dev/null; then
    echo -e "${RED}❌ Go not found${NC}"
    exit 1
fi
echo "✅"

echo -n "  - mcp/postgres image: "
if ! docker image inspect mcp/postgres &> /dev/null; then
    echo -e "${GREEN}ℹ️  Not found, pulling...${NC}"
    docker pull mcp/postgres || {
        echo -e "${RED}❌ Failed to pull mcp/postgres image${NC}"
        exit 1
    }
fi
echo "✅"

echo ""
echo -e "${YELLOW}🔨 Building mcp-front binary...${NC}"
cd ..
go build -o mcp-front .
if [ ! -f "mcp-front" ]; then
    echo -e "${RED}❌ Build failed - binary not found${NC}"
    exit 1
fi
echo "✅ Binary built successfully"

cd integration
echo ""
echo -e "${YELLOW}🧪 Running integration tests...${NC}"
echo ""

# Run tests with timeout and verbose output
if go test -v -timeout 15m; then
    echo ""
    echo -e "${GREEN}🎉 All integration tests passed!${NC}"
    echo ""
    echo "Test coverage:"
    echo "  ✅ End-to-end integration"
    echo "  ✅ Security scenarios"
    echo "  ✅ Authentication bypass protection"
    echo "  ✅ Failure handling"
    echo "  ✅ OAuth 2.1 flow (Claude.ai compatibility)"
    echo "  ✅ Dynamic client registration"
    echo "  ✅ CORS headers and preflight"
    echo "  ✅ Health check endpoint"
    echo ""
    exit 0
else
    echo ""
    echo -e "${RED}❌ Integration tests failed${NC}"
    echo ""
    echo -e "${YELLOW}🔍 Docker Compose logs:${NC}"
    echo "----------------------------------------"
    docker-compose -f config/docker-compose.test.yml logs 2>/dev/null || echo "No Docker logs available"
    echo "----------------------------------------"
    echo ""
    exit 1
fi
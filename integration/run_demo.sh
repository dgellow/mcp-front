#!/bin/bash

# Run the integration test environment for real Claude.ai connection

set -e

echo "🚀 Starting mcp-front demo environment..."
echo "========================================="
echo ""

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Change to integration directory
cd "$(dirname "$0")"

# Clean up any existing processes
echo "🧹 Cleaning up any existing processes..."
docker-compose -f config/docker-compose.test.yml down -v 2>/dev/null || true
pkill -f mcp-front 2>/dev/null || true
sleep 2

# Start PostgreSQL test database
echo -e "${YELLOW}📦 Starting PostgreSQL test database...${NC}"
docker-compose -f config/docker-compose.test.yml up -d
echo "   Database: postgresql://testuser:testpass@localhost:15432/testdb"
echo "   Test data: users and orders tables"

# Wait for database to be ready
echo "⏳ Waiting for database to be ready..."
for i in {1..30}; do
    if docker-compose -f config/docker-compose.test.yml exec -T test-postgres pg_isready -U testuser -d testdb &>/dev/null; then
        echo -e "${GREEN}✅ Database is ready!${NC}"
        break
    fi
    echo -n "."
    sleep 1
done
echo ""

# Check for Google OAuth credentials
if [ -z "$GOOGLE_CLIENT_ID" ] || [ -z "$GOOGLE_CLIENT_SECRET" ]; then
    echo -e "${YELLOW}⚠️  No Google OAuth credentials found in environment${NC}"
    echo "   Using simple token authentication instead"
    echo "   To enable OAuth, set GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET"
    USE_OAUTH=false
else
    echo -e "${YELLOW}🔐 Google OAuth configured${NC}"
    echo "   Client ID: ${GOOGLE_CLIENT_ID:0:20}..."
    USE_OAUTH=true
fi

# Build mcp-front
echo -e "${YELLOW}🔨 Building mcp-front...${NC}"
cd ..
go build -o mcp-front .
if [ $? -ne 0 ]; then
    echo "❌ Build failed!"
    exit 1
fi
cd integration
echo "✅ Build successful"

# Start mcp-front
echo -e "${YELLOW}🚀 Starting mcp-front...${NC}"
if [ "$USE_OAUTH" = true ]; then
    echo "   Using OAuth config because GOOGLE_CLIENT_ID and GOOGLE_CLIENT_SECRET are set"
    echo "   Config: config/config.oauth-test.json"
    JWT_SECRET="${JWT_SECRET:-demo-jwt-secret-for-testing-32-chars-long}" ../mcp-front -config config/config.oauth-test.json &
else
    echo "   Using token config because Google OAuth credentials not found"
    echo "   Config: config/config.demo-token.json" 
    ../mcp-front -config config/config.demo-token.json &
fi
MCP_PID=$!

# Wait for mcp-front to be ready
echo "⏳ Waiting for mcp-front to be ready..."
for i in {1..30}; do
    if curl -s -f http://localhost:8080/health >/dev/null 2>&1 || curl -s http://localhost:8080/postgres/ 2>&1 | grep -q "Unauthorized"; then
        echo -e "${GREEN}✅ mcp-front is ready!${NC}"
        break
    fi
    echo -n "."
    sleep 1
done
echo ""

# Display connection information
echo ""
echo "==========================================="
echo -e "${GREEN}🎉 Demo environment is ready!${NC}"
echo "==========================================="
echo ""
echo "MCP Server URLs for Claude.ai:"
echo -e "${YELLOW}  http://localhost:8080/postgres/sse${NC}"
echo ""
if [ "$USE_OAUTH" = true ]; then
    echo "Authentication: Google OAuth"
    echo "  OAuth discovery: http://localhost:8080/.well-known/oauth-authorization-server"
    echo "  Allowed domains: test.com (see config/config.oauth-test.json)"
    echo ""
    echo "To connect from MCP Inspector:"
    echo "1. Add MCP server: http://localhost:8080/postgres/sse"
    echo "2. The OAuth flow will start automatically"
    echo "3. Sign in with a Google account from an allowed domain"
else
    echo "Authentication: Bearer Token"
    echo "  Token: test-token (or demo-token)"
    echo ""
    echo "To connect from Claude.ai or MCP Inspector:"
    echo "1. Add MCP server: http://localhost:8080/postgres/sse"
    echo "2. Use Bearer token: test-token"
fi
echo ""
echo "Database contains test data:"
echo "  - users table (Alice, Bob, Charlie)"
echo "  - orders table (sample orders)"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop the demo environment${NC}"
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down demo environment..."
    kill $MCP_PID 2>/dev/null || true
    docker-compose -f config/docker-compose.test.yml down -v
    echo "✅ Demo environment stopped"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Keep running
while true; do
    sleep 1
done
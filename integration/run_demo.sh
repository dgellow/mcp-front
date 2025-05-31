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

# Start mock OAuth server
echo -e "${YELLOW}🔐 Starting mock OAuth server...${NC}"
# Run a simple OAuth mock server
cat > /tmp/mock_oauth.py << 'EOF'
from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import urllib.parse

class OAuthHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path.startswith('/auth'):
            # OAuth authorization endpoint
            query = urllib.parse.urlparse(self.path).query
            params = urllib.parse.parse_qs(query)
            redirect_uri = params.get('redirect_uri', [''])[0]
            state = params.get('state', [''])[0]
            
            # Redirect back with auth code
            redirect_url = f"{redirect_uri}?code=test-auth-code&state={state}"
            self.send_response(302)
            self.send_header('Location', redirect_url)
            self.end_headers()
        else:
            self.send_response(404)
            self.end_headers()
    
    def do_POST(self):
        if self.path == '/token':
            # Token endpoint
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "access_token": "test-access-token",
                "token_type": "Bearer",
                "expires_in": 3600
            }
            self.wfile.write(json.dumps(response).encode())
        elif self.path == '/userinfo':
            # Userinfo endpoint
            self.send_response(200)
            self.send_header('Content-Type', 'application/json')
            self.end_headers()
            response = {
                "email": "demo@test.com",
                "hd": "test.com"
            }
            self.wfile.write(json.dumps(response).encode())
        else:
            self.send_response(404)
            self.end_headers()
    
    def log_message(self, format, *args):
        # Suppress logs
        pass

print("Mock OAuth server running on http://localhost:9090")
httpd = HTTPServer(('localhost', 9090), OAuthHandler)
httpd.serve_forever()
EOF

python3 /tmp/mock_oauth.py &
OAUTH_PID=$!
echo "   OAuth endpoints: http://localhost:9090"
sleep 2

# Set up environment variables for OAuth
export GOOGLE_OAUTH_AUTH_URL=http://localhost:9090/auth
export GOOGLE_OAUTH_TOKEN_URL=http://localhost:9090/token
export GOOGLE_USERINFO_URL=http://localhost:9090/userinfo

# Start mcp-front
echo -e "${YELLOW}🚀 Starting mcp-front...${NC}"
../mcp-front -config config/config.demo.json &
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
echo "Authentication:"
echo "  Token: test-token"
echo ""
echo "Database contains test data:"
echo "  - users table (Alice, Bob, Charlie)"
echo "  - orders table (sample orders)"
echo ""
echo "OAuth endpoints (mock):"
echo "  Auth: http://localhost:9090/auth"
echo "  Token: http://localhost:9090/token"
echo ""
echo "To connect from Claude.ai:"
echo "1. Add MCP server: http://localhost:8080/postgres/sse"
echo "2. It will use OAuth flow or you can use token: test-token"
echo ""
echo -e "${YELLOW}Press Ctrl+C to stop the demo environment${NC}"
echo ""

# Function to cleanup on exit
cleanup() {
    echo ""
    echo "🛑 Shutting down demo environment..."
    kill $MCP_PID 2>/dev/null || true
    kill $OAUTH_PID 2>/dev/null || true
    docker-compose -f config/docker-compose.test.yml down -v
    rm -f /tmp/mock_oauth.py
    echo "✅ Demo environment stopped"
    exit 0
}

# Set up signal handlers
trap cleanup SIGINT SIGTERM

# Keep running
while true; do
    sleep 1
done
#!/bin/bash

# Integration test runner - quiet unless there are failures
set -e

# Colors
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# Change to integration directory
cd "$(dirname "$0")"

# Function for cleanup
cleanup() {
    docker-compose -f config/docker-compose.test.yml down -v &>/dev/null || true
    pkill -f mcp-front &>/dev/null || true
}

# Set up cleanup on exit
trap cleanup EXIT

# Check required tools silently
check_dependencies() {
    local missing=()
    
    command -v docker &>/dev/null || missing+=("docker")
    command -v docker-compose &>/dev/null || missing+=("docker-compose")
    command -v go &>/dev/null || missing+=("go")
    
    if [ ${#missing[@]} -ne 0 ]; then
        echo -e "${RED}❌ Missing required tools: ${missing[*]}${NC}"
        exit 1
    fi
    
    # Pull mcp/postgres if needed (silently)
    if ! docker image inspect mcp/postgres &>/dev/null; then
        docker pull mcp/postgres &>/dev/null || {
            echo -e "${RED}❌ Failed to pull mcp/postgres image${NC}"
            exit 1
        }
    fi
}

# Build binary
build_binary() {
    cd ..
    go build -o cmd/mcp-front/mcp-front ./cmd/mcp-front &>/dev/null
    if [ ! -f "cmd/mcp-front/mcp-front" ]; then
        echo -e "${RED}❌ Build failed${NC}"
        exit 1
    fi
    cd integration
}

# Simple spinner animation
show_animation() {
    local spinners=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
    local frame=0
    
    # Hide cursor
    tput civis
    
    while true; do
        printf "\r  ${spinners[$((frame % ${#spinners[@]}))]} Running tests..."
        frame=$((frame + 1))
        sleep 0.1
    done
}

# Run tests
run_tests() {
    # Create a log file for mcp-front output
    export MCP_LOG_FILE="/tmp/mcp-front-test.log"
    
    # Start animation in background
    show_animation &
    local anim_pid=$!
    
    # Run tests, capturing output
    if go test -timeout 15m &>/tmp/test-output.log; then
        # Kill animation and clear line
        kill $anim_pid 2>/dev/null || true
        wait $anim_pid 2>/dev/null || true
        printf "\r\033[K"
        tput cnorm  # Show cursor again
        
        # Success - print minimal output
        echo -e "${GREEN}✓ All tests passed${NC}"
        return 0
    else
        # Kill animation and clear line
        kill $anim_pid 2>/dev/null || true
        wait $anim_pid 2>/dev/null || true
        printf "\r\033[K"
        tput cnorm  # Show cursor again
        # Failure - show details
        echo -e "${RED}❌ Tests failed${NC}"
        echo ""
        echo "Test output:"
        echo "----------------------------------------"
        cat /tmp/test-output.log
        echo "----------------------------------------"
        echo ""
        
        # Show docker logs if available
        if docker-compose -f config/docker-compose.test.yml ps -q &>/dev/null; then
            echo "Docker logs:"
            echo "----------------------------------------"
            docker-compose -f config/docker-compose.test.yml logs 2>/dev/null || true
            echo "----------------------------------------"
            echo ""
        fi
        
        # Show mcp-front logs if available
        if [ -f "$MCP_LOG_FILE" ]; then
            echo "mcp-front logs (last 50 lines):"
            echo "----------------------------------------"
            tail -50 "$MCP_LOG_FILE" 2>/dev/null || true
            echo "----------------------------------------"
            echo ""
        fi
        
        return 1
    fi
}

# Main execution
check_dependencies
build_binary
run_tests
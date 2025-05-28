# Multi-stage build for smaller final image
FROM golang:1.23-alpine AS builder

# Install git for fetching dependencies
RUN apk add --no-cache git ca-certificates

WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o mcp-front .

# Final stage
FROM alpine:latest

# Install ca-certificates for HTTPS requests and docker CLI for stdio containers
RUN apk --no-cache add ca-certificates docker-cli

WORKDIR /root/

# Copy the binary from builder stage
COPY --from=builder /app/mcp-front .

# Copy config file
COPY config-oauth.json ./config.json

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/.well-known/oauth-authorization-server || exit 1

# Run the application
CMD ["./mcp-front"]
# MCP Auth Proxy Makefile

.PHONY: build test clean docker-build docker-push deploy-gce help

# Variables
BINARY_NAME=mcp-auth-proxy
DOCKER_IMAGE=mcp-auth-proxy
GCP_PROJECT_ID ?= your-gcp-project-id
IMAGE_TAG ?= latest
DOCKER_REGISTRY ?= gcr.io

# Build the binary
build:
	@echo "Building $(BINARY_NAME)..."
	go build -o $(BINARY_NAME) .

# Run tests
test:
	@echo "Running tests..."
	go test -v ./...

# Clean build artifacts
clean:
	@echo "Cleaning..."
	rm -f $(BINARY_NAME)
	docker rmi $(DOCKER_IMAGE):$(IMAGE_TAG) 2>/dev/null || true

# Build Docker image
docker-build:
	@echo "Building Docker image..."
	docker build -t $(DOCKER_IMAGE):$(IMAGE_TAG) .

# Push Docker image to registry
docker-push: docker-build
	@echo "Pushing to $(DOCKER_REGISTRY)/$(GCP_PROJECT_ID)/$(DOCKER_IMAGE):$(IMAGE_TAG)..."
	docker tag $(DOCKER_IMAGE):$(IMAGE_TAG) $(DOCKER_REGISTRY)/$(GCP_PROJECT_ID)/$(DOCKER_IMAGE):$(IMAGE_TAG)
	docker push $(DOCKER_REGISTRY)/$(GCP_PROJECT_ID)/$(DOCKER_IMAGE):$(IMAGE_TAG)

# Run locally with Docker Compose
run-local:
	@echo "Starting local environment..."
	docker-compose up --build

# Stop local environment
stop-local:
	@echo "Stopping local environment..."
	docker-compose down

# Deploy to GCE
deploy-gce: docker-push
	@echo "Deploying to GCE..."
	@if [ -z "$(GCP_PROJECT_ID)" ]; then \
		echo "Error: GCP_PROJECT_ID not set"; \
		exit 1; \
	fi
	
	# Create instance template
	gcloud compute instance-templates create mcp-proxy-template-$(shell date +%s) \
		--machine-type=e2-standard-2 \
		--image-family=cos-stable \
		--image-project=cos-cloud \
		--container-image=$(DOCKER_REGISTRY)/$(GCP_PROJECT_ID)/$(DOCKER_IMAGE):$(IMAGE_TAG) \
		--container-env-file=.env \
		--tags=mcp-proxy \
		--project=$(GCP_PROJECT_ID)

# Create health check
setup-health-check:
	@echo "Setting up health check..."
	gcloud compute health-checks create http mcp-proxy-health \
		--port=8080 \
		--request-path="/.well-known/oauth-authorization-server" \
		--project=$(GCP_PROJECT_ID) || true

# Create backend service
setup-backend:
	@echo "Setting up backend service..."
	gcloud compute backend-services create mcp-proxy-backend \
		--protocol=HTTP \
		--health-checks=mcp-proxy-health \
		--global \
		--project=$(GCP_PROJECT_ID) || true

# Create firewall rule
setup-firewall:
	@echo "Setting up firewall rule..."
	gcloud compute firewall-rules create allow-mcp-proxy \
		--allow tcp:8080 \
		--source-ranges 0.0.0.0/0 \
		--target-tags mcp-proxy \
		--project=$(GCP_PROJECT_ID) || true

# Full GCE setup
setup-gce: setup-health-check setup-backend setup-firewall
	@echo "GCE infrastructure setup complete"

# Format code
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Lint code
lint:
	@echo "Linting code..."
	golangci-lint run

# Security scan
security-scan:
	@echo "Running security scan..."
	gosec ./...

# Generate mocks (if using mockgen)
generate-mocks:
	@echo "Generating mocks..."
	go generate ./...

# Download dependencies
deps:
	@echo "Downloading dependencies..."
	go mod download
	go mod tidy

# Update dependencies
update-deps:
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy

# Run with OAuth config
run-oauth:
	@echo "Running with OAuth configuration..."
	./$(BINARY_NAME) -config config-oauth.json

# Run with original config (no OAuth)
run-simple:
	@echo "Running with simple token authentication..."
	./$(BINARY_NAME) -config mcp-proxy/config.json

# Check Docker is running
check-docker:
	@docker info > /dev/null 2>&1 || (echo "Error: Docker is not running" && exit 1)

# Development setup
dev-setup:
	@echo "Setting up development environment..."
	@if ! command -v go > /dev/null; then \
		echo "Error: Go is not installed"; \
		exit 1; \
	fi
	@if ! command -v docker > /dev/null; then \
		echo "Error: Docker is not installed"; \
		exit 1; \
	fi
	go mod download
	@echo "Development environment ready!"

# Help
help:
	@echo "Available targets:"
	@echo "  build           Build the binary"
	@echo "  test            Run tests"
	@echo "  clean           Clean build artifacts"
	@echo "  docker-build    Build Docker image"
	@echo "  docker-push     Push Docker image to registry"
	@echo "  run-local       Run with Docker Compose"
	@echo "  stop-local      Stop Docker Compose"
	@echo "  deploy-gce      Deploy to Google Compute Engine"
	@echo "  setup-gce       Set up GCE infrastructure"
	@echo "  run-oauth       Run with OAuth configuration"
	@echo "  run-simple      Run with simple token auth"
	@echo "  fmt             Format code"
	@echo "  lint            Lint code"
	@echo "  deps            Download dependencies"
	@echo "  dev-setup       Set up development environment"
	@echo "  help            Show this help message"
	@echo ""
	@echo "Variables:"
	@echo "  GCP_PROJECT_ID  GCP project ID (required for deployment)"
	@echo "  IMAGE_TAG       Docker image tag (default: latest)"
	@echo "  DOCKER_REGISTRY Docker registry (default: gcr.io)"
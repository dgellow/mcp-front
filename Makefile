doc:
	cd docs-site && npm run dev

format:
	go fmt ./...
	cd docs-site && npm run format

build:
	go build -o mcp-front ./cmd/mcp-front
	cd docs-site && npm run build

.PHONY: doc format build
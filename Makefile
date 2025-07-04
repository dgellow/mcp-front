doc:
	cd docs-site && npm run dev

format:
	go fmt ./...
	# go run golang.org/x/tools/gopls/internal/analysis/modernize/cmd/modernize@latest -fix -test ./...
	modernize -fix -test ./...
	cd docs-site && npm run format

lint:
	staticcheck ./...
	golangci-lint run ./...

build:
	go build -o mcp-front ./cmd/mcp-front
	cd docs-site && npm run build

.PHONY: doc format build lint
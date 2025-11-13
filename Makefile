.PHONY: build clean test install release-local help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
LDFLAGS := -s -w -X main.version=$(VERSION)

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build for current platform
	go build -ldflags="$(LDFLAGS)" -o serve

build-all: ## Build for all platforms
	@echo "Building for all platforms..."
	GOOS=linux GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/serve-linux-amd64
	GOOS=linux GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o dist/serve-linux-arm64
	GOOS=darwin GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/serve-darwin-amd64
	GOOS=darwin GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o dist/serve-darwin-arm64
	GOOS=windows GOARCH=amd64 go build -ldflags="$(LDFLAGS)" -o dist/serve-windows-amd64.exe
	GOOS=windows GOARCH=arm64 go build -ldflags="$(LDFLAGS)" -o dist/serve-windows-arm64.exe
	@echo "Done! Binaries are in ./dist/"

release-local: clean build-all ## Create local release archives
	@echo "Creating release archives..."
	@mkdir -p dist/archives
	cd dist && tar -czf archives/serve-linux-amd64.tar.gz serve-linux-amd64 ../README.md ../LICENSE ../config.example.json
	cd dist && tar -czf archives/serve-linux-arm64.tar.gz serve-linux-arm64 ../README.md ../LICENSE ../config.example.json
	cd dist && tar -czf archives/serve-darwin-amd64.tar.gz serve-darwin-amd64 ../README.md ../LICENSE ../config.example.json
	cd dist && tar -czf archives/serve-darwin-arm64.tar.gz serve-darwin-arm64 ../README.md ../LICENSE ../config.example.json
	cd dist && zip -q archives/serve-windows-amd64.zip serve-windows-amd64.exe ../README.md ../LICENSE ../config.example.json
	cd dist && zip -q archives/serve-windows-arm64.zip serve-windows-arm64.exe ../README.md ../LICENSE ../config.example.json
	@echo "Done! Archives are in ./dist/archives/"

clean: ## Clean build artifacts
	rm -f serve
	rm -rf dist/

test: ## Run tests
	go test -v ./...

test-coverage: ## Run tests with coverage
	go test -cover ./...

test-coverage-html: ## Generate HTML coverage report
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

test-short: ## Run tests without verbose output
	go test ./...

install: ## Install to $GOPATH/bin
	go install -ldflags="$(LDFLAGS)"

run: ## Run the server
	go run -ldflags="$(LDFLAGS)" .

fmt: ## Format code
	go fmt ./...

vet: ## Run go vet
	go vet ./...

lint: ## Run golangci-lint (if installed)
	@if command -v golangci-lint >/dev/null 2>&1; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not installed. Install from https://golangci-lint.run/"; \
	fi

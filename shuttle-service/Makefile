# Makefile for Shuttle Service

.PHONY: build run test clean docker docker-run deps fmt vet

# Variables
BINARY_NAME=shuttle-service
DOCKER_IMAGE=shuttle-service
DOCKER_TAG=latest

# Build the application
build:
	go build -o $(BINARY_NAME) .

# Run the application
run:
	go run . -config config.json

# Run tests
test:
	go test -v ./...

# Run tests with coverage
test-coverage:
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Clean build artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -f coverage.out coverage.html

# Install dependencies
deps:
	go mod download
	go mod tidy

# Format code
fmt:
	go fmt ./...

# Vet code
vet:
	go vet ./...

# Build Docker image
docker:
	docker build -t $(DOCKER_IMAGE):$(DOCKER_TAG) .

# Run with Docker Compose
docker-run:
	docker-compose up -d

# Stop Docker Compose
docker-stop:
	docker-compose down

# View logs
docker-logs:
	docker-compose logs -f shuttle-service

# Development setup
dev-setup: deps
	@echo "Creating default config if it doesn't exist..."
	@test -f config.json || echo '{}' > config.json
	@echo "Development setup complete!"

# Production build
build-prod:
	CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -ldflags '-w -s' -o $(BINARY_NAME) .

# Cross-platform builds
build-windows:
	GOOS=windows GOARCH=amd64 go build -o $(BINARY_NAME).exe .

build-mac:
	GOOS=darwin GOARCH=amd64 go build -o $(BINARY_NAME)-mac .

build-all: build build-windows build-mac

# Lint code (requires golangci-lint)
lint:
	golangci-lint run

# Security scan (requires gosec)
security:
	gosec ./...

# Install development tools
install-tools:
	go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest
	go install github.com/securecodewarrior/gosec/v2/cmd/gosec@latest

# Help
help:
	@echo "Available commands:"
	@echo "  build         - Build the application"
	@echo "  run           - Run the application"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  clean         - Clean build artifacts"
	@echo "  deps          - Install dependencies"
	@echo "  fmt           - Format code"
	@echo "  vet           - Vet code"
	@echo "  docker        - Build Docker image"
	@echo "  docker-run    - Run with Docker Compose"
	@echo "  docker-stop   - Stop Docker Compose"
	@echo "  docker-logs   - View logs"
	@echo "  dev-setup     - Set up development environment"
	@echo "  build-prod    - Production build"
	@echo "  build-all     - Build for all platforms"
	@echo "  lint          - Lint code"
	@echo "  security      - Security scan"
	@echo "  install-tools - Install development tools"
	@echo "  help          - Show this help"
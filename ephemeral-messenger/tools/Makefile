# Makefile for Ephemeral Messenger Key Management Tools
#
# This builds all key generation and management tools for the hardware
# key enforcement system.

.PHONY: all clean keygen keygen-gui yubikey-provision install test

# Default target
all: keygen keygen-gui yubikey-provision

# CLI Key Generation Tool
keygen:
	@echo "🔨 Building CLI key generation tool..."
	cd keygen && go build -o ../bin/keygen .
	@echo "✅ keygen built successfully"

# GUI Key Generation Tool
keygen-gui:
	@echo "🔨 Building GUI key generation tool..."
	cd keygen-gui && cargo build --release
	cp keygen-gui/target/release/keygen-gui bin/
	@echo "✅ keygen-gui built successfully"

# YubiKey Provisioning Tool
yubikey-provision:
	@echo "🔨 Building YubiKey provisioning tool..."
	cd yubikey-provision && go build -o ../bin/yubikey-provision .
	@echo "✅ yubikey-provision built successfully"

# Create bin directory
bin:
	mkdir -p bin

# Install dependencies
deps:
	@echo "📦 Installing dependencies..."
	cd keygen && go mod tidy
	cd yubikey-provision && go mod tidy
	cd keygen-gui && cargo fetch
	@echo "✅ Dependencies installed"

# Run tests
test: test-keygen test-yubikey

test-keygen:
	@echo "🧪 Testing key generation..."
	cd keygen && go test ./...

test-yubikey:
	@echo "🧪 Testing YubiKey tools..."
	cd yubikey-provision && go test ./...

# Install tools to system PATH
install: all
	@echo "📦 Installing tools to /usr/local/bin..."
	sudo cp bin/* /usr/local/bin/
	sudo chmod +x /usr/local/bin/keygen
	sudo chmod +x /usr/local/bin/keygen-gui
	sudo chmod +x /usr/local/bin/yubikey-provision
	@echo "✅ Tools installed successfully"

# Clean build artifacts
clean:
	@echo "🧹 Cleaning build artifacts..."
	rm -rf bin/
	cd keygen && go clean
	cd keygen-gui && cargo clean
	cd yubikey-provision && go clean
	@echo "✅ Clean completed"

# Development setup
dev-setup: deps bin
	@echo "🛠️  Development environment ready"
	@echo "Run 'make all' to build all tools"

# Help
help:
	@echo "Ephemeral Messenger Key Management Tools"
	@echo "========================================"
	@echo ""
	@echo "Available targets:"
	@echo "  all              - Build all tools"
	@echo "  keygen           - Build CLI key generation tool"
	@echo "  keygen-gui       - Build GUI key generation tool"
	@echo "  yubikey-provision- Build YubiKey provisioning tool"
	@echo "  deps             - Install dependencies"
	@echo "  test             - Run all tests"
	@echo "  install          - Install tools to system PATH"
	@echo "  clean            - Clean build artifacts"
	@echo "  dev-setup        - Set up development environment"
	@echo "  help             - Show this help message"
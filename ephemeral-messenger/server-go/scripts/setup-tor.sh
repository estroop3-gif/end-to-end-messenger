#!/bin/bash

# Ephemeral Messenger Tor Setup Script
# Sets up Tor with hidden services for secure messaging

set -euo pipefail

# Configuration
TOR_DATA_DIR="${TOR_DATA_DIR:-/var/lib/ephemeral-tor}"
TOR_CONFIG_DIR="${TOR_CONFIG_DIR:-/etc/ephemeral-tor}"
TOR_USER="${TOR_USER:-ephemeral}"
SERVICE_NAME="${SERVICE_NAME:-ephemeral-messenger}"
SERVICE_PORT="${SERVICE_PORT:-8443}"
CONTROL_PORT="${CONTROL_PORT:-9051}"
SOCKS_PORT="${SOCKS_PORT:-9050}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date +'%Y-%m-%d %H:%M:%S')]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if running as root
check_root() {
    if [[ $EUID -eq 0 ]]; then
        error "This script should not be run as root for security reasons"
        exit 1
    fi
}

# Install Tor if not present
install_tor() {
    log "Checking Tor installation..."

    if command -v tor &> /dev/null; then
        success "Tor is already installed: $(tor --version | head -n1)"
        return
    fi

    log "Installing Tor..."

    # Detect OS and install Tor
    if [[ "$OSTYPE" == "linux-gnu"* ]]; then
        if command -v apt-get &> /dev/null; then
            # Debian/Ubuntu
            sudo apt-get update
            sudo apt-get install -y tor tor-geoipdb obfs4proxy
        elif command -v yum &> /dev/null; then
            # RedHat/CentOS
            sudo yum install -y epel-release
            sudo yum install -y tor obfs4proxy
        elif command -v dnf &> /dev/null; then
            # Fedora
            sudo dnf install -y tor obfs4proxy
        elif command -v pacman &> /dev/null; then
            # Arch Linux
            sudo pacman -S tor obfs4proxy
        else
            error "Unsupported Linux distribution"
            exit 1
        fi
    elif [[ "$OSTYPE" == "darwin"* ]]; then
        # macOS
        if command -v brew &> /dev/null; then
            brew install tor
        else
            error "Homebrew is required on macOS"
            exit 1
        fi
    else
        error "Unsupported operating system: $OSTYPE"
        exit 1
    fi

    success "Tor installed successfully"
}

# Create necessary directories
create_directories() {
    log "Creating Tor directories..."

    # Create data directory
    mkdir -p "$TOR_DATA_DIR"
    chmod 700 "$TOR_DATA_DIR"

    # Create config directory
    mkdir -p "$TOR_CONFIG_DIR"
    chmod 755 "$TOR_CONFIG_DIR"

    # Create hidden service directory
    mkdir -p "$TOR_DATA_DIR/hidden_services"
    chmod 700 "$TOR_DATA_DIR/hidden_services"

    # Create service-specific directory
    mkdir -p "$TOR_DATA_DIR/hidden_services/$SERVICE_NAME"
    chmod 700 "$TOR_DATA_DIR/hidden_services/$SERVICE_NAME"

    success "Directories created"
}

# Generate Tor configuration
generate_torrc() {
    log "Generating Tor configuration..."

    local torrc_path="$TOR_CONFIG_DIR/torrc"

    cat > "$torrc_path" << EOF
# Ephemeral Messenger Tor Configuration
# Generated on $(date)

# Basic configuration
DataDirectory $TOR_DATA_DIR
ControlPort $CONTROL_PORT
SOCKSPort $SOCKS_PORT

# Logging
Log notice file $TOR_DATA_DIR/tor.log
SafeLogging 1

# Security
CookieAuthentication 1
ExcludeExitNodes {??}
StrictNodes 0

# Circuit settings
CircuitBuildTimeout 10
MaxCircuitDirtiness 600
NewCircuitPeriod 30

# Hidden service configuration
HiddenServiceDir $TOR_DATA_DIR/hidden_services/$SERVICE_NAME
HiddenServicePort 80 127.0.0.1:$SERVICE_PORT
HiddenServiceVersion 3

# Client settings
SocksPolicy accept *

# Performance
KeepalivePeriod 60
CircuitsAvailableTimeout 30

# Anonymous settings
IsolateClientAuth 1
IsolateClientProtocol 1
IsolateDestAddr 1
IsolateDestPort 1
EOF

    chmod 600 "$torrc_path"
    success "Tor configuration generated: $torrc_path"
}

# Generate client authorization keys
generate_client_auth() {
    log "Generating client authorization keys..."

    local auth_dir="$TOR_DATA_DIR/hidden_services/$SERVICE_NAME/authorized_clients"
    mkdir -p "$auth_dir"
    chmod 700 "$auth_dir"

    # Generate a sample client key
    local client_name="default_client"
    local client_key_file="$auth_dir/$client_name.auth"

    # Generate x25519 private key
    openssl genpkey -algorithm x25519 -out "$auth_dir/$client_name.key" 2>/dev/null || {
        # Fallback if x25519 not supported
        openssl ecparam -genkey -name secp256r1 -out "$auth_dir/$client_name.key"
    }

    # Create client auth file
    echo "descriptor:x25519:$(openssl pkey -in "$auth_dir/$client_name.key" -noout -text | grep -A1 'pub:' | tail -n1 | tr -d ' \n')" > "$client_key_file"

    chmod 600 "$auth_dir"/*

    success "Client authorization keys generated in $auth_dir"
}

# Start Tor daemon
start_tor() {
    log "Starting Tor daemon..."

    local torrc_path="$TOR_CONFIG_DIR/torrc"

    # Kill any existing Tor process
    pkill -f "tor.*$torrc_path" || true
    sleep 2

    # Start Tor
    nohup tor -f "$torrc_path" > "$TOR_DATA_DIR/tor_startup.log" 2>&1 &
    local tor_pid=$!

    # Wait for Tor to start
    log "Waiting for Tor to start..."
    local attempts=0
    local max_attempts=30

    while [[ $attempts -lt $max_attempts ]]; do
        if netstat -ln | grep -q ":$CONTROL_PORT "; then
            success "Tor started successfully (PID: $tor_pid)"
            echo "$tor_pid" > "$TOR_DATA_DIR/tor.pid"
            break
        fi

        sleep 1
        ((attempts++))
    done

    if [[ $attempts -eq $max_attempts ]]; then
        error "Tor failed to start within $max_attempts seconds"
        cat "$TOR_DATA_DIR/tor_startup.log"
        exit 1
    fi
}

# Get onion address
get_onion_address() {
    log "Retrieving onion address..."

    local hostname_file="$TOR_DATA_DIR/hidden_services/$SERVICE_NAME/hostname"
    local attempts=0
    local max_attempts=30

    while [[ $attempts -lt $max_attempts ]]; do
        if [[ -f "$hostname_file" ]]; then
            local onion_addr=$(cat "$hostname_file")
            success "Onion service address: $onion_addr"

            # Save to easily accessible location
            echo "$onion_addr" > "$TOR_DATA_DIR/onion_address"
            chmod 644 "$TOR_DATA_DIR/onion_address"

            return
        fi

        sleep 1
        ((attempts++))
    done

    error "Failed to retrieve onion address"
    exit 1
}

# Test Tor connection
test_connection() {
    log "Testing Tor connection..."

    # Test SOCKS proxy
    if curl --socks5-hostname "127.0.0.1:$SOCKS_PORT" -s "https://check.torproject.org/api/ip" | grep -q '"IsTor":true'; then
        success "Tor SOCKS proxy is working"
    else
        warning "Tor SOCKS proxy test failed"
    fi

    # Test control port
    if nc -z 127.0.0.1 "$CONTROL_PORT" 2>/dev/null; then
        success "Tor control port is accessible"
    else
        warning "Tor control port is not accessible"
    fi
}

# Create systemd service (optional)
create_systemd_service() {
    if [[ ! -d "/etc/systemd/system" ]]; then
        warning "Systemd not available, skipping service creation"
        return
    fi

    log "Creating systemd service..."

    local service_file="/etc/systemd/system/ephemeral-tor.service"

    sudo tee "$service_file" > /dev/null << EOF
[Unit]
Description=Ephemeral Messenger Tor Service
After=network.target
Wants=network.target

[Service]
Type=simple
User=$USER
Group=$USER
ExecStart=/usr/bin/tor -f $TOR_CONFIG_DIR/torrc
ExecReload=/bin/kill -HUP \$MAINPID
KillSignal=SIGINT
TimeoutStopSec=30
Restart=on-failure
RestartSec=5

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=strict
ReadWritePaths=$TOR_DATA_DIR

[Install]
WantedBy=multi-user.target
EOF

    sudo systemctl daemon-reload
    success "Systemd service created: $service_file"

    log "To enable and start the service:"
    echo "  sudo systemctl enable ephemeral-tor"
    echo "  sudo systemctl start ephemeral-tor"
}

# Generate usage instructions
generate_instructions() {
    log "Generating usage instructions..."

    local instructions_file="$TOR_DATA_DIR/USAGE_INSTRUCTIONS.txt"

    cat > "$instructions_file" << EOF
Ephemeral Messenger Tor Setup Complete
======================================

Configuration:
- Tor data directory: $TOR_DATA_DIR
- Tor config directory: $TOR_CONFIG_DIR
- SOCKS proxy: 127.0.0.1:$SOCKS_PORT
- Control port: 127.0.0.1:$CONTROL_PORT

Onion Service:
- Service name: $SERVICE_NAME
- Local port: $SERVICE_PORT
- Onion address: $(cat "$TOR_DATA_DIR/onion_address" 2>/dev/null || echo "Not yet available")

Files:
- Tor configuration: $TOR_CONFIG_DIR/torrc
- Onion address: $TOR_DATA_DIR/onion_address
- Tor log: $TOR_DATA_DIR/tor.log
- PID file: $TOR_DATA_DIR/tor.pid

Commands:
- Start Tor: tor -f $TOR_CONFIG_DIR/torrc
- Stop Tor: kill \$(cat $TOR_DATA_DIR/tor.pid)
- Test connection: curl --socks5-hostname 127.0.0.1:$SOCKS_PORT https://check.torproject.org/api/ip

Client Access:
To connect to the service through Tor:
1. Configure SOCKS proxy: 127.0.0.1:$SOCKS_PORT
2. Access the onion service: http://[onion_address]

Security Notes:
- Keep your private keys secure
- Monitor Tor logs for suspicious activity
- Regularly update Tor version
- Use client authorization for additional security

Generated on: $(date)
EOF

    chmod 644 "$instructions_file"
    success "Instructions saved to: $instructions_file"
}

# Cleanup function
cleanup() {
    log "Cleaning up..."

    # Stop Tor if we started it
    if [[ -f "$TOR_DATA_DIR/tor.pid" ]]; then
        local tor_pid=$(cat "$TOR_DATA_DIR/tor.pid")
        if kill -0 "$tor_pid" 2>/dev/null; then
            kill "$tor_pid"
            log "Stopped Tor process $tor_pid"
        fi
    fi
}

# Main execution
main() {
    log "Starting Ephemeral Messenger Tor setup..."

    # Set up cleanup trap
    trap cleanup EXIT

    # Run setup steps
    check_root
    install_tor
    create_directories
    generate_torrc
    generate_client_auth
    start_tor
    get_onion_address
    test_connection
    create_systemd_service
    generate_instructions

    success "Tor setup completed successfully!"
    echo ""
    echo "Next steps:"
    echo "1. Review the configuration in $TOR_CONFIG_DIR/torrc"
    echo "2. Check the onion address in $TOR_DATA_DIR/onion_address"
    echo "3. Start your Ephemeral Messenger server on port $SERVICE_PORT"
    echo "4. Test connectivity using the instructions in $TOR_DATA_DIR/USAGE_INSTRUCTIONS.txt"
    echo ""
    echo "Your onion service is accessible at:"
    cat "$TOR_DATA_DIR/onion_address" 2>/dev/null || echo "Address not yet available"
}

# Handle script arguments
case "${1:-setup}" in
    "setup")
        main
        ;;
    "start")
        start_tor
        ;;
    "stop")
        if [[ -f "$TOR_DATA_DIR/tor.pid" ]]; then
            kill "$(cat "$TOR_DATA_DIR/tor.pid")"
            success "Tor stopped"
        else
            warning "Tor PID file not found"
        fi
        ;;
    "status")
        if [[ -f "$TOR_DATA_DIR/tor.pid" ]] && kill -0 "$(cat "$TOR_DATA_DIR/tor.pid")" 2>/dev/null; then
            success "Tor is running (PID: $(cat "$TOR_DATA_DIR/tor.pid"))"
        else
            warning "Tor is not running"
        fi
        ;;
    "address")
        if [[ -f "$TOR_DATA_DIR/onion_address" ]]; then
            cat "$TOR_DATA_DIR/onion_address"
        else
            error "Onion address not found"
            exit 1
        fi
        ;;
    "test")
        test_connection
        ;;
    "help")
        echo "Usage: $0 [setup|start|stop|status|address|test|help]"
        echo ""
        echo "Commands:"
        echo "  setup  - Complete Tor setup (default)"
        echo "  start  - Start Tor daemon"
        echo "  stop   - Stop Tor daemon"
        echo "  status - Check Tor status"
        echo "  address - Show onion address"
        echo "  test   - Test Tor connection"
        echo "  help   - Show this help"
        ;;
    *)
        error "Unknown command: $1"
        echo "Use '$0 help' for usage information"
        exit 1
        ;;
esac
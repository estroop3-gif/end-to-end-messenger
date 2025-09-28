#!/bin/bash

# Ephemeral Messenger Tails Setup Script
# This script automates the secure deployment of Ephemeral Messenger on Tails OS
#
# SECURITY WARNING: Review this script before execution
# Only run on a clean Tails installation with persistence enabled

set -euo pipefail

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
PERSISTENT_DIR="/home/amnesia/Persistent"
APP_DIR="$PERSISTENT_DIR/ephemeral-messenger"
TOR_CONFIG_DIR="$PERSISTENT_DIR/tor-config"
LOG_FILE="$PERSISTENT_DIR/ephemeral-messenger-setup.log"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Logging function
log() {
    local level="$1"
    shift
    local message="$*"
    local timestamp=$(date '+%Y-%m-%d %H:%M:%S')

    case "$level" in
        "INFO")  echo -e "${GREEN}[INFO]${NC} $message" ;;
        "WARN")  echo -e "${YELLOW}[WARN]${NC} $message" ;;
        "ERROR") echo -e "${RED}[ERROR]${NC} $message" ;;
        "DEBUG") echo -e "${BLUE}[DEBUG]${NC} $message" ;;
    esac

    echo "[$timestamp] [$level] $message" >> "$LOG_FILE"
}

# Error handling
error_exit() {
    log "ERROR" "$1"
    exit 1
}

# Check if running on Tails
check_tails() {
    log "INFO" "Checking Tails environment..."

    if [[ ! -f /etc/amnesia/version ]]; then
        error_exit "This script must be run on Tails OS"
    fi

    if [[ ! -d "$PERSISTENT_DIR" ]]; then
        error_exit "Persistence is not enabled. Please enable persistence and reboot."
    fi

    local tails_version=$(cat /etc/amnesia/version)
    log "INFO" "Running on Tails $tails_version"
}

# Check prerequisites
check_prerequisites() {
    log "INFO" "Checking prerequisites..."

    # Check if running as amnesia user
    if [[ "$USER" != "amnesia" ]]; then
        error_exit "This script must be run as the amnesia user"
    fi

    # Check for required commands
    local required_commands=("git" "curl" "tor" "node" "npm" "go")
    for cmd in "${required_commands[@]}"; do
        if ! command -v "$cmd" &> /dev/null; then
            log "WARN" "$cmd is not installed. Installing dependencies..."
            install_dependencies
            break
        fi
    done

    log "INFO" "Prerequisites check completed"
}

# Install required dependencies
install_dependencies() {
    log "INFO" "Installing dependencies..."

    # Update package lists
    sudo apt update || error_exit "Failed to update package lists"

    # Install required packages
    sudo apt install -y \
        build-essential \
        git \
        curl \
        nodejs \
        npm \
        golang-go \
        tor \
        ufw \
        apparmor-utils \
        secure-delete \
        || error_exit "Failed to install dependencies"

    # Verify Go installation
    if ! go version &> /dev/null; then
        error_exit "Go installation failed"
    fi

    # Verify Node.js installation
    if ! node --version &> /dev/null; then
        error_exit "Node.js installation failed"
    fi

    log "INFO" "Dependencies installed successfully"
}

# Set up directory structure
setup_directories() {
    log "INFO" "Setting up directory structure..."

    # Create application directories
    mkdir -p "$APP_DIR"/{data,logs,backups,configs}
    mkdir -p "$TOR_CONFIG_DIR"

    # Set proper permissions
    chmod 700 "$APP_DIR"
    chmod 700 "$TOR_CONFIG_DIR"

    log "INFO" "Directory structure created"
}

# Configure Tor
configure_tor() {
    log "INFO" "Configuring Tor..."

    # Generate control password hash
    local control_password=$(openssl rand -base64 32)
    local password_hash=$(tor --hash-password "$control_password")

    # Create Tor configuration
    cat > "$TOR_CONFIG_DIR/torrc" << EOF
# Ephemeral Messenger Tor Configuration
# Generated on $(date)

# Basic Tor settings
SocksPort 9050
ControlPort 9051
HashedControlPassword $password_hash
CookieAuthentication 1

# Hidden service configuration
HiddenServiceDir $TOR_CONFIG_DIR/ephemeral-messenger
HiddenServiceVersion 3
HiddenServicePort 80 127.0.0.1:8080
HiddenServiceMaxStreams 50
HiddenServiceMaxStreamsCloseCircuit 1

# Security settings
AvoidDiskWrites 1
DisableDebuggerAttachment 1
SafeLogging 1

# Performance and reliability
NumEntryGuards 3
NumCPUs 2
KeepalivePeriod 60

# Circuit settings
NewCircuitPeriod 30
MaxCircuitDirtiness 600
LearnCircuitBuildTimeout 1

# Exit policy (no exit traffic)
ExitPolicy reject *:*
EOF

    # Store control password securely
    echo "$control_password" > "$TOR_CONFIG_DIR/control_password"
    chmod 600 "$TOR_CONFIG_DIR/control_password"

    # Verify Tor configuration
    if ! tor --verify-config -f "$TOR_CONFIG_DIR/torrc"; then
        error_exit "Tor configuration verification failed"
    fi

    log "INFO" "Tor configuration completed"
}

# Configure firewall
configure_firewall() {
    log "INFO" "Configuring firewall..."

    # Reset firewall
    sudo ufw --force reset

    # Set default policies
    sudo ufw default deny incoming
    sudo ufw default deny outgoing

    # Allow Tor traffic
    sudo ufw allow out 9050
    sudo ufw allow out 9051

    # Allow localhost communication
    sudo ufw allow out on lo
    sudo ufw allow in on lo
    sudo ufw allow from 127.0.0.1
    sudo ufw allow to 127.0.0.1

    # Enable firewall
    sudo ufw --force enable

    log "INFO" "Firewall configured"
}

# Create AppArmor profile
create_apparmor_profile() {
    log "INFO" "Creating AppArmor profile..."

    sudo tee /etc/apparmor.d/ephemeral-messenger > /dev/null << 'EOF'
#include <tunables/global>

/home/amnesia/Persistent/ephemeral-messenger/server/ephemeral-messenger-server {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  # Network access
  network inet stream,
  network inet6 stream,
  network unix stream,

  # File access permissions
  /home/amnesia/Persistent/ephemeral-messenger/** rw,
  /tmp/** rw,
  /proc/sys/kernel/random/uuid r,
  /dev/urandom r,

  # Deny direct network access
  deny network inet dgram,
  deny network inet6 dgram,
  deny network raw,

  # Deny unnecessary system access
  deny /etc/passwd r,
  deny /etc/shadow r,
  deny /home/** w,
  deny /root/** rwklx,
  deny /var/log/** w,
}
EOF

    # Load AppArmor profile
    sudo apparmor_parser -r /etc/apparmor.d/ephemeral-messenger

    log "INFO" "AppArmor profile created and loaded"
}

# Configure memory security
configure_memory_security() {
    log "INFO" "Configuring memory security..."

    # Configure kernel security settings
    sudo sysctl -w kernel.kptr_restrict=2
    sudo sysctl -w kernel.dmesg_restrict=1
    sudo sysctl -w net.core.bpf_jit_harden=2
    sudo sysctl -w kernel.unprivileged_bpf_disabled=1

    # Disable swap
    sudo swapoff -a

    # Make settings persistent
    sudo tee -a /etc/sysctl.conf > /dev/null << 'EOF'

# Ephemeral Messenger security settings
kernel.kptr_restrict=2
kernel.dmesg_restrict=1
net.core.bpf_jit_harden=2
kernel.unprivileged_bpf_disabled=1
EOF

    log "INFO" "Memory security configured"
}

# Build application
build_application() {
    log "INFO" "Building Ephemeral Messenger..."

    # Copy source code to persistent directory
    if [[ -d "$PROJECT_DIR" ]]; then
        cp -r "$PROJECT_DIR"/* "$APP_DIR/"
    else
        error_exit "Source code not found. Please ensure this script is run from the project directory."
    fi

    # Build Go server
    cd "$APP_DIR/server"
    log "INFO" "Building Go server..."
    go mod download || error_exit "Failed to download Go dependencies"
    go build -ldflags="-s -w" -o ephemeral-messenger-server . || error_exit "Failed to build Go server"

    # Build Tauri client
    cd "$APP_DIR/client-tauri"
    log "INFO" "Building Tauri client..."
    npm install || error_exit "Failed to install npm dependencies"
    npm run build || error_exit "Failed to build Tauri client"

    # Set executable permissions
    chmod +x "$APP_DIR/server/ephemeral-messenger-server"

    log "INFO" "Application built successfully"
}

# Create systemd service
create_systemd_service() {
    log "INFO" "Creating systemd service..."

    sudo tee /etc/systemd/system/ephemeral-messenger.service > /dev/null << EOF
[Unit]
Description=Ephemeral Messenger Server
After=network.target tor.service
Requires=tor.service

[Service]
Type=simple
User=amnesia
Group=amnesia
WorkingDirectory=$APP_DIR
ExecStart=$APP_DIR/server/ephemeral-messenger-server
Restart=always
RestartSec=10

# Security settings
NoNewPrivileges=yes
PrivateTmp=yes
PrivateDevices=yes
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=$APP_DIR

# Resource limits
LimitNOFILE=1024
LimitNPROC=512
MemoryMax=1G

# Environment
Environment=TOR_CONTROL_PORT=9051
Environment=TOR_SOCKS_PORT=9050

[Install]
WantedBy=multi-user.target
EOF

    # Reload systemd and enable service
    sudo systemctl daemon-reload
    sudo systemctl enable ephemeral-messenger

    log "INFO" "Systemd service created"
}

# Create startup script
create_startup_script() {
    log "INFO" "Creating startup script..."

    cat > "$APP_DIR/start-ephemeral-messenger.sh" << 'EOF'
#!/bin/bash

# Ephemeral Messenger Startup Script for Tails
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TOR_CONFIG_DIR="/home/amnesia/Persistent/tor-config"

echo "Starting Ephemeral Messenger on Tails..."

# Check if Tor is running
if ! pgrep -x "tor" > /dev/null; then
    echo "Error: Tor is not running. Please start Tor first."
    exit 1
fi

# Set security-conscious environment
export GOMEMLIMIT=512MiB
export GOMAXPROCS=2
export CGO_ENABLED=0

# Change to application directory
cd "$SCRIPT_DIR"

# Start Tor with custom configuration
echo "Starting Tor with custom configuration..."
tor -f "$TOR_CONFIG_DIR/torrc" --quiet &
TOR_PID=$!

# Wait for Tor to bootstrap
echo "Waiting for Tor to bootstrap..."
timeout 60 bash -c 'until nc -z 127.0.0.1 9051; do sleep 1; done'

if [ $? -ne 0 ]; then
    echo "Error: Tor failed to start properly"
    kill $TOR_PID 2>/dev/null || true
    exit 1
fi

# Get onion address
ONION_ADDRESS=""
if [[ -f "$TOR_CONFIG_DIR/ephemeral-messenger/hostname" ]]; then
    ONION_ADDRESS=$(cat "$TOR_CONFIG_DIR/ephemeral-messenger/hostname")
    echo "Onion service available at: $ONION_ADDRESS"
fi

# Start the server
echo "Starting Ephemeral Messenger server..."
./server/ephemeral-messenger-server &
SERVER_PID=$!

# Wait for server to start
sleep 5

# Check if server started successfully
if ! kill -0 $SERVER_PID 2>/dev/null; then
    echo "Error: Server failed to start"
    kill $TOR_PID 2>/dev/null || true
    exit 1
fi

echo "Ephemeral Messenger server is running (PID: $SERVER_PID)"
echo "Tor is running (PID: $TOR_PID)"
echo "Access the application at: http://localhost:8080"
if [[ -n "$ONION_ADDRESS" ]]; then
    echo "Onion service: http://$ONION_ADDRESS"
fi

# Function to cleanup on exit
cleanup() {
    echo "Shutting down Ephemeral Messenger..."
    kill $SERVER_PID 2>/dev/null || true
    kill $TOR_PID 2>/dev/null || true

    # Secure wipe of temporary files
    find /tmp -name "*ephemeral*" -type f -exec shred -vfz -n 3 {} \; 2>/dev/null || true

    echo "Shutdown complete."
}

# Set up signal handlers
trap cleanup EXIT INT TERM

echo "Press Ctrl+C to shutdown."

# Wait for processes
wait
EOF

    chmod +x "$APP_DIR/start-ephemeral-messenger.sh"

    log "INFO" "Startup script created"
}

# Create security check script
create_security_check_script() {
    log "INFO" "Creating security check script..."

    cat > "$APP_DIR/scripts/security-check.py" << 'EOF'
#!/usr/bin/env python3

"""
Ephemeral Messenger Security Check Script for Tails
Verifies security configuration and identifies potential issues
"""

import subprocess
import socket
import requests
import json
import sys
import os
from pathlib import Path

def check_tor_status():
    """Check if Tor is running and configured correctly"""
    print("Checking Tor status...")

    try:
        # Check if Tor is running
        result = subprocess.run(['pgrep', '-x', 'tor'], capture_output=True)
        if result.returncode != 0:
            print("❌ Tor is not running")
            return False

        # Check Tor SOCKS proxy
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        result = sock.connect_ex(('127.0.0.1', 9050))
        sock.close()

        if result != 0:
            print("❌ Tor SOCKS proxy not accessible")
            return False

        print("✅ Tor is running and accessible")
        return True

    except Exception as e:
        print(f"❌ Error checking Tor: {e}")
        return False

def check_firewall_status():
    """Check UFW firewall configuration"""
    print("Checking firewall status...")

    try:
        result = subprocess.run(['sudo', 'ufw', 'status'], capture_output=True, text=True)

        if 'Status: active' not in result.stdout:
            print("❌ Firewall is not active")
            return False

        # Check for required rules
        required_rules = ['9050', '9051', 'lo']
        for rule in required_rules:
            if rule not in result.stdout:
                print(f"❌ Missing firewall rule for {rule}")
                return False

        print("✅ Firewall is properly configured")
        return True

    except Exception as e:
        print(f"❌ Error checking firewall: {e}")
        return False

def check_apparmor_status():
    """Check AppArmor profile status"""
    print("Checking AppArmor status...")

    try:
        result = subprocess.run(['sudo', 'apparmor_status'], capture_output=True, text=True)

        if 'ephemeral-messenger' not in result.stdout:
            print("❌ AppArmor profile not loaded")
            return False

        print("✅ AppArmor profile is loaded")
        return True

    except Exception as e:
        print(f"❌ Error checking AppArmor: {e}")
        return False

def check_memory_security():
    """Check memory security settings"""
    print("Checking memory security...")

    security_settings = {
        'kernel.kptr_restrict': '2',
        'kernel.dmesg_restrict': '1',
        'net.core.bpf_jit_harden': '2',
        'kernel.unprivileged_bpf_disabled': '1'
    }

    try:
        for setting, expected in security_settings.items():
            result = subprocess.run(['sysctl', setting], capture_output=True, text=True)
            current_value = result.stdout.split('=')[1].strip()

            if current_value != expected:
                print(f"❌ {setting} is {current_value}, expected {expected}")
                return False

        print("✅ Memory security settings are correct")
        return True

    except Exception as e:
        print(f"❌ Error checking memory security: {e}")
        return False

def check_application_status():
    """Check if Ephemeral Messenger is running"""
    print("Checking application status...")

    try:
        # Check if server is responding
        response = requests.get('http://localhost:8080/health', timeout=5)

        if response.status_code == 200:
            health_data = response.json()
            print(f"✅ Application is running (status: {health_data.get('status', 'unknown')})")
            return True
        else:
            print(f"❌ Application health check failed (status: {response.status_code})")
            return False

    except requests.exceptions.RequestException as e:
        print(f"❌ Application is not responding: {e}")
        return False

def check_onion_service():
    """Check onion service status"""
    print("Checking onion service...")

    try:
        hostname_file = Path('/home/amnesia/Persistent/tor-config/ephemeral-messenger/hostname')

        if not hostname_file.exists():
            print("❌ Onion service hostname file not found")
            return False

        onion_address = hostname_file.read_text().strip()
        print(f"✅ Onion service: {onion_address}")

        # Try to connect through Tor
        proxies = {'http': 'socks5h://127.0.0.1:9050'}
        response = requests.get(f'http://{onion_address}/health',
                              proxies=proxies, timeout=30)

        if response.status_code == 200:
            print("✅ Onion service is accessible")
            return True
        else:
            print(f"❌ Onion service health check failed")
            return False

    except Exception as e:
        print(f"❌ Error checking onion service: {e}")
        return False

def main():
    """Main security check function"""
    print("Ephemeral Messenger Security Check")
    print("=" * 40)

    checks = [
        check_tor_status,
        check_firewall_status,
        check_apparmor_status,
        check_memory_security,
        check_application_status,
        check_onion_service
    ]

    passed = 0
    total = len(checks)

    for check in checks:
        if check():
            passed += 1
        print()

    print(f"Security Check Results: {passed}/{total} checks passed")

    if passed == total:
        print("✅ All security checks passed")
        return 0
    else:
        print("❌ Some security checks failed")
        return 1

if __name__ == '__main__':
    sys.exit(main())
EOF

    chmod +x "$APP_DIR/scripts/security-check.py"

    log "INFO" "Security check script created"
}

# Run security tests
run_security_tests() {
    log "INFO" "Running security tests..."

    cd "$APP_DIR"

    # Run crypto tests
    if [[ -f "tests/crypto_tests.py" ]]; then
        python3 tests/crypto_tests.py || log "WARN" "Crypto tests failed"
    fi

    # Run security tests
    if [[ -f "tests/security_tests.py" ]]; then
        python3 tests/security_tests.py || log "WARN" "Security tests failed"
    fi

    log "INFO" "Security tests completed"
}

# Create desktop launcher
create_desktop_launcher() {
    log "INFO" "Creating desktop launcher..."

    cat > "/home/amnesia/Desktop/Ephemeral Messenger.desktop" << EOF
[Desktop Entry]
Version=1.0
Type=Application
Name=Ephemeral Messenger
Comment=Secure Anonymous Messaging
Exec=$APP_DIR/start-ephemeral-messenger.sh
Icon=applications-internet
Terminal=true
Categories=Network;InstantMessaging;
StartupNotify=true
EOF

    chmod +x "/home/amnesia/Desktop/Ephemeral Messenger.desktop"

    log "INFO" "Desktop launcher created"
}

# Main setup function
main() {
    log "INFO" "Starting Ephemeral Messenger setup on Tails..."

    # Initialize log file
    touch "$LOG_FILE"
    chmod 600 "$LOG_FILE"

    # Run setup steps
    check_tails
    check_prerequisites
    setup_directories
    configure_tor
    configure_firewall
    create_apparmor_profile
    configure_memory_security
    build_application
    create_systemd_service
    create_startup_script
    create_security_check_script
    run_security_tests
    create_desktop_launcher

    log "INFO" "Setup completed successfully!"

    echo ""
    echo "=========================================="
    echo "Ephemeral Messenger Setup Complete!"
    echo "=========================================="
    echo ""
    echo "Next steps:"
    echo "1. Reboot Tails to ensure all security settings are applied"
    echo "2. After reboot, run: $APP_DIR/start-ephemeral-messenger.sh"
    echo "3. Run security check: python3 $APP_DIR/scripts/security-check.py"
    echo ""
    echo "Desktop launcher created: ~/Desktop/Ephemeral Messenger.desktop"
    echo "Log file: $LOG_FILE"
    echo ""
    echo "For help and documentation, see: $APP_DIR/docs/"
    echo ""
}

# Run main function
main "$@"
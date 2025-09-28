#!/bin/bash

# Ephemeral Onion Service Creation Script
# Creates a temporary Tor v3 onion service with optional client authorization

set -euo pipefail

# Configuration
TOR_CONTROL_PORT="${TOR_CONTROL_PORT:-9051}"
TOR_CONTROL_HOST="${TOR_CONTROL_HOST:-127.0.0.1}"
TOR_CONTROL_PASSWORD="${TOR_CONTROL_PASSWORD:-}"
LOCAL_PORT="${LOCAL_PORT:-8080}"
ONION_PORT="${ONION_PORT:-80}"
CLIENT_AUTH_KEY="${CLIENT_AUTH_KEY:-}"
VERBOSE="${VERBOSE:-false}"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log() {
    echo -e "${BLUE}[$(date '+%Y-%m-%d %H:%M:%S')]${NC} $1" >&2
}

error() {
    echo -e "${RED}[ERROR]${NC} $1" >&2
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1" >&2
}

warn() {
    echo -e "${YELLOW}[WARNING]${NC} $1" >&2
}

usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Creates an ephemeral Tor v3 onion service.

OPTIONS:
    -h, --help              Show this help message
    -p, --port PORT         Local port to expose (default: 8080)
    -o, --onion-port PORT   Onion service port (default: 80)
    -c, --control-port PORT Tor control port (default: 9051)
    -a, --auth-key KEY      Client authorization public key (optional)
    -v, --verbose           Verbose output
    --cleanup               Delete existing onion service and exit

EXAMPLES:
    # Create simple onion service
    $0

    # Create onion service with client authorization
    $0 --auth-key "descriptor:x25519:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="

    # Custom ports
    $0 --port 3000 --onion-port 80

ENVIRONMENT VARIABLES:
    TOR_CONTROL_PORT        Tor control port (default: 9051)
    TOR_CONTROL_HOST        Tor control host (default: 127.0.0.1)
    TOR_CONTROL_PASSWORD    Tor control password (if required)
    LOCAL_PORT             Local service port (default: 8080)
    ONION_PORT             Onion service port (default: 80)
    CLIENT_AUTH_KEY        Client authorization key
    VERBOSE                Enable verbose output (true/false)

EOF
}

check_dependencies() {
    local deps=("netcat" "timeout")
    for dep in "${deps[@]}"; do
        if ! command -v "$dep" &> /dev/null; then
            error "Required dependency '$dep' not found"
            return 1
        fi
    done
}

check_tor_connection() {
    log "Checking Tor control connection..."

    if ! timeout 5 netcat -z "$TOR_CONTROL_HOST" "$TOR_CONTROL_PORT" 2>/dev/null; then
        error "Cannot connect to Tor control port at $TOR_CONTROL_HOST:$TOR_CONTROL_PORT"
        error "Make sure Tor is running and ControlPort is enabled"
        return 1
    fi

    success "Connected to Tor control port"
}

send_tor_command() {
    local command="$1"
    local expected_response="${2:-250}"

    if [[ "$VERBOSE" == "true" ]]; then
        log "Sending command: $command"
    fi

    local response
    if [[ -n "$TOR_CONTROL_PASSWORD" ]]; then
        response=$(echo -e "AUTHENTICATE \"$TOR_CONTROL_PASSWORD\"\r\n$command\r\nQUIT\r\n" | \
                  timeout 10 netcat "$TOR_CONTROL_HOST" "$TOR_CONTROL_PORT" 2>/dev/null)
    else
        response=$(echo -e "AUTHENTICATE\r\n$command\r\nQUIT\r\n" | \
                  timeout 10 netcat "$TOR_CONTROL_HOST" "$TOR_CONTROL_PORT" 2>/dev/null)
    fi

    if [[ "$VERBOSE" == "true" ]]; then
        log "Response: $response"
    fi

    if ! echo "$response" | grep -q "^$expected_response"; then
        error "Tor command failed: $command"
        error "Response: $response"
        return 1
    fi

    echo "$response"
}

create_onion_service() {
    log "Creating ephemeral onion service..."

    local add_onion_cmd="ADD_ONION NEW:ED25519-V3 Port=$ONION_PORT,127.0.0.1:$LOCAL_PORT Flags=Detach"

    if [[ -n "$CLIENT_AUTH_KEY" ]]; then
        add_onion_cmd="$add_onion_cmd ClientAuth=$CLIENT_AUTH_KEY"
        log "Using client authorization"
    fi

    local response
    response=$(send_tor_command "$add_onion_cmd")

    # Extract onion address from response
    local onion_address
    onion_address=$(echo "$response" | grep "ServiceID=" | cut -d'=' -f2 | tr -d '\r')

    if [[ -z "$onion_address" ]]; then
        error "Failed to extract onion address from response"
        return 1
    fi

    # Store the service ID for cleanup
    echo "$onion_address" > "/tmp/ephemeral_onion_service_id"

    success "Onion service created: ${onion_address}.onion"
    echo "ONION_ADDRESS=${onion_address}.onion"
    echo "LOCAL_PORT=$LOCAL_PORT"
    echo "ONION_PORT=$ONION_PORT"

    if [[ -n "$CLIENT_AUTH_KEY" ]]; then
        echo "CLIENT_AUTH=enabled"
    fi
}

delete_onion_service() {
    if [[ ! -f "/tmp/ephemeral_onion_service_id" ]]; then
        warn "No ephemeral onion service found to delete"
        return 0
    fi

    local service_id
    service_id=$(cat "/tmp/ephemeral_onion_service_id")

    log "Deleting onion service: $service_id"

    local del_cmd="DEL_ONION $service_id"
    send_tor_command "$del_cmd" > /dev/null

    rm -f "/tmp/ephemeral_onion_service_id"
    success "Onion service deleted"
}

cleanup_on_exit() {
    log "Cleaning up..."
    delete_onion_service || true
}

generate_client_auth_key() {
    log "Generating client authorization key..."

    # Generate X25519 key pair for client authorization
    # This is a placeholder - use proper key generation in production
    local private_key
    private_key=$(openssl genpkey -algorithm X25519 2>/dev/null | openssl pkey -text -noout 2>/dev/null | \
                 grep -A1 "pub:" | tail -n1 | tr -d ' :' | head -c64)

    if [[ ${#private_key} -eq 64 ]]; then
        echo "CLIENT_AUTH_PRIVATE_KEY=$private_key"

        # Convert to descriptor format (simplified)
        echo "CLIENT_AUTH_KEY=descriptor:x25519:$(echo -n "$private_key" | base64 -w0)"
    else
        error "Failed to generate client authorization key"
        return 1
    fi
}

wait_for_service() {
    local onion_address="$1"
    local max_attempts=30
    local attempt=1

    log "Waiting for onion service to become available..."

    while [[ $attempt -le $max_attempts ]]; do
        if timeout 10 curl --socks5 127.0.0.1:9050 \
           "http://$onion_address:$ONION_PORT/health" &>/dev/null; then
            success "Onion service is responding"
            return 0
        fi

        log "Attempt $attempt/$max_attempts - waiting..."
        sleep 2
        ((attempt++))
    done

    warn "Onion service may not be fully ready yet"
    return 1
}

main() {
    local cleanup_only=false
    local generate_auth=false

    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            -h|--help)
                usage
                exit 0
                ;;
            -p|--port)
                LOCAL_PORT="$2"
                shift 2
                ;;
            -o|--onion-port)
                ONION_PORT="$2"
                shift 2
                ;;
            -c|--control-port)
                TOR_CONTROL_PORT="$2"
                shift 2
                ;;
            -a|--auth-key)
                CLIENT_AUTH_KEY="$2"
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            --cleanup)
                cleanup_only=true
                shift
                ;;
            --generate-auth)
                generate_auth=true
                shift
                ;;
            *)
                error "Unknown option: $1"
                usage
                exit 1
                ;;
        esac
    done

    # Check dependencies
    check_dependencies

    # Check Tor connection
    check_tor_connection

    # Handle cleanup-only mode
    if [[ "$cleanup_only" == "true" ]]; then
        delete_onion_service
        exit 0
    fi

    # Handle auth key generation
    if [[ "$generate_auth" == "true" ]]; then
        generate_client_auth_key
        exit 0
    fi

    # Set up cleanup on exit
    trap cleanup_on_exit EXIT INT TERM

    # Create the onion service
    create_onion_service

    # Extract onion address for health check
    local onion_address
    onion_address=$(cat "/tmp/ephemeral_onion_service_id")

    # Wait for service to be ready (optional)
    if [[ "$VERBOSE" == "true" ]]; then
        wait_for_service "$onion_address" || true
    fi

    # Keep running until interrupted
    log "Onion service is running. Press Ctrl+C to stop."

    # Wait for interrupt
    while true; do
        sleep 1
    done
}

# Run main function
main "$@"
#!/bin/sh

# Docker entrypoint script for Ephemeral Messenger
set -e

echo "Starting Ephemeral Messenger in Docker..."

# Set up Tor data directory permissions
chown -R messenger:messenger /tor-data

# Start Tor in background
echo "Starting Tor..."
tor -f /tor-config/torrc &
TOR_PID=$!

# Wait for Tor to start
echo "Waiting for Tor to bootstrap..."
sleep 10

# Check if Tor is running
if ! kill -0 $TOR_PID 2>/dev/null; then
    echo "Error: Tor failed to start"
    exit 1
fi

# Wait for Tor control port
timeout=30
while [ $timeout -gt 0 ]; do
    if nc -z localhost 9051; then
        break
    fi
    sleep 1
    timeout=$((timeout - 1))
done

if [ $timeout -eq 0 ]; then
    echo "Error: Tor control port not available"
    kill $TOR_PID 2>/dev/null || true
    exit 1
fi

# Display onion address when available
if [ -f /tor-data/ephemeral-messenger/hostname ]; then
    ONION_ADDRESS=$(cat /tor-data/ephemeral-messenger/hostname)
    echo "Onion service available at: $ONION_ADDRESS"
fi

# Set environment variables
export TOR_CONTROL_PORT=9051
export TOR_SOCKS_PORT=9050

# Function to handle shutdown
shutdown() {
    echo "Shutting down..."
    kill $TOR_PID 2>/dev/null || true
    exit 0
}

# Set up signal handlers
trap shutdown TERM INT

# Start the Ephemeral Messenger server
echo "Starting Ephemeral Messenger server..."
exec ./ephemeral-messenger-server
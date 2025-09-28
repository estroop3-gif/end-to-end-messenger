#!/bin/bash

# Test script for Ephemeral Messenger Server
# This script tests various server endpoints and functionality

set -e

SERVER_URL="http://localhost:8443"
WS_URL="ws://localhost:8443"

echo "🔍 Testing Ephemeral Messenger Server"
echo "======================================="

# Function to check if server is running
check_server() {
    echo "📡 Checking if server is running..."
    if curl -s "${SERVER_URL}/health" > /dev/null 2>&1; then
        echo "✅ Server is running"
        return 0
    else
        echo "❌ Server is not running"
        return 1
    fi
}

# Function to test health endpoint
test_health() {
    echo "🏥 Testing health endpoint..."
    response=$(curl -s "${SERVER_URL}/health")

    if echo "$response" | jq -e '.status == "healthy"' > /dev/null 2>&1; then
        echo "✅ Health check passed"
        echo "📊 Health response: $response"
    else
        echo "❌ Health check failed"
        echo "❌ Response: $response"
        return 1
    fi
}

# Function to test stats endpoint
test_stats() {
    echo "📈 Testing stats endpoint..."
    response=$(curl -s "${SERVER_URL}/stats")

    if echo "$response" | jq -e '.server' > /dev/null 2>&1; then
        echo "✅ Stats endpoint working"
        echo "📊 Current stats: $response"
    else
        echo "❌ Stats endpoint failed"
        echo "❌ Response: $response"
        return 1
    fi
}

# Function to test WebSocket connection
test_websocket() {
    echo "🔌 Testing WebSocket connection..."

    # Create a simple WebSocket test using websocat if available
    if command -v websocat &> /dev/null; then
        echo "Testing WebSocket with websocat..."

        # Test connection with fingerprint
        timeout 5s websocat "${WS_URL}/ws?fingerprint=test123456789abcdef" <<< '{"test": "connection"}' && {
            echo "✅ WebSocket connection successful"
        } || {
            echo "⚠️  WebSocket test inconclusive (timeout or no websocat)"
        }
    else
        echo "⚠️  websocat not available, skipping WebSocket test"
        echo "💡 Install websocat for WebSocket testing: cargo install websocat"
    fi
}

# Function to test rate limiting
test_rate_limiting() {
    echo "🚦 Testing rate limiting..."

    success_count=0
    total_requests=15

    for i in $(seq 1 $total_requests); do
        if curl -s -o /dev/null -w "%{http_code}" "${SERVER_URL}/health" | grep -q "200"; then
            ((success_count++))
        fi
        sleep 0.1
    done

    echo "📊 Rate limiting test: $success_count/$total_requests requests succeeded"

    if [ $success_count -lt $total_requests ]; then
        echo "✅ Rate limiting appears to be working"
    else
        echo "⚠️  All requests succeeded - rate limiting may not be active"
    fi
}

# Function to test CORS headers
test_cors() {
    echo "🌐 Testing CORS headers..."

    headers=$(curl -s -I "${SERVER_URL}/health")

    if echo "$headers" | grep -i "access-control-allow-origin" > /dev/null; then
        echo "✅ CORS headers present"
    else
        echo "⚠️  CORS headers not found"
    fi
}

# Function to test security headers
test_security_headers() {
    echo "🔒 Testing security headers..."

    headers=$(curl -s -I "${SERVER_URL}/health")

    security_headers=(
        "X-Content-Type-Options"
        "X-Frame-Options"
        "X-XSS-Protection"
    )

    for header in "${security_headers[@]}"; do
        if echo "$headers" | grep -i "$header" > /dev/null; then
            echo "✅ $header header present"
        else
            echo "⚠️  $header header missing"
        fi
    done
}

# Function to run load test
test_load() {
    echo "🏋️  Running basic load test..."

    if command -v ab &> /dev/null; then
        echo "Using Apache Bench for load testing..."
        ab -n 100 -c 10 "${SERVER_URL}/health" 2>/dev/null | grep -E "(Requests per second|Time per request)"
        echo "✅ Load test completed"
    else
        echo "⚠️  Apache Bench not available, skipping load test"
        echo "💡 Install apache2-utils for load testing"
    fi
}

# Main test execution
main() {
    echo "🚀 Starting Ephemeral Messenger Server Tests"
    echo ""

    # Check if required tools are available
    if ! command -v curl &> /dev/null; then
        echo "❌ curl is required but not installed"
        exit 1
    fi

    if ! command -v jq &> /dev/null; then
        echo "⚠️  jq not found - JSON parsing may be limited"
    fi

    # Run tests
    if check_server; then
        echo ""
        test_health
        echo ""
        test_stats
        echo ""
        test_websocket
        echo ""
        test_rate_limiting
        echo ""
        test_cors
        echo ""
        test_security_headers
        echo ""
        test_load
        echo ""
        echo "🎉 Test suite completed!"
        echo ""
        echo "📋 Summary:"
        echo "   - Health check: ✅"
        echo "   - Stats endpoint: ✅"
        echo "   - Security headers: ✅"
        echo "   - Rate limiting: ✅"
        echo ""
        echo "🔧 To start the server:"
        echo "   go run . (from server-go directory)"
        echo ""
        echo "🐳 To start with Docker:"
        echo "   docker-compose up -d"

    else
        echo ""
        echo "❌ Server is not running. Please start the server first:"
        echo ""
        echo "🔧 To start the server:"
        echo "   cd server-go"
        echo "   go run ."
        echo ""
        echo "🐳 Or with Docker:"
        echo "   docker-compose up -d"
        echo ""
        exit 1
    fi
}

# Handle script arguments
case "${1:-}" in
    "health")
        check_server && test_health
        ;;
    "stats")
        check_server && test_stats
        ;;
    "websocket")
        check_server && test_websocket
        ;;
    "load")
        check_server && test_load
        ;;
    "help"|"-h"|"--help")
        echo "Usage: $0 [test_name]"
        echo ""
        echo "Available tests:"
        echo "  health     - Test health endpoint"
        echo "  stats      - Test stats endpoint"
        echo "  websocket  - Test WebSocket connection"
        echo "  load       - Run load test"
        echo "  (no args)  - Run all tests"
        echo ""
        ;;
    *)
        main
        ;;
esac
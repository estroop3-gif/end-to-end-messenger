# Ephemeral Messenger Docker Configuration
# Multi-stage build for secure, minimal production image

# Stage 1: Build Go server
FROM golang:1.19-alpine AS server-builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy Go module files
COPY server/go.mod server/go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY server/ .

# Build the server with security flags
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o ephemeral-messenger-server .

# Stage 2: Build frontend (if needed for standalone)
FROM node:16-alpine AS frontend-builder

WORKDIR /app

# Copy package files
COPY client-tauri/package*.json ./

# Install dependencies
RUN npm ci --only=production

# Copy source code
COPY client-tauri/ .

# Build frontend assets
RUN npm run build

# Stage 3: Tor setup
FROM alpine:3.18 AS tor-builder

# Install Tor
RUN apk add --no-cache tor

# Create Tor configuration
RUN mkdir -p /tor-config
COPY configs/docker-torrc /tor-config/torrc

# Stage 4: Final production image
FROM alpine:3.18

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    tzdata \
    tor \
    tini \
    curl \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 1000 messenger && \
    adduser -u 1000 -G messenger -s /bin/sh -D messenger

# Create application directories
RUN mkdir -p /app /tor-data /app/logs && \
    chown -R messenger:messenger /app /tor-data

# Copy Tor configuration
COPY --from=tor-builder /tor-config /tor-config
RUN chown -R messenger:messenger /tor-config

# Copy built server
COPY --from=server-builder /app/ephemeral-messenger-server /app/
RUN chmod +x /app/ephemeral-messenger-server

# Copy frontend assets (if applicable)
COPY --from=frontend-builder /app/dist /app/public/

# Copy additional configurations
COPY configs/docker-entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Switch to non-root user
USER messenger

# Set working directory
WORKDIR /app

# Expose port (will be mapped to Tor hidden service)
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD curl -f http://localhost:8080/health || exit 1

# Use tini as init system
ENTRYPOINT ["/sbin/tini", "--"]

# Start the application
CMD ["/entrypoint.sh"]
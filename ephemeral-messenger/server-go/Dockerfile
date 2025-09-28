# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o server .

# Final stage
FROM alpine:latest

# Install runtime dependencies
RUN apk add --no-cache ca-certificates tzdata tor

# Create non-root user
RUN addgroup -g 1001 ephemeral && \
    adduser -D -s /bin/sh -u 1001 -G ephemeral ephemeral

# Set working directory
WORKDIR /home/ephemeral

# Copy binary from builder stage
COPY --from=builder /app/server .

# Copy configuration files
COPY --from=builder /app/config/ ./config/

# Create necessary directories
RUN mkdir -p /home/ephemeral/logs /home/ephemeral/tor

# Set ownership
RUN chown -R ephemeral:ephemeral /home/ephemeral

# Switch to non-root user
USER ephemeral

# Expose port
EXPOSE 8443

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8443/health || exit 1

# Run the server
CMD ["./server"]
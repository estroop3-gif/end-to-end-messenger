# Triple-Encryption Onion Transport Deployment Guide

## Overview

This guide covers deploying the complete triple-encryption onion transport system for the JESUS IS KING secure messenger. The system consists of:

1. **Client Applications** (Tauri Rust) - Desktop messaging clients
2. **Local Relays** (Go) - Local proxies for clients
3. **Shuttle Service** (Go) - Central message queuing service
4. **Redis** - Persistent message storage

## Architecture

```
[Client A] ←→ [Local Relay A] ←→ [Shuttle Service] ←→ [Local Relay B] ←→ [Client B]
     ↑              ↑                    ↑                   ↑              ↑
   Tauri           Go                   Go                  Go            Tauri
  Desktop       WebSocket             HTTP API           WebSocket      Desktop
```

## Prerequisites

### System Requirements

**Minimum Requirements:**
- CPU: 2 cores
- RAM: 4GB
- Storage: 10GB SSD
- Network: 100 Mbps

**Recommended for Production:**
- CPU: 4+ cores
- RAM: 8GB+
- Storage: 50GB+ SSD
- Network: 1 Gbps

### Software Dependencies

- **Go 1.21+** - For local relays and shuttle service
- **Rust 1.70+** - For client applications
- **Redis 7.0+** - For message persistence
- **Docker & Docker Compose** (optional but recommended)
- **nginx** - For reverse proxy (production)

## Component Deployment

### 1. Redis Setup

#### Docker Deployment (Recommended)

```bash
# Create Redis data directory
mkdir -p /opt/redis/data

# Create Redis configuration
cat > /opt/redis/redis.conf << EOF
bind 0.0.0.0
port 6379
protected-mode yes
requirepass your-secure-password-here

# Memory settings
maxmemory 2gb
maxmemory-policy allkeys-lru

# Persistence
save 900 1
save 300 10
save 60 10000
appendonly yes
appendfsync everysec

# Security
rename-command FLUSHDB ""
rename-command FLUSHALL ""
rename-command DEBUG ""
EOF

# Start Redis container
docker run -d \
  --name redis-shuttle \
  --restart unless-stopped \
  -p 6379:6379 \
  -v /opt/redis/data:/data \
  -v /opt/redis/redis.conf:/usr/local/etc/redis/redis.conf \
  redis:7.2-alpine redis-server /usr/local/etc/redis/redis.conf
```

#### Native Installation

```bash
# Install Redis (Ubuntu/Debian)
sudo apt update
sudo apt install redis-server

# Configure Redis
sudo nano /etc/redis/redis.conf

# Start Redis service
sudo systemctl enable redis-server
sudo systemctl start redis-server
```

### 2. Shuttle Service Deployment

#### Docker Deployment

```bash
# Create shuttle service directory
mkdir -p /opt/shuttle-service

# Create configuration
cat > /opt/shuttle-service/config.json << EOF
{
  "server": {
    "port": 8081,
    "host": "0.0.0.0",
    "read_timeout": "30s",
    "write_timeout": "30s",
    "idle_timeout": "120s",
    "enable_tls": true,
    "tls_cert": "/etc/ssl/shuttle/cert.pem",
    "tls_key": "/etc/ssl/shuttle/key.pem",
    "cors_origins": ["https://yourdomain.com"]
  },
  "redis": {
    "addr": "redis:6379",
    "password": "your-secure-password-here",
    "db": 0,
    "pool_size": 20,
    "min_idle_conns": 5,
    "max_retries": 3,
    "dial_timeout": "5s",
    "read_timeout": "3s",
    "write_timeout": "3s",
    "idle_timeout": "5m"
  },
  "queue": {
    "default_ttl": "24h",
    "max_ttl": "168h",
    "max_message_size": 2097152,
    "max_queue_size": 50000,
    "cleanup_interval": "5m",
    "max_retries": 3,
    "retry_delay": "1m",
    "dead_letter_ttl": "24h"
  },
  "auth": {
    "enabled": true,
    "jwt_secret": "your-jwt-secret-256-bits-minimum",
    "token_ttl": "24h",
    "api_keys": [
      {
        "name": "relay-service",
        "key": "your-api-key-here-minimum-32-chars",
        "permissions": ["offer", "claim", "ack"],
        "rate_limit": 10000
      }
    ],
    "require_https": true
  },
  "limits": {
    "rate_limit": {
      "enabled": true,
      "requests_per_minute": 1000,
      "burst_size": 100,
      "cleanup_interval": "5m",
      "by_ip": true,
      "by_api_key": true
    },
    "max_concurrent": 5000,
    "max_memory_mb": 2048,
    "max_connections": 10000
  }
}
EOF

# Create docker-compose file
cat > /opt/shuttle-service/docker-compose.yml << EOF
version: '3.8'

services:
  shuttle-service:
    image: your-registry/shuttle-service:latest
    container_name: shuttle-service
    restart: unless-stopped
    ports:
      - "8081:8081"
    volumes:
      - ./config.json:/app/config.json:ro
      - /etc/ssl/shuttle:/etc/ssl/shuttle:ro
    environment:
      - LOG_LEVEL=info
    depends_on:
      - redis
    networks:
      - shuttle-network
    healthcheck:
      test: ["CMD", "curl", "-f", "https://localhost:8081/api/v1/health"]
      interval: 30s
      timeout: 10s
      retries: 3

  redis:
    image: redis:7.2-alpine
    container_name: redis-shuttle
    restart: unless-stopped
    ports:
      - "6379:6379"
    volumes:
      - redis_data:/data
      - ./redis.conf:/usr/local/etc/redis/redis.conf:ro
    command: redis-server /usr/local/etc/redis/redis.conf
    networks:
      - shuttle-network
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
      interval: 30s
      timeout: 3s
      retries: 3

volumes:
  redis_data:
    driver: local

networks:
  shuttle-network:
    driver: bridge
EOF

# Deploy shuttle service
cd /opt/shuttle-service
docker-compose up -d
```

#### Native Deployment

```bash
# Build shuttle service
cd shuttle-service
make build-prod

# Create service user
sudo useradd -r -s /bin/false shuttle

# Create directories
sudo mkdir -p /opt/shuttle-service
sudo mkdir -p /var/log/shuttle-service
sudo mkdir -p /etc/shuttle-service

# Copy binary and config
sudo cp shuttle-service /opt/shuttle-service/
sudo cp config.json /etc/shuttle-service/
sudo chown -R shuttle:shuttle /opt/shuttle-service
sudo chown -R shuttle:shuttle /var/log/shuttle-service

# Create systemd service
cat > /etc/systemd/system/shuttle-service.service << EOF
[Unit]
Description=Shuttle Service for Onion Transport
After=network.target redis.service
Requires=redis.service

[Service]
Type=simple
User=shuttle
Group=shuttle
WorkingDirectory=/opt/shuttle-service
ExecStart=/opt/shuttle-service/shuttle-service -config /etc/shuttle-service/config.json
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/shuttle-service

[Install]
WantedBy=multi-user.target
EOF

# Start service
sudo systemctl daemon-reload
sudo systemctl enable shuttle-service
sudo systemctl start shuttle-service
```

### 3. Local Relay Deployment

#### Docker Deployment

```bash
# Create local relay directory
mkdir -p /opt/local-relay

# Create configuration
cat > /opt/local-relay/config.json << EOF
{
  "server": {
    "port": 8080,
    "host": "0.0.0.0",
    "enable_tls": true,
    "tls_cert": "/etc/ssl/relay/cert.pem",
    "tls_key": "/etc/ssl/relay/key.pem"
  },
  "shuttle": {
    "url": "https://shuttle.yourdomain.com",
    "api_key": "your-api-key-here-minimum-32-chars",
    "timeout": "30s"
  },
  "crypto": {
    "key_rotation_interval": "24h",
    "cleanup_interval": "1h"
  }
}
EOF

# Deploy local relay
docker run -d \
  --name local-relay \
  --restart unless-stopped \
  -p 8080:8080 \
  -v /opt/local-relay/config.json:/app/config.json:ro \
  -v /etc/ssl/relay:/etc/ssl/relay:ro \
  your-registry/local-relay:latest
```

#### Native Deployment

```bash
# Build local relay
cd local-relay
go build -o local-relay .

# Create service user
sudo useradd -r -s /bin/false relay

# Create directories
sudo mkdir -p /opt/local-relay
sudo mkdir -p /var/log/local-relay
sudo mkdir -p /etc/local-relay

# Copy binary and config
sudo cp local-relay /opt/local-relay/
sudo cp config.json /etc/local-relay/
sudo chown -R relay:relay /opt/local-relay
sudo chown -R relay:relay /var/log/local-relay

# Create systemd service
cat > /etc/systemd/system/local-relay.service << EOF
[Unit]
Description=Local Relay for Onion Transport
After=network.target

[Service]
Type=simple
User=relay
Group=relay
WorkingDirectory=/opt/local-relay
ExecStart=/opt/local-relay/local-relay -config /etc/local-relay/config.json
Restart=always
RestartSec=5
StandardOutput=journal
StandardError=journal

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/var/log/local-relay

[Install]
WantedBy=multi-user.target
EOF

# Start service
sudo systemctl daemon-reload
sudo systemctl enable local-relay
sudo systemctl start local-relay
```

### 4. Client Application Deployment

#### Build Client

```bash
# Build Tauri application
cd ephemeral-messenger/client-tauri
npm install
npm run tauri build

# Installers will be in src-tauri/target/release/bundle/
```

#### Distribution

**Windows:**
- Use the `.msi` installer from the build output
- Code signing recommended for production
- Windows Defender SmartScreen may require reputation building

**Linux:**
- Use the `.AppImage` for universal compatibility
- `.deb` packages for Debian/Ubuntu
- `.rpm` packages for Red Hat/Fedora

**macOS:**
- Use the `.dmg` installer
- Code signing and notarization required for distribution
- May require developer certificate

## Production Configuration

### SSL/TLS Certificates

#### Let's Encrypt (Recommended)

```bash
# Install certbot
sudo apt install certbot

# Generate certificates
sudo certbot certonly --standalone -d shuttle.yourdomain.com
sudo certbot certonly --standalone -d relay.yourdomain.com

# Copy certificates to service directories
sudo cp /etc/letsencrypt/live/shuttle.yourdomain.com/fullchain.pem /etc/ssl/shuttle/cert.pem
sudo cp /etc/letsencrypt/live/shuttle.yourdomain.com/privkey.pem /etc/ssl/shuttle/key.pem
sudo cp /etc/letsencrypt/live/relay.yourdomain.com/fullchain.pem /etc/ssl/relay/cert.pem
sudo cp /etc/letsencrypt/live/relay.yourdomain.com/privkey.pem /etc/ssl/relay/key.pem

# Set permissions
sudo chown shuttle:shuttle /etc/ssl/shuttle/*
sudo chown relay:relay /etc/ssl/relay/*
sudo chmod 600 /etc/ssl/shuttle/* /etc/ssl/relay/*
```

### Reverse Proxy (nginx)

```nginx
# /etc/nginx/sites-available/shuttle-service
server {
    listen 443 ssl http2;
    server_name shuttle.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/shuttle.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/shuttle.yourdomain.com/privkey.pem;

    # Security headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;

    # Rate limiting
    limit_req_zone $binary_remote_addr zone=shuttle:10m rate=100r/m;
    limit_req zone=shuttle burst=20 nodelay;

    location /api/v1/ {
        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Timeouts
        proxy_connect_timeout 5s;
        proxy_send_timeout 30s;
        proxy_read_timeout 30s;

        # Buffer settings
        proxy_buffering on;
        proxy_buffer_size 4k;
        proxy_buffers 8 4k;
    }

    location /health {
        proxy_pass http://127.0.0.1:8081/api/v1/health;
        access_log off;
    }
}

# /etc/nginx/sites-available/local-relay
server {
    listen 443 ssl http2;
    server_name relay.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/relay.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/relay.yourdomain.com/privkey.pem;

    # WebSocket support
    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # WebSocket timeouts
        proxy_read_timeout 3600s;
        proxy_send_timeout 3600s;
    }
}
```

### Firewall Configuration

```bash
# UFW (Ubuntu)
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP (for Let's Encrypt)
sudo ufw allow 443/tcp   # HTTPS
sudo ufw deny 6379/tcp   # Block direct Redis access
sudo ufw deny 8080/tcp   # Block direct relay access
sudo ufw deny 8081/tcp   # Block direct shuttle access
sudo ufw enable

# iptables (alternative)
iptables -A INPUT -p tcp --dport 22 -j ACCEPT
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
iptables -A INPUT -p tcp --dport 6379 -j DROP
iptables -A INPUT -p tcp --dport 8080 -j DROP
iptables -A INPUT -p tcp --dport 8081 -j DROP
```

## Monitoring & Logging

### Health Checks

```bash
# Shuttle service health
curl -f https://shuttle.yourdomain.com/api/v1/health

# Local relay health (WebSocket test)
wscat -c wss://relay.yourdomain.com/health

# Redis health
redis-cli ping
```

### Monitoring Setup

#### Prometheus Metrics (Future Enhancement)

```yaml
# prometheus.yml
global:
  scrape_interval: 15s

scrape_configs:
  - job_name: 'shuttle-service'
    static_configs:
      - targets: ['localhost:8081']
    metrics_path: '/api/v1/metrics'

  - job_name: 'local-relay'
    static_configs:
      - targets: ['localhost:8080']
    metrics_path: '/metrics'

  - job_name: 'redis'
    static_configs:
      - targets: ['localhost:9121']
```

#### Log Aggregation

```yaml
# docker-compose.logging.yml
version: '3.8'

services:
  shuttle-service:
    logging:
      driver: "json-file"
      options:
        max-size: "10m"
        max-file: "3"

  fluentd:
    image: fluent/fluentd:latest
    volumes:
      - ./fluentd.conf:/fluentd/etc/fluent.conf
    ports:
      - "24224:24224"
```

### Log Analysis

```bash
# Follow shuttle service logs
docker logs -f shuttle-service

# Filter error logs
journalctl -u shuttle-service | grep ERROR

# Check Redis logs
docker logs redis-shuttle

# Monitor connection counts
ss -tlnp | grep :8081
```

## Security Hardening

### System Hardening

```bash
# Disable unnecessary services
sudo systemctl disable bluetooth
sudo systemctl disable cups
sudo systemctl disable avahi-daemon

# Configure automatic security updates
sudo apt install unattended-upgrades
sudo dpkg-reconfigure unattended-upgrades

# Harden SSH
cat >> /etc/ssh/sshd_config << EOF
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
MaxAuthTries 3
ClientAliveInterval 300
ClientAliveCountMax 2
EOF

sudo systemctl reload sshd
```

### Key Management

```bash
# Generate strong API keys
openssl rand -hex 32

# Generate JWT secrets
openssl rand -base64 32

# Rotate keys regularly (monthly recommended)
# Update configuration files and restart services
```

### Access Control

```bash
# Limit Redis access
echo 'bind 127.0.0.1 ::1' >> /etc/redis/redis.conf

# Service user restrictions
sudo usermod -s /usr/sbin/nologin shuttle
sudo usermod -s /usr/sbin/nologin relay

# File permissions
sudo chmod 600 /etc/shuttle-service/config.json
sudo chmod 600 /etc/local-relay/config.json
```

## Backup & Recovery

### Database Backup

```bash
#!/bin/bash
# redis-backup.sh

BACKUP_DIR="/opt/backups/redis"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Create Redis backup
redis-cli BGSAVE
cp /var/lib/redis/dump.rdb $BACKUP_DIR/dump_$DATE.rdb

# Compress and encrypt
gzip $BACKUP_DIR/dump_$DATE.rdb
gpg --symmetric --cipher-algo AES256 $BACKUP_DIR/dump_$DATE.rdb.gz

# Cleanup old backups (keep 30 days)
find $BACKUP_DIR -name "*.rdb.gz.gpg" -mtime +30 -delete
```

### Configuration Backup

```bash
#!/bin/bash
# config-backup.sh

BACKUP_DIR="/opt/backups/config"
DATE=$(date +%Y%m%d_%H%M%S)

mkdir -p $BACKUP_DIR

# Backup configurations
tar -czf $BACKUP_DIR/config_$DATE.tar.gz \
    /etc/shuttle-service/ \
    /etc/local-relay/ \
    /etc/nginx/sites-available/ \
    /etc/ssl/

# Encrypt backup
gpg --symmetric --cipher-algo AES256 $BACKUP_DIR/config_$DATE.tar.gz
rm $BACKUP_DIR/config_$DATE.tar.gz
```

### Disaster Recovery

```bash
# Service restoration procedure
sudo systemctl stop shuttle-service local-relay redis

# Restore Redis data
sudo cp /opt/backups/redis/dump_latest.rdb /var/lib/redis/dump.rdb
sudo chown redis:redis /var/lib/redis/dump.rdb

# Restore configurations
sudo tar -xzf /opt/backups/config/config_latest.tar.gz -C /

# Start services
sudo systemctl start redis shuttle-service local-relay
```

## Performance Tuning

### Redis Optimization

```conf
# /etc/redis/redis.conf

# Memory optimization
maxmemory-policy allkeys-lru
hash-max-ziplist-entries 512
hash-max-ziplist-value 64

# Network optimization
tcp-keepalive 300
tcp-backlog 511

# Persistence optimization
save 900 1
save 300 10
save 60 10000
stop-writes-on-bgsave-error no
```

### Go Service Optimization

```bash
# Environment variables
export GOGC=100
export GOMEMLIMIT=2GiB
export GOMAXPROCS=4
```

### System Optimization

```bash
# Network optimization
echo 'net.core.rmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.core.wmem_max = 16777216' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_rmem = 4096 4096 16777216' >> /etc/sysctl.conf
echo 'net.ipv4.tcp_wmem = 4096 4096 16777216' >> /etc/sysctl.conf

# File descriptor limits
echo 'shuttle soft nofile 65536' >> /etc/security/limits.conf
echo 'shuttle hard nofile 65536' >> /etc/security/limits.conf

sysctl -p
```

## Troubleshooting

### Common Issues

#### Service Won't Start

```bash
# Check service status
sudo systemctl status shuttle-service

# Check logs
journalctl -u shuttle-service -f

# Check configuration
sudo -u shuttle /opt/shuttle-service/shuttle-service -config /etc/shuttle-service/config.json
```

#### Connection Issues

```bash
# Test Redis connectivity
redis-cli ping

# Test HTTP endpoints
curl -v https://shuttle.yourdomain.com/api/v1/health

# Test WebSocket connectivity
wscat -c wss://relay.yourdomain.com/
```

#### Performance Issues

```bash
# Monitor resource usage
htop
iotop
nethogs

# Check Redis performance
redis-cli info stats

# Profile Go services
curl http://localhost:6060/debug/pprof/goroutine?debug=1
```

### Log Analysis

```bash
# Parse error patterns
grep -E "(ERROR|FATAL)" /var/log/shuttle-service/shuttle.log | tail -100

# Connection tracking
grep "connection" /var/log/shuttle-service/shuttle.log | awk '{print $1, $2, $5}' | sort | uniq -c

# Performance metrics
grep "duration" /var/log/shuttle-service/shuttle.log | awk '{print $NF}' | sort -n
```

## Scaling

### Horizontal Scaling

```yaml
# docker-compose.scale.yml
version: '3.8'

services:
  shuttle-service:
    image: your-registry/shuttle-service:latest
    deploy:
      replicas: 3
    ports:
      - "8081-8083:8081"

  nginx:
    image: nginx:alpine
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf
    ports:
      - "443:443"
    depends_on:
      - shuttle-service
```

### Load Balancer Configuration

```nginx
upstream shuttle_backend {
    server 127.0.0.1:8081;
    server 127.0.0.1:8082;
    server 127.0.0.1:8083;
}

server {
    listen 443 ssl http2;

    location /api/v1/ {
        proxy_pass http://shuttle_backend;
    }
}
```

This completes the comprehensive deployment guide for the triple-encryption onion transport system.
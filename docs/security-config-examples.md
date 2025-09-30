# Security Configuration Examples

This document provides comprehensive examples of security configurations for the enhanced triple-encryption onion transport system.

## Overview

The enhanced security features include:
- **Certificate Pinning**: Prevents MITM attacks through certificate validation
- **Request Signing**: HMAC-SHA256 and Ed25519 digital signatures for API authentication
- **Mutual TLS (mTLS)**: Client certificate authentication
- **Intrusion Detection**: Real-time monitoring and threat detection
- **Security Monitoring**: Comprehensive client-side security monitoring

## 1. Certificate Pinning Configuration

### Client-Side Configuration (Rust/Tauri)

```json
{
  "certificate_pinning": {
    "mode": "enforce",
    "pins": {
      "shuttle.yourdomain.com": [
        {
          "spki_sha256": "YLh1dHA7nLIe6dYoOOwNO1j7fAY3HZayA1dT8RTUdI8=",
          "description": "Primary Let's Encrypt certificate",
          "expires_at": 1735689600,
          "is_backup": false
        },
        {
          "spki_sha256": "C5+lpZ7tcVwmwQIMcRtPbsQtWLABXhQzejna0wHFr8M=",
          "description": "Backup certificate",
          "expires_at": 1735689600,
          "is_backup": true
        }
      ],
      "relay.yourdomain.com": [
        {
          "spki_sha256": "FBOFKGjZJSZowYOdGjT4cg1t5z6n5u3kP4xRj2r8zTg=",
          "description": "Relay service certificate",
          "expires_at": 1735689600,
          "is_backup": false
        }
      ]
    },
    "backup_pins": {
      "shuttle.yourdomain.com": [
        {
          "spki_sha256": "sRHdihwgkaIb1P1gxX8HFszlD+7/gTfNvuAybgLPNis=",
          "description": "Emergency backup certificate",
          "expires_at": 1767225600,
          "is_backup": true
        }
      ]
    },
    "update_url": "https://security.yourdomain.com/api/v1/certificate-pins"
  }
}
```

### Generating Certificate Pins

```bash
# Extract SPKI hash from a certificate
openssl x509 -in certificate.pem -pubkey -noout | \
openssl pkey -pubin -outform der | \
openssl dgst -sha256 -binary | \
base64

# Alternative using curl and openssl
echo | openssl s_client -connect shuttle.yourdomain.com:443 2>/dev/null | \
openssl x509 -pubkey -noout | \
openssl pkey -pubin -outform der | \
openssl dgst -sha256 -binary | \
base64
```

## 2. Request Signing Configuration

### HMAC-SHA256 Signing

```json
{
  "request_signing": {
    "enabled": true,
    "method": "HmacSha256",
    "key_id": "relay-service-key-001",
    "secret": "your-base64-encoded-secret-key-here",
    "include_headers": ["content-type", "user-agent"],
    "max_timestamp_skew": 300
  }
}
```

### Ed25519 Digital Signatures

```json
{
  "request_signing": {
    "enabled": true,
    "method": "Ed25519",
    "key_id": "client-ed25519-001",
    "private_key_path": "/secure/keys/client-ed25519.pem",
    "include_headers": ["content-type", "authorization"],
    "max_timestamp_skew": 300
  }
}
```

### Server-Side Verification Configuration

```json
{
  "signature_verification": {
    "enabled": true,
    "max_timestamp_skew": 300,
    "hmac_keys": {
      "relay-service-key-001": "your-base64-encoded-secret-key-here",
      "client-key-002": "another-secret-key-here"
    },
    "ed25519_public_keys": {
      "client-ed25519-001": "base64-encoded-public-key-here",
      "admin-ed25519-001": "another-public-key-here"
    },
    "required_headers": ["x-timestamp", "x-nonce"],
    "nonce_cache_size": 10000
  }
}
```

## 3. Mutual TLS (mTLS) Configuration

### Server Configuration

```json
{
  "mtls": {
    "enabled": true,
    "require_client_cert": true,
    "trusted_cas": [
      "/etc/ssl/ca/client-ca.pem",
      "/etc/ssl/ca/backup-ca.pem"
    ],
    "allowed_client_certs": [
      "A1B2C3D4E5F6789012345678901234567890ABCDEF1234567890ABCDEF123456",
      "FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321FEDCBA0987654321"
    ],
    "crl_distribution_points": [
      "http://crl.yourdomain.com/client-ca.crl"
    ],
    "ocsp_enabled": true,
    "certificate_binding": {
      "CN=relay-client-001,O=YourOrg,C=US": {
        "client_id": "relay-001",
        "permissions": ["offer", "claim", "ack"],
        "rate_limit": 1000
      },
      "CN=admin-client,O=YourOrg,C=US": {
        "client_id": "admin-001",
        "permissions": ["admin", "stats", "health"],
        "rate_limit": 100
      }
    },
    "cache_timeout": "5m"
  }
}
```

### Client Certificate Generation

```bash
# Generate client private key
openssl genpkey -algorithm RSA -out client.key -pkcs8 -aes256

# Generate certificate signing request
openssl req -new -key client.key -out client.csr \
  -subj "/CN=relay-client-001/O=YourOrg/C=US"

# Sign with CA (assuming you have ca.key and ca.crt)
openssl x509 -req -in client.csr -CA ca.crt -CAkey ca.key \
  -out client.crt -days 365 -extensions client_cert \
  -extfile <(echo -e "client_cert\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=clientAuth")

# Convert to PKCS#12 for easy distribution
openssl pkcs12 -export -out client.p12 -inkey client.key -in client.crt -certfile ca.crt
```

## 4. Intrusion Detection System Configuration

### Shuttle Service IDS Configuration

```json
{
  "intrusion_detection": {
    "enabled": true,
    "scanning_threshold": {
      "requests_per_minute": 100,
      "unique_paths_per_hour": 50,
      "error_rate_threshold": 0.3,
      "suspicious_user_agents": [
        "sqlmap",
        "nikto",
        "nmap",
        "dirb",
        "gobuster"
      ],
      "window_size": "1h"
    },
    "brute_force_threshold": {
      "failed_attempts_threshold": 5,
      "time_window": "5m",
      "lockout_duration": "30m",
      "monitored_endpoints": ["/api/v1/auth", "/api/v1/login"]
    },
    "rate_limit_threshold": {
      "violations_threshold": 10,
      "monitoring_window": "1h",
      "escalation_ratio": 2.0
    },
    "sql_injection_patterns": [
      "(?i)(union\\s+(all\\s+)?select)",
      "(?i)(select\\s+\\*\\s+from)",
      "(?i)(insert\\s+into\\s+\\w+)",
      "(?i)(delete\\s+from\\s+\\w+)",
      "(?i)('\\s*or\\s*'\\s*=\\s*')",
      "(?i)('\\s*or\\s*1\\s*=\\s*1)"
    ],
    "xss_patterns": [
      "(?i)(<script[^>]*>.*?</script>)",
      "(?i)(javascript\\s*:)",
      "(?i)(on\\w+\\s*=)",
      "(?i)(<iframe[^>]*>)",
      "(?i)(document\\.(cookie|domain|write))"
    ],
    "payload_anomaly_threshold": {
      "max_size_bytes": 10485760,
      "compression_ratio": 0.1,
      "entropy_threshold": 7.5,
      "binary_data_ratio": 0.8
    },
    "geo_location_blocking": {
      "enabled": false,
      "blocked_countries": ["XX", "YY"],
      "allowed_countries": [],
      "database_path": "/var/lib/geoip/GeoLite2-Country.mmdb"
    },
    "alert_webhooks": [
      "https://alerts.yourdomain.com/webhook/security",
      "https://slack.com/api/webhooks/your-webhook-url"
    ],
    "log_level": "warn",
    "retention_period": "72h"
  }
}
```

### Alert Webhook Payload Example

```json
{
  "alert": {
    "id": "evt_1699123456789012345",
    "timestamp": "2024-01-15T10:30:00Z",
    "event_type": "sql_injection_attempt",
    "threat_level": "HIGH",
    "source_ip": "192.168.1.100",
    "user_agent": "Mozilla/5.0 (compatible; sqlmap/1.7.2)",
    "request_uri": "/api/v1/offer?id=1' OR '1'='1",
    "method": "POST",
    "description": "SQL injection pattern detected in parameter 'id'",
    "metadata": {
      "parameter": "id",
      "value": "1' OR '1'='1",
      "pattern_matched": "(?i)('\\s*or\\s*'\\s*=\\s*')"
    },
    "action": "blocked"
  },
  "timestamp": "2024-01-15T10:30:00Z",
  "service": "shuttle-service",
  "environment": "production",
  "severity": "HIGH",
  "summary": "sql_injection_attempt from 192.168.1.100"
}
```

## 5. Client-Side Security Monitoring

### Security Monitor Configuration

```json
{
  "security_monitoring": {
    "enabled": true,
    "connection_monitoring": {
      "max_connection_failures": 5,
      "failure_window_seconds": 300,
      "max_reconnect_attempts": 3,
      "monitor_cert_changes": true,
      "detect_mitm": true
    },
    "key_monitoring": {
      "monitor_key_rotation": true,
      "expected_rotation_interval": 86400,
      "alert_unexpected_changes": true,
      "monitor_key_entropy": true,
      "min_key_entropy": 7.0
    },
    "traffic_analysis": {
      "monitor_timing_attacks": true,
      "monitor_padding_attacks": true,
      "detect_traffic_patterns": true,
      "max_message_frequency": 10.0,
      "monitor_size_patterns": true
    },
    "alerts": {
      "enabled": true,
      "destinations": [
        {
          "alert_type": "log",
          "destination": "/var/log/security.log",
          "format": "json"
        },
        {
          "alert_type": "webhook",
          "destination": "https://monitoring.yourdomain.com/alerts",
          "format": "json"
        }
      ],
      "min_alert_level": "Medium",
      "rate_limit_seconds": 300
    },
    "logging": {
      "log_events": true,
      "log_level": "warn",
      "include_sensitive": false,
      "auto_rotate": true
    }
  }
}
```

## 6. Production Deployment Security

### Nginx Configuration with Security Headers

```nginx
server {
    listen 443 ssl http2;
    server_name shuttle.yourdomain.com;

    # SSL/TLS Configuration
    ssl_certificate /etc/ssl/certs/shuttle.crt;
    ssl_certificate_key /etc/ssl/private/shuttle.key;
    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384;
    ssl_prefer_server_ciphers off;

    # Security Headers
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains; preload" always;
    add_header X-Frame-Options DENY always;
    add_header X-Content-Type-Options nosniff always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; font-src 'self'; object-src 'none'; media-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'self';" always;

    # Rate Limiting
    limit_req_zone $binary_remote_addr zone=api:10m rate=100r/m;
    limit_req_zone $binary_remote_addr zone=auth:10m rate=5r/m;

    location /api/v1/ {
        limit_req zone=api burst=20 nodelay;

        proxy_pass http://127.0.0.1:8081;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Security
        proxy_hide_header Server;
        proxy_hide_header X-Powered-By;
    }

    location /api/v1/auth {
        limit_req zone=auth burst=5 nodelay;
        proxy_pass http://127.0.0.1:8081;
    }
}
```

### Firewall Rules (iptables)

```bash
#!/bin/bash
# Security-focused firewall rules

# Flush existing rules
iptables -F
iptables -X
iptables -t nat -F
iptables -t nat -X

# Default policies
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT

# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT

# Allow established connections
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow SSH (rate limited)
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --set --name SSH
iptables -A INPUT -p tcp --dport 22 -m state --state NEW -m recent --update --seconds 60 --hitcount 4 --name SSH -j DROP
iptables -A INPUT -p tcp --dport 22 -j ACCEPT

# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT

# Block common attack ports
iptables -A INPUT -p tcp --dport 23 -j DROP    # Telnet
iptables -A INPUT -p tcp --dport 135 -j DROP   # RPC
iptables -A INPUT -p tcp --dport 139 -j DROP   # NetBIOS
iptables -A INPUT -p tcp --dport 445 -j DROP   # SMB

# Rate limit ICMP
iptables -A INPUT -p icmp -m limit --limit 1/sec -j ACCEPT
iptables -A INPUT -p icmp -j DROP

# Log dropped packets
iptables -A INPUT -m limit --limit 5/min -j LOG --log-prefix "iptables denied: " --log-level 7

# Save rules
iptables-save > /etc/iptables/rules.v4
```

## 7. Monitoring and Alerting Setup

### Prometheus Metrics Configuration

```yaml
# prometheus.yml
global:
  scrape_interval: 15s
  evaluation_interval: 15s

rule_files:
  - "security_rules.yml"

scrape_configs:
  - job_name: 'shuttle-service'
    static_configs:
      - targets: ['localhost:8081']
    metrics_path: '/api/v1/metrics'
    scrape_interval: 30s

  - job_name: 'security-events'
    static_configs:
      - targets: ['localhost:8081']
    metrics_path: '/api/v1/security/metrics'
    scrape_interval: 60s

alerting:
  alertmanagers:
    - static_configs:
        - targets:
          - alertmanager:9093
```

### Security Alert Rules

```yaml
# security_rules.yml
groups:
  - name: security_alerts
    rules:
      - alert: HighFailureRate
        expr: rate(shuttle_requests_failed[5m]) > 0.1
        for: 2m
        labels:
          severity: warning
        annotations:
          summary: "High failure rate detected"
          description: "Request failure rate is {{ $value }} over the last 5 minutes"

      - alert: SecurityEventDetected
        expr: increase(shuttle_security_events_total[1m]) > 0
        for: 0m
        labels:
          severity: critical
        annotations:
          summary: "Security event detected"
          description: "{{ $value }} security events in the last minute"

      - alert: BruteForceAttack
        expr: increase(shuttle_blocked_ips_total[5m]) > 3
        for: 1m
        labels:
          severity: critical
        annotations:
          summary: "Possible brute force attack"
          description: "{{ $value }} IPs blocked in the last 5 minutes"
```

## 8. Key Management and Rotation

### Automated Key Rotation Script

```bash
#!/bin/bash
# Automated key rotation for security

set -euo pipefail

# Configuration
KEY_STORE="/secure/keys"
BACKUP_DIR="/secure/backups"
LOG_FILE="/var/log/key-rotation.log"

log() {
    echo "$(date '+%Y-%m-%d %H:%M:%S') $1" | tee -a "$LOG_FILE"
}

rotate_signing_keys() {
    log "Starting signing key rotation"

    # Generate new Ed25519 keypair
    openssl genpkey -algorithm Ed25519 -out "$KEY_STORE/signing-new.pem"
    openssl pkey -in "$KEY_STORE/signing-new.pem" -pubout -out "$KEY_STORE/signing-new.pub"

    # Backup old keys
    if [ -f "$KEY_STORE/signing.pem" ]; then
        cp "$KEY_STORE/signing.pem" "$BACKUP_DIR/signing-$(date +%Y%m%d-%H%M%S).pem"
    fi

    # Activate new keys
    mv "$KEY_STORE/signing-new.pem" "$KEY_STORE/signing.pem"
    mv "$KEY_STORE/signing-new.pub" "$KEY_STORE/signing.pub"

    # Update configuration
    update_signing_config

    log "Signing key rotation completed"
}

rotate_encryption_keys() {
    log "Starting encryption key rotation"

    # Generate new symmetric key
    openssl rand -hex 32 > "$KEY_STORE/encryption-new.key"

    # Backup old key
    if [ -f "$KEY_STORE/encryption.key" ]; then
        cp "$KEY_STORE/encryption.key" "$BACKUP_DIR/encryption-$(date +%Y%m%d-%H%M%S).key"
    fi

    # Activate new key
    mv "$KEY_STORE/encryption-new.key" "$KEY_STORE/encryption.key"

    log "Encryption key rotation completed"
}

update_signing_config() {
    # Update application configuration with new public key
    PUBLIC_KEY=$(base64 -w 0 "$KEY_STORE/signing.pub")

    # Update config file (customize for your setup)
    sed -i "s/\"public_key\": \".*\"/\"public_key\": \"$PUBLIC_KEY\"/" /etc/shuttle/config.json

    # Restart service
    systemctl reload shuttle-service
}

# Main execution
case "${1:-all}" in
    "signing")
        rotate_signing_keys
        ;;
    "encryption")
        rotate_encryption_keys
        ;;
    "all")
        rotate_signing_keys
        rotate_encryption_keys
        ;;
    *)
        echo "Usage: $0 [signing|encryption|all]"
        exit 1
        ;;
esac

log "Key rotation process completed successfully"
```

### Crontab for Automated Rotation

```bash
# Run key rotation weekly on Sundays at 2 AM
0 2 * * 0 /usr/local/bin/rotate-keys.sh all >> /var/log/key-rotation.log 2>&1

# Cleanup old backups monthly
0 3 1 * * find /secure/backups -name "*.pem" -mtime +30 -delete
0 3 1 * * find /secure/backups -name "*.key" -mtime +30 -delete
```

This completes the comprehensive security configuration examples for the enhanced triple-encryption onion transport system. These configurations provide multiple layers of security including certificate pinning, request signing, mutual TLS, intrusion detection, and security monitoring.
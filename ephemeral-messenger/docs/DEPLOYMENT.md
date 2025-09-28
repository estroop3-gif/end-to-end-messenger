# Ephemeral Messenger Deployment Guide

## Overview

This guide covers secure deployment of Ephemeral Messenger in various environments, with special focus on Tails OS deployment for maximum security and anonymity.

## Tails OS Deployment (Recommended for High Security)

### Prerequisites

- **Tails OS**: Version 5.0 or later
- **Hardware Requirements**:
  - 8GB+ RAM (recommended 16GB for optimal performance)
  - 64GB+ persistent storage
  - Hardware security token (YubiKey recommended)
- **Network**: Tor network access (built into Tails)

### Tails Deployment Runbook

#### Step 1: Tails Setup and Persistence

1. **Boot Tails with Persistence**
   ```bash
   # Enable persistence and set strong passphrase
   # Configure persistent folders:
   # - Personal Data
   # - Additional Software
   # - Dotfiles
   # - SSH Client
   ```

2. **Configure Additional Software**
   ```bash
   # Add to persistent APT packages
   sudo apt update
   sudo apt install -y build-essential git curl nodejs npm golang-go tor

   # Configure persistent Tor settings
   sudo mkdir -p /home/amnesia/Persistent/tor-config
   ```

3. **Set Up Persistent Directory Structure**
   ```bash
   mkdir -p /home/amnesia/Persistent/ephemeral-messenger
   mkdir -p /home/amnesia/Persistent/ephemeral-messenger/data
   mkdir -p /home/amnesia/Persistent/ephemeral-messenger/logs
   mkdir -p /home/amnesia/Persistent/ephemeral-messenger/backups
   ```

#### Step 2: Secure Installation

1. **Download and Verify Source Code**
   ```bash
   cd /home/amnesia/Persistent

   # Download source (replace with actual repository)
   git clone https://github.com/your-org/ephemeral-messenger.git
   cd ephemeral-messenger

   # Verify GPG signatures (in production)
   # git verify-commit HEAD
   ```

2. **Build Application**
   ```bash
   # Build Go server
   cd server
   go mod download
   go build -ldflags="-s -w" -o ephemeral-messenger-server .
   cd ..

   # Build Tauri client
   cd client-tauri
   npm install
   npm run build
   cd ..
   ```

3. **Set Up Tor Configuration**
   ```bash
   # Create Tor configuration for hidden service
   cat > /home/amnesia/Persistent/tor-config/torrc << 'EOF'
   # Ephemeral Messenger Tor Configuration

   # Basic Tor settings
   SocksPort 9050
   ControlPort 9051
   HashedControlPassword 16:872860B76453A77D60CA2BB8C1A7042072093276A3D701AD684053EC4C
   CookieAuthentication 1

   # Hidden service configuration
   HiddenServiceDir /home/amnesia/Persistent/tor-config/ephemeral-messenger
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
   ```

#### Step 3: Security Hardening

1. **Configure Firewall**
   ```bash
   # Create firewall rules
   sudo ufw --force reset
   sudo ufw default deny incoming
   sudo ufw default deny outgoing

   # Allow only Tor traffic
   sudo ufw allow out 9050
   sudo ufw allow out 9051
   sudo ufw allow out on lo
   sudo ufw allow in on lo

   # Allow localhost communication
   sudo ufw allow from 127.0.0.1
   sudo ufw allow to 127.0.0.1

   # Enable firewall
   sudo ufw --force enable
   ```

2. **Set Up AppArmor Profile**
   ```bash
   # Create AppArmor profile for enhanced security
   sudo cat > /etc/apparmor.d/ephemeral-messenger << 'EOF'
   #include <tunables/global>

   /home/amnesia/Persistent/ephemeral-messenger/server/ephemeral-messenger-server {
     #include <abstractions/base>
     #include <abstractions/nameservice>

     # Allow network access through Tor only
     network inet stream,
     network inet6 stream,
     network unix stream,

     # File access permissions
     /home/amnesia/Persistent/ephemeral-messenger/** rw,
     /tmp/** rw,
     /proc/sys/kernel/random/uuid r,

     # Deny direct network access
     deny network inet dgram,
     deny network inet6 dgram,
     deny network raw,

     # Deny unnecessary system access
     deny /etc/passwd r,
     deny /etc/shadow r,
     deny /home/** w,
   }
   EOF

   sudo apparmor_parser -r /etc/apparmor.d/ephemeral-messenger
   ```

3. **Configure Secure Memory Settings**
   ```bash
   # Configure memory protection
   sudo sysctl -w kernel.kptr_restrict=2
   sudo sysctl -w kernel.dmesg_restrict=1
   sudo sysctl -w net.core.bpf_jit_harden=2
   sudo sysctl -w kernel.unprivileged_bpf_disabled=1

   # Disable swap to prevent key material from being written to disk
   sudo swapoff -a
   ```

#### Step 4: Service Configuration

1. **Create Systemd Service (for persistence across reboots)**
   ```bash
   sudo cat > /etc/systemd/system/ephemeral-messenger.service << 'EOF'
   [Unit]
   Description=Ephemeral Messenger Server
   After=network.target tor.service
   Requires=tor.service

   [Service]
   Type=simple
   User=amnesia
   Group=amnesia
   WorkingDirectory=/home/amnesia/Persistent/ephemeral-messenger
   ExecStart=/home/amnesia/Persistent/ephemeral-messenger/server/ephemeral-messenger-server
   Restart=always
   RestartSec=10

   # Security settings
   NoNewPrivileges=yes
   PrivateTmp=yes
   PrivateDevices=yes
   ProtectHome=yes
   ProtectSystem=strict
   ReadWritePaths=/home/amnesia/Persistent/ephemeral-messenger

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

   sudo systemctl daemon-reload
   sudo systemctl enable ephemeral-messenger
   ```

2. **Create Startup Script**
   ```bash
   cat > /home/amnesia/Persistent/ephemeral-messenger/start-ephemeral-messenger.sh << 'EOF'
   #!/bin/bash

   # Ephemeral Messenger Startup Script for Tails
   set -e

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
   cd /home/amnesia/Persistent/ephemeral-messenger

   # Start Tor with custom configuration
   echo "Starting Tor with custom configuration..."
   tor -f /home/amnesia/Persistent/tor-config/torrc --quiet &
   TOR_PID=$!

   # Wait for Tor to bootstrap
   echo "Waiting for Tor to bootstrap..."
   timeout 60 bash -c 'until nc -z 127.0.0.1 9051; do sleep 1; done'

   if [ $? -ne 0 ]; then
       echo "Error: Tor failed to start properly"
       kill $TOR_PID 2>/dev/null || true
       exit 1
   fi

   # Start the server
   echo "Starting Ephemeral Messenger server..."
   ./server/ephemeral-messenger-server &
   SERVER_PID=$!

   # Start the client
   echo "Starting Ephemeral Messenger client..."
   cd client-tauri
   npm run tauri dev &
   CLIENT_PID=$!

   # Function to cleanup on exit
   cleanup() {
       echo "Shutting down Ephemeral Messenger..."
       kill $CLIENT_PID 2>/dev/null || true
       kill $SERVER_PID 2>/dev/null || true
       kill $TOR_PID 2>/dev/null || true

       # Secure wipe of temporary files
       find /tmp -name "*ephemeral*" -type f -exec shred -vfz -n 3 {} \; 2>/dev/null || true

       echo "Shutdown complete."
   }

   # Set up signal handlers
   trap cleanup EXIT INT TERM

   echo "Ephemeral Messenger is now running."
   echo "Access the client through the Tauri application window."
   echo "Press Ctrl+C to shutdown."

   # Wait for processes
   wait
   EOF

   chmod +x /home/amnesia/Persistent/ephemeral-messenger/start-ephemeral-messenger.sh
   ```

#### Step 5: Security Verification

1. **Run Security Checks**
   ```bash
   # Run the security test suite
   cd /home/amnesia/Persistent/ephemeral-messenger
   python3 tests/security_tests.py

   # Verify Tor configuration
   tor --verify-config -f /home/amnesia/Persistent/tor-config/torrc

   # Check for security vulnerabilities
   python3 tests/crypto_tests.py
   ```

2. **Verify Network Isolation**
   ```bash
   # Ensure all traffic goes through Tor
   sudo netstat -tlnp | grep ephemeral-messenger

   # Check for DNS leaks
   dig @8.8.8.8 check.torproject.org
   # Should fail or timeout

   # Verify onion service
   curl --socks5-hostname 127.0.0.1:9050 http://your-onion-address.onion/health
   ```

#### Step 6: Operational Procedures

1. **Daily Startup Procedure**
   ```bash
   # 1. Boot Tails with persistence
   # 2. Connect to secure network
   # 3. Run startup script
   /home/amnesia/Persistent/ephemeral-messenger/start-ephemeral-messenger.sh

   # 4. Verify security status
   python3 /home/amnesia/Persistent/ephemeral-messenger/scripts/security-check.py
   ```

2. **Daily Shutdown Procedure**
   ```bash
   # 1. Close all messaging sessions
   # 2. Secure wipe temporary data
   # 3. Shutdown application
   # 4. Shutdown Tails (automatic secure wipe)
   ```

## Alternative Deployment Options

### Docker Deployment

For less critical environments, Docker provides easier deployment:

```bash
# Build Docker image
docker build -t ephemeral-messenger .

# Run with Tor network
docker run -d \
  --name ephemeral-messenger \
  --network=bridge \
  -p 127.0.0.1:8080:8080 \
  -v tor-data:/var/lib/tor \
  ephemeral-messenger
```

### Linux Server Deployment

For server environments:

```bash
# System dependencies
sudo apt update
sudo apt install -y golang nodejs npm tor

# Configure Tor
sudo systemctl enable tor
sudo systemctl start tor

# Deploy application
make install-server
sudo systemctl enable ephemeral-messenger
sudo systemctl start ephemeral-messenger
```

### Kubernetes Deployment

For cloud environments (reduced security):

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: ephemeral-messenger
spec:
  replicas: 1
  selector:
    matchLabels:
      app: ephemeral-messenger
  template:
    metadata:
      labels:
        app: ephemeral-messenger
    spec:
      containers:
      - name: ephemeral-messenger
        image: ephemeral-messenger:latest
        ports:
        - containerPort: 8080
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
```

## Security Considerations by Environment

### Tails OS (Highest Security)
- ✅ Amnesic operating system
- ✅ Built-in Tor integration
- ✅ No persistent storage by default
- ✅ Hardware-based isolation
- ⚠️ Requires technical expertise

### Dedicated Linux Server (High Security)
- ✅ Full control over environment
- ✅ Hardware security token support
- ✅ Professional Tor configuration
- ⚠️ Requires system administration skills
- ❌ Not amnesic

### Docker Containers (Medium Security)
- ✅ Process isolation
- ✅ Easy deployment
- ⚠️ Shared kernel with host
- ❌ Not suitable for high-threat environments

### Cloud Deployment (Lower Security)
- ✅ High availability
- ✅ Easy scaling
- ❌ Third-party infrastructure
- ❌ Potential government access
- ❌ Not recommended for sensitive communications

## Monitoring and Maintenance

### Health Monitoring

```bash
# Check service status
curl http://localhost:8080/health

# Monitor Tor status
curl --socks5-hostname 127.0.0.1:9050 http://your-onion.onion/health

# Check security status
python3 scripts/security-monitor.py
```

### Log Management

```bash
# Application logs (minimal logging for security)
tail -f /var/log/ephemeral-messenger/app.log

# Tor logs
sudo tail -f /var/log/tor/tor.log

# System logs
sudo journalctl -u ephemeral-messenger -f
```

### Backup and Recovery

```bash
# Backup configuration (no message data to backup)
tar -czf ephemeral-messenger-config-$(date +%Y%m%d).tar.gz \
  /home/amnesia/Persistent/tor-config/ \
  /home/amnesia/Persistent/ephemeral-messenger/configs/

# Restore configuration
tar -xzf ephemeral-messenger-config-YYYYMMDD.tar.gz -C /
```

## Troubleshooting

### Common Issues

1. **Tor Connection Failed**
   ```bash
   # Check Tor status
   sudo systemctl status tor

   # Verify Tor configuration
   tor --verify-config -f /path/to/torrc

   # Restart Tor
   sudo systemctl restart tor
   ```

2. **Application Won't Start**
   ```bash
   # Check port conflicts
   sudo netstat -tlnp | grep 8080

   # Check permissions
   ls -la /home/amnesia/Persistent/ephemeral-messenger/

   # Check logs
   sudo journalctl -u ephemeral-messenger --no-pager
   ```

3. **Memory Issues**
   ```bash
   # Check memory usage
   free -h
   ps aux | grep ephemeral-messenger

   # Adjust memory limits
   sudo systemctl edit ephemeral-messenger
   # Add: [Service]
   #      MemoryMax=2G
   ```

### Emergency Procedures

1. **Security Compromise Suspected**
   ```bash
   # Immediate shutdown
   sudo systemctl stop ephemeral-messenger
   sudo systemctl stop tor

   # Secure wipe
   shred -vfz -n 3 /tmp/ephemeral-*

   # Reboot Tails (automatic secure wipe)
   sudo reboot
   ```

2. **Data Breach Response**
   ```bash
   # Document the incident
   # Notify affected users through secure channels
   # Regenerate all cryptographic keys
   # Review and update security procedures
   ```

## Production Deployment Checklist

### Pre-Deployment
- [ ] Security review completed
- [ ] Penetration testing passed
- [ ] Code audit completed
- [ ] Dependencies verified
- [ ] Hardware tokens configured
- [ ] Backup procedures tested

### Deployment
- [ ] Tails OS configured with persistence
- [ ] Tor hidden service configured
- [ ] Firewall rules applied
- [ ] AppArmor profiles loaded
- [ ] Services configured and enabled
- [ ] Security tests passed

### Post-Deployment
- [ ] Health checks passing
- [ ] Monitoring configured
- [ ] Incident response procedures documented
- [ ] User training completed
- [ ] Regular security audits scheduled
- [ ] Update procedures documented

## Support and Updates

### Security Updates
- Monitor security advisories
- Test updates in isolated environment
- Apply critical security patches immediately
- Document all changes

### Bug Reports
- Use secure channels for bug reports
- Include minimal reproduction information
- Exclude sensitive user data
- Follow responsible disclosure practices

Remember: The security of Ephemeral Messenger depends on proper deployment and operational security. Always prioritize security over convenience, and regularly review and update your security practices.
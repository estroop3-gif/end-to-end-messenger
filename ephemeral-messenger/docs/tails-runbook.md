# Tails Runbook - Ephemeral Messenger

This runbook provides step-by-step instructions for compiling, transferring, and running Ephemeral Messenger on TailsOS.

## ⚠️ SECURITY NOTICE ⚠️

- **Always verify binary signatures** before running on production systems
- **Exchange public keys out-of-band** using a separate secure channel
- **Validate safety numbers** before sending sensitive messages
- **Never save private keys** to persistent storage without hardware encryption

## Prerequisites

### Required Hardware
- Two Tails USB drives (minimum 8GB each)
- YubiKey or compatible hardware security token (strongly recommended)
- USB drive for file transfer (if compiling elsewhere)

### TailsOS Configuration
- Tails 5.0 or later
- Tor enabled (default)
- Optional: Persistent volume with encryption for development

## Part 1: Compilation (Development Machine)

### 1.1 Install Build Dependencies

On a secure Linux system (preferably Tails with persistence):

```bash
# Update package lists
sudo apt update

# Install Go (for server)
sudo apt install golang-go

# Install Node.js and npm (for client)
curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
sudo apt install nodejs

# Install additional dependencies
sudo apt install git build-essential python3-dev libffi-dev

# Verify installations
go version
node --version
npm --version
```

### 1.2 Clone and Build Server

```bash
# Clone repository (or transfer source code)
git clone [repository-url] ephemeral-messenger
cd ephemeral-messenger

# Build server
cd server
go mod download
go mod verify

# Build with static linking for Tails compatibility
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -ldflags='-w -s -extldflags "-static"' \
    -a -installsuffix cgo \
    -o ephemeral-messenger-server .

# Verify binary
file ephemeral-messenger-server
ldd ephemeral-messenger-server  # Should show "not a dynamic executable"
```

### 1.3 Build Client

```bash
# Build client
cd ../client
npm ci --production
npm run build:reproducible

# The built application will be in the 'out' directory
ls -la out/
```

### 1.4 Create Distribution Package

```bash
# Create distribution directory
cd ..
mkdir -p dist/{bin,docs,tools,demo}

# Copy binaries
cp server/ephemeral-messenger-server dist/bin/
cp -r client/out/* dist/bin/

# Copy essential files
cp README.md dist/
cp docs/tails-runbook.md dist/docs/
cp tools/create_ephemeral_onion.sh dist/tools/
cp demo/* dist/demo/ 2>/dev/null || true

# Create checksums
cd dist
sha256sum bin/* > checksums.txt
cd ..

# Create tarball
tar -czf ephemeral-messenger-tails.tar.gz dist/
```

### 1.5 Sign Distribution (Production)

```bash
# Sign the distribution (requires signing key)
gpg --armor --detach-sign ephemeral-messenger-tails.tar.gz

# Verify signature
gpg --verify ephemeral-messenger-tails.tar.gz.asc ephemeral-messenger-tails.tar.gz
```

## Part 2: Transfer to Tails

### 2.1 Prepare Transfer Media

On your development machine:

```bash
# Copy to USB drive (replace /dev/sdX with your USB device)
sudo mount /dev/sdX1 /mnt/usb
cp ephemeral-messenger-tails.tar.gz* /mnt/usb/
sync
sudo umount /mnt/usb
```

### 2.2 Verify on Tails

Boot Tails and insert the USB drive:

```bash
# Mount USB drive
sudo mkdir -p /mnt/transfer
sudo mount /dev/sdb1 /mnt/transfer

# Copy to Tails
cp /mnt/transfer/ephemeral-messenger-tails.tar.gz* ~/

# Verify signature (if you have the signing public key)
gpg --verify ephemeral-messenger-tails.tar.gz.asc ephemeral-messenger-tails.tar.gz

# Extract
tar -xzf ephemeral-messenger-tails.tar.gz
cd dist/

# Verify checksums
sha256sum -c checksums.txt
```

## Part 3: Setup on Tails

### 3.1 Verify System Security

```bash
# Check no swap is active
cat /proc/swaps
# Should show only header line

# Check Tor is running
systemctl status tor
curl --socks5 127.0.0.1:9050 https://check.torproject.org/

# Check available memory
free -h
```

### 3.2 Install Application

```bash
# Make binaries executable
chmod +x bin/ephemeral-messenger-server
chmod +x tools/create_ephemeral_onion.sh

# Test server
./bin/ephemeral-messenger-server -version
```

### 3.3 Configure Tor (if needed)

```bash
# Check Tor control port configuration
sudo grep -E "ControlPort|HashedControlPassword" /etc/tor/torrc

# If ControlPort is not enabled, add it:
echo "ControlPort 9051" | sudo tee -a /etc/tor/torrc
echo "CookieAuthentication 1" | sudo tee -a /etc/tor/torrc

# Restart Tor
sudo systemctl restart tor

# Wait for Tor to start
sleep 5
```

## Part 4: Running Ephemeral Messenger

### 4.1 Setup Hardware Token (Recommended)

```bash
# Insert YubiKey and verify detection
lsusb | grep Yubico

# Check OpenPGP card status
gpg --card-status

# If first time setup needed:
gpg --card-edit
# Follow prompts to set up keys
```

### 4.2 Start Receiver

Machine A (receiver):

```bash
# Start the server
cd dist/
TOR_CONTROL_PORT=9051 ./bin/ephemeral-messenger-server &
SERVER_PID=$!

# Create ephemeral onion service
./tools/create_ephemeral_onion.sh --verbose

# Note the onion address output, e.g.:
# ONION_ADDRESS=abc123...xyz.onion
```

### 4.3 Generate and Exchange Keys

On receiver machine:

```bash
# Start the client application
./bin/ephemeral-messenger-client

# Follow UI prompts to:
# 1. Generate identity (use hardware token if available)
# 2. Export public key
# 3. Display QR code for key exchange
```

### 4.4 Start Sender

Machine B (sender):

```bash
# Start client
./bin/ephemeral-messenger-client

# In the UI:
# 1. Generate or load identity
# 2. Import recipient's public key (scan QR or paste)
# 3. Verify fingerprint with recipient via voice/video call
# 4. Enter recipient's onion address
# 5. Compose message
# 6. Run pre-send security checks
# 7. Send message
```

## Part 5: Operational Security Checklist

### 5.1 Before Every Send

**CRITICAL**: The application will automatically check these items before allowing any send:

- [ ] Tor connectivity verified
- [ ] No swap enabled
- [ ] Memory locking available
- [ ] Hardware token present (if required by policy)
- [ ] Recipient fingerprint verified within safe time window
- [ ] Binary signature valid
- [ ] Onion service created within allowed time window

### 5.2 Key Exchange Verification

**Out-of-Band Verification Process:**

1. **Generate keys** on both machines
2. **Export public keys**
3. **Exchange fingerprints** via separate secure channel:
   - Voice call with fingerprint readback
   - Video call with QR code display
   - Encrypted message via different system
   - In-person exchange
4. **Verify fingerprints match** before first message
5. **Re-verify if fingerprint changes**

### 5.3 Session Security

- **Always use fresh onion addresses** for each session
- **Verify onion address** through separate channel
- **Monitor for unusual delays** (possible MITM)
- **Keep sessions short** (< 30 minutes)
- **Wipe memory** before shutdown

## Part 6: Troubleshooting

### 6.1 Common Issues

**Tor Connection Failed:**
```bash
# Check Tor status
systemctl status tor

# Restart Tor if needed
sudo systemctl restart tor

# Test SOCKS proxy
curl --socks5 127.0.0.1:9050 https://check.torproject.org/
```

**Memory Lock Failed:**
```bash
# Check available memory
free -h

# Verify no swap
cat /proc/swaps

# Check process limits
ulimit -l
```

**Hardware Token Not Detected:**
```bash
# Check USB devices
lsusb

# Check GPG card
gpg --card-status

# Restart pcscd if needed
sudo systemctl restart pcscd
```

### 6.2 Security Warnings

**If any pre-send check fails:**
1. **DO NOT PROCEED** with sending
2. **Address the specific issue** mentioned
3. **Re-run security checks**
4. **Only send when ALL checks pass**

**If fingerprint verification fails:**
1. **STOP IMMEDIATELY**
2. **Contact recipient via separate secure channel**
3. **Re-verify identity and keys**
4. **Consider compromise scenario**

## Part 7: Clean Shutdown

### 7.1 Secure Cleanup

```bash
# Stop client application (it will auto-wipe)
# Stop server
kill $SERVER_PID

# Clean onion service
./tools/create_ephemeral_onion.sh --cleanup

# Clear shell history
history -c
history -w

# Force memory cleanup
sync
echo 3 | sudo tee /proc/sys/vm/drop_caches

# Shutdown Tails
sudo shutdown -h now
```

### 7.2 Persistent Data

**On Tails shutdown, the following is automatically wiped:**
- All temporary files
- Application memory
- Encryption keys (unless hardware stored)
- Message content
- Onion service private keys

**Only persistent data (if using persistent volume):**
- Public keys (if explicitly saved)
- Verified fingerprint database
- Application configuration

## Emergency Procedures

### Compromise Detection

If you suspect compromise:

1. **Immediately disconnect** from network
2. **Power off machines** (hard shutdown)
3. **Do not restart** the same Tails session
4. **Generate new keys** on fresh Tails boot
5. **Notify all contacts** via alternative secure channel
6. **Consider all previous communications compromised**

### Key Compromise

If private keys are compromised:

1. **Stop using compromised keys immediately**
2. **Generate new key pair**
3. **Distribute new public key** to all contacts
4. **Revoke old keys** if using formal PKI
5. **Assume all previous messages** sent with compromised keys are readable by adversaries

---

**End of Tails Runbook**

For additional security considerations, see:
- [OpSec Checklist](opsec-checklist.md)
- [Security Model](security-model.md)
- [Threat Analysis](threat-analysis.md)
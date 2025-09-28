# Operational Security (OpSec) Checklist

This checklist ensures proper operational security when using Ephemeral Messenger. **ALL items must be verified before each session.**

## ⚠️ CRITICAL SECURITY NOTICE ⚠️

**FAILURE TO FOLLOW THIS CHECKLIST MAY RESULT IN:**
- Message interception
- Identity compromise
- Location exposure
- Key material theft
- Complete operational compromise

## Pre-Session Setup

### Environment Verification
- [ ] **Using TailsOS or equivalent amnesic system**
  - Fresh boot (no persistence for sensitive operations)
  - All network traffic routes through Tor
  - No swap space enabled
  - Secure boot verified

- [ ] **Hardware Security**
  - Physical security of environment ensured
  - No cameras/microphones in sensitive areas
  - YubiKey or hardware token available and functional
  - No USB devices from untrusted sources

- [ ] **Network Security**
  - Tor daemon running and verified
  - No direct internet connection bypassing Tor
  - Public WiFi or cellular connection (avoid home/work networks)
  - VPN disabled (conflicts with Tor)

### Software Verification
- [ ] **Binary Integrity**
  - Application binaries signature verified
  - SHA256 checksums match known good values
  - Downloaded from official/verified sources only
  - No modifications to application files

- [ ] **System State**
  - No swap enabled (`cat /proc/swaps` shows header only)
  - Memory locking available and functional
  - Sufficient RAM available (minimum 4GB recommended)
  - All unnecessary services disabled

## Key Management

### Identity Generation
- [ ] **Hardware Token Setup**
  - YubiKey inserted and recognized
  - OpenPGP applet configured and functional
  - PIN/passphrase set and memorized (not written down)
  - Backup recovery method secured separately

- [ ] **Key Generation**
  - Keys generated on target hardware only
  - Private keys never transferred between devices
  - Strong entropy source verified
  - Key generation performed in secure environment

### Key Exchange
- [ ] **Out-of-Band Verification**
  - Recipient identity verified through separate secure channel
  - Voice/video call for fingerprint verification
  - QR code exchanged in person or via trusted channel
  - Safety numbers verified and documented

- [ ] **Identity Confirmation**
  - Recipient fingerprint matches expected value
  - No warnings about changed identity keys
  - Previous session keys cleared if recipient regenerated
  - Time since last verification acceptable (< 24 hours)

## Pre-Send Security Checks

### Automated Checks (Must All Pass)
- [ ] **Tor Connectivity**
  - Connection to Tor SOCKS proxy verified
  - Test .onion site reachable
  - Tor circuits building successfully
  - Control port accessible

- [ ] **System Security**
  - No swap space active
  - Memory locking functional
  - Hardware token present (if required by policy)
  - Sufficient secure memory available

- [ ] **Recipient Verification**
  - Fingerprint verified within allowed time window
  - Onion service address confirmed through secure channel
  - Onion service created within allowed time window (< 5 minutes)
  - No security warnings for recipient

- [ ] **Binary Security**
  - Application signature verified
  - No tampering detected
  - All dependencies verified
  - Runtime integrity checks passed

### Manual Verification
- [ ] **Message Review**
  - Message content reviewed for sensitive information
  - No personal identifiers or metadata included
  - Language and typing patterns considered
  - Message necessity confirmed

- [ ] **Operational Security**
  - Physical environment secure
  - No unauthorized observers
  - Sufficient time for secure transmission
  - Exit strategy planned

## During Transmission

### Monitoring
- [ ] **Connection Security**
  - Tor connection stable throughout transmission
  - No unexpected network changes
  - Transmission time reasonable (< 2 minutes for text)
  - No error messages or warnings

- [ ] **Physical Security**
  - Environment remains secure
  - No interruptions or distractions
  - Hardware token remains connected
  - No unusual system behavior

### Response Handling
- [ ] **Successful Transmission**
  - Transmission confirmed by recipient
  - No error codes returned
  - Message delivered within expected timeframe
  - Recipient confirms message integrity

- [ ] **Error Handling**
  - Any errors properly investigated
  - No retransmission without security recheck
  - Logs cleared if any errors occur
  - Alternative communication method considered

## Post-Transmission

### Immediate Cleanup
- [ ] **Memory Cleaning**
  - All message content cleared from memory
  - Encryption keys wiped
  - Temporary files removed
  - Browser/application cache cleared

- [ ] **Session Termination**
  - Onion service properly terminated
  - Tor circuits closed
  - Application properly closed with secure wipe
  - Hardware token removed

### System Cleanup
- [ ] **Log Management**
  - System logs reviewed for sensitive information
  - Application logs cleared
  - Tor logs cleared if necessary
  - Shell history cleared

- [ ] **Final Security**
  - No plaintext remnants on system
  - All temporary files removed
  - Secure memory wiped
  - System ready for shutdown

## Session End

### Secure Shutdown
- [ ] **Application Shutdown**
  - All cryptographic material wiped
  - Secure shutdown procedure completed
  - No background processes remaining
  - Hardware token removed

- [ ] **System Shutdown**
  - TailsOS shutdown properly initiated
  - Memory wiped during shutdown
  - No persistent data remains
  - Hardware powered off completely

## Emergency Procedures

### Compromise Detection
If ANY of the following occur:
- **Unexpected system behavior**
- **Network anomalies**
- **Hardware token errors**
- **Tor connection issues**
- **Recipient verification failures**

**IMMEDIATE ACTIONS:**
1. **STOP all transmission immediately**
2. **Disconnect from network**
3. **Power off system (hard shutdown)**
4. **Remove hardware token**
5. **Consider all communications compromised**
6. **Notify recipients via alternative secure channel**

### Key Compromise
If private keys are suspected compromised:
1. **Immediately cease using compromised keys**
2. **Generate new identity on clean system**
3. **Notify all contacts via out-of-band channel**
4. **Assume all previous communications readable**
5. **Revoke compromised keys if using formal PKI**

### Physical Compromise
If physical security is breached:
1. **Immediately power off system**
2. **Remove and secure hardware token**
3. **Assume complete compromise**
4. **Do not power on system again**
5. **Generate new identity on different hardware**

## Verification Log

Document verification of critical items:

```
Date: _______________
Time: _______________
Operator: ___________

Pre-Session Checks:
[ ] Environment verified
[ ] Hardware security confirmed
[ ] Network security established
[ ] Software integrity verified

Key Management:
[ ] Hardware token functional
[ ] Keys verified
[ ] Identity exchange completed
[ ] Fingerprints verified

Pre-Send Checks:
[ ] All automated checks passed
[ ] Manual verification completed
[ ] Recipient confirmed
[ ] Message reviewed

Transmission:
[ ] Connection secure throughout
[ ] No errors encountered
[ ] Recipient confirmed receipt
[ ] Cleanup completed

Notes:
_________________________________
_________________________________
_________________________________

Operator Signature: _______________
```

## Additional Security Considerations

### Time-Based Security
- **Session Duration**: Keep sessions < 30 minutes
- **Key Lifetime**: Regenerate keys every 30 days
- **Onion Lifetime**: Use fresh onions for each session
- **Verification Window**: Re-verify identities every 24 hours

### Communication Patterns
- **Frequency**: Avoid regular patterns
- **Timing**: Vary communication times
- **Volume**: Keep messages brief
- **Language**: Consider linguistic fingerprinting

### Plausible Deniability
- **Cover Stories**: Prepare explanations for legitimate use
- **Traffic Analysis**: Use dummy traffic if available
- **Timing Correlation**: Space communications irregularly
- **Behavior Patterns**: Maintain consistent operational patterns

---

**Remember: Security is only as strong as the weakest link. Every step matters.**

**When in doubt, abort the session and start fresh with full security verification.**
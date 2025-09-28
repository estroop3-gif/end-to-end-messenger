# Ephemeral Messenger User Guide

## Overview

Ephemeral Messenger is a secure, end-to-end encrypted messaging and document sharing application designed for maximum privacy and security. This guide will help you get started and use the application safely.

## Key Features

- **End-to-End Encryption**: All messages and documents are encrypted before leaving your device
- **Zero Persistence**: Messages are automatically deleted and never stored permanently
- **Tor Integration**: Anonymous communication through the Tor network
- **Hardware Token Support**: Enhanced security with YubiKey and WebAuthn devices
- **Secure Documents**: Create encrypted documents with access controls and expiration
- **Zero Knowledge**: The server cannot read your messages or documents

## Getting Started

### First Launch

1. **Generate Your Identity**
   - On first launch, you'll be prompted to create a secure identity
   - Choose a strong passphrase (at least 16 characters with mixed case, numbers, and symbols)
   - Your identity includes your public key fingerprint (this is how others identify you)
   - **Important**: Your passphrase cannot be recovered. Write it down securely.

2. **Share Your Fingerprint**
   - Your 64-character fingerprint is your public identifier
   - Share this with contacts you want to communicate with
   - Example: `a1b2c3d4e5f6789...` (truncated for display)

3. **Add Contacts**
   - Get fingerprints from your contacts through a secure channel
   - Verify fingerprints in person or through a trusted method
   - **Never trust fingerprints received through insecure channels**

### Basic Messaging

#### Sending Messages

1. Select a contact from your contact list
2. Type your message in the text area
3. Click "Send" or press Ctrl+Enter
4. Messages are automatically encrypted before transmission

#### Receiving Messages

1. Messages appear automatically when you're connected
2. You'll see delivery confirmations for messages you send
3. Messages are automatically decrypted and displayed

#### Message Security Features

- **Automatic Expiration**: Messages expire after 24 hours by default
- **No Storage**: Messages are never permanently stored
- **Forward Secrecy**: Past messages remain secure even if keys are compromised
- **Delivery Confirmation**: Know when your messages are delivered

### Secure Documents

#### Creating Documents

1. Click "New Document" in the main interface
2. Enter document title and content
3. Select recipients (contacts who can access the document)
4. Set security policies:
   - **Expiration**: How long the document remains accessible
   - **Access Control**: Who can read, edit, or share
   - **Self-Destruct**: Automatic deletion after reading

5. Choose a document passphrase (different from your identity passphrase)
6. Click "Create Document"

#### Opening Documents

1. Select a `.securedoc` file
2. Enter the document passphrase
3. The document will decrypt and open in the editor
4. Make changes as needed
5. Save to apply changes (re-encryption happens automatically)

#### Document Security

- **Multi-Layer Encryption**: Documents are encrypted with multiple keys
- **Access Policies**: Fine-grained control over who can access what
- **Audit Trail**: Track document access and modifications
- **Secure Deletion**: Documents are cryptographically wiped when deleted

### Hardware Token Integration

#### Supported Devices

- **YubiKey**: All YubiKey 5 series devices
- **WebAuthn**: Any FIDO2-compatible security key
- **FIDO U2F**: Legacy U2F devices (limited functionality)

#### Setting Up a Hardware Token

1. Insert your security key
2. Go to Settings → Security → Hardware Tokens
3. Click "Enroll New Token"
4. Follow the on-screen prompts
5. Touch your security key when prompted
6. Give your token a memorable name

#### Using Hardware Tokens

- **Message Signing**: Cryptographically sign important messages
- **Document Access**: Require token presence to access sensitive documents
- **Identity Protection**: Use token for identity operations
- **Multi-Factor Authentication**: Enhanced security for critical operations

### Network Security

#### Tor Integration

Ephemeral Messenger automatically routes traffic through Tor for maximum anonymity:

- **Hidden Services**: Connect to .onion addresses
- **Circuit Management**: Automatic circuit rotation for privacy
- **Bridge Support**: Connect through bridges in censored regions
- **Exit Node Selection**: Intelligent routing for best privacy

#### Connection Status

Monitor your security status:
- **Green**: Fully anonymous through Tor
- **Yellow**: Partial anonymity (some direct connections)
- **Red**: No anonymity (direct connections only)

Always ensure you see green status for sensitive communications.

### Privacy Best Practices

#### Operational Security

1. **Device Security**
   - Use full disk encryption
   - Keep your operating system updated
   - Use strong device passwords/PINs
   - Log out when not in use

2. **Network Security**
   - Always use Tor when possible
   - Avoid public WiFi for sensitive communications
   - Use VPN as an additional layer (VPN → Tor)
   - Verify .onion addresses carefully

3. **Communication Security**
   - Verify contact fingerprints in person
   - Use code words for identity verification
   - Be suspicious of unusual requests
   - Never share passphrases or private keys

#### Data Hygiene

1. **Regular Cleanup**
   - Clear browser cache and cookies
   - Restart the application daily
   - Use secure deletion for sensitive files
   - Clear clipboard after copying sensitive data

2. **Passphrase Management**
   - Use unique, strong passphrases
   - Never reuse passphrases
   - Consider using a password manager
   - Store backup passphrases securely offline

3. **Document Security**
   - Use short expiration times for sensitive documents
   - Limit recipient lists to necessary parties only
   - Regular security audits of document access
   - Secure deletion of local copies

### Advanced Features

#### Custom Security Policies

Create custom security policies for different types of communications:

1. **High Security Mode**
   - Hardware token required for all operations
   - Short message expiration (1 hour)
   - Frequent key rotation
   - Enhanced audit logging

2. **Standard Mode**
   - Software-only authentication
   - Standard expiration (24 hours)
   - Normal security features
   - Basic audit logging

3. **Emergency Mode**
   - Quick message sending
   - Automatic secure deletion
   - Minimal logging
   - Fast connection setup

#### Backup and Recovery

**Identity Backup**:
1. Export your identity to a secure backup
2. Store backup in multiple secure locations
3. Test recovery process regularly
4. Update backups after key changes

**Document Backup**:
1. Export important documents
2. Use secure external storage
3. Encrypt backup archives
4. Regular backup verification

### Troubleshooting

#### Connection Issues

**Cannot Connect to Tor**:
1. Check your internet connection
2. Try using Tor bridges
3. Check firewall settings
4. Contact your network administrator

**Message Delivery Failures**:
1. Verify recipient fingerprint
2. Check network connectivity
3. Ensure recipient is online
4. Try resending after a few minutes

#### Encryption Issues

**Cannot Decrypt Message**:
1. Verify sender fingerprint
2. Check if message has expired
3. Ensure correct identity is loaded
4. Check for clock synchronization issues

**Document Access Denied**:
1. Verify document passphrase
2. Check if document has expired
3. Ensure you're in the recipient list
4. Verify document integrity

#### Performance Issues

**Slow Message Delivery**:
1. Check Tor circuit status
2. Try creating new circuits
3. Verify server connectivity
4. Consider using bridges

**High Memory Usage**:
1. Restart the application
2. Clear message history
3. Close unused documents
4. Check for memory leaks

### Security Warnings

#### Red Flags

**Never** proceed if you encounter:
- Requests to disable security features
- Unusual certificate warnings
- Unexpected fingerprint changes
- Requests for passphrases or private keys
- Suspicious network activity
- Unexpected system behavior

#### Emergency Procedures

**If You Suspect Compromise**:
1. **Immediately** disconnect from the network
2. Close the application
3. Generate a new identity
4. Notify all contacts of the compromise
5. Secure wipe old identity data
6. Conduct security audit

**Device Seizure/Loss**:
1. Remotely revoke identity if possible
2. Change all related passphrases
3. Notify contacts of potential compromise
4. Generate new identity on secure device
5. Review recent communications for exposure

### Legal and Compliance

#### Jurisdiction Considerations

- Understand local laws regarding encryption
- Some countries restrict or prohibit encrypted communications
- Consider legal implications of anonymous communications
- Consult legal counsel if uncertain

#### Data Retention

- Ephemeral Messenger stores no persistent data
- Messages are automatically deleted
- No communication logs are maintained
- Server logs contain no sensitive information

### Getting Help

#### Documentation

- [API Documentation](./API.md) - For developers
- [Security Guide](./SECURITY.md) - Detailed security information
- [Developer Guide](./DEVELOPER.md) - Development and customization
- [Deployment Guide](./DEPLOYMENT.md) - Self-hosting instructions

#### Support Resources

- Review documentation thoroughly before seeking help
- Check GitHub issues for known problems
- Use secure channels for sensitive support requests
- Never share private keys or passphrases

#### Community

- Participate in security discussions
- Report bugs and vulnerabilities responsibly
- Contribute to documentation and testing
- Help other users with basic questions

Remember: Your security is only as strong as your weakest practice. Stay vigilant, keep learning, and prioritize security in all your communications.
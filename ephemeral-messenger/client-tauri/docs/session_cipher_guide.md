# Session Cipher User Guide

## Overview

The Session Cipher system adds an additional layer of encryption to your ephemeral messaging sessions. This guide explains how to use cipher codes to create secure messaging sessions with custom encryption algorithms.

## What are Session Ciphers?

Session ciphers provide an extra layer of encryption applied **before** the main Signal protocol encryption. This creates a "layered encryption" approach:

```
Your Message
    ↓ Session Cipher (Caesar/Vigenère/AEAD/OTP)
Session Encrypted
    ↓ Signal Protocol (Double Ratchet)
Final Encrypted Message
```

## Getting Started

### 1. Accessing Session Ciphers

In the Ephemeral Messenger application:

1. Navigate to the **Message Center**
2. Click on the **🔐 Cipher Sessions** tab
3. You'll see options to **Create** or **Join** a session

### 2. Creating a Cipher Session

#### Step 1: Generate a Cipher Code

1. Click **"Create Session"**
2. Fill in the session details:
   - **Label**: A descriptive name for your session
   - **Algorithm**: Choose your cipher type
   - **Duration**: How long the session should last
   - **Participants**: Who can join the session

#### Step 2: Choose Your Algorithm

**Caesar Cipher** (Educational/Demo)
- Simple letter shifting cipher
- Good for learning cryptography concepts
- **Not secure** for real communications

**Vigenère Cipher** (Educational/Demo)
- Keyword-based polyalphabetic cipher
- Historically significant but **not secure**
- Good for understanding classical cryptography

**AEAD Encryption** (Secure)
- Modern authenticated encryption
- Uses ChaCha20-Poly1305
- **Cryptographically secure**

**One-Time Pad (OTP)** (Theoretically Perfect)
- Information-theoretically secure
- Requires pre-shared random data
- **Perfect security** when used correctly

#### Step 3: Share the Cipher Code

After generating, you'll receive:
- **Base58 Code**: Text string to share with participants
- **QR Code**: Visual code for easy scanning

### 3. Joining a Cipher Session

1. Click **"Join Session"**
2. Enter the cipher code you received
3. Or scan the QR code with your device camera
4. Add your participant name
5. Click **"Join Session"**

## Using Cipher Sessions

### Sending Messages

1. Select your active cipher session
2. Type your message in the input field
3. Click **Send** or press **Enter**

Your message will be:
1. Encrypted with the session cipher
2. Then encrypted with Signal protocol
3. Transmitted securely

### Receiving Messages

Messages are automatically:
1. Decrypted from Signal protocol
2. Decrypted from session cipher
3. Displayed in plaintext

### Session Information

View session details:
- **Session ID**: Unique identifier
- **Algorithm**: Cipher type being used
- **Participants**: Who's in the session
- **Message Count**: How many messages sent
- **Time Remaining**: Until session expires

## Security Features

### Memory Protection

- **Ephemeral Keys**: Session keys stored only in secure memory
- **Automatic Cleanup**: Keys automatically destroyed when session ends
- **Zero Disk Storage**: Session plaintext never written to disk

### Perfect Forward Secrecy

- Each session uses unique ephemeral keys
- Compromising one session doesn't affect others
- Session termination destroys all secrets

### Cryptographic Integrity

- All cipher codes are cryptographically signed
- Message authenticity verified
- Tampering detection built-in

## Advanced Features

### Re-enveloping

When ending a session, you can choose to "re-envelope" messages:

- **Enabled**: Messages are re-encrypted with your long-term key
- **Disabled**: Session messages are permanently deleted

### OTP Pad Management

For One-Time Pad sessions:

- **Range Tracking**: System tracks which pad bytes are used
- **Double-spend Prevention**: Used ranges can't be reused
- **Secure Consumption**: Pad consumption logged securely

### Session Expiration

Sessions automatically expire based on:
- **Time Limit**: Maximum duration
- **Message Count**: Maximum number of messages
- **Inactivity**: Automatic cleanup after inactivity

## Command Line Interface

For advanced users, the `session_cli` tool provides command-line access:

### Generate Cipher Code
```bash
session_cli generate "My Session" caesar:13 3600 alice
```

### Start Session
```bash
session_cli start '{"version":1,...}' alice,bob 60
```

### Encrypt/Decrypt Messages
```bash
session_cli encrypt session_id "Hello, World!"
session_cli decrypt session_id "48656c6c6f..."
```

### List Active Sessions
```bash
session_cli list
```

### Run Tests
```bash
session_cli test all
```

## Best Practices

### For Security

1. **Use AEAD or OTP** for sensitive communications
2. **Keep OTP pads secret** and never reuse them
3. **Verify cipher codes** before joining sessions
4. **End sessions promptly** when done
5. **Enable re-enveloping** for important messages

### For Privacy

1. **Use descriptive labels** for easy identification
2. **Set appropriate expiration times**
3. **Limit participants** to necessary people only
4. **Monitor active sessions** regularly

### For Reliability

1. **Test your setup** with demo algorithms first
2. **Have backup communication** methods ready
3. **Document your cipher codes** securely
4. **Verify message delivery** in critical situations

## Troubleshooting

### Common Issues

**"Cipher code invalid"**
- Check the code was copied correctly
- Verify the code hasn't expired
- Ensure you have the complete code

**"Session not found"**
- Session may have expired
- Check you're using the correct session ID
- Verify you've joined the session

**"Decryption failed"**
- Session might be corrupted
- Try refreshing the application
- Contact session creator

**"OTP range conflict"**
- OTP pad bytes already used
- Use a different pad offset
- Generate new OTP pad

### Getting Help

1. Check the application logs
2. Try the `session_cli test` command
3. Verify your cipher code format
4. Contact your session administrator

## Educational Resources

### Understanding Ciphers

The application includes educational cipher algorithms:

- **Caesar Cipher**: Learn about simple substitution
- **Vigenère Cipher**: Understand polyalphabetic ciphers
- **Historical Context**: See how cryptography evolved
- **Modern Comparison**: Contrast with AEAD encryption

### Security Concepts

- **Layered Security**: Multiple encryption layers
- **Perfect Forward Secrecy**: Session isolation
- **Authenticated Encryption**: Integrity + confidentiality
- **Information Theory**: OTP perfect secrecy

## API Integration

Developers can integrate session ciphers programmatically:

### Tauri Commands

```typescript
// Generate cipher code
const cipherCode = await invoke('generate_cipher_code', {
  label: "My Session",
  algorithm: { Caesar: { shift: 3 } },
  ttlSeconds: 3600,
  producerFingerprint: "alice",
  embedSecret: false
});

// Start session
const sessionId = await invoke('start_cipher_session', {
  sessionId: null,
  cipherCode,
  participants: ["alice", "bob"],
  ttlMinutes: 60
});

// Encrypt message
const encrypted = await invoke('encrypt_session_message', {
  sessionId,
  plaintext: "Hello, World!"
});
```

### React Components

The `SessionManager` component provides a complete UI:

```tsx
<SessionManager
  onError={handleError}
  onSessionCreated={handleSessionCreated}
  onSessionJoined={handleSessionJoined}
  activeSession={activeSession}
  sessionMessages={sessionMessages}
  onSendMessage={handleSendMessage}
/>
```

## Privacy Notice

Session ciphers are designed with privacy in mind:

- **No Telemetry**: No usage data collected
- **Local Processing**: All encryption done locally
- **Ephemeral Data**: Session data automatically destroyed
- **Open Source**: Code available for audit

Remember: The security of your session depends on the algorithm chosen and proper key management. For maximum security, use AEAD or OTP algorithms with appropriate operational security practices.
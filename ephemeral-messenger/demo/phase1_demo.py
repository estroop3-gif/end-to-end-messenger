#!/usr/bin/env python3
"""
Phase 1 Demo: Core crypto and .securedoc format
Demonstrates triple encryption and secure document format using Python

This is a simplified proof-of-concept implementation showing:
1. Triple encryption (simplified versions)
2. .securedoc file format
3. Key generation and management
4. Encrypt/decrypt roundtrip testing

For production, this would be implemented in Rust with proper audited libraries.
"""

import os
import json
import base64
import tarfile
import argparse
import hashlib
import time
from typing import Dict, List, Tuple, Optional
from dataclasses import dataclass, asdict
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, x25519
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import secrets

@dataclass
class Identity:
    """User identity with signing and encryption keys"""
    public_identity: str
    fingerprint: str
    created_at: int

@dataclass
class DocumentPolicy:
    """Document access and security policy"""
    watermark_enabled: bool = False
    offline_open_allowed: bool = True
    max_open_count: Optional[int] = None
    require_hardware_token: bool = False
    auto_expire_hours: Optional[int] = None

@dataclass
class SecureDocManifest:
    """Manifest for .securedoc files"""
    version: str
    author_fingerprint: str
    recipients: List[str]
    created_at: int
    expires_at: Optional[int]
    content_hash: str
    title: str
    content_type: str
    policy: DocumentPolicy

@dataclass
class RecipientEnvelope:
    """Per-recipient encrypted keys"""
    recipient_id: str
    age_wrapped_key: str
    layer_b_key: str
    layer_a_session_key: Optional[str] = None

class CryptoManager:
    """Simplified crypto manager for demo"""

    def __init__(self):
        self.signing_key: Optional[ed25519.Ed25519PrivateKey] = None
        self.dh_key: Optional[x25519.X25519PrivateKey] = None
        self.passphrase_key: Optional[bytes] = None
        self.identity: Optional[Identity] = None

    def generate_identity(self, passphrase: str) -> Identity:
        """Generate new identity with signing and DH keys"""
        print("🔑 Generating identity...")

        # Generate Ed25519 signing key
        self.signing_key = ed25519.Ed25519PrivateKey.generate()
        sign_public = self.signing_key.public_key()

        # Generate X25519 DH key
        self.dh_key = x25519.X25519PrivateKey.generate()
        dh_public = self.dh_key.public_key()

        # Derive passphrase key
        salt = secrets.token_bytes(32)
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
        )
        self.passphrase_key = kdf.derive(passphrase.encode())

        # Create public identity
        sign_bytes = sign_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
        dh_bytes = dh_public.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )

        combined = sign_bytes + dh_bytes
        public_identity = base64.b64encode(combined).decode()

        # Generate fingerprint
        fingerprint = hashlib.sha256(combined).hexdigest()[:16].upper()

        self.identity = Identity(
            public_identity=public_identity,
            fingerprint=fingerprint,
            created_at=int(time.time())
        )

        print(f"  Identity fingerprint: {fingerprint}")
        return self.identity

    def encrypt_message(self, plaintext: str, recipient_identity: str) -> Dict:
        """Encrypt message with triple encryption (simplified)"""
        if not self.identity:
            raise ValueError("No identity generated")

        plaintext_bytes = plaintext.encode()

        # Layer A: Signal Double Ratchet (simplified - just pass through for demo)
        layer_a_data = plaintext_bytes

        # Layer B: Identity ECDH encryption
        layer_b_data = self._encrypt_layer_b(layer_a_data, recipient_identity)

        # Layer C: Passphrase encryption
        layer_c_data = self._encrypt_layer_c(layer_b_data)

        # Sign the final ciphertext
        signature = self.signing_key.sign(layer_c_data)

        return {
            "layer_a": base64.b64encode(layer_a_data).decode(),
            "layer_b": base64.b64encode(layer_b_data).decode(),
            "layer_c": base64.b64encode(layer_c_data).decode(),
            "signature": base64.b64encode(signature).decode(),
            "timestamp": int(time.time()),
            "metadata": {
                "content_type": "text/plain",
                "content_length": len(plaintext)
            }
        }

    def decrypt_message(self, encrypted_msg: Dict) -> str:
        """Decrypt message (reverse triple encryption)"""
        if not self.identity:
            raise ValueError("No identity generated")

        # Get encrypted data
        layer_c_data = base64.b64decode(encrypted_msg["layer_c"])

        # Verify signature
        signature = base64.b64decode(encrypted_msg["signature"])
        try:
            public_key = self.signing_key.public_key()
            public_key.verify(signature, layer_c_data)
            print("  ✓ Signature verified")
        except Exception as e:
            print(f"  ⚠ Signature verification failed: {e}")

        # Layer C: Passphrase decryption
        layer_b_data = self._decrypt_layer_c(layer_c_data)

        # Layer B: Identity ECDH decryption
        layer_a_data = self._decrypt_layer_b(layer_b_data)

        # Layer A: Signal Double Ratchet (simplified)
        plaintext_bytes = layer_a_data

        return plaintext_bytes.decode()

    def _encrypt_layer_b(self, data: bytes, recipient_identity: str) -> bytes:
        """Layer B: ECDH + ChaCha20Poly1305 (simplified for demo)"""
        # For demo: use our own key as recipient (self-encryption)
        shared_secret = self.dh_key.exchange(self.dh_key.public_key())

        # Derive encryption key
        derived_key = hashlib.sha256(shared_secret).digest()

        # Encrypt with ChaCha20Poly1305
        cipher = ChaCha20Poly1305(derived_key)
        nonce = secrets.token_bytes(12)
        ciphertext = cipher.encrypt(nonce, data, None)

        return nonce + ciphertext

    def _decrypt_layer_b(self, data: bytes) -> bytes:
        """Layer B decryption"""
        nonce = data[:12]
        ciphertext = data[12:]

        # Recreate shared secret
        shared_secret = self.dh_key.exchange(self.dh_key.public_key())
        derived_key = hashlib.sha256(shared_secret).digest()

        cipher = ChaCha20Poly1305(derived_key)
        return cipher.decrypt(nonce, ciphertext, None)

    def _encrypt_layer_c(self, data: bytes) -> bytes:
        """Layer C: Passphrase encryption"""
        if not self.passphrase_key:
            raise ValueError("No passphrase key")

        cipher = ChaCha20Poly1305(self.passphrase_key)
        nonce = secrets.token_bytes(12)
        ciphertext = cipher.encrypt(nonce, data, None)

        return nonce + ciphertext

    def _decrypt_layer_c(self, data: bytes) -> bytes:
        """Layer C decryption"""
        if not self.passphrase_key:
            raise ValueError("No passphrase key")

        nonce = data[:12]
        ciphertext = data[12:]

        cipher = ChaCha20Poly1305(self.passphrase_key)
        return cipher.decrypt(nonce, ciphertext, None)

class SecureDocFormat:
    """Simplified .securedoc format implementation"""

    def create_document(self, content: str, recipients: List[str], title: str,
                       author_fingerprint: str, signing_key: ed25519.Ed25519PrivateKey) -> bytes:
        """Create encrypted .securedoc file"""
        print("📄 Creating secure document...")

        # Create manifest
        content_hash = hashlib.sha256(content.encode()).hexdigest()
        manifest = SecureDocManifest(
            version="1.0",
            author_fingerprint=author_fingerprint,
            recipients=recipients,
            created_at=int(time.time()),
            expires_at=None,
            content_hash=content_hash,
            title=title,
            content_type="text/plain",
            policy=DocumentPolicy()
        )

        # Generate document encryption key
        doc_key = secrets.token_bytes(32)

        # Encrypt content
        cipher = ChaCha20Poly1305(doc_key)
        nonce = secrets.token_bytes(12)
        encrypted_content = cipher.encrypt(nonce, content.encode(), None)
        final_content = nonce + encrypted_content

        # Create recipient envelopes (simplified - same key for all)
        envelopes = {}
        for recipient_id in recipients:
            # In real implementation, would use recipient's public key
            envelope = RecipientEnvelope(
                recipient_id=recipient_id,
                age_wrapped_key=base64.b64encode(doc_key).decode(),  # Simplified
                layer_b_key=base64.b64encode(secrets.token_bytes(32)).decode()
            )
            envelopes[recipient_id] = envelope

        # Sign manifest
        manifest_json = json.dumps(asdict(manifest), sort_keys=True).encode()
        signature = signing_key.sign(manifest_json)

        # Create tar archive
        import io
        tar_buffer = io.BytesIO()

        with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
            # Add manifest
            manifest_info = tarfile.TarInfo('manifest.json')
            manifest_info.size = len(manifest_json)
            tar.addfile(manifest_info, io.BytesIO(manifest_json))

            # Add signature
            sig_info = tarfile.TarInfo('sigs/manifest.sig')
            sig_info.size = len(signature)
            tar.addfile(sig_info, io.BytesIO(signature))

            # Add encrypted content
            content_info = tarfile.TarInfo('content.enc')
            content_info.size = len(final_content)
            tar.addfile(content_info, io.BytesIO(final_content))

            # Add recipient envelopes
            for recipient_id, envelope in envelopes.items():
                envelope_json = json.dumps(asdict(envelope)).encode()
                envelope_info = tarfile.TarInfo(f'recipients/{recipient_id}.json')
                envelope_info.size = len(envelope_json)
                tar.addfile(envelope_info, io.BytesIO(envelope_json))

        return tar_buffer.getvalue()

    def open_document(self, securedoc_data: bytes, recipient_id: str) -> Tuple[str, SecureDocManifest]:
        """Open and decrypt .securedoc file"""
        print("📖 Opening secure document...")

        import io
        tar_buffer = io.BytesIO(securedoc_data)

        manifest = None
        encrypted_content = None
        envelope = None

        with tarfile.open(fileobj=tar_buffer, mode='r') as tar:
            for member in tar.getmembers():
                if member.name == 'manifest.json':
                    manifest_data = tar.extractfile(member).read()
                    manifest_dict = json.loads(manifest_data)
                    # Convert back to dataclass
                    policy_dict = manifest_dict.pop('policy')
                    manifest = SecureDocManifest(
                        policy=DocumentPolicy(**policy_dict),
                        **manifest_dict
                    )
                elif member.name == 'content.enc':
                    encrypted_content = tar.extractfile(member).read()
                elif member.name == f'recipients/{recipient_id}.json':
                    envelope_data = tar.extractfile(member).read()
                    envelope_dict = json.loads(envelope_data)
                    envelope = RecipientEnvelope(**envelope_dict)

        if not manifest or not encrypted_content or not envelope:
            raise ValueError("Invalid .securedoc file")

        # Decrypt content
        doc_key = base64.b64decode(envelope.age_wrapped_key)
        nonce = encrypted_content[:12]
        ciphertext = encrypted_content[12:]

        cipher = ChaCha20Poly1305(doc_key)
        content_bytes = cipher.decrypt(nonce, ciphertext, None)
        content = content_bytes.decode()

        # Verify content hash
        expected_hash = manifest.content_hash
        actual_hash = hashlib.sha256(content.encode()).hexdigest()
        if expected_hash != actual_hash:
            raise ValueError("Content hash verification failed")

        print(f"  ✓ Document opened: {manifest.title}")
        print(f"  ✓ Content hash verified")

        return content, manifest

def main():
    parser = argparse.ArgumentParser(description="Phase 1 Demo: Secure Messaging & Documents")
    subparsers = parser.add_subparsers(dest='command', help='Available commands')

    # Test roundtrip
    test_parser = subparsers.add_parser('test', help='Test encrypt/decrypt roundtrip')
    test_parser.add_argument('--message', default='Hello, secure world! 🔒', help='Test message')

    # Encrypt document
    encrypt_parser = subparsers.add_parser('encrypt', help='Encrypt a document')
    encrypt_parser.add_argument('-i', '--input', required=True, help='Input file')
    encrypt_parser.add_argument('-o', '--output', required=True, help='Output .securedoc file')
    encrypt_parser.add_argument('-t', '--title', default='Untitled Document', help='Document title')
    encrypt_parser.add_argument('-r', '--recipients', default='self', help='Recipients (comma-separated)')

    # Decrypt document
    decrypt_parser = subparsers.add_parser('decrypt', help='Decrypt a .securedoc file')
    decrypt_parser.add_argument('-i', '--input', required=True, help='Input .securedoc file')
    decrypt_parser.add_argument('-o', '--output', default='-', help='Output file or - for stdout')

    args = parser.parse_args()

    if args.command == 'test':
        test_roundtrip(args.message)
    elif args.command == 'encrypt':
        encrypt_document(args.input, args.output, args.title, args.recipients.split(','))
    elif args.command == 'decrypt':
        decrypt_document(args.input, args.output)
    else:
        parser.print_help()

def test_roundtrip(message: str):
    """Test complete encrypt/decrypt roundtrip"""
    print("🔄 Testing encrypt/decrypt roundtrip...")
    print(f"  Original message: \"{message}\"")

    # Initialize crypto manager
    crypto = CryptoManager()
    identity = crypto.generate_identity("demo_passphrase")

    # Test message encryption
    print("  🔒 Testing message encryption...")
    encrypted_msg = crypto.encrypt_message(message, identity.public_identity)
    print(f"    Encrypted size: {len(encrypted_msg['layer_c'])} bytes (base64)")

    # Test message decryption
    print("  🔓 Testing message decryption...")
    decrypted_msg = crypto.decrypt_message(encrypted_msg)
    print(f"    Decrypted message: \"{decrypted_msg}\"")

    # Verify message roundtrip
    if message == decrypted_msg:
        print("  ✅ Message roundtrip successful!")
    else:
        print("  ❌ Message roundtrip failed!")
        return

    # Test document encryption
    print("  📄 Testing document encryption...")
    securedoc = SecureDocFormat()
    securedoc_data = securedoc.create_document(
        message, ["self"], "Test Document", identity.fingerprint, crypto.signing_key
    )
    print(f"    Document size: {len(securedoc_data)} bytes")

    # Test document decryption
    print("  📖 Testing document decryption...")
    decrypted_content, manifest = securedoc.open_document(securedoc_data, "self")
    print(f"    Decrypted content: \"{decrypted_content}\"")
    print(f"    Document title: {manifest.title}")

    # Verify document roundtrip
    if message == decrypted_content:
        print("  ✅ Document roundtrip successful!")
    else:
        print("  ❌ Document roundtrip failed!")
        return

    print("🎉 All tests passed! Phase 1 core crypto system is working.")

def encrypt_document(input_file: str, output_file: str, title: str, recipients: List[str]):
    """Encrypt a document to .securedoc format"""
    print(f"🔒 Encrypting document: {input_file} -> {output_file}")

    # Read input
    with open(input_file, 'r') as f:
        content = f.read()

    print(f"  Content length: {len(content)} bytes")
    print(f"  Recipients: {recipients}")

    # Generate identity
    crypto = CryptoManager()
    identity = crypto.generate_identity("demo_passphrase")

    # Create encrypted document
    securedoc = SecureDocFormat()
    securedoc_data = securedoc.create_document(
        content, recipients, title, identity.fingerprint, crypto.signing_key
    )

    # Apply size padding (round up to 4KB blocks)
    padded_size = ((len(securedoc_data) + 4095) // 4096) * 4096
    padding = secrets.token_bytes(padded_size - len(securedoc_data))
    final_data = securedoc_data + padding

    # Write output
    with open(output_file, 'wb') as f:
        f.write(final_data)

    print(f"✅ Document encrypted successfully!")
    print(f"  Output: {output_file}")
    print(f"  Final size: {len(final_data)} bytes (padded)")

def decrypt_document(input_file: str, output_file: str):
    """Decrypt a .securedoc file"""
    print(f"🔓 Decrypting document: {input_file}")

    # Read encrypted file
    with open(input_file, 'rb') as f:
        securedoc_data = f.read()

    print(f"  File size: {len(securedoc_data)} bytes")

    # Remove padding (find end of tar data)
    # Simplified: just try to parse as tar and ignore trailing data
    import io
    tar_buffer = io.BytesIO(securedoc_data)

    # Find actual tar size by reading headers
    actual_size = len(securedoc_data)
    try:
        with tarfile.open(fileobj=tar_buffer, mode='r') as tar:
            # Get position after last member
            for member in tar.getmembers():
                pass
            actual_size = tar_buffer.tell()
    except:
        pass

    # Use only the actual tar data
    clean_data = securedoc_data[:actual_size]

    # Decrypt document
    securedoc = SecureDocFormat()
    content, manifest = securedoc.open_document(clean_data, "self")

    print(f"  Title: {manifest.title}")
    print(f"  Author: {manifest.author_fingerprint}")
    print(f"  Created: {time.ctime(manifest.created_at)}")
    print(f"  Content length: {len(content)} bytes")

    # Write output
    if output_file == '-':
        print("\n--- DECRYPTED CONTENT ---")
        print(content)
        print("--- END CONTENT ---")
    else:
        with open(output_file, 'w') as f:
            f.write(content)
        print(f"✅ Document decrypted successfully!")
        print(f"  Output: {output_file}")

if __name__ == "__main__":
    main()
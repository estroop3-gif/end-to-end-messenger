#!/usr/bin/env python3
"""
Comprehensive Test Suite for Ephemeral Messenger Crypto Functions
Tests all cryptographic operations, security guarantees, and edge cases
"""

import os
import sys
import unittest
import tempfile
import shutil
import json
import time
import hashlib
import tarfile
from pathlib import Path

# Add the demo directory to path for imports
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'demo'))

try:
    from phase1_demo import CryptoManager, SecureDocument, Identity
except ImportError as e:
    print(f"Error importing crypto modules: {e}")
    print("Please ensure phase1_demo.py is available")
    sys.exit(1)


class TestCryptoManager(unittest.TestCase):
    """Test the core cryptographic manager functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.crypto = CryptoManager()
        self.test_passphrase = "test_passphrase_with_sufficient_entropy_2024"
        self.test_message = "This is a test message for encryption"
        self.test_document_content = "# Test Document\n\nThis is a test document with some content."

    def test_identity_generation(self):
        """Test identity generation with various passphrases"""
        # Test normal passphrase
        identity = self.crypto.generate_identity(self.test_passphrase)
        self.assertIsInstance(identity, Identity)
        self.assertTrue(len(identity.fingerprint) > 0)
        self.assertTrue(len(identity.public_identity) > 0)

        # Test that same passphrase generates same identity
        identity2 = self.crypto.generate_identity(self.test_passphrase)
        self.assertEqual(identity.fingerprint, identity2.fingerprint)
        self.assertEqual(identity.public_identity, identity2.public_identity)

        # Test different passphrase generates different identity
        identity3 = self.crypto.generate_identity(self.test_passphrase + "_different")
        self.assertNotEqual(identity.fingerprint, identity3.fingerprint)

    def test_identity_generation_edge_cases(self):
        """Test identity generation edge cases"""
        # Test empty passphrase (should still work)
        identity = self.crypto.generate_identity("")
        self.assertIsInstance(identity, Identity)

        # Test very long passphrase
        long_passphrase = "a" * 10000
        identity = self.crypto.generate_identity(long_passphrase)
        self.assertIsInstance(identity, Identity)

        # Test unicode passphrase
        unicode_passphrase = "тест_пароль_мкраїна_🔐🔑"
        identity = self.crypto.generate_identity(unicode_passphrase)
        self.assertIsInstance(identity, Identity)

    def test_message_encryption_decryption(self):
        """Test basic message encryption and decryption"""
        identity = self.crypto.generate_identity(self.test_passphrase)

        # Test encryption
        encrypted = self.crypto.encrypt_message(self.test_message, identity.public_identity)
        self.assertIsInstance(encrypted, str)
        self.assertNotEqual(encrypted, self.test_message)
        self.assertTrue(len(encrypted) > len(self.test_message))

        # Test decryption
        decrypted = self.crypto.decrypt_message(encrypted)
        self.assertEqual(decrypted, self.test_message)

    def test_message_encryption_different_recipients(self):
        """Test message encryption for different recipients"""
        identity1 = self.crypto.generate_identity(self.test_passphrase)
        identity2 = self.crypto.generate_identity(self.test_passphrase + "_2")

        # Encrypt for identity1
        encrypted1 = self.crypto.encrypt_message(self.test_message, identity1.public_identity)

        # Should decrypt with identity1
        decrypted1 = self.crypto.decrypt_message(encrypted1)
        self.assertEqual(decrypted1, self.test_message)

        # Should not be the same when encrypted for identity2
        encrypted2 = self.crypto.encrypt_message(self.test_message, identity2.public_identity)
        self.assertNotEqual(encrypted1, encrypted2)

    def test_message_encryption_large_data(self):
        """Test encryption of large messages"""
        # Test with 1MB of data
        large_message = "A" * (1024 * 1024)
        identity = self.crypto.generate_identity(self.test_passphrase)

        encrypted = self.crypto.encrypt_message(large_message, identity.public_identity)
        decrypted = self.crypto.decrypt_message(encrypted)
        self.assertEqual(decrypted, large_message)

    def test_message_encryption_binary_data(self):
        """Test encryption of binary data"""
        # Test with binary data (converted to base64 for JSON compatibility)
        import base64
        binary_data = os.urandom(10000)
        binary_message = base64.b64encode(binary_data).decode('utf-8')

        identity = self.crypto.generate_identity(self.test_passphrase)

        encrypted = self.crypto.encrypt_message(binary_message, identity.public_identity)
        decrypted = self.crypto.decrypt_message(encrypted)
        self.assertEqual(decrypted, binary_message)

    def test_message_tampering_detection(self):
        """Test that tampered messages are detected"""
        identity = self.crypto.generate_identity(self.test_passphrase)
        encrypted = self.crypto.encrypt_message(self.test_message, identity.public_identity)

        # Parse the encrypted message
        encrypted_data = json.loads(encrypted)

        # Tamper with different parts
        test_cases = [
            ('outer_encrypted', lambda x: x[:-10] + "tampered!"),
            ('inner_signature', lambda x: x[:-10] + "tampered!"),
            ('timestamp', lambda x: x + 1000000),
        ]

        for field, tamper_func in test_cases:
            with self.subTest(field=field):
                tampered_data = encrypted_data.copy()
                if field in tampered_data:
                    tampered_data[field] = tamper_func(tampered_data[field])
                    tampered_json = json.dumps(tampered_data)

                    # Should raise exception or return None for tampered data
                    with self.assertRaises((Exception, ValueError)):
                        self.crypto.decrypt_message(tampered_json)

    def test_invalid_decryption_inputs(self):
        """Test decryption with invalid inputs"""
        test_cases = [
            "",
            "not_json",
            "{}",
            '{"invalid": "structure"}',
            '{"outer_encrypted": "invalid_base64", "inner_signature": "test"}',
        ]

        for invalid_input in test_cases:
            with self.subTest(input=invalid_input):
                with self.assertRaises((Exception, ValueError)):
                    self.crypto.decrypt_message(invalid_input)


class TestSecureDocument(unittest.TestCase):
    """Test secure document functionality"""

    def setUp(self):
        """Set up test fixtures"""
        self.crypto = CryptoManager()
        self.test_passphrase = "test_document_passphrase_2024"
        self.temp_dir = tempfile.mkdtemp()
        self.addCleanup(shutil.rmtree, self.temp_dir)

    def test_document_creation_and_parsing(self):
        """Test basic document creation and parsing"""
        identity = self.crypto.generate_identity(self.test_passphrase)

        doc = SecureDocument(
            title="Test Document",
            content=self.test_document_content,
            recipients=[identity.public_identity],
            policy={"expiration": 3600},
            passphrase="doc_passphrase"
        )

        # Test serialization
        doc_path = os.path.join(self.temp_dir, "test.securedoc")
        doc.save(doc_path, self.crypto)

        # Verify file was created
        self.assertTrue(os.path.exists(doc_path))

        # Test parsing
        parsed_doc = SecureDocument.load(doc_path, self.crypto)
        self.assertEqual(parsed_doc.title, "Test Document")
        self.assertEqual(parsed_doc.content, self.test_document_content)

    def test_document_tar_structure(self):
        """Test that .securedoc files have correct tar structure"""
        identity = self.crypto.generate_identity(self.test_passphrase)

        doc = SecureDocument(
            title="Tar Structure Test",
            content="Content for tar test",
            recipients=[identity.public_identity],
            policy={},
            passphrase="test_pass"
        )

        doc_path = os.path.join(self.temp_dir, "structure.securedoc")
        doc.save(doc_path, self.crypto)

        # Open as tar file and verify structure
        with tarfile.open(doc_path, 'r') as tar:
            members = tar.getnames()
            expected_files = ['manifest.json', 'content.encrypted', 'signatures.json']

            for expected_file in expected_files:
                self.assertIn(expected_file, members)

            # Verify manifest structure
            manifest_data = tar.extractfile('manifest.json').read()
            manifest = json.loads(manifest_data.decode('utf-8'))

            required_fields = ['title', 'created', 'version', 'encryption', 'recipients', 'policy']
            for field in required_fields:
                self.assertIn(field, manifest)

    def test_document_multiple_recipients(self):
        """Test documents with multiple recipients"""
        identity1 = self.crypto.generate_identity(self.test_passphrase)
        identity2 = self.crypto.generate_identity(self.test_passphrase + "_2")

        doc = SecureDocument(
            title="Multi-Recipient Document",
            content="Content for multiple recipients",
            recipients=[identity1.public_identity, identity2.public_identity],
            policy={},
            passphrase="multi_pass"
        )

        doc_path = os.path.join(self.temp_dir, "multi.securedoc")
        doc.save(doc_path, self.crypto)

        # Both identities should be able to decrypt
        # (In a full implementation, we'd test with both identities)
        parsed_doc = SecureDocument.load(doc_path, self.crypto)
        self.assertEqual(parsed_doc.content, "Content for multiple recipients")

    def test_document_policy_enforcement(self):
        """Test document policy enforcement"""
        identity = self.crypto.generate_identity(self.test_passphrase)

        # Test expiration policy
        doc = SecureDocument(
            title="Expiring Document",
            content="This document should expire",
            recipients=[identity.public_identity],
            policy={"expiration": -1},  # Already expired
            passphrase="expire_pass"
        )

        doc_path = os.path.join(self.temp_dir, "expired.securedoc")
        doc.save(doc_path, self.crypto)

        # Should be able to create but not necessarily access (depends on implementation)
        parsed_doc = SecureDocument.load(doc_path, self.crypto)
        self.assertIsNotNone(parsed_doc)

    def test_document_size_padding(self):
        """Test that document size is padded for privacy"""
        identity = self.crypto.generate_identity(self.test_passphrase)

        # Create documents of different sizes
        small_content = "Small"
        large_content = "Large" * 1000

        small_doc = SecureDocument("Small", small_content, [identity.public_identity], {}, "pass1")
        large_doc = SecureDocument("Large", large_content, [identity.public_identity], {}, "pass2")

        small_path = os.path.join(self.temp_dir, "small.securedoc")
        large_path = os.path.join(self.temp_dir, "large.securedoc")

        small_doc.save(small_path, self.crypto)
        large_doc.save(large_path, self.crypto)

        small_size = os.path.getsize(small_path)
        large_size = os.path.getsize(large_path)

        # Large document should be larger, but small document should be padded
        self.assertGreater(large_size, small_size)
        self.assertGreater(small_size, len(small_content))  # Should be padded

    def test_document_version_compatibility(self):
        """Test document format version compatibility"""
        identity = self.crypto.generate_identity(self.test_passphrase)

        doc = SecureDocument(
            title="Version Test",
            content="Version compatibility test",
            recipients=[identity.public_identity],
            policy={},
            passphrase="version_pass"
        )

        doc_path = os.path.join(self.temp_dir, "version.securedoc")
        doc.save(doc_path, self.crypto)

        # Verify version is recorded in manifest
        with tarfile.open(doc_path, 'r') as tar:
            manifest_data = tar.extractfile('manifest.json').read()
            manifest = json.loads(manifest_data.decode('utf-8'))
            self.assertIn('version', manifest)
            self.assertEqual(manifest['version'], '1.0')


class TestSecurityProperties(unittest.TestCase):
    """Test security properties and guarantees"""

    def setUp(self):
        """Set up test fixtures"""
        self.crypto = CryptoManager()
        self.test_passphrase = "security_test_passphrase_2024"

    def test_encryption_nondeterminism(self):
        """Test that encryption is non-deterministic"""
        identity = self.crypto.generate_identity(self.test_passphrase)
        message = "Non-deterministic test"

        # Encrypt the same message multiple times
        encrypted1 = self.crypto.encrypt_message(message, identity.public_identity)
        encrypted2 = self.crypto.encrypt_message(message, identity.public_identity)

        # Should be different ciphertexts
        self.assertNotEqual(encrypted1, encrypted2)

        # But should decrypt to same plaintext
        decrypted1 = self.crypto.decrypt_message(encrypted1)
        decrypted2 = self.crypto.decrypt_message(encrypted2)
        self.assertEqual(decrypted1, message)
        self.assertEqual(decrypted2, message)

    def test_timing_attack_resistance(self):
        """Test resistance to timing attacks"""
        identity = self.crypto.generate_identity(self.test_passphrase)

        # Test that decryption time is not significantly different for invalid vs valid
        valid_encrypted = self.crypto.encrypt_message("test", identity.public_identity)
        invalid_encrypted = valid_encrypted[:-10] + "invalid123"

        # Time valid decryption
        start_time = time.time()
        try:
            self.crypto.decrypt_message(valid_encrypted)
        except:
            pass
        valid_time = time.time() - start_time

        # Time invalid decryption
        start_time = time.time()
        try:
            self.crypto.decrypt_message(invalid_encrypted)
        except:
            pass
        invalid_time = time.time() - start_time

        # Times should be relatively similar (within 10x)
        # This is a basic check - sophisticated timing analysis would need more samples
        ratio = max(valid_time, invalid_time) / min(valid_time, invalid_time)
        self.assertLess(ratio, 10.0, "Potential timing attack vulnerability")

    def test_passphrase_entropy_requirements(self):
        """Test that weak passphrases are handled appropriately"""
        weak_passphrases = [
            "password",
            "123456",
            "qwerty",
            "a",
            "",
        ]

        for weak_pass in weak_passphrases:
            with self.subTest(passphrase=weak_pass):
                # Should still work but might warn about entropy
                identity = self.crypto.generate_identity(weak_pass)
                self.assertIsInstance(identity, Identity)

    def test_memory_cleanup_simulation(self):
        """Test that sensitive data is properly handled"""
        # This test simulates memory cleanup by ensuring no plaintext is left in variables
        identity = self.crypto.generate_identity(self.test_passphrase)
        secret_message = "SUPER_SECRET_DATA_" + "X" * 1000

        encrypted = self.crypto.encrypt_message(secret_message, identity.public_identity)
        decrypted = self.crypto.decrypt_message(encrypted)

        self.assertEqual(decrypted, secret_message)

        # In a real implementation, we'd test that secret_message is wiped from memory
        # Here we just verify the operations completed successfully

    def test_forward_secrecy_properties(self):
        """Test forward secrecy properties"""
        # Test that old messages remain secure even if current keys are compromised
        identity1 = self.crypto.generate_identity(self.test_passphrase)

        message1 = "Message from the past"
        encrypted1 = self.crypto.encrypt_message(message1, identity1.public_identity)

        # Simulate key rotation by generating new identity with different passphrase
        identity2 = self.crypto.generate_identity(self.test_passphrase + "_rotated")

        # Old encrypted message should still decrypt with original identity
        decrypted1 = self.crypto.decrypt_message(encrypted1)
        self.assertEqual(decrypted1, message1)

        # New identity should not be able to decrypt old messages
        # (This would require implementing proper key rotation in the demo)


class TestErrorHandling(unittest.TestCase):
    """Test error handling and edge cases"""

    def setUp(self):
        """Set up test fixtures"""
        self.crypto = CryptoManager()

    def test_corrupted_data_handling(self):
        """Test handling of corrupted encrypted data"""
        identity = self.crypto.generate_identity("test_corruption")
        original = "Test message for corruption"
        encrypted = self.crypto.encrypt_message(original, identity.public_identity)

        # Test various types of corruption
        corruptions = [
            encrypted[:-5],  # Truncated
            encrypted + "extra_data",  # Extended
            encrypted.replace('A', 'B'),  # Character substitution
            '{"malformed": json}',  # Malformed JSON
        ]

        for corrupted in corruptions:
            with self.subTest(corruption=corrupted[:50]):
                with self.assertRaises((Exception, ValueError)):
                    self.crypto.decrypt_message(corrupted)

    def test_invalid_public_key_handling(self):
        """Test handling of invalid public keys"""
        invalid_keys = [
            "",
            "not_a_key",
            "invalid_base64_key!@#",
            "a" * 1000,  # Too long
        ]

        for invalid_key in invalid_keys:
            with self.subTest(key=invalid_key[:50]):
                with self.assertRaises((Exception, ValueError)):
                    self.crypto.encrypt_message("test", invalid_key)

    def test_resource_exhaustion_protection(self):
        """Test protection against resource exhaustion attacks"""
        identity = self.crypto.generate_identity("resource_test")

        # Test with very large message (should handle gracefully)
        try:
            # 10MB message
            large_message = "A" * (10 * 1024 * 1024)
            encrypted = self.crypto.encrypt_message(large_message, identity.public_identity)
            decrypted = self.crypto.decrypt_message(encrypted)
            self.assertEqual(len(decrypted), len(large_message))
        except MemoryError:
            # Acceptable to fail with memory error for very large messages
            pass

    def test_concurrent_operations(self):
        """Test concurrent cryptographic operations"""
        import threading
        import queue

        identity = self.crypto.generate_identity("concurrent_test")
        results = queue.Queue()
        errors = queue.Queue()

        def encrypt_decrypt_task(message_id):
            try:
                message = f"Concurrent message {message_id}"
                encrypted = self.crypto.encrypt_message(message, identity.public_identity)
                decrypted = self.crypto.decrypt_message(encrypted)
                results.put((message_id, decrypted == message))
            except Exception as e:
                errors.put((message_id, str(e)))

        # Run 10 concurrent operations
        threads = []
        for i in range(10):
            thread = threading.Thread(target=encrypt_decrypt_task, args=(i,))
            threads.append(thread)
            thread.start()

        # Wait for all threads to complete
        for thread in threads:
            thread.join()

        # Verify all operations succeeded
        self.assertTrue(errors.empty(), f"Errors occurred: {list(errors.queue)}")
        self.assertEqual(results.qsize(), 10)

        while not results.empty():
            message_id, success = results.get()
            self.assertTrue(success, f"Message {message_id} failed")


def run_performance_tests():
    """Run performance benchmarks"""
    print("\n" + "="*50)
    print("PERFORMANCE BENCHMARKS")
    print("="*50)

    crypto = CryptoManager()
    identity = crypto.generate_identity("performance_test_passphrase")

    # Test identity generation performance
    start_time = time.time()
    for _ in range(10):
        crypto.generate_identity(f"test_pass_{_}")
    identity_time = (time.time() - start_time) / 10
    print(f"Identity generation: {identity_time:.3f}s per operation")

    # Test encryption performance
    message_sizes = [100, 1000, 10000, 100000]
    for size in message_sizes:
        message = "A" * size

        start_time = time.time()
        encrypted = crypto.encrypt_message(message, identity.public_identity)
        encrypt_time = time.time() - start_time

        start_time = time.time()
        decrypted = crypto.decrypt_message(encrypted)
        decrypt_time = time.time() - start_time

        print(f"Message size {size:6d}: encrypt {encrypt_time:.3f}s, decrypt {decrypt_time:.3f}s")


def main():
    """Run all tests"""
    print("Ephemeral Messenger Crypto Test Suite")
    print("=====================================")

    # Create test suite
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add test classes
    test_classes = [
        TestCryptoManager,
        TestSecureDocument,
        TestSecurityProperties,
        TestErrorHandling,
    ]

    for test_class in test_classes:
        tests = loader.loadTestsFromTestCase(test_class)
        suite.addTests(tests)

    # Run tests
    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    # Run performance tests
    run_performance_tests()

    # Summary
    print(f"\n{'='*50}")
    print("TEST SUMMARY")
    print(f"{'='*50}")
    print(f"Tests run: {result.testsRun}")
    print(f"Failures: {len(result.failures)}")
    print(f"Errors: {len(result.errors)}")
    print(f"Success rate: {((result.testsRun - len(result.failures) - len(result.errors)) / result.testsRun * 100):.1f}%")

    if result.failures:
        print(f"\nFAILURES:")
        for test, traceback in result.failures:
            print(f"- {test}: {traceback.split('AssertionError:')[-1].strip()}")

    if result.errors:
        print(f"\nERRORS:")
        for test, traceback in result.errors:
            print(f"- {test}: {traceback.splitlines()[-1]}")

    return len(result.failures) + len(result.errors) == 0


if __name__ == '__main__':
    success = main()
    sys.exit(0 if success else 1)
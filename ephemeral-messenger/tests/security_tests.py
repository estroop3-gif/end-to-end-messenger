#!/usr/bin/env python3
"""
Security Testing and Penetration Test Suite for Ephemeral Messenger
Tests security controls, vulnerability detection, and attack resistance
"""

import os
import sys
import time
import json
import base64
import hashlib
import requests
import websocket
import threading
import subprocess
from urllib.parse import urljoin
import ssl
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed

# Configuration
SERVER_URL = "http://localhost:8443"
WS_URL = "ws://localhost:8443/ws"
TEST_TIMEOUT = 30
MAX_THREADS = 50

class SecurityTestSuite:
    """Main security test suite class"""

    def __init__(self):
        self.server_url = SERVER_URL
        self.ws_url = WS_URL
        self.session = requests.Session()
        self.session.timeout = TEST_TIMEOUT
        self.vulnerabilities = []
        self.test_results = []

    def log_vulnerability(self, severity, category, description, evidence=None):
        """Log a discovered vulnerability"""
        vuln = {
            'severity': severity,
            'category': category,
            'description': description,
            'evidence': evidence,
            'timestamp': time.time()
        }
        self.vulnerabilities.append(vuln)
        print(f"[{severity.upper()}] {category}: {description}")

    def log_test_result(self, test_name, passed, details=None):
        """Log a test result"""
        result = {
            'test': test_name,
            'passed': passed,
            'details': details,
            'timestamp': time.time()
        }
        self.test_results.append(result)
        status = "PASS" if passed else "FAIL"
        print(f"[{status}] {test_name}")
        if details and not passed:
            print(f"    Details: {details}")

    def test_server_availability(self):
        """Test if server is available for testing"""
        try:
            response = self.session.get(f"{self.server_url}/health")
            if response.status_code == 200:
                self.log_test_result("Server Availability", True)
                return True
            else:
                self.log_test_result("Server Availability", False, f"Status: {response.status_code}")
                return False
        except Exception as e:
            self.log_test_result("Server Availability", False, str(e))
            return False

    def test_security_headers(self):
        """Test for proper security headers"""
        try:
            response = self.session.get(f"{self.server_url}/health")

            required_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection': '1',
                'Strict-Transport-Security': 'max-age',
                'Content-Security-Policy': 'default-src',
            }

            missing_headers = []
            weak_headers = []

            for header, expected in required_headers.items():
                actual = response.headers.get(header, '')

                if not actual:
                    missing_headers.append(header)
                elif isinstance(expected, list):
                    if not any(exp in actual for exp in expected):
                        weak_headers.append(f"{header}: {actual}")
                elif expected not in actual:
                    weak_headers.append(f"{header}: {actual}")

            if missing_headers:
                self.log_vulnerability(
                    'medium', 'Security Headers',
                    f"Missing security headers: {', '.join(missing_headers)}"
                )

            if weak_headers:
                self.log_vulnerability(
                    'low', 'Security Headers',
                    f"Weak security headers: {', '.join(weak_headers)}"
                )

            passed = not missing_headers and not weak_headers
            self.log_test_result("Security Headers", passed)

        except Exception as e:
            self.log_test_result("Security Headers", False, str(e))

    def test_information_disclosure(self):
        """Test for information disclosure vulnerabilities"""
        test_paths = [
            '/debug',
            '/admin',
            '/.env',
            '/config',
            '/server-status',
            '/server-info',
            '/.git/config',
            '/package.json',
            '/go.mod',
            '/Dockerfile',
        ]

        disclosed_paths = []

        for path in test_paths:
            try:
                response = self.session.get(f"{self.server_url}{path}")
                if response.status_code == 200:
                    disclosed_paths.append(path)
            except:
                pass

        if disclosed_paths:
            self.log_vulnerability(
                'medium', 'Information Disclosure',
                f"Exposed paths: {', '.join(disclosed_paths)}"
            )

        self.log_test_result("Information Disclosure", len(disclosed_paths) == 0)

    def test_http_methods(self):
        """Test for dangerous HTTP methods"""
        dangerous_methods = ['TRACE', 'DEBUG', 'PUT', 'DELETE', 'PATCH']
        allowed_methods = []

        for method in dangerous_methods:
            try:
                response = self.session.request(method, f"{self.server_url}/health")
                if response.status_code not in [405, 501]:
                    allowed_methods.append(method)
            except:
                pass

        if allowed_methods:
            self.log_vulnerability(
                'low', 'HTTP Methods',
                f"Dangerous methods allowed: {', '.join(allowed_methods)}"
            )

        self.log_test_result("HTTP Methods", len(allowed_methods) == 0)

    def test_rate_limiting(self):
        """Test rate limiting effectiveness"""
        fingerprint = "rate_limit_test_001"
        ws_url = f"{self.ws_url}?fingerprint={fingerprint}"

        try:
            # Test WebSocket rate limiting
            connections = []
            max_connections = 20

            for i in range(max_connections):
                try:
                    ws = websocket.create_connection(ws_url, timeout=5)
                    connections.append(ws)
                except Exception:
                    break

            if len(connections) >= max_connections:
                self.log_vulnerability(
                    'medium', 'Rate Limiting',
                    f"No connection rate limiting - created {len(connections)} connections"
                )

            # Clean up connections
            for ws in connections:
                try:
                    ws.close()
                except:
                    pass

            # Test HTTP rate limiting
            rapid_requests = 0
            for i in range(200):
                try:
                    response = self.session.get(f"{self.server_url}/health", timeout=1)
                    if response.status_code == 200:
                        rapid_requests += 1
                    elif response.status_code == 429:
                        break
                except:
                    break

            rate_limit_effective = rapid_requests < 150
            self.log_test_result("Rate Limiting", rate_limit_effective)

            if not rate_limit_effective:
                self.log_vulnerability(
                    'medium', 'Rate Limiting',
                    f"HTTP rate limiting ineffective - {rapid_requests} requests succeeded"
                )

        except Exception as e:
            self.log_test_result("Rate Limiting", False, str(e))

    def test_input_validation(self):
        """Test input validation and sanitization"""
        # Test WebSocket parameter injection
        malicious_fingerprints = [
            "'; DROP TABLE users; --",
            "<script>alert('xss')</script>",
            "../../../../etc/passwd",
            "A" * 10000,  # Buffer overflow attempt
            "\x00\x01\x02",  # Null bytes
            "%2e%2e%2f%2e%2e%2f",  # Directory traversal
        ]

        vulnerable_inputs = []

        for fingerprint in malicious_fingerprints:
            try:
                ws_url = f"{self.ws_url}?fingerprint={fingerprint}"
                ws = websocket.create_connection(ws_url, timeout=5)

                # Send malicious message
                malicious_message = {
                    "to": "<script>alert('xss')</script>",
                    "content": "'; DROP TABLE messages; --"
                }

                ws.send(json.dumps(malicious_message))

                # Wait for response or error
                try:
                    response = ws.recv_timeout(2)
                    # If we get a response without error, input validation might be weak
                    vulnerable_inputs.append(fingerprint[:50])
                except:
                    pass

                ws.close()

            except Exception:
                # Connection rejected - good
                pass

        if vulnerable_inputs:
            self.log_vulnerability(
                'high', 'Input Validation',
                f"Weak input validation for: {vulnerable_inputs[:3]}..."
            )

        self.log_test_result("Input Validation", len(vulnerable_inputs) == 0)

    def test_authentication_bypass(self):
        """Test for authentication bypass vulnerabilities"""
        # Test accessing endpoints without proper authentication
        protected_endpoints = [
            '/admin',
            '/config',
            '/users',
            '/keys',
        ]

        bypassed_endpoints = []

        for endpoint in protected_endpoints:
            try:
                response = self.session.get(f"{self.server_url}{endpoint}")
                if response.status_code == 200:
                    bypassed_endpoints.append(endpoint)
            except:
                pass

        # Test WebSocket without fingerprint
        try:
            ws = websocket.create_connection(self.ws_url, timeout=5)
            bypassed_endpoints.append("WebSocket without fingerprint")
            ws.close()
        except:
            pass

        if bypassed_endpoints:
            self.log_vulnerability(
                'high', 'Authentication Bypass',
                f"Unprotected endpoints: {', '.join(bypassed_endpoints)}"
            )

        self.log_test_result("Authentication Bypass", len(bypassed_endpoints) == 0)

    def test_websocket_security(self):
        """Test WebSocket specific security issues"""
        fingerprint = "ws_security_test_001"
        ws_url = f"{self.ws_url}?fingerprint={fingerprint}"

        try:
            ws = websocket.create_connection(ws_url, timeout=5)

            # Test message size limits
            large_message = {
                "to": "test_recipient",
                "content": "A" * (2 * 1024 * 1024)  # 2MB message
            }

            try:
                ws.send(json.dumps(large_message))
                response = ws.recv_timeout(5)
                self.log_vulnerability(
                    'medium', 'WebSocket Security',
                    "No message size limits enforced"
                )
            except Exception:
                # Good - large message rejected
                pass

            # Test connection flooding
            message_flood = []
            for i in range(1000):
                message_flood.append({
                    "to": "flood_recipient",
                    "content": f"Flood message {i}"
                })

            flood_sent = 0
            for msg in message_flood:
                try:
                    ws.send(json.dumps(msg))
                    flood_sent += 1
                except Exception:
                    break

            if flood_sent > 500:
                self.log_vulnerability(
                    'medium', 'WebSocket Security',
                    f"Message flooding possible - sent {flood_sent} messages"
                )

            ws.close()
            self.log_test_result("WebSocket Security", flood_sent <= 500)

        except Exception as e:
            self.log_test_result("WebSocket Security", False, str(e))

    def test_tls_configuration(self):
        """Test TLS/SSL configuration if HTTPS is enabled"""
        if not self.server_url.startswith('https'):
            self.log_test_result("TLS Configuration", True, "HTTP server - TLS not applicable")
            return

        try:
            # Extract hostname and port
            url_parts = self.server_url.replace('https://', '').split(':')
            hostname = url_parts[0]
            port = int(url_parts[1]) if len(url_parts) > 1 else 443

            # Test TLS connection
            context = ssl.create_default_context()

            with socket.create_connection((hostname, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cipher = ssock.cipher()
                    version = ssock.version()

                    # Check for weak ciphers
                    weak_ciphers = ['RC4', 'DES', 'MD5', 'SHA1']
                    if any(weak in cipher[0] for weak in weak_ciphers):
                        self.log_vulnerability(
                            'medium', 'TLS Configuration',
                            f"Weak cipher: {cipher[0]}"
                        )

                    # Check TLS version
                    if version in ['SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1']:
                        self.log_vulnerability(
                            'high', 'TLS Configuration',
                            f"Weak TLS version: {version}"
                        )

            self.log_test_result("TLS Configuration", True)

        except Exception as e:
            self.log_test_result("TLS Configuration", False, str(e))

    def test_cors_configuration(self):
        """Test CORS configuration for security issues"""
        try:
            headers = {
                'Origin': 'https://evil.com',
                'Access-Control-Request-Method': 'GET'
            }

            response = self.session.options(f"{self.server_url}/health", headers=headers)

            cors_origin = response.headers.get('Access-Control-Allow-Origin', '')

            if cors_origin == '*':
                self.log_vulnerability(
                    'medium', 'CORS Configuration',
                    "Wildcard CORS origin allows any domain"
                )

            if 'evil.com' in cors_origin:
                self.log_vulnerability(
                    'high', 'CORS Configuration',
                    "CORS allows malicious origin"
                )

            self.log_test_result("CORS Configuration", cors_origin != '*' and 'evil.com' not in cors_origin)

        except Exception as e:
            self.log_test_result("CORS Configuration", False, str(e))

    def test_denial_of_service(self):
        """Test for DoS vulnerabilities"""
        def send_request():
            try:
                response = self.session.get(f"{self.server_url}/health", timeout=5)
                return response.status_code == 200
            except:
                return False

        # Test concurrent request handling
        with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
            futures = [executor.submit(send_request) for _ in range(MAX_THREADS)]

            successful_requests = sum(1 for future in as_completed(futures, timeout=30) if future.result())

        dos_resistant = successful_requests > MAX_THREADS * 0.8
        self.log_test_result("Denial of Service Resistance", dos_resistant)

        if not dos_resistant:
            self.log_vulnerability(
                'medium', 'Denial of Service',
                f"Server degraded under load - only {successful_requests}/{MAX_THREADS} requests succeeded"
            )

    def test_error_handling(self):
        """Test error handling for information leakage"""
        # Test various error conditions
        error_tests = [
            ('/nonexistent', 404),
            ('/health', 200),  # Valid request for comparison
        ]

        information_leaked = []

        for path, expected_status in error_tests:
            try:
                response = self.session.get(f"{self.server_url}{path}")

                # Check for stack traces or sensitive information in errors
                sensitive_patterns = [
                    'stack trace',
                    'panic:',
                    'runtime error',
                    '/home/',
                    '/root/',
                    'database',
                    'password',
                    'secret',
                ]

                response_text = response.text.lower()
                for pattern in sensitive_patterns:
                    if pattern in response_text:
                        information_leaked.append(f"{path}: {pattern}")

            except Exception:
                pass

        if information_leaked:
            self.log_vulnerability(
                'medium', 'Error Handling',
                f"Information leakage in errors: {information_leaked[:3]}..."
            )

        self.log_test_result("Error Handling", len(information_leaked) == 0)

    def test_crypto_implementation(self):
        """Test cryptographic implementation security"""
        # This would require access to the crypto module
        # For now, we'll test basic crypto-related endpoints

        crypto_tests_passed = True

        # Test if server exposes crypto details
        try:
            response = self.session.get(f"{self.server_url}/crypto")
            if response.status_code == 200:
                self.log_vulnerability(
                    'medium', 'Crypto Implementation',
                    "Crypto implementation details exposed"
                )
                crypto_tests_passed = False
        except:
            pass

        # Test random number quality (basic test)
        try:
            randoms = []
            for _ in range(10):
                # This would need to be adapted to actual crypto endpoints
                response = self.session.get(f"{self.server_url}/health")
                # Extract any random-looking data from response
                if 'session' in response.headers:
                    randoms.append(response.headers['session'])

            # Check for repeated values (basic randomness test)
            if len(set(randoms)) < len(randoms):
                self.log_vulnerability(
                    'high', 'Crypto Implementation',
                    "Poor randomness detected in session IDs"
                )
                crypto_tests_passed = False

        except Exception:
            pass

        self.log_test_result("Crypto Implementation", crypto_tests_passed)

    def run_all_tests(self):
        """Run all security tests"""
        print("Starting Security Test Suite")
        print("=" * 50)

        if not self.test_server_availability():
            print("Server not available - cannot run security tests")
            return False

        # Core security tests
        self.test_security_headers()
        self.test_information_disclosure()
        self.test_http_methods()
        self.test_rate_limiting()
        self.test_input_validation()
        self.test_authentication_bypass()
        self.test_websocket_security()
        self.test_tls_configuration()
        self.test_cors_configuration()
        self.test_denial_of_service()
        self.test_error_handling()
        self.test_crypto_implementation()

        return True

    def generate_report(self):
        """Generate security test report"""
        print("\n" + "=" * 50)
        print("SECURITY TEST REPORT")
        print("=" * 50)

        # Summary
        total_tests = len(self.test_results)
        passed_tests = sum(1 for result in self.test_results if result['passed'])

        print(f"Tests Run: {total_tests}")
        print(f"Tests Passed: {passed_tests}")
        print(f"Tests Failed: {total_tests - passed_tests}")
        print(f"Success Rate: {(passed_tests / total_tests * 100):.1f}%")

        # Vulnerabilities by severity
        severity_counts = {}
        for vuln in self.vulnerabilities:
            severity = vuln['severity']
            severity_counts[severity] = severity_counts.get(severity, 0) + 1

        print(f"\nVulnerabilities Found: {len(self.vulnerabilities)}")
        for severity in ['critical', 'high', 'medium', 'low']:
            count = severity_counts.get(severity, 0)
            if count > 0:
                print(f"  {severity.capitalize()}: {count}")

        # Detailed vulnerabilities
        if self.vulnerabilities:
            print("\nDETAILED VULNERABILITIES:")
            print("-" * 30)
            for vuln in self.vulnerabilities:
                print(f"[{vuln['severity'].upper()}] {vuln['category']}")
                print(f"  {vuln['description']}")
                if vuln['evidence']:
                    print(f"  Evidence: {vuln['evidence']}")
                print()

        # Security score
        critical_weight = 10
        high_weight = 5
        medium_weight = 2
        low_weight = 1

        penalty = (severity_counts.get('critical', 0) * critical_weight +
                  severity_counts.get('high', 0) * high_weight +
                  severity_counts.get('medium', 0) * medium_weight +
                  severity_counts.get('low', 0) * low_weight)

        max_score = 100
        security_score = max(0, max_score - penalty)

        print(f"SECURITY SCORE: {security_score}/100")

        if security_score >= 90:
            print("Security Status: EXCELLENT")
        elif security_score >= 80:
            print("Security Status: GOOD")
        elif security_score >= 70:
            print("Security Status: FAIR")
        elif security_score >= 60:
            print("Security Status: POOR")
        else:
            print("Security Status: CRITICAL")

        return {
            'total_tests': total_tests,
            'passed_tests': passed_tests,
            'vulnerabilities': len(self.vulnerabilities),
            'security_score': security_score,
            'vulnerabilities_by_severity': severity_counts
        }


def main():
    """Main function to run security tests"""
    security_suite = SecurityTestSuite()

    if security_suite.run_all_tests():
        report = security_suite.generate_report()

        # Save detailed report to file
        with open('security_test_report.json', 'w') as f:
            json.dump({
                'test_results': security_suite.test_results,
                'vulnerabilities': security_suite.vulnerabilities,
                'summary': report
            }, f, indent=2, default=str)

        print(f"\nDetailed report saved to: security_test_report.json")

        # Exit code based on security score
        if report['security_score'] < 70:
            print("Security tests FAILED - score below 70")
            return 1
        else:
            print("Security tests PASSED")
            return 0
    else:
        print("Could not run security tests")
        return 1


if __name__ == '__main__':
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        print("\nSecurity tests interrupted by user")
        sys.exit(1)
    except Exception as e:
        print(f"Security tests failed with error: {e}")
        sys.exit(1)
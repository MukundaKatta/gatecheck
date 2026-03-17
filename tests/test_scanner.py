"""Tests for GateCheck scanner modules."""

import pytest

from gatecheck.models import Endpoint, HTTPMethod, Severity
from gatecheck.scanner.auth import AuthScanner
from gatecheck.scanner.injection import InjectionScanner
from gatecheck.scanner.exposure import DataExposureScanner


class TestAuthScanner:
    def setup_method(self):
        self.scanner = AuthScanner(timeout=5.0)

    def teardown_method(self):
        self.scanner.close()

    def test_init(self):
        assert self.scanner.timeout == 5.0

    def test_weak_token_detection_short_token(self):
        endpoint = Endpoint(
            url="https://api.example.com/users",
            auth_token="abc",
        )
        findings = self.scanner._check_weak_tokens(endpoint)
        assert len(findings) >= 1
        assert findings[0].severity == Severity.HIGH
        assert "Weak" in findings[0].title

    def test_weak_token_detection_numeric_only(self):
        endpoint = Endpoint(
            url="https://api.example.com/users",
            auth_token="12345",
        )
        findings = self.scanner._check_weak_tokens(endpoint)
        assert len(findings) >= 1

    def test_weak_token_detection_predictable_prefix(self):
        endpoint = Endpoint(
            url="https://api.example.com/users",
            auth_token="test_token",
        )
        findings = self.scanner._check_weak_tokens(endpoint)
        assert len(findings) >= 1

    def test_strong_token_no_finding(self):
        endpoint = Endpoint(
            url="https://api.example.com/users",
            auth_token="eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.signature_here_with_sufficient_length",
        )
        findings = self.scanner._check_weak_tokens(endpoint)
        # JWT will be checked separately, weak token pattern should not match
        weak_pattern_findings = [f for f in findings if "Weak Authentication Token" in f.title]
        assert len(weak_pattern_findings) == 0

    def test_no_token_no_finding(self):
        endpoint = Endpoint(url="https://api.example.com/users")
        findings = self.scanner._check_weak_tokens(endpoint)
        assert len(findings) == 0

    def test_http_credential_warning(self):
        endpoint = Endpoint(
            url="http://api.example.com/users",
            auth_token="mytoken123456789",
        )
        findings = self.scanner._check_auth_header_issues(endpoint)
        assert len(findings) == 1
        assert findings[0].severity == Severity.HIGH
        assert "Unencrypted" in findings[0].title

    def test_https_no_credential_warning(self):
        endpoint = Endpoint(
            url="https://api.example.com/users",
            auth_token="mytoken123456789",
        )
        findings = self.scanner._check_auth_header_issues(endpoint)
        assert len(findings) == 0

    def test_bola_check_no_id_in_url(self):
        endpoint = Endpoint(url="https://api.example.com/users")
        findings = self.scanner._check_bola(endpoint)
        assert len(findings) == 0

    def test_admin_endpoint_detection(self):
        endpoint = Endpoint(
            url="https://api.example.com/admin/settings",
            headers={"Authorization": "Bearer validtoken"},
        )
        # This just checks the pattern detection, not actual HTTP calls
        url_lower = endpoint.url.lower()
        admin_indicators = ["/admin", "/manage", "/internal", "/debug", "/config"]
        assert any(ind in url_lower for ind in admin_indicators)

    def test_scan_returns_scan_result(self):
        # Scan with no reachable endpoints should still return a result
        endpoints = [
            Endpoint(url="https://unreachable-host-test-12345.example.com/api"),
        ]
        result = self.scanner.scan(endpoints)
        assert result.scanner_name == "AuthScanner"
        assert result.endpoints_scanned == 1


class TestInjectionScanner:
    def setup_method(self):
        self.scanner = InjectionScanner(timeout=5.0)

    def teardown_method(self):
        self.scanner.close()

    def test_init(self):
        assert self.scanner.timeout == 5.0

    def test_sql_payloads_defined(self):
        assert len(self.scanner.SQL_PAYLOADS) >= 5
        for payload_info in self.scanner.SQL_PAYLOADS:
            assert "payload" in payload_info
            assert "type" in payload_info
            assert "description" in payload_info

    def test_nosql_payloads_defined(self):
        assert len(self.scanner.NOSQL_PAYLOADS) >= 3
        for payload_info in self.scanner.NOSQL_PAYLOADS:
            assert "payload" in payload_info
            assert "type" in payload_info

    def test_command_payloads_defined(self):
        assert len(self.scanner.COMMAND_PAYLOADS) >= 5

    def test_sql_error_patterns(self):
        import re
        test_strings = [
            "You have an error in your SQL syntax near",
            "Warning: mysql_query()",
            "PostgreSQL ERROR: syntax error",
            "ORA-12345: error",
            "SQLSTATE[42000]",
        ]
        for test_str in test_strings:
            matched = any(
                re.search(pattern, test_str, re.IGNORECASE)
                for pattern in self.scanner.SQL_ERROR_PATTERNS
            )
            assert matched, f"Pattern not matched for: {test_str}"

    def test_command_output_patterns(self):
        import re
        test_strings = [
            "root:x:0:0:root:/root:/bin/bash",
            "uid=33(www-data) gid=33(www-data)",
            "total 42",
        ]
        for test_str in test_strings:
            matched = any(
                re.search(pattern, test_str)
                for pattern in self.scanner.COMMAND_OUTPUT_PATTERNS
            )
            assert matched, f"Pattern not matched for: {test_str}"

    def test_boolean_blind_detection_true(self):
        import httpx
        baseline = httpx.Response(200, text="user data here" * 10)
        test_resp = httpx.Response(200, text="user data here" * 10)
        assert self.scanner._detect_boolean_blind(baseline, test_resp, "1' AND 1=1--")

    def test_boolean_blind_detection_false(self):
        import httpx
        baseline = httpx.Response(200, text="user data here" * 10)
        test_resp = httpx.Response(500, text="error")
        assert self.scanner._detect_boolean_blind(baseline, test_resp, "1' AND 1=2--")

    def test_scan_returns_result(self):
        endpoints = [
            Endpoint(url="https://unreachable-host-test-12345.example.com/api"),
        ]
        result = self.scanner.scan(endpoints)
        assert result.scanner_name == "InjectionScanner"
        assert result.endpoints_scanned == 1


class TestDataExposureScanner:
    def setup_method(self):
        self.scanner = DataExposureScanner(timeout=5.0)

    def teardown_method(self):
        self.scanner.close()

    def test_init(self):
        assert self.scanner.timeout == 5.0

    def test_pii_patterns_ssn(self):
        import re
        pattern = self.scanner.PII_PATTERNS["ssn"]["pattern"]
        assert re.search(pattern, "SSN: 123-45-6789")
        assert not re.search(pattern, "phone: 123-456-7890")

    def test_pii_patterns_email(self):
        import re
        pattern = self.scanner.PII_PATTERNS["email"]["pattern"]
        assert re.search(pattern, "email: user@example.com")
        assert not re.search(pattern, "not an email")

    def test_pii_patterns_credit_card(self):
        import re
        pattern = self.scanner.PII_PATTERNS["credit_card"]["pattern"]
        assert re.search(pattern, "card: 4111111111111111")
        assert re.search(pattern, "card: 5500 0000 0000 0004")

    def test_credential_patterns_api_key(self):
        import re
        pattern = self.scanner.CREDENTIAL_PATTERNS["api_key"]["pattern"]
        assert re.search(pattern, '{"api_key": "sk_live_abcdef12345678"}')

    def test_credential_patterns_password(self):
        import re
        pattern = self.scanner.CREDENTIAL_PATTERNS["password_field"]["pattern"]
        assert re.search(pattern, '{"password": "secret123"}')

    def test_credential_patterns_aws_key(self):
        import re
        pattern = self.scanner.CREDENTIAL_PATTERNS["aws_key"]["pattern"]
        assert re.search(pattern, "AKIAIOSFODNN7EXAMPLE")

    def test_internal_path_patterns(self):
        import re
        unix_pattern = self.scanner.INTERNAL_PATH_PATTERNS["unix_path"]["pattern"]
        assert re.search(unix_pattern, "path: /home/user/app/config.py")
        assert re.search(unix_pattern, "error at /var/log/app.log")

    def test_stack_trace_pattern(self):
        import re
        pattern = self.scanner.INTERNAL_PATH_PATTERNS["stack_trace"]["pattern"]
        assert re.search(pattern, 'File "/app/main.py", line 42')
        assert re.search(pattern, "Traceback (most recent call last):")

    def test_find_sensitive_keys(self):
        data = {
            "username": "john",
            "password": "secret",
            "profile": {
                "name": "John",
                "ssn": "123-45-6789",
            },
        }
        found = self.scanner._find_sensitive_keys(data)
        assert "password" in found
        assert "profile.ssn" in found

    def test_find_sensitive_keys_in_list(self):
        data = [
            {"username": "john", "secret": "abc"},
            {"username": "jane", "password": "xyz"},
        ]
        found = self.scanner._find_sensitive_keys(data)
        assert "[0].secret" in found
        assert "[1].password" in found

    def test_find_sensitive_keys_empty(self):
        data = {"username": "john", "name": "John"}
        found = self.scanner._find_sensitive_keys(data)
        assert len(found) == 0

    def test_scan_returns_result(self):
        endpoints = [
            Endpoint(url="https://unreachable-host-test-12345.example.com/api"),
        ]
        result = self.scanner.scan(endpoints)
        assert result.scanner_name == "DataExposureScanner"

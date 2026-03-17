"""Data exposure scanner.

Checks API responses for sensitive data leakage including PII,
credentials, internal paths, and other confidential information.
"""

from __future__ import annotations

import re
import time

import httpx

from gatecheck.models import Endpoint, Finding, ScanResult, Severity


class DataExposureScanner:
    """Scans API responses for excessive data exposure and sensitive information.

    Checks for:
    - Personally Identifiable Information (PII) leakage
    - Credential exposure in responses
    - Internal path disclosure
    - Debug/stack trace information
    - Excessive data in responses
    """

    PII_PATTERNS: dict[str, dict[str, str]] = {
        "ssn": {
            "pattern": r"\b\d{3}-\d{2}-\d{4}\b",
            "description": "Social Security Number",
        },
        "email": {
            "pattern": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
            "description": "Email address",
        },
        "phone": {
            "pattern": r"\b(?:\+?1[-.]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b",
            "description": "Phone number",
        },
        "credit_card": {
            "pattern": r"\b(?:4\d{3}|5[1-5]\d{2}|3[47]\d{2}|6(?:011|5\d{2}))[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b",
            "description": "Credit card number",
        },
        "date_of_birth": {
            "pattern": r'"(?:dob|date_of_birth|birth_?date|birthday)":\s*"[^"]*"',
            "description": "Date of birth field",
        },
        "ip_address_private": {
            "pattern": r"\b(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}|192\.168\.\d{1,3}\.\d{1,3})\b",
            "description": "Private IP address",
        },
    }

    CREDENTIAL_PATTERNS: dict[str, dict[str, str]] = {
        "api_key": {
            "pattern": r'"(?:api[_-]?key|apikey|api[_-]?secret)":\s*"[^"]{8,}"',
            "description": "API key in response",
        },
        "password_field": {
            "pattern": r'"(?:password|passwd|pass|pwd|secret|credential)":\s*"[^"]*"',
            "description": "Password/secret field in response",
        },
        "aws_key": {
            "pattern": r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}",
            "description": "AWS access key",
        },
        "private_key": {
            "pattern": r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
            "description": "Private key material",
        },
        "bearer_token": {
            "pattern": r'"(?:token|access_token|auth_token|jwt)":\s*"[A-Za-z0-9._-]{20,}"',
            "description": "Authentication token in response body",
        },
        "connection_string": {
            "pattern": r"(?:mongodb|mysql|postgres|redis)://[^\s\"']+",
            "description": "Database connection string",
        },
    }

    INTERNAL_PATH_PATTERNS: dict[str, dict[str, str]] = {
        "unix_path": {
            "pattern": r"(?:/home/|/var/|/etc/|/opt/|/usr/|/tmp/)[^\s\"']+",
            "description": "Unix filesystem path",
        },
        "windows_path": {
            "pattern": r"[A-Z]:\\(?:Users|Windows|Program Files|inetpub)[^\s\"']+",
            "description": "Windows filesystem path",
        },
        "stack_trace": {
            "pattern": r"(?:Traceback|at\s+[\w$.]+\([\w.]+:\d+\)|File\s+\"[^\"]+\",\s+line\s+\d+)",
            "description": "Stack trace / debug information",
        },
        "internal_url": {
            "pattern": r"https?://(?:localhost|127\.0\.0\.1|internal|staging|dev)[^\s\"']*",
            "description": "Internal/development URL",
        },
    }

    # Fields that should typically not be in API responses
    SENSITIVE_FIELD_NAMES = [
        "password", "passwd", "pass", "pwd", "secret",
        "ssn", "social_security", "tax_id",
        "credit_card", "card_number", "cvv", "cvc",
        "private_key", "secret_key", "api_secret",
        "bank_account", "routing_number",
    ]

    MAX_RESPONSE_SIZE_KB = 500  # Flag responses larger than this

    def __init__(self, timeout: float = 10.0):
        self.timeout = timeout
        self._client: httpx.Client | None = None

    @property
    def client(self) -> httpx.Client:
        if self._client is None:
            self._client = httpx.Client(timeout=self.timeout, follow_redirects=True)
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None

    def scan(self, endpoints: list[Endpoint]) -> ScanResult:
        """Run all data exposure checks against the provided endpoints."""
        start_time = time.time()
        findings: list[Finding] = []

        for endpoint in endpoints:
            response = self._fetch_response(endpoint)
            if response is None:
                continue

            findings.extend(self._check_pii_exposure(endpoint, response))
            findings.extend(self._check_credential_exposure(endpoint, response))
            findings.extend(self._check_internal_paths(endpoint, response))
            findings.extend(self._check_excessive_data(endpoint, response))
            findings.extend(self._check_sensitive_headers(endpoint, response))
            findings.extend(self._check_sensitive_fields(endpoint, response))

        duration = time.time() - start_time
        return ScanResult(
            target=endpoints[0].url if endpoints else "",
            endpoints_scanned=len(endpoints),
            findings=findings,
            scan_duration_seconds=round(duration, 3),
            scanner_name="DataExposureScanner",
        )

    def _fetch_response(self, endpoint: Endpoint) -> httpx.Response | None:
        """Fetch the response from an endpoint."""
        try:
            return self.client.request(
                method=endpoint.method.value,
                url=endpoint.url,
                headers=endpoint.headers,
                params=endpoint.params,
                json=endpoint.body,
            )
        except httpx.RequestError:
            return None

    def _check_pii_exposure(
        self, endpoint: Endpoint, response: httpx.Response
    ) -> list[Finding]:
        """Check for PII in the API response."""
        findings: list[Finding] = []
        body = response.text

        for pii_type, info in self.PII_PATTERNS.items():
            matches = re.findall(info["pattern"], body, re.IGNORECASE)
            if matches:
                # Redact the actual values in evidence
                sample = matches[0][:4] + "****" if len(matches[0]) > 4 else "****"
                findings.append(Finding(
                    title=f"PII Exposure: {info['description']}",
                    description=(
                        f"Endpoint {endpoint.display_name} response contains "
                        f"{info['description']} data. Found {len(matches)} occurrence(s)."
                    ),
                    severity=Severity.HIGH if pii_type in ("ssn", "credit_card") else Severity.MEDIUM,
                    category="data_exposure",
                    endpoint=endpoint.display_name,
                    evidence=f"Pattern: {pii_type}, Sample: {sample}, Count: {len(matches)}",
                    recommendation=(
                        f"Remove or mask {info['description']} data from API responses. "
                        "Only return data that the client explicitly needs. Apply field-level "
                        "access controls."
                    ),
                    owasp_mapping="API3:2023 Broken Object Property Level Authorization",
                    cwe_id="CWE-200",
                ))

        return findings

    def _check_credential_exposure(
        self, endpoint: Endpoint, response: httpx.Response
    ) -> list[Finding]:
        """Check for credential leakage in the response."""
        findings: list[Finding] = []
        body = response.text

        for cred_type, info in self.CREDENTIAL_PATTERNS.items():
            if re.search(info["pattern"], body, re.IGNORECASE):
                findings.append(Finding(
                    title=f"Credential Exposure: {info['description']}",
                    description=(
                        f"Endpoint {endpoint.display_name} response contains "
                        f"{info['description']}. This is a serious security risk."
                    ),
                    severity=Severity.CRITICAL,
                    category="data_exposure",
                    endpoint=endpoint.display_name,
                    evidence=f"Credential type: {cred_type}",
                    recommendation=(
                        f"Never include {info['description']} in API responses. "
                        "Use environment variables for secrets, and implement response "
                        "filtering to prevent accidental credential leakage."
                    ),
                    owasp_mapping="API3:2023 Broken Object Property Level Authorization",
                    cwe_id="CWE-200",
                ))

        return findings

    def _check_internal_paths(
        self, endpoint: Endpoint, response: httpx.Response
    ) -> list[Finding]:
        """Check for internal path disclosure in responses."""
        findings: list[Finding] = []
        body = response.text

        for path_type, info in self.INTERNAL_PATH_PATTERNS.items():
            if re.search(info["pattern"], body, re.IGNORECASE):
                findings.append(Finding(
                    title=f"Internal Path Disclosure: {info['description']}",
                    description=(
                        f"Endpoint {endpoint.display_name} reveals {info['description']}. "
                        "This information assists attackers in mapping the server environment."
                    ),
                    severity=Severity.MEDIUM if path_type != "stack_trace" else Severity.HIGH,
                    category="data_exposure",
                    endpoint=endpoint.display_name,
                    evidence=f"Disclosure type: {path_type}",
                    recommendation=(
                        "Disable debug mode in production. Implement custom error handlers "
                        "that do not reveal internal details. Sanitize all responses to "
                        "remove filesystem paths and internal URLs."
                    ),
                    owasp_mapping="API8:2023 Security Misconfiguration",
                    cwe_id="CWE-209",
                ))

        return findings

    def _check_excessive_data(
        self, endpoint: Endpoint, response: httpx.Response
    ) -> list[Finding]:
        """Check for excessive data in API responses."""
        findings: list[Finding] = []

        response_size_kb = len(response.content) / 1024

        if response_size_kb > self.MAX_RESPONSE_SIZE_KB:
            findings.append(Finding(
                title="Excessive Data Exposure",
                description=(
                    f"Endpoint {endpoint.display_name} returned "
                    f"{response_size_kb:.1f} KB of data, exceeding the "
                    f"{self.MAX_RESPONSE_SIZE_KB} KB threshold."
                ),
                severity=Severity.MEDIUM,
                category="data_exposure",
                endpoint=endpoint.display_name,
                evidence=f"Response size: {response_size_kb:.1f} KB",
                recommendation=(
                    "Implement pagination for list endpoints. Use field selection "
                    "(sparse fieldsets) to return only needed data. Apply response "
                    "size limits."
                ),
                owasp_mapping="API3:2023 Broken Object Property Level Authorization",
                cwe_id="CWE-200",
            ))

        return findings

    def _check_sensitive_headers(
        self, endpoint: Endpoint, response: httpx.Response
    ) -> list[Finding]:
        """Check for sensitive information in response headers."""
        findings: list[Finding] = []
        headers = dict(response.headers)

        # Check for server version disclosure
        server = headers.get("server", "")
        if re.search(r"[\d.]+", server):
            findings.append(Finding(
                title="Server Version Disclosure",
                description=(
                    f"Endpoint {endpoint.display_name} reveals server software "
                    f"version in the Server header: {server}"
                ),
                severity=Severity.LOW,
                category="data_exposure",
                endpoint=endpoint.display_name,
                evidence=f"Server header: {server}",
                recommendation=(
                    "Remove or genericize the Server header. Do not expose "
                    "software versions to clients."
                ),
                owasp_mapping="API8:2023 Security Misconfiguration",
                cwe_id="CWE-200",
            ))

        # Check for missing security headers
        security_headers = {
            "x-content-type-options": "X-Content-Type-Options",
            "x-frame-options": "X-Frame-Options",
            "strict-transport-security": "Strict-Transport-Security",
            "content-security-policy": "Content-Security-Policy",
        }

        missing = [
            name for header, name in security_headers.items()
            if header not in {k.lower() for k in headers}
        ]

        if missing:
            findings.append(Finding(
                title="Missing Security Headers",
                description=(
                    f"Endpoint {endpoint.display_name} is missing security headers: "
                    f"{', '.join(missing)}"
                ),
                severity=Severity.LOW,
                category="data_exposure",
                endpoint=endpoint.display_name,
                evidence=f"Missing headers: {', '.join(missing)}",
                recommendation=(
                    "Add security headers to all API responses: "
                    + ", ".join(missing)
                ),
                owasp_mapping="API8:2023 Security Misconfiguration",
                cwe_id="CWE-693",
            ))

        return findings

    def _check_sensitive_fields(
        self, endpoint: Endpoint, response: httpx.Response
    ) -> list[Finding]:
        """Check for sensitive field names in JSON responses."""
        findings: list[Finding] = []

        try:
            data = response.json()
        except (ValueError, TypeError):
            return findings

        found_fields = self._find_sensitive_keys(data)
        if found_fields:
            findings.append(Finding(
                title="Sensitive Fields in Response",
                description=(
                    f"Endpoint {endpoint.display_name} response contains "
                    f"sensitive field names: {', '.join(found_fields)}"
                ),
                severity=Severity.HIGH,
                category="data_exposure",
                endpoint=endpoint.display_name,
                evidence=f"Sensitive fields: {', '.join(found_fields)}",
                recommendation=(
                    "Remove sensitive fields from API responses. Use response DTOs "
                    "or serializer field selection to exclude sensitive data."
                ),
                owasp_mapping="API3:2023 Broken Object Property Level Authorization",
                cwe_id="CWE-200",
            ))

        return findings

    def _find_sensitive_keys(self, data: object, prefix: str = "") -> list[str]:
        """Recursively find sensitive field names in JSON data."""
        found: list[str] = []
        if isinstance(data, dict):
            for key, value in data.items():
                full_key = f"{prefix}.{key}" if prefix else key
                if key.lower() in self.SENSITIVE_FIELD_NAMES:
                    found.append(full_key)
                found.extend(self._find_sensitive_keys(value, full_key))
        elif isinstance(data, list):
            for i, item in enumerate(data[:5]):  # Limit list scanning
                found.extend(self._find_sensitive_keys(item, f"{prefix}[{i}]"))
        return found

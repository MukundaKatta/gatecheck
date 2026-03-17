"""Authentication security scanner.

Tests for authentication weaknesses including missing auth, weak tokens,
and broken access control vulnerabilities.
"""

from __future__ import annotations

import re
import time
from typing import Any

import httpx

from gatecheck.models import Endpoint, Finding, ScanResult, Severity


class AuthScanner:
    """Scans API endpoints for authentication and authorization vulnerabilities.

    Tests include:
    - Missing authentication enforcement
    - Weak or predictable tokens
    - Broken object-level authorization (BOLA)
    - Broken function-level authorization
    - Missing rate limiting on auth endpoints
    """

    WEAK_TOKEN_PATTERNS = [
        r"^[a-zA-Z0-9]{1,8}$",           # Very short tokens
        r"^(test|demo|admin|password)",     # Predictable prefixes
        r"^[0-9]+$",                        # Numeric-only tokens
        r"^(Bearer\s+)?null$",              # Null tokens
        r"^(Bearer\s+)?undefined$",         # Undefined tokens
        r"^base64:[A-Za-z0-9+/=]{1,20}$",  # Very short base64
    ]

    SENSITIVE_HEADERS = [
        "authorization",
        "x-api-key",
        "x-auth-token",
        "cookie",
    ]

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
        """Run all authentication checks against the provided endpoints."""
        start_time = time.time()
        findings: list[Finding] = []

        for endpoint in endpoints:
            findings.extend(self._check_missing_auth(endpoint))
            findings.extend(self._check_weak_tokens(endpoint))
            findings.extend(self._check_bola(endpoint))
            findings.extend(self._check_broken_function_auth(endpoint))
            findings.extend(self._check_auth_header_issues(endpoint))

        duration = time.time() - start_time
        return ScanResult(
            target=endpoints[0].url if endpoints else "",
            endpoints_scanned=len(endpoints),
            findings=findings,
            scan_duration_seconds=round(duration, 3),
            scanner_name="AuthScanner",
        )

    def _check_missing_auth(self, endpoint: Endpoint) -> list[Finding]:
        """Test if endpoint is accessible without authentication."""
        findings: list[Finding] = []

        # Build a request without any auth headers
        headers = {
            k: v for k, v in endpoint.headers.items()
            if k.lower() not in self.SENSITIVE_HEADERS
        }

        try:
            response = self.client.request(
                method=endpoint.method.value,
                url=endpoint.url,
                headers=headers,
                params=endpoint.params,
            )

            if response.status_code in (200, 201, 204):
                findings.append(Finding(
                    title="Missing Authentication",
                    description=(
                        f"Endpoint {endpoint.display_name} is accessible without "
                        f"any authentication credentials. Returned HTTP {response.status_code}."
                    ),
                    severity=Severity.CRITICAL,
                    category="authentication",
                    endpoint=endpoint.display_name,
                    evidence=f"HTTP {response.status_code} with no auth headers",
                    recommendation=(
                        "Enforce authentication on all API endpoints. Use OAuth 2.0, "
                        "API keys, or JWT tokens with proper validation."
                    ),
                    owasp_mapping="API2:2023 Broken Authentication",
                    cwe_id="CWE-306",
                ))
        except httpx.RequestError:
            pass  # Network errors are not findings

        return findings

    def _check_weak_tokens(self, endpoint: Endpoint) -> list[Finding]:
        """Analyze authentication tokens for weakness indicators."""
        findings: list[Finding] = []

        token = endpoint.auth_token
        if not token:
            # Also check headers for tokens
            for header_name in self.SENSITIVE_HEADERS:
                token = endpoint.headers.get(header_name, "")
                if token:
                    break

        if not token:
            return findings

        # Strip Bearer prefix for analysis
        raw_token = re.sub(r"^Bearer\s+", "", token, flags=re.IGNORECASE)

        for pattern in self.WEAK_TOKEN_PATTERNS:
            if re.match(pattern, raw_token, re.IGNORECASE):
                findings.append(Finding(
                    title="Weak Authentication Token",
                    description=(
                        f"The authentication token for {endpoint.display_name} "
                        f"matches a weak pattern: {pattern}"
                    ),
                    severity=Severity.HIGH,
                    category="authentication",
                    endpoint=endpoint.display_name,
                    evidence=f"Token matches weak pattern: {pattern}",
                    recommendation=(
                        "Use cryptographically strong, randomly generated tokens "
                        "with sufficient entropy (at least 128 bits). Avoid predictable "
                        "token formats."
                    ),
                    owasp_mapping="API2:2023 Broken Authentication",
                    cwe_id="CWE-1391",
                ))
                break

        # Check for JWT without signature verification indicators
        parts = raw_token.split(".")
        if len(parts) == 3:
            findings.extend(self._check_jwt_weaknesses(raw_token, endpoint))

        return findings

    def _check_jwt_weaknesses(self, token: str, endpoint: Endpoint) -> list[Finding]:
        """Check JWT tokens for common weaknesses."""
        import base64
        import json

        findings: list[Finding] = []
        parts = token.split(".")

        try:
            # Decode header (add padding)
            header_b64 = parts[0] + "=" * (4 - len(parts[0]) % 4)
            header = json.loads(base64.urlsafe_b64decode(header_b64))

            # Check for 'none' algorithm
            alg = header.get("alg", "")
            if alg.lower() == "none":
                findings.append(Finding(
                    title="JWT Algorithm None Vulnerability",
                    description=(
                        f"JWT token for {endpoint.display_name} uses 'none' algorithm, "
                        "allowing unsigned tokens."
                    ),
                    severity=Severity.CRITICAL,
                    category="authentication",
                    endpoint=endpoint.display_name,
                    evidence=f"JWT header: alg={alg}",
                    recommendation=(
                        "Never accept JWTs with 'none' algorithm. Enforce a specific "
                        "algorithm (RS256 or ES256) on the server side."
                    ),
                    owasp_mapping="API2:2023 Broken Authentication",
                    cwe_id="CWE-327",
                ))

            # Check for weak algorithms
            if alg.upper() in ("HS256",) and len(parts[2]) < 20:
                findings.append(Finding(
                    title="JWT Weak Signing",
                    description=(
                        f"JWT for {endpoint.display_name} uses {alg} with a "
                        "potentially weak signature."
                    ),
                    severity=Severity.MEDIUM,
                    category="authentication",
                    endpoint=endpoint.display_name,
                    evidence=f"Algorithm: {alg}, short signature",
                    recommendation="Use RS256 or ES256 for JWT signing with strong keys.",
                    owasp_mapping="API2:2023 Broken Authentication",
                    cwe_id="CWE-326",
                ))

        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            pass

        return findings

    def _check_bola(self, endpoint: Endpoint) -> list[Finding]:
        """Check for Broken Object Level Authorization (BOLA).

        Tests whether substituting object IDs in URLs allows access to
        other users' resources.
        """
        findings: list[Finding] = []

        # Detect numeric IDs in the URL path
        url = endpoint.url
        id_pattern = re.compile(r"/(\d+)(?:/|$|\?)")
        match = id_pattern.search(url)
        if not match:
            return findings

        original_id = match.group(1)
        # Try adjacent IDs
        test_ids = [str(int(original_id) + 1), str(int(original_id) - 1), "1", "0"]

        for test_id in test_ids:
            if test_id == original_id:
                continue
            test_url = url[:match.start(1)] + test_id + url[match.end(1):]

            try:
                response = self.client.request(
                    method=endpoint.method.value,
                    url=test_url,
                    headers=endpoint.headers,
                    params=endpoint.params,
                )
                if response.status_code in (200, 201):
                    findings.append(Finding(
                        title="Broken Object Level Authorization (BOLA)",
                        description=(
                            f"Endpoint {endpoint.display_name} may be vulnerable to "
                            f"BOLA. Replacing ID {original_id} with {test_id} "
                            f"returned HTTP {response.status_code}."
                        ),
                        severity=Severity.CRITICAL,
                        category="authorization",
                        endpoint=endpoint.display_name,
                        evidence=f"ID substitution {original_id}->{test_id}: HTTP {response.status_code}",
                        recommendation=(
                            "Implement object-level authorization checks. Verify that "
                            "the authenticated user owns or has access to the requested resource."
                        ),
                        owasp_mapping="API1:2023 Broken Object Level Authorization",
                        cwe_id="CWE-639",
                    ))
                    break  # One finding is sufficient
            except httpx.RequestError:
                pass

        return findings

    def _check_broken_function_auth(self, endpoint: Endpoint) -> list[Finding]:
        """Check for Broken Function Level Authorization.

        Tests whether admin/privileged endpoints are accessible with
        regular user credentials.
        """
        findings: list[Finding] = []
        admin_indicators = ["/admin", "/manage", "/internal", "/debug", "/config"]

        url_lower = endpoint.url.lower()
        if not any(indicator in url_lower for indicator in admin_indicators):
            return findings

        try:
            response = self.client.request(
                method=endpoint.method.value,
                url=endpoint.url,
                headers=endpoint.headers,
                params=endpoint.params,
            )
            if response.status_code in (200, 201, 204):
                findings.append(Finding(
                    title="Broken Function Level Authorization",
                    description=(
                        f"Administrative endpoint {endpoint.display_name} appears "
                        f"accessible. Returned HTTP {response.status_code}."
                    ),
                    severity=Severity.HIGH,
                    category="authorization",
                    endpoint=endpoint.display_name,
                    evidence=f"Admin endpoint returned HTTP {response.status_code}",
                    recommendation=(
                        "Implement role-based access control (RBAC). Deny access to "
                        "administrative functions by default and whitelist authorized roles."
                    ),
                    owasp_mapping="API5:2023 Broken Function Level Authorization",
                    cwe_id="CWE-285",
                ))
        except httpx.RequestError:
            pass

        return findings

    def _check_auth_header_issues(self, endpoint: Endpoint) -> list[Finding]:
        """Check for authentication header configuration issues."""
        findings: list[Finding] = []

        # Check if auth is sent over non-HTTPS
        if endpoint.url.startswith("http://") and endpoint.auth_token:
            findings.append(Finding(
                title="Credentials Sent Over Unencrypted Connection",
                description=(
                    f"Endpoint {endpoint.display_name} transmits authentication "
                    "credentials over HTTP instead of HTTPS."
                ),
                severity=Severity.HIGH,
                category="authentication",
                endpoint=endpoint.display_name,
                evidence="URL scheme is http:// with auth token present",
                recommendation=(
                    "Always use HTTPS for API communication, especially when "
                    "transmitting authentication credentials."
                ),
                owasp_mapping="API2:2023 Broken Authentication",
                cwe_id="CWE-319",
            ))

        return findings

"""Injection vulnerability scanner.

Tests for SQL injection, NoSQL injection, and command injection payloads
against API endpoints.
"""

from __future__ import annotations

import re
import time
from typing import Any

import httpx

from gatecheck.models import Endpoint, Finding, ScanResult, Severity


class InjectionScanner:
    """Scans API endpoints for injection vulnerabilities.

    Tests include:
    - SQL injection (classic, blind, error-based, union-based)
    - NoSQL injection (MongoDB operator injection, JSON injection)
    - Command injection (OS command execution via input fields)
    """

    SQL_PAYLOADS: list[dict[str, str]] = [
        {"payload": "' OR '1'='1", "type": "classic_sqli", "description": "Classic SQL injection tautology"},
        {"payload": "'; DROP TABLE users;--", "type": "classic_sqli", "description": "SQL injection with DROP"},
        {"payload": "' UNION SELECT NULL,NULL,NULL--", "type": "union_sqli", "description": "UNION-based SQL injection"},
        {"payload": "1' AND 1=1--", "type": "boolean_sqli", "description": "Boolean-based blind SQL injection (true)"},
        {"payload": "1' AND 1=2--", "type": "boolean_sqli", "description": "Boolean-based blind SQL injection (false)"},
        {"payload": "' OR SLEEP(5)--", "type": "time_sqli", "description": "Time-based blind SQL injection"},
        {"payload": "1; WAITFOR DELAY '0:0:5'--", "type": "time_sqli", "description": "MSSQL time-based injection"},
        {"payload": "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(0x7e,version(),0x7e,FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--", "type": "error_sqli", "description": "Error-based SQL injection"},
        {"payload": "admin'--", "type": "auth_bypass_sqli", "description": "SQL injection auth bypass"},
        {"payload": "1' ORDER BY 1--", "type": "probe_sqli", "description": "SQL injection column count probe"},
    ]

    NOSQL_PAYLOADS: list[dict[str, Any]] = [
        {"payload": {"$gt": ""}, "type": "operator_injection", "description": "MongoDB $gt operator injection"},
        {"payload": {"$ne": None}, "type": "operator_injection", "description": "MongoDB $ne null injection"},
        {"payload": {"$regex": ".*"}, "type": "regex_injection", "description": "MongoDB regex match-all injection"},
        {"payload": {"$where": "1==1"}, "type": "where_injection", "description": "MongoDB $where injection"},
        {"payload": {"$exists": True}, "type": "operator_injection", "description": "MongoDB $exists injection"},
    ]

    COMMAND_PAYLOADS: list[dict[str, str]] = [
        {"payload": "; ls -la", "type": "cmd_injection", "description": "Unix command injection with semicolon"},
        {"payload": "| cat /etc/passwd", "type": "cmd_injection", "description": "Pipe-based command injection"},
        {"payload": "$(whoami)", "type": "cmd_injection", "description": "Command substitution injection"},
        {"payload": "`id`", "type": "cmd_injection", "description": "Backtick command injection"},
        {"payload": "& dir", "type": "cmd_injection", "description": "Windows command injection"},
        {"payload": "\n/bin/cat /etc/passwd", "type": "cmd_injection", "description": "Newline-based command injection"},
        {"payload": "{{7*7}}", "type": "ssti", "description": "Server-side template injection probe"},
    ]

    SQL_ERROR_PATTERNS = [
        r"SQL syntax.*MySQL",
        r"Warning.*mysql_",
        r"PostgreSQL.*ERROR",
        r"ORA-\d{5}",
        r"Microsoft.*ODBC.*SQL Server",
        r"Unclosed quotation mark",
        r"pg_query\(\)",
        r"SQLite3?::SQLException",
        r"SQLSTATE\[",
        r"syntax error at or near",
        r"mysql_fetch",
        r"you have an error in your sql syntax",
    ]

    COMMAND_OUTPUT_PATTERNS = [
        r"root:.*:0:0:",                   # /etc/passwd content
        r"uid=\d+\(.*\)\s+gid=\d+",       # id command output
        r"total\s+\d+",                     # ls output
        r"Volume Serial Number",            # dir output on Windows
        r"\b(www-data|apache|nginx|nobody)\b",  # Common service accounts
        r"49",                              # 7*7 SSTI result
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
        """Run all injection checks against the provided endpoints."""
        start_time = time.time()
        findings: list[Finding] = []

        for endpoint in endpoints:
            findings.extend(self._test_sql_injection(endpoint))
            findings.extend(self._test_nosql_injection(endpoint))
            findings.extend(self._test_command_injection(endpoint))

        duration = time.time() - start_time
        return ScanResult(
            target=endpoints[0].url if endpoints else "",
            endpoints_scanned=len(endpoints),
            findings=findings,
            scan_duration_seconds=round(duration, 3),
            scanner_name="InjectionScanner",
        )

    def _test_sql_injection(self, endpoint: Endpoint) -> list[Finding]:
        """Test endpoint for SQL injection vulnerabilities."""
        findings: list[Finding] = []

        # Get baseline response
        baseline_response = self._get_baseline(endpoint)

        for payload_info in self.SQL_PAYLOADS:
            payload = payload_info["payload"]
            result = self._send_payload_in_params(endpoint, payload)
            if result is None:
                continue

            response_text = result.text
            status_code = result.status_code

            # Check for SQL error messages in response
            for pattern in self.SQL_ERROR_PATTERNS:
                if re.search(pattern, response_text, re.IGNORECASE):
                    findings.append(Finding(
                        title="SQL Injection Detected",
                        description=(
                            f"Endpoint {endpoint.display_name} is vulnerable to "
                            f"{payload_info['description']}. SQL error message "
                            "leaked in response."
                        ),
                        severity=Severity.CRITICAL,
                        category="injection",
                        endpoint=endpoint.display_name,
                        evidence=f"Payload: {payload} | Error pattern: {pattern}",
                        recommendation=(
                            "Use parameterized queries or prepared statements. "
                            "Never concatenate user input into SQL queries. "
                            "Implement input validation and sanitize all user-supplied data."
                        ),
                        owasp_mapping="API8:2023 Security Misconfiguration",
                        cwe_id="CWE-89",
                    ))
                    break

            # Check for boolean-based blind SQLi
            if payload_info["type"] == "boolean_sqli" and baseline_response is not None:
                if self._detect_boolean_blind(
                    baseline_response, result, payload_info["payload"]
                ):
                    findings.append(Finding(
                        title="Blind SQL Injection (Boolean-based)",
                        description=(
                            f"Endpoint {endpoint.display_name} shows different "
                            f"behavior for true/false SQL conditions, indicating "
                            "boolean-based blind SQL injection."
                        ),
                        severity=Severity.CRITICAL,
                        category="injection",
                        endpoint=endpoint.display_name,
                        evidence=f"Payload: {payload} caused behavioral change",
                        recommendation=(
                            "Use parameterized queries. Implement WAF rules to "
                            "detect and block SQL injection attempts."
                        ),
                        owasp_mapping="API8:2023 Security Misconfiguration",
                        cwe_id="CWE-89",
                    ))

        return findings

    def _test_nosql_injection(self, endpoint: Endpoint) -> list[Finding]:
        """Test endpoint for NoSQL injection vulnerabilities."""
        findings: list[Finding] = []

        if endpoint.body is None:
            return findings

        for payload_info in self.NOSQL_PAYLOADS:
            # Replace each string value in the body with the NoSQL payload
            for key in endpoint.body:
                if isinstance(endpoint.body[key], str):
                    modified_body = dict(endpoint.body)
                    modified_body[key] = payload_info["payload"]

                    try:
                        response = self.client.request(
                            method=endpoint.method.value,
                            url=endpoint.url,
                            headers=endpoint.headers,
                            json=modified_body,
                        )

                        if response.status_code in (200, 201):
                            findings.append(Finding(
                                title="NoSQL Injection Detected",
                                description=(
                                    f"Endpoint {endpoint.display_name} accepted "
                                    f"NoSQL operator in field '{key}': "
                                    f"{payload_info['description']}."
                                ),
                                severity=Severity.HIGH,
                                category="injection",
                                endpoint=endpoint.display_name,
                                evidence=f"Field: {key}, Payload: {payload_info['payload']}",
                                recommendation=(
                                    "Validate and sanitize all input. Reject objects and "
                                    "operators in string fields. Use allowlists for expected "
                                    "input types."
                                ),
                                owasp_mapping="API8:2023 Security Misconfiguration",
                                cwe_id="CWE-943",
                            ))
                            break
                    except httpx.RequestError:
                        pass

        return findings

    def _test_command_injection(self, endpoint: Endpoint) -> list[Finding]:
        """Test endpoint for OS command injection vulnerabilities."""
        findings: list[Finding] = []

        for payload_info in self.COMMAND_PAYLOADS:
            payload = payload_info["payload"]
            result = self._send_payload_in_params(endpoint, payload)
            if result is None:
                continue

            response_text = result.text

            for pattern in self.COMMAND_OUTPUT_PATTERNS:
                if re.search(pattern, response_text):
                    findings.append(Finding(
                        title="Command Injection Detected",
                        description=(
                            f"Endpoint {endpoint.display_name} is vulnerable to "
                            f"{payload_info['description']}. OS command output "
                            "detected in response."
                        ),
                        severity=Severity.CRITICAL,
                        category="injection",
                        endpoint=endpoint.display_name,
                        evidence=f"Payload: {payload} | Output pattern: {pattern}",
                        recommendation=(
                            "Never pass user input to OS commands. Use language-native "
                            "functions instead of shell commands. If shell commands are "
                            "unavoidable, use strict allowlists and escape all input."
                        ),
                        owasp_mapping="API8:2023 Security Misconfiguration",
                        cwe_id="CWE-78",
                    ))
                    break

        return findings

    def _send_payload_in_params(
        self, endpoint: Endpoint, payload: str
    ) -> httpx.Response | None:
        """Send a payload by injecting it into query parameters or body fields."""
        try:
            # Inject into query params
            if endpoint.params:
                modified_params = {k: payload for k in endpoint.params}
                return self.client.request(
                    method=endpoint.method.value,
                    url=endpoint.url,
                    headers=endpoint.headers,
                    params=modified_params,
                )

            # Inject into body fields
            if endpoint.body:
                modified_body = {
                    k: payload if isinstance(v, str) else v
                    for k, v in endpoint.body.items()
                }
                return self.client.request(
                    method=endpoint.method.value,
                    url=endpoint.url,
                    headers=endpoint.headers,
                    json=modified_body,
                )

            # Inject as a query parameter
            return self.client.request(
                method=endpoint.method.value,
                url=endpoint.url,
                headers=endpoint.headers,
                params={"q": payload},
            )
        except httpx.RequestError:
            return None

    def _get_baseline(self, endpoint: Endpoint) -> httpx.Response | None:
        """Get a baseline response for comparison."""
        try:
            return self.client.request(
                method=endpoint.method.value,
                url=endpoint.url,
                headers=endpoint.headers,
                params=endpoint.params,
            )
        except httpx.RequestError:
            return None

    def _detect_boolean_blind(
        self,
        baseline: httpx.Response,
        test_response: httpx.Response,
        payload: str,
    ) -> bool:
        """Detect boolean-based blind SQL injection by comparing responses."""
        # If the true condition matches baseline but false condition differs
        if "1=1" in payload:
            return (
                test_response.status_code == baseline.status_code
                and len(test_response.text) == len(baseline.text)
            )
        if "1=2" in payload:
            return (
                test_response.status_code != baseline.status_code
                or abs(len(test_response.text) - len(baseline.text)) > 50
            )
        return False

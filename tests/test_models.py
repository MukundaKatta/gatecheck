"""Tests for GateCheck data models."""

import pytest

from gatecheck.models import Endpoint, Finding, HTTPMethod, ScanResult, Severity


class TestSeverity:
    def test_severity_values(self):
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"

    def test_severity_numeric(self):
        assert Severity.CRITICAL.numeric == 5
        assert Severity.HIGH.numeric == 4
        assert Severity.MEDIUM.numeric == 3
        assert Severity.LOW.numeric == 2
        assert Severity.INFO.numeric == 1

    def test_severity_ordering(self):
        severities = [Severity.LOW, Severity.CRITICAL, Severity.MEDIUM]
        sorted_sev = sorted(severities, key=lambda s: s.numeric, reverse=True)
        assert sorted_sev == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


class TestEndpoint:
    def test_create_endpoint(self):
        ep = Endpoint(url="https://api.example.com/users")
        assert ep.url == "https://api.example.com/users"
        assert ep.method == HTTPMethod.GET
        assert ep.headers == {}
        assert ep.params == {}
        assert ep.body is None

    def test_endpoint_with_all_fields(self):
        ep = Endpoint(
            url="https://api.example.com/users",
            method=HTTPMethod.POST,
            headers={"Content-Type": "application/json"},
            params={"page": "1"},
            body={"name": "test"},
            auth_token="abc123",
            description="Create user",
        )
        assert ep.method == HTTPMethod.POST
        assert ep.auth_token == "abc123"
        assert ep.body == {"name": "test"}

    def test_display_name(self):
        ep = Endpoint(url="https://api.example.com/users", method=HTTPMethod.DELETE)
        assert ep.display_name == "DELETE https://api.example.com/users"


class TestFinding:
    def test_create_finding(self):
        f = Finding(
            title="Test Finding",
            description="A test vulnerability",
            severity=Severity.HIGH,
            category="test",
            endpoint="GET /api/test",
        )
        assert f.title == "Test Finding"
        assert f.severity == Severity.HIGH
        assert f.evidence == ""
        assert f.recommendation == ""

    def test_finding_severity_icon(self):
        f = Finding(
            title="Critical Issue",
            description="desc",
            severity=Severity.CRITICAL,
            category="test",
            endpoint="GET /test",
        )
        assert f.severity_icon == "[CRITICAL]"

    def test_finding_with_owasp(self):
        f = Finding(
            title="Missing Auth",
            description="desc",
            severity=Severity.HIGH,
            category="auth",
            endpoint="GET /api",
            owasp_mapping="API2:2023 Broken Authentication",
            cwe_id="CWE-306",
        )
        assert "API2:2023" in f.owasp_mapping
        assert f.cwe_id == "CWE-306"


class TestScanResult:
    def test_empty_result(self):
        result = ScanResult(target="https://api.example.com")
        assert result.total_findings == 0
        assert result.critical_count == 0

    def test_result_with_findings(self):
        findings = [
            Finding(title="F1", description="d", severity=Severity.CRITICAL, category="auth", endpoint="e"),
            Finding(title="F2", description="d", severity=Severity.HIGH, category="auth", endpoint="e"),
            Finding(title="F3", description="d", severity=Severity.CRITICAL, category="auth", endpoint="e"),
            Finding(title="F4", description="d", severity=Severity.LOW, category="auth", endpoint="e"),
        ]
        result = ScanResult(
            target="https://api.example.com",
            endpoints_scanned=2,
            findings=findings,
        )
        assert result.total_findings == 4
        assert result.critical_count == 2
        assert result.high_count == 1
        assert result.low_count == 1
        assert result.medium_count == 0

    def test_findings_by_severity(self):
        findings = [
            Finding(title="F1", description="d", severity=Severity.HIGH, category="c", endpoint="e"),
            Finding(title="F2", description="d", severity=Severity.HIGH, category="c", endpoint="e"),
            Finding(title="F3", description="d", severity=Severity.LOW, category="c", endpoint="e"),
        ]
        result = ScanResult(target="t", findings=findings)
        grouped = result.findings_by_severity()
        assert len(grouped[Severity.HIGH]) == 2
        assert len(grouped[Severity.LOW]) == 1

    def test_merge_results(self):
        r1 = ScanResult(
            target="t",
            endpoints_scanned=3,
            findings=[Finding(title="F1", description="d", severity=Severity.HIGH, category="c", endpoint="e")],
            scanner_name="Scanner1",
        )
        r2 = ScanResult(
            target="t",
            endpoints_scanned=2,
            findings=[Finding(title="F2", description="d", severity=Severity.LOW, category="c", endpoint="e")],
            scanner_name="Scanner2",
        )
        merged = r1.merge(r2)
        assert merged.endpoints_scanned == 5
        assert merged.total_findings == 2
        assert "Scanner1" in merged.scanner_name
        assert "Scanner2" in merged.scanner_name

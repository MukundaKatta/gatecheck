"""Tests for GateCheck analyzer modules."""

import pytest

from gatecheck.analyzer.compliance import (
    ComplianceStatus,
    OWASPAPIChecker,
    OWASP_API_TOP_10,
)
from gatecheck.analyzer.endpoint import EndpointAnalyzer
from gatecheck.analyzer.report_gen import SecurityReportGenerator
from gatecheck.models import Endpoint, Finding, HTTPMethod, ScanResult, Severity


class TestEndpointAnalyzer:
    def setup_method(self):
        self.analyzer = EndpointAnalyzer()

    def test_analyze_empty(self):
        profile = self.analyzer.analyze([])
        assert profile.total_endpoints == 0

    def test_analyze_single_endpoint(self):
        ep = Endpoint(url="https://api.example.com/users/123", method=HTTPMethod.GET)
        profile = self.analyzer.analyze([ep])
        assert profile.total_endpoints == 1
        assert profile.base_url == "https://api.example.com"
        assert "GET" in profile.methods_used

    def test_profile_detects_id_parameter(self):
        ep = Endpoint(url="https://api.example.com/users/42/orders")
        profile = self.analyzer.analyze([ep])
        assert profile.endpoint_profiles[0].has_id_parameter is True

    def test_profile_detects_uuid(self):
        ep = Endpoint(url="https://api.example.com/users/550e8400-e29b-41d4-a716-446655440000")
        profile = self.analyzer.analyze([ep])
        assert profile.endpoint_profiles[0].has_id_parameter is True

    def test_profile_no_id(self):
        ep = Endpoint(url="https://api.example.com/users")
        profile = self.analyzer.analyze([ep])
        assert profile.endpoint_profiles[0].has_id_parameter is False

    def test_profile_detects_auth(self):
        ep = Endpoint(
            url="https://api.example.com/users",
            headers={"Authorization": "Bearer token123"},
        )
        profile = self.analyzer.analyze([ep])
        assert profile.endpoint_profiles[0].has_auth is True
        assert profile.has_authentication is True

    def test_profile_detects_admin_endpoint(self):
        ep = Endpoint(url="https://api.example.com/admin/settings")
        profile = self.analyzer.analyze([ep])
        assert profile.endpoint_profiles[0].is_admin_endpoint is True
        assert profile.admin_endpoints == 1

    def test_risk_score_no_auth(self):
        ep = Endpoint(url="https://api.example.com/users")
        profile = self.analyzer.analyze([ep])
        assert profile.endpoint_profiles[0].risk_score >= 3.0
        assert "No authentication detected" in profile.endpoint_profiles[0].risk_factors

    def test_risk_score_mutation_endpoint(self):
        ep = Endpoint(url="https://api.example.com/users", method=HTTPMethod.POST)
        profile = self.analyzer.analyze([ep])
        assert "Accepts data mutation" in profile.endpoint_profiles[0].risk_factors

    def test_risk_score_http_not_https(self):
        ep = Endpoint(url="http://api.example.com/users")
        profile = self.analyzer.analyze([ep])
        assert "Unencrypted HTTP connection" in profile.endpoint_profiles[0].risk_factors

    def test_multiple_endpoints(self):
        endpoints = [
            Endpoint(url="https://api.example.com/users", method=HTTPMethod.GET),
            Endpoint(url="https://api.example.com/users", method=HTTPMethod.POST),
            Endpoint(url="https://api.example.com/admin/config", method=HTTPMethod.GET),
        ]
        profile = self.analyzer.analyze(endpoints)
        assert profile.total_endpoints == 3
        assert {"GET", "POST"} == profile.methods_used
        assert profile.admin_endpoints == 1
        assert profile.data_mutation_endpoints == 1

    def test_prioritize_for_scanning(self):
        endpoints = [
            Endpoint(
                url="https://api.example.com/public",
                headers={"Authorization": "Bearer token"},
            ),
            Endpoint(url="http://api.example.com/admin/users/123", method=HTTPMethod.DELETE),
        ]
        prioritized = self.analyzer.prioritize_for_scanning(endpoints)
        # The admin/delete/http/id endpoint should be higher risk
        assert prioritized[0].url == "http://api.example.com/admin/users/123"


class TestOWASPAPIChecker:
    def setup_method(self):
        self.checker = OWASPAPIChecker()

    def test_owasp_top_10_defined(self):
        assert len(OWASP_API_TOP_10) == 10
        for cat in OWASP_API_TOP_10:
            assert "id" in cat
            assert "name" in cat
            assert "description" in cat

    def test_check_no_findings(self):
        result = ScanResult(target="test", scanner_name="test")
        report = self.checker.check([result])
        assert report.not_tested_count == 10
        assert report.overall_score == 0.0

    def test_check_with_auth_finding(self):
        result = ScanResult(
            target="test",
            findings=[
                Finding(
                    title="Missing Auth",
                    description="No auth required",
                    severity=Severity.CRITICAL,
                    category="authentication",
                    endpoint="GET /api",
                    owasp_mapping="API2:2023 Broken Authentication",
                ),
            ],
        )
        report = self.checker.check([result])
        assert report.failing_count >= 1

        # Find the Broken Authentication category
        auth_cat = next(c for c in report.categories if "API2:2023" in c.id)
        assert auth_cat.status == ComplianceStatus.FAIL
        assert len(auth_cat.findings) >= 1

    def test_check_keyword_mapping(self):
        result = ScanResult(
            target="test",
            findings=[
                Finding(
                    title="SQL Injection",
                    description="SQL injection found",
                    severity=Severity.HIGH,
                    category="injection",
                    endpoint="GET /api",
                    # No explicit owasp_mapping
                ),
            ],
        )
        report = self.checker.check([result])
        # Should map to API8 (Security Misconfiguration) via keyword
        misconfig = next(c for c in report.categories if "API8:2023" in c.id)
        assert len(misconfig.findings) >= 1

    def test_gap_analysis(self):
        result = ScanResult(target="test")
        report = self.checker.check([result])
        gaps = self.checker.get_gap_analysis(report)
        assert len(gaps) == 10  # All categories untested


class TestSecurityReportGenerator:
    def setup_method(self):
        self.generator = SecurityReportGenerator()

    def test_generate_empty_report(self):
        result = ScanResult(target="https://api.example.com", scanner_name="test")
        report = self.generator.generate([result])
        assert report["executive_summary"]["total_findings"] == 0
        assert report["executive_summary"]["overall_risk_level"] == "NONE"

    def test_generate_critical_report(self):
        result = ScanResult(
            target="https://api.example.com",
            endpoints_scanned=5,
            findings=[
                Finding(
                    title="Critical Issue",
                    description="Something critical",
                    severity=Severity.CRITICAL,
                    category="auth",
                    endpoint="GET /api",
                    recommendation="Fix it now",
                ),
            ],
            scanner_name="TestScanner",
        )
        report = self.generator.generate([result])
        assert report["executive_summary"]["overall_risk_level"] == "CRITICAL"
        assert report["executive_summary"]["breakdown"]["critical"] == 1
        assert len(report["findings"]) == 1
        assert report["findings"][0]["id"] == "GC-0001"

    def test_generate_json(self):
        import json
        result = ScanResult(target="test", scanner_name="test")
        json_str = self.generator.generate_json([result])
        parsed = json.loads(json_str)
        assert "metadata" in parsed
        assert "executive_summary" in parsed

    def test_recommendations_prioritized(self):
        findings = [
            Finding(
                title="Low Issue",
                description="d",
                severity=Severity.LOW,
                category="c",
                endpoint="e",
                recommendation="Low priority fix",
            ),
            Finding(
                title="Critical Issue",
                description="d",
                severity=Severity.CRITICAL,
                category="c",
                endpoint="e",
                recommendation="Critical fix needed",
            ),
        ]
        result = ScanResult(target="t", findings=findings)
        report = self.generator.generate([result])
        recs = report["recommendations"]
        assert len(recs) == 2
        assert recs[0]["priority"] == "critical"

    def test_metadata_includes_scanners(self):
        results = [
            ScanResult(target="t", scanner_name="AuthScanner"),
            ScanResult(target="t", scanner_name="InjectionScanner"),
        ]
        report = self.generator.generate(results)
        assert "AuthScanner" in report["metadata"]["scanners_used"]
        assert "InjectionScanner" in report["metadata"]["scanners_used"]

    def test_owasp_compliance_included(self):
        result = ScanResult(target="t", scanner_name="test")
        report = self.generator.generate([result], include_owasp=True)
        assert "owasp_compliance" in report
        assert "categories" in report["owasp_compliance"]
        assert len(report["owasp_compliance"]["categories"]) == 10

    def test_owasp_compliance_excluded(self):
        result = ScanResult(target="t", scanner_name="test")
        report = self.generator.generate([result], include_owasp=False)
        assert "owasp_compliance" not in report

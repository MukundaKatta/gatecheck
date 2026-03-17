"""Security report generator.

Generates comprehensive security reports from scan results with
findings, severity assessments, and remediation recommendations.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from gatecheck.analyzer.compliance import ComplianceReport, ComplianceStatus, OWASPAPIChecker
from gatecheck.models import Finding, ScanResult, Severity


class SecurityReportGenerator:
    """Generates structured security reports from scan results.

    Supports multiple output formats and provides:
    - Executive summary
    - Detailed findings with evidence
    - Severity distribution
    - OWASP API Top 10 compliance mapping
    - Prioritized remediation recommendations
    """

    def __init__(self) -> None:
        self.owasp_checker = OWASPAPIChecker()

    def generate(
        self,
        scan_results: list[ScanResult],
        include_owasp: bool = True,
    ) -> dict[str, Any]:
        """Generate a comprehensive security report.

        Args:
            scan_results: List of scan results from different scanners.
            include_owasp: Whether to include OWASP API Top 10 mapping.

        Returns:
            Structured report dictionary.
        """
        # Merge all findings
        all_findings: list[Finding] = []
        total_endpoints = 0
        total_duration = 0.0
        scanners_used: list[str] = []

        for result in scan_results:
            all_findings.extend(result.findings)
            total_endpoints += result.endpoints_scanned
            total_duration += result.scan_duration_seconds
            if result.scanner_name:
                scanners_used.append(result.scanner_name)

        # Sort findings by severity
        all_findings.sort(key=lambda f: f.severity.numeric, reverse=True)

        report: dict[str, Any] = {
            "metadata": self._build_metadata(
                scan_results, total_endpoints, total_duration, scanners_used
            ),
            "executive_summary": self._build_executive_summary(all_findings),
            "severity_distribution": self._build_severity_distribution(all_findings),
            "findings": [self._format_finding(f, i + 1) for i, f in enumerate(all_findings)],
            "recommendations": self._build_recommendations(all_findings),
        }

        if include_owasp:
            compliance_report = self.owasp_checker.check(scan_results)
            report["owasp_compliance"] = self._format_owasp_compliance(compliance_report)

        return report

    def generate_json(self, scan_results: list[ScanResult], **kwargs: Any) -> str:
        """Generate report as JSON string."""
        report = self.generate(scan_results, **kwargs)
        return json.dumps(report, indent=2, default=str)

    def _build_metadata(
        self,
        scan_results: list[ScanResult],
        total_endpoints: int,
        total_duration: float,
        scanners_used: list[str],
    ) -> dict[str, Any]:
        """Build report metadata section."""
        targets = list({r.target for r in scan_results if r.target})
        return {
            "report_generated": datetime.now(timezone.utc).isoformat(),
            "targets": targets,
            "endpoints_scanned": total_endpoints,
            "scan_duration_seconds": round(total_duration, 3),
            "scanners_used": scanners_used,
            "gatecheck_version": "0.1.0",
        }

    def _build_executive_summary(self, findings: list[Finding]) -> dict[str, Any]:
        """Build executive summary section."""
        total = len(findings)
        critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in findings if f.severity == Severity.HIGH)
        medium = sum(1 for f in findings if f.severity == Severity.MEDIUM)
        low = sum(1 for f in findings if f.severity == Severity.LOW)
        info = sum(1 for f in findings if f.severity == Severity.INFO)

        if critical > 0:
            risk_level = "CRITICAL"
            summary = (
                f"The scan identified {total} security finding(s), including "
                f"{critical} CRITICAL issue(s) that require immediate attention. "
                "The API has significant security vulnerabilities that could lead "
                "to data breaches or system compromise."
            )
        elif high > 0:
            risk_level = "HIGH"
            summary = (
                f"The scan identified {total} security finding(s), including "
                f"{high} HIGH severity issue(s). These vulnerabilities pose "
                "significant risk and should be addressed promptly."
            )
        elif medium > 0:
            risk_level = "MEDIUM"
            summary = (
                f"The scan identified {total} security finding(s), with "
                f"{medium} MEDIUM severity issue(s). While not immediately "
                "exploitable, these should be remediated in the near term."
            )
        elif total > 0:
            risk_level = "LOW"
            summary = (
                f"The scan identified {total} low-severity or informational "
                "finding(s). The API appears to have reasonable security controls."
            )
        else:
            risk_level = "NONE"
            summary = (
                "No security findings were identified during the scan. "
                "This does not guarantee the absence of vulnerabilities."
            )

        return {
            "overall_risk_level": risk_level,
            "total_findings": total,
            "summary": summary,
            "breakdown": {
                "critical": critical,
                "high": high,
                "medium": medium,
                "low": low,
                "info": info,
            },
        }

    def _build_severity_distribution(self, findings: list[Finding]) -> dict[str, int]:
        """Build severity distribution."""
        return {
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in findings if f.severity == Severity.LOW),
            "info": sum(1 for f in findings if f.severity == Severity.INFO),
        }

    def _format_finding(self, finding: Finding, index: int) -> dict[str, Any]:
        """Format a single finding for the report."""
        return {
            "id": f"GC-{index:04d}",
            "title": finding.title,
            "severity": finding.severity.value,
            "category": finding.category,
            "endpoint": finding.endpoint,
            "description": finding.description,
            "evidence": finding.evidence,
            "recommendation": finding.recommendation,
            "owasp_mapping": finding.owasp_mapping,
            "cwe_id": finding.cwe_id,
        }

    def _build_recommendations(self, findings: list[Finding]) -> list[dict[str, Any]]:
        """Build prioritized remediation recommendations."""
        # Group recommendations by category and priority
        rec_map: dict[str, dict[str, Any]] = {}

        for finding in findings:
            if not finding.recommendation:
                continue

            key = finding.recommendation[:80]  # Group similar recommendations
            if key not in rec_map:
                rec_map[key] = {
                    "recommendation": finding.recommendation,
                    "priority": finding.severity.value,
                    "priority_numeric": finding.severity.numeric,
                    "affected_endpoints": [],
                    "related_findings": 0,
                }

            rec_map[key]["affected_endpoints"].append(finding.endpoint)
            rec_map[key]["related_findings"] += 1

            # Upgrade priority if a more severe finding shares this rec
            if finding.severity.numeric > rec_map[key]["priority_numeric"]:
                rec_map[key]["priority"] = finding.severity.value
                rec_map[key]["priority_numeric"] = finding.severity.numeric

        # Sort by priority
        recs = sorted(rec_map.values(), key=lambda r: r["priority_numeric"], reverse=True)

        return [
            {
                "recommendation": r["recommendation"],
                "priority": r["priority"],
                "affected_endpoints": list(set(r["affected_endpoints"])),
                "related_findings_count": r["related_findings"],
            }
            for r in recs
        ]

    def _format_owasp_compliance(self, report: ComplianceReport) -> dict[str, Any]:
        """Format OWASP compliance report section."""
        categories = []
        for cat in report.categories:
            categories.append({
                "id": cat.id,
                "name": cat.name,
                "status": cat.status.value,
                "findings_count": len(cat.findings),
                "description": cat.description,
                "recommendation": cat.recommendation if cat.recommendation else None,
            })

        status_icon = {
            ComplianceStatus.PASS: "PASS",
            ComplianceStatus.FAIL: "FAIL",
            ComplianceStatus.WARNING: "WARN",
            ComplianceStatus.NOT_TESTED: "N/A",
        }

        return {
            "overall_score": report.overall_score,
            "summary": {
                "passing": report.passing_count,
                "failing": report.failing_count,
                "warnings": report.warning_count,
                "not_tested": report.not_tested_count,
            },
            "categories": categories,
            "gap_analysis": self.owasp_checker.get_gap_analysis(report),
        }

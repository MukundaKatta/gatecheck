"""OWASP API Security Top 10 compliance checker.

Maps security findings to OWASP API Security Top 10 (2023 edition)
categories and provides compliance assessment.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum

from gatecheck.models import Finding, ScanResult, Severity


class ComplianceStatus(str, Enum):
    """Compliance status for an OWASP category."""

    PASS = "pass"
    FAIL = "fail"
    WARNING = "warning"
    NOT_TESTED = "not_tested"


@dataclass
class OWASPCategory:
    """Represents one OWASP API Security Top 10 category."""

    id: str
    name: str
    description: str
    status: ComplianceStatus = ComplianceStatus.NOT_TESTED
    findings: list[Finding] = field(default_factory=list)
    recommendation: str = ""


@dataclass
class ComplianceReport:
    """Full OWASP API Security Top 10 compliance report."""

    categories: list[OWASPCategory] = field(default_factory=list)
    overall_score: float = 0.0  # 0-100
    passing_count: int = 0
    failing_count: int = 0
    warning_count: int = 0
    not_tested_count: int = 0


# OWASP API Security Top 10 - 2023 Edition
OWASP_API_TOP_10: list[dict[str, str]] = [
    {
        "id": "API1:2023",
        "name": "Broken Object Level Authorization",
        "description": (
            "APIs expose endpoints that handle object identifiers, creating a wide "
            "attack surface for Object Level Access Control issues. Authorization "
            "checks should be applied at every function that accesses a data source "
            "using user-supplied input."
        ),
        "keywords": "bola,authorization,object level,idor,insecure direct object",
    },
    {
        "id": "API2:2023",
        "name": "Broken Authentication",
        "description": (
            "Authentication mechanisms are often implemented incorrectly, allowing "
            "attackers to compromise authentication tokens or exploit implementation "
            "flaws to assume other users' identities."
        ),
        "keywords": "authentication,auth,token,jwt,credential,login,password,session",
    },
    {
        "id": "API3:2023",
        "name": "Broken Object Property Level Authorization",
        "description": (
            "APIs tend to expose endpoints that return all object properties. This "
            "is relevant for both excessive data exposure and mass assignment."
        ),
        "keywords": "data exposure,property,mass assignment,excessive data,pii,sensitive field",
    },
    {
        "id": "API4:2023",
        "name": "Unrestricted Resource Consumption",
        "description": (
            "Satisfying API requests requires resources such as network bandwidth, "
            "CPU, memory, and storage. APIs can be vulnerable if they do not limit "
            "the size or number of resources requested."
        ),
        "keywords": "rate limit,resource,dos,denial of service,throttle,pagination",
    },
    {
        "id": "API5:2023",
        "name": "Broken Function Level Authorization",
        "description": (
            "Complex access control policies with different hierarchies, groups, and "
            "roles, and an unclear separation between administrative and regular "
            "functions, tend to lead to authorization flaws."
        ),
        "keywords": "function level,admin,privilege,role,rbac,escalation",
    },
    {
        "id": "API6:2023",
        "name": "Unrestricted Access to Sensitive Business Flows",
        "description": (
            "APIs vulnerable to this risk expose a business flow without compensating "
            "for the damage it can cause if used excessively in an automated way."
        ),
        "keywords": "business flow,automation,abuse,bot,scraping",
    },
    {
        "id": "API7:2023",
        "name": "Server Side Request Forgery",
        "description": (
            "SSRF flaws can occur when an API fetches a remote resource without "
            "validating the user-supplied URL. This allows attackers to coerce the "
            "application to send a crafted request to an unexpected destination."
        ),
        "keywords": "ssrf,server side request,url,fetch,redirect",
    },
    {
        "id": "API8:2023",
        "name": "Security Misconfiguration",
        "description": (
            "APIs and the systems supporting them typically contain complex configurations "
            "that can be misconfigured. Security misconfiguration can happen at any level "
            "of the API stack."
        ),
        "keywords": "misconfiguration,injection,sqli,xss,header,cors,debug,stack trace,version",
    },
    {
        "id": "API9:2023",
        "name": "Improper Inventory Management",
        "description": (
            "APIs tend to expose more endpoints than traditional web applications, "
            "making proper and updated documentation important. An inventory of "
            "hosts and deployed API versions also plays a role."
        ),
        "keywords": "inventory,documentation,version,deprecated,endpoint management",
    },
    {
        "id": "API10:2023",
        "name": "Unsafe Consumption of APIs",
        "description": (
            "Developers tend to trust data received from third-party APIs more than "
            "user input. Attackers target integrated services to compromise APIs."
        ),
        "keywords": "third party,integration,upstream,consumption,trust",
    },
]


class OWASPAPIChecker:
    """Maps security findings to OWASP API Security Top 10 categories.

    Provides:
    - Automatic categorization of findings to OWASP categories
    - Compliance scoring
    - Category-level recommendations
    - Gap analysis for untested areas
    """

    def __init__(self) -> None:
        self.categories = self._initialize_categories()

    def _initialize_categories(self) -> list[OWASPCategory]:
        """Initialize OWASP categories from the Top 10 definitions."""
        return [
            OWASPCategory(
                id=cat["id"],
                name=cat["name"],
                description=cat["description"],
            )
            for cat in OWASP_API_TOP_10
        ]

    def check(self, scan_results: list[ScanResult]) -> ComplianceReport:
        """Map scan results to OWASP categories and generate compliance report."""
        # Reset categories
        self.categories = self._initialize_categories()

        # Collect all findings
        all_findings: list[Finding] = []
        for result in scan_results:
            all_findings.extend(result.findings)

        # Map findings to categories
        for finding in all_findings:
            mapped = False
            # First try explicit owasp_mapping field
            if finding.owasp_mapping:
                for category in self.categories:
                    if category.id in finding.owasp_mapping or category.name.lower() in finding.owasp_mapping.lower():
                        category.findings.append(finding)
                        mapped = True
                        break

            # Fall back to keyword matching
            if not mapped:
                self._map_by_keywords(finding)

        # Determine status for each category
        for category in self.categories:
            if category.findings:
                max_severity = max(f.severity.numeric for f in category.findings)
                if max_severity >= Severity.HIGH.numeric:
                    category.status = ComplianceStatus.FAIL
                elif max_severity >= Severity.MEDIUM.numeric:
                    category.status = ComplianceStatus.WARNING
                else:
                    category.status = ComplianceStatus.WARNING
                category.recommendation = self._generate_category_recommendation(category)
            else:
                # If we had scan results but no findings for this category,
                # mark it as passed (optimistic)
                if all_findings:
                    category.status = ComplianceStatus.PASS
                else:
                    category.status = ComplianceStatus.NOT_TESTED

        return self._build_report()

    def _map_by_keywords(self, finding: Finding) -> None:
        """Map a finding to OWASP categories based on keyword matching."""
        finding_text = (
            f"{finding.title} {finding.description} {finding.category} "
            f"{finding.cwe_id}"
        ).lower()

        best_match: OWASPCategory | None = None
        best_score = 0

        for i, cat_def in enumerate(OWASP_API_TOP_10):
            keywords = cat_def["keywords"].split(",")
            score = sum(1 for kw in keywords if kw.strip() in finding_text)
            if score > best_score:
                best_score = score
                best_match = self.categories[i]

        if best_match and best_score > 0:
            best_match.findings.append(finding)

    def _generate_category_recommendation(self, category: OWASPCategory) -> str:
        """Generate a recommendation for a category based on its findings."""
        severity_counts = {}
        for f in category.findings:
            severity_counts[f.severity] = severity_counts.get(f.severity, 0) + 1

        parts = [f"{category.name}: {len(category.findings)} finding(s) detected."]

        if Severity.CRITICAL in severity_counts:
            parts.append(
                f"  {severity_counts[Severity.CRITICAL]} CRITICAL issue(s) require immediate remediation."
            )
        if Severity.HIGH in severity_counts:
            parts.append(
                f"  {severity_counts[Severity.HIGH]} HIGH severity issue(s) should be addressed promptly."
            )

        # Collect unique recommendations from findings
        unique_recs = list(dict.fromkeys(f.recommendation for f in category.findings if f.recommendation))
        for rec in unique_recs[:3]:
            parts.append(f"  - {rec}")

        return "\n".join(parts)

    def _build_report(self) -> ComplianceReport:
        """Build the final compliance report."""
        passing = sum(1 for c in self.categories if c.status == ComplianceStatus.PASS)
        failing = sum(1 for c in self.categories if c.status == ComplianceStatus.FAIL)
        warning = sum(1 for c in self.categories if c.status == ComplianceStatus.WARNING)
        not_tested = sum(1 for c in self.categories if c.status == ComplianceStatus.NOT_TESTED)

        tested_count = len(self.categories) - not_tested
        if tested_count > 0:
            score = (passing / tested_count) * 100
        else:
            score = 0.0

        return ComplianceReport(
            categories=self.categories,
            overall_score=round(score, 1),
            passing_count=passing,
            failing_count=failing,
            warning_count=warning,
            not_tested_count=not_tested,
        )

    def get_gap_analysis(self, report: ComplianceReport) -> list[str]:
        """Identify areas that were not tested in the scan."""
        gaps: list[str] = []
        for category in report.categories:
            if category.status == ComplianceStatus.NOT_TESTED:
                gaps.append(
                    f"{category.id} {category.name}: Not covered by current scan. "
                    f"Consider adding specific tests for this category."
                )
        return gaps

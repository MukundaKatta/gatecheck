"""Data models for GateCheck API security scanning."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Severity levels for security findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def numeric(self) -> int:
        """Return numeric value for sorting (higher = more severe)."""
        return {
            Severity.CRITICAL: 5,
            Severity.HIGH: 4,
            Severity.MEDIUM: 3,
            Severity.LOW: 2,
            Severity.INFO: 1,
        }[self]


class HTTPMethod(str, Enum):
    """Supported HTTP methods."""

    GET = "GET"
    POST = "POST"
    PUT = "PUT"
    PATCH = "PATCH"
    DELETE = "DELETE"
    OPTIONS = "OPTIONS"
    HEAD = "HEAD"


class Endpoint(BaseModel):
    """Represents an API endpoint to scan."""

    url: str = Field(..., description="Full URL of the endpoint")
    method: HTTPMethod = Field(default=HTTPMethod.GET, description="HTTP method")
    headers: dict[str, str] = Field(default_factory=dict, description="Request headers")
    params: dict[str, str] = Field(default_factory=dict, description="Query parameters")
    body: dict[str, Any] | None = Field(default=None, description="Request body")
    auth_token: str | None = Field(default=None, description="Authentication token")
    description: str = Field(default="", description="Endpoint description")

    @property
    def display_name(self) -> str:
        """Human-readable endpoint identifier."""
        return f"{self.method.value} {self.url}"


class Finding(BaseModel):
    """A single security finding from a scan."""

    title: str = Field(..., description="Short title of the finding")
    description: str = Field(..., description="Detailed description of the vulnerability")
    severity: Severity = Field(..., description="Severity level")
    category: str = Field(..., description="Finding category (e.g., 'authentication', 'injection')")
    endpoint: str = Field(..., description="Affected endpoint")
    evidence: str = Field(default="", description="Evidence or proof of the finding")
    recommendation: str = Field(default="", description="Remediation recommendation")
    owasp_mapping: str = Field(default="", description="OWASP API Security Top 10 mapping")
    cwe_id: str = Field(default="", description="CWE identifier")

    @property
    def severity_icon(self) -> str:
        """Return an icon string for the severity level."""
        icons = {
            Severity.CRITICAL: "[CRITICAL]",
            Severity.HIGH: "[HIGH]",
            Severity.MEDIUM: "[MEDIUM]",
            Severity.LOW: "[LOW]",
            Severity.INFO: "[INFO]",
        }
        return icons[self.severity]


class ScanResult(BaseModel):
    """Aggregated result of a security scan against one or more endpoints."""

    target: str = Field(..., description="Target API base URL or identifier")
    endpoints_scanned: int = Field(default=0, description="Number of endpoints scanned")
    findings: list[Finding] = Field(default_factory=list, description="List of findings")
    scan_duration_seconds: float = Field(default=0.0, description="Duration of the scan")
    scanner_name: str = Field(default="", description="Name of the scanner that produced this result")

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)

    @property
    def total_findings(self) -> int:
        return len(self.findings)

    def findings_by_severity(self) -> dict[Severity, list[Finding]]:
        """Group findings by severity level."""
        grouped: dict[Severity, list[Finding]] = {}
        for finding in self.findings:
            grouped.setdefault(finding.severity, []).append(finding)
        return grouped

    def merge(self, other: ScanResult) -> ScanResult:
        """Merge another scan result into this one."""
        return ScanResult(
            target=self.target,
            endpoints_scanned=self.endpoints_scanned + other.endpoints_scanned,
            findings=self.findings + other.findings,
            scan_duration_seconds=self.scan_duration_seconds + other.scan_duration_seconds,
            scanner_name=f"{self.scanner_name}, {other.scanner_name}" if self.scanner_name else other.scanner_name,
        )

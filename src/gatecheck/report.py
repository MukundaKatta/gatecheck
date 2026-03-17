"""Rich console report output for GateCheck.

Provides formatted terminal output for scan results using the Rich library.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from gatecheck.analyzer.compliance import ComplianceReport, ComplianceStatus
from gatecheck.models import Finding, ScanResult, Severity


SEVERITY_COLORS = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

COMPLIANCE_COLORS = {
    ComplianceStatus.PASS: "green",
    ComplianceStatus.FAIL: "red",
    ComplianceStatus.WARNING: "yellow",
    ComplianceStatus.NOT_TESTED: "dim",
}


def print_scan_summary(console: Console, results: list[ScanResult]) -> None:
    """Print a summary of all scan results."""
    all_findings: list[Finding] = []
    total_endpoints = 0
    total_duration = 0.0

    for result in results:
        all_findings.extend(result.findings)
        total_endpoints += result.endpoints_scanned
        total_duration += result.scan_duration_seconds

    severity_counts = {
        Severity.CRITICAL: 0,
        Severity.HIGH: 0,
        Severity.MEDIUM: 0,
        Severity.LOW: 0,
        Severity.INFO: 0,
    }
    for f in all_findings:
        severity_counts[f.severity] += 1

    # Summary panel
    summary_parts = [
        f"Endpoints scanned: {total_endpoints}",
        f"Total findings: {len(all_findings)}",
        f"Scan duration: {total_duration:.2f}s",
        "",
        "Severity Breakdown:",
    ]
    for severity, count in severity_counts.items():
        if count > 0:
            summary_parts.append(f"  {severity.value.upper()}: {count}")

    console.print(Panel(
        "\n".join(summary_parts),
        title="GateCheck Scan Summary",
        border_style="bold cyan",
    ))


def print_findings_table(console: Console, findings: list[Finding]) -> None:
    """Print findings in a formatted table."""
    if not findings:
        console.print("[green]No security findings detected.[/green]")
        return

    # Sort by severity
    findings.sort(key=lambda f: f.severity.numeric, reverse=True)

    table = Table(
        title="Security Findings",
        show_lines=True,
        border_style="dim",
    )
    table.add_column("#", style="dim", width=4)
    table.add_column("Severity", width=10)
    table.add_column("Title", width=35)
    table.add_column("Endpoint", width=30)
    table.add_column("Category", width=15)
    table.add_column("OWASP", width=15)

    for i, finding in enumerate(findings, 1):
        severity_text = Text(
            finding.severity.value.upper(),
            style=SEVERITY_COLORS[finding.severity],
        )
        table.add_row(
            str(i),
            severity_text,
            finding.title,
            finding.endpoint,
            finding.category,
            finding.owasp_mapping[:15] if finding.owasp_mapping else "-",
        )

    console.print(table)


def print_finding_detail(console: Console, finding: Finding, index: int) -> None:
    """Print detailed information about a single finding."""
    color = SEVERITY_COLORS[finding.severity]

    console.print(f"\n[{color}]--- Finding #{index}: {finding.title} ---[/{color}]")
    console.print(f"  [bold]Severity:[/bold] [{color}]{finding.severity.value.upper()}[/{color}]")
    console.print(f"  [bold]Category:[/bold] {finding.category}")
    console.print(f"  [bold]Endpoint:[/bold] {finding.endpoint}")
    console.print(f"  [bold]Description:[/bold] {finding.description}")

    if finding.evidence:
        console.print(f"  [bold]Evidence:[/bold] {finding.evidence}")
    if finding.recommendation:
        console.print(f"  [bold]Recommendation:[/bold] {finding.recommendation}")
    if finding.owasp_mapping:
        console.print(f"  [bold]OWASP:[/bold] {finding.owasp_mapping}")
    if finding.cwe_id:
        console.print(f"  [bold]CWE:[/bold] {finding.cwe_id}")


def print_compliance_report(console: Console, report: ComplianceReport) -> None:
    """Print OWASP API Top 10 compliance report."""
    table = Table(
        title="OWASP API Security Top 10 Compliance",
        show_lines=True,
        border_style="dim",
    )
    table.add_column("ID", width=12)
    table.add_column("Category", width=45)
    table.add_column("Status", width=10)
    table.add_column("Findings", width=10, justify="center")

    for category in report.categories:
        color = COMPLIANCE_COLORS[category.status]
        status_text = Text(category.status.value.upper(), style=color)
        table.add_row(
            category.id,
            category.name,
            status_text,
            str(len(category.findings)),
        )

    console.print(table)
    console.print(
        f"\n[bold]Overall Compliance Score:[/bold] {report.overall_score:.1f}% "
        f"({report.passing_count} pass, {report.failing_count} fail, "
        f"{report.warning_count} warn, {report.not_tested_count} not tested)"
    )

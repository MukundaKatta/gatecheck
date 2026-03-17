"""Command-line interface for GateCheck API Security Scanner."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import click
from rich.console import Console

from gatecheck.analyzer.compliance import OWASPAPIChecker
from gatecheck.analyzer.endpoint import EndpointAnalyzer
from gatecheck.analyzer.report_gen import SecurityReportGenerator
from gatecheck.models import Endpoint, HTTPMethod, ScanResult
from gatecheck.report import (
    print_compliance_report,
    print_finding_detail,
    print_findings_table,
    print_scan_summary,
)
from gatecheck.scanner.auth import AuthScanner
from gatecheck.scanner.exposure import DataExposureScanner
from gatecheck.scanner.injection import InjectionScanner

console = Console()


@click.group()
@click.version_option(version="0.1.0", prog_name="gatecheck")
def cli() -> None:
    """GateCheck - API Security Scanner.

    Scan REST APIs for authentication flaws, injection vulnerabilities,
    data exposure issues, and OWASP API Top 10 compliance.
    """
    pass


@cli.command()
@click.argument("url")
@click.option("--method", "-m", default="GET", type=click.Choice(
    ["GET", "POST", "PUT", "PATCH", "DELETE"], case_sensitive=False
), help="HTTP method to use.")
@click.option("--header", "-H", multiple=True, help="Request headers (format: Key:Value).")
@click.option("--token", "-t", help="Authentication token (Bearer).")
@click.option("--body", "-d", help="Request body as JSON string.")
@click.option("--scan-type", "-s", multiple=True, default=["all"],
              type=click.Choice(["all", "auth", "injection", "exposure"], case_sensitive=False),
              help="Types of scans to run.")
@click.option("--output", "-o", type=click.Path(), help="Save report to JSON file.")
@click.option("--timeout", default=10.0, help="Request timeout in seconds.")
@click.option("--verbose", "-v", is_flag=True, help="Show detailed findings.")
def scan(
    url: str,
    method: str,
    header: tuple[str, ...],
    token: str | None,
    body: str | None,
    scan_type: tuple[str, ...],
    output: str | None,
    timeout: float,
    verbose: bool,
) -> None:
    """Scan an API endpoint for security vulnerabilities."""
    console.print(f"[bold cyan]GateCheck API Security Scanner[/bold cyan]")
    console.print(f"Target: {url}\n")

    # Parse headers
    headers: dict[str, str] = {}
    for h in header:
        if ":" in h:
            key, value = h.split(":", 1)
            headers[key.strip()] = value.strip()

    # Parse body
    body_dict = None
    if body:
        try:
            body_dict = json.loads(body)
        except json.JSONDecodeError:
            console.print("[red]Error: Invalid JSON body.[/red]")
            sys.exit(1)

    # Build endpoint
    endpoint = Endpoint(
        url=url,
        method=HTTPMethod(method.upper()),
        headers=headers,
        body=body_dict,
        auth_token=token,
    )

    if token:
        headers["Authorization"] = f"Bearer {token}"
        endpoint.headers = headers

    endpoints = [endpoint]

    # Run scans
    scan_types = set(scan_type)
    run_all = "all" in scan_types
    results: list[ScanResult] = []

    if run_all or "auth" in scan_types:
        console.print("[dim]Running authentication scan...[/dim]")
        scanner = AuthScanner(timeout=timeout)
        try:
            results.append(scanner.scan(endpoints))
        finally:
            scanner.close()

    if run_all or "injection" in scan_types:
        console.print("[dim]Running injection scan...[/dim]")
        scanner_inj = InjectionScanner(timeout=timeout)
        try:
            results.append(scanner_inj.scan(endpoints))
        finally:
            scanner_inj.close()

    if run_all or "exposure" in scan_types:
        console.print("[dim]Running data exposure scan...[/dim]")
        scanner_exp = DataExposureScanner(timeout=timeout)
        try:
            results.append(scanner_exp.scan(endpoints))
        finally:
            scanner_exp.close()

    console.print()

    # Display results
    print_scan_summary(console, results)

    all_findings = []
    for r in results:
        all_findings.extend(r.findings)

    print_findings_table(console, all_findings)

    if verbose:
        for i, finding in enumerate(sorted(all_findings, key=lambda f: f.severity.numeric, reverse=True), 1):
            print_finding_detail(console, finding, i)

    # OWASP compliance
    checker = OWASPAPIChecker()
    compliance = checker.check(results)
    console.print()
    print_compliance_report(console, compliance)

    # Save report if requested
    if output:
        generator = SecurityReportGenerator()
        report_json = generator.generate_json(results)
        Path(output).write_text(report_json)
        console.print(f"\n[green]Report saved to {output}[/green]")


@cli.command()
@click.argument("url")
@click.option("--token", "-t", help="Authentication token.")
def profile(url: str, token: str | None) -> None:
    """Profile an API endpoint's attack surface."""
    console.print(f"[bold cyan]Endpoint Profiling[/bold cyan]")
    console.print(f"Target: {url}\n")

    headers = {}
    if token:
        headers["Authorization"] = f"Bearer {token}"

    endpoint = Endpoint(url=url, headers=headers, auth_token=token)
    analyzer = EndpointAnalyzer()
    ep_profile = analyzer.analyze([endpoint])

    console.print(f"Base URL: {ep_profile.base_url}")
    console.print(f"Total endpoints: {ep_profile.total_endpoints}")
    console.print(f"Average risk score: {ep_profile.average_risk_score}/10")

    for prof in ep_profile.endpoint_profiles:
        console.print(f"\n[bold]{prof.method} {prof.path}[/bold]")
        console.print(f"  Risk score: {prof.risk_score}/10")
        console.print(f"  Auth present: {prof.has_auth}")
        console.print(f"  Admin endpoint: {prof.is_admin_endpoint}")
        for factor in prof.risk_factors:
            console.print(f"  - {factor}")


@cli.command("owasp")
def owasp_info() -> None:
    """Display OWASP API Security Top 10 (2023) categories."""
    from gatecheck.analyzer.compliance import OWASP_API_TOP_10

    console.print("[bold cyan]OWASP API Security Top 10 - 2023 Edition[/bold cyan]\n")

    for cat in OWASP_API_TOP_10:
        console.print(f"[bold]{cat['id']}[/bold] - {cat['name']}")
        console.print(f"  {cat['description']}\n")


if __name__ == "__main__":
    cli()

# GateCheck

API Security Scanner that detects authentication flaws, injection vulnerabilities, and data exposure issues in REST APIs. Maps findings to the OWASP API Security Top 10 (2023 edition).

## Features

### Scanners
- **AuthScanner** - Tests for missing authentication, weak tokens, JWT weaknesses, Broken Object Level Authorization (BOLA), and broken function-level authorization
- **InjectionScanner** - Tests for SQL injection (classic, blind, error-based, union-based), NoSQL injection (MongoDB operator/regex/$where), and OS command injection
- **DataExposureScanner** - Checks for PII leakage (SSN, email, credit cards, phone numbers), credential exposure (API keys, passwords, AWS keys, connection strings), internal path disclosure, stack traces, and missing security headers

### Analyzers
- **EndpointAnalyzer** - Profiles API attack surface with risk scoring, identifies high-value targets, and prioritizes endpoints for scanning
- **SecurityReportGenerator** - Produces comprehensive reports with executive summaries, severity distribution, prioritized remediation recommendations, and OWASP compliance mapping
- **OWASPAPIChecker** - Maps findings to OWASP API Security Top 10 (2023), provides compliance scoring, and gap analysis

### OWASP API Security Top 10 Coverage
- API1:2023 Broken Object Level Authorization
- API2:2023 Broken Authentication
- API3:2023 Broken Object Property Level Authorization
- API4:2023 Unrestricted Resource Consumption
- API5:2023 Broken Function Level Authorization
- API6:2023 Unrestricted Access to Sensitive Business Flows
- API7:2023 Server Side Request Forgery
- API8:2023 Security Misconfiguration
- API9:2023 Improper Inventory Management
- API10:2023 Unsafe Consumption of APIs

## Installation

```bash
pip install -e .
```

## Usage

### CLI

```bash
# Full scan of an endpoint
gatecheck scan https://api.example.com/users

# Scan with authentication
gatecheck scan https://api.example.com/users -t YOUR_TOKEN

# Run specific scan types
gatecheck scan https://api.example.com/users -s auth -s injection

# Save report to file
gatecheck scan https://api.example.com/users -o report.json -v

# Profile an endpoint
gatecheck profile https://api.example.com/users/123

# View OWASP API Top 10 categories
gatecheck owasp
```

### Python API

```python
from gatecheck.models import Endpoint, HTTPMethod
from gatecheck.scanner import AuthScanner, InjectionScanner, DataExposureScanner
from gatecheck.analyzer import SecurityReportGenerator, OWASPAPIChecker

endpoint = Endpoint(
    url="https://api.example.com/users",
    method=HTTPMethod.GET,
    auth_token="your-token",
)

# Run scans
auth_result = AuthScanner().scan([endpoint])
injection_result = InjectionScanner().scan([endpoint])
exposure_result = DataExposureScanner().scan([endpoint])

# Generate report
generator = SecurityReportGenerator()
report = generator.generate([auth_result, injection_result, exposure_result])
```

## Development

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT

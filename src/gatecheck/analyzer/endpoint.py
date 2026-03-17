"""Endpoint analyzer for profiling API surface area."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlparse

from gatecheck.models import Endpoint, HTTPMethod


@dataclass
class EndpointProfile:
    """Profile information about a single endpoint."""

    url: str
    method: str
    path: str = ""
    path_segments: list[str] = field(default_factory=list)
    has_id_parameter: bool = False
    has_auth: bool = False
    is_admin_endpoint: bool = False
    accepts_body: bool = False
    query_params: list[str] = field(default_factory=list)
    risk_score: float = 0.0
    risk_factors: list[str] = field(default_factory=list)


@dataclass
class APISurfaceProfile:
    """Aggregate profile of an API's attack surface."""

    base_url: str
    total_endpoints: int = 0
    endpoint_profiles: list[EndpointProfile] = field(default_factory=list)
    unique_paths: int = 0
    methods_used: set[str] = field(default_factory=set)
    has_authentication: bool = False
    admin_endpoints: int = 0
    data_mutation_endpoints: int = 0
    average_risk_score: float = 0.0
    high_risk_endpoints: list[EndpointProfile] = field(default_factory=list)


class EndpointAnalyzer:
    """Profiles API endpoints to understand the attack surface.

    Analyzes endpoints for:
    - Path structure and parameterization
    - Authentication requirements
    - Risk scoring based on functionality
    - Identification of high-value targets
    """

    ADMIN_PATH_INDICATORS = [
        "admin", "manage", "internal", "debug", "config",
        "settings", "system", "control", "dashboard",
    ]

    SENSITIVE_PATH_INDICATORS = [
        "user", "account", "profile", "payment", "billing",
        "auth", "login", "password", "token", "key",
        "secret", "credential", "financial", "medical",
    ]

    DATA_MUTATION_METHODS = {HTTPMethod.POST, HTTPMethod.PUT, HTTPMethod.PATCH, HTTPMethod.DELETE}

    def __init__(self) -> None:
        pass

    def analyze(self, endpoints: list[Endpoint]) -> APISurfaceProfile:
        """Analyze a list of endpoints and produce an API surface profile."""
        if not endpoints:
            return APISurfaceProfile(base_url="")

        profiles: list[EndpointProfile] = []
        methods_used: set[str] = set()
        paths_seen: set[str] = set()

        for ep in endpoints:
            profile = self._profile_endpoint(ep)
            profiles.append(profile)
            methods_used.add(ep.method.value)
            paths_seen.add(profile.path)

        base_url = self._extract_base_url(endpoints[0].url)
        admin_count = sum(1 for p in profiles if p.is_admin_endpoint)
        mutation_count = sum(
            1 for ep in endpoints if ep.method in self.DATA_MUTATION_METHODS
        )
        avg_risk = sum(p.risk_score for p in profiles) / len(profiles) if profiles else 0.0
        high_risk = [p for p in profiles if p.risk_score >= 7.0]

        return APISurfaceProfile(
            base_url=base_url,
            total_endpoints=len(endpoints),
            endpoint_profiles=profiles,
            unique_paths=len(paths_seen),
            methods_used=methods_used,
            has_authentication=any(p.has_auth for p in profiles),
            admin_endpoints=admin_count,
            data_mutation_endpoints=mutation_count,
            average_risk_score=round(avg_risk, 2),
            high_risk_endpoints=high_risk,
        )

    def _profile_endpoint(self, endpoint: Endpoint) -> EndpointProfile:
        """Create a detailed profile for a single endpoint."""
        parsed = urlparse(endpoint.url)
        path = parsed.path
        segments = [s for s in path.split("/") if s]

        has_id = bool(re.search(r"/\d+(?:/|$)", path)) or bool(
            re.search(r"/[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", path, re.IGNORECASE)
        )

        has_auth = bool(
            endpoint.auth_token
            or any(
                k.lower() in ("authorization", "x-api-key", "x-auth-token")
                for k in endpoint.headers
            )
        )

        is_admin = any(
            indicator in path.lower()
            for indicator in self.ADMIN_PATH_INDICATORS
        )

        accepts_body = endpoint.method in self.DATA_MUTATION_METHODS
        query_params = list(endpoint.params.keys())

        risk_score, risk_factors = self._calculate_risk(
            endpoint, path, has_id, has_auth, is_admin, accepts_body
        )

        return EndpointProfile(
            url=endpoint.url,
            method=endpoint.method.value,
            path=path,
            path_segments=segments,
            has_id_parameter=has_id,
            has_auth=has_auth,
            is_admin_endpoint=is_admin,
            accepts_body=accepts_body,
            query_params=query_params,
            risk_score=risk_score,
            risk_factors=risk_factors,
        )

    def _calculate_risk(
        self,
        endpoint: Endpoint,
        path: str,
        has_id: bool,
        has_auth: bool,
        is_admin: bool,
        accepts_body: bool,
    ) -> tuple[float, list[str]]:
        """Calculate a risk score (0-10) for an endpoint."""
        score = 0.0
        factors: list[str] = []

        # Data mutation endpoints are higher risk
        if accepts_body:
            score += 2.0
            factors.append("Accepts data mutation")

        # ID-based endpoints risk BOLA
        if has_id:
            score += 1.5
            factors.append("Contains object ID parameter")

        # No authentication is a major risk
        if not has_auth:
            score += 3.0
            factors.append("No authentication detected")

        # Admin endpoints are high value targets
        if is_admin:
            score += 2.0
            factors.append("Administrative endpoint")

        # Sensitive data paths
        path_lower = path.lower()
        for indicator in self.SENSITIVE_PATH_INDICATORS:
            if indicator in path_lower:
                score += 1.0
                factors.append(f"Sensitive path component: {indicator}")
                break

        # HTTP (not HTTPS)
        if endpoint.url.startswith("http://"):
            score += 1.0
            factors.append("Unencrypted HTTP connection")

        return min(score, 10.0), factors

    def _extract_base_url(self, url: str) -> str:
        """Extract the base URL from a full URL."""
        parsed = urlparse(url)
        return f"{parsed.scheme}://{parsed.netloc}"

    def prioritize_for_scanning(
        self, endpoints: list[Endpoint]
    ) -> list[Endpoint]:
        """Sort endpoints by risk priority for efficient scanning."""
        profile = self.analyze(endpoints)
        scored = list(zip(profile.endpoint_profiles, endpoints))
        scored.sort(key=lambda x: x[0].risk_score, reverse=True)
        return [ep for _, ep in scored]

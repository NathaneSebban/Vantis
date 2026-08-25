"""
Cloud storage / registry misconfiguration checks.

Organizations routinely name cloud storage buckets after their own domain
(e.g. "example-com", "example", "www-example-com"). This module derives a
short list of likely bucket names from the target's domain and does a single
GET against each major provider's public listing URL — the same
well-known, read-only technique tools like cloud_enum use. It never writes,
deletes, or authenticates; a "public" verdict is reached purely from the
provider's own unauthenticated listing response.

It also checks for an exposed Docker Registry HTTP API v2 catalog on the
target's own origin, which (when reachable without auth) lists every image
repository stored on it.

Detection only — GET requests, no exploitation, no data exfiltration beyond
what the provider already serves unauthenticated to anyone who asks.
"""
from __future__ import annotations

import re

from vantis.core.plugin_base import ModuleContext, ScanModule
from vantis.core.report import Confidence, Finding, Severity
from vantis.utils.http_client import HttpClient

_NON_ALNUM_RE = re.compile(r"[^a-z0-9]+")


def candidate_bucket_names(domain: str) -> list[str]:
    """Pure: derive a short, deduplicated list of plausible bucket/container
    names from a domain, e.g. 'www.example.com' ->
    ['example', 'example-com', 'www-example-com', 'example.com']."""
    domain = domain.lower().strip(".")
    bare = domain[4:] if domain.startswith("www.") else domain
    parts = bare.split(".")
    root = parts[0] if parts else bare

    candidates = [
        root,
        _NON_ALNUM_RE.sub("-", bare).strip("-"),
        _NON_ALNUM_RE.sub("-", domain).strip("-"),
        bare,
    ]
    out: list[str] = []
    for c in candidates:
        if c and c not in out:
            out.append(c)
    return out


def classify_s3_response(status_code: int, body: str) -> str | None:
    """Pure: interpret an S3 bucket-listing response. Returns 'public',
    'private', 'missing', or None (inconclusive)."""
    if status_code == 200 and "<ListBucketResult" in body:
        return "public"
    if status_code == 403 and ("AccessDenied" in body or "<Error>" in body):
        return "private"
    if status_code == 404 and "NoSuchBucket" in body:
        return "missing"
    return None


def classify_gcs_response(status_code: int, body: str) -> str | None:
    """Pure: interpret a Google Cloud Storage bucket JSON listing response."""
    if status_code == 200 and '"kind": "storage#objects"' in body:
        return "public"
    if status_code in (401, 403):
        return "private"
    if status_code == 404:
        return "missing"
    return None


def classify_azure_response(status_code: int, body: str) -> str | None:
    """Pure: interpret an Azure Blob container listing response."""
    if status_code == 200 and "<EnumerationResults" in body:
        return "public"
    if status_code in (403, 404):
        return "private_or_missing"
    return None


class CloudMisconfigModule(ScanModule):
    name = "cloud-misconfig"
    category = "recon"
    description = "Guess and probe cloud storage buckets (S3/GCS/Azure) and check for an exposed Docker registry"

    def __init__(self, ctx: ModuleContext):
        super().__init__(ctx)
        # A dedicated client with no auth (cloud provider endpoints, unlike
        # the target, should never receive the operator's target-auth
        # headers/cookies) but the same timeout/rate-limit discipline.
        self._cloud_client = HttpClient(timeout=ctx.http_timeout, delay=ctx.rate_limit_delay)

    def run(self) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_buckets())
        findings.extend(self._check_docker_registry())
        return findings

    def _check_buckets(self) -> list[Finding]:
        findings: list[Finding] = []
        names = candidate_bucket_names(self.ctx.target.host)[:4]  # keep it fast, most-likely first

        for name in names:
            # Amazon S3
            resp = self._cloud_client.get(f"https://{name}.s3.amazonaws.com/")
            if resp is not None:
                verdict = classify_s3_response(resp.status_code, resp.text or "")
                if verdict == "public":
                    findings.append(self._bucket_finding("S3", name, f"https://{name}.s3.amazonaws.com/"))

            # Google Cloud Storage
            resp = self._cloud_client.get(f"https://storage.googleapis.com/storage/v1/b/{name}/o")
            if resp is not None:
                verdict = classify_gcs_response(resp.status_code, resp.text or "")
                if verdict == "public":
                    findings.append(self._bucket_finding("Google Cloud Storage", name,
                                                          f"https://storage.googleapis.com/{name}/"))

            # Azure Blob Storage (container listing needs the storage account
            # name; we try the domain-derived name as the account too)
            resp = self._cloud_client.get(
                f"https://{name}.blob.core.windows.net/{name}?restype=container&comp=list"
            )
            if resp is not None:
                verdict = classify_azure_response(resp.status_code, resp.text or "")
                if verdict == "public":
                    findings.append(self._bucket_finding(
                        "Azure Blob Storage", name,
                        f"https://{name}.blob.core.windows.net/{name}"
                    ))

        return findings

    def _bucket_finding(self, provider: str, name: str, url: str) -> Finding:
        return Finding(
            module=self.name, confidence=Confidence.HIGH, owasp="A05:2021", cwe="CWE-284",
            title=f"Publicly listable {provider} bucket: {name}",
            severity=Severity.HIGH,
            target=str(self.ctx.target),
            matched_at=url,
            description=(
                f"A {provider} bucket named after the target's domain answers an unauthenticated "
                "listing request, exposing every object name it contains (and, depending on ACLs, "
                "the objects themselves)."
            ),
            evidence=f"Unauthenticated listing succeeded at {url}",
            remediation=(
                f"Restrict the bucket's ACL/IAM policy so listing and object access require "
                "authentication, and audit what was exposed while it was public."
            ),
            references=["https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/10-Business_Logic_Testing/"],
        )

    def _check_docker_registry(self) -> list[Finding]:
        client = self.ctx.new_http_client()
        base = str(self.ctx.target).rstrip("/")
        resp = client.get(f"{base}/v2/_catalog")
        if resp is None or resp.status_code != 200:
            return []
        try:
            data = resp.json()
        except ValueError:
            return []
        repos = data.get("repositories") if isinstance(data, dict) else None
        if not isinstance(repos, list):
            return []

        return [Finding(
            module=self.name, confidence=Confidence.HIGH, owasp="A05:2021", cwe="CWE-284",
            title="Docker Registry catalog exposed without authentication",
            severity=Severity.HIGH,
            target=base,
            matched_at=f"{base}/v2/_catalog",
            description="The Docker Registry HTTP API v2 catalog endpoint lists every image repository "
                        "without requiring authentication, exposing internal image/service names and "
                        "(via each repo's tags/manifest) potentially the images themselves.",
            evidence=f"{len(repos)} repositor{'y' if len(repos) == 1 else 'ies'} listed, e.g. "
                     f"{', '.join(repos[:6])}",
            remediation="Require authentication on the registry (htpasswd, token auth, or a private "
                        "network) and never expose /v2/_catalog publicly.",
        )]

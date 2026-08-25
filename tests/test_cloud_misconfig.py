"""Tests for cloud storage / registry misconfiguration detection."""
import re

import responses

from vantis.core.plugin_base import ModuleContext
from vantis.core.target import Target
from vantis.modules.recon.cloud_misconfig import (
    CloudMisconfigModule,
    candidate_bucket_names,
    classify_azure_response,
    classify_gcs_response,
    classify_s3_response,
)


def test_candidate_bucket_names_derives_plausible_names():
    names = candidate_bucket_names("www.example.com")
    assert "example" in names
    assert "example-com" in names
    assert len(names) == len(set(names))  # deduplicated


def test_classify_s3_response():
    assert classify_s3_response(200, "<ListBucketResult>...") == "public"
    assert classify_s3_response(403, "<Error><Code>AccessDenied</Code></Error>") == "private"
    assert classify_s3_response(404, "<Error><Code>NoSuchBucket</Code></Error>") == "missing"
    assert classify_s3_response(200, "<html>not s3</html>") is None


def test_classify_gcs_response():
    assert classify_gcs_response(200, '{"kind": "storage#objects", "items": []}') == "public"
    assert classify_gcs_response(403, "{}") == "private"
    assert classify_gcs_response(404, "{}") == "missing"


def test_classify_azure_response():
    assert classify_azure_response(200, "<EnumerationResults>...") == "public"
    assert classify_azure_response(404, "") == "private_or_missing"


@responses.activate
def test_module_flags_public_s3_bucket():
    target = Target(raw="https://example.com")
    ctx = ModuleContext(target=target)

    responses.add(responses.GET, "https://example.s3.amazonaws.com/",
                   body="<ListBucketResult>public</ListBucketResult>", status=200)
    # Every other probe (other candidate names, GCS, Azure, registry) misses.
    responses.add(responses.GET, re.compile(r".*"), status=404)

    findings = CloudMisconfigModule(ctx).run()
    assert any(f.title.startswith("Publicly listable S3 bucket") for f in findings)


@responses.activate
def test_module_flags_exposed_docker_registry():
    target = Target(raw="https://example.com")
    ctx = ModuleContext(target=target)

    responses.add(responses.GET, "https://example.com/v2/_catalog",
                   json={"repositories": ["internal-api", "billing-service"]}, status=200)
    responses.add(responses.GET, re.compile(r".*"), status=404)

    findings = CloudMisconfigModule(ctx).run()
    docker = [f for f in findings if "Docker Registry" in f.title]
    assert len(docker) == 1
    assert "internal-api" in docker[0].evidence


@responses.activate
def test_module_reports_nothing_when_everything_is_private_or_missing():
    target = Target(raw="https://example.com")
    ctx = ModuleContext(target=target)
    responses.add(responses.GET, re.compile(r".*"), status=404)

    findings = CloudMisconfigModule(ctx).run()
    assert findings == []

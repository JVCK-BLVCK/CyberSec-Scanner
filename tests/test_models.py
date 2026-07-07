import pytest 
from pydantic import ValidationError
from app.models import ScanRequest, ScanResponse


# ___ScanRequest - Valid URLs___
# 
# pytest.mark.parametrize is one of the pytest's most powerful features, 
# allowing you to run the same test function with different sets of parameters. 
# In this case, we are testing the ScanRequest model's URL validation logic 
# with a variety of valid URLs to ensure that it accepts them without raising a ValidationError.

@pytest.mark.parametrize("url", [
    "http://example.com",
    "https://example.com",
    "http://example.com:8080",
    "https://example.com/path/to/page",
    "http://sub.example.com",
    "https://localhost",
    "http://localhost:5000",
    "https://192.168.1.1"
])

def test_valid_urls_are_accepted(url):
    """Test that valid URLs are accepted by the ScanRequest model."""
    try:
        request = ScanRequest(target_url=url)
        assert request.target_url == url
    except ValidationError:
        pytest.fail(f"ValidationError raised for valid URL: {url}")


# ─── ScanRequest — invalid URLs ──────────────────────────────────────────────
#
# pytest.raises is a context manager that EXPECTS an exception.
# If the exception is NOT raised, the test FAILS — which proves bad input
# was silently accepted, exactly the security hole we're testing against.
#
# We also assert the error MESSAGE is useful. A ValidationError with no
# actionable message is nearly as bad as no validation at all — it tells
# the API consumer nothing about how to fix their request.


@pytest.mark.parametrize("url, error_message",[
    ("not_a_url", "URL must include scheme (e.g. https:// or http:// )  and domain"),
    ("",          "URL must include scheme (e.g. https:// or http:// )  and domain"),
    ("ftp://example.com", "URL scheme must be http or https"),
    ("javascript://evil.com", "URL scheme must be http or https"),
    ("//example.com", "URL must include scheme (e.g. https:// or http:// )  and domain"),
    ("http://", "URL must include scheme (e.g. https:// or http:// )  and domain")

])

def test_invalid_urls_are_rejected(url, error_message):
    """Test that invalid URLs are rejected by the ScanRequest model."""
    """This test ensures that bad input cannot reach the scanner logic, 
    which is crucial for preventing errors and potential security issues. 
    By validating the URL format at the model level, we can catch issues early and provide clear feedback to API consumers."""
    with pytest.raises(ValidationError) as exc_info:
        ScanRequest(target_url=url)

        # We also verify the error MESSAGE is helpful - ValidationError
        # With no useful message is nearly as bad as no validation at all, because it doesn't 
        # guide the user on how to fix their input. By asserting that the error message contains 
        # specific text, we ensure that our validation logic provides actionable feedback to users, 
        # which is essential for a good developer experience when using our API. 
        # This also helps catch cases where the validation might be failing for the wrong 
        # reason or not providing enough information about what went wrong.
    assert error_message in str(exc_info.value)


# ___ScanResponse - Structure and Optional Fields___
# ScanResponse is the data contract between storage and every client.
# Pydantic enforces the contract at construction time — these tests
# confirm the contract is what we think it is.

def test_scan_response_requires_scan_id_and_status():
    """ScanResponse Must fail if required fields are missing."""
    with pytest.raises(ValidationError):
        ScanResponse()  # pyright: ignore[reportCallIssue] # Missing both scan_id and status


def test_scan_response_results_defaults_to_none():
    """ScanResponse should allow results to be optional and default to None."""
    # Omitting it should not raise an error, and results should be None by default
    response = ScanResponse(scan_id="test-scan-123", status="in_progress")
    assert response.results is None


def test_scan_response_accepts_empty_results_list():
    """ScanResponse should accept an empty list for results."""
    """Any empty list is valid - it means the scan found nothing, which is a perfectly valid outcome. 
    By allowing an empty list, we can represent the case where a scan completed successfully but did not 
    find any vulnerabilities or issues. This is important for accurately reflecting the results of a scan 
    and avoiding confusion for API consumers who might expect results to always be present."""
    response = ScanResponse(scan_id="test-scan-123", status="completed", results=[])
    assert response.results == []


def test_scan_response_accepts_findings():
    """ScanResponse should accept a list of findings in the results field."""
    """results must accept a list of dicts - real Nuclei findings"""
    findings = [
        {
            "template_id": "CVE-2021-44228",
            "severity": "critical",},
        {
            "template_id": "CVE-2020-1472",
            "severity": "high",},
    ]
    response = ScanResponse(scan_id="test-scan-123", status="completed", results=findings)
    assert len(response.results) == 2 # type: ignore
    assert response.results[0]["severity"] == "critical" # type: ignore


def test_scan_response_valid_statuses():
    """ScanResponse should accept valid status values."""
    """Verify all expected status strings are accepted - this ensures our model can represent all the states our application uses to track scan progress and outcomes. By testing each valid status, we confirm that our model is flexible enough to handle the different scenarios that can occur during a scan's lifecycle, such as in_progress, completed, and failed. This is crucial for accurately representing the state of a scan and providing meaningful feedback to API consumers."""
    for status in ["in_progress", "completed", "failed"]:
        response = ScanResponse(scan_id="test-scan-123", status=status)
        assert response.status == status


def test_scan_response_error_defaults_to_none():
    """error is Optional — successful and in-progress scans have no error.
    Must default to None without being specified."""
    response = ScanResponse(scan_id="test-123", status="completed")
    assert response.error is None
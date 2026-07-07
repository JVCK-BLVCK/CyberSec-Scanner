from fastapi import responses
import pytest
from unittest.mock import Mock, patch, MagicMock
import asyncio
from app.storage import save_scan, load_scan
from fastapi.testclient import TestClient
from pathlib import Path
from app.rate_limiter import limiter
from app.main import app
from slowapi.errors import RateLimitExceeded


# ___Health_Checking___
def test_health_check_returns_200():
    """
        Health check must work without authentication.
    """
    from app.main import app
    with TestClient(app) as unauth_client:
        response = unauth_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"

def test_health_check_not_rate_limited(with_rate_limiting):
    """
        Orchestrators poll frequently - health check must never 429.
    """
    from app.main import app
    with TestClient(app) as client:
        responses = [client.get("/health").status_code for _ in range(20)]
    assert 429 not in responses
    

# ___Rate Limiting___

# We need to confirm that the rate limiting mechanism is working correctly and that clients receive the 
# appropriate response when they exceed the defined limits.
# This involves sending multiple requests to the /scan endpoint in quick succession and verifying that after a 
# certain number of requests (defined in rate_limiter.py), the API returns a 429 Too Many Requests status code.

def test_post_scan_rate_limit_returns_429(client, with_rate_limiting):
    """
    When a client exceeds the defined rate limits for the /scan endpoint, the API should return a 429 Too Many Requests status code.
    This ensures that the rate limiting mechanism is working correctly and that clients are aware when they have made too many requests.
    
    """
    responses = []
    for _ in range(15):
        response = client.post("/scan", json={"target_url": "https://example.com"})
        responses.append(response.status_code)

    assert 429 in responses, f"Expected a 429 Too Many Requests status code after exceeding rate limits, but got: {responses}"
    
def test_get_scan_rate_limit_returns_429(client, patched_scan_dir, with_rate_limiting):
    """When a client exceeds the defined rate limits for the GET /scan/{scan_id} endpoint, the API should return a 429 Too Many Requests status code.
    This ensures that the rate limiting mechanism is working correctly for all endpoints and that clients are aware when they have made too many requests."""
    # Seed the scan directory with a valid scan so we get 200s before we hit the rate limit, not 404s which would indicate a different issue with the API.
   
    asyncio.run(save_scan("rate-limit-scan", {
        "scan_id": "rate-limit-scan",
        "target_url": "https://example.com",
        "status": "completed",
        "timestamp": "2024-01-01T00:00:00Z",
        "error": None,
        "results": []
    }))

    responses = []
    for _ in range(70):
        response = client.get("/scan/rate-limit-scan")
        responses.append(response.status_code)

    assert 429 in responses, f"Expected a 429 Too Many Requests status code after exceeding rate limits, but got: {responses}"


def test_post_scan_without_api_key_returns_401():
    """When a POST request is made to /scan without an API key, the API should return a 401 Unauthorized status code.
    This ensures that the authentication mechanism is working correctly and that unauthorized requests are rejected."""
    
    # Fresh Client with no headers - deliberately unauthenticated to test 401 response
    with TestClient(app) as unauth_client:
        response = unauth_client.post(
        "/scan", 
        json={"target_url": "https://example.com"}
        )

    assert response.status_code == 401
    


def test_get_scan_without_api_key_returns_401():
    """When a GET request is made to /scan/{scan_id} without an API key, the API should return a 401 Unauthorized status code.
    This ensures that the authentication mechanism is working correctly and that unauthorized requests are rejected."""
    from app.main import app
    # Fresh Client with no headers - deliberately unauthenticated to test 401 response
    with TestClient(app) as unauth_client:
        response = unauth_client.get("/scan/any-scan-id")

    assert response.status_code == 401

def test_post_scan_with_wrong_api_key_returns_401():
    """When a POST request is made to /scan with an incorrect API key, the API should return a 401 Unauthorized status code.
    This ensures that the authentication mechanism is working correctly and that requests with invalid credentials are rejected."""
    from app.main import app
    # Fresh Client with wrong API key in headers to test 401 response
    with TestClient(app, headers={"X-API-KEY": "wrong-api-key"}) as wrong_key_client:
        response = wrong_key_client.post(
        "/scan", 
        json={"target_url": "https://example.com"}
        )

    assert response.status_code == 401
    

def test_get_scan_with_correct_api_key_returns_202():
    """When a POST request is made to /scan with the correct API key, the API should return a 202 Accepted status code.
    This confirms that the authentication mechanism allows valid requests to proceed and that the API is functioning as expected for authorized users."""
    from app.main import app
    # Fresh Client with correct API key in headers to test successful request
    with TestClient(app, headers={"X-API-KEY": "test-api-key-12345"}) as auth_client:
        response = auth_client.post(
        "/scan", 
        json={"target_url": "https://example.com"}
        )

    assert response.status_code == 202


# ___POST /scan -Scan creation____
# 
# The creation endpoint has three responsibilities:
# 1. Reject invalid URLs before they reach the scanner.
# 2. Return a scan_id the client can use to poll for results.
# 3. Trigger the scan asynchronously, allowing the client to check back 
#    for results without waiting for the scan to complete.
# 
# We mock run_nuclei in every POST test because we are testing the API's
# behavior, not the scanner's functionality. This allows us to focus on
# the API's response to various inputs without relying on the actual scanning 
# process, which can be time-consuming and is outside the scope of these tests.

@pytest.mark.parametrize("url", [
    "http://example.com",  # Valid URL
    "https://example.com",  # Valid URL
    "https://example.com:8080",  # Valid URL with port
    "https://sub.example.com/patch",  # Valid URL with path
    "http://192.168.1.1",  # Valid IP address
    "http://localhost:5000",  # Valid localhost URL
    "http://example.com?query=param",  # Valid URL with query parameters
    "http://example.com#fragment",  # Valid URL with fragment
    "http://example.com/path/to/resource?query=param#fragment",  # Valid URL with path, query, and fragment
    
])

def test_post_scan_valid_url_returns_202(client, url):
    """Every valid URL must be accepted with 202 Accepted - not 200 OK, 
    because the scan is processed asynchronously."""
    with patch("app.main.run_nuclei"):
        response = client.post("/scan", json={"target_url": url})

    assert response.status_code == 202 
 
def test_post_scan_returns_scan_id(client):
    """Every scan creation must return a unique scan_id that the 
    client can use to poll for results."""
    with patch("app.main.run_nuclei"):
        response = client.post("/scan", json={"target_url": "https://example.com"})

    data = response.json()
    assert "scan_id" in data
    assert data["scan_id"] is not None
    assert len(data["scan_id"]) > 0


def test_post_scan_returns_in_progress_status(client):
    """When a scan is created, the API should return a status indicating 
    that the scan is in progress.
    Initial status should be 'in_progress' because the scan is triggered asynchronously. 
    This means the scan runs in the background so 'completed' is never valid at creation time."""
    with patch("app.main.run_nuclei"):
        response = client.post("/scan", json={"target_url": "https://example.com"})

    assert response.json()["status"] == "in_progress"


def test_post_scan_id_is_unique_per_request(client):
    """Each scan creation should generate a unique scan_id, even if the same URL is scanned multiple times.
    Duplicate scan_ids would cause scans to overwrite each other's results."""
    with patch("app.main.run_nuclei"):
        response_a = client.post("/scan", json={"target_url": "https://example.com"})
        response_b = client.post("/scan", json={"target_url": "https://example.com"})
    
    assert response_a.json()["scan_id"] != response_b.json()["scan_id"]


def test_post_scan_saves_initial_states(client, patched_scan_dir):
    """When a scan is created, the API should save the initial state of the scan in the expected directory structure.
    This ensures that the scan's progress can be tracked and results can be stored properly.
    or After POST /scan, the scan must be immediately retrievable via GET /scan/{scan_id}.
    If the initial save fails, the client's first poll returns 404 - not found, which is a poor user experience, 
    that's confusing, and indicates a bug in the API."""
    with patch("app.main.run_nuclei"):
        post_response = client.post("/scan", json={"target_url": "https://example.com"})

    scan_id = post_response.json()["scan_id"]

    # The scan file must exist on disk immediately after creation, even if the scan is still in progress.
    scan_file = patched_scan_dir / f"{scan_id}.jsonl"
    assert scan_file.exists(), "Scan file should exist immediately after POST /scan even if the scan is still in progress. "
    "If the file doesn't exist, the client won't be able to poll for results, which is a critical bug in the API."


# ___POST /scan - Invalid URLs ___
# 
# FastAPI surfaces Pydantc validation errors as 422 unprocessable entity responses. 
# This means that if the target_url fails validation, the API should return a 422 status code with details 
# about the validation error. This is important for clients to understand why their request was rejected and
# how to fix it.
# This is the HTTP-level proof that bad input never reaches the scanner, 
# which is critical for preventing errors and ensuring the stability of the API.
# We already proved the validator works at the model level in test_models.py, 
# so here we are just confirming that the API correctly returns a 422 status code for invalid URLs.


@pytest.mark.parametrize("url", [
    "invalid-url",  # Invalid URL
    "",  # Empty URL
    "http:/example.com",  # Invalid URL (missing slash)
    "http://",  # Invalid URL (missing host)
    "://example.com",  # Invalid URL (missing scheme)
    "http://example .com",  # Invalid URL (space in domain)
    "javascript://evil.com",  # Invalid URL with unsupported scheme
])

def test_post_scan_invalid_url_returns_422(client, url):
    """When an invalid URL is submitted to the scan creation endpoint, the API should reject it with a 422 Unprocessable Entity status code.
    This ensures that bad input is caught early and doesn't cause errors in the scanner.
    A 500 error would mean the invalid input reached the scanner, which is a critical bug.
    A 422 error is the correct response, indicating that the input was understood but failed validation."""
    response = client.post("/scan", json={"target_url": url})
    assert response.status_code == 422
    

def test_post_scan_missing_body_returns_422(client):
    """When a POST request is made to /scan without a JSON body, the API should return a 422 Unprocessable Entity status code.
    This ensures that the client is aware that the request was malformed and that the required data was not provided."""
    response = client.post("/scan")
    assert response.status_code == 422


def test_post_scan_empty_body_returns_422(client):
    """When a POST request is made to /scan with an empty JSON body, the API should return a 422 Unprocessable Entity status code.
    This ensures that the client is aware that the required data was not provided, even if the request was technically well-formed."""
    response = client.post("/scan", json={})
    assert response.status_code == 422


def test_post_scan_422_contains_error_details(client):
    """When a POST request is made to /scan with invalid input, the API should return a 422 Unprocessable Entity status code with details about the validation error.
    This helps clients understand why their request was rejected and how to fix it."""
    response = client.post("/scan", json={"target_url": "invalid-url"})
    assert response.status_code == 422
    data = response.json()
    assert "detail" in data
    assert isinstance(data["detail"], list)
    assert len(data["detail"]) > 0


# ___GET /scan/{scan_id} - Scan retrieval___
# 
# The retrieval endpoint has three responsibilities:
# 1. Return the current status of the scan (e.g., in_progress, completed, failed).
# 2. Return the scan results if the scan is completed.
# 3. Handle cases where the scan_id does not exist or is invalid.
# 
# The responses shape must match ScanResponse, 
# which means it must always include the scan_id, target, status, and results fields,
# even if some of those fields are null or empty depending on the scan's state.

def test_get_scan_returns_in_progress_status_immediately_after_post(client):
    """After a scan is created with POST /scan, a GET request to /scan/{scan_id} should return a status of 'in_progress' immediately, 
    even if the scan has not completed yet. This confirms that the scan is being processed asynchronously and that the API is correctly
    tracking the scan's progress from the moment it is created.
    A return of 'completed' at this stage would indicate a bug, as the scan cannot be completed immediately after creation."""
    with patch("app.main.run_nuclei"):
        post_response = client.post("/scan", json={"target_url": "https://example.com"})

    print(post_response.json())

    scan_id = post_response.json()["scan_id"]
    get_response = client.get(f"/scan/{scan_id}")

    assert get_response.status_code == 200
    assert get_response.json()["status"] == "in_progress"


def test_get_scan_returns_correct_scan_id_and_target_url(client):
    """When a scan is created and then retrieved, the GET /scan/{scan_id} response should include the correct scan_id 
    and target_url that were provided in the POST request. This ensures that the API is correctly associating the scan_id with
    the target URL and that clients can trust the information returned by the GET endpoint."""
    with patch("app.main.run_nuclei"):
        post_response = client.post("/scan", json={"target_url": "https://example.com"})

    print(post_response.json())

    scan_id = post_response.json()["scan_id"]
    get_response = client.get(f"/scan/{scan_id}")

    assert get_response.json()["scan_id"] == scan_id
    assert get_response.json()["target"] == "https://example.com"


def test_get_scan_nonexistent_returns_404(client):
    """When a GET request is made to /scan/{scan_id} with a scan_id that does not exist, the API should return a 404 Not Found status code.
    Not 500, because a 500 error would mean load_scan raised an exception instead of returning None for a missing scan, which is a critical bug in the API.
    This ensures that clients are aware that the requested resource does not exist and prevents confusion about the scan's status."""
    response = client.get("/scan/nonexistent-scan-id")
    assert response.status_code == 404


def test_get_scan_404_contains_error_messages(client):
    """The 404 response must contain a human-readable error message in the response body, 
    so clients can understand why their request failed and how to fix it."""
    response = client.get("/scan/nonexistent-scan-id")
    assert response.status_code == 404
    data = response.json()
    assert "detail" in data
    assert "not found" in data["detail"].lower()
    assert len(data["detail"]) > 0


def test_get_scan_response_shape(client):
    """The GET /scan/{scan_id} response must always include the fields defined in the ScanResponse model, 
    even if some of those fields are null or empty depending on the scan's state. 
    This ensures that clients can reliably parse the response and that the API adheres to its defined contract.
    Those are the fields every client depends on to track scan lifecycle and display results, 
    so missing fields would be a critical bug in the API."""
    with patch("app.main.run_nuclei"):
        post_response = client.post("/scan", json={"target_url": "https://example.com"})

    scan_id = post_response.json()["scan_id"]
    get_response = client.get(f"/scan/{scan_id}")

    data = get_response.json()
    assert "scan_id" in data
    assert "target" in data
    assert "status" in data
    assert "results" in data


# ___Completed scan retrieval___
# 
# To test the retrieval of completed scans, we need to simulate the completion of a scan.
# We can achieve this by mocking the run_nuclei function to immediately write a completed
# scan file with results to the expected location.
# This allows us to test the GET /scan/{scan_id} endpoint's behavior when a scan is completed,
# including returning the correct status and results, without having to wait for an actual scan to run

async def test_get_completed_scan_returns_results(client, patched_scan_dir):
    """When a scan is completed, a GET request to /scan/{scan_id} should return a status of 'completed' and include the scan results.
    This confirms that the API correctly updates the scan's status and returns the expected data when a scan is finished."""

    from app.storage import save_scan

    # Create a completed scan file with results
    completed_scan = {
        "scan_id": "completed-scan-001",
        "target_url": "https://example.com",
        "status": "completed",
        "timestamp": "2024-01-01T00:00:00Z",
        "error": None,
        "results": [
            {"template_id": "CVE-2024-1234", 
             "severity": "high",
             "host": "https://example.com",
             "info": "Example vulnerability found"
             }
        ]
    }

    await save_scan("completed-scan-001", completed_scan)

    response = client.get("/scan/completed-scan-001")
    data = response.json()

    assert data["status"] == "completed"
    assert data["results"] is not None
    assert len(data["results"]) == 1
    assert data["results"][0]["severity"] == "high"


async def test_get_failed_scan_returns_error_message(client, patched_scan_dir):
    """When a scan fails, a GET request to /scan/{scan_id} should return a status of 'failed' and include an error message.
    This confirms that the API correctly updates the scan's status and provides useful information about the failure."""
    from app.storage import save_scan

    # Create a failed scan file with an error message
    failed_scan = {
        "scan_id": "failed-scan-001",
        "target_url": "https://example.com",
        "status": "failed",
        "timestamp": "2024-01-01T00:00:00Z",
        "error": "Example error message",
        "results": []
    }

    await save_scan("failed-scan-001", failed_scan)

    response = client.get("/scan/failed-scan-001")
    data = response.json()

    assert data["status"] == "failed"
    assert data["error"] == "Example error message"
    assert data["results"] == []



# ___Concurrent scan Isolation___
# 
# This is the most important API-Level test.
# We need to confirm that when multiple scans are created concurrently, their data is correctly 
# isolated and does not interfere with each other.
# This means that each scan_id should correspond to its own unique scan file, and the results
# We simulate concurrent scan creation by rapidly sending multiple POST requests to /scan and then
# verifying that each scan_id is unique and that the corresponding scan files contain the correct data.
# 
# This test ensures that the API can handle multiple scans at the same time without data
# corruption or interference, which is critical for real-world usage where multiple 
# clients may be using the API simultaneously.
# 
# This is the API-level proof of the storage isolation we tested in the test_storage.py -
# but now we prove it through the full HTTP stack, which confirms that the entire 
# API correctly handles concurrent scans without interference, 
# which is essential for the stability and reliability of the service.

def test_concurrent_scans_are_isolated(client, patched_scan_dir):
    """When multiple scans are created concurrently, each scan should have its own unique scan_id and corresponding scan file, 
    and the data for each scan should be correctly isolated without interference. This confirms that the API can handle concurrent scans 
    without data corruption or mix-ups, which is critical for real-world usage."""
    with patch("app.main.run_nuclei"):
        response_a = client.post("/scan", json={"target_url": "https://example.com"})
        response_b = client.post("/scan", json={"target_url": "https://example.com"})
    

    scan_id_a = response_a.json()["scan_id"]
    scan_id_b = response_b.json()["scan_id"]

    # Each scan_id should be unique and Know about itself
    data_a = client.get(f"/scan/{scan_id_a}").json()
    data_b = client.get(f"/scan/{scan_id_b}").json()


    assert data_a["scan_id"] == scan_id_a
    assert data_b["scan_id"] == scan_id_b
    assert data_a["target"] == "https://example.com"
    assert data_b["target"] == "https://example.com"

    """Each scan_id should be unique, but got duplicate scan_ids, 
    which indicates a critical bug in the API that would cause scan data to overwrite each other."""
    
    assert data_a["scan_id"] != data_b["scan_id"] 


def test_polling_wrong_id_after_scan_created(client):
    """After creating a scan, if the client polls with a wrong scan_id, the API should return a 404 Not Found status code.
    This ensures that clients are aware that they are requesting a non-existent resource and prevents confusion about the scan's status."""
    with patch("app.main.run_nuclei"):
        response = client.post("/scan", json={"target_url": "https://example.com"})

    scan_id = response.json()["scan_id"]
    wrong_scan_id = "wrong-" + scan_id
    
    response = client.get(f"/scan/{wrong_scan_id}")

    assert response.status_code == 404
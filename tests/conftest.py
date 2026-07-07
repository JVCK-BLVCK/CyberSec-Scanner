"""
Test configuration and fixtures for CyberS MVP.
 
Fixture design principles:
  - autouse fixtures apply globally so individual tests stay focused on assertions
  - patched_scan_dir isolates every file operation to a temp directory
  - prevent_real_nuclei_execution patches run_nuclei DIRECTLY (not asyncio.to_thread)
    so that asyncio.to_thread remains functional for save_scan's own use
"""

import asyncio
import os
import json
import pytest 
from pathlib import Path
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

# Set a test API key in the evironment variable before any tests run, 
# so that the authentication dependency can retrieve it during tests.
# This ensures that the auth mechanism is tested with a known valid key 
# and that tests don't fail due to missing configuration.

os.environ["SCANNER_API_KEY"] = "test-api-key-12345" 

# ─── Nuclei execution prevention ─────────────────────────────────────────────
#
# CRITICAL: patch run_nuclei directly, NOT asyncio.to_thread.
#
# asyncio is a singleton module — every Python module shares the exact same
# asyncio object. Patching app.mcp_server.asyncio.to_thread patches it globally,
# which means save_scan's call to asyncio.to_thread(save_scan_sync, ...) also
# gets silently replaced with a no-op. Result: scan files are never written,
# load_scan returns None for everything, every test that saves data fails with
# "TypeError: 'NoneType' object is not subscriptable".
#
# Patching run_nuclei directly is the precise intervention:
#   - asyncio.to_thread is untouched — save_scan works correctly
#   - run_nuclei is a no-op mock — no real Nuclei execution
#   - asyncio.create_task in mcp_server receives a thread coroutine wrapping
#     the mock, schedules it, mock runs synchronously, completes cleanly
#     — no "coroutine never awaited" warning


@pytest.fixture(autouse=True)
def prevent_real_nuclei_execution():
    """
    Patches run_nuclei in both app.main and app.mcp_server.

    """
    with patch("app.main.run_nuclei"), \
         patch("app.mcp_server.run_nuclei"):
        yield


# ___Background task cleanup___

@pytest.fixture(autouse=True)
def clear_background_tasks():
    """
        Clear the task registry after each test.
        Prevent task state from leaking between tests, which would cause shutdown tests to see
        tasks from previous tests still registered.
    """
    yield
    from app.tasks import _background_tasks
    _background_tasks.clear()


# ___Rate limter isolation___

@pytest.fixture(autouse=True)
def reset_rate_limiter():
    """
    Disable rate limiting for test by default.
    
    All tests share the same client IP so without this,
    10 POST requests anywhere in the suite exhausts 
    the limit and all subsequent POSTs get 429s, which is not what we want for most tests.

    Rate imit tests explicitly re-enable  via with_rate_limiting fixture.

    """
    from app.rate_limiter import limiter
    limiter.enabled = False 
    yield
    limiter.enabled = True 


@pytest.fixture
def with_rate_limiting():
    """
    Explicitly enable rate limiting for tests that need to verify it, 
    since it's disabled by default for most tests by the reset_rate_limiter fixture.
    Usage: Add with_rate_limiting as a parameter to any test that needs to verify rate limiting behavior,
    and it will enable the limiter for the duration of that test, 
    allowing you to test that 429 responses are returned when limits are exceeded.

    used only by rate limit specific tests.

    """
    from app.rate_limiter import limiter
    limiter.enabled = True
    yield 
    limiter.enabled = False


# ___Storage isolation___

@pytest.fixture
def temp_scan_dir(tmp_path):
    """Fixture to create a temporary scans directory for testing."""
    scan_dir = tmp_path / "scans"
    scan_dir.mkdir()
    return scan_dir


@pytest.fixture
def patched_scan_dir(temp_scan_dir, monkeypatch):
    """Fixture to patch the SCAN_DIR in storage module to use the temporary directory."""
    """Redirects storage.SCAN_DIR to the temporary directory created by temp_scan_dir fixture, 
    ensuring that all file operations during tests are isolated and do not affect the real filesystem."""
    import app.storage as storage
    monkeypatch.setattr(storage, "SCAN_DIR", temp_scan_dir)
    return temp_scan_dir


@pytest.fixture
def mock_nuclei_success():
    """Fixture to mock subprocess.run() for a successful Nuclei scan."""
    # This is the finding Nuclei would write to the output file
    sample_finding = {
        "template_id": "CVE-2021-44228",
        "name": "Log4Shell RCE",
        "severity": "critical",
        "host": "https://vulnerable.com",
        "matched_at": "https://vulnerable.com/api/login"
        }
    
    with patch("app.scanner.subprocess.run") as mock_run:
        # Mock the behavior of subprocess.run() to write the sample finding to the expected output file
        # Make subprocess.run return a successful mock result.
        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stderr = ""
        mock_run.return_value = mock_result

        # patch the file reading in scanner to simulate output 
        # We patch path.exists to return True and built-in open to return our sample finding as file content
        with patch("app.scanner.Path.exists", return_value=True):
            with patch("builtins.open", create=True) as mock_open:
                # Simulate the content of the output file as a JSONL line with our sample finding
                mock_open.return_value.__enter__.return_value = [json.dumps(sample_finding) + "\n"]
                yield {
                    "sample_finding": sample_finding,
                    "mock_run": mock_run,
                    "mock_open": mock_open
                }


@pytest.fixture
def mock_nuclei_timeout():
    """Fixture to mock subprocess.run() for a Nuclei scan that times out."""
    import subprocess
    with patch("app.scanner.subprocess.run") as mock_run:
        # Simulate a timeout by having subprocess.run raise a TimeoutExpired exception
        mock_run.side_effect = subprocess.TimeoutExpired(cmd="nuclei", timeout=300)
        yield mock_run


# ___HTTP test client___

@pytest.fixture
def client(patched_scan_dir):
    """
    Provides a TetClient wired to an Isolated storage directory and auth headers.
    patched_scan_dir ensures every HTTP request that touches storage
    writes to the temp directory, not the real filesystem.
    """
    from app.main import app
    with TestClient(
        app,
        headers={"X-API-KEY": "test-api-key-12345"}
    ) as test_client:
        yield test_client
    

# ___Sample data fixtures___

@pytest.fixture
def sample_scan_data():
    """Returns a dictionary with sample scan metadata and results that can be used in tests to verify correct handling of scan data."""
    return {
        "scan_id": "test-scan-123",
        "target": "https://example.com",
        "status": "completed",
        "timestamp": "2024-01-01T12:00:00Z",
        "error": None,
        "results": [
            {
                "template_id": "CVE-2021-44228",
                "name": "Log4Shell RCE",
                "severity": "critical",
                "host": "https://example.com",
                "matched_at": "https://example.com/api/login"
            },
            {
                "template_id": "CVE-2020-1472",
                "name": "Log4Shell RCE",
                "severity": "critical",
                "host": "https://example.com",
                "matched_at": "https://example.com/api/login"
            }
        ]
    }


@pytest.fixture
def sample_empty_scan_data():
    """Returns a valid completed scan with zero findings - a common real world 
    scenario that we need to ensure is handled correctly."""
    return {
        "scan_id": "test-scan-empty-456",
        "target": "https://example.com",
        "status": "completed",
        "timestamp": "2024-01-01T12:00:00Z",
        "error": None,
        "results": []
    }


@pytest.fixture
def sample_failed_scan_data():
    """Returns a dictionary with sample scan metadata indicating a failed scan, useful for testing error handling and status reporting."""
    return {
        "scan_id": "test-scan-failed-789",
        "target": "https://example.com",
        "status": "failed",
        "timestamp": "2024-01-01T12:00:00Z",
        "error": "Nuclei scan timed out after 5 minutes",
        "results": []
    }



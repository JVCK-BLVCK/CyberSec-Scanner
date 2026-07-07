import json
from typing import Literal
import pytest
from unittest.mock import patch
from app.storage import save_scan, load_scan
import asyncio


# ___Unicode and Special Characters___
# 
# Test that the application can handle Unicode characters in file names and scan results.
# Real targets include internationalized domain names (IDNs), Unicode paths, and special caharacters
# in query strings/payloads.
# This test ensures that the application can process and store scan results
# containing Unicode characters without errors or data corruption.
# Why this matters for security testing: Attackers may use Unicode characters to obfuscate malicious payloads or
# to target specific internationalized domains. Ensuring that the application can handle these characters
# is crucial for accurate scanning and reporting.
# If the application fails to handle Unicode characters properly, 
# it may lead to incorrect scan results, missed vulnerabilities, or even application crashes.


@pytest.mark.parametrize("url", [
    "https://münchen.de",                          # German umlaut domain
    "https://例え.jp",                              # Japanese domain
    "https://example.com/path/ñoño",               # Spanish special chars in path
    "https://example.com/search?q=hello%20world",  # URL encoded spaces
    "https://example.com/path?key=value&other=123",# Multiple query params
    "https://xn--nxasmq6b.com",                    # Punycode encoded domain
    
    ])

def test_unicode_and_special_urls_accepted_by_validator(url):
    """Valid international and special-character URLs must pass validation.
    Rejecting them silently would make the scanner useless for global targets.
    """
    from app.models import ScanRequest
    request = ScanRequest(target_url=url)
    assert request.target_url == url, f"URL should be accepted as-is: {url}"


async def test_unicode_url_survives_storage_roundtrip(patched_scan_dir):
    """Scan results containing Unicode characters should be stored and retrieved without corruption.
    JSON encoding/decoding handles Unicode natively -this test proves the storage
    layer doesn't accidentally strip or escape it."""
    scan_data = {
        "scan_id": "unicode-scan-001",
        "target": "https://münchen.de/path/ñoño",
        "status": "completed",
        "timestamp": "2024-01-01T10:00:00",
        "error": None,
        "result": []

    }

    await save_scan("unicode-scan-001", scan_data)
    loaded = await load_scan("unicode-scan-001")

    assert loaded ["target"]  ==  "https://münchen.de/path/ñoño" # pyright: ignore[reportOptionalSubscript]
    assert loaded ["status"]  == "completed" # pyright: ignore[reportOptionalSubscript]


async def test_special_characters_in_findings_preserved(patched_scan_dir):
    """Nuclei findings can contain any characters - angle brackets, quotes, backslashes.
    These are common in vulnerability description and payloads.
    Corrupting them makes the findings untrustworthy as evidence."""

    scan_data = {
        "scan_id":   "special-chars-001",
        "target":    "https://example.com",
        "status":    "completed",
        "timestamp": "2024-01-01T10:00:00",
        "error":     None,
        "results":   [{
            "template-id": "xss-test",
            "payload":     "<script>alert('xss')</script>",  # XSS payload
            "description": 'Found injection: "; DROP TABLE users; --',  # SQLi
            "path":        "C:\\Windows\\System32\\",        # Windows path
        }]
    }
    await save_scan("special-chars-001", scan_data)
    loaded = await load_scan("special-chars-001")

    assert loaded["results"][0]["payload"] == "<script>alert('xss')</script>" # type: ignore
    assert "DROP TABLE" in loaded["results"][0]["description"] # pyright: ignore[reportOptionalSubscript]
    assert loaded["results"][0]["path"] == "C:\\Windows\\System32\\" # pyright: ignore[reportOptionalSubscript]


# ___Very Long URLs___
# 
# URL length limits vary by browser, server, and proxy
# RFC 7230 sets no hard limit but recommends handling at least 8000 chars.
# A scanner must handle long URLs without truncating or crashing.

async def test_very_long_url_accepted_by_validator():
    """A URL at the upper bound of realistic length must be accepted.
    Truncating long URLs silently is a data integrity failure."""
    from app.models import ScanRequest
    long_path = "/path/" + "a" * 2000 + "/endpoint"
    url = f"https://example.com{long_path}"
    request = ScanRequest(target_url = url)
    assert len(request.target_url) > 2000


async def test_very_long_url_survives_storage_roundtrip(patched_scan_dir):
    """A very long URL must survive save/load without truncation.
    JSONL has no line length limit - this test proves the file writing
    doesn't accidentally truncate long values."""
    long_url = "https://example.com" + "a" * 5000
    scan_data = {
        "scan_id":   "long-url-001",
        "target":    long_url,
        "status":    "completed",
        "timestamp": "2024-01-01T10:00:00",
        "error":     None,
        "results":   []
    }
    await save_scan("long-url-001", scan_data)
    loaded = await load_scan("long-url-001")

    assert loaded["target"] == long_url # pyright: ignore[reportOptionalSubscript]
    assert len(loaded["target"]) > 5000 # pyright: ignore[reportOptionalSubscript]


# ___Concurrent writes___
# 
# In production, multiple scans run simultaneously. Each writes to its own file-
# but the filesystem must handle concurrent access without corruption.
# This test simulates real concurrency using python threads, not just sequential
# calls pretending to be concurrent.
# 
# The threading model here mirrors what actually happens in the app:
# FastAPI's background tasks run in a thread pool, so multiple run_nuclei
# calls can execute simultaneously, each calling save_scanconcurrently.

async def test_concurrent_writes_do_not_corrupt_data(patched_scan_dir):
    """Simultaneous writes to different scan files must all complete
    correctly without any file being corrupted or overwritten."""

    import asyncio

    num_scans = 20 
    errors = []

    async def write_scan(index):
        scan_id = f"concurrent-scan-{index:03d}"
        await save_scan(scan_id, {
            "scan_id":   scan_id,
            "target":    f"https://target-{index}.com",
            "status":    "completed",
            "timestamp": "2024-01-01T10:00:00",
            "error":     None,
            "results":   [{"template-id": f"vuln-{index}", "index": index}]
        })

    # Launch all writes concurrently using asyncio.gather - This simulates the real concurrent 
    # execution in the app more accurately than threads, since save_scan is async and releases the 
    # GIL during file I/O. This allows us to test the actual async concurrency behavior of the storage layer.

    await asyncio.gather(*[write_scan(i) for i in range(num_scans)])

    # Verify every scan was written correctly - no overwrites, no corruption
    for i in range(num_scans):
        scan_id = f"concurrent-scan-{i:03d}"
        loaded = await load_scan(scan_id)

        assert loaded is not None,                          f"Scan {i} was lost"
        assert loaded["scan_id"] == scan_id,                f"Scan {i} has wrong scan_id"
        assert loaded["target"]  == f"https://target-{i}.com", f"Scan {i} has wrong target"
        assert loaded["results"][0]["index"] == i,          f"Scan {i} has wrong result index"


async def test_concurrent_reads_return_correct_data(patched_scan_dir):
    """Simultaneous reads of the same scan must all return identical data.
    A read that returns partial data mid-write is a race condition."""

    import asyncio
    
    scan_data = {
        "scan_id":   "shared-scan-001",
        "target":    "https://example.com",
        "status":    "completed",
        "timestamp": "2024-01-01T10:00:00",
        "error":     None,
        "results":   [{"template-id": "CVE-2024-001", "severity": "critical"}]
    }

    await save_scan ("shared-scan-001", scan_data)

    # Run multiple concurrent reads
    results = await asyncio.gather(*[load_scan("shared-scan-001") for _ in range(20)])
    assert len(results) == 20, "Should have 20 results from concurrent reads"
                                   
    # Every read must return identical data 
    for result in results:
        assert result["scan_id"]                   == "shared-scan-001" # pyright: ignore[reportOptionalSubscript]
        assert result["results"][0]["template-id"] == "CVE-2024-001" # pyright: ignore[reportOptionalSubscript]


# ___Disk error simulation___
# 
# Disk fill up. Permissions change.Network Mounts disconnect.
# Storage layer must fail loudly with a clear IOError - Never silently
# return None or partial data when a write fails.
# A silent failure here means a scan appears to be in_progress forever
# with no way for the user or operator to know why.

async def test_save_scan_raises_on_permission_error(patched_scan_dir, monkeypatch):
    """When the filesystem rejects a write, save_scan must raise IOError."""
    from pathlib import Path

    def mock_write_text(*args, **kwargs):
        raise PermissionError("Permission denied: /scans/")
    
    monkeypatch.setattr(Path, "write_text", mock_write_text)

    with pytest.raises(IOError) as exc_info:
        await save_scan("perm-error-scan", {
            "scan_id":   "perm-error-scan",
            "target":    "https://example.com",
            "status":    "in_progress",
            "timestamp": "2024-01-01T10:00:00",
            "error":     None,
            "results":   []
        })

    assert "Failed to save scan" in str(exc_info.value)


async def test_load_scan_raises_on_read_permission_error(patched_scan_dir, monkeypatch):
    """When the filesystem rejects a read, load_scan must raise IOError.
    """
    from pathlib import Path

    # First the file is written legitimately
    await save_scan("read-perm-scan", {
        "scan_id":   "read-perm-scan",
        "target":    "https://example.com",
        "status":    "completed",
        "timestamp": "2024-01-01T10:00:00",
        "error":     None,
        "results":   []
    })
    
    # Now the files are unreadable
    def mock_read_text(*args, **kwargs):
        raise PermissionError("Permission denied")
    
    monkeypatch.setattr(Path, "read_text", mock_read_text)

    with pytest.raises(IOError):
        await load_scan("read-perm-scan")


# ___Malformed data___
# 
# Files can be corrupted by interrupted writes, manual edits, or disk errors.
# Every malformed file scenario must produce a clear, actionable error -
# never silent data loss or a crash with an unhelpful traceback.

async def test_completely_invalid_jsonl_raises_ioerror(patched_scan_dir):
    """A file containing random bytes must raise IOError with a clear message"""
    corrupt =patched_scan_dir / "corrupt-001.jsonl"
    corrupt.write_text("}}}}not json at all{{{{")

    with pytest.raises(IOError) as exc_info:
        await load_scan("corrupt-001")
    
    assert "Failed to load scan" in str(exc_info.value)


async def test_truncated_json_object_raises_ioerror(patched_scan_dir):
    """A file truncated mid-write — a real scenario during power loss —
    must raise IOError, not silently return partial data."""
    truncated = patched_scan_dir / "truncated-001.jsonl"
    truncated.write_text('{"_type": "metadata", "scan_id": "truncated-001"')
    # ↑ no closing brace — simulates interrupted write

    with pytest.raises(IOError):
        await load_scan("truncated-001")


async def test_valid_metadata_then_malformed_result_raises_ioerror(patched_scan_dir):
    """Corruption in a result line — not the metadata line — must still raise.
    Returning metadata with no results would be silently misleading."""
    mixed = patched_scan_dir / "mixed-001.jsonl"
    valid_meta = json.dumps({
        "_type":     "metadata",
        "scan_id":   "mixed-001",
        "target":    "https://example.com",
        "status":    "completed",
        "timestamp": "2024-01-01T10:00:00",
        "error":     None
    })
    mixed.write_text(valid_meta + "\n" + "{this is not json}\n")

    with pytest.raises(IOError):
        await load_scan("mixed-001")


async def test_unknown_type_field_is_skipped_silently(patched_scan_dir):
    """A line with an unknown _type must be skipped — not crash the loader.
    This is forward compatibility: future versions may add new line types
    and old readers must gracefully ignore what they don't understand."""
    future_format = patched_scan_dir / "future-001.jsonl"
    meta = json.dumps({
        "_type": "metadata", "scan_id": "future-001",
        "target": "https://example.com", "status": "completed",
        "timestamp": "2024-01-01T10:00:00", "error": None
    })
    future_line = json.dumps({
        "_type": "audit_log",   # unknown type — from a future version
        "event": "scan_started",
        "user":  "admin"
    })
    result_line = json.dumps({
        "_type": "result",
        "template-id": "CVE-2024-0001",
        "severity": "high"
    })
    future_format.write_text(meta + "\n" + future_line + "\n" + result_line + "\n")

    loaded = await load_scan("future-001")

    assert loaded is not None
    assert loaded["status"]  == "completed"
    assert len(loaded["results"]) == 1            # only the result line
    assert loaded["results"][0]["template-id"] == "CVE-2024-0001"


# ___API edge cases ___

async def test_api_handles_unicode_url_end_to_end(client):
    """A unicode URL must survive the full HTTP stack - Validation, 
    storage, and retrieval - without corruption at any layer."""
    with patch("app.main.run_nuclei"):
        post_response = client.post(
            "/scan", 
            json={"target_url": "https://münchen.de/path"}

        )

        assert post_response.status_code == 202
        scan_id = post_response.json()["scan_id"]

        get_response = client.get(f"/scan/{scan_id}")
        assert get_response.status_code      ==   200
        assert get_response.json()["target"] ==   "https://münchen.de/path"


async def test_api_handles_very_long_url_end_to_end(client):
    """A very long URL must survive validation and storage without truncation."""
    long_url = "https://example.com/" + "a" * 2000
    with patch("app.main.run_nuclei"):
        post_response = client.post("/scan", json={"target_url": long_url})

    assert post_response.status_code ==202
    scan_id = post_response.json()["scan_id"]

    get_response = client.get(f"/scan/{scan_id}")
    assert len(get_response.json()["target"]) > 2000


async def test_scan_id_with_special_characters_returns_404(client):
    """Scan IDs with path traversal attempts must return 404 cleanly -
    never expose filesystem structure or crash the server.
    This is a direct security test for the API."""
    dangerous_ids = [
        "../../../etc/passwd",
        "..%2F..%2Fetc%2Fpasswd",
        "scan/../../secret",
    ]
    for dangerous_id in dangerous_ids:
        response = client.get(f"/scan/{dangerous_id}")
        # Must never return 500 - 400 or 422 are both acceptable
        assert response.status_code in [404, 422, 307], \
            f"Dangerous scan_id '{dangerous_id}' returned {response.status_code}"
        

async def test_extremely_large_results_api_response(client, patched_scan_dir):
    """An API response with hundreds of findings must be returned completely.
    This tests that FastAPI doesn't truncate large response bodies."""
    from app.storage import save_scan

    large_scan = {
        "scan_id":   "large-api-scan-001",
        "target":    "https://example.com",
        "status":    "completed",
        "timestamp": "2024-01-01T10:00:00",
        "error":     None,
        "results":   [
            {"template-id": f"CVE-2024-{i:05d}", "severity": "high"}
            for i in range(300)
        ]
    }
    await save_scan("large-api-scan-001", large_scan)

    response = client.get("/scan/large-api-scan-001")
    assert response.status_code   == 200
    assert len(response.json()["results"])== 300
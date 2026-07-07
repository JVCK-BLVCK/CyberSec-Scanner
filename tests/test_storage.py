import json
import pytest
from app.storage import save_scan, load_scan

# ___Save and Load roundtrip test___

# The most fundamental contract: What goes in must come out unchanged.
# We test three distinct cases because each represents a real scenario 
# the application will encounter in production 

async def test_save_and_load_completed_scan(patched_scan_dir, sample_scan_data): 
    """A completed scan with findings must survive a full save/load cycle
    with every field intact -nothing added, nothing lost, nothing mutated. 
    """
    await save_scan(sample_scan_data["scan_id"], sample_scan_data)
    loaded = await load_scan(sample_scan_data["scan_id"])

    assert loaded is not None
    assert loaded["scan_id"] == sample_scan_data["scan_id"]
    assert loaded["target"] == sample_scan_data["target"]
    assert loaded["status"] == sample_scan_data["status"]
    assert loaded["timestamp"] == sample_scan_data["timestamp"]
    assert loaded["error"] is None
    assert len(loaded["results"]) == len(sample_scan_data["results"])


async def test_save_and_load_empty_scan(patched_scan_dir, sample_empty_scan_data):
    """
    Completed scan with zero findings must be preserved accurately.
    An empty results list is NOT the same as None — it means 'scanned, found nothing'
    rather than 'scan not yet complete'. This distinction matters to API clients.
    """
    await save_scan(sample_empty_scan_data["scan_id"], sample_empty_scan_data)
    loaded = await load_scan(sample_empty_scan_data["scan_id"])

    assert loaded["status"] == "completed" # type: ignore
    assert loaded["results"] == [] # type: ignore
    assert loaded["error"] is None # type: ignore


async def test_save_and_load_failed_scan(patched_scan_dir, sample_failed_scan_data):
    """A failed scan with an error message must survive a full save/load cycle
    that message is the only way the API can tell the user what went wrong, so it's 
    crucial that it is preserved accurately."""
    await save_scan(sample_failed_scan_data["scan_id"], sample_failed_scan_data)
    loaded = await load_scan(sample_failed_scan_data["scan_id"])

    assert loaded["status"] == "failed" # type: ignore
    assert loaded["results"] == []  # type: ignore # failed scans should have no results
    assert loaded["error"] == sample_failed_scan_data["error"] # type: ignore
    


# ___Results Integrity and Error Handling___

# Each Finding is a dict that came from Nuclei's JSON output 
# we need to verify the save/load cycle doesn't mutate, reorder,
# or drop any fields from those findings. We also need to ensure that error messages are preserved exactly,
# because they are critical for debugging and user feedback.

async def test_results_fields_are_preserved(patched_scan_dir, sample_scan_data):
    """Each finding's fields must be preserved exactly through the save/load cycle.
    This ensures that the detailed information about each vulnerability is not lost or altered, 
    which is essential for users to understand the scan results and take appropriate action."""
    await save_scan(sample_scan_data["scan_id"], sample_scan_data)
    loaded = await load_scan(sample_scan_data["scan_id"])

    original_findings = sample_scan_data["results"]
    loaded_findings = loaded["results"] # type: ignore

    for original, loaded_finding in zip(original_findings, loaded_findings):
        for key, value in original.items():
            assert loaded_finding[key] == value

            # assert loaded_finding[key] == value, f"Field '{key}' was not preserved correctly. Expected: {value}, Got: {loaded_finding[key]}"


async def test_results_order_is_preserved(patched_scan_dir, sample_scan_data):
    """The order of findings in the results list must be preserved through the save/load cycle.
    The order of findings can be important for users to understand the sequence of vulnerabilities 
    or to correlate with the original Nuclei output. Preserving the order ensures that the scan results 
    are presented in a consistent and expected manner."""
    await save_scan(sample_scan_data["scan_id"], sample_scan_data)
    loaded = await load_scan(sample_scan_data["scan_id"])

    original_ids = [r["template_id"] for r in sample_scan_data["results"]]
    loaded_ids = [r["template_id"] for r in loaded["results"]] # type: ignore
    assert original_ids == loaded_ids

    # assert original_ids == loaded_ids, f"Order of findings was not preserved. Expected: {original_ids}, Got: {loaded_ids}"

async def test_original_type_tag_not_exposed_to_caller(patched_scan_dir, sample_scan_data):
    """The original '_type' tag from Nuclei's output must not be exposed in the API response.
    This is important to prevent confusion for API consumers, as the 'type' field in Nuclei's output 
    is an internal detail that does not have a clear meaning in the context of our API. By ensuring that 
    this field is not included in the results returned to users, we can provide a cleaner and more intuitive 
    API experience while still preserving all the relevant information about each finding."""
    await save_scan(sample_scan_data["scan_id"], sample_scan_data)
    loaded = await load_scan(sample_scan_data["scan_id"])

    # Check metadata fields are preserved
    assert "_type" not in loaded # type: ignore

    # Check every result row does not have the 'type' field
    for result in loaded["results"]: # type: ignore
        assert "_type" not in result

        # assert "_type" not in result, f"The 'type' field should not be exposed to API consumers, but it was found in: {result}"

# ____Missing Scan Handling____

# Load_scan must return None for a missing scan, not raise an exception. 
# This allows the API to return a clean 404 response instead of a 500 error, 
# which is crucial for a good user experience and proper error handling in the
# API layer. We also want to ensure that the function handles the case of a missing 
# files gracefully without crashing, which is important for robustness and reliability
# of the application in production environments where missing scans may be a 
# common occurrence due to user error or cleanup processes.

async def test_load_nonexistent_scan_returns_none(patched_scan_dir):
    """A Scan ID that was never saved must return None, not raise an exception.
    This allows the API to handle missing scans gracefully and return a 404 response 
    instead of crashing with a 500 error, which is crucial for a good user experience and proper error handling."""
    
    result = await load_scan("This-id-does-not-exist")
    assert result is None

async def test_load_returns_none_for_random_ids(patched_scan_dir):
    """Randomly generated Scan IDs that were never saved must return None, not raise an exception.
    This test ensures that the load_scan function can handle arbitrary input without crashing, 
    which is important for robustness and security. By verifying that random IDs return None, we confirm 
    that the function is properly checking for the existence of scan files and not exposing any vulnerabilities 
    or unexpected behavior when faced with invalid input."""
    
    assert await load_scan("random-id-12345") is None
    assert await load_scan("another-random-id-67890") is None
    assert await load_scan("yet-another-random-id-abcde") is None
    

# ____Data Isolation Between Scans____
# Each scan must be stored and loaded independently, with no data leakage between them.
# This test ensures that the storage system properly isolates data for different scans, 
# which is crucial for data integrity and security. By verifying that each scan's data is 
# stored in a separate file and that loading one scan does not affect another, we can confirm
# that the storage system is correctly managing scan data and preventing any unintended interactions or
# data corruption between scans. This is especially important in a multi-user environment where multiple
# scans may be running concurrently, and we need to ensure that each user's data is kept separate and secure.

async def test_two_scans_do_not_share_data(patched_scan_dir):
    """Two different scans must not share data - each should be stored in a separate file and loading one should not affect the other. 
    This ensures that the storage system properly isolates data for different scans, which is crucial for data
    integrity and security. By verifying that each scan's data is stored independently and that loading one scan does 
    not affect another, we can confirm that the storage system is correctly managing scan data 
    and preventing any unintended interactions or data corruption between scans."""

    scan_a = {
        "scan_id": "scan-a",
        "target": "http://example.com",
        "status": "completed",
        "timestamp": "2024-01-01T12:00:00Z",
        "error": None,
        "results": [{"template_id": "vuln-a", "severity": "high"}]
    }

    scan_b = {
        "scan_id": "scan-b",
        "target": "http://test.com",
        "status": "completed",
        "timestamp": "2024-01-02T12:00:00Z",
        "error": None,
        "results": [{"template_id": "vuln-b", "severity": "medium"}]
    }

    await save_scan("scan_aaa", scan_a)
    await save_scan("scan_bbb", scan_b)

    loaded_a = await load_scan("scan_aaa")
    loaded_b = await load_scan("scan_bbb")

    # Each scan must have exactly its own data, with no overlap or leakage
    assert loaded_a ["target"] == "http://example.com" # type: ignore
    assert loaded_a ["results"][0]["template_id"] == "vuln-a" # type: ignore
    assert loaded_b ["target"] == "http://test.com" # type: ignore
    assert loaded_b ["results"][0]["template_id"] == "vuln-b" # type: ignore


    # Cross-contamination check - A's findings must not appear in B and vice versa
    a_ids = [r["template_id"] for r in loaded_a["results"]] # type: ignore
    b_ids = [r["template_id"] for r in loaded_b["results"]] # type: ignore

    assert "vuln-a" not in b_ids
    assert "vuln-b" not in a_ids


async def test_overwriting_scan_replaces_all_data(patched_scan_dir, sample_scan_data):
    """Overwriting an existing scan ID must replace all data, not merge or append to it. 
    This test ensures that when a scan is saved with an existing ID, the new data completely replaces the old data, 
    which is important for maintaining data integrity and preventing confusion. By verifying that all fields are replaced 
    and that no old data persists after an overwrite, we can confirm that the save_scan function is correctly handling updates 
    to existing scans and not allowing any unintended merging of data."""
    
    # Save initial scan (first save)"""
    initial = {**sample_scan_data, "status": "in_progress", "results": []}
    await save_scan(sample_scan_data["scan_id"], initial)

    loaded_initial = await load_scan(sample_scan_data["scan_id"])
    assert loaded_initial["status"] == "in_progress" # type: ignore
    assert loaded_initial["results"] == [] # type: ignore

    # Save updated scan (second save) - this should completely replace the initial data (Completed with findings)
    await save_scan(sample_scan_data["scan_id"], sample_scan_data)

    loaded_final = await load_scan(sample_scan_data["scan_id"])
    assert loaded_final["status"] == "completed" # type: ignore
    assert len(loaded_final["results"]) == len(sample_scan_data["results"]) # type: ignore

    # Check that the findings from the initial save are not present in the final loaded data
    initial_ids = [r["template_id"] for r in loaded_initial["results"]] # type: ignore
    final_ids = [r["template_id"] for r in loaded_final["results"]] # type: ignore
    for template_id in initial_ids:
        assert template_id not in final_ids, f"Finding '{template_id}' from initial save should not be present after overwrite, but it was found in final results."


# ___Corrupted Data/file Handling___

# The load_scan function should handle corrupted files gracefully, either by returning None or by raising a clear exception.
# Load_scan must raise IOError if the file exists but cannot be read, and it must raise a JSONDecodeError if the file contents are not valid JSON.
# This test ensures that the load_scan function can handle cases where the scan file is present but cannot be read or is not valid JSON,
# which is important for robustness and reliability of the application. 
# By verifying that appropriate exceptions are raised in these scenarios, 
# we can confirm that the function is properly handling error conditions and providing clear feedback for debugging and user notification, 
# rather than crashing or returning misleading results.

# We simulate corrupted files by creating files with invalid JSON content and then attempting to load them, verifying that the correct exceptions are raised.

async def test_corrupted_json_raises_ioerror(patched_scan_dir):
    """A scan file that exists but cannot be read must raise an IOError.
    This test simulates a corrupted file by creating a file with invalid JSON content and then attempting to load it, 
    verifying that an IOError is raised to indicate that the file cannot be read properly."""
    
    corrupt_file = patched_scan_dir / "corrupted_scan.jsonl"
    corrupt_file.write_text("This is not valid JSON content")
    
    with pytest.raises(IOError) as exc_info:
        await load_scan("corrupted_scan")

    assert "Failed to load scan" in str(exc_info.value)

async def test_partially_corrupted_file_raises_ioerror(patched_scan_dir, sample_scan_data):
    """A scan file that is partially corrupted (e.g. valid JSON followed by invalid JSON) must raise an IOError.
    This test simulates a partially corrupted file by writing valid JSON metadata followed by invalid JSON content, 
    and then attempts to load it, verifying that an IOError is raised to indicate that the file cannot be read properly."""
    
    scan_id = "partially-corrupted-scan"

    # Write valid metadata then a corrupted result line
    corrupt_file = patched_scan_dir / f"{scan_id}.jsonl"
    valid_metadata = json.dumps({
        "_type" : "metadata",
        "scan_id": scan_id,
        "target": "http://example.com",
        "status": "completed",
        "timestamp": "2024-01-01T12:00:00Z",
        "error": None
    })

    corrupt_file.write_text(valid_metadata + "\n" + "This is not valid JSON content")

    with pytest.raises(IOError) as exc_info:
        await load_scan(scan_id)

    assert "Failed to load scan" in str(exc_info.value)
    

# async def test_empty_file_returns_none(patched_scan_dir):
#     """An empty scan file must return None, not raise an exception.
#     This test simulates an empty file by creating a file with no content and then attempting to load it, 
#     verifying that the load_scan function returns None to indicate that the scan data could not be loaded."""
    
#     empty_file = patched_scan_dir / "empty_scan.jsonl"
#     empty_file.write_text("")  # Create an empty file

#     # empty_file.touch()  # Create an empty file

#     result = await load_scan("empty-scan")
#     assert result is None


async def test_empty_file_returns_none(patched_scan_dir):
    """An empty file has no metadata — must return None, not raise.
    Empty files can result from an interrupted initial write."""
    (patched_scan_dir / "empty-scan.jsonl").write_text("")
    assert await load_scan("empty-scan") is None


# async def test_blank_lines_only_returns_none(patched_scan_dir):
#     """A scan file that contains only blank lines must return None, not raise an exception.
#     This test simulates a file with only blank lines by writing several newline characters to a file and then attempting to load it, 
#     verifying that the load_scan function returns None to indicate that no valid scan data could be loaded."""
    
#     blank_file = patched_scan_dir / "blank_lines_scan.jsonl"
#     blank_file.write_text("\n\n\n")  # Write several blank lines

#     result = await load_scan("blank-lines-scan")
#     assert result is None


async def test_blank_lines_only_returns_none(patched_scan_dir):
    """A file of only blank lines must behave identically to an empty file.
    This validates the blank-line skipping logic in load_scan."""
    (patched_scan_dir / "blank-scan.jsonl").write_text("\n\n\n\n")
    assert await load_scan("blank-scan") is None


# ___Multiple Scans Data Isolation___(Large dataset test)__
# Real scans against large targets can produce hundreds of findings.
# We need to ensure that the storage system can handle multiple 
# large scans without any data leakage or corruption between them, 
# which is crucial for data integrity and reliability in production. 
# This test simulates two large scans with many findings and verifies 
# that each scan's data is stored and loaded independently, 
# with no overlap or contamination of results, even when the dataset is large.

async def test_large_number_of_results(patched_scan_dir):
    """Storage must handle 500 findings without data loss.
    This is a realistic upper bound for a thorough Nuclei scan against a large target, 
    and we need to ensure that our storage system can handle this volume of data without any issues."""

    findings = [
        {
            "template_id": f"CVE-2024-{str(i).zfill(5)}",
            "severity": "high",
            "host": f"https://example.com/endpoint-{i}"

        }
        for i in range(500)
    ]

    large_scan = {
        "scan_id": "large-scan-001",
        "target": "http://example.com",
        "status": "completed",
        "timestamp": "2024-01-01T12:00:00Z",
        "error": None,
        "results": findings
    }

    await save_scan("large-scan-001", large_scan)
    loaded = await load_scan("large-scan-001")

    assert len(loaded["results"]) == 500 # type: ignore
    # Check that all findings are present and correct - if the file was truncated 
    # or if there was any data loss, this would fail
    assert loaded["results"][0]["template_id"] == "CVE-2024-00000" # type: ignore
    assert loaded["results"][499]["template_id"] == "CVE-2024-00499" # type: ignore

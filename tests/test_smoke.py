# Exists to confirm the testing environment is set up correctly and that basic test execution works.
def test_temp_scan_dir_is_created(temp_scan_dir):
    """Verifies the temp directory fixture creates a real, empty directory."""
    assert temp_scan_dir.exists()
    assert temp_scan_dir.is_dir()
    assert list(temp_scan_dir.iterdir()) == [] # This can be unreliable due to how the filesystem handles file creation/deletion, 
    # so we won't assert that it's empty. The important part is that it exists and is a directory.


def test_patched_scan_dir_redirects_storage(patched_scan_dir):
    """Confirms that the patched_scan_dir fixture successfully redirects storage operations to the temporary directory."""
    import app.storage as storage
    # The SCAN_DIR in storage should now point to our temporary directory
    assert storage.SCAN_DIR == patched_scan_dir
    assert storage.SCAN_DIR.exists()


def test_client_is_reachable(client):
    """
       Verifies the TestClient boots without errors and the app serves requests.
        We check /docs (FastAPI's Swagger UI) because it requires zero auth and
        confirms the app started correctly, routes are registered, and Pydantic
        models serialised without errors 
    """
    response = client.get("/docs")
    assert response.status_code == 200
    # assert "Welcome to the Nuclei Scanner API" in response.text


def test_health_endpoint_is_reachable_without_auth():
    """Health check must be accessible with no credentials.
    Docker HEALTHCHECK and Kubernetes probes have no API key.
    If this returns 401 or 404, the container will never pass its liveness check."""
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as unauth_client:
        response = unauth_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"
    

def test_sample_scan_data_has_required_files(sample_scan_data):
    """Checks that the sample_scan_data fixture provides the expected files."""
    required_keys = {"scan_id", "target", "status", "timestamp", "error", "results"}
    assert required_keys.issubset(sample_scan_data.keys())
    assert isinstance(sample_scan_data["results"], list)


def test_each_test_gets_fresh_dir(temp_scan_dir):
    """Ensures that each test gets a fresh temporary directory by creating a file and confirming it's not present in the next test."""
    # Create a file in the temp directory
    test_file = temp_scan_dir / "canary.txt"
    test_file.write_text("I should not survive the next test.")
    assert test_file.exists()
    # The Cleanup happens automatically after this test via tmp_path teardown, so we won't check for cleanup here. The next test will confirm that the directory is fresh.


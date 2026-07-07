import pytest
import asyncio
from app.tasks import spawn_background_task, _background_tasks
from fastapi.testclient import TestClient
import tracemalloc


tracemalloc.start()


def test_health_check_returns_200():
    """Health check must work without authentication."""
    from app.main import app
    with TestClient(app) as unauth_client:
        response = unauth_client.get("/health")
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_health_check_not_rate_limited(with_rate_limiting):
    """Orchestrators poll frequently — health check must never 429."""
    from app.main import app
    with TestClient(app) as client:
        responses = [client.get("/health").status_code for _ in range(20)]
    assert 429 not in responses


async def test_spawn_returns_a_task():
    async def quick():
        return "done"
    
    task = spawn_background_task(quick())
    await task
    assert task.result() == "done"


async def test_task_is_removed_from_set_after_completion():
    async def quick():
        pass

    task = spawn_background_task(quick())
    await task
    await asyncio.sleep(0)   # let the done-callback fire
    assert task not in _background_tasks


async def test_exception_is_logged_not_raised_to_caller():
    async def boom():
        raise ValueError("scan exploded")
    
    task = spawn_background_task(boom())
    await asyncio.sleep(0.05)   # let the task run and the callback fire
    assert task.done()
    assert isinstance(task.exception(), ValueError)

async def test_shutdown_marks_pending_scan_as_failed(patched_scan_dir):
    from app.storage import save_scan, load_scan
    from app.tasks import spawn_background_task, shutdown_pending_scans

    await save_scan("shutdown-test", {
        "scan_id": "shutdown-test", "target": "https://example.com",
        "status": "in_progress", "timestamp": "2024-01-01T10:00:00",
        "error": None, "results": []
    })

    async def never_finishes():
        await asyncio.sleep(999)

    spawn_background_task(never_finishes(), scan_id="shutdown-test")
    interrupted = await shutdown_pending_scans(grace_period=0.1)

    assert "shutdown-test" in interrupted
    loaded = await load_scan("shutdown-test")
    assert loaded["status"] == "failed" # pyright: ignore[reportOptionalSubscript]
    assert "shut down" in loaded["error"].lower() # pyright: ignore[reportOptionalSubscript]

async def test_shutdown_handles_multiple_pending_scans_independently(patched_scan_dir):
    """
        Multiple scans pending at shutdown must each get their own correct failed status
        no cross-contamination between scan_ids.
    """
    from app.storage import save_scan, load_scan
    from app.tasks import spawn_background_task, shutdown_pending_scans

    for sid in ["scan-a", "scan-b", "scan-c"]:
        await save_scan(sid, {
            "scan_id": sid, "target": f"https://{sid}.com",
            "status": "in_progress", "timestamp": "2024-01-01T10:00:00",
            "error": None, "results": []
        })
    
    async def never_finishes():
        await asyncio.sleep(999)

    for sid in ["scan-a", "scan-b", "scan-c"]:
        spawn_background_task(never_finishes(), scan_id=sid)

    interrupted = await shutdown_pending_scans(grace_period=0.1)

    assert set(interrupted) == {"scan-a", "scan-b", "scan-c"}
    for sid in ["scan-a", "scan-b", "scan-c"]:
        loaded = await load_scan(sid)
        assert loaded ["status"] == "failed" # pyright: ignore[reportOptionalSubscript]
        assert loaded ["target"] == f"https://{sid}.com" # pyright: ignore[reportOptionalSubscript]

async def test_shutdown_with_no_pending_tasks_returns_empty_list():
    from app.tasks import shutdown_pending_scans
    assert await shutdown_pending_scans(grace_period=0.1) == []

snapshot = tracemalloc.take_snapshot()
top_stats = snapshot.statistics("lineno")

print ("[ Top 10 ]")
for stat in top_stats[:10]:
    print(stat)

"""
Unified background task execution for both the HTTP API and MCP server.
 
Both main.py (HTTP) and mcp_server.py (MCP) need to fire run_nuclei
without blocking the caller. This module provides a single entry point
for that, solving two problems that naive asyncio.create_task() has:
 
Problem 1 — garbage collection:
    asyncio only holds a weak reference to Tasks. If you don't keep a
    strong reference, the Task can be garbage-collected before it finishes,
    silently killing the scan mid-flight. _background_tasks is a dict that
    holds a strong reference until the Task completes.
 
Problem 2 — silent exception loss:
    If an exception occurs inside a Task and nobody awaits it, Python
    prints "Task exception was never retrieved" to stderr — but only when
    the Task is garbage-collected, which may be long after the failure.
    The done-callback logs it immediately via structured logging.
 
Problem 3 — graceful shutdown:
    _background_tasks maps each Task to its scan_id. On SIGTERM,
    shutdown_pending_scans can find and fail every in-progress scan so
    polling clients get a clear answer instead of an eternal "in_progress".
"""

import asyncio
import logging

logger = logging.getLogger(__name__)

# Maps each running Task to the scan_id it's executing — so on shutdown
# we know exactly which scans to mark failed, not just that "something"
# was running.
_background_tasks: dict[asyncio.Task, str | None] = {}


def spawn_background_task(coro, scan_id: str | None = None) -> asyncio.Task:
    """
    Schedule a coroutine to run without blocking the caller.

    Used identically by main.py (HTTP) and mcp_server.py (MCP) so both
    entry points share one exception-handling and shutdown path.
 
    Args:
        coro:    The coroutine to run (e.g. asyncio.to_thread(run_nuclei, ...))
        scan_id: Optional scan_id to register for shutdown tracking.
                Pass None for background work not associated with a scan.
 
    Returns:
        The created asyncio.Task.
    
    """
    task = asyncio.create_task(coro)
    _background_tasks[task] = scan_id

    def _on_done(completed: asyncio.Task):
        _background_tasks.pop(completed, None)

        if completed.cancelled():
            return
        
        exc = completed.exception()
        if exc is not None:
            logger.error({
                "event": "background_task_failed",
                "scan_id" : scan_id,
                "error": str(exc),
                "type" : type(exc).__name__

            })

    task.add_done_callback(_on_done)
    return task


async def shutdown_pending_scans(grace_period: float = 5) -> list[str]:
    """
    Called on SIGTERM via the FastAPI lifespan shutdown handler.
 
    Gives running scans a brief window to complete naturally (some may be
    seconds from finishing). After the grace period, cancels remaining tasks
    and marks their scans as failed in storage so polling clients receive
    a clear, honest answer rather than an eternal "in_progress" status.
 
    Args:
        grace_period: Seconds to wait before force-cancelling tasks.
                      Docker's default SIGTERM grace period is 10 seconds.
                      Scans take 1-10 minutes, so most won't finish here —
                      the value of this function is the explicit failure
                      marking, not waiting for completion.
 
    Returns:
        List of scan_ids that were interrupted.
    """
    # Local import avoids circular dependency:
    # tasks.py -> storage.py is fine
    # storage.py -> tasks.py would create a cycle
    from app.storage import save_scan, load_scan   # local import — avoids circular import

    if not _background_tasks:
        return []

    tasks = list(_background_tasks.keys())

    _, pending = await asyncio.wait(tasks, timeout=grace_period)

    interrupted = []

    for task in pending:
        scan_id = _background_tasks.get(task)
        task.cancel()

        if scan_id:
            try:
                data = await load_scan(scan_id)
                if data and data["status"] == "in_progress":
                    await save_scan(scan_id, {
                        **data,
                        "status": "failed",
                        "error": "Service shut down before scan completed"
                    })
                interrupted.append(scan_id)
            except (IOError, Exception) as e:
                # Best-effort -log and continue even if storage fails
                logger.error({
                    "event": "shutdown_mark_failed_error",
                    "scan_id" : scan_id,
                    "error" : str(e)
                })

    return interrupted # type: ignore
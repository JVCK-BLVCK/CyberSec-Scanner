
import asyncio
import json
import logging
import uuid
from datetime import datetime, timezone

from mcp.server.fastmcp import FastMCP

from app.logging_config import setup_logging
from app.tasks import spawn_background_task
from app.models import ScanRequest
from app.scanner import run_nuclei
from app.storage import load_scan, save_scan

setup_logging(level="INFO")
logger = logging.getLogger(__name__)

# Initialize the FastMCP application
mcp = FastMCP(
    "ScanMe", 
    instructions= """ Vulnerability Scanner using Nuclei.

Workflow:
1. Call scan_target with a URL — returns scan_id immediately
2. Call get_scan_status repeatedly until status is 'completed' or 'failed'
3. Report findings from the results field 

Each finding includes:
- template-id: The Nuclei template that matched (e.g. CVE-2024-0001)
- severity: The severity level assigned by the template (e.g. critical, high, medium, low)
- info: Additional info from the template (e.g. affected URL, parameter, etc.)

Never wait inside scan_target - always poll with get_scan_status to allow for better scalability and responsiveness. 
The MCP server can handle multiple concurrent scans without blocking, and clients can check progress at their own pace.

"""  
)


@mcp.tool()
async def scan_target(target_url: str, timeout_seconds: int = 600) -> str:
    """
    Submit a URL for vulnerability scanning. Returns immediately with a scan_id.

    Do NOT wait for completion here. After calling this tool, poll
    get_scan_status every 30 seconds until status is completed or failed.
    Scans typically take 2 to 10 minutes depending on target complexity.

    Args:
        target_url: The URL to scan. Must use http or https scheme.
        timeout_seconds: The maximum time to wait for the scan to complete.
    Returns:
        JSON with scan_id to use for polling get_scan_status. 

    """
    try: 
        validated = ScanRequest(target_url=target_url)
    except Exception as e:
        return json.dumps({"error": "Invalid URL", "detail": str(e)})
    
    scan_id = str(uuid.uuid4())
    started = datetime.now(timezone.utc)

    logger.info({
        "event":     "mcp_scan_requested",
        "scan_id":   scan_id,
        "target":    validated.target_url,
        "timestamp": started.isoformat()
    })

    # Save initial scan record with status "in_progress" so get_scan_status can return meaningful data immediately, 
    # even if the scan is still running.
    await save_scan(scan_id, {
        "scan_id":   scan_id,
        "target":    validated.target_url,
        "status":    "in_progress",
        "timestamp": started.isoformat(),
        "error":     None,
        "results":   []
    })

    # Run the blocking scan_nuclei function in a separate thread to avoid blocking the event loop.
    # This allows the MCP server to remain responsive and handle multiple concurrent scans without waiting for each one to finish before starting the next.
    spawn_background_task(
        asyncio.to_thread(run_nuclei, scan_id, validated.target_url), scan_id=scan_id
    )

    logger.info({
        "event":    "mcp_scan_queued",
        "scan_id":   scan_id,
        "target":    validated.target_url,
    })

    # Return immediately -scan is running in background, client should poll get_scan_status for updates
    return json.dumps({
        "scan_id": scan_id,
        "status":  "in_progress",
        "message": "Scan started. Poll get_scan_status every 30 seconds until status is completed or failed.",
        "target":  validated.target_url,
        "started_at": started.isoformat()
    })

@mcp.tool()
async def get_scan_status(scan_id: str) -> str:
    """
    Retrieve current status and results for an existing scan either running or completed.

    Args:
        scan_id: The scan_id returned by scan_target.

    Returns:
        JSON string with current scan status, findings_count and any findings list when completed.
        If scan_id is unknown, returns error message. Always returns valid JSON.

    """
    if not scan_id:
        return json.dumps({"error": "scan_id is required"})

    try:
        data = await load_scan(scan_id)
    except IOError as e:
        return json.dumps({"error": f"Storage error: {str(e)}"})

    if data is None:
        return json.dumps({"error": "Scan not found", "scan_id": scan_id})
    
    status = data["status"]

    # Build a response that gives Claude everything it needs to decide what to do next:
    # Whether to keep polling, or if completed, how many findings and what they are.
    # This allows Claude to make informed decisions about whether to wait, 
    # ask the user for more info, or report results, without needing to call additional tools or ask follow-up questions.
    response ={
        "scan_id":        data["scan_id"],
        "target":         data.get("target"),
        "status":         status,
        "findings_count": len(data.get("results", [])),
        "findings":       data.get("results", []),
        "error":          data.get("error"),
        "timestamp":      data.get("timestamp")
    }

    if status == "in_progress":
        response["message"] = "Scan is still running. Please check back later for results." \
        "Poll again in 30 seconds or so. " \
        "If the scan is taking significantly longer than expected, there may be an issue with the target or the scanning process."

    elif status == "completed":
        response["findings"] = data.get("results", [])
        response["message"] = (
            f"Scan completed. Found {response['findings_count']} vulnerabilities. " 
            if response["findings_count"] > 0 
            else "Scan completed. No vulnerabilities found."

        )
    
    elif status == "failed":
        response["error"] = data.get("error")
        response["message"] = f"Scan failed: {data.get('error')}"
    
    return json.dumps(response, indent=2)
        


if __name__ == "__main__":
    mcp.run()

"Fast API entry point"
import asyncio
import logging
import os
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from uuid import uuid4

from fastapi import Depends, FastAPI, HTTPException, Request
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from app.auth import verify_api_key
from app.logging_config import setup_logging
from app.models import ScanRequest, ScanResponse
from app.rate_limiter import limiter
from app.scanner import run_nuclei
from app.storage import SCAN_DIR, load_scan, save_scan
from app.tasks import spawn_background_task, shutdown_pending_scans


# Initialize structured JSON logging before anything else 
# to ensure all loggers in all modules use this configuration automatically
setup_logging(level="INFO")

logger = logging.getLogger(__name__)

# ___Lifespan___
# 
# FastAPI's lifespan replaces the deprecated @app.on_event("startup/shutdown").
# On shutdown, we give in_progress scans a brief window to complete, then 
# explicitly mark any still-running scans as failed so clients polling 
# GET/scan/{id} receive a clear answer instead of an eternal "in_progress".

@asynccontextmanager
async def lifespan(app: FastAPI):
    # startup - nothing needed: storage directory is created at import time 
    yield
    # shutdown - graceful cleanup of background tasks
    logger.info({"event": "shutdown_initiated"})
    interrupted = await shutdown_pending_scans(grace_period=5)
    if interrupted:
        logger.warning({
            "event": "scans_interrupted_on_shutdown",
            "scan_ids": interrupted,
            "count": len(interrupted)
        })

# ___Application___

app = FastAPI(
    title = "ScanMe",
    description="""
    ## ScanMe 

    Scans Web applications and APIs for security vulnerability using the 
    [Nuclei](https://nuclei.projectdiscovery.io/) engine.

    ### Authentication
    All endpoints require an API key for authentication.
    Clients must include a valid API key in the `X-API-KEY` header of each request.

    ### Workflow
    1. Submit a target URL via 'POST /scan' to initiate a scan - receive a unique `scan_id` immediately.
    2. Poll 'GET /scan/{scan_id}' until "status" changes from "in_progress" to "completed" or "failed", then retrieve results.
    3. Results include any vulnerabilities found, along with metadata about the scan/findings.

    ### Rate Limiting
    To prevent abuse and ensure fair usage, the API implements rate limiting:
    - `POST /scan`: Limited to 10 requests per minute per IP address.
    - `GET /scan/{scan_id}`: Limited to 60 requests per minute per IP address.

    Clients that exceed these limits will receive a 429 Too Many Requests response, 
    indicating that they have made too many requests in a given amount of time and should slow down.

    ### Security Considerations
    - API keys should be kept secret and secure. Do not hardcode them in source code or expose them in client-side applications.
    - The API should be accessed over HTTPS to protect API keys and data in transit.

    """,
    version="1.0",
    contact={
        "name": "ScanMe",
        "email": "cybers@security.com",
        "url": "https://cybers.com"
        
    },
    license_info={
        "name": "MIT License",
        "url": "https://opensource.org/licenses/MIT"
    },
    lifespan=lifespan

)

# Register the rate limit exceeded handler with FastAPI's exception handling system
# This ensures that when a client exceeds the defined rate limits, 
# they receive a clear and consistent JSON response indicating that they have made too many requests, 
# along with a 429 status code.
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler) # type: ignore

# ___Health Check___
# 
# No authentication, no rate limiting - orchestrators (Docker, Kubernetes, load balancers) 
# poll this without credentials. Checks the storage layer is writable so a disk-full or 
# permission failure is surfaced early.

@app.get(
        "/health",
        tags=["Operations"],
        summary="Service health check",
        description="Used by Docker HEALTHCHECK and Kubernetes readiness probes."
)
async def health_check():
    storage_ok = SCAN_DIR.exists() and os.access(SCAN_DIR, os.W_OK)
    if not storage_ok:
        raise HTTPException(status_code=503, detail="Storage not writable")
    return{
        "status": "healthy",
        "service": "ScanMe",
        "version": "1.0"
    }


# ___POST / scan___

@app.post(
    "/scan", 
    response_model=ScanResponse, 
    status_code=202,
    summary="Submit a URL for Vulnerability scanning",
    description="""
    Submits a target URL and queues it for vulnerability scanning using the Nuclei engine.

    Returns immediately with a "scan_id" - the scan runs asynchronously in the background, 
    and clients can poll the GET /scan/{scan_id} endpoint for status and results.

    """,
    responses={

        202: {"description": "Scan accepted and queued for processing"},
        401: {"description": "Missing or invalid API key"},
        422: {"description": "URL failed validation — check scheme and format"},
        429: {"description": "Rate limit exceeded — maximum 10 scans per minute"},
        500: {"description": "Storage error — scan could not be initialised"},

    },
    tags=["scanning"]
    
    )
# 10 scans per minute per ip address - defined in rate_limiter.py
@limiter.limit("10/minute")
async def start_scan(
    request: Request,
    scan_request: ScanRequest, 
    api_key: str = Depends(verify_api_key)

    ):

    """
    async def -yields control during save_scan's disk write.
    Other requests are handled while this waits for disk.
    """

    scan_id = str(uuid4())
    started = datetime.now(timezone.utc)

    logger.info({
        "event": "scan_started",
        "scan_id": scan_id,
        "target": scan_request.target_url,
        "timestamp": started.isoformat()
    })
    
    # Save initial in-progress status with metadata
    initial_data = {
        "scan_id": scan_id,
        "target": scan_request.target_url,
        "status": "in_progress",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "error": None,
        "results": []
    }
    
    try:
        await save_scan(scan_id, initial_data)
    except IOError as e:
        # Storage failure is critical since we won't be able to update scan results later, 
        # so we log the error and return a 500 response to the client immediately.
        logger.error({
            "event":     "scan_creation_failed",
            "scan_id":   scan_id,
            "target":    scan_request.target_url,
            "error":     str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        raise HTTPException(
            status_code=500, 
            detail="Failed to create scan. Please try again later."
        )
    
    spawn_background_task(
        asyncio.to_thread(run_nuclei, scan_id, scan_request.target_url),
        scan_id=scan_id
    )
    
    logger.info({
        "event": "scan_queued",
        "scan_id": scan_id,
        "target": scan_request.target_url,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

    return ScanResponse(scan_id=scan_id, status="in_progress")

# ___GET/scan/{scan_id}___

@app.get(
    "/scan/{scan_id}", 
    response_model=ScanResponse,
    summary="Get scan status and results",
    description="""
    Retrieves the status and results of a previously submitted scan using its unique `scan_id`.

    Clients should poll this endpoint using the `scan_id` received from the POST /scan response until the "status" 
    field changes from "in_progress" to either "completed" or "failed".
    Typically, clients would poll every 30 seconds to check for updates without overwhelming the server with requests.
    A Scan duration can vary from 1-5 minutes depending on the target and scan complexity, 
    so polling every 30 seconds is a good balance between timely updates and avoiding excessive requests.
    """,
    responses={
        200: {"description": "Scan found — check status field for current state"},
        401: {"description": "Missing or invalid API key"},
        404: {"description": "Scan not found — invalid or expired scan_id"},
        429: {"description": "Rate limit exceeded — maximum 60 polls per minute"},
        500: {"description": "Storage error — scan could not be retrieved"},
    },
    tags=["scanning"]

)
@limiter.limit("20/minute")
async def get_scan(
    request: Request,
    scan_id: str, 
    api_key: str = Depends(verify_api_key)
    
    ):
    
    """
    Why 20/minute for GET?
    GET requests are much less resource intensive than starting a new scan, so we can allow a higher rate limit for status checks.
    This allows clients to poll for status updates more frequently without hitting rate limits, while still protecting against abuse.
    Clients need to check scan status more frequently than they start scans, especially for longer-running scans, 
    so a higher limit here improves usability without significantly increasing risk of abuse.

    """
    logger.info({
        "event": "scan_status_requested",
        "scan_id": scan_id,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })

    try:
        data = await load_scan(scan_id)
    except IOError as e:
        # Storage read failure is critical since we can't retrieve scan results, 
        # so we log the error and return a 500 response to the client immediately.
        logger.error({
            "event": "scan_status_retrieval_failed",
            "scan_id": scan_id,
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        raise HTTPException(
            status_code=500, 
            detail="Failed to retrieve scan status. Please try again later."
        )
    
    
    if data is None:
        logger.info({
            "event": "scan_not_found",
            "scan_id": scan_id,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        raise HTTPException(status_code=404, detail="Scan not found")
    
    logger.info({
        "event": "scan_status_retrieved",
        "scan_id": scan_id,
        "status": data.get("status"),
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    
    
    # Data is now always a dict from storage.py
    return ScanResponse(
        scan_id=data["scan_id"],
        target = data.get("target"),
        status = data["status"],
        results = data.get("results"),
        error = data.get("error")
    )
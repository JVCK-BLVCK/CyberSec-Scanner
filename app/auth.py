"""API key Authentication for the Vulnerability Scanner API.

Every protected endpoint depends on verify_api_key,which checks the X-API-KEY header 
against the expected value in the environment variable. If the key is missing or invalid,
a 401 Unauthorized response is returned immediately, and the request is not processed further.

"""
import logging
import os 
from datetime import datetime, timezone

from fastapi import HTTPException, Security
from fastapi.security import APIKeyHeader

logger = logging.getLogger(__name__)

# Define the expected header name for the API Key.
# APIKeyHeader is a FastAPI security utility that extracts the API key from the specified header.
# It tells FastAPI to look for this header on every request that depends on this security scheme.
# auto_error = False means we handle the error response ourselves in the verify_api_key function.
# with a custome error message rather than the FASTAPI's generic one.

API_KEY_HEADER = APIKeyHeader(name="X-API-KEY", auto_error=False)

def get_api_key() -> str:
    """
    Retrieve the expected API key from environment variable at runtime.
    
    This allows us to change the API key without redeploying the application, 
    which is important for security best practices (e.g. rotating keys regularly).
    
    Why environment variable and not a hardcoded string? 
    Because hardcoding secrets end up in git history, Docker images, and 
    log files. Environment variables are injected at runtime and never touch the codebase, 
    making them much safer for managing secrets like API Keys.

    In development: set it in your Shell
    $env:SCANNER_API_KEY = "your-dev-secret-key" # PowerShell
    export SCANNER_API_KEY="your-dev-secret-key" # Bash/Linux/Mac

    In production: set it in your hosting environment's secret manager or 
    environment variable configuration (e.g. AWS Secrets Manager, Heroku Config Vars, etc.)
    Inject via Docker, Kubernetes secrets, or cloud secret manager - code never changes, 
    just the environment variable value.

    """
    key = os.environ.get("SCANNER_API_KEY")
    if not key:
        raise RuntimeError(
            "SCANNER_API_KEY environment variable not set." \
            "Please set it to a secure value before starting the application."
        )
    
    return key

async def verify_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    """
    FastAPI dependency function to verify the provided API key against the expected value.

    This function is used as a dependency in protected endpoints. 
    If the API key is valid, it returns the key (or could return user info in a more complex implementation).
    If invalid, it raises an HTTPException with a 401 status code, which FastAPI will handle by returning an appropriate response to the client.
    
    """
    if not api_key:
        logger.warning({
            "event" : "authentication_failed; no API key provided",
            "detail": "Request received without X-API-KEY.",
            "timestamp": datetime.now(timezone.utc).isoformat(),

        })
        raise HTTPException(
            status_code = 401,
            detail="Unauthorized: API key missing. Please provide a valid API key in the X-API-KEY header."
        )
    
    try:
        expected = get_api_key()
    except RuntimeError as e:
        # If the expected API key is not configured properly, 
        # this is a critical issue that should be logged and alerted on immediately.
        # Server misconfiguration - the env var was never set or was cleared accidentally.
        logger.error({
            "event": "Authentication_failed; server misconfiguration",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        raise HTTPException(
            status_code=500,
            detail="Invalid API Key."
        )
    
    if api_key != expected:
        logger.warning({
            "event": "authentication_failed; invalid API key provided",
            "provided_key": api_key,
            "timestamp": datetime.now(timezone.utc).isoformat()
        })

        raise HTTPException(
            status_code=401,
            detail="Unauthorized: Invalid API key. Please provide a valid API key in the X-API-KEY header."
        )
    
    return api_key
    # return api_key if api_key == expected else HTTPException(
    #     status_code=401,
    #     detail="Unauthorized: Invalid API key." )
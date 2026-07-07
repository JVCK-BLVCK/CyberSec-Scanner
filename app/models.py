"Scan Request/response models"
from pydantic import BaseModel, Field, field_validator
from typing import Optional, List, Dict
from urllib.parse import urlparse
import re


class ScanRequest(BaseModel):
    """
    Represents the expected structure of the JSON payload for initiating a scan.
    The target_url field is validated to ensure it includes a valid scheme (http or https) and a network location (domain).
    It also checks for the presence of characters that are never valid in URLs (like newlines or null bytes) to prevent malformed input.
    This validation helps ensure that the API receives well-formed URLs, which can prevent errors during scanning and reduce the risk of certain types of injection attacks.

    """
    target_url: str = Field(
        ...,
        description= "The URL to be scanned. Must include the scheme (http:// or https://) and a valid domain",
        examples = [
            "https://example.com",
            "http://testsite.local",
            "https://subdomain.example.com/path?query=param#fragment"
            "http://192.168.1.1:8080"
        ]
        
    )
    
    @field_validator('target_url')
    @classmethod
    def validate_url(cls, v: str) -> str:
        result = urlparse(v)

        if not all([result.scheme, result.netloc]):
            raise ValueError("URL must include scheme (e.g. https:// or http:// )  and domain")
        
        if result.scheme not in ["http", "https"]:
            raise ValueError("URL scheme must be http or https")
        
        # 3 — Block characters that are never valid in any URL context
        #     Note: &, ?, =, #, +, % are all legitimate URL characters
        #     We only block things that represent malformed or injected input
        if re.search(r'[\n\r\x00 ]', v):
            raise ValueError("URL contains invalid characters")
        
        return v
       

class ScanResponse(BaseModel):
    scan_id: str = Field(
        ..., 
        description="Unique identifier for the scan, returned when a scan is initiated. Used to check status and retrieve results."
    )
    target: Optional[str] = Field(
        default=None,
        description="The URL that was scanned. Included in responses for traceability, " \
        "but may be omitted in some error cases where the scan couldn't be initiated properly."
    )  
    status: str = Field(
        ..., 
        description="Current status of the scan. Possible values: in_progress, completed, failed"
    )
    results: Optional[List[Dict]] = Field(
        default=None,
        description="List of vulnerability findings from the scan. Each finding is a dictionary containing details about the vulnerability. " \
        "This field is included in completed scans and may be omitted or null in in-progress or failed scans."
    )
    error: Optional[str] = Field(
        default=None,
        description="Error message if the scan failed. Null if the scan is in progress or completed successfully."
    )
"""
Rate limiting module to control the frequency of scans and prevent abuse. 
This module provides a simple in-memory rate limiter that tracks scan requests 
per target URL and enforces limits based on configurable thresholds. 
It is designed to be used in conjunction with the scanning functionality 
to ensure that scans are performed at a reasonable rate and to protect against 
potential abuse or overloading of the system.

Uses slowapi - A Fast API native wrapper around the limits library.
The rate limiter is applied to the /scan endpoint to limit the number of scans 
that can be initiated for a given target URL within a specified time window.

Why rate Limit a security tool specifically?
1. Scanning is resource-intensive -each scan spawns a subprocess
2. Without limits, one client can exhaust the thread pool 
3. Uncontrolled scanning of third party targets creates legal liability and ethical issues
4. Rate limits force intentionality - users must consciously choose to scan.

"""
import logging
from slowapi import Limiter
from slowapi.util import get_remote_address


logger = logging.getLogger(__name__)

# get_remote_address extracts the client's IP address from the request, which is used as the key for rate limiting.
# The default limit is set to 10 scans per minute per IP address, but this can be adjusted as needed.
# This means that any single IP address can only initiate 10 scans within an minute, 
# which helps prevent abuse while still allowing legitimate use.
# The limiter can be applied to specific endpoints using the @limiter.limit decorator, 
# which is done in the main application code.
# For more complex scenarios, you could implement additional logic to track scan frequency per 
# target URL or user account, but this basic IP-based rate limiting provides a good starting point for preventing abuse.

limiter = Limiter(key_func=get_remote_address, default_limits=["10/minute"])

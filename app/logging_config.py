"""Structured logging configuration for the Vulnerability scanner.

All log output is JSON -Machine readable, queryable, and pipeable into
any observability platform (Datadog, Grafana, Cloudwatch, etc.

Every log entry carries at Minimum:
- timestamp: When the event occurred, in ISO 8601 format for easy parsing 
-level: severity (INFO, WARNING, ERROR)
- event: What happened (Human readable)
-logger: Which module produced it (e.g. app.scanner, app.main, etc.)
-scan_id: Which scan this belongs to (Where applicable, e.g. for scanner logs)

"""
import json
import logging
import sys
from datetime import datetime, timezone


class JSONFormatter(logging.Formatter):
    """
    Formats every log record as a single JSON object on one line.

    Why one line per record? Log aggregation tools (Datadog, CloudWatch,
    Splunk) treat each line as one event. Multi-line logs break ingestion.
    JSON-per-line is the universal contract of structured logging.
    """

    def format(self, record: logging.LogRecord) -> str:
        # Base fields present on every log entry
        log_entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level": record.levelname,
            "logger": record.name,
            "event": record.getMessage(),
        }

        # The message can be either a plain string or a dict.
        # If it's a dict, merge its keys directly into the log entry
        # so callers can pass structured data naturally:
        #   logger.info({"event": "scan_started", "scan_id": "abc"})
        # instead of having to serialise manually.
        if isinstance(record.msg, dict):
            log_entry.update(record.msg)
        else:
            log_entry["event"] = str(record.msg)

        # Attach exception info if present -never silently drop tracebacks
        if record.exc_info:
            log_entry["exception"] = self.formatException(record.exc_info)

        return json.dumps(log_entry)
    

def setup_logging(level: str = "INFO") -> None:
    """
    Configure structured JSON logging for the entire application.

    Call this once at application startup — in main.py before the
    FastAPI app is created. All subsequent logger = getLogger(__name__)
    calls in every module will automatically use this configuration.

    Args:
        level: Minimum log level. "DEBUG" in development, "INFO" in production.
    """
    # Remove any existing handlers to avoid duplicate log entries
    # (common when running under uvicorn which sets up its own handlers)
    root_logger = logging.getLogger()
    root_logger.handlers.clear()

    # Single handler that writes to stderr (console) so logs flow naturally in containers
    # and are captured by any process supervisor (Docker, kubernetes, systemd, k8s, etc.)
    handler = logging.StreamHandler(sys.stderr)
    handler.setFormatter(JSONFormatter())

    root_logger.addHandler(handler)
    root_logger.setLevel(getattr(logging, level.upper(), logging.INFO))

    # Silence noisy third-party loggers that would pollute log stream
    # with irrelevant info (e.g. "INFO:urllib3.connectionpool:Starting new HTTPS connection")
    # uvicorn's access logs is redundant when you have structured route logging in main.py, 
    # and it can be very verbose, so we set it to WARNING to only capture potential issues.
    logging.getLogger("uvicorn.access").setLevel(logging.WARNING)
    logging.getLogger("uvicorn.error").setLevel(logging.WARNING)
 
"Nuclei Execution Logic"
import json
import logging
import subprocess
import sys
import threading
from datetime import datetime, timezone
from app.storage import save_scan_sync, SCAN_DIR   # sync writer — no asyncio.run()


logger = logging.getLogger(__name__)


def run_nuclei(scan_id: str, target_url: str):
    """Execute Nuclei scanner, stream results into storage and save them as they arrive."""

    started = datetime.now(timezone.utc)
    status = "failed"
    error = None
    results: list = []
    proc = None       # explicit None so the TimeoutExpired handler never hits NameError if proc is referenced before assignment

    
    logger.info(json.dumps({
        "event": "nuclei_scan_started",
        "scan_id": scan_id,
        "target": target_url,
        "timestamp": started.isoformat()
    }))

    # Write "in_progress" immediately -scan_target already wrote it, but this
    # acts as a confirmation that the thread actually started.
    save_scan_sync(scan_id, {
        "scan_id": scan_id,
        "target": target_url,
        "status": "in_progress",
        "timestamp": started.isoformat(),
        "error": None,
        "results": [],

    })


    command = [
        "nuclei",
        "-u", target_url,
        "-jsonl",
        "-rate-limit", "10",     # max 10 requests/sec (default is 150)
        "-timeout", "10",        # per-request timeout in seconds
        "-retries", "1",         # retry once before marking unresponsive
        "-c", "2",               # max 2 concurrent templates
        "-severity", "info,low,medium,high,critical",
        "-exclude", "CVE-2023-2986.yaml,CVE-2024-9487.yaml",
        "-nmhe",
        "-no-interactsh",
        "-exclude-tags", "sqli,sql,sql-injection,injection,blind,time-based,sleep,dos,fuzz,wordpress,wp,ssti,ssrf,oast,xxe,pmpro,apache,lfi,woocommerce",
        "-exclude-type", "code",
        "-disable-unsigned-templates",  
    ]

    
    try: 
        proc = subprocess.Popen(
            command, 
            stdout=subprocess.PIPE, 
            stderr=subprocess.PIPE, 
            text=True,
            creationflags=subprocess.CREATE_NEW_PROCESS_GROUP if sys.platform == "win32" else 0
        )


        # Drain stderr in a separate thread to prevent blocking if Nuclei produces a lot of output
        stderr_lines: list[str] = []

        def _drain_stderr(pipe):
            for line in pipe:
                stderr_lines.append(line)
                
        stderr_thread = threading.Thread(target=_drain_stderr, args=(proc.stderr,), daemon=True)
        stderr_thread.start()


        # ___STREAMING LOOP___
        # Read stdout one line at a time. Each line is a complete JSON finding.
        # This allows us to save results incrementally and update scan status in real-time, rather than waiting for the entire scan to finish.
        # save_scan_sync writes atomically after every finding so get_scan_status always returns a valid, up-to-date snapshot.
        # No asyncio.run() - no second event loop - no file-lock deadlock.
        deadline = started.timestamp() + 600  # 10 minute deadline


        for raw_line in proc.stdout:
            if datetime.now(timezone.utc).timestamp() > deadline:
                proc.kill()
                error = "Nuclei scan timed out after 10 minutes"
                logger.error(json.dumps({
                    "event": "scan_timeout",
                    "scan_id": scan_id,
                    "target": target_url,
                    "status": status,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }))
                break
            
            line = raw_line.strip()
            if not line:
                continue

            try:
                finding = json.loads(line)
                results.append(finding)

                # synchronous atomic write - safe from any thread
                save_scan_sync(scan_id, {
                    "scan_id": scan_id,
                    "target": target_url,
                    "status": status,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "error": None,
                    "results": results,
                })

            except json.JSONDecodeError:
                logger.warning(json.dumps({
                    "event": "invalid_json_line",
                    "scan_id": scan_id,
                    "target": target_url,
                    "line": line,
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }))

        # ___END STREAMING LOOP___

        proc.wait()
        stderr_thread.join(timeout=5)
        stderr = "".join(stderr_lines)

        if error is None: 
            if proc.returncode != 0:
                raise subprocess.CalledProcessError(proc.returncode, command, "", stderr)
            
            status = "completed"

        if stderr:
            logger.warning(json.dumps({
                "event": "nuclei_stderr_output",
                "scan_id": scan_id,
                "target": target_url,
                "status": status,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "stderr": stderr
            }))

    except subprocess.CalledProcessError as e:
        error = f"Nuclei scan failed with exit code: {e.returncode}"
        logger.error(json.dumps({
            "event": "scan_process_failed",
            "scan_id": scan_id,
            "target": target_url,
            "status": status,
            "returncode": e.returncode,
            "stderr": e.stderr,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }))
    
    except FileNotFoundError:
        error = "Nuclei not found in system PATH"
        logger.error(json.dumps({
            "event": "nuclei_not_found",
            "scan_id": scan_id,
            "target": target_url,
            "status": status,
            "error": error,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }))

    finally:
        # Write terminal state -synchronous, same as above 
        save_scan_sync(scan_id, {
            "scan_id":   scan_id,
            "target":    target_url,
            "status":    status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error":     error,
            "results":   results,
        })

        logger.info(json.dumps({
            "event": "nuclei_scan_finished",
            "scan_id": scan_id,
            "target": target_url,
            "status": status,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "error": error
        }))
# syntax=docker/dockerfile:1

# ___Stage 1:Build Nuclei___
# 
# We use the official Go image solely to compile Nuclei. This entire stage
# gets discarded after the build — its size (~1GB) never enters your final image.
#
# Why compile from source rather than downloading a release binary?
# go install always resolves @latest via the Go module proxy — no guessing
# GitHub release asset filenames, no URL that breaks when a new version drops.
# The binary is also guaranteed to match the current architecture (amd64/arm64).
#
# golang:1.25-alpine is used here because the Go Docker image
# registry follows a different versioning scheme than your local Go install.
# Always verify at hub.docker.com/r/golang/tags before changing this.
# Use Alpine variant pinned to a recent Alpine release to pick up security
# fixes in the base musl/OS packages while keeping a small image for the
# build stage.
# Use a more up-to-date Alpine variant to pick up security fixes
FROM golang:1.25-alpine AS nuclei-builder

# CGO_ENABLED=0 produces a fully static binary with zero shared library
# dependencies. This is critical for multi-stage builds — a binary compiled
# against Alpine's musl libc cannot run on Debian's glibc (which python:slim
# uses). A static binary runs anywhere regardless of the underlying libc.
ENV CGO_ENABLED=0

# Install git and CA certificates - some Go modules are fetched directly from
# git over HTTPS during go install and need trusted CAs to validate TLS.
RUN apk add --no-cache git ca-certificates \
    && update-ca-certificates

# Compile and install Nuclei. The binary lands at /go/bin/nuclei.
# This layer is cached — only re-runs when you explicitly change the version.
RUN go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@v3.9.0


# __Stage 2: Python runtime___
# python:3.13-slim is Debian-based with only the minimum packages needed
# to run Python. Not Alpine, because several Python packages (including
# some compiled extensions) require glibc. Using slim avoids the
# "no matching distribution found" errors that plague Alpine Python images.
FROM python:3.13-slim-bookworm AS final

# ── System dependencies ───────────────────────────────────────────────────────
#
# ca-certificates: Nuclei makes HTTPS requests to scan targets — without
#   trusted CA certificates those requests fail with SSL errors.
# git: Nuclei fetches and updates its vulnerability template library from
#   GitHub. Without git, template updates fail silently.
#
# --no-install-recommends: skips suggested packages, keeps image lean.
# dist-upgrade ensures the image installs the latest security updates for
# the underlying Debian packages before application dependencies are added.
# The final rm -rf clears the apt package cache which is never needed again.
RUN apt-get update && apt-get dist-upgrade -y --no-install-recommends \
    && apt-get install -y --no-install-recommends \
        ca-certificates \
        git \
    && rm -rf /var/lib/apt/lists/*


# ___Non-root user___
# 
# A vulnerability scanner is itself a high-value target — it runs arbitrary
# network requests against potentially hostile systems. If Nuclei finds a
# vulnerability that can be exploited during the scan itself (unlikely but
# not impossible), a non-root process limits blast radius enormously.
#
# -r creates a system user/group (no home directory, no shell, no login).
# Containers should never run as root unless they have no other option.
RUN groupadd -r scanner && useradd -r -g scanner scanner


# ___Working directory___
# 
# All subsequent COPY/RUN commands work relative to this path.
# /app is the conventional location for application code in containers.
WORKDIR /app

# ── Copy Nuclei binary from Stage 1 ──────────────────────────────────────────
#
# COPY --from=nuclei-builder copies from Stage 1's filesystem into Stage 2.
# We copy only the single compiled binary — the entire Go toolchain,
# module cache, and source files stay behind in Stage 1 and are discarded.
COPY --from=nuclei-builder /go/bin/nuclei /usr/local/bin/nuclei


# ── Python dependencies ───────────────────────────────────────────────────────
#
# COPY requirements.txt BEFORE app/ code. This is the critical layer caching
# trick: Docker rebuilds a layer only when its input changes. If you copy
# everything at once, ANY code change invalidates the pip install layer and
# reinstalls all packages on every build. Copying requirements.txt separately
# means pip only re-runs when dependencies actually change — code-only changes
# skip straight to COPY app/ which takes milliseconds not minutes.
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
# --no-cache-dir: pip's download cache is useless in a container — the layer
# itself IS the cache. --no-cache-dir saves ~50MB of image size per build.

# ── Application code ──────────────────────────────────────────────────────────
COPY app/ ./app/
COPY pytest.ini .

# ── Storage directory ─────────────────────────────────────────────────────────
#
# Create the scans/ directory and give ownership to the scanner user.
# MUST happen before USER scanner — chown needs root permissions.
# We create it here so the directory exists in the image layer,
# but in production you'll mount a volume over it (see docker-compose.yml)
# so scan data persists across container restarts.
RUN mkdir -p /app/scans && chown -R scanner:scanner /app

# ── Drop to non-root ──────────────────────────────────────────────────────────
#
# Every instruction after this line runs as scanner, not root.
# This applies to both the build and the running container.
USER scanner

# ── Expose port ───────────────────────────────────────────────────────────────
#
# EXPOSE is documentation — it doesn't actually publish the port.
# The actual publishing happens with -p 8000:8000 in docker run or
# under ports: in docker-compose.yml. EXPOSE tells humans and tools
# which port the application expects to receive traffic on.
EXPOSE 8000

# ── Health check ──────────────────────────────────────────────────────────────
#
# Docker polls this command every 30 seconds. If it fails 3 times
# consecutively, Docker marks the container unhealthy and (with Compose's
# depends_on: condition: service_healthy) won't route traffic to it.
#
# --start-period=10s: Don't count failures during the first 10 seconds.
# Uvicorn takes a moment to start — without this, Docker marks the
# container unhealthy before it's had a chance to initialise.
#
# We use Python's built-in urllib rather than curl because curl isn't
# installed in the slim image, and installing it just for healthchecks
# would add unnecessary bloat.
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD python -c \
    "import urllib.request; urllib.request.urlopen('http://localhost:8000/health')" \
    || exit 1


# ── Startup command ───────────────────────────────────────────────────────────
#
# Exec form (JSON array) is required here, not shell form ("uvicorn ...").
# Shell form runs: /bin/sh -c "uvicorn ..." which means SIGTERM from Docker
# goes to /bin/sh, not uvicorn. Uvicorn never receives the signal, your
# graceful shutdown handler never fires, and in-progress scans are killed
# without being marked failed.
# Exec form runs uvicorn directly as PID 1 — SIGTERM goes straight to it.
#
# --host 0.0.0.0 is required inside a container — the default 127.0.0.1
# binds to the container's loopback interface only, which is unreachable
# from outside the container even with port publishing.
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]

# ___Stage 3: Test image___
# 
# Inherits everything from the production image, but adds test dependencies and a test command.
# Same python, packages, Nuclei/binary, same OS and ONLY adds test infrastructure on top.
# This stage is used for CI/CD testing and is not used in production.
# 
# Why build from "final" not from scratch? Because we want to test the actual production image, not a separate build.
FROM final AS test

# Switch back to root temporarily to install test dependencies. We don't need to run tests as root, but installing packages requires root.
USER root

COPY requirements-test.txt .
RUN pip install --no-cache-dir -r requirements-test.txt

# Copy test files - not needed in production, only in this test stage.
COPY tests/ ./tests/

# Drop back to non-root for test execution. Tests should run as a non-root user to catch any permission issues that might arise in production.
USER scanner

# Default command for this stage is to run tests. This can be overridden in CI/CD pipelines if needed.
CMD ["python", "-m", "pytest", "tests/", "--tb=short", "-q"]

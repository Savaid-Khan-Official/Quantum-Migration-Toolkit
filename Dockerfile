# ============================================================================
# Dockerfile - QuantumMigrate PQC Auto-Migration Toolkit
# ============================================================================
# Multi-stage build for an optimized, minimal container.
#
# Build:
#   docker build -t quantum-migrate .
#
# Run (scan a local directory):
#   docker run --rm -v /path/to/code:/scan quantum-migrate /scan [options]
#
# Run with all features:
#   docker run --rm -v /path/to/code:/scan quantum-migrate \
#       /scan --entropy --proximity --remediate --format=sarif \
#       --vendor-into /scan --patch-build-system --backup
#
# Build with optional features:
#   docker build --build-arg USE_RE2=ON -t quantum-migrate .
# ============================================================================

# ---- Stage 1: Build ----
FROM alpine:3.20 AS builder

ARG USE_RE2=OFF

RUN apk add --no-cache \
    build-base \
    cmake \
    linux-headers \
    openssl-dev \
    git

# Install RE2 if requested
RUN if [ "$USE_RE2" = "ON" ]; then \
        apk add --no-cache re2-dev; \
    fi

WORKDIR /src

# Copy unified engine + CLI source
COPY CMakeLists.txt .
COPY engine/ engine/
COPY cli/ cli/

WORKDIR /src/build

RUN cmake .. \
    -DCMAKE_BUILD_TYPE=Release \
    -DUSE_RE2=${USE_RE2} \
    && cmake --build . --parallel $(nproc)

# ---- Stage 2: Runtime ----
FROM alpine:3.20

RUN apk add --no-cache libstdc++ libgcc openssl

# Install RE2 runtime lib if it was used at build time
ARG USE_RE2=OFF
RUN if [ "$USE_RE2" = "ON" ]; then \
        apk add --no-cache re2; \
    fi

# Create non-root user for security
RUN adduser -D scanner
USER scanner

COPY --from=builder /src/build/cli/quantum-migrate /usr/local/bin/quantum-migrate
COPY engine/rules.json /usr/local/share/quantum-migrate/rules.json

# Default: show help
ENTRYPOINT ["quantum-migrate"]
CMD ["--help"]

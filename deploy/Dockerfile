# Multi-stage production Dockerfile for FlowGuard Lite
# Produces a minimal Debian slim-based image with full glibc support for DuckDB.

# Stage 1: Build the Go application natively in a Debian environment
FROM golang:1.25-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Download Go dependencies
COPY go.mod ./
RUN go mod download

# Copy source code
COPY . .

# Compile Go binary with CGO enabled for DuckDB support
RUN CGO_ENABLED=1 GOOS=linux go build \
    -tags production \
    -ldflags="-s -w" \
    -o /app/flowguard \
    ./cmd/flowguard

# Stage 2: Minimal runtime image
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    ca-certificates \
    tzdata \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /

# Copy the compiled binary
COPY --from=builder /app/flowguard /usr/local/bin/flowguard

# Create directory for database storage and configuration
RUN mkdir -p /data

# Expose default communication ports
# - 8080: Web Dashboard & JSON REST API
# - 2055/udp: NetFlow / IPFIX collector
# - 6343/udp: sFlow collector
EXPOSE 8080 2055/udp 6343/udp

VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/flowguard"]
CMD ["-config", "/data/config.yaml"]


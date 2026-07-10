# Stage 1: Build the UI assets via Vite/Node
FROM node:22-bookworm AS ui-builder
WORKDIR /work
COPY web/package.json web/package-lock.json* ./web/
RUN cd web && npm install
COPY web/ ./web/
RUN cd web && npm run build

# Stage 2: Build the Go application natively in a Debian environment
FROM golang:1.25-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Download Go dependencies
COPY go.mod go.sum ./
RUN go mod download

# Copy source code
COPY . .

# Copy built UI assets from ui-builder stage
COPY --from=ui-builder /work/internal/ui/assets/dist /src/internal/ui/assets/dist

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
    libpcap0.8 \
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

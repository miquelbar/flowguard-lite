# Multi-stage production Dockerfile for FlowGuard Lite
# Produces a statically linked, minimal image containing ca-certificates.

# Stage 1: Build the Go application natively
FROM golang:1.25-alpine AS builder

WORKDIR /src

# Download Go dependencies
COPY go.mod ./
RUN go mod download

# Copy source code
COPY . .

# Compile Go binary statically with CGO disabled for maximum portability
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-s -w" \
    -o /app/flowguard \
    ./cmd/flowguard

# Stage 2: Minimal runtime image
FROM alpine:3.19

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /

# Copy the statically compiled binary
COPY --from=builder /app/flowguard /usr/local/bin/flowguard

# Create directory for SQLite daily shards and configuration
RUN mkdir -p /data

# Expose default communication ports
# - 8080: Web Dashboard & JSON REST API
# - 2055/udp: NetFlow / IPFIX collector
# - 6343/udp: sFlow collector
EXPOSE 8080 2055/udp 6343/udp

VOLUME ["/data"]

ENTRYPOINT ["/usr/local/bin/flowguard"]
CMD ["-config", "/data/config.yaml"]

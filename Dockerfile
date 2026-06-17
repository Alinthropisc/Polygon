# =============================================================================
# Polygon — Multi-stage Docker build
# =============================================================================
# NOTE: Raw socket methods (SYN, ICMP, AMP amplification) require elevated
# capabilities at runtime. Run with:
#   docker run --cap-add NET_RAW --cap-add NET_ADMIN polygon [args]
# =============================================================================

# -----------------------------------------------------------------------------
# Stage 1: Builder
# -----------------------------------------------------------------------------
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /build

# Copy dependency manifests first for layer caching
COPY go.mod go.sum ./
RUN go mod download

# Copy the rest of the source tree and build
COPY . .

# Raw sockets require Linux; target linux/amd64 explicitly
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -trimpath -ldflags="-s -w" -o bin/polygon ./cmd/polygon

# -----------------------------------------------------------------------------
# Stage 2: Final image
# -----------------------------------------------------------------------------
FROM alpine:3.21

RUN apk add --no-cache ca-certificates && \
    adduser -D -u 1000 polygon

COPY --from=builder /build/bin/polygon /usr/local/bin/polygon

# Polygon makes outbound connections; no inbound ports to expose.
# Grant NET_RAW / NET_ADMIN at runtime (see note at top of file).

USER polygon

ENTRYPOINT ["/usr/local/bin/polygon"]

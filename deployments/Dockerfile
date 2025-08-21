# ====================================================================
# EDR DETECTION ENGINE - DOCKERFILE
# ====================================================================
# Tác giả: Senior Software Engineer - EDR Platform Team
# Mô tả: Docker image cho EDR detection engine
# ====================================================================

# Build stage
FROM golang:1.21-alpine AS builder

# Install dependencies
RUN apk add --no-cache git ca-certificates tzdata

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build application
RUN CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o edr-detection-engine ./cmd/edr-server/

# Final stage
FROM alpine:latest

# Install ca-certificates và wget cho health check
RUN apk --no-cache add ca-certificates wget

# Create non-root user
RUN addgroup -g 1001 -S edr && \
    adduser -u 1001 -S edr -G edr

# Set working directory
WORKDIR /app

# Copy binary từ builder stage
COPY --from=builder /app/edr-detection-engine .

# Web templates removed (not needed currently)

# Create directories
RUN mkdir -p /app/rules /app/logs && \
    chown -R edr:edr /app

# Switch to non-root user
USER edr

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --no-verbose --tries=1 --spider http://localhost:8080/health || exit 1

# Run application
CMD ["./edr-detection-engine"]

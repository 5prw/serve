# Build stage
FROM golang:1.21-alpine AS builder

# Install build dependencies
RUN apk add --no-cache git make

# Set working directory
WORKDIR /app

# Copy go mod files
COPY go.mod ./

# Download dependencies
RUN go mod download

# Copy source code
COPY . .

# Build the application
RUN CGO_ENABLED=0 GOOS=linux go build -ldflags="-s -w -X main.version=docker" -o serve

# Runtime stage
FROM alpine:latest

# Install runtime dependencies
RUN apk --no-cache add ca-certificates tzdata

# Create non-root user
RUN addgroup -g 1000 serve && \
    adduser -D -u 1000 -G serve serve

# Set working directory
WORKDIR /app

# Copy binary from builder
COPY --from=builder /app/serve /app/serve

# Copy example config
COPY --from=builder /app/config.example.json /app/config.example.json

# Create directory for serving files
RUN mkdir -p /app/public && \
    chown -R serve:serve /app

# Switch to non-root user
USER serve

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD wget --no-verbose --tries=1 --spider http://localhost:8080/ || exit 1

# Run the application
ENTRYPOINT ["/app/serve"]
CMD ["-dir", "/app/public"]

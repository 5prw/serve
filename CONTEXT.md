# CONTEXT.md - Serve File Server

Complete development documentation, architecture decisions, and technical context for the Serve static file server project.

## Table of Contents

1. [Project Overview](#project-overview)
2. [Architecture](#architecture)
3. [File Structure](#file-structure)
4. [Core Components](#core-components)
5. [Design Decisions](#design-decisions)
6. [Security Implementation](#security-implementation)
7. [Performance Optimizations](#performance-optimizations)
8. [Configuration System](#configuration-system)
9. [Middleware Chain](#middleware-chain)
10. [Logging System](#logging-system)
11. [Future Enhancements](#future-enhancements)
12. [Development Guide](#development-guide)

---

## Project Overview

**Serve** is a production-ready static file server written in Go, designed to be a single-binary solution for serving files with advanced security, performance, and configuration options.

### Goals

- **Simplicity**: Single executable, no dependencies
- **Security**: Built-in protection against common attacks
- **Performance**: Efficient compression, caching, and resource handling
- **Flexibility**: Comprehensive configuration options
- **Production-Ready**: Suitable for development and production environments

### Why Go?

- **Single Binary**: Compiles to a single executable without runtime dependencies
- **Cross-Platform**: Native support for Linux, Windows, macOS, ARM
- **Performance**: Fast execution, low memory footprint
- **Standard Library**: Excellent HTTP server implementation built-in
- **Maintainability**: Simple, readable code with strong typing

---

## Architecture

### High-Level Architecture

```
┌─────────────────────────────────────────────────────────┐
│                     Client Request                       │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                   Middleware Chain                       │
│  ┌─────────────────────────────────────────────────┐   │
│  │ 1. Logging Middleware                           │   │
│  │ 2. Security Headers                             │   │
│  │ 3. Custom Headers                               │   │
│  │ 4. IP Filtering (Whitelist/Blacklist)          │   │
│  │ 5. Rate Limiting                                │   │
│  │ 6. Basic Authentication                         │   │
│  │ 7. CORS                                         │   │
│  │ 8. Path Traversal Protection                   │   │
│  │ 9. Hidden Files Blocking                       │   │
│  │ 10. Compression (Gzip)                         │   │
│  │ 11. Cache Headers                              │   │
│  └─────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                   File Handler                           │
│  ┌─────────────────────────────────────────────────┐   │
│  │ • Path Resolution                               │   │
│  │ • File/Directory Detection                      │   │
│  │ • Index File Serving                            │   │
│  │ • Directory Listing                             │   │
│  │ • SPA Mode Handling                             │   │
│  │ • ETag Generation                               │   │
│  │ • Error Pages                                   │   │
│  └─────────────────────────────────────────────────┘   │
└────────────────────────┬────────────────────────────────┘
                         │
                         ▼
┌─────────────────────────────────────────────────────────┐
│                    HTTP Response                         │
└─────────────────────────────────────────────────────────┘
```

### Component Diagram

```
┌──────────────┐
│   main.go    │  Entry point, CLI parsing, signal handling
└──────┬───────┘
       │
       ├─────────┐
       │         │
       ▼         ▼
┌──────────┐ ┌────────────┐
│config.go │ │ logger.go  │  Configuration & Logging subsystems
└────┬─────┘ └─────┬──────┘
     │             │
     └──────┬──────┘
            │
            ▼
      ┌──────────┐
      │server.go │  HTTP server setup & file handling
      └────┬─────┘
           │
           ▼
    ┌──────────────┐
    │middleware.go │  Security & performance middleware
    └──────────────┘
```

---

## File Structure

```
serve/
├── main.go                 # CLI entry point, flag parsing, application lifecycle
├── config.go               # Configuration structures and JSON loading
├── server.go               # HTTP server, file serving logic, directory listing
├── middleware.go           # All middleware implementations
├── logger.go               # Logging system with colors and levels
├── go.mod                  # Go module definition
├── config.example.json     # Example configuration file
├── index.html              # Demo/welcome page
├── Makefile                # Build automation
├── .gitignore              # Git ignore rules
├── LICENSE                 # MIT License
├── README.md               # English documentation
├── README.pt-BR.md         # Portuguese documentation
├── CONTEXT.md              # This file - development context
└── .github/
    └── workflows/
        └── release.yml     # GitHub Actions for automated releases
```

---

## Core Components

### 1. main.go

**Purpose**: Application entry point and CLI interface

**Key Responsibilities**:
- Parse command-line flags
- Load configuration from file or defaults
- Validate configuration
- Initialize logger and server
- Handle graceful shutdown (SIGINT, SIGTERM)

**Important Functions**:
- `main()`: Entry point, orchestrates initialization
- `loadConfiguration()`: Loads config from file or returns defaults
- `validateConfig()`: Validates all configuration options
- `printHelp()`: Displays help message

**Configuration Priority** (highest to lowest):
1. Command-line flags
2. Configuration file
3. Default values

### 2. config.go

**Purpose**: Configuration data structures and persistence

**Key Structures**:

```go
Config
├── Server       (ServerConfig)       # Host, port, root directory, timeouts
├── Security     (SecurityConfig)     # HTTPS, auth, CORS, rate limit, IP filtering
├── Performance  (PerformanceConfig)  # Compression, cache, ETags, headers
├── Logging      (LoggingConfig)      # Level, output, colors
└── Features     (FeaturesConfig)     # Directory listing, SPA mode, error pages
```

**Key Functions**:
- `DefaultConfig()`: Returns sensible defaults
- `LoadConfig()`: Loads from JSON file
- `SaveConfig()`: Saves to JSON file
- `GetReadTimeout()`, `GetWriteTimeout()`: Convert to time.Duration

**Design Decisions**:
- Uses pointer types for optional configs (BasicAuth, CORS, RateLimit)
- Falls back to defaults if file doesn't exist
- Supports partial configuration (merges with defaults)

### 3. server.go

**Purpose**: HTTP server setup and file serving logic

**Key Components**:

**Server struct**:
```go
type Server struct {
    config *Config
    logger *Logger
    mux    *http.ServeMux
}
```

**Key Functions**:
- `NewServer()`: Creates server instance
- `Start()`: Starts HTTP/HTTPS server
- `setupHandlers()`: Configures middleware chain
- `createFileHandler()`: Main file serving logic
- `serveDirectory()`: Directory handling (index files, listing)
- `serveFile()`: File serving with ETag support
- `serveSPAIndex()`: SPA mode handling
- `serveDirectoryListing()`: HTML directory listing
- `serveError()`: Custom error pages

**File Serving Logic**:
1. Clean and validate path
2. Check if file/directory exists
3. If directory: try index files → directory listing → 403
4. If file: serve with ETags and caching
5. If not found: SPA mode or 404

**Directory Listing**:
- Beautiful HTML template
- Sorts directories first, then files
- Shows file size and modification time
- Filters hidden files if configured
- Mobile-responsive design

### 4. middleware.go

**Purpose**: HTTP middleware for security and performance

**Available Middlewares**:

1. **LoggingMiddleware**: Request/response logging
2. **SecurityHeadersMiddleware**: X-Content-Type-Options, X-Frame-Options, X-XSS-Protection
3. **BlockHiddenFilesMiddleware**: Blocks access to files starting with "."
4. **PathTraversalMiddleware**: Prevents ".." in paths
5. **BasicAuthMiddleware**: HTTP Basic Authentication with constant-time comparison
6. **CORSMiddleware**: Cross-Origin Resource Sharing
7. **RateLimitMiddleware**: Token bucket rate limiting per IP
8. **IPFilterMiddleware**: IP whitelist/blacklist
9. **CompressionMiddleware**: Gzip compression
10. **CustomHeadersMiddleware**: User-defined headers
11. **CacheMiddleware**: Cache-Control headers

**Middleware Chain Pattern**:
```go
type Middleware func(http.Handler) http.Handler

func Chain(h http.Handler, middlewares ...Middleware) http.Handler {
    for i := len(middlewares) - 1; i >= 0; i-- {
        h = middlewares[i](h)
    }
    return h
}
```

**Rate Limiter Implementation**:
- Token bucket algorithm
- Per-IP tracking
- Configurable requests/minute and burst size
- Automatic cleanup of old entries
- Thread-safe with mutex

### 5. logger.go

**Purpose**: Logging system with colors and levels

**Features**:
- Color-coded console output (can be disabled)
- Multiple log levels: DEBUG, INFO, WARN, ERROR
- Separate access and error logs
- File output support (with multi-writer)
- Request logging with timing
- Beautiful startup banner

**Log Levels**:
- **DEBUG**: Development/troubleshooting
- **INFO**: Normal operations
- **WARN**: Warnings
- **ERROR**: Errors only

**Access Log Format**:
```
[timestamp] METHOD PATH - STATUS - DURATION - REMOTE_ADDR
```

**Colors**:
- Green: Success (2xx)
- Yellow: Client errors (4xx)
- Red: Server errors (5xx)
- Blue: Methods
- Cyan: Paths
- Gray: Timestamps/metadata

---

## Design Decisions

### 1. Why Go?

**Pros**:
- Compiles to single binary (easy distribution)
- Excellent standard library for HTTP
- Fast compilation and execution
- Great concurrency support
- Cross-platform by default

**Cons Considered**:
- Larger binary size than C/Rust (~12MB)
- Garbage collector (minimal impact for this use case)

**Decision**: Go's benefits far outweigh the cons for this use case.

### 2. Configuration Format: JSON

**Considered**: YAML, TOML, JSON

**Chosen**: JSON

**Reasons**:
- No external dependencies (encoding/json is stdlib)
- Universal format
- Good tooling support
- Simple to parse and generate

### 3. Middleware Pattern

**Pattern**: Function wrapping

**Reasons**:
- Composable
- Order-independent definition (chain determines order)
- Easy to add/remove middleware
- Standard Go idiom

### 4. Rate Limiting: Token Bucket

**Algorithm**: Token bucket (not sliding window, not fixed window)

**Reasons**:
- Allows bursts
- Simple implementation
- Fair resource distribution
- Memory efficient

### 5. Logging: Custom Logger vs. Library

**Decision**: Custom logger

**Reasons**:
- No external dependencies
- Full control over format
- Color support built-in
- Exactly what we need, nothing more

### 6. Hidden File Protection

**Implementation**: Path component checking (not regex)

**Reasons**:
- Faster than regex
- More secure (can't be bypassed with encoding tricks)
- Clearer intent

### 7. Path Traversal Protection

**Implementation**: filepath.Clean + ".." detection

**Reasons**:
- Standard library handles OS-specific path separators
- Simple and effective
- Catches encoded attempts

---

## Security Implementation

### 1. Path Traversal Protection

**Attack**: `../../etc/passwd`

**Defense**:
```go
cleanPath := filepath.Clean(r.URL.Path)
if strings.Contains(cleanPath, "..") {
    return 403
}
```

**Why it works**:
- `filepath.Clean` normalizes paths
- Explicit check for ".." catches any remaining attempts

### 2. Hidden Files Protection

**Attack**: `/.env`, `/.git/config`

**Defense**:
```go
parts := strings.Split(filepath.Clean(r.URL.Path), "/")
for _, part := range parts {
    if strings.HasPrefix(part, ".") && part != "." && part != ".." {
        return 403
    }
}
```

**Why it works**:
- Checks each path component separately
- Can't be bypassed with encoding

### 3. Basic Auth

**Attack**: Timing attacks to guess credentials

**Defense**:
```go
usernameMatch := subtle.ConstantTimeCompare([]byte(username), []byte(config.Username)) == 1
passwordMatch := subtle.ConstantTimeCompare([]byte(password), []byte(config.Password)) == 1
```

**Why it works**:
- `subtle.ConstantTimeCompare` prevents timing attacks
- Takes same time regardless of match position

### 4. Rate Limiting

**Attack**: DDoS, brute force

**Defense**: Token bucket per IP with configurable rate and burst

**Why it works**:
- Limits requests per time period
- Allows bursts for legitimate use
- Per-IP tracking prevents single attacker from consuming all resources

### 5. CORS

**Attack**: Cross-origin requests from unauthorized domains

**Defense**: Whitelist of allowed origins

**Why it works**:
- Only explicitly allowed origins can make requests
- Credentials only sent to trusted origins

### 6. Security Headers

**Headers Set**:
- `X-Content-Type-Options: nosniff` - Prevents MIME sniffing
- `X-Frame-Options: DENY` - Prevents clickjacking
- `X-XSS-Protection: 1; mode=block` - XSS protection

---

## Performance Optimizations

### 1. Gzip Compression

**Implementation**: Wrapping writer with gzip

**Benefit**: 60-90% size reduction for text files

**Configuration**: Compression level 1-9 (default: 6)

**Trade-offs**:
- Level 1: Fastest, lower compression
- Level 9: Slowest, best compression
- Level 6: Good balance

### 2. ETags

**Implementation**: `"modtime-size"` hash

**Benefit**: Client can skip downloads if file unchanged

**Flow**:
1. Generate ETag from file modtime and size
2. Client sends `If-None-Match` header
3. If matches: return 304 Not Modified
4. If different: send full file

### 3. Cache Headers

**Implementation**: `Cache-Control: public, max-age=N`

**Benefit**: Browsers cache files locally

**Configuration**: max-age in seconds (default: 3600)

### 4. Connection Timeouts

**Purpose**: Prevent resource exhaustion from slow clients

**Configuration**:
- Read timeout: 30s (default)
- Write timeout: 30s (default)

### 5. Memory Efficiency

**Techniques**:
- Streaming file serving (not loaded into memory)
- Gzip uses buffered writer
- Rate limiter cleanup goroutine
- No global state (thread-safe)

---

## Configuration System

### Configuration Hierarchy

```
Command-line flags > Config file > Defaults
```

### Default Configuration

**Philosophy**: Secure by default, convenient for development

**Defaults**:
- Port: 8080
- Host: 0.0.0.0
- Directory listing: OFF (security)
- Hidden file blocking: ON (security)
- Compression: ON (performance)
- Logging: ON
- HTTPS: OFF (requires cert)
- Authentication: OFF (requires credentials)

### Configuration Validation

**Validations**:
- Port range: 1-65535
- Root directory exists and is directory
- HTTPS requires cert and key files
- Basic auth requires username and password
- Compression level: 1-9
- Log level: debug, info, warn, error

---

## Middleware Chain

### Order Matters!

The middleware chain order is carefully designed:

1. **Logging**: First, to capture all requests
2. **Security Headers**: Early security
3. **Custom Headers**: User customization
4. **IP Filtering**: Block bad IPs early
5. **Rate Limiting**: Prevent abuse
6. **Authentication**: Verify identity
7. **CORS**: Cross-origin checks
8. **Path Traversal**: Path security
9. **Hidden Files**: File security
10. **Compression**: Last, compress final output
11. **Cache**: Last, set cache headers

**Why This Order**:
- Logging first captures everything
- Security checks before expensive operations
- Compression last to compress final output
- Cache last to set final headers

---

## Logging System

### Log Levels

```
DEBUG < INFO < WARN < ERROR
```

**Configuration**:
- `level: "debug"` - Shows everything
- `level: "info"` - Normal operation (default)
- `level: "warn"` - Warnings and errors
- `level: "error"` - Errors only

### Access Logs

**Format**:
```
[2025-10-28 14:30:15] GET /index.html - 200 - 15.2ms - 192.168.1.100
```

**Information**:
- Timestamp
- HTTP method
- Path
- Status code
- Response time
- Client IP

### Error Logs

**Format**:
```
[2025-10-28 14:30:15] [ERROR] Failed to open file: no such file or directory
```

### File Logging

**Implementation**:
```go
writer := io.MultiWriter(os.Stdout, file)
```

**Benefits**:
- Logs to both console and file
- File preserved after restart
- Console for live monitoring

---

## Future Enhancements

### Planned Features

1. **HTTP/2 Support**
   - Requires minimal changes (Go stdlib supports it)
   - Better performance for modern browsers

2. **Brotli Compression**
   - Better compression than gzip
   - Need to add external library

3. **WebDAV Support**
   - Upload/modify files
   - Useful for remote file management

4. **TLS Certificate Auto-Renewal**
   - Let's Encrypt integration
   - Automatic HTTPS

5. **Metrics/Prometheus**
   - Request counts
   - Response times
   - Active connections

6. **Graceful Reload**
   - Reload config without downtime
   - Signal-based (SIGHUP)

7. **Virtual Hosts**
   - Multiple sites on one server
   - Different configs per domain

8. **Access Control Lists (ACL)**
   - Fine-grained path permissions
   - User/group based access

9. **Request/Response Modification**
   - Rewrite rules
   - Header modification
   - Redirect rules

10. **Bandwidth Limiting**
    - Global bandwidth cap
    - Per-IP bandwidth limiting

### Technical Debt

None currently. Code is clean and well-structured.

### Performance Improvements

1. **Connection Pooling**: Already handled by Go's stdlib
2. **HTTP Caching**: Add Last-Modified support
3. **Static Compression**: Pre-compress common files
4. **Memory Mapping**: For very large files

---

## Development Guide

### Prerequisites

- Go 1.21 or higher
- Make (optional, for convenience)
- Git

### Building

```bash
# Development build
go build

# Production build (optimized)
go build -ldflags="-s -w"

# With version
go build -ldflags="-s -w -X main.version=v1.0.0"

# Using Make
make build
```

### Testing

```bash
# Run tests
go test -v ./...

# Run with coverage
go test -cover ./...

# Generate coverage HTML
go test -coverprofile=coverage.out ./...
go tool cover -html=coverage.out
```

### Code Style

- Use `gofmt` for formatting
- Run `go vet` for checks
- Consider `golangci-lint` for comprehensive linting

```bash
go fmt ./...
go vet ./...
golangci-lint run
```

### Adding a New Feature

1. **Update config.go**: Add configuration options
2. **Update middleware.go or server.go**: Implement feature
3. **Update main.go**: Add CLI flags if needed
4. **Update config.example.json**: Document new options
5. **Update README.md**: Document usage
6. **Update CONTEXT.md**: Document architecture changes

### Creating a Release

```bash
# Tag version
git tag -a v1.0.0 -m "Release v1.0.0"
git push origin v1.0.0

# GitHub Actions will automatically:
# - Build for all platforms
# - Create release archives
# - Upload to GitHub Releases
```

### Manual Multi-Platform Build

```bash
# Using Make
make build-all
make release-local

# Manual
GOOS=linux GOARCH=amd64 go build -o serve-linux-amd64
GOOS=darwin GOARCH=arm64 go build -o serve-darwin-arm64
GOOS=windows GOARCH=amd64 go build -o serve-windows-amd64.exe
```

### Debugging

**Enable debug logging**:
```json
{
  "logging": {
    "level": "debug"
  }
}
```

**Verbose request logging**:
- All middleware steps logged
- File access attempts
- Configuration loading

**Common Issues**:

1. **Port already in use**: Change port or kill existing process
2. **Permission denied**: Run with sudo (ports < 1024) or use higher port
3. **File not found**: Check root_dir is correct
4. **HTTPS cert errors**: Verify cert and key files exist

---

## Testing Scenarios

### Manual Testing Checklist

- [ ] Basic file serving
- [ ] Directory listing
- [ ] Index file serving
- [ ] SPA mode
- [ ] 404 pages
- [ ] Custom error pages
- [ ] Basic authentication
- [ ] CORS headers
- [ ] Rate limiting (use `ab` or `hey`)
- [ ] IP filtering
- [ ] Gzip compression (check headers)
- [ ] ETag support (conditional requests)
- [ ] HTTPS with self-signed cert
- [ ] Hidden file blocking
- [ ] Path traversal blocking
- [ ] Logging to file
- [ ] Configuration file loading
- [ ] CLI flag overrides

### Automated Testing (Future)

Create `server_test.go` with:
- Unit tests for each middleware
- Integration tests for file serving
- Security tests for attack vectors
- Performance benchmarks

---

## Production Deployment

### Systemd Service

Create `/etc/systemd/system/serve.service`:

```ini
[Unit]
Description=Serve Static File Server
After=network.target

[Service]
Type=simple
User=www-data
Group=www-data
WorkingDirectory=/var/www
ExecStart=/usr/local/bin/serve -config /etc/serve/config.json
Restart=on-failure
RestartSec=5s

[Install]
WantedBy=multi-user.target
```

Enable and start:
```bash
sudo systemctl enable serve
sudo systemctl start serve
sudo systemctl status serve
```

### Docker Deployment

See README.md for Dockerfile example.

### Reverse Proxy (Nginx)

```nginx
server {
    listen 80;
    server_name example.com;

    location / {
        proxy_pass http://localhost:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Security Hardening

1. Run as non-root user
2. Use HTTPS with valid certificates
3. Enable rate limiting
4. Set up IP whitelist if possible
5. Block hidden files
6. Use strong basic auth passwords
7. Keep server updated
8. Monitor logs for suspicious activity

---

## Metrics and Monitoring

### Key Metrics to Monitor

- Request rate (req/s)
- Response times (p50, p95, p99)
- Error rate (4xx, 5xx)
- Bandwidth usage
- Active connections
- Memory usage
- CPU usage

### Log Analysis

```bash
# Count requests by status code
cat serve.log | grep -oP '\d{3}' | sort | uniq -c

# Top requested paths
cat serve.log | grep -oP 'GET \K[^ ]+' | sort | uniq -c | sort -rn | head -10

# Slow requests (>1s)
cat serve.log | awk -F' - ' '$3 > 1000 {print}'
```

---

## Contributing Guidelines

### Code Review Checklist

- [ ] Code follows Go conventions
- [ ] All exports have documentation comments
- [ ] Configuration is backwards compatible
- [ ] Security implications considered
- [ ] Performance impact minimal
- [ ] Tests added (when test suite exists)
- [ ] Documentation updated (README, CONTEXT)
- [ ] Example config updated if needed

### Commit Message Format

```
<type>: <short description>

<detailed description>

<footer>
```

**Types**: feat, fix, docs, refactor, test, chore

**Example**:
```
feat: Add support for Brotli compression

Implements Brotli compression as an alternative to Gzip.
Can be enabled in config with "compression_type": "brotli".

Closes #42
```

---

## References

### Go Documentation

- [net/http](https://pkg.go.dev/net/http)
- [encoding/json](https://pkg.go.dev/encoding/json)
- [compress/gzip](https://pkg.go.dev/compress/gzip)
- [crypto/subtle](https://pkg.go.dev/crypto/subtle)

### Security Resources

- [OWASP Top 10](https://owasp.org/www-project-top-ten/)
- [Security Headers](https://securityheaders.com/)
- [HTTP Security Best Practices](https://httptoolkit.tech/blog/http-security-headers/)

### Performance Resources

- [Go Performance Tuning](https://github.com/dgryski/go-perfbook)
- [HTTP/2 in Go](https://go.dev/blog/h2push)

---

## License

MIT License - See LICENSE file

## Authors

- Initial implementation by Claude Code
- Maintained by the community

---

**Last Updated**: 2025-10-28
**Version**: 1.0.0

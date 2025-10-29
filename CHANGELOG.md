# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Planned
- HTTP/2 support
- Brotli compression
- WebDAV support
- Let's Encrypt integration
- Prometheus metrics
- Graceful configuration reload

## [1.0.0] - 2025-10-28

### Added
- Initial release
- Static file serving
- HTTP and HTTPS support
- Basic authentication
- CORS support with configurable origins
- Rate limiting per IP address
- IP whitelist and blacklist
- Path traversal protection
- Hidden file blocking
- Gzip compression with configurable levels (1-9)
- ETag support for efficient caching
- Cache-Control headers
- Custom HTTP headers
- Directory listing with beautiful HTML template
- SPA (Single Page Application) mode
- Custom index files
- Custom error pages
- Colored console logging
- Multiple log levels (debug, info, warn, error)
- Access and error logs
- File logging support
- JSON configuration file support
- Command-line flag support
- Configuration validation
- Graceful shutdown handling
- Security headers (X-Content-Type-Options, X-Frame-Options, X-XSS-Protection)
- Cross-platform compilation support
- GitHub Actions workflow for automated releases
- Comprehensive documentation (README in English and Portuguese)
- Developer documentation (CONTEXT.md)
- Example configuration file
- Makefile for easy building
- MIT License

### Security
- Constant-time comparison for authentication (prevents timing attacks)
- Path traversal protection with filepath.Clean
- Hidden file blocking for sensitive files (.env, .git, etc.)
- Rate limiting to prevent DDoS attacks
- IP filtering for access control
- Security headers by default
- HTTPS/TLS support

### Performance
- Gzip compression reduces bandwidth usage
- ETags reduce unnecessary file transfers
- Configurable cache headers
- Efficient streaming file serving (doesn't load files into memory)
- Token bucket rate limiting algorithm
- Automatic cleanup of rate limiter entries

## [0.1.0] - 2025-10-28

### Added
- Basic prototype
- Simple file serving
- Configuration structure

---

## Release Notes

### v1.0.0 - Initial Production Release

This is the first production-ready release of Serve, a static file server written in Go.

**Highlights**:
- Complete security features for production use
- High performance with compression and caching
- Flexible configuration via JSON or command-line
- Beautiful logging with colors
- Cross-platform support (Linux, Windows, macOS, ARM)
- Single binary with no dependencies

**Download**: See [Releases](https://github.com/5prw/serve/releases)

**Documentation**: See [README.md](README.md) and [CONTEXT.md](CONTEXT.md)

---

[Unreleased]: https://github.com/5prw/serve/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/5prw/serve/releases/tag/v1.0.0
[0.1.0]: https://github.com/5prw/serve/releases/tag/v0.1.0

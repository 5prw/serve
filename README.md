# Serve - Static File Server

A lightweight, fast, and feature-rich static file server written in Go. Perfect for development, testing, and production.

[Português](README.pt-BR.md)

## Features

### Core
- ✅ HTTP/HTTPS static file server
- ✅ Single executable with no dependencies
- ✅ Cross-platform (Linux, Windows, macOS)
- ✅ Configuration via JSON file or command-line flags
- ✅ Hot reload configuration

### Security
- 🔒 HTTPS/TLS support
- 🔒 Basic authentication (username/password)
- 🔒 Configurable CORS
- 🔒 Rate limiting per IP
- 🔒 IP whitelist/blacklist
- 🔒 Path traversal protection
- 🔒 Hidden file blocking (.env, .git, etc.)
- 🔒 Automatic security headers

### Performance
- ⚡ Gzip compression with configurable levels
- ⚡ ETags for efficient caching
- ⚡ Configurable cache headers
- ⚡ Custom HTTP headers
- ⚡ Configurable timeouts

### Features
- 📁 Optional directory listing
- 📄 Custom index files
- 🎯 SPA (Single Page Application) mode
- 🎨 Custom error pages
- 📊 Detailed colored logs
- 📝 Separate access and error logs

## Installation

### Download Pre-built Binaries

Download the latest release for your platform from the [releases page](https://github.com/5prw/serve/releases).

#### Linux/macOS
```bash
# Download and extract
tar -xzf serve-linux-amd64.tar.gz

# Make executable and move to PATH
chmod +x serve-linux-amd64
sudo mv serve-linux-amd64 /usr/local/bin/serve

# Verify installation
serve -version
```

#### Windows
```powershell
# Download and extract serve-windows-amd64.zip

# Add to PATH or run directly
.\serve-windows-amd64.exe -version
```

### Build from Source

```bash
git clone https://github.com/5prw/serve.git
cd serve
go build -o serve
```

### Using Make

```bash
# Build for current platform
make build

# Build for all platforms
make build-all

# Create release archives
make release-local

# See all options
make help
```

## Quick Start

### Basic Server

```bash
# Serve current directory on port 8080
./serve

# Serve a specific directory
./serve -dir /var/www

# Custom port
./serve -port 3000

# Enable directory listing
./serve -list
```

### Using Configuration File

```bash
# Generate example configuration
./serve -generate-config config.json

# Start with configuration
./serve -config config.json
```

## Configuration

### Configuration File

The configuration file uses JSON format. Complete example:

```json
{
  "server": {
    "port": 8080,
    "host": "0.0.0.0",
    "root_dir": ".",
    "read_timeout": 30,
    "write_timeout": 30
  },
  "security": {
    "enable_https": false,
    "cert_file": "/path/to/cert.pem",
    "key_file": "/path/to/key.pem",
    "basic_auth": {
      "enabled": true,
      "username": "admin",
      "password": "secret",
      "realm": "Restricted Area"
    },
    "cors": {
      "enabled": true,
      "allowed_origins": ["https://example.com"],
      "allowed_methods": ["GET", "POST", "OPTIONS"],
      "allowed_headers": ["*"],
      "allow_credentials": true,
      "max_age": 3600
    },
    "rate_limit": {
      "enabled": true,
      "requests_per_ip": 100,
      "burst_size": 20
    },
    "ip_whitelist": ["192.168.1.100", "10.0.0.50"],
    "ip_blacklist": ["192.168.1.200"],
    "block_hidden_files": true
  },
  "performance": {
    "enable_compression": true,
    "compression_level": 6,
    "enable_cache": true,
    "cache_max_age": 3600,
    "enable_etags": true,
    "custom_headers": {
      "X-Powered-By": "Serve"
    }
  },
  "logging": {
    "enabled": true,
    "level": "info",
    "access_log": true,
    "error_log": true,
    "log_file": "",
    "color_output": true
  },
  "features": {
    "directory_listing": false,
    "index_files": ["index.html", "index.htm"],
    "spa_mode": false,
    "spa_index": "index.html",
    "custom_error_pages": {
      "404": "404.html",
      "403": "403.html"
    }
  }
}
```

### Command-Line Options

```
  -config string
        Path to configuration file (JSON)

  -port int
        Port to listen on (overrides config)

  -host string
        Host to bind to (overrides config)

  -dir string
        Root directory to serve (overrides config)

  -list
        Enable directory listing

  -generate-config string
        Generate example config file and exit

  -version
        Show version and exit

  -help
        Show this help message
```

## Use Cases

### 1. Frontend Development

```bash
# Serve React/Vue/Angular app
./serve -dir ./dist -port 3000 -list
```

### 2. Single Page Application (SPA)

Create a `config.json`:

```json
{
  "server": {
    "port": 8080,
    "root_dir": "./dist"
  },
  "features": {
    "spa_mode": true,
    "spa_index": "index.html"
  }
}
```

```bash
./serve -config config.json
```

### 3. Server with Authentication

```json
{
  "server": {
    "port": 8080,
    "root_dir": "./files"
  },
  "security": {
    "basic_auth": {
      "enabled": true,
      "username": "admin",
      "password": "mypassword",
      "realm": "Private Files"
    },
    "block_hidden_files": true
  }
}
```

### 4. HTTPS Server

```bash
# Generate self-signed certificate for testing
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
```

```json
{
  "server": {
    "port": 8443,
    "root_dir": "."
  },
  "security": {
    "enable_https": true,
    "cert_file": "cert.pem",
    "key_file": "key.pem"
  }
}
```

### 5. API with CORS

```json
{
  "server": {
    "port": 8080,
    "root_dir": "./api"
  },
  "security": {
    "cors": {
      "enabled": true,
      "allowed_origins": ["http://localhost:3000", "https://myapp.com"],
      "allowed_methods": ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
      "allowed_headers": ["Content-Type", "Authorization"],
      "allow_credentials": true
    }
  }
}
```

### 6. Production Server with Rate Limiting

```json
{
  "server": {
    "port": 80,
    "root_dir": "/var/www/html"
  },
  "security": {
    "rate_limit": {
      "enabled": true,
      "requests_per_ip": 100,
      "burst_size": 20
    },
    "block_hidden_files": true
  },
  "performance": {
    "enable_compression": true,
    "compression_level": 9,
    "enable_cache": true,
    "cache_max_age": 86400,
    "enable_etags": true
  },
  "logging": {
    "enabled": true,
    "level": "info",
    "access_log": true,
    "error_log": true,
    "log_file": "/var/log/serve.log"
  }
}
```

## Security

### Best Practices

1. **Always block hidden files** in production:
   ```json
   "block_hidden_files": true
   ```

2. **Use HTTPS** in production:
   ```json
   "enable_https": true
   ```

3. **Implement rate limiting** to prevent DDoS attacks:
   ```json
   "rate_limit": {
     "enabled": true,
     "requests_per_ip": 100
   }
   ```

4. **Use authentication** for sensitive content:
   ```json
   "basic_auth": {
     "enabled": true,
     "username": "admin",
     "password": "strong-password"
   }
   ```

5. **Whitelist IPs** when possible:
   ```json
   "ip_whitelist": ["192.168.1.0/24"]
   ```

## Performance

### Optimizations

- **Compression**: Enable gzip to reduce response sizes
- **Cache**: Configure `cache_max_age` appropriately
- **ETags**: Reduces unnecessary transfers
- **Timeouts**: Configure to avoid hanging connections

### Benchmark

```bash
# Install benchmarking tool
go install github.com/rakyll/hey@latest

# Test performance
hey -n 10000 -c 100 http://localhost:8080/
```

## Example Logs

```
╔═══════════════════════════════════════╗
║                                       ║
║          SERVE - File Server          ║
║                                       ║
╚═══════════════════════════════════════╝

[2025-10-28 14:30:00] [INFO] Server starting...
[2025-10-28 14:30:00] [INFO] Protocol: HTTP
[2025-10-28 14:30:00] [INFO] Host: 0.0.0.0
[2025-10-28 14:30:00] [INFO] Port: 8080
[2025-10-28 14:30:00] [INFO] Root Directory: .
[2025-10-28 14:30:00] [INFO] Compression: Enabled (level 6)

[2025-10-28 14:30:00] [INFO] ✓ Server running at http://0.0.0.0:8080
[2025-10-28 14:30:00] [INFO] Press Ctrl+C to stop

[2025-10-28 14:30:15] GET /index.html - 200 - 15.2ms - 192.168.1.100
[2025-10-28 14:30:16] GET /style.css - 200 - 8.5ms - 192.168.1.100
[2025-10-28 14:30:17] GET /app.js - 200 - 12.1ms - 192.168.1.100
```

## Docker Support

Create a `Dockerfile`:

```dockerfile
FROM golang:1.21-alpine AS builder
WORKDIR /app
COPY . .
RUN go build -ldflags="-s -w" -o serve

FROM alpine:latest
RUN apk --no-cache add ca-certificates
WORKDIR /root/
COPY --from=builder /app/serve .
COPY --from=builder /app/config.example.json .
EXPOSE 8080
CMD ["./serve"]
```

Build and run:

```bash
docker build -t serve .
docker run -p 8080:8080 -v $(pwd):/root/files serve -dir /root/files
```

## Contributing

Contributions are welcome! Please:

1. Fork the project
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Development

See [CONTEXT.md](CONTEXT.md) for detailed development documentation, architecture decisions, and project structure.

## License

MIT License - see the [LICENSE](LICENSE) file for details.

## Support

- 🐛 [Bug Reports](https://github.com/5prw/serve/issues)
- 💡 [Feature Requests](https://github.com/5prw/serve/issues)
- 📖 [Documentation](https://github.com/5prw/serve/wiki)

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for a list of changes.

---

Made with ❤️ in Go

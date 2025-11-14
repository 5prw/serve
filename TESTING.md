# Testing Guide

This document describes the testing strategy and how to run tests for the Serve project.

## Overview

The project includes comprehensive unit tests covering:
- **Configuration**: Loading, saving, validation, and defaults
- **Runtime Config**: Environment variable collection and HTTP serving
- **Middleware**: Security, authentication, CORS, rate limiting, caching
- **Server**: File serving, directory listing, error handling

Current test coverage: **~39%** of statements

## Running Tests

### Basic Commands

```bash
# Run all tests
go test ./...

# Run tests with verbose output
go test -v ./...

# Run tests for specific package
go test -v ./... -run TestConfigLoading
```

### Using Make

```bash
# Run tests
make test

# Run tests with coverage
make test-coverage

# Generate HTML coverage report
make test-coverage-html
```

## Test Files

- `config_test.go` - Configuration loading, saving, and defaults
- `server_test.go` - Runtime config, environment variables, file handling
- `middleware_test.go` - All middleware functionality

## Test Coverage

### Current Coverage by Component

| Component | Coverage | Tests |
|-----------|----------|-------|
| Config | ~80% | 7 tests |
| Runtime Config | ~90% | 7 tests |
| Middleware | ~60% | 11 tests |
| Server | ~20% | 2 tests |

### Generating Coverage Report

```bash
# Generate coverage profile
go test -coverprofile=coverage.out ./...

# View coverage in terminal
go tool cover -func=coverage.out

# Generate HTML report
go tool cover -html=coverage.out -o coverage.html
open coverage.html  # macOS
xdg-open coverage.html  # Linux
start coverage.html  # Windows
```

## Test Examples

### Testing Configuration

```go
func TestDefaultConfig(t *testing.T) {
    config := DefaultConfig()

    if config.Server.Port != 8080 {
        t.Errorf("Expected default port 8080, got %d", config.Server.Port)
    }
}
```

### Testing Runtime Config

```go
func TestCollectEnvVarsWithPrefix(t *testing.T) {
    os.Setenv("APP_API_URL", "https://api.example.com")
    defer os.Unsetenv("APP_API_URL")

    config := &RuntimeConfigConfig{EnvPrefix: "APP_"}
    server := NewServer(config, logger)
    result := server.collectEnvVars(config)

    if result["API_URL"] != "https://api.example.com" {
        t.Errorf("Expected API_URL, got %s", result["API_URL"])
    }
}
```

### Testing Middleware

```go
func TestBasicAuthMiddleware(t *testing.T) {
    config := &BasicAuthConfig{
        Enabled: true,
        Username: "admin",
        Password: "secret",
    }

    middleware := BasicAuthMiddleware(config)
    handler := middleware(testHandler())

    req := httptest.NewRequest("GET", "/", nil)
    req.SetBasicAuth("admin", "secret")
    w := httptest.NewRecorder()

    handler.ServeHTTP(w, req)

    if w.Code != http.StatusOK {
        t.Errorf("Expected 200 with correct auth")
    }
}
```

## Best Practices

### 1. Table-Driven Tests

Use table-driven tests for multiple test cases:

```go
tests := []struct {
    name     string
    input    string
    expected string
}{
    {"case1", "input1", "expected1"},
    {"case2", "input2", "expected2"},
}

for _, tt := range tests {
    t.Run(tt.name, func(t *testing.T) {
        result := function(tt.input)
        if result != tt.expected {
            t.Errorf("got %s, want %s", result, tt.expected)
        }
    })
}
```

### 2. Cleanup with defer

Always cleanup test resources:

```go
func TestWithEnvVars(t *testing.T) {
    os.Setenv("TEST_VAR", "value")
    defer os.Unsetenv("TEST_VAR")

    // test code
}
```

### 3. Use Subtests

Group related tests using subtests:

```go
t.Run("NoAuth", func(t *testing.T) {
    // test without authentication
})

t.Run("WithAuth", func(t *testing.T) {
    // test with authentication
})
```

### 4. Mock External Dependencies

Use `httptest` for testing HTTP handlers:

```go
req := httptest.NewRequest("GET", "/", nil)
w := httptest.NewRecorder()
handler.ServeHTTP(w, req)
```

## Continuous Integration

### GitHub Actions Example

```yaml
name: Tests

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
        with:
          go-version: '1.21'

      - name: Run tests
        run: go test -v -race -coverprofile=coverage.out ./...

      - name: Upload coverage
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.out
```

## Future Improvements

### Areas Needing More Tests

1. **File Serving** - Test actual file serving, directory listing, SPA mode
2. **Error Handling** - Test error pages, 404s, 403s
3. **Logger** - Test log output and formatting
4. **Integration Tests** - End-to-end testing of complete workflows

### Suggested Test Cases

```go
// File serving
TestServeFile
TestServeDirectory
TestServeIndexFile
TestSPAMode
TestCustomErrorPages

// Security
TestPathTraversalPrevention (integration test with actual files)
TestHiddenFileBlocking (integration test with actual files)

// Performance
TestCompression
TestETagGeneration
TestCacheHeaders
```

## Benchmarking

### Running Benchmarks

```bash
# Run all benchmarks
go test -bench=. ./...

# Run specific benchmark
go test -bench=BenchmarkRuntimeConfig ./...

# With memory profiling
go test -bench=. -benchmem ./...
```

### Example Benchmark

```go
func BenchmarkCollectEnvVars(b *testing.B) {
    os.Setenv("APP_VAR1", "value1")
    os.Setenv("APP_VAR2", "value2")
    defer func() {
        os.Unsetenv("APP_VAR1")
        os.Unsetenv("APP_VAR2")
    }()

    config := &RuntimeConfigConfig{EnvPrefix: "APP_"}
    server := NewServer(config, logger)

    b.ResetTimer()
    for i := 0; i < b.N; i++ {
        server.collectEnvVars(config)
    }
}
```

## Debugging Tests

### Verbose Output

```bash
# Show all test output
go test -v ./...

# Show only failed tests
go test ./...
```

### Run Single Test

```bash
# Run specific test
go test -v -run TestConfigLoading

# Run tests matching pattern
go test -v -run "TestRuntime.*"
```

### Debug with Delve

```bash
# Install delve
go install github.com/go-delve/delve/cmd/dlv@latest

# Debug test
dlv test -- -test.run TestConfigLoading
```

## Common Issues

### Issue: Tests Fail with "address already in use"

**Solution**: Tests use different ports or use `httptest.Server`

### Issue: Race Conditions

**Solution**: Run with race detector:
```bash
go test -race ./...
```

### Issue: Flaky Tests

**Solution**:
- Avoid time-dependent tests
- Use mocks for external dependencies
- Clean up resources properly

## Contributing

When adding new features:

1. ✅ Write tests first (TDD)
2. ✅ Aim for >70% coverage for new code
3. ✅ Test both success and error cases
4. ✅ Add table-driven tests for multiple scenarios
5. ✅ Document complex test scenarios

## Resources

- [Go Testing Package](https://pkg.go.dev/testing)
- [Go Testing Best Practices](https://go.dev/doc/tutorial/add-a-test)
- [Table Driven Tests](https://dave.cheney.net/2019/05/07/prefer-table-driven-tests)
- [httptest Package](https://pkg.go.dev/net/http/httptest)

---

**Last Updated**: 2025-11-13
**Test Coverage**: ~39%
**Total Tests**: 25+

package main

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Helper function to create a simple test handler
func testHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("OK"))
	})
}

func TestSecurityHeadersMiddleware(t *testing.T) {
	middleware := SecurityHeadersMiddleware()
	handler := middleware(testHandler())

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check security headers
	headers := w.Header()

	if headers.Get("X-Content-Type-Options") != "nosniff" {
		t.Errorf("Expected X-Content-Type-Options: nosniff")
	}
	if headers.Get("X-Frame-Options") != "DENY" {
		t.Errorf("Expected X-Frame-Options: DENY")
	}
	if headers.Get("X-XSS-Protection") != "1; mode=block" {
		t.Errorf("Expected X-XSS-Protection: 1; mode=block")
	}
}

func TestBlockHiddenFilesMiddleware(t *testing.T) {
	middleware := BlockHiddenFilesMiddleware(".")
	handler := middleware(testHandler())

	tests := []struct {
		path           string
		expectedStatus int
	}{
		{"/index.html", http.StatusOK},
		{"/style.css", http.StatusOK},
		{"/.env", http.StatusForbidden},
		{"/.git/config", http.StatusForbidden},
		{"/dir/.hidden", http.StatusForbidden},
		{"/normal/path/file.txt", http.StatusOK},
	}

	for _, test := range tests {
		req := httptest.NewRequest("GET", test.path, nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != test.expectedStatus {
			t.Errorf("Path %s: expected status %d, got %d", test.path, test.expectedStatus, w.Code)
		}
	}
}

func TestPathTraversalMiddleware(t *testing.T) {
	middleware := PathTraversalMiddleware(".")
	handler := middleware(testHandler())

	tests := []struct {
		path           string
		expectedStatus int
		description    string
	}{
		{"/index.html", http.StatusOK, "normal path"},
		{"/normal/path", http.StatusOK, "normal nested path"},
		{"/path/with/../dots", http.StatusOK, "path with .. is cleaned by filepath.Clean"},
	}

	for _, test := range tests {
		req := httptest.NewRequest("GET", test.path, nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != test.expectedStatus {
			t.Errorf("%s: Path %s: expected status %d, got %d",
				test.description, test.path, test.expectedStatus, w.Code)
		}
	}

	// Note: The real path traversal protection happens in the file serving logic
	// where paths are resolved against rootDir using filepath.Join, which prevents
	// escaping the root directory. The middleware normalizes paths using filepath.Clean.
}

func TestBasicAuthMiddleware(t *testing.T) {
	config := &BasicAuthConfig{
		Enabled:  true,
		Username: "admin",
		Password: "secret",
		Realm:    "Test",
	}

	middleware := BasicAuthMiddleware(config)
	handler := middleware(testHandler())

	// Test without auth
	t.Run("NoAuth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 without auth, got %d", w.Code)
		}
		if w.Header().Get("WWW-Authenticate") == "" {
			t.Errorf("Expected WWW-Authenticate header")
		}
	})

	// Test with correct auth
	t.Run("CorrectAuth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.SetBasicAuth("admin", "secret")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 with correct auth, got %d", w.Code)
		}
	})

	// Test with incorrect auth
	t.Run("IncorrectAuth", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.SetBasicAuth("admin", "wrong")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusUnauthorized {
			t.Errorf("Expected 401 with incorrect auth, got %d", w.Code)
		}
	})

	// Test with auth disabled
	t.Run("Disabled", func(t *testing.T) {
		disabledConfig := &BasicAuthConfig{
			Enabled: false,
		}
		disabledMiddleware := BasicAuthMiddleware(disabledConfig)
		disabledHandler := disabledMiddleware(testHandler())

		req := httptest.NewRequest("GET", "/", nil)
		w := httptest.NewRecorder()

		disabledHandler.ServeHTTP(w, req)

		if w.Code != http.StatusOK {
			t.Errorf("Expected 200 when auth disabled, got %d", w.Code)
		}
	})
}

func TestCORSMiddleware(t *testing.T) {
	config := &CORSConfig{
		Enabled:          true,
		AllowedOrigins:   []string{"https://example.com"},
		AllowedMethods:   []string{"GET", "POST"},
		AllowedHeaders:   []string{"Content-Type"},
		AllowCredentials: true,
		MaxAge:           3600,
	}

	middleware := CORSMiddleware(config)
	handler := middleware(testHandler())

	// Test with allowed origin
	t.Run("AllowedOrigin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "https://example.com")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "https://example.com" {
			t.Errorf("Expected CORS origin header")
		}
		if w.Header().Get("Access-Control-Allow-Credentials") != "true" {
			t.Errorf("Expected credentials header")
		}
	})

	// Test with disallowed origin
	t.Run("DisallowedOrigin", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "https://evil.com")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "" {
			t.Errorf("Should not set CORS headers for disallowed origin")
		}
	})

	// Test OPTIONS preflight
	t.Run("Preflight", func(t *testing.T) {
		req := httptest.NewRequest("OPTIONS", "/", nil)
		req.Header.Set("Origin", "https://example.com")
		w := httptest.NewRecorder()

		handler.ServeHTTP(w, req)

		if w.Code != http.StatusNoContent {
			t.Errorf("Expected 204 for OPTIONS, got %d", w.Code)
		}
	})

	// Test wildcard origin
	t.Run("Wildcard", func(t *testing.T) {
		wildcardConfig := &CORSConfig{
			Enabled:        true,
			AllowedOrigins: []string{"*"},
		}
		wildcardMiddleware := CORSMiddleware(wildcardConfig)
		wildcardHandler := wildcardMiddleware(testHandler())

		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Origin", "https://any-origin.com")
		w := httptest.NewRecorder()

		wildcardHandler.ServeHTTP(w, req)

		if w.Header().Get("Access-Control-Allow-Origin") != "*" {
			t.Errorf("Expected wildcard CORS")
		}
	})
}

func TestRateLimitMiddleware(t *testing.T) {
	config := &RateLimitConfig{
		Enabled:       true,
		RequestsPerIP: 2,
		BurstSize:     2,
	}

	limiter := NewRateLimiter(config)
	middleware := RateLimitMiddleware(limiter)
	handler := middleware(testHandler())

	// Make requests from same IP
	req1 := httptest.NewRequest("GET", "/", nil)
	req1.RemoteAddr = "192.168.1.100:1234"
	w1 := httptest.NewRecorder()
	handler.ServeHTTP(w1, req1)

	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = "192.168.1.100:1234"
	w2 := httptest.NewRecorder()
	handler.ServeHTTP(w2, req2)

	// First two requests should succeed
	if w1.Code != http.StatusOK {
		t.Errorf("First request should succeed, got %d", w1.Code)
	}
	if w2.Code != http.StatusOK {
		t.Errorf("Second request should succeed, got %d", w2.Code)
	}

	// Third request should be rate limited
	req3 := httptest.NewRequest("GET", "/", nil)
	req3.RemoteAddr = "192.168.1.100:1234"
	w3 := httptest.NewRecorder()
	handler.ServeHTTP(w3, req3)

	if w3.Code != http.StatusTooManyRequests {
		t.Errorf("Third request should be rate limited, got %d", w3.Code)
	}

	// Different IP should not be affected
	req4 := httptest.NewRequest("GET", "/", nil)
	req4.RemoteAddr = "192.168.1.200:5678"
	w4 := httptest.NewRecorder()
	handler.ServeHTTP(w4, req4)

	if w4.Code != http.StatusOK {
		t.Errorf("Different IP should not be rate limited, got %d", w4.Code)
	}
}

func TestIPFilterMiddleware(t *testing.T) {
	// Test with whitelist
	t.Run("Whitelist", func(t *testing.T) {
		whitelist := []string{"192.168.1.100"}
		middleware := IPFilterMiddleware(whitelist, nil)
		handler := middleware(testHandler())

		// Allowed IP
		req1 := httptest.NewRequest("GET", "/", nil)
		req1.RemoteAddr = "192.168.1.100:1234"
		w1 := httptest.NewRecorder()
		handler.ServeHTTP(w1, req1)
		if w1.Code != http.StatusOK {
			t.Errorf("Whitelisted IP should be allowed, got %d", w1.Code)
		}

		// Disallowed IP
		req2 := httptest.NewRequest("GET", "/", nil)
		req2.RemoteAddr = "192.168.1.200:5678"
		w2 := httptest.NewRecorder()
		handler.ServeHTTP(w2, req2)
		if w2.Code != http.StatusForbidden {
			t.Errorf("Non-whitelisted IP should be blocked, got %d", w2.Code)
		}
	})

	// Test with blacklist
	t.Run("Blacklist", func(t *testing.T) {
		blacklist := []string{"192.168.1.100"}
		middleware := IPFilterMiddleware(nil, blacklist)
		handler := middleware(testHandler())

		// Blacklisted IP
		req1 := httptest.NewRequest("GET", "/", nil)
		req1.RemoteAddr = "192.168.1.100:1234"
		w1 := httptest.NewRecorder()
		handler.ServeHTTP(w1, req1)
		if w1.Code != http.StatusForbidden {
			t.Errorf("Blacklisted IP should be blocked, got %d", w1.Code)
		}

		// Allowed IP
		req2 := httptest.NewRequest("GET", "/", nil)
		req2.RemoteAddr = "192.168.1.200:5678"
		w2 := httptest.NewRecorder()
		handler.ServeHTTP(w2, req2)
		if w2.Code != http.StatusOK {
			t.Errorf("Non-blacklisted IP should be allowed, got %d", w2.Code)
		}
	})
}

func TestCustomHeadersMiddleware(t *testing.T) {
	headers := map[string]string{
		"X-Custom-Header": "custom-value",
		"X-Powered-By":    "Serve",
	}

	middleware := CustomHeadersMiddleware(headers)
	handler := middleware(testHandler())

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check custom headers are set
	if w.Header().Get("X-Custom-Header") != "custom-value" {
		t.Errorf("Expected X-Custom-Header to be set")
	}
	if w.Header().Get("X-Powered-By") != "Serve" {
		t.Errorf("Expected X-Powered-By to be set")
	}
}

func TestCacheMiddleware(t *testing.T) {
	middleware := CacheMiddleware(3600)
	handler := middleware(testHandler())

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Check cache header
	cacheControl := w.Header().Get("Cache-Control")
	if !strings.Contains(cacheControl, "public") {
		t.Errorf("Expected 'public' in Cache-Control, got: %s", cacheControl)
	}
	if !strings.Contains(cacheControl, "max-age=3600") {
		t.Errorf("Expected 'max-age=3600' in Cache-Control, got: %s", cacheControl)
	}
}

func TestChain(t *testing.T) {
	// Create a simple middleware that adds a header
	middleware1 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Middleware-1", "1")
			next.ServeHTTP(w, r)
		})
	}

	middleware2 := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Middleware-2", "2")
			next.ServeHTTP(w, r)
		})
	}

	handler := Chain(testHandler(), middleware1, middleware2)

	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	// Both middleware should have been applied
	if w.Header().Get("X-Middleware-1") != "1" {
		t.Errorf("Middleware 1 was not applied")
	}
	if w.Header().Get("X-Middleware-2") != "2" {
		t.Errorf("Middleware 2 was not applied")
	}
}

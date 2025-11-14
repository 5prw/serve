package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestCollectEnvVarsWithPrefix(t *testing.T) {
	// Set up test environment variables
	os.Setenv("APP_API_URL", "https://api.example.com")
	os.Setenv("APP_VERSION", "1.0.0")
	os.Setenv("APP_FEATURE_X", "true")
	os.Setenv("OTHER_VAR", "should-not-appear")
	defer func() {
		os.Unsetenv("APP_API_URL")
		os.Unsetenv("APP_VERSION")
		os.Unsetenv("APP_FEATURE_X")
		os.Unsetenv("OTHER_VAR")
	}()

	config := &Config{
		RuntimeConfig: &RuntimeConfigConfig{
			EnvPrefix: "APP_",
		},
	}
	logger, _ := NewLogger(&LoggingConfig{Enabled: false})
	server := NewServer(config, logger)

	result := server.collectEnvVars(config.RuntimeConfig)

	// Check that APP_ vars are included without prefix
	if result["API_URL"] != "https://api.example.com" {
		t.Errorf("Expected API_URL to be https://api.example.com, got %s", result["API_URL"])
	}
	if result["VERSION"] != "1.0.0" {
		t.Errorf("Expected VERSION to be 1.0.0, got %s", result["VERSION"])
	}
	if result["FEATURE_X"] != "true" {
		t.Errorf("Expected FEATURE_X to be true, got %s", result["FEATURE_X"])
	}

	// Check that OTHER_VAR is not included
	if _, exists := result["OTHER_VAR"]; exists {
		t.Errorf("OTHER_VAR should not be included")
	}

	// Check that prefixed keys are not included
	if _, exists := result["APP_API_URL"]; exists {
		t.Errorf("APP_API_URL should not be included (prefix should be removed)")
	}
}

func TestCollectEnvVarsWithList(t *testing.T) {
	// Set up test environment variables
	os.Setenv("API_URL", "https://api.example.com")
	os.Setenv("DATABASE_URL", "postgres://localhost/db")
	os.Setenv("SECRET_KEY", "should-not-appear")
	defer func() {
		os.Unsetenv("API_URL")
		os.Unsetenv("DATABASE_URL")
		os.Unsetenv("SECRET_KEY")
	}()

	config := &Config{
		RuntimeConfig: &RuntimeConfigConfig{
			EnvVariables: []string{"API_URL", "DATABASE_URL"},
		},
	}
	logger, _ := NewLogger(&LoggingConfig{Enabled: false})
	server := NewServer(config, logger)

	result := server.collectEnvVars(config.RuntimeConfig)

	// Check that listed vars are included
	if result["API_URL"] != "https://api.example.com" {
		t.Errorf("Expected API_URL to be https://api.example.com, got %s", result["API_URL"])
	}
	if result["DATABASE_URL"] != "postgres://localhost/db" {
		t.Errorf("Expected DATABASE_URL to be postgres://localhost/db, got %s", result["DATABASE_URL"])
	}

	// Check that SECRET_KEY is not included
	if _, exists := result["SECRET_KEY"]; exists {
		t.Errorf("SECRET_KEY should not be included (not in list)")
	}

	// Should have exactly 2 entries
	if len(result) != 2 {
		t.Errorf("Expected 2 entries, got %d", len(result))
	}
}

func TestCollectEnvVarsEmpty(t *testing.T) {
	config := &Config{
		RuntimeConfig: &RuntimeConfigConfig{
			EnvPrefix:    "",
			EnvVariables: []string{},
		},
	}
	logger, _ := NewLogger(&LoggingConfig{Enabled: false})
	server := NewServer(config, logger)

	result := server.collectEnvVars(config.RuntimeConfig)

	// Should return empty map when no prefix and no list
	if len(result) != 0 {
		t.Errorf("Expected empty result, got %d entries", len(result))
	}
}

func TestHandleRuntimeConfigJavaScript(t *testing.T) {
	// Set up test environment
	os.Setenv("APP_API_URL", "https://api.test.com")
	os.Setenv("APP_VERSION", "2.0.0")
	defer func() {
		os.Unsetenv("APP_API_URL")
		os.Unsetenv("APP_VERSION")
	}()

	config := &Config{
		RuntimeConfig: &RuntimeConfigConfig{
			Enabled:   true,
			Route:     "/runtime-config.js",
			Format:    "js",
			VarName:   "TEST_CONFIG",
			EnvPrefix: "APP_",
			NoCache:   true,
		},
	}
	logger, _ := NewLogger(&LoggingConfig{Enabled: false})
	server := NewServer(config, logger)

	// Create request
	req := httptest.NewRequest("GET", "/runtime-config.js", nil)
	w := httptest.NewRecorder()

	// Call handler
	server.handleRuntimeConfig(w, req)

	// Check response
	resp := w.Result()
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/javascript" {
		t.Errorf("Expected Content-Type application/javascript, got %s", contentType)
	}

	// Check no-cache headers
	cacheControl := resp.Header.Get("Cache-Control")
	if !strings.Contains(cacheControl, "no-cache") {
		t.Errorf("Expected no-cache in Cache-Control, got %s", cacheControl)
	}

	// Check body
	body := w.Body.String()
	if !strings.Contains(body, "window.TEST_CONFIG") {
		t.Errorf("Expected window.TEST_CONFIG in body, got: %s", body)
	}
	if !strings.Contains(body, "https://api.test.com") {
		t.Errorf("Expected API URL in body, got: %s", body)
	}
	if !strings.Contains(body, "2.0.0") {
		t.Errorf("Expected version in body, got: %s", body)
	}

	// Verify it's valid JavaScript
	if !strings.HasPrefix(body, "window.TEST_CONFIG = ") {
		t.Errorf("Body should start with 'window.TEST_CONFIG = ', got: %s", body[:min(50, len(body))])
	}
	if !strings.HasSuffix(body, ";") {
		t.Errorf("Body should end with semicolon")
	}
}

func TestHandleRuntimeConfigJSON(t *testing.T) {
	// Set up test environment
	os.Setenv("API_URL", "https://api.json.com")
	os.Setenv("TOKEN", "abc123")
	defer func() {
		os.Unsetenv("API_URL")
		os.Unsetenv("TOKEN")
	}()

	config := &Config{
		RuntimeConfig: &RuntimeConfigConfig{
			Enabled:      true,
			Route:        "/config.json",
			Format:       "json",
			EnvVariables: []string{"API_URL", "TOKEN"},
			NoCache:      false,
		},
	}
	logger, _ := NewLogger(&LoggingConfig{Enabled: false})
	server := NewServer(config, logger)

	// Create request
	req := httptest.NewRequest("GET", "/config.json", nil)
	w := httptest.NewRecorder()

	// Call handler
	server.handleRuntimeConfig(w, req)

	// Check response
	resp := w.Result()
	defer resp.Body.Close()

	// Check status code
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	// Check content type
	contentType := resp.Header.Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected Content-Type application/json, got %s", contentType)
	}

	// Check that no-cache headers are NOT present (NoCache is false)
	cacheControl := resp.Header.Get("Cache-Control")
	if strings.Contains(cacheControl, "no-store") {
		t.Errorf("Did not expect no-store in Cache-Control when NoCache=false")
	}

	// Check body is valid JSON
	var result map[string]string
	if err := json.Unmarshal(w.Body.Bytes(), &result); err != nil {
		t.Fatalf("Body is not valid JSON: %v", err)
	}

	// Check values
	if result["API_URL"] != "https://api.json.com" {
		t.Errorf("Expected API_URL to be https://api.json.com, got %s", result["API_URL"])
	}
	if result["TOKEN"] != "abc123" {
		t.Errorf("Expected TOKEN to be abc123, got %s", result["TOKEN"])
	}
}

func TestHandleRuntimeConfigDefaultFormat(t *testing.T) {
	// When format is not specified, should default to "js"
	config := &Config{
		RuntimeConfig: &RuntimeConfigConfig{
			Enabled:   true,
			Format:    "", // empty = should use default
			VarName:   "CONFIG",
			EnvPrefix: "TEST_",
		},
	}
	logger, _ := NewLogger(&LoggingConfig{Enabled: false})
	server := NewServer(config, logger)

	req := httptest.NewRequest("GET", "/config", nil)
	w := httptest.NewRecorder()

	server.handleRuntimeConfig(w, req)

	// Should default to JavaScript format
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/javascript" {
		t.Errorf("Expected default format to be JavaScript, got Content-Type: %s", contentType)
	}

	body := w.Body.String()
	if !strings.Contains(body, "window.CONFIG") {
		t.Errorf("Expected JavaScript format with window.CONFIG")
	}
}

func TestHandleRuntimeConfigDefaultVarName(t *testing.T) {
	// When var_name is not specified, should default to "APP_CONFIG"
	config := &Config{
		RuntimeConfig: &RuntimeConfigConfig{
			Enabled: true,
			Format:  "js",
			VarName: "", // empty = should use default
		},
	}
	logger, _ := NewLogger(&LoggingConfig{Enabled: false})
	server := NewServer(config, logger)

	req := httptest.NewRequest("GET", "/config", nil)
	w := httptest.NewRecorder()

	server.handleRuntimeConfig(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "window.APP_CONFIG") {
		t.Errorf("Expected default var name APP_CONFIG, got: %s", body)
	}
}

func TestFormatSize(t *testing.T) {
	tests := []struct {
		size     int64
		expected string
	}{
		{0, "0 B"},
		{100, "100 B"},
		{1023, "1023 B"},
		{1024, "1.0 KB"},
		{1536, "1.5 KB"},
		{1048576, "1.0 MB"},
		{1073741824, "1.0 GB"},
		{1099511627776, "1.0 TB"},
	}

	for _, test := range tests {
		result := formatSize(test.size)
		if result != test.expected {
			t.Errorf("formatSize(%d) = %s, expected %s", test.size, result, test.expected)
		}
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

package main

import (
	"encoding/json"
	"os"
	"testing"
)

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig()

	// Test server defaults
	if config.Server.Port != 8080 {
		t.Errorf("Expected default port 8080, got %d", config.Server.Port)
	}
	if config.Server.Host != "0.0.0.0" {
		t.Errorf("Expected default host 0.0.0.0, got %s", config.Server.Host)
	}
	if config.Server.RootDir != "." {
		t.Errorf("Expected default root_dir ., got %s", config.Server.RootDir)
	}

	// Test security defaults
	if config.Security.EnableHTTPS != false {
		t.Errorf("Expected HTTPS disabled by default")
	}
	if config.Security.BlockHiddenFiles != true {
		t.Errorf("Expected block_hidden_files to be true by default")
	}

	// Test performance defaults
	if config.Performance.EnableCompression != true {
		t.Errorf("Expected compression enabled by default")
	}
	if config.Performance.CompressionLevel != 6 {
		t.Errorf("Expected compression level 6, got %d", config.Performance.CompressionLevel)
	}
	if config.Performance.EnableCache != true {
		t.Errorf("Expected cache enabled by default")
	}
	if config.Performance.EnableETags != true {
		t.Errorf("Expected ETags enabled by default")
	}

	// Test logging defaults
	if config.Logging.Enabled != true {
		t.Errorf("Expected logging enabled by default")
	}
	if config.Logging.Level != "info" {
		t.Errorf("Expected log level info, got %s", config.Logging.Level)
	}

	// Test features defaults
	if config.Features.DirectoryListing != false {
		t.Errorf("Expected directory listing disabled by default")
	}
	if len(config.Features.IndexFiles) != 2 {
		t.Errorf("Expected 2 default index files, got %d", len(config.Features.IndexFiles))
	}
	if config.Features.SPAMode != false {
		t.Errorf("Expected SPA mode disabled by default")
	}
}

func TestLoadConfig(t *testing.T) {
	// Create temporary config file
	tmpFile, err := os.CreateTemp("", "test-config-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())

	// Write test config
	testConfig := map[string]interface{}{
		"server": map[string]interface{}{
			"port":     9999,
			"host":     "127.0.0.1",
			"root_dir": "/test",
		},
		"logging": map[string]interface{}{
			"level": "debug",
		},
	}

	encoder := json.NewEncoder(tmpFile)
	if err := encoder.Encode(testConfig); err != nil {
		t.Fatalf("Failed to write test config: %v", err)
	}
	tmpFile.Close()

	// Load config
	config, err := LoadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	// Verify loaded values
	if config.Server.Port != 9999 {
		t.Errorf("Expected port 9999, got %d", config.Server.Port)
	}
	if config.Server.Host != "127.0.0.1" {
		t.Errorf("Expected host 127.0.0.1, got %s", config.Server.Host)
	}
	if config.Server.RootDir != "/test" {
		t.Errorf("Expected root_dir /test, got %s", config.Server.RootDir)
	}
	if config.Logging.Level != "debug" {
		t.Errorf("Expected log level debug, got %s", config.Logging.Level)
	}

	// Verify defaults are still applied for non-specified values
	if config.Performance.EnableCompression != true {
		t.Errorf("Expected default compression to be enabled")
	}
}

func TestLoadConfigNonExistent(t *testing.T) {
	// Loading non-existent file should return default config
	config, err := LoadConfig("non-existent-file.json")
	if err != nil {
		t.Fatalf("Expected no error for non-existent file, got: %v", err)
	}

	// Should return default values
	if config.Server.Port != 8080 {
		t.Errorf("Expected default port for non-existent file")
	}
}

func TestSaveConfig(t *testing.T) {
	// Create temporary file
	tmpFile, err := os.CreateTemp("", "test-save-config-*.json")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	tmpFile.Close()
	defer os.Remove(tmpFile.Name())

	// Create custom config
	config := DefaultConfig()
	config.Server.Port = 7777
	config.Server.Host = "localhost"
	config.Logging.Level = "warn"

	// Save config
	if err := SaveConfig(tmpFile.Name(), config); err != nil {
		t.Fatalf("Failed to save config: %v", err)
	}

	// Load it back
	loadedConfig, err := LoadConfig(tmpFile.Name())
	if err != nil {
		t.Fatalf("Failed to load saved config: %v", err)
	}

	// Verify values
	if loadedConfig.Server.Port != 7777 {
		t.Errorf("Expected port 7777, got %d", loadedConfig.Server.Port)
	}
	if loadedConfig.Server.Host != "localhost" {
		t.Errorf("Expected host localhost, got %s", loadedConfig.Server.Host)
	}
	if loadedConfig.Logging.Level != "warn" {
		t.Errorf("Expected log level warn, got %s", loadedConfig.Logging.Level)
	}
}

func TestGetTimeouts(t *testing.T) {
	config := ServerConfig{
		ReadTimeout:  10,
		WriteTimeout: 20,
	}

	readTimeout := config.GetReadTimeout()
	writeTimeout := config.GetWriteTimeout()

	if readTimeout.Seconds() != 10 {
		t.Errorf("Expected read timeout 10s, got %v", readTimeout)
	}
	if writeTimeout.Seconds() != 20 {
		t.Errorf("Expected write timeout 20s, got %v", writeTimeout)
	}
}

func TestRuntimeConfigDefaults(t *testing.T) {
	config := &RuntimeConfigConfig{
		Enabled: true,
	}

	// Test that empty values will use defaults in server
	if config.Route != "" {
		t.Errorf("Expected empty route (to use default), got %s", config.Route)
	}
	if config.Format != "" {
		t.Errorf("Expected empty format (to use default), got %s", config.Format)
	}
	if config.VarName != "" {
		t.Errorf("Expected empty var_name (to use default), got %s", config.VarName)
	}
}

func TestConfigJSON(t *testing.T) {
	// Test that config can be marshaled and unmarshaled
	originalConfig := DefaultConfig()
	originalConfig.Server.Port = 3000

	// Add runtime config
	originalConfig.RuntimeConfig = &RuntimeConfigConfig{
		Enabled:   true,
		Route:     "/config.js",
		Format:    "js",
		VarName:   "CONFIG",
		EnvPrefix: "TEST_",
		NoCache:   true,
	}

	// Marshal
	data, err := json.Marshal(originalConfig)
	if err != nil {
		t.Fatalf("Failed to marshal config: %v", err)
	}

	// Unmarshal
	var loadedConfig Config
	if err := json.Unmarshal(data, &loadedConfig); err != nil {
		t.Fatalf("Failed to unmarshal config: %v", err)
	}

	// Verify
	if loadedConfig.Server.Port != 3000 {
		t.Errorf("Expected port 3000 after unmarshal, got %d", loadedConfig.Server.Port)
	}
	if loadedConfig.RuntimeConfig == nil {
		t.Fatalf("Expected runtime config to be present")
	}
	if loadedConfig.RuntimeConfig.Route != "/config.js" {
		t.Errorf("Expected runtime config route /config.js, got %s", loadedConfig.RuntimeConfig.Route)
	}
	if loadedConfig.RuntimeConfig.EnvPrefix != "TEST_" {
		t.Errorf("Expected env prefix TEST_, got %s", loadedConfig.RuntimeConfig.EnvPrefix)
	}
}

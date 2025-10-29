package main

import (
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

var version = "dev" // set via ldflags during build

func main() {
	// Flags de linha de comando
	configFile := flag.String("config", "", "Path to configuration file (JSON)")
	port := flag.Int("port", 0, "Port to listen on (overrides config)")
	host := flag.String("host", "", "Host to bind to (overrides config)")
	rootDir := flag.String("dir", "", "Root directory to serve (overrides config)")
	enableListing := flag.Bool("list", false, "Enable directory listing")
	generateConfig := flag.String("generate-config", "", "Generate example config file and exit")
	showVersion := flag.Bool("version", false, "Show version and exit")
	showHelp := flag.Bool("help", false, "Show help and exit")

	flag.Parse()

	// Mostra versão
	if *showVersion {
		fmt.Printf("serve version %s\n", version)
		os.Exit(0)
	}

	// Mostra ajuda
	if *showHelp {
		printHelp()
		os.Exit(0)
	}

	// Gera arquivo de configuração de exemplo
	if *generateConfig != "" {
		if err := SaveConfig(*generateConfig, DefaultConfig()); err != nil {
			fmt.Fprintf(os.Stderr, "Error generating config: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Example configuration saved to: %s\n", *generateConfig)
		os.Exit(0)
	}

	// Carrega configuração
	config, err := loadConfiguration(*configFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error loading configuration: %v\n", err)
		os.Exit(1)
	}

	// Sobrescreve com flags da linha de comando
	if *port > 0 {
		config.Server.Port = *port
	}
	if *host != "" {
		config.Server.Host = *host
	}
	if *rootDir != "" {
		config.Server.RootDir = *rootDir
	}
	if *enableListing {
		config.Features.DirectoryListing = true
	}

	// Valida configuração
	if err := validateConfig(config); err != nil {
		fmt.Fprintf(os.Stderr, "Invalid configuration: %v\n", err)
		os.Exit(1)
	}

	// Cria o logger
	logger, err := NewLogger(&config.Logging)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating logger: %v\n", err)
		os.Exit(1)
	}

	// Cria e inicia o servidor
	server := NewServer(config, logger)

	// Configura handler para SIGINT/SIGTERM
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Inicia o servidor em uma goroutine
	errChan := make(chan error, 1)
	go func() {
		if err := server.Start(); err != nil {
			errChan <- err
		}
	}()

	// Aguarda sinal de término ou erro
	select {
	case err := <-errChan:
		logger.Error("Server error: %v", err)
		os.Exit(1)
	case sig := <-sigChan:
		logger.Info("\nReceived signal %v, shutting down gracefully...", sig)
		os.Exit(0)
	}
}

// loadConfiguration carrega a configuração
func loadConfiguration(configFile string) (*Config, error) {
	if configFile == "" {
		return DefaultConfig(), nil
	}

	config, err := LoadConfig(configFile)
	if err != nil {
		return nil, fmt.Errorf("failed to load config file: %w", err)
	}

	return config, nil
}

// validateConfig valida a configuração
func validateConfig(config *Config) error {
	// Valida porta
	if config.Server.Port < 1 || config.Server.Port > 65535 {
		return fmt.Errorf("invalid port: %d (must be between 1-65535)", config.Server.Port)
	}

	// Valida diretório raiz
	if info, err := os.Stat(config.Server.RootDir); err != nil {
		return fmt.Errorf("root directory error: %w", err)
	} else if !info.IsDir() {
		return fmt.Errorf("root path is not a directory: %s", config.Server.RootDir)
	}

	// Valida HTTPS
	if config.Security.EnableHTTPS {
		if config.Security.CertFile == "" || config.Security.KeyFile == "" {
			return fmt.Errorf("HTTPS enabled but cert_file or key_file not specified")
		}
		if _, err := os.Stat(config.Security.CertFile); err != nil {
			return fmt.Errorf("certificate file not found: %s", config.Security.CertFile)
		}
		if _, err := os.Stat(config.Security.KeyFile); err != nil {
			return fmt.Errorf("key file not found: %s", config.Security.KeyFile)
		}
	}

	// Valida autenticação básica
	if config.Security.BasicAuth != nil && config.Security.BasicAuth.Enabled {
		if config.Security.BasicAuth.Username == "" || config.Security.BasicAuth.Password == "" {
			return fmt.Errorf("basic auth enabled but username or password not specified")
		}
		if config.Security.BasicAuth.Realm == "" {
			config.Security.BasicAuth.Realm = "Restricted"
		}
	}

	// Valida nível de compressão
	if config.Performance.CompressionLevel < 1 || config.Performance.CompressionLevel > 9 {
		config.Performance.CompressionLevel = 6
	}

	// Valida log level
	validLevels := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	if !validLevels[config.Logging.Level] {
		config.Logging.Level = "info"
	}

	return nil
}

// printHelp imprime a ajuda
func printHelp() {
	fmt.Printf(`serve - Simple HTTP file server with advanced features

VERSION:
  %s

USAGE:
  serve [options]

OPTIONS:
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

EXAMPLES:
  # Serve current directory on port 8080
  serve

  # Serve specific directory on custom port
  serve -dir /var/www -port 3000

  # Enable directory listing
  serve -list

  # Use configuration file
  serve -config config.json

  # Generate example configuration
  serve -generate-config config.example.json

CONFIGURATION:
  Configuration can be provided via a JSON file using the -config flag.
  Use -generate-config to create an example configuration file.

FEATURES:
  • Static file serving
  • Directory listing (optional)
  • HTTPS/TLS support
  • Basic authentication
  • CORS support
  • Rate limiting
  • IP whitelist/blacklist
  • Gzip compression
  • Cache headers
  • ETags
  • SPA mode
  • Custom error pages
  • Access logging
  • Security headers

For more information, visit: https://github.com/5prw/serve
`, version)
}

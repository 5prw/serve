package main

import (
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

// Logger gerencia os logs da aplicação
type Logger struct {
	config      *LoggingConfig
	accessLog   *log.Logger
	errorLog    *log.Logger
	infoLog     *log.Logger
	debugLog    *log.Logger
	colorOutput bool
}

// Cores ANSI
const (
	colorReset  = "\033[0m"
	colorRed    = "\033[31m"
	colorGreen  = "\033[32m"
	colorYellow = "\033[33m"
	colorBlue   = "\033[34m"
	colorPurple = "\033[35m"
	colorCyan   = "\033[36m"
	colorWhite  = "\033[37m"
	colorGray   = "\033[90m"
)

// NewLogger cria um novo logger
func NewLogger(config *LoggingConfig) (*Logger, error) {
	logger := &Logger{
		config:      config,
		colorOutput: config.ColorOutput,
	}

	var writer io.Writer = os.Stdout

	// Se um arquivo de log foi especificado, usa ele
	if config.LogFile != "" {
		file, err := os.OpenFile(config.LogFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return nil, err
		}
		writer = io.MultiWriter(os.Stdout, file)
		logger.colorOutput = false // Desabilita cores em arquivos
	}

	logger.accessLog = log.New(writer, "", 0)
	logger.errorLog = log.New(writer, "", 0)
	logger.infoLog = log.New(writer, "", 0)
	logger.debugLog = log.New(writer, "", 0)

	return logger, nil
}

// colorize adiciona cor ao texto se habilitado
func (l *Logger) colorize(color, text string) string {
	if l.colorOutput {
		return color + text + colorReset
	}
	return text
}

// formatTime formata o timestamp
func (l *Logger) formatTime() string {
	return time.Now().Format("2006-01-02 15:04:05")
}

// Access registra um log de acesso
func (l *Logger) Access(method, path string, status int, duration time.Duration, remoteAddr string) {
	if !l.config.Enabled || !l.config.AccessLog {
		return
	}

	statusColor := colorGreen
	if status >= 400 && status < 500 {
		statusColor = colorYellow
	} else if status >= 500 {
		statusColor = colorRed
	}

	timestamp := l.colorize(colorGray, l.formatTime())
	methodStr := l.colorize(colorBlue, method)
	pathStr := l.colorize(colorCyan, path)
	statusStr := l.colorize(statusColor, fmt.Sprintf("%d", status))
	durationStr := l.colorize(colorGray, duration.String())
	remoteStr := l.colorize(colorGray, remoteAddr)

	l.accessLog.Printf("[%s] %s %s - %s - %s - %s\n",
		timestamp, methodStr, pathStr, statusStr, durationStr, remoteStr)
}

// Error registra um log de erro
func (l *Logger) Error(format string, v ...interface{}) {
	if !l.config.Enabled || !l.config.ErrorLog {
		return
	}

	timestamp := l.colorize(colorGray, l.formatTime())
	level := l.colorize(colorRed, "ERROR")
	message := fmt.Sprintf(format, v...)

	l.errorLog.Printf("[%s] [%s] %s\n", timestamp, level, message)
}

// Info registra um log informativo
func (l *Logger) Info(format string, v ...interface{}) {
	if !l.config.Enabled {
		return
	}

	if l.config.Level == "error" || l.config.Level == "warn" {
		return
	}

	timestamp := l.colorize(colorGray, l.formatTime())
	level := l.colorize(colorGreen, "INFO")
	message := fmt.Sprintf(format, v...)

	l.infoLog.Printf("[%s] [%s] %s\n", timestamp, level, message)
}

// Warn registra um log de aviso
func (l *Logger) Warn(format string, v ...interface{}) {
	if !l.config.Enabled {
		return
	}

	if l.config.Level == "error" {
		return
	}

	timestamp := l.colorize(colorGray, l.formatTime())
	level := l.colorize(colorYellow, "WARN")
	message := fmt.Sprintf(format, v...)

	l.infoLog.Printf("[%s] [%s] %s\n", timestamp, level, message)
}

// Debug registra um log de debug
func (l *Logger) Debug(format string, v ...interface{}) {
	if !l.config.Enabled || l.config.Level != "debug" {
		return
	}

	timestamp := l.colorize(colorGray, l.formatTime())
	level := l.colorize(colorPurple, "DEBUG")
	message := fmt.Sprintf(format, v...)

	l.debugLog.Printf("[%s] [%s] %s\n", timestamp, level, message)
}

// PrintBanner imprime o banner de inicialização
func (l *Logger) PrintBanner(config *Config) {
	if !l.config.Enabled {
		return
	}

	banner := `
╔═══════════════════════════════════════╗
║                                       ║
║          SERVE - File Server          ║
║                                       ║
╚═══════════════════════════════════════╝
`
	fmt.Println(l.colorize(colorCyan, banner))

	protocol := "HTTP"
	if config.Security.EnableHTTPS {
		protocol = "HTTPS"
	}

	l.Info("Server starting...")
	l.Info("Protocol: %s", protocol)
	l.Info("Host: %s", config.Server.Host)
	l.Info("Port: %d", config.Server.Port)
	l.Info("Root Directory: %s", config.Server.RootDir)
	l.Info("Directory Listing: %v", config.Features.DirectoryListing)
	l.Info("SPA Mode: %v", config.Features.SPAMode)

	if config.Security.BasicAuth != nil && config.Security.BasicAuth.Enabled {
		l.Info("Basic Auth: Enabled")
	}

	if config.Security.CORS != nil && config.Security.CORS.Enabled {
		l.Info("CORS: Enabled")
	}

	if config.Security.RateLimit != nil && config.Security.RateLimit.Enabled {
		l.Info("Rate Limit: %d req/min", config.Security.RateLimit.RequestsPerIP)
	}

	if config.Performance.EnableCompression {
		l.Info("Compression: Enabled (level %d)", config.Performance.CompressionLevel)
	}

	fmt.Println()
	l.Info("%s Server running at %s://%s:%d",
		l.colorize(colorGreen, "✓"),
		protocol,
		config.Server.Host,
		config.Server.Port)
	l.Info("Press Ctrl+C to stop")
	fmt.Println()
}

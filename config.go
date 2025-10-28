package main

import (
	"encoding/json"
	"os"
	"time"
)

// Config representa a configuração completa do servidor
type Config struct {
	Server       ServerConfig       `json:"server"`
	Security     SecurityConfig     `json:"security"`
	Performance  PerformanceConfig  `json:"performance"`
	Logging      LoggingConfig      `json:"logging"`
	Features     FeaturesConfig     `json:"features"`
}

// ServerConfig configurações básicas do servidor
type ServerConfig struct {
	Port         int    `json:"port"`
	Host         string `json:"host"`
	RootDir      string `json:"root_dir"`
	ReadTimeout  int    `json:"read_timeout"`   // segundos
	WriteTimeout int    `json:"write_timeout"`  // segundos
}

// SecurityConfig configurações de segurança
type SecurityConfig struct {
	EnableHTTPS      bool              `json:"enable_https"`
	CertFile         string            `json:"cert_file"`
	KeyFile          string            `json:"key_file"`
	BasicAuth        *BasicAuthConfig  `json:"basic_auth,omitempty"`
	CORS             *CORSConfig       `json:"cors,omitempty"`
	RateLimit        *RateLimitConfig  `json:"rate_limit,omitempty"`
	IPWhitelist      []string          `json:"ip_whitelist,omitempty"`
	IPBlacklist      []string          `json:"ip_blacklist,omitempty"`
	BlockHiddenFiles bool              `json:"block_hidden_files"`
	AllowedPaths     []string          `json:"allowed_paths,omitempty"`
	BlockedPaths     []string          `json:"blocked_paths,omitempty"`
}

// BasicAuthConfig autenticação básica
type BasicAuthConfig struct {
	Enabled  bool   `json:"enabled"`
	Username string `json:"username"`
	Password string `json:"password"`
	Realm    string `json:"realm"`
}

// CORSConfig configurações CORS
type CORSConfig struct {
	Enabled          bool     `json:"enabled"`
	AllowedOrigins   []string `json:"allowed_origins"`
	AllowedMethods   []string `json:"allowed_methods"`
	AllowedHeaders   []string `json:"allowed_headers"`
	AllowCredentials bool     `json:"allow_credentials"`
	MaxAge           int      `json:"max_age"`
}

// RateLimitConfig limitação de taxa
type RateLimitConfig struct {
	Enabled       bool `json:"enabled"`
	RequestsPerIP int  `json:"requests_per_ip"` // requisições por minuto
	BurstSize     int  `json:"burst_size"`
}

// PerformanceConfig configurações de performance
type PerformanceConfig struct {
	EnableCompression bool              `json:"enable_compression"`
	CompressionLevel  int               `json:"compression_level"` // 1-9
	EnableCache       bool              `json:"enable_cache"`
	CacheMaxAge       int               `json:"cache_max_age"` // segundos
	EnableETags       bool              `json:"enable_etags"`
	CustomHeaders     map[string]string `json:"custom_headers,omitempty"`
}

// LoggingConfig configurações de logs
type LoggingConfig struct {
	Enabled     bool   `json:"enabled"`
	Level       string `json:"level"` // debug, info, warn, error
	AccessLog   bool   `json:"access_log"`
	ErrorLog    bool   `json:"error_log"`
	LogFile     string `json:"log_file,omitempty"`
	ColorOutput bool   `json:"color_output"`
}

// FeaturesConfig funcionalidades adicionais
type FeaturesConfig struct {
	DirectoryListing bool     `json:"directory_listing"`
	IndexFiles       []string `json:"index_files"`
	SPAMode          bool     `json:"spa_mode"` // redireciona tudo para index.html
	SPAIndex         string   `json:"spa_index"`
	CustomErrorPages map[string]string `json:"custom_error_pages,omitempty"`
}

// DefaultConfig retorna a configuração padrão
func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Port:         8080,
			Host:         "0.0.0.0",
			RootDir:      ".",
			ReadTimeout:  30,
			WriteTimeout: 30,
		},
		Security: SecurityConfig{
			EnableHTTPS:      false,
			BlockHiddenFiles: true,
		},
		Performance: PerformanceConfig{
			EnableCompression: true,
			CompressionLevel:  6,
			EnableCache:       true,
			CacheMaxAge:       3600,
			EnableETags:       true,
		},
		Logging: LoggingConfig{
			Enabled:     true,
			Level:       "info",
			AccessLog:   true,
			ErrorLog:    true,
			ColorOutput: true,
		},
		Features: FeaturesConfig{
			DirectoryListing: false,
			IndexFiles:       []string{"index.html", "index.htm"},
			SPAMode:          false,
			SPAIndex:         "index.html",
		},
	}
}

// LoadConfig carrega a configuração de um arquivo JSON
func LoadConfig(filename string) (*Config, error) {
	config := DefaultConfig()

	// Se o arquivo não existir, retorna a configuração padrão
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return config, nil
	}

	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	decoder := json.NewDecoder(file)
	if err := decoder.Decode(config); err != nil {
		return nil, err
	}

	return config, nil
}

// SaveConfig salva a configuração em um arquivo JSON
func SaveConfig(filename string, config *Config) error {
	file, err := os.Create(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(config)
}

// GetReadTimeout retorna o timeout de leitura como Duration
func (c *ServerConfig) GetReadTimeout() time.Duration {
	return time.Duration(c.ReadTimeout) * time.Second
}

// GetWriteTimeout retorna o timeout de escrita como Duration
func (c *ServerConfig) GetWriteTimeout() time.Duration {
	return time.Duration(c.WriteTimeout) * time.Second
}

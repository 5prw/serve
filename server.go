package main

import (
	"encoding/json"
	"fmt"
	"html/template"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Server representa o servidor HTTP
type Server struct {
	config *Config
	logger *Logger
	mux    *http.ServeMux
}

// NewServer cria uma nova instância do servidor
func NewServer(config *Config, logger *Logger) *Server {
	return &Server{
		config: config,
		logger: logger,
		mux:    http.NewServeMux(),
	}
}

// Start inicia o servidor
func (s *Server) Start() error {
	// Configura o handler principal
	s.setupHandlers()

	// Cria o servidor HTTP
	addr := fmt.Sprintf("%s:%d", s.config.Server.Host, s.config.Server.Port)

	server := &http.Server{
		Addr:         addr,
		Handler:      s.mux,
		ReadTimeout:  s.config.Server.GetReadTimeout(),
		WriteTimeout: s.config.Server.GetWriteTimeout(),
	}

	// Imprime o banner
	s.logger.PrintBanner(s.config)

	// Inicia o servidor
	if s.config.Security.EnableHTTPS {
		return server.ListenAndServeTLS(
			s.config.Security.CertFile,
			s.config.Security.KeyFile,
		)
	}

	return server.ListenAndServe()
}

// setupHandlers configura os handlers e middlewares
func (s *Server) setupHandlers() {
	// Handler principal
	var handler http.Handler = s.createFileHandler()

	// Aplica middlewares na ordem correta
	var middlewares []Middleware

	// Logging (primeiro para capturar tudo)
	middlewares = append(middlewares, LoggingMiddleware(s.logger))

	// Security headers
	middlewares = append(middlewares, SecurityHeadersMiddleware())

	// Custom headers
	if len(s.config.Performance.CustomHeaders) > 0 {
		middlewares = append(middlewares, CustomHeadersMiddleware(s.config.Performance.CustomHeaders))
	}

	// IP filtering
	if len(s.config.Security.IPWhitelist) > 0 || len(s.config.Security.IPBlacklist) > 0 {
		middlewares = append(middlewares, IPFilterMiddleware(
			s.config.Security.IPWhitelist,
			s.config.Security.IPBlacklist,
		))
	}

	// Rate limiting
	if s.config.Security.RateLimit != nil && s.config.Security.RateLimit.Enabled {
		limiter := NewRateLimiter(s.config.Security.RateLimit)
		middlewares = append(middlewares, RateLimitMiddleware(limiter))
	}

	// Basic auth
	if s.config.Security.BasicAuth != nil && s.config.Security.BasicAuth.Enabled {
		middlewares = append(middlewares, BasicAuthMiddleware(s.config.Security.BasicAuth))
	}

	// CORS
	if s.config.Security.CORS != nil && s.config.Security.CORS.Enabled {
		middlewares = append(middlewares, CORSMiddleware(s.config.Security.CORS))
	}

	// Path traversal protection
	middlewares = append(middlewares, PathTraversalMiddleware(s.config.Server.RootDir))

	// Block hidden files
	if s.config.Security.BlockHiddenFiles {
		middlewares = append(middlewares, BlockHiddenFilesMiddleware(s.config.Server.RootDir))
	}

	// Compression
	if s.config.Performance.EnableCompression {
		middlewares = append(middlewares, CompressionMiddleware(s.config.Performance.CompressionLevel))
	}

	// Cache headers
	if s.config.Performance.EnableCache && s.config.Performance.CacheMaxAge > 0 {
		middlewares = append(middlewares, CacheMiddleware(s.config.Performance.CacheMaxAge))
	}

	// Aplica os middlewares
	handler = Chain(handler, middlewares...)

	// Runtime config route (se habilitado, deve ser registrado antes do handler principal)
	if s.config.RuntimeConfig != nil && s.config.RuntimeConfig.Enabled {
		route := s.config.RuntimeConfig.Route
		if route == "" {
			route = "/runtime-config.js"
		}
		s.mux.HandleFunc(route, s.handleRuntimeConfig)
		s.logger.Info("Runtime Config enabled at: %s", route)
	}

	s.mux.Handle("/", handler)
}

// createFileHandler cria o handler para servir arquivos
func (s *Server) createFileHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Resolve o caminho do arquivo
		path := filepath.Join(s.config.Server.RootDir, filepath.Clean(r.URL.Path))

		// Verifica se o arquivo existe
		info, err := os.Stat(path)
		if err != nil {
			if os.IsNotExist(err) {
				// Modo SPA - redireciona para index.html
				if s.config.Features.SPAMode {
					s.serveSPAIndex(w, r)
					return
				}
				s.serveError(w, r, http.StatusNotFound)
				return
			}
			s.logger.Error("Error accessing path %s: %v", path, err)
			s.serveError(w, r, http.StatusInternalServerError)
			return
		}

		// Se for um diretório
		if info.IsDir() {
			s.serveDirectory(w, r, path)
			return
		}

		// Serve o arquivo
		s.serveFile(w, r, path, info)
	})
}

// serveDirectory serve um diretório
func (s *Server) serveDirectory(w http.ResponseWriter, r *http.Request, path string) {
	// Tenta servir index files
	for _, indexFile := range s.config.Features.IndexFiles {
		indexPath := filepath.Join(path, indexFile)
		if info, err := os.Stat(indexPath); err == nil && !info.IsDir() {
			s.serveFile(w, r, indexPath, info)
			return
		}
	}

	// Se directory listing estiver habilitado, mostra a listagem
	if s.config.Features.DirectoryListing {
		s.serveDirectoryListing(w, r, path)
		return
	}

	// Caso contrário, retorna 403
	s.serveError(w, r, http.StatusForbidden)
}

// serveFile serve um arquivo
func (s *Server) serveFile(w http.ResponseWriter, r *http.Request, path string, info os.FileInfo) {
	// Adiciona ETag se habilitado
	if s.config.Performance.EnableETags {
		etag := fmt.Sprintf(`"%x-%x"`, info.ModTime().Unix(), info.Size())
		w.Header().Set("ETag", etag)

		// Verifica If-None-Match
		if match := r.Header.Get("If-None-Match"); match != "" {
			if match == etag {
				w.WriteHeader(http.StatusNotModified)
				return
			}
		}
	}

	// Serve o arquivo
	http.ServeFile(w, r, path)
}

// serveSPAIndex serve o index.html para modo SPA
func (s *Server) serveSPAIndex(w http.ResponseWriter, r *http.Request) {
	indexPath := filepath.Join(s.config.Server.RootDir, s.config.Features.SPAIndex)
	info, err := os.Stat(indexPath)
	if err != nil {
		s.serveError(w, r, http.StatusNotFound)
		return
	}
	s.serveFile(w, r, indexPath, info)
}

// serveDirectoryListing serve a listagem de diretório
func (s *Server) serveDirectoryListing(w http.ResponseWriter, r *http.Request, path string) {
	entries, err := os.ReadDir(path)
	if err != nil {
		s.logger.Error("Error reading directory %s: %v", path, err)
		s.serveError(w, r, http.StatusInternalServerError)
		return
	}

	// Filtra arquivos ocultos se configurado
	if s.config.Security.BlockHiddenFiles {
		filtered := make([]fs.DirEntry, 0)
		for _, entry := range entries {
			if !strings.HasPrefix(entry.Name(), ".") {
				filtered = append(filtered, entry)
			}
		}
		entries = filtered
	}

	// Ordena: diretórios primeiro, depois arquivos
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].IsDir() != entries[j].IsDir() {
			return entries[i].IsDir()
		}
		return entries[i].Name() < entries[j].Name()
	})

	// Prepara os dados para o template
	type FileInfo struct {
		Name    string
		Path    string
		IsDir   bool
		Size    string
		ModTime string
	}

	var files []FileInfo
	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		size := "-"
		if !entry.IsDir() {
			size = formatSize(info.Size())
		}

		files = append(files, FileInfo{
			Name:    entry.Name(),
			Path:    filepath.Join(r.URL.Path, entry.Name()),
			IsDir:   entry.IsDir(),
			Size:    size,
			ModTime: info.ModTime().Format("2006-01-02 15:04:05"),
		})
	}

	// Renderiza o template
	tmpl := template.Must(template.New("listing").Parse(directoryListingTemplate))

	data := struct {
		Path  string
		Files []FileInfo
	}{
		Path:  r.URL.Path,
		Files: files,
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := tmpl.Execute(w, data); err != nil {
		s.logger.Error("Error rendering directory listing: %v", err)
		s.serveError(w, r, http.StatusInternalServerError)
	}
}

// serveError serve uma página de erro
func (s *Server) serveError(w http.ResponseWriter, r *http.Request, status int) {
	// Verifica se existe uma página de erro customizada
	if s.config.Features.CustomErrorPages != nil {
		if errorPage, ok := s.config.Features.CustomErrorPages[fmt.Sprintf("%d", status)]; ok {
			errorPath := filepath.Join(s.config.Server.RootDir, errorPage)
			if _, err := os.Stat(errorPath); err == nil {
				http.ServeFile(w, r, errorPath)
				return
			}
		}
	}

	// Página de erro padrão
	http.Error(w, http.StatusText(status), status)
}

// formatSize formata o tamanho do arquivo
func formatSize(size int64) string {
	const unit = 1024
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "KMGTPE"[exp])
}

// handleRuntimeConfig serve o runtime config baseado em variáveis de ambiente
func (s *Server) handleRuntimeConfig(w http.ResponseWriter, r *http.Request) {
	cfg := s.config.RuntimeConfig

	// Coleta variáveis de ambiente
	envVars := s.collectEnvVars(cfg)

	// Determina o formato
	format := cfg.Format
	if format == "" {
		format = "js"
	}

	var content []byte
	var contentType string

	switch format {
	case "json":
		// Formato JSON
		data, err := json.MarshalIndent(envVars, "", "  ")
		if err != nil {
			s.logger.Error("Error marshaling runtime config: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}
		content = data
		contentType = "application/json"

	case "js":
		fallthrough
	default:
		// Formato JavaScript
		varName := cfg.VarName
		if varName == "" {
			varName = "APP_CONFIG"
		}

		data, err := json.MarshalIndent(envVars, "", "  ")
		if err != nil {
			s.logger.Error("Error marshaling runtime config: %v", err)
			http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			return
		}

		content = []byte(fmt.Sprintf("window.%s = %s;", varName, string(data)))
		contentType = "application/javascript"
	}

	// Headers de cache
	if cfg.NoCache {
		w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
		w.Header().Set("Pragma", "no-cache")
		w.Header().Set("Expires", "0")
	}

	w.Header().Set("Content-Type", contentType)
	w.Write(content)
}

// collectEnvVars coleta variáveis de ambiente baseado na configuração
func (s *Server) collectEnvVars(cfg *RuntimeConfigConfig) map[string]string {
	result := make(map[string]string)

	// Se há lista específica de variáveis, usa ela
	if len(cfg.EnvVariables) > 0 {
		for _, envVar := range cfg.EnvVariables {
			if value := os.Getenv(envVar); value != "" {
				result[envVar] = value
			}
		}
		return result
	}

	// Caso contrário, usa prefixo
	prefix := cfg.EnvPrefix
	if prefix == "" {
		return result // sem prefix e sem lista, retorna vazio
	}

	// Itera sobre todas as variáveis de ambiente
	for _, env := range os.Environ() {
		// Separa nome=valor
		parts := strings.SplitN(env, "=", 2)
		if len(parts) != 2 {
			continue
		}

		key := parts[0]
		value := parts[1]

		// Verifica se tem o prefixo
		if strings.HasPrefix(key, prefix) {
			// Remove o prefixo para a chave no resultado
			cleanKey := strings.TrimPrefix(key, prefix)
			result[cleanKey] = value
		}
	}

	return result
}

// Template para listagem de diretórios
const directoryListingTemplate = `<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Index of {{.Path}}</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            padding: 2rem;
            background: #f5f5f5;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 8px;
            box-shadow: 0 2px 8px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        h1 {
            padding: 2rem;
            background: #2c3e50;
            color: white;
            font-size: 1.5rem;
        }
        table {
            width: 100%;
            border-collapse: collapse;
        }
        th {
            background: #34495e;
            color: white;
            padding: 1rem;
            text-align: left;
            font-weight: 600;
        }
        td {
            padding: 1rem;
            border-bottom: 1px solid #ecf0f1;
        }
        tr:hover {
            background: #f8f9fa;
        }
        a {
            color: #3498db;
            text-decoration: none;
            display: flex;
            align-items: center;
        }
        a:hover {
            color: #2980b9;
            text-decoration: underline;
        }
        .icon {
            margin-right: 0.5rem;
            font-size: 1.2rem;
        }
        .size, .modified {
            color: #7f8c8d;
        }
    </style>
</head>
<body>
    <div class="container">
        <h1>📁 Index of {{.Path}}</h1>
        <table>
            <thead>
                <tr>
                    <th>Name</th>
                    <th width="150">Size</th>
                    <th width="200">Modified</th>
                </tr>
            </thead>
            <tbody>
                {{if ne .Path "/"}}
                <tr>
                    <td><a href=".."><span class="icon">📁</span> ..</a></td>
                    <td class="size">-</td>
                    <td class="modified">-</td>
                </tr>
                {{end}}
                {{range .Files}}
                <tr>
                    <td>
                        <a href="{{.Path}}">
                            <span class="icon">{{if .IsDir}}📁{{else}}📄{{end}}</span>
                            {{.Name}}{{if .IsDir}}/{{end}}
                        </a>
                    </td>
                    <td class="size">{{.Size}}</td>
                    <td class="modified">{{.ModTime}}</td>
                </tr>
                {{end}}
            </tbody>
        </table>
    </div>
</body>
</html>`

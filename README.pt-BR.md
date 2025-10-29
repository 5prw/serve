# Serve - Static File Server

Um servidor de arquivos estáticos leve, rápido e rico em recursos, escrito em Go. Perfeito para desenvolvimento, testes e produção.

## Características

### Básicas
- ✅ Servidor HTTP/HTTPS de arquivos estáticos
- ✅ Executável único sem dependências
- ✅ Cross-platform (Linux, Windows, macOS)
- ✅ Configuração via arquivo JSON ou flags de linha de comando
- ✅ Hot reload de configuração

### Segurança
- 🔒 Suporte HTTPS/TLS
- 🔒 Autenticação básica (usuário/senha)
- 🔒 CORS configurável
- 🔒 Rate limiting por IP
- 🔒 Whitelist/blacklist de IPs
- 🔒 Proteção contra path traversal
- 🔒 Bloqueio de arquivos ocultos (.env, .git, etc)
- 🔒 Security headers automáticos

### Performance
- ⚡ Compressão gzip com nível configurável
- ⚡ ETags para cache eficiente
- ⚡ Cache headers configuráveis
- ⚡ Custom headers HTTP
- ⚡ Timeouts configuráveis

### Funcionalidades
- 📁 Listagem de diretórios (opcional)
- 📄 Index files personalizados
- 🎯 Modo SPA (Single Page Application)
- 🎨 Páginas de erro customizadas
- 📊 Logs detalhados com cores
- 📝 Access logs e error logs separados

## Instalação

### Compilar do fonte

```bash
git clone https://github.com/yourusername/serve.git
cd serve
go build -o serve
```

### Compilar para múltiplas plataformas

```bash
# Linux
GOOS=linux GOARCH=amd64 go build -o serve-linux

# Windows
GOOS=windows GOARCH=amd64 go build -o serve.exe

# macOS
GOOS=darwin GOARCH=amd64 go build -o serve-macos
```

## Uso Rápido

### Servidor básico

```bash
# Serve o diretório atual na porta 8080
./serve

# Serve um diretório específico
./serve -dir /var/www

# Porta customizada
./serve -port 3000

# Habilitar listagem de diretórios
./serve -list
```

### Usando arquivo de configuração

```bash
# Gerar arquivo de configuração de exemplo
./serve -generate-config config.json

# Iniciar com configuração
./serve -config config.json
```

## Configuração

### Arquivo de Configuração

O arquivo de configuração usa formato JSON. Exemplo completo:

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

### Opções de Linha de Comando

```
  -config string
        Caminho para arquivo de configuração (JSON)

  -port int
        Porta para escutar (sobrescreve config)

  -host string
        Host para bind (sobrescreve config)

  -dir string
        Diretório raiz para servir (sobrescreve config)

  -list
        Habilitar listagem de diretórios

  -generate-config string
        Gerar arquivo de configuração de exemplo

  -version
        Mostrar versão

  -help
        Mostrar ajuda
```

## Casos de Uso

### 1. Desenvolvimento Frontend

```bash
# Serve aplicação React/Vue/Angular
./serve -dir ./dist -port 3000 -list
```

### 2. Single Page Application (SPA)

Crie um arquivo `config.json`:

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

### 3. Servidor com Autenticação

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

### 4. Servidor HTTPS

```bash
# Gerar certificado autoassinado para testes
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

### 5. API com CORS

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

### 6. Servidor de Produção com Rate Limiting

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

## Segurança

### Boas Práticas

1. **Sempre bloqueie arquivos ocultos** em produção:
   ```json
   "block_hidden_files": true
   ```

2. **Use HTTPS** em produção:
   ```json
   "enable_https": true
   ```

3. **Implemente rate limiting** para prevenir ataques DDoS:
   ```json
   "rate_limit": {
     "enabled": true,
     "requests_per_ip": 100
   }
   ```

4. **Use autenticação** para conteúdo sensível:
   ```json
   "basic_auth": {
     "enabled": true,
     "username": "admin",
     "password": "strong-password"
   }
   ```

5. **Whitelist IPs** se possível:
   ```json
   "ip_whitelist": ["192.168.1.0/24"]
   ```

## Performance

### Otimizações

- **Compressão**: Habilite gzip para reduzir tamanho das respostas
- **Cache**: Configure `cache_max_age` apropriadamente
- **ETags**: Reduz transferências desnecessárias
- **Timeouts**: Configure para evitar conexões pendentes

### Benchmark

```bash
# Instalar ferramenta de benchmark
go install github.com/rakyll/hey@latest

# Testar performance
hey -n 10000 -c 100 http://localhost:8080/
```

## Exemplos de Logs

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

## Contribuindo

Contribuições são bem-vindas! Por favor:

1. Fork o projeto
2. Crie uma branch para sua feature (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## Licença

MIT License - veja o arquivo LICENSE para detalhes.

## Suporte

- 🐛 [Report de Bugs](https://github.com/yourusername/serve/issues)
- 💡 [Feature Requests](https://github.com/yourusername/serve/issues)
- 📖 [Documentação](https://github.com/yourusername/serve/wiki)

---

Feito com ❤️ em Go

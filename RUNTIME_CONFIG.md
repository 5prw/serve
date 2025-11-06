# Runtime Config Feature

The Runtime Config feature allows you to serve dynamic configuration from environment variables to your frontend application. This is especially useful for containerized applications (Docker/Kubernetes) where configuration varies by environment.

## Use Cases

- **SPAs in containers**: Serve different API URLs per environment without rebuilding
- **Feature flags**: Enable/disable features via environment variables
- **Kubernetes ConfigMaps**: Expose ConfigMap values to frontend apps
- **Multi-environment deployments**: Same Docker image for dev/staging/prod

## How It Works

1. Configure runtime config in `config.json`
2. Set environment variables (with prefix or specific names)
3. Server exposes a special route (e.g., `/runtime-config.js`)
4. Frontend fetches this route to get current configuration
5. Variables are read at request time (always current)

## Configuration

### Basic Configuration

```json
{
  "runtime_config": {
    "enabled": true,
    "route": "/runtime-config.js",
    "format": "js",
    "var_name": "APP_CONFIG",
    "env_prefix": "APP_",
    "no_cache": true
  }
}
```

### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `enabled` | boolean | false | Enable/disable runtime config |
| `route` | string | "/runtime-config.js" | Route where config will be served |
| `format` | string | "js" | Output format: "js" or "json" |
| `var_name` | string | "APP_CONFIG" | JavaScript variable name (js format only) |
| `env_prefix` | string | "" | Prefix for environment variables to include |
| `env_variables` | array | [] | Specific environment variables to include |
| `no_cache` | boolean | false | If true, adds no-cache headers |

## Output Formats

### JavaScript Format (default)

**Configuration**:
```json
{
  "format": "js",
  "var_name": "APP_CONFIG"
}
```

**Output** (`/runtime-config.js`):
```javascript
window.APP_CONFIG = {
  "API_URL": "https://api.example.com",
  "FEATURE_FLAG": "true",
  "VERSION": "1.0.0"
};
```

**Usage in HTML**:
```html
<script src="/runtime-config.js"></script>
<script>
  console.log('API URL:', window.APP_CONFIG.API_URL);
  fetch(window.APP_CONFIG.API_URL + '/users');
</script>
```

### JSON Format

**Configuration**:
```json
{
  "format": "json"
}
```

**Output** (`/config.json`):
```json
{
  "API_URL": "https://api.example.com",
  "FEATURE_FLAG": "true",
  "VERSION": "1.0.0"
}
```

**Usage in JavaScript**:
```javascript
fetch('/config.json')
  .then(res => res.json())
  .then(config => {
    console.log('API URL:', config.API_URL);
  });
```

## Environment Variable Selection

You can choose variables in two ways:

### 1. By Prefix (Recommended)

All environment variables starting with the prefix will be included, with the prefix removed from the key.

**Configuration**:
```json
{
  "env_prefix": "APP_"
}
```

**Environment Variables**:
```bash
APP_API_URL=https://api.example.com
APP_VERSION=1.0.0
APP_FEATURE_X=true
OTHER_VAR=ignored
```

**Output**:
```javascript
window.APP_CONFIG = {
  "API_URL": "https://api.example.com",    // APP_ removed
  "VERSION": "1.0.0",                      // APP_ removed
  "FEATURE_X": "true"                      // APP_ removed
};
// OTHER_VAR is not included (no APP_ prefix)
```

### 2. Specific Variables

Explicitly list which environment variables to include.

**Configuration**:
```json
{
  "env_variables": ["API_URL", "DATABASE_URL", "REDIS_URL"]
}
```

**Environment Variables**:
```bash
API_URL=https://api.example.com
DATABASE_URL=postgres://localhost/db
REDIS_URL=redis://localhost:6379
SECRET_KEY=secret123
```

**Output**:
```json
{
  "API_URL": "https://api.example.com",
  "DATABASE_URL": "postgres://localhost/db",
  "REDIS_URL": "redis://localhost:6379"
}
// SECRET_KEY is not included (not in list)
```

**Note**: If both `env_prefix` and `env_variables` are set, `env_variables` takes priority.

## Complete Examples

### Example 1: React App with Multiple Environments

**docker-compose.yml**:
```yaml
services:
  frontend:
    image: myapp/frontend:latest
    environment:
      - APP_API_URL=${API_URL}
      - APP_ENV=${ENVIRONMENT}
      - APP_ANALYTICS_ID=${ANALYTICS_ID}
    volumes:
      - ./config.json:/app/config.json
    command: ["/app/serve", "-config", "/app/config.json", "-dir", "/app/build"]
```

**config.json**:
```json
{
  "server": {
    "port": 8080,
    "root_dir": "/app/build"
  },
  "features": {
    "spa_mode": true
  },
  "runtime_config": {
    "enabled": true,
    "route": "/runtime-config.js",
    "format": "js",
    "var_name": "APP_CONFIG",
    "env_prefix": "APP_",
    "no_cache": true
  }
}
```

**React (index.html)**:
```html
<!DOCTYPE html>
<html>
<head>
  <title>My App</title>
  <!-- Load runtime config FIRST -->
  <script src="/runtime-config.js"></script>
</head>
<body>
  <div id="root"></div>
  <script src="/static/js/main.js"></script>
</body>
</html>
```

**React (src/config.js)**:
```javascript
// Read config from window
const config = window.APP_CONFIG || {};

export default {
  apiUrl: config.API_URL || 'http://localhost:3000',
  environment: config.ENV || 'development',
  analyticsId: config.ANALYTICS_ID || '',
};
```

### Example 2: Kubernetes Deployment

**kubernetes/configmap.yaml**:
```yaml
apiVersion: v1
kind: ConfigMap
metadata:
  name: frontend-config
data:
  APP_API_URL: "https://api.production.com"
  APP_VERSION: "v1.2.3"
  APP_FEATURE_NEW_UI: "true"
```

**kubernetes/deployment.yaml**:
```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: frontend
spec:
  replicas: 3
  template:
    spec:
      containers:
      - name: frontend
        image: myapp/frontend:latest
        ports:
        - containerPort: 8080
        envFrom:
        - configMapRef:
            name: frontend-config
        volumeMounts:
        - name: config
          mountPath: /app/config.json
          subPath: config.json
      volumes:
      - name: config
        configMap:
          name: serve-config
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: serve-config
data:
  config.json: |
    {
      "server": {
        "port": 8080,
        "root_dir": "/app/build"
      },
      "features": {
        "spa_mode": true
      },
      "runtime_config": {
        "enabled": true,
        "route": "/runtime-config.js",
        "format": "js",
        "env_prefix": "APP_",
        "no_cache": true
      }
    }
```

### Example 3: Vue.js with JSON Format

**config.json**:
```json
{
  "runtime_config": {
    "enabled": true,
    "route": "/config.json",
    "format": "json",
    "env_prefix": "VUE_APP_",
    "no_cache": true
  }
}
```

**Vue (src/main.js)**:
```javascript
import { createApp } from 'vue'
import App from './App.vue'

// Fetch runtime config before mounting app
fetch('/config.json')
  .then(res => res.json())
  .then(config => {
    const app = createApp(App)
    app.config.globalProperties.$config = config
    app.mount('#app')
  })
  .catch(err => {
    console.error('Failed to load config:', err)
    // Fallback to defaults
    const app = createApp(App)
    app.config.globalProperties.$config = {}
    app.mount('#app')
  })
```

**Vue Component**:
```vue
<template>
  <div>
    <p>API URL: {{ $config.API_URL }}</p>
    <p>Version: {{ $config.VERSION }}</p>
  </div>
</template>
```

## Security Considerations

1. **Never expose secrets**: Don't include sensitive values (API keys, passwords)
2. **Use specific variables**: Prefer `env_variables` over `env_prefix` for security
3. **Validate in backend**: Frontend config is public, validate everything server-side
4. **Use HTTPS**: Protect config in transit with HTTPS
5. **Consider auth**: Use basic auth if config contains semi-sensitive data

**Bad Example** (DON'T DO THIS):
```bash
APP_SECRET_KEY=super-secret-123
APP_DATABASE_PASSWORD=password123
```

**Good Example**:
```bash
APP_API_URL=https://api.example.com
APP_ENVIRONMENT=production
APP_FEATURE_FLAG=true
```

## Caching Strategy

### No Cache (Recommended for Runtime Config)

```json
{
  "no_cache": true
}
```

This adds headers:
```
Cache-Control: no-cache, no-store, must-revalidate
Pragma: no-cache
Expires: 0
```

**Why**: Ensures frontend always gets latest config when env vars change.

### With Cache (Use Carefully)

```json
{
  "no_cache": false
}
```

Uses default cache headers from `performance.cache_max_age`.

**When to use**: If config rarely changes and you want better performance.

## Troubleshooting

### Config is empty

**Problem**: `/runtime-config.js` returns `{}`

**Solutions**:
1. Check environment variables are set: `env | grep APP_`
2. Verify prefix matches: `"env_prefix": "APP_"` needs vars starting with `APP_`
3. Check specific vars exist: If using `env_variables`, ensure they're set

### Variables not updating

**Problem**: Changes to env vars don't reflect in output

**Solutions**:
1. Restart the server (env vars are read at request time, but server needs restart)
2. Check `no_cache: true` is set
3. Clear browser cache

### Wrong format

**Problem**: Expected JSON but got JavaScript

**Solution**: Check `"format": "json"` is set correctly

### Route not found

**Problem**: 404 on `/runtime-config.js`

**Solutions**:
1. Verify `"enabled": true`
2. Check `route` configuration matches your request
3. Ensure runtime config is registered before main handler (it should be automatic)

## Performance Impact

- **Negligible**: Reading env vars is very fast (cached by OS)
- **No file I/O**: Everything is in memory
- **No database**: No external dependencies
- **Adds ~1ms**: To first request only (if no-cache is false)

## Comparison with Alternatives

| Approach | Pros | Cons |
|----------|------|------|
| **Runtime Config** | ✓ Single image<br>✓ Dynamic config<br>✓ Simple | ✗ Public config<br>✗ Needs server |
| **Build-time** | ✓ Static<br>✓ No server needed | ✗ Rebuild per env<br>✗ Slow deploys |
| **Inject at deploy** | ✓ Single image | ✗ Complex<br>✗ Needs build tools |
| **Config service** | ✓ Centralized<br>✓ Dynamic | ✗ Extra dependency<br>✗ Network calls |

## Best Practices

1. **Use prefix**: `APP_` or `REACT_APP_` keeps it organized
2. **Enable no-cache**: Ensures config is always fresh
3. **Load early**: Fetch config before app initialization
4. **Provide defaults**: Gracefully handle missing config
5. **Document vars**: List all expected env vars in README
6. **Validate types**: Convert strings to numbers/booleans as needed
7. **Use TypeScript**: Type your config for safety

## Example: Full React Setup

**Dockerfile**:
```dockerfile
FROM node:18 AS builder
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM alpine:latest
RUN apk add --no-cache ca-certificates
COPY --from=builder /app/build /app/build
COPY --from=builder /app/serve /app/serve
COPY --from=builder /app/config.json /app/config.json
EXPOSE 8080
CMD ["/app/serve", "-config", "/app/config.json", "-dir", "/app/build"]
```

**config.json**:
```json
{
  "server": {
    "port": 8080,
    "root_dir": "/app/build"
  },
  "features": {
    "spa_mode": true,
    "index_files": ["index.html"]
  },
  "performance": {
    "enable_compression": true,
    "enable_cache": true,
    "cache_max_age": 86400
  },
  "runtime_config": {
    "enabled": true,
    "route": "/runtime-config.js",
    "format": "js",
    "var_name": "REACT_APP_CONFIG",
    "env_prefix": "REACT_APP_",
    "no_cache": true
  }
}
```

**src/config.ts**:
```typescript
interface Config {
  API_URL: string;
  ENV: string;
  FEATURE_X: boolean;
}

declare global {
  interface Window {
    REACT_APP_CONFIG?: Record<string, string>;
  }
}

const rawConfig = window.REACT_APP_CONFIG || {};

const config: Config = {
  API_URL: rawConfig.API_URL || 'http://localhost:3000',
  ENV: rawConfig.ENV || 'development',
  FEATURE_X: rawConfig.FEATURE_X === 'true',
};

export default config;
```

---

**Last Updated**: 2025-10-29
**Version**: 1.1.0

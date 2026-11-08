# ASS — Server Service

Binario único en Rust que reemplaza **Nginx/Caddy + Certbot + PM2/Systemd + ngrok** con un solo archivo de configuración.

## Características

| Módulo | Descripción |
|--------|-------------|
| **Proxy inverso** | HTTP/HTTPS nativo con hyper + tokio. Enrutamiento por dominio/subdominio, wildcard, fallback SPA |
| **TLS automático** | Cliente ACME integrado (Let's Encrypt / ZeroSSL). Emisión, renovación automática (<30 días), SNI dinámico |
| **Gestión de procesos** | Supervisión con reinicio automático, logs rotativos, señales de control (stop/restart/reload) |
| **Build engine** | `git clone/pull` + comandos de build nativos. Auto-rebuild al detectar cambios |
| **Firewall de app** | Allowlist/blocklist CIDR, rate limiting por IP, bloqueo sin Host, límite de body |
| **Headers seguros** | HSTS, CSP, X-Frame-Options, etc. automáticos por app |
| **Túneles** | WebSocket hacia servidor relay para exponer servicios detrás de CGNAT/IP dinámica |
| **Self-updater** | `ass update` descarga, verifica firma Ed25519 y reemplaza el binario atómicamente |

## Instalación rápida

```bash
# Descargar binario
curl -L https://github.com/ass-project/ss/releases/latest/download/ss-linux-amd64 -o ss
chmod +x ss
sudo mv ss /usr/local/bin/
```

## Uso

```bash
ss init          # Genera ass.toml de ejemplo
ss validate      # Valida la configuración
ss start         # Inicia todos los servicios
ss status        # Estado de procesos y certificados
ss logs mi-api   # Logs en tiempo real
ss cert issue api.ejemplo.com  # Emite certificado manualmente
ss update        # Actualiza SS
ss info          # Información del sistema
```

## Configuración (`ass.toml`)

```toml
[server]
host = "0.0.0.0"
http_port = 80
https_port = 443
ssl_email = "admin@ejemplo.com"
acme_provider = "letsencrypt"
force_https = true

# ─── App backend (Go, Node, Python, etc.) ───────────────────
[[app]]
name = "mi-api"
domain = "api.ejemplo.com"
repo = "https://github.com/usuario/mi-api"
branch = "main"
workdir = "/srv/mi-api"
build = "go build -o app ./cmd/server"
exec = "./app"
port = 8080
auto_update = true
poll_interval_secs = 60
security_headers = true
max_restarts = 10
restart_delay_secs = 2

[app.env]
DATABASE_URL = "postgres://localhost/mydb"
APP_ENV = "production"

# ─── Frontend estático ───────────────────────────────────────
[[app]]
name = "frontend"
domain = "ejemplo.com"
domains = ["www.ejemplo.com"]

[[app.static_routes]]
prefix = "/"
dir = "/var/www/frontend/dist"
compress = true

# ─── Múltiples dominios en una app ───────────────────────────
[[app]]
name = "panel"
domain = "panel.ejemplo.com"
exec = "node server.js"
port = 3000
workdir = "/srv/panel"

# ─── Túneles (opcional) ──────────────────────────────────────
[tunnel]
enabled = false
relay_server = "relay.ejemplo.com:7000"
auth_token = "mi-token"

[[tunnel.tunnels]]
name = "dev-local"
local_port = 3000
proto = "http"
remote_subdomain = "dev"

# ─── Firewall ────────────────────────────────────────────────
[firewall]
enabled = true
rate_limit_rps = 100
rate_limit_burst = 200
allowlist = ["127.0.0.1/32", "10.0.0.0/8"]
max_body_mb = 10

# ─── Auto-update ─────────────────────────────────────────────
[updater]
auto_check = true
channel = "stable"
# verify_key = "clave-ed25519-hex"

# ─── Logging ─────────────────────────────────────────────────
[logging]
level = "info"
format = "pretty"   # pretty | json | compact
file = true
rotation = "daily"
keep = 7
```

## Como servicio systemd

```ini
# /etc/systemd/system/ass.service
[Unit]
Description=AASS - App Service Server
After=network.target

[Service]
ExecStart=/usr/local/bin/ass start --foreground -c /etc/ass/ass.toml
Restart=on-failure
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
```

```bash
systemctl enable --now ss
```

## Arquitectura

```
ss (binario único)
├── cli/         Clap CLI: start, stop, status, cert, update, logs...
├── config/      Parser de ass.toml / ass.json (serde + toml)
├── proxy/       Servidor HTTP/HTTPS (hyper/tokio), enrutamiento, ficheros estáticos
├── tls/         Gestor ACME: emisión, renovación, SNI dinámico (rustls)
├── firewall/    Allowlist/blocklist CIDR, rate limiter por IP (governor)
├── process/     Supervisor de procesos: spawn, restart, logs, BuildEngine
├── tunnel/      Cliente WebSocket hacia relay (tokio-tungstenite)
└── updater/     Self-update con verificación Ed25519 (ring)
```

## Construir desde fuente

```bash
git clone https://github.com/ass-project/ss
cd ss
cargo build --release
# Binario en: target/release/ss (~ 6-8 MB)
```

Requiere Rust 1.75+.

## Comparativa

| Herramienta | SS | Caddy | Nginx + Certbot |
|---|---|---|---|
| Binario único | ✓ | ✓ | ✗ |
| TLS automático | ✓ | ✓ | Con certbot |
| Gestión de procesos | ✓ | ✗ | Con PM2/systemd |
| Rate limiting | ✓ | Con plugins | Con módulo |
| Túneles | ✓ | ✗ | ✗ |
| Auto-update | ✓ | ✗ | ✗ |
| Config unificada | ✓ | Parcial | ✗ |
| Consumo en idle | ~5 MB | ~30 MB | ~20 MB |

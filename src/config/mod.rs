// config/mod.rs — Configuración unificada de ASS (ass.toml / ass.json)
use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

// ─────────────────────────────────────────────
//  Configuración raíz
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    #[serde(default)]
    pub server: ServerConfig,

    #[serde(default, rename = "app")]
    pub apps: Vec<AppConfig>,

    #[serde(default)]
    pub tunnel: TunnelConfig,

    #[serde(default)]
    pub firewall: FirewallConfig,

    #[serde(default)]
    pub updater: UpdaterConfig,

    #[serde(default)]
    pub logging: LoggingConfig,
}

// ─────────────────────────────────────────────
//  [server]
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerConfig {
    /// Dirección de escucha (default: 0.0.0.0)
    #[serde(default = "defaults::host")]
    pub host: String,

    /// Puerto HTTP (default: 80)
    #[serde(default = "defaults::http_port")]
    pub http_port: u16,

    /// Puerto HTTPS (default: 443)
    #[serde(default = "defaults::https_port")]
    pub https_port: u16,

    /// Email para Let's Encrypt / ZeroSSL
    pub ssl_email: Option<String>,

    /// Directorio donde se almacenan los certificados
    #[serde(default = "defaults::certs_dir")]
    pub certs_dir: PathBuf,

    /// Directorio de datos persistentes de ASS
    #[serde(default = "defaults::data_dir")]
    pub data_dir: PathBuf,

    /// Directorio de logs
    #[serde(default = "defaults::log_dir")]
    pub log_dir: PathBuf,

    /// Proveedor ACME (letsencrypt | zerossl)
    #[serde(default = "defaults::acme_provider")]
    pub acme_provider: AcmeProvider,

    /// Si true, redirige HTTP → HTTPS automáticamente
    #[serde(default = "defaults::force_https")]
    pub force_https: bool,

    /// Timeout de conexiones de proxy en segundos
    #[serde(default = "defaults::proxy_timeout")]
    pub proxy_timeout_secs: u64,

    /// Máximo de conexiones simultáneas (0 = ilimitado)
    #[serde(default)]
    pub max_connections: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "lowercase")]
pub enum AcmeProvider {
    LetsEncrypt,
    ZeroSSL,
    /// URL directa al directorio ACME (para staging / privado)
    Custom(String),
}

impl AcmeProvider {
    pub fn directory_url(&self) -> &str {
        match self {
            AcmeProvider::LetsEncrypt => "https://acme-v02.api.letsencrypt.org/directory",
            AcmeProvider::ZeroSSL => "https://acme.zerossl.com/v2/DV90",
            AcmeProvider::Custom(url) => url,
        }
    }
}

impl Default for ServerConfig {
    fn default() -> Self {
        Self {
            host: defaults::host(),
            http_port: defaults::http_port(),
            https_port: defaults::https_port(),
            ssl_email: None,
            certs_dir: defaults::certs_dir(),
            data_dir: defaults::data_dir(),
            log_dir: defaults::log_dir(),
            acme_provider: defaults::acme_provider(),
            force_https: defaults::force_https(),
            proxy_timeout_secs: defaults::proxy_timeout(),
            max_connections: 0,
        }
    }
}

// ─────────────────────────────────────────────
//  [[app]]
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    /// Nombre único de la aplicación
    pub name: String,

    /// Dominio(s) que enruta a esta app (soporta wildcards: *.example.com)
    pub domain: Option<String>,

    /// Lista alternativa si se usan múltiples dominios
    #[serde(default)]
    pub domains: Vec<String>,

    /// Comando de build (opcional)
    pub build: Option<String>,

    /// Directorio de trabajo para build/exec
    pub workdir: Option<PathBuf>,

    /// Repositorio git a sincronizar antes de build
    pub repo: Option<String>,

    /// Rama git (default: main)
    #[serde(default = "defaults::git_branch")]
    pub branch: String,

    /// Comando de inicio del proceso
    pub exec: Option<String>,

    /// Puerto interno al que proxy apunta
    pub port: Option<u16>,

    /// Socket Unix alternativo
    pub socket: Option<PathBuf>,

    /// Variables de entorno para el proceso
    #[serde(default)]
    pub env: std::collections::HashMap<String, String>,

    /// Si true, ASS gestiona auto-pull + rebuild al detectar cambios
    #[serde(default)]
    pub auto_update: bool,

    /// Intervalo en segundos para poll de git (default: 60)
    #[serde(default = "defaults::poll_interval")]
    pub poll_interval_secs: u64,

    /// Máx reintentos antes de marcar el proceso como failed
    #[serde(default = "defaults::max_restarts")]
    pub max_restarts: u32,

    /// Delay entre reinicios en segundos
    #[serde(default = "defaults::restart_delay")]
    pub restart_delay_secs: u64,

    /// Si false, no se solicita TLS para este app
    #[serde(default = "defaults::tls_enabled")]
    pub tls: bool,

    /// Rutas estáticas: prefijo → directorio local
    #[serde(default)]
    pub static_routes: Vec<StaticRoute>,

    /// Cabeceras extras a añadir a las respuestas
    #[serde(default)]
    pub extra_headers: std::collections::HashMap<String, String>,

    /// Headers de seguridad automáticos (CSP, HSTS, etc.)
    #[serde(default = "defaults::security_headers")]
    pub security_headers: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StaticRoute {
    pub prefix: String,
    pub dir: PathBuf,
    /// Habilitar gzip/brotli en ficheros estáticos
    #[serde(default)]
    pub compress: bool,
}

impl AppConfig {
    /// Retorna todos los dominios configurados para esta app
    pub fn all_domains(&self) -> Vec<String> {
        let mut d = self.domains.clone();
        if let Some(ref dom) = self.domain {
            if !d.contains(dom) {
                d.insert(0, dom.clone());
            }
        }
        d
    }
}

// ─────────────────────────────────────────────
//  [tunnel]
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize, Default)]
pub struct TunnelConfig {
    /// Habilitar módulo de túneles
    #[serde(default)]
    pub enabled: bool,

    /// Servidor relay al que conectarse
    pub relay_server: Option<String>,

    /// Token de autenticación en el relay
    pub auth_token: Option<String>,

    /// Túneles individuales
    #[serde(default)]
    pub tunnels: Vec<TunnelEntry>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TunnelEntry {
    pub name: String,
    /// Puerto local a exponer
    pub local_port: u16,
    /// Subdominio remoto asignado
    pub remote_subdomain: Option<String>,
    /// Protocolo (tcp | http | https)
    #[serde(default = "defaults::tunnel_proto")]
    pub proto: String,
}

// ─────────────────────────────────────────────
//  [firewall]
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallConfig {
    /// Activar módulo de firewall de aplicación
    #[serde(default = "defaults::firewall_enabled")]
    pub enabled: bool,

    /// IPs/CIDRs siempre permitidas (bypass total)
    #[serde(default)]
    pub allowlist: Vec<String>,

    /// IPs/CIDRs bloqueadas
    #[serde(default)]
    pub blocklist: Vec<String>,

    /// Rate limiting global: peticiones por segundo por IP
    #[serde(default = "defaults::rate_limit_rps")]
    pub rate_limit_rps: u32,

    /// Burst máximo antes de empezar a rechazar
    #[serde(default = "defaults::rate_limit_burst")]
    pub rate_limit_burst: u32,

    /// Si true, bloquea peticiones sin Host header
    #[serde(default = "defaults::block_no_host")]
    pub block_no_host: bool,

    /// Tamaño máximo del body en MB (0 = ilimitado)
    #[serde(default = "defaults::max_body_mb")]
    pub max_body_mb: u64,

    /// Países bloqueados (códigos ISO, requiere GeoIP DB)
    #[serde(default)]
    pub blocked_countries: Vec<String>,
}

impl Default for FirewallConfig {
    fn default() -> Self {
        Self {
            enabled: defaults::firewall_enabled(),
            allowlist: vec![],
            blocklist: vec![],
            rate_limit_rps: defaults::rate_limit_rps(),
            rate_limit_burst: defaults::rate_limit_burst(),
            block_no_host: defaults::block_no_host(),
            max_body_mb: defaults::max_body_mb(),
            blocked_countries: vec![],
        }
    }
}

// ─────────────────────────────────────────────
//  [updater]
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdaterConfig {
    /// URL base de releases (GitHub releases API u otro)
    #[serde(default = "defaults::update_url")]
    pub release_url: String,

    /// Clave pública Ed25519 para verificar firmas (hex)
    pub verify_key: Option<String>,

    /// Si true, `ss` comprueba updates al inicio
    #[serde(default)]
    pub auto_check: bool,

    /// Canal: stable | beta | nightly
    #[serde(default = "defaults::update_channel")]
    pub channel: String,
}

impl Default for UpdaterConfig {
    fn default() -> Self {
        Self {
            release_url: defaults::update_url(),
            verify_key: None,
            auto_check: false,
            channel: defaults::update_channel(),
        }
    }
}

// ─────────────────────────────────────────────
//  [logging]
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoggingConfig {
    /// Nivel de log: trace | debug | info | warn | error
    #[serde(default = "defaults::log_level")]
    pub level: String,

    /// Formato: pretty | json | compact
    #[serde(default = "defaults::log_format")]
    pub format: String,

    /// Si true, escribe logs a archivos en log_dir
    #[serde(default)]
    pub file: bool,

    /// Rotación de logs: daily | hourly | never
    #[serde(default = "defaults::log_rotation")]
    pub rotation: String,

    /// Máx archivos de log a retener
    #[serde(default = "defaults::log_keep")]
    pub keep: usize,
}

impl Default for LoggingConfig {
    fn default() -> Self {
        Self {
            level: defaults::log_level(),
            format: defaults::log_format(),
            file: false,
            rotation: defaults::log_rotation(),
            keep: defaults::log_keep(),
        }
    }
}

// ─────────────────────────────────────────────
//  Defaults
// ─────────────────────────────────────────────

mod defaults {
    use super::AcmeProvider;
    use std::path::PathBuf;

    pub fn host() -> String { "0.0.0.0".into() }
    pub fn http_port() -> u16 { 80 }
    pub fn https_port() -> u16 { 443 }
    pub fn certs_dir() -> PathBuf { PathBuf::from("/etc/ass/certs") }
    pub fn data_dir() -> PathBuf { PathBuf::from("/var/lib/ass") }
    pub fn log_dir() -> PathBuf { PathBuf::from("/var/log/ass") }
    pub fn acme_provider() -> AcmeProvider { AcmeProvider::LetsEncrypt }
    pub fn force_https() -> bool { true }
    pub fn proxy_timeout() -> u64 { 30 }
    pub fn git_branch() -> String { "main".into() }
    pub fn poll_interval() -> u64 { 60 }
    pub fn max_restarts() -> u32 { 10 }
    pub fn restart_delay() -> u64 { 2 }
    pub fn tls_enabled() -> bool { true }
    pub fn security_headers() -> bool { true }
    pub fn tunnel_proto() -> String { "http".into() }
    pub fn firewall_enabled() -> bool { true }
    pub fn rate_limit_rps() -> u32 { 100 }
    pub fn rate_limit_burst() -> u32 { 200 }
    pub fn block_no_host() -> bool { true }
    pub fn max_body_mb() -> u64 { 10 }
    pub fn update_url() -> String {
        "https://api.github.com/repos/ass-project/ss/releases/latest".into()
    }
    pub fn update_channel() -> String { "stable".into() }
    pub fn log_level() -> String { "info".into() }
    pub fn log_format() -> String { "pretty".into() }
    pub fn log_rotation() -> String { "daily".into() }
    pub fn log_keep() -> usize { 7 }
}

// ─────────────────────────────────────────────
//  Loader
// ─────────────────────────────────────────────

impl Config {
    /// Carga la configuración desde el archivo (auto-detecta .toml / .json)
    pub fn load(path: &Path) -> Result<Self> {
        let content = std::fs::read_to_string(path)
            .with_context(|| format!("No se pudo leer el archivo de configuración: {}", path.display()))?;

        let cfg: Config = if path.extension().map(|e| e == "json").unwrap_or(false) {
            serde_json::from_str(&content)
                .with_context(|| "Error al parsear ass.json")?
        } else {
            toml::from_str(&content)
                .with_context(|| "Error al parsear ass.toml")?
        };

        cfg.validate()?;
        Ok(cfg)
    }

    /// Busca el archivo de config en ubicaciones estándar
    pub fn find_and_load() -> Result<(Self, PathBuf)> {
        let candidates = [
            PathBuf::from("ass.toml"),
            PathBuf::from("ass.json"),
            PathBuf::from("/etc/ass/ass.toml"),
            PathBuf::from("/etc/ass/ass.json"),
        ];

        for path in &candidates {
            if path.exists() {
                tracing::info!("Usando configuración: {}", path.display());
                return Ok((Self::load(path)?, path.clone()));
            }
        }

        anyhow::bail!(
            "No se encontró archivo de configuración. Crea un ass.toml o ejecuta `ass init`"
        )
    }

    /// Genera una configuración de ejemplo
    pub fn example_toml() -> &'static str {
        r#"
[server]
host = "0.0.0.0"
http_port = 80
https_port = 443
ssl_email = "admin@ejemplo.com"
acme_provider = "letsencrypt"
force_https = true

[[app]]
name = "mi-api"
domain = "api.ejemplo.com"
build = "go build -o app main.go"
exec = "./app"
port = 8080
auto_update = true
poll_interval_secs = 60
security_headers = true

[app.env]
DATABASE_URL = "postgres://localhost/mydb"
APP_ENV = "production"

[[app]]
name = "frontend"
domain = "ejemplo.com"
workdir = "/var/www/frontend"

[[app.static_routes]]
prefix = "/"
dir = "/var/www/frontend/dist"
compress = true

[tunnel]
enabled = false
relay_server = "relay.ejemplo.com:7000"
auth_token = "mi-token-secreto"

[[tunnel.tunnels]]
name = "dev-api"
local_port = 3000
proto = "http"
remote_subdomain = "dev"

[firewall]
enabled = true
rate_limit_rps = 100
rate_limit_burst = 200
allowlist = ["127.0.0.1/32", "10.0.0.0/8"]
blocklist = []
block_no_host = true
max_body_mb = 10

[updater]
auto_check = true
channel = "stable"

[logging]
level = "info"
format = "pretty"
file = true
rotation = "daily"
keep = 7
"#
    }

    /// Valida coherencia básica de la configuración
    fn validate(&self) -> Result<()> {
        for app in &self.apps {
            if app.name.is_empty() {
                anyhow::bail!("Todas las apps deben tener un `name`");
            }
            if app.port.is_none() && app.socket.is_none() && app.static_routes.is_empty() {
                anyhow::bail!(
                    "La app '{}' debe tener `port`, `socket` o `static_routes`",
                    app.name
                );
            }
            if app.all_domains().is_empty() {
                tracing::warn!("La app '{}' no tiene dominios configurados; no se creará ninguna ruta de proxy", app.name);
            }
        }
        if self.server.ssl_email.is_none() {
            tracing::warn!("No hay `ssl_email` configurado; TLS automático estará deshabilitado");
        }
        Ok(())
    }
}

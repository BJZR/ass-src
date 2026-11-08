// cli/mod.rs — Definición de la interfaz CLI con clap
use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser, Debug)]
#[command(
    name = "ass",
    version = env!("CARGO_PKG_VERSION"),
    author,
    about = "ASS - Server Service: proxy inverso, TLS automático, gestión de procesos y más",
    long_about = r#"
ASS (App Service) es un binario único que reemplaza Nginx/Caddy + Certbot +
PM2/Systemd + ngrok, gestionado desde un único archivo ass.toml.

Ejemplos:
  ass start                    # Inicia ASS con ass.toml en el directorio actual
  ass start -c /etc/ass/ass.toml # Inicia con configuración específica
  ass status                   # Estado de todos los servicios
  ass restart mi-api           # Reinicia la app "mi-api"
  ass logs mi-api              # Muestra logs en tiempo real
  ass cert issue app.ej.com    # Emite/renueva certificado manualmente
  ass update                   # Actualiza ASS a la última versión
  ass init                     # Genera ass.toml de ejemplo
"#
)]
pub struct Cli {
    /// Ruta al archivo de configuración (default: ass.toml)
    #[arg(short, long, global = true, value_name = "FILE")]
    pub config: Option<PathBuf>,

    /// Nivel de verbosidad: -v info, -vv debug, -vvv trace
    #[arg(short, long, global = true, action = clap::ArgAction::Count)]
    pub verbose: u8,

    #[command(subcommand)]
    pub command: Commands,
}

#[derive(Subcommand, Debug)]
pub enum Commands {
    /// Inicia ASS y todos los servicios definidos en la configuración
    Start(StartArgs),

    /// Detiene todos los servicios
    Stop,

    /// Reinicia ASS o una app específica
    Restart(AppSelector),

    /// Muestra el estado de todos los servicios
    Status,

    /// Muestra los logs de una app en tiempo real (tail -f)
    Logs(LogsArgs),

    /// Gestión de certificados TLS
    Cert(CertCommand),

    /// Actualiza el binario ASS a la última versión
    Update(UpdateArgs),

    /// Genera un ass.toml de ejemplo en el directorio actual
    Init(InitArgs),

    /// Valida la configuración sin iniciar servicios
    Validate,

    /// Muestra información del sistema y diagnósticos
    Info,

    /// Gestiona los túneles de exposición
    Tunnel(TunnelCommand),

    /// Recarga la configuración sin reiniciar (hot reload)
    Reload,
}

// ─── Argumentos de subcomandos ─────────────────

#[derive(Args, Debug)]
pub struct StartArgs {
    /// Ejecutar en primer plano (por defecto va a background si hay systemd)
    #[arg(short, long)]
    pub foreground: bool,

    /// No emitir certificados TLS al inicio
    #[arg(long)]
    pub no_tls: bool,

    /// No iniciar los procesos de las apps
    #[arg(long)]
    pub no_apps: bool,
}

#[derive(Args, Debug)]
pub struct AppSelector {
    /// Nombre de la app (omitir para reiniciar todo)
    pub app: Option<String>,
}

#[derive(Args, Debug)]
pub struct LogsArgs {
    /// Nombre de la app
    pub app: String,

    /// Número de líneas a mostrar del histórico
    #[arg(short = 'n', long, default_value = "50")]
    pub lines: usize,

    /// No hacer tail; mostrar solo las últimas N líneas y salir
    #[arg(long)]
    pub no_follow: bool,
}

#[derive(Args, Debug)]
pub struct CertCommand {
    #[command(subcommand)]
    pub action: CertAction,
}

#[derive(Subcommand, Debug)]
pub enum CertAction {
    /// Emite o renueva un certificado para un dominio
    Issue {
        /// Dominio(s) para el certificado
        #[arg(required = true)]
        domains: Vec<String>,
    },

    /// Lista todos los certificados gestionados
    List,

    /// Muestra detalles de un certificado
    Info {
        domain: String,
    },

    /// Revoca un certificado
    Revoke {
        domain: String,
    },
}

#[derive(Args, Debug)]
pub struct UpdateArgs {
    /// Solo comprobar si hay actualizaciones sin instalar
    #[arg(long)]
    pub check_only: bool,

    /// Canal de actualizaciones (stable, beta, nightly)
    #[arg(long)]
    pub channel: Option<String>,

    /// Forzar downgrade a una versión específica
    #[arg(long)]
    pub version: Option<String>,
}

#[derive(Args, Debug)]
pub struct InitArgs {
    /// Sobrescribir si ya existe ass.toml
    #[arg(short, long)]
    pub force: bool,

    /// Formato de salida: toml (default) | json
    #[arg(long, default_value = "toml")]
    pub format: String,
}

#[derive(Args, Debug)]
pub struct TunnelCommand {
    #[command(subcommand)]
    pub action: TunnelAction,
}

#[derive(Subcommand, Debug)]
pub enum TunnelAction {
    /// Lista túneles activos y sus URLs públicas
    List,

    /// Expone un puerto local sin modificar ass.toml
    Open {
        /// Puerto local a exponer
        port: u16,
        /// Nombre del túnel
        #[arg(long)]
        name: Option<String>,
    },

    /// Cierra un túnel activo
    Close {
        name: String,
    },
}

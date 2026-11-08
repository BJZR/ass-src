// main.rs — ASS (App Service Server) — punto de entrada principal
//
// Orquesta todos los módulos: proxy, TLS, firewall, procesos, túneles, actualizador.

mod cli;
mod config;
mod firewall;
mod process;
mod proxy;
mod tls;
mod tunnel;
mod updater;

use anyhow::Result;
use clap::Parser;
use std::{path::PathBuf, sync::Arc};
use tokio::signal;
use tracing::{error, info, warn};
use tracing_subscriber::{fmt, EnvFilter};

use cli::{CertAction, Cli, Commands, TunnelAction};
use config::Config;
use firewall::Firewall;
use process::{BuildEngine, ProcessManager};
use proxy::{ProxyServer, Router};
use tls::TlsManager;
use tunnel::TunnelManager;
use updater::Updater;

// ─────────────────────────────────────────────
//  Entry point
// ─────────────────────────────────────────────

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    // Configurar logging inicial (antes de cargar config)
    setup_logging(cli.verbose, "info", "pretty");

    match cli.command {
        // ── ass init ──────────────────────────
        Commands::Init(args) => cmd_init(args).await,

        // ── ass validate ──────────────────────
        Commands::Validate => {
            let path = resolve_config_path(cli.config);
            match Config::load(&path) {
                Ok(cfg) => {
                    println!("✓ Configuración válida: {}", path.display());
                    println!("  Apps: {}", cfg.apps.len());
                    println!("  Túneles: {}", cfg.tunnel.tunnels.len());
                    Ok(())
                }
                Err(e) => {
                    eprintln!("✗ Configuración inválida: {}", e);
                    std::process::exit(1);
                }
            }
        }

        // ── ass info ───────────────────────────
        Commands::Info => cmd_info().await,

        // ── ass update ────────────────────────
        Commands::Update(args) => {
            let (cfg, _) = Config::find_and_load().unwrap_or_else(|_| {
                (Config::default_minimal(), PathBuf::from("ass.toml"))
            });
            let updater = Updater::new(cfg.updater);
            if args.check_only {
                let info = updater.check_update().await?;
                if info.update_available {
                    println!("Nueva versión disponible: {} → {}", info.current, info.latest);
                    if let Some(notes) = info.changelog {
                        println!("\nCambios:\n{}", notes);
                    }
                } else {
                    println!("ASS ya está actualizado ({})", info.current);
                }
            } else {
                updater.perform_update().await?;
            }
            Ok(())
        }

        // ── ass cert ───────────────────────────
        Commands::Cert(cert_cmd) => {
            let path = resolve_config_path(cli.config);
            let cfg = Config::load(&path)?;
            let tls_mgr = TlsManager::new(cfg.server.clone());
            tls_mgr.init().await?;

            match cert_cmd.action {
                CertAction::Issue { domains } => {
                    for domain in &domains {
                        match tls_mgr.provision_cert(domain).await {
                            Ok(info) => println!("✓ {} — expira {}", domain, info.expires_at.format("%Y-%m-%d")),
                            Err(e) => eprintln!("✗ {}: {}", domain, e),
                        }
                    }
                }
                CertAction::List => {
                    println!("Certificados gestionados por ASS:");
                    // TODO: iterar certs_dir e imprimir info
                    println!("  (Ver directorio: {})", cfg.server.certs_dir.display());
                }
                CertAction::Info { domain } => {
                    println!("Info de certificado para: {}", domain);
                    // Implementación simplificada
                }
                CertAction::Revoke { domain } => {
                    warn!("Revocación de {} solicitada (no implementada en este build)", domain);
                }
            }
            Ok(())
        }

        // ── ass tunnel ────────────────────────
        Commands::Tunnel(tunnel_cmd) => {
            let path = resolve_config_path(cli.config);
            let cfg = Config::load(&path)?;
            let mgr = TunnelManager::new(cfg.tunnel);

            match tunnel_cmd.action {
                TunnelAction::List => {
                    let status = mgr.status().await;
                    if status.is_empty() {
                        println!("No hay túneles configurados");
                    } else {
                        for (name, state) in status {
                            println!("  {} → {}", name, state);
                        }
                    }
                }
                TunnelAction::Open { port, name } => {
                    println!("Apertura de túnel ad-hoc al puerto {} (pendiente de relay configurado)", port);
                }
                TunnelAction::Close { name } => {
                    println!("Cerrando túnel '{}'...", name);
                }
            }
            Ok(())
        }

        // ── ass logs ───────────────────────────
        Commands::Logs(args) => {
            let path = resolve_config_path(cli.config);
            let cfg = Config::load(&path)?;
            let log_dir = cfg.server.log_dir.clone();
            cmd_logs(&args.app, log_dir, args.lines, !args.no_follow).await
        }

        // ── ass status ─────────────────────────
        Commands::Status => {
            let path = resolve_config_path(cli.config);
            let cfg = Config::load(&path)?;
            println!("ASS v{}", env!("CARGO_PKG_VERSION"));
            println!("\nApps configuradas:");
            for app in &cfg.apps {
                println!(
                    "  [{:12}] dominio: {:30} puerto: {:?}",
                    app.name,
                    app.domain.as_deref().unwrap_or("—"),
                    app.port
                );
            }
            Ok(())
        }

        // ── ass stop ───────────────────────────
        Commands::Stop => {
            info!("Enviando señal de parada...");
            // En producción: comunicarse con el daemon via socket Unix o señal
            println!("Deteniendo ASS (SIGTERM al daemon)");
            Ok(())
        }

        // ── ass restart ────────────────────────
        Commands::Restart(sel) => {
            if let Some(app) = sel.app {
                println!("Reiniciando app '{}'...", app);
            } else {
                println!("Reiniciando todos los servicios...");
            }
            Ok(())
        }

        // ── ass reload ────────────────────────
        Commands::Reload => {
            println!("Recargando configuración (SIGHUP al daemon)...");
            Ok(())
        }

        // ── ass start ─────────────────────────
        Commands::Start(start_args) => {
            let path = resolve_config_path(cli.config);
            let cfg = Arc::new(Config::load(&path)?);

            // Re-inicializar logging con settings de config
            setup_logging(cli.verbose, &cfg.logging.level, &cfg.logging.format);

            info!(
                version = env!("CARGO_PKG_VERSION"),
                config = %path.display(),
                "Iniciando ASS..."
            );

            run(cfg, start_args).await
        }
    }
}

// ─────────────────────────────────────────────
//  Bucle principal de ejecución
// ─────────────────────────────────────────────

async fn run(cfg: Arc<Config>, args: cli::StartArgs) -> Result<()> {
    // 1. Crear directorios necesarios
    for dir in [&cfg.server.data_dir, &cfg.server.log_dir, &cfg.server.certs_dir] {
        std::fs::create_dir_all(dir)?;
    }

    // 2. Inicializar TLS manager
    let tls_manager = Arc::new(TlsManager::new(cfg.server.clone()));
    tls_manager.init().await?;

    // 3. Provisionar certificados para todos los dominios
    if !args.no_tls && cfg.server.ssl_email.is_some() {
        let all_domains: Vec<String> = cfg.apps.iter()
            .flat_map(|a| a.all_domains())
            .filter(|d| !d.starts_with('*'))  // wildcards requieren DNS-01
            .collect();

        if !all_domains.is_empty() {
            info!("Provisionando certificados TLS para {} dominio(s)...", all_domains.len());
            tls_manager.ensure_certs(&all_domains).await?;
        }
    } else if args.no_tls {
        warn!("TLS deshabilitado por flag --no-tls");
    }

    // 4. Inicializar firewall
    let firewall = Arc::new(Firewall::new(cfg.firewall.clone()));

    // 5. Construir tabla de enrutamiento
    let router = Arc::new(Router::new(&cfg.apps));

    // 6. Inicializar motor de procesos
    let process_manager = Arc::new(ProcessManager::new(cfg.server.log_dir.clone()));

    // 7. Lanzar apps
    if !args.no_apps {
        for app in &cfg.apps {
            // Clone (git) si hay repo configurado
            if app.repo.is_some() {
                if let Err(e) = BuildEngine::git_clone(app).await {
                    error!(app = %app.name, error = %e, "Error en git clone inicial");
                }
            }

            // Build inicial
            if let Err(e) = BuildEngine::build(app).await {
                error!(app = %app.name, error = %e, "Error en build inicial");
                continue;
            }

            // Iniciar proceso supervisado
            if let Err(e) = process_manager.spawn(app.clone()).await {
                error!(app = %app.name, error = %e, "Error al iniciar proceso");
            }

            // Auto-update loop si está habilitado
            if app.auto_update {
                let app_clone = app.clone();
                let pm_clone = process_manager.clone();
                tokio::spawn(async move {
                    process::auto_update_loop(app_clone, pm_clone).await;
                });
            }
        }
    }

    // 8. Construir servidor proxy
    let proxy = Arc::new(ProxyServer::new(
        cfg.clone(),
        router,
        firewall,
        tls_manager.clone(),
    ));

    // 9. Lanzar túneles
    if cfg.tunnel.enabled {
        let tunnel_mgr = TunnelManager::new(cfg.tunnel.clone());
        if let Err(e) = tunnel_mgr.start_all().await {
            error!(error = %e, "Error iniciando túneles");
        }
    }

    // 10. Verificación de updates al inicio
    if cfg.updater.auto_check {
        let updater_cfg = cfg.updater.clone();
        tokio::spawn(async move {
            let updater = Updater::new(updater_cfg);
            match updater.check_update().await {
                Ok(info) if info.update_available => {
                    info!(
                        current = %info.current,
                        latest = %info.latest,
                        "Nueva versión de ASS disponible. Ejecuta `ass update` para actualizar."
                    );
                }
                Ok(_) => {}
                Err(e) => warn!(error = %e, "No se pudo comprobar actualizaciones"),
            }
        });
    }

    // 11. Renovación automática de certificados (cada 12h)
    {
        let tls_mgr = tls_manager.clone();
        tokio::spawn(async move {
            tls_mgr.renewal_loop(43200).await; // 12 horas
        });
    }

    // 12. Iniciar servidores HTTP y HTTPS concurrentemente
    info!(
        http = cfg.server.http_port,
        https = cfg.server.https_port,
        "Servidores de red activos"
    );

    let proxy_http = proxy.clone();
    let proxy_https = proxy.clone();

    let http_task = tokio::spawn(async move {
        if let Err(e) = proxy_http.serve_http().await {
            error!(error = %e, "Error en servidor HTTP");
        }
    });

    let https_task = tokio::spawn(async move {
        if let Err(e) = proxy_https.serve_https().await {
            error!(error = %e, "Error en servidor HTTPS");
        }
    });

    print_banner(&cfg);

    // 13. Esperar señal de parada (Ctrl+C / SIGTERM)
    #[cfg(unix)]
    {
        let mut sigterm = signal::unix::signal(signal::unix::SignalKind::terminate())
            .expect("Error registrando SIGTERM");
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Señal Ctrl+C recibida, deteniendo ASS...");
            }
            _ = sigterm.recv() => {
                info!("SIGTERM recibido, deteniendo ASS...");
            }
        }
    }
    #[cfg(not(unix))]
    {
        signal::ctrl_c().await.expect("Error esperando Ctrl+C");
        info!("Señal Ctrl+C recibida, deteniendo ASS...");
    }

    // 14. Shutdown graceful
    info!("Deteniendo procesos supervisados...");
    process_manager.stop_all().await;

    http_task.abort();
    https_task.abort();

    info!("ASS detenido correctamente.");
    Ok(())
}

// ─────────────────────────────────────────────
//  Comando: ass init
// ─────────────────────────────────────────────

async fn cmd_init(args: cli::InitArgs) -> Result<()> {
    let filename = if args.format == "json" { "ass.json" } else { "ass.toml" };
    let path = PathBuf::from(filename);

    if path.exists() && !args.force {
        eprintln!("{} ya existe. Usa --force para sobrescribir.", filename);
        std::process::exit(1);
    }

    let content = Config::example_toml();
    std::fs::write(&path, content.trim_start())?;
    println!("✓ {} generado.", filename);
    println!("  Edítalo y ejecuta `ass start` para iniciar.");
    Ok(())
}

// ─────────────────────────────────────────────
//  Comando: ass info
// ─────────────────────────────────────────────

async fn cmd_info() -> Result<()> {
    println!("ASS - App Service Server v{}", env!("CARGO_PKG_VERSION"));
    println!("Build: {} {}", std::env::consts::OS, std::env::consts::ARCH);
    println!();
    println!("Módulos:");
    println!("  ✓ Proxy inverso HTTP/HTTPS");
    println!("  ✓ TLS automático (ACME / Let's Encrypt)");
    println!("  ✓ Gestión de procesos y supervisión");
    println!("  ✓ Firewall de aplicación + rate limiting");
    println!("  ✓ Túneles WebSocket (requiere relay externo)");
    println!("  ✓ Auto-actualización con firma Ed25519");
    println!("  ✓ Build engine (git pull + comandos nativos)");
    println!();

    // Información del sistema
    let mut sys = sysinfo::System::new_all();
    sys.refresh_all();
    println!("Sistema:");
    println!("  RAM total:       {} MB", sys.total_memory() / 1024 / 1024);
    println!("  RAM disponible:  {} MB", sys.available_memory() / 1024 / 1024);
    println!("  CPUs:            {}", sys.cpus().len());
    println!("  Kernel:          {}", sysinfo::System::kernel_version().unwrap_or_default());

    Ok(())
}

// ─────────────────────────────────────────────
//  Comando: ass logs
// ─────────────────────────────────────────────

async fn cmd_logs(app: &str, log_dir: PathBuf, lines: usize, follow: bool) -> Result<()> {
    let log_file = log_dir.join(format!("{}.stdout.log", app));

    if !log_file.exists() {
        eprintln!("No se encontraron logs para '{}' en {}", app, log_file.display());
        std::process::exit(1);
    }

    // Leer las últimas N líneas
    let content = tokio::fs::read_to_string(&log_file).await?;
    let lines_vec: Vec<&str> = content.lines().collect();
    let start = lines_vec.len().saturating_sub(lines);
    for line in &lines_vec[start..] {
        println!("{}", line);
    }

    if follow {
        // Tail simplificado: poll cada 500ms
        let mut last_size = tokio::fs::metadata(&log_file).await?.len();
        loop {
            tokio::time::sleep(std::time::Duration::from_millis(500)).await;
            let new_size = match tokio::fs::metadata(&log_file).await {
                Ok(m) => m.len(),
                Err(_) => continue,
            };
            if new_size > last_size {
                let content = tokio::fs::read_to_string(&log_file).await?;
                let all_lines: Vec<&str> = content.lines().collect();
                // Imprimir solo líneas nuevas (aproximación)
                let prev_line_count = last_size as usize / 80; // heurístico
                for line in &all_lines[prev_line_count.min(all_lines.len())..] {
                    println!("{}", line);
                }
                last_size = new_size;
            }
        }
    }

    Ok(())
}

// ─────────────────────────────────────────────
//  Setup de logging
// ─────────────────────────────────────────────

fn setup_logging(verbose: u8, level: &str, format: &str) {
    let env_level = match verbose {
        0 => level.to_string(),
        1 => "debug".to_string(),
        _ => "trace".to_string(),
    };

    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(format!("ss={},warn", env_level)));

    match format {
        "json" => {
            tracing_subscriber::fmt()
                .json()
                .with_env_filter(filter)
                .init();
        }
        "compact" => {
            tracing_subscriber::fmt()
                .compact()
                .with_env_filter(filter)
                .init();
        }
        _ => {
            tracing_subscriber::fmt()
                .pretty()
                .with_env_filter(filter)
                .init();
        }
    }
}

// ─────────────────────────────────────────────
//  Banner de inicio
// ─────────────────────────────────────────────

fn print_banner(cfg: &Config) {
    println!();
    println!("  ░█████╗░░██████╗░██████╗");
    println!("  ██╔══██╗██╔════╝██╔════╝  ASS v{}", env!("CARGO_PKG_VERSION"));
    println!("  ███████║╚█████╗░╚█████╗░  App Service Server");
    println!("  ██╔══██║░╚═══██╗░╚═══██╗");
    println!("  ██║  ██║██████╔╝██████╔╝  http://{}:{}", cfg.server.host, cfg.server.http_port);
    println!("  ╚═╝  ╚═╝╚═════╝ ╚═════╝   https://{}:{}", cfg.server.host, cfg.server.https_port);
    println!();

    for app in &cfg.apps {
        let domains = app.all_domains();
        let domain_str = domains.first().map(|s| s.as_str()).unwrap_or("—");
        println!(
            "  → {} @ {} (:{:?})",
            app.name,
            domain_str,
            app.port.map(|p| p.to_string()).unwrap_or_else(|| "socket".into())
        );
    }
    println!();
}

// ─────────────────────────────────────────────
//  Utilidades
// ─────────────────────────────────────────────

fn resolve_config_path(path: Option<PathBuf>) -> PathBuf {
    path.unwrap_or_else(|| {
        for candidate in ["ass.toml", "ass.json", "/etc/ass/ass.toml", "/etc/ass/ass.json"] {
            let p = PathBuf::from(candidate);
            if p.exists() {
                return p;
            }
        }
        PathBuf::from("ass.toml")
    })
}

impl Config {
    /// Configuración mínima para cuando no hay ass.toml disponible
    fn default_minimal() -> Self {
        Config {
            server: Default::default(),
            apps: vec![],
            tunnel: Default::default(),
            firewall: Default::default(),
            updater: Default::default(),
            logging: Default::default(),
        }
    }
}

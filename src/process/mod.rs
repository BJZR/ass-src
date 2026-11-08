// process/mod.rs — Gestión y supervisión de procesos backend
use crate::config::AppConfig;
use anyhow::{Context, Result};
use std::{
    collections::HashMap,
    path::PathBuf,
    process::Stdio,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    process::{Child, Command},
    sync::{mpsc, RwLock},
    time::sleep,
};
use tracing::{error, info, warn};

// ─────────────────────────────────────────────
//  Estado de un proceso supervisado
// ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum ProcessState {
    Starting,
    Running { pid: u32 },
    Stopped,
    Failed { reason: String },
    Restarting { attempt: u32 },
}

impl std::fmt::Display for ProcessState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessState::Starting => write!(f, "iniciando"),
            ProcessState::Running { pid } => write!(f, "corriendo (pid {})", pid),
            ProcessState::Stopped => write!(f, "detenido"),
            ProcessState::Failed { reason } => write!(f, "fallido: {}", reason),
            ProcessState::Restarting { attempt } => write!(f, "reiniciando (intento {})", attempt),
        }
    }
}

// ─────────────────────────────────────────────
//  Proceso supervisado individual
// ─────────────────────────────────────────────

pub struct SupervisedProcess {
    pub name: String,
    pub config: AppConfig,
    pub state: ProcessState,
    pub started_at: Option<Instant>,
    pub restart_count: u32,
    /// Canal para enviar señales al supervisor
    pub control_tx: mpsc::Sender<ProcessSignal>,
}

#[derive(Debug)]
pub enum ProcessSignal {
    Stop,
    Restart,
    Reload,
}

// ─────────────────────────────────────────────
//  Gestor de procesos principal
// ─────────────────────────────────────────────

pub struct ProcessManager {
    processes: Arc<RwLock<HashMap<String, Arc<RwLock<SupervisedProcess>>>>>,
    log_dir: PathBuf,
}

impl ProcessManager {
    pub fn new(log_dir: PathBuf) -> Self {
        Self {
            processes: Arc::new(RwLock::new(HashMap::new())),
            log_dir,
        }
    }

    /// Lanza una aplicación y la supervisa en background
    pub async fn spawn(&self, app: AppConfig) -> Result<()> {
        let exec = match app.exec.as_ref() {
            Some(e) => e.clone(),
            None => {
                info!(app = %app.name, "Sin exec definido, omitiendo supervisión de proceso");
                return Ok(());
            }
        };

        std::fs::create_dir_all(&self.log_dir)?;

        let name = app.name.clone();
        let (control_tx, control_rx) = mpsc::channel::<ProcessSignal>(8);

        let supervised = SupervisedProcess {
            name: name.clone(),
            config: app.clone(),
            state: ProcessState::Starting,
            started_at: None,
            restart_count: 0,
            control_tx,
        };

        let supervised = Arc::new(RwLock::new(supervised));
        self.processes.write().await.insert(name.clone(), supervised.clone());

        let log_dir = self.log_dir.clone();

        // Spawn del bucle de supervisión en background
        tokio::spawn(async move {
            supervision_loop(supervised, exec, app, control_rx, log_dir).await;
        });

        info!(app = %name, "Proceso supervisado iniciado");
        Ok(())
    }

    /// Envía señal a un proceso por nombre
    pub async fn signal(&self, name: &str, signal: ProcessSignal) -> Result<()> {
        let procs = self.processes.read().await;
        let proc = procs.get(name)
            .with_context(|| format!("No existe proceso '{}'", name))?;
        proc.read().await.control_tx.send(signal).await
            .context("Error al enviar señal al proceso")?;
        Ok(())
    }

    /// Detiene todos los procesos ordenadamente
    pub async fn stop_all(&self) {
        let procs = self.processes.read().await;
        for (name, proc) in procs.iter() {
            let _ = proc.read().await.control_tx.send(ProcessSignal::Stop).await;
            info!(app = %name, "Señal de parada enviada");
        }
    }

    /// Obtiene el estado actual de todos los procesos
    pub async fn status(&self) -> Vec<(String, ProcessState)> {
        let procs = self.processes.read().await;
        let mut result = Vec::new();
        for (name, proc) in procs.iter() {
            let state = proc.read().await.state.clone();
            result.push((name.clone(), state));
        }
        result
    }
}

// ─────────────────────────────────────────────
//  Bucle de supervisión
// ─────────────────────────────────────────────

async fn supervision_loop(
    supervised: Arc<RwLock<SupervisedProcess>>,
    exec: String,
    app: AppConfig,
    mut control_rx: mpsc::Receiver<ProcessSignal>,
    log_dir: PathBuf,
) {
    let max_restarts = app.max_restarts;
    let restart_delay = Duration::from_secs(app.restart_delay_secs);
    let mut restart_count = 0u32;

    loop {
        // Actualizar estado a Starting
        supervised.write().await.state = ProcessState::Restarting { attempt: restart_count };

        match launch_process(&exec, &app, &log_dir).await {
            Ok(mut child) => {
                let pid = child.id().unwrap_or(0);
                supervised.write().await.state = ProcessState::Running { pid };
                supervised.write().await.started_at = Some(Instant::now());

                info!(app = %app.name, pid = pid, "Proceso en ejecución");

                // Esperar: fin del proceso o señal de control
                tokio::select! {
                    status = child.wait() => {
                        match status {
                            Ok(exit) if exit.success() => {
                                info!(app = %app.name, "Proceso terminó normalmente");
                                supervised.write().await.state = ProcessState::Stopped;
                                break;
                            }
                            Ok(exit) => {
                                let reason = format!("Exit code: {}", exit);
                                error!(app = %app.name, reason = %reason, "Proceso falló");
                                supervised.write().await.state = ProcessState::Failed { reason };
                            }
                            Err(e) => {
                                let reason = e.to_string();
                                error!(app = %app.name, error = %reason, "Error esperando proceso");
                                supervised.write().await.state = ProcessState::Failed { reason };
                            }
                        }
                    }
                    signal = control_rx.recv() => {
                        match signal {
                            Some(ProcessSignal::Stop) | None => {
                                info!(app = %app.name, "Deteniendo proceso por señal");
                                let _ = child.kill().await;
                                supervised.write().await.state = ProcessState::Stopped;
                                return;
                            }
                            Some(ProcessSignal::Restart) => {
                                info!(app = %app.name, "Reiniciando por señal");
                                let _ = child.kill().await;
                                // Continúa el loop
                            }
                            Some(ProcessSignal::Reload) => {
                                // Enviar SIGHUP para reload graceful (Unix)
                                #[cfg(unix)]
                                {
                                    if let Some(pid) = child.id() {
                                        use nix::sys::signal::{kill, Signal};
                                        use nix::unistd::Pid;
                                        let _ = kill(Pid::from_raw(pid as i32), Signal::SIGHUP);
                                        info!(app = %app.name, pid = pid, "SIGHUP enviado (reload)");
                                    }
                                }
                                continue;
                            }
                        }
                    }
                }
            }
            Err(e) => {
                error!(app = %app.name, error = %e, "No se pudo lanzar proceso");
                supervised.write().await.state = ProcessState::Failed { reason: e.to_string() };
            }
        }

        // Comprobar límite de reinicios
        restart_count += 1;
        supervised.write().await.restart_count = restart_count;

        if restart_count >= max_restarts {
            error!(
                app = %app.name,
                restarts = restart_count,
                "Máximo de reinicios alcanzado; el proceso permanecerá detenido"
            );
            supervised.write().await.state = ProcessState::Failed {
                reason: format!("Máximo de {} reinicios alcanzado", max_restarts),
            };
            break;
        }

        warn!(
            app = %app.name,
            attempt = restart_count,
            delay_secs = restart_delay.as_secs(),
            "Esperando antes de reiniciar..."
        );
        sleep(restart_delay).await;
    }
}

// ─────────────────────────────────────────────
//  Lanzamiento del proceso hijo
// ─────────────────────────────────────────────

async fn launch_process(exec: &str, app: &AppConfig, log_dir: &PathBuf) -> Result<Child> {
    // Parsear el comando (soporta argumentos)
    let parts: Vec<&str> = exec.split_whitespace().collect();
    let (bin, args) = parts.split_first()
        .context("Comando exec vacío")?;

    let stdout_log = log_dir.join(format!("{}.stdout.log", app.name));
    let stderr_log = log_dir.join(format!("{}.stderr.log", app.name));

    let stdout_file = std::fs::OpenOptions::new()
        .create(true).append(true).open(&stdout_log)?;
    let stderr_file = std::fs::OpenOptions::new()
        .create(true).append(true).open(&stderr_log)?;

    let mut cmd = Command::new(bin);
    cmd.args(args)
        .stdout(Stdio::from(stdout_file))
        .stderr(Stdio::from(stderr_file))
        .kill_on_drop(true);

    // Variables de entorno
    for (k, v) in &app.env {
        cmd.env(k, v);
    }

    // Puerto como variable de entorno (convenio 12-factor)
    if let Some(port) = app.port {
        cmd.env("PORT", port.to_string());
    }

    // Directorio de trabajo
    if let Some(ref workdir) = app.workdir {
        cmd.current_dir(workdir);
    }

    let child = cmd.spawn()
        .with_context(|| format!("Error al ejecutar '{}'", exec))?;

    Ok(child)
}

// ─────────────────────────────────────────────
//  Motor de Build
// ─────────────────────────────────────────────

pub struct BuildEngine;

impl BuildEngine {
    /// Ejecuta el comando de build de una app
    pub async fn build(app: &AppConfig) -> Result<()> {
        let build_cmd = match app.build.as_ref() {
            Some(b) => b.clone(),
            None => return Ok(()),
        };

        info!(app = %app.name, cmd = %build_cmd, "Ejecutando build...");

        let parts: Vec<&str> = build_cmd.split_whitespace().collect();
        let (bin, args) = parts.split_first()
            .context("Comando build vacío")?;

        let mut cmd = tokio::process::Command::new(bin);
        cmd.args(args);

        for (k, v) in &app.env {
            cmd.env(k, v);
        }

        if let Some(ref workdir) = app.workdir {
            cmd.current_dir(workdir);
        }

        let output = cmd.output().await
            .with_context(|| format!("Error al ejecutar build: {}", build_cmd))?;

        if output.status.success() {
            info!(app = %app.name, "Build completado exitosamente");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            error!(app = %app.name, stderr = %stderr, "Build falló");
            anyhow::bail!("Build falló para '{}': {}", app.name, stderr)
        }
    }

    /// Hace git pull en el directorio de trabajo
    pub async fn git_pull(app: &AppConfig) -> Result<bool> {
        let workdir = app.workdir.as_ref()
            .context("workdir requerido para git pull")?;

        let output = tokio::process::Command::new("git")
            .args(["pull", "origin", &app.branch])
            .current_dir(workdir)
            .output()
            .await
            .context("Error al ejecutar git pull")?;

        if output.status.success() {
            let stdout = String::from_utf8_lossy(&output.stdout);
            let changed = !stdout.contains("Already up to date");
            if changed {
                info!(app = %app.name, "Cambios detectados en git");
            }
            Ok(changed)
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("git pull falló: {}", stderr)
        }
    }

    /// Clona un repositorio si workdir no existe
    pub async fn git_clone(app: &AppConfig) -> Result<()> {
        let repo = app.repo.as_ref().context("repo no configurado")?;
        let workdir = app.workdir.as_ref().context("workdir requerido para git clone")?;

        if workdir.exists() {
            return Ok(());
        }

        info!(app = %app.name, repo = %repo, "Clonando repositorio...");

        let output = tokio::process::Command::new("git")
            .args(["clone", "--branch", &app.branch, repo, workdir.to_str().unwrap_or(".")])
            .output()
            .await
            .context("Error al ejecutar git clone")?;

        if output.status.success() {
            info!(app = %app.name, "Repositorio clonado");
            Ok(())
        } else {
            let stderr = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!("git clone falló: {}", stderr)
        }
    }
}

// ─────────────────────────────────────────────
//  Auto-updater de apps (git poll + rebuild)
// ─────────────────────────────────────────────

pub async fn auto_update_loop(
    app: AppConfig,
    process_manager: Arc<ProcessManager>,
) {
    let interval = Duration::from_secs(app.poll_interval_secs);
    let name = app.name.clone();

    loop {
        sleep(interval).await;

        info!(app = %name, "Comprobando actualizaciones de git...");

        let changed = match BuildEngine::git_pull(&app).await {
            Ok(c) => c,
            Err(e) => {
                warn!(app = %name, error = %e, "Error en git pull");
                continue;
            }
        };

        if changed {
            if let Err(e) = BuildEngine::build(&app).await {
                error!(app = %name, error = %e, "Error en build tras actualización");
                continue;
            }

            // Reiniciar proceso con nueva versión
            if let Err(e) = process_manager.signal(&name, ProcessSignal::Restart).await {
                error!(app = %name, error = %e, "Error al reiniciar tras actualización");
            } else {
                info!(app = %name, "App reiniciada con nueva versión");
            }
        }
    }
}

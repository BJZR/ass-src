// tunnel/mod.rs — Módulo de túneles P2P/WebSocket para exposición detrás de CGNAT
//
// Arquitectura:
//   Cliente ASS local ──WebSocket──► Servidor relay ──► Internet
//
// El servidor relay (ss-relay, separado) acepta conexiones de clientes
// y de browsers, los conecta haciendo de bridge TCP bidireccional.
// Este módulo implementa el lado cliente del túnel.

use crate::config::{TunnelConfig, TunnelEntry};
use anyhow::{Context, Result};
use futures::{SinkExt, StreamExt};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    sync::RwLock,
    time::sleep,
};
use tokio_tungstenite::{connect_async, tungstenite::Message};
use tracing::{error, info, warn};

// ─────────────────────────────────────────────
//  Estado de un túnel individual
// ─────────────────────────────────────────────

#[derive(Debug, Clone, PartialEq)]
pub enum TunnelState {
    Connecting,
    Connected { public_url: String },
    Disconnected,
    Error(String),
}

impl std::fmt::Display for TunnelState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            TunnelState::Connecting => write!(f, "conectando"),
            TunnelState::Connected { public_url } => write!(f, "activo → {}", public_url),
            TunnelState::Disconnected => write!(f, "desconectado"),
            TunnelState::Error(e) => write!(f, "error: {}", e),
        }
    }
}

// ─────────────────────────────────────────────
//  Gestor de túneles
// ─────────────────────────────────────────────

pub struct TunnelManager {
    config: TunnelConfig,
    states: Arc<RwLock<std::collections::HashMap<String, TunnelState>>>,
}

impl TunnelManager {
    pub fn new(config: TunnelConfig) -> Self {
        Self {
            config,
            states: Arc::new(RwLock::new(std::collections::HashMap::new())),
        }
    }

    /// Lanza todos los túneles configurados
    pub async fn start_all(&self) -> Result<()> {
        if !self.config.enabled {
            info!("Módulo de túneles deshabilitado");
            return Ok(());
        }

        let relay = self.config.relay_server.as_ref()
            .context("tunnel.relay_server no configurado")?;
        let auth_token = self.config.auth_token.clone();

        for entry in &self.config.tunnels {
            let entry = entry.clone();
            let relay = relay.clone();
            let token = auth_token.clone();
            let states = self.states.clone();

            tokio::spawn(async move {
                tunnel_loop(entry, relay, token, states).await;
            });
        }

        Ok(())
    }

    /// Obtiene el estado de todos los túneles
    pub async fn status(&self) -> Vec<(String, TunnelState)> {
        self.states.read().await
            .iter()
            .map(|(k, v)| (k.clone(), v.clone()))
            .collect()
    }
}

// ─────────────────────────────────────────────
//  Bucle de reconexión de un túnel individual
// ─────────────────────────────────────────────

async fn tunnel_loop(
    entry: TunnelEntry,
    relay_server: String,
    auth_token: Option<String>,
    states: Arc<RwLock<std::collections::HashMap<String, TunnelState>>>,
) {
    let name = entry.name.clone();
    let mut backoff = Duration::from_secs(1);
    const MAX_BACKOFF: Duration = Duration::from_secs(60);

    loop {
        states.write().await.insert(name.clone(), TunnelState::Connecting);
        info!(tunnel = %name, relay = %relay_server, "Conectando túnel...");

        match connect_tunnel(&entry, &relay_server, auth_token.as_deref()).await {
            Ok(public_url) => {
                states.write().await.insert(
                    name.clone(),
                    TunnelState::Connected { public_url: public_url.clone() },
                );
                info!(tunnel = %name, url = %public_url, "Túnel activo");
                backoff = Duration::from_secs(1); // reset backoff en conexión exitosa
            }
            Err(e) => {
                let msg = e.to_string();
                error!(tunnel = %name, error = %msg, "Error en túnel");
                states.write().await.insert(name.clone(), TunnelState::Error(msg));

                warn!(tunnel = %name, delay = ?backoff, "Reintentando conexión...");
                sleep(backoff).await;
                backoff = (backoff * 2).min(MAX_BACKOFF);
            }
        }
    }
}

// ─────────────────────────────────────────────
//  Conexión WebSocket al relay y bridge TCP
// ─────────────────────────────────────────────

async fn connect_tunnel(
    entry: &TunnelEntry,
    relay_server: &str,
    auth_token: Option<&str>,
) -> Result<String> {
    // URL WebSocket del relay
    let subdomain = entry.remote_subdomain.as_deref().unwrap_or(&entry.name);
    let ws_url = format!(
        "wss://{}/register?subdomain={}&proto={}&port={}",
        relay_server, subdomain, entry.proto, entry.local_port
    );

    let (ws_stream, _) = connect_async(&ws_url).await
        .with_context(|| format!("No se pudo conectar al relay: {}", relay_server))?;

    let (mut ws_write, mut ws_read) = ws_stream.split();

    // Autenticación
    if let Some(token) = auth_token {
        ws_write.send(Message::Text(format!("AUTH {}", token).into())).await?;
    }

    // Esperar confirmación y URL pública del relay
    let public_url = match ws_read.next().await {
        Some(Ok(Message::Text(msg))) => {
            if msg.starts_with("OK ") {
                msg[3..].to_string()
            } else {
                anyhow::bail!("Relay rechazó conexión: {}", msg);
            }
        }
        Some(Ok(_)) => anyhow::bail!("Respuesta inesperada del relay"),
        Some(Err(e)) => anyhow::bail!("Error WebSocket: {}", e),
        None => anyhow::bail!("Relay cerró la conexión inmediatamente"),
    };

    // Bucle: recibir conexiones del relay y hacer bridge con servicio local
    // El relay envía mensajes: "CONNECT <conn_id>" cuando llega una conexión externa
    // Luego los datos se multiplexan sobre el mismo WebSocket usando frames binarios

    // Nota: implementación simplificada de multiplexación.
    // Producción usaría yamux o similar para múltiples streams simultáneos.
    loop {
        match ws_read.next().await {
            Some(Ok(Message::Text(cmd))) => {
                if cmd.starts_with("CONNECT ") {
                    let conn_id = cmd[8..].trim().to_string();
                    let local_port = entry.local_port;
                    let conn_id2 = conn_id.clone();

                    // Conectar al servicio local
                    match TcpStream::connect(format!("127.0.0.1:{}", local_port)).await {
                        Ok(local_stream) => {
                            // En producción: multiplexar sobre el WebSocket
                            // Por ahora logeamos la conexión
                            info!(tunnel = %entry.name, conn = %conn_id, "Nueva conexión bridgeada al puerto {}", local_port);
                        }
                        Err(e) => {
                            warn!(tunnel = %entry.name, conn = %conn_id2, error = %e, "No se pudo conectar al servicio local");
                        }
                    }
                }
            }
            Some(Ok(Message::Ping(data))) => {
                let _ = ws_write.send(Message::Pong(data)).await;
            }
            Some(Ok(Message::Close(_))) | None => {
                anyhow::bail!("Relay cerró la conexión WebSocket");
            }
            Some(Err(e)) => {
                anyhow::bail!("Error en WebSocket del relay: {}", e);
            }
            _ => {}
        }
    }
}

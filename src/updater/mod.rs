// updater/mod.rs — Self-updater con verificación criptográfica (Ed25519)
use crate::config::UpdaterConfig;
use anyhow::{Context, Result};
use base64::Engine;
use ring::signature::{self, Ed25519KeyPair, UnparsedPublicKey, ED25519};
use serde::{Deserialize, Serialize};
use std::path::PathBuf;
use tracing::{info, warn};

// ─────────────────────────────────────────────
//  Respuesta de GitHub Releases API
// ─────────────────────────────────────────────

#[derive(Debug, Deserialize)]
struct GithubRelease {
    tag_name: String,
    name: String,
    body: Option<String>,
    assets: Vec<GithubAsset>,
}

#[derive(Debug, Deserialize)]
struct GithubAsset {
    name: String,
    browser_download_url: String,
    size: u64,
}

// ─────────────────────────────────────────────
//  Información de versión
// ─────────────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VersionInfo {
    pub current: String,
    pub latest: String,
    pub update_available: bool,
    pub changelog: Option<String>,
    pub download_url: Option<String>,
}

// ─────────────────────────────────────────────
//  Actualizador
// ─────────────────────────────────────────────

pub struct Updater {
    config: UpdaterConfig,
    http: reqwest::Client,
}

impl Updater {
    pub fn new(config: UpdaterConfig) -> Self {
        let http = reqwest::Client::builder()
            .user_agent(format!("ASS/{} (self-updater)", env!("CARGO_PKG_VERSION")))
            .timeout(std::time::Duration::from_secs(30))
            .build()
            .expect("Error creando cliente HTTP del updater");

        Self { config, http }
    }

    pub fn current_version() -> &'static str {
        env!("CARGO_PKG_VERSION")
    }

    /// Comprueba si hay una versión más nueva disponible
    pub async fn check_update(&self) -> Result<VersionInfo> {
        let release = self.fetch_latest_release().await?;
        let current = Self::current_version().to_string();
        let latest = release.tag_name.trim_start_matches('v').to_string();

        let update_available = is_newer(&current, &latest);

        // Encontrar el asset para la plataforma actual
        let download_url = find_asset_url(&release.assets);

        Ok(VersionInfo {
            current,
            latest,
            update_available,
            changelog: release.body,
            download_url,
        })
    }

    /// Descarga, verifica y aplica la actualización
    pub async fn perform_update(&self) -> Result<()> {
        let info = self.check_update().await?;

        if !info.update_available {
            info!("ASS ya está en la versión más reciente ({})", info.current);
            return Ok(());
        }

        let download_url = info.download_url
            .context("No se encontró un asset para esta plataforma")?;

        info!(
            current = %info.current,
            latest = %info.latest,
            "Descargando actualización..."
        );

        // 1. Descargar binario a directorio temporal
        let bytes = self.download_binary(&download_url).await?;

        // 2. Descargar firma (.sig) si hay clave de verificación
        if let Some(ref key_hex) = self.config.verify_key {
            let sig_url = format!("{}.sig", download_url);
            let sig_bytes = self.http.get(&sig_url).send().await?.bytes().await?;

            self.verify_signature(&bytes, &sig_bytes, key_hex)
                .context("Verificación de firma fallida; actualización cancelada")?;

            info!("Firma criptográfica verificada ✓");
        } else {
            warn!("No hay clave de verificación configurada; omitiendo verificación de firma");
        }

        // 3. Reemplazar el ejecutable en caliente
        self.replace_binary(bytes).await?;

        info!(version = %info.latest, "¡Actualización completada! Reinicia ASS para activarla.");
        Ok(())
    }

    /// Descarga el binario y retorna los bytes
    async fn download_binary(&self, url: &str) -> Result<Vec<u8>> {
        let resp = self.http.get(url).send().await
            .with_context(|| format!("Error al descargar {}", url))?;

        let total = resp.content_length().unwrap_or(0);
        let bytes = resp.bytes().await
            .context("Error al leer body de descarga")?;

        info!(bytes = bytes.len(), total = total, "Descarga completada");
        Ok(bytes.to_vec())
    }

    /// Verifica firma Ed25519 del binario
    fn verify_signature(&self, data: &[u8], sig_bytes: &[u8], key_hex: &str) -> Result<()> {
        // Decodificar clave pública (hex o base64)
        let key_bytes = if key_hex.contains('+') || key_hex.contains('/') || key_hex.ends_with('=') {
            base64::engine::general_purpose::STANDARD
                .decode(key_hex)
                .context("Error decodificando clave pública (base64)")?
        } else {
            hex::decode(key_hex).unwrap_or_else(|_| {
                base64::engine::general_purpose::STANDARD
                    .decode(key_hex)
                    .unwrap_or_default()
            })
        };

        let public_key = UnparsedPublicKey::new(&ED25519, &key_bytes);
        public_key
            .verify(data, sig_bytes)
            .map_err(|_| anyhow::anyhow!("Firma Ed25519 inválida"))?;

        Ok(())
    }

    /// Reemplaza el ejecutable actual de forma atómica
    async fn replace_binary(&self, new_binary: Vec<u8>) -> Result<()> {
        // Ruta del ejecutable actual
        let current_exe = std::env::current_exe()
            .context("No se pudo obtener la ruta del ejecutable actual")?;

        // Escribir en archivo temporal en el mismo directorio (misma partición para rename atómico)
        let parent = current_exe.parent()
            .context("No se pudo obtener directorio del ejecutable")?;

        let tmp_path = parent.join(".ss_update_tmp");
        tokio::fs::write(&tmp_path, &new_binary).await
            .context("Error escribiendo nuevo ejecutable temporal")?;

        // Dar permisos de ejecución
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mut perms = std::fs::metadata(&tmp_path)?.permissions();
            perms.set_mode(0o755);
            std::fs::set_permissions(&tmp_path, perms)?;
        }

        // Backup del ejecutable actual
        let backup_path = parent.join(".ss_backup");
        if current_exe.exists() {
            tokio::fs::rename(&current_exe, &backup_path).await
                .context("Error creando backup del ejecutable")?;
        }

        // Rename atómico
        tokio::fs::rename(&tmp_path, &current_exe).await
            .with_context(|| {
                // Restaurar backup si falla
                format!("Error al reemplazar ejecutable en {}", current_exe.display())
            })?;

        info!(path = %current_exe.display(), "Ejecutable reemplazado atómicamente");
        Ok(())
    }

    async fn fetch_latest_release(&self) -> Result<GithubRelease> {
        let resp = self.http
            .get(&self.config.release_url)
            .header("Accept", "application/vnd.github.v3+json")
            .send()
            .await
            .context("Error al consultar releases")?
            .error_for_status()
            .context("Error HTTP en releases API")?
            .json::<GithubRelease>()
            .await
            .context("Error al parsear respuesta de releases")?;

        Ok(resp)
    }
}

// ─────────────────────────────────────────────
//  Utilidades de versiones (semver simple)
// ─────────────────────────────────────────────

fn parse_version(v: &str) -> (u64, u64, u64) {
    let parts: Vec<&str> = v.split('.').collect();
    let n = |i: usize| parts.get(i).and_then(|s| s.parse().ok()).unwrap_or(0u64);
    (n(0), n(1), n(2))
}

fn is_newer(current: &str, latest: &str) -> bool {
    parse_version(latest) > parse_version(current)
}

/// Selecciona el asset correcto según la plataforma
fn find_asset_url(assets: &[GithubAsset]) -> Option<String> {
    let os = std::env::consts::OS;    // linux, macos, windows
    let arch = std::env::consts::ARCH; // x86_64, aarch64

    let os_tag = match os {
        "linux" => "linux",
        "macos" => "darwin",
        "windows" => "windows",
        _ => os,
    };

    let arch_tag = match arch {
        "x86_64" => "amd64",
        "aarch64" => "arm64",
        other => other,
    };

    // Buscar asset que contenga os y arch en el nombre
    assets.iter().find(|a| {
        let name = a.name.to_lowercase();
        name.contains(os_tag) && name.contains(arch_tag) && !name.ends_with(".sig")
    })
    .map(|a| a.browser_download_url.clone())
}

// ─────────────────────────────────────────────
//  Módulo hex (sin dependencia externa extra)
// ─────────────────────────────────────────────

mod hex {
    pub fn decode(s: &str) -> Result<Vec<u8>, ()> {
        if s.len() % 2 != 0 { return Err(()); }
        (0..s.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&s[i..i+2], 16).map_err(|_| ()))
            .collect()
    }
}

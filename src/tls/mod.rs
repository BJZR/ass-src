// tls/mod.rs — Gestión automática de TLS/SSL con ACME (Let's Encrypt / ZeroSSL)
use crate::config::{AcmeProvider, ServerConfig};
use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use rustls::ServerConfig as TlsServerConfig;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};

// ─────────────────────────────────────────────
//  Estructuras de datos del certificado
// ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub struct CertInfo {
    pub domain: String,
    pub cert_path: PathBuf,
    pub key_path: PathBuf,
    pub expires_at: DateTime<Utc>,
    pub issued_by: String,
}

impl CertInfo {
    /// Retorna true si el certificado expira en menos de `days` días
    pub fn expires_in_less_than(&self, days: i64) -> bool {
        let remaining = self.expires_at - Utc::now();
        remaining.num_days() < days
    }

    pub fn is_expired(&self) -> bool {
        self.expires_at < Utc::now()
    }
}

// ─────────────────────────────────────────────
//  Gestor TLS principal
// ─────────────────────────────────────────────

pub struct TlsManager {
    config: ServerConfig,
    /// Mapa domain → CertInfo
    certs: Arc<RwLock<HashMap<String, CertInfo>>>,
    /// Mapa domain → ServerConfig TLS compilado
    tls_configs: Arc<RwLock<HashMap<String, Arc<TlsServerConfig>>>>,
}

impl TlsManager {
    pub fn new(config: ServerConfig) -> Self {
        Self {
            config,
            certs: Arc::new(RwLock::new(HashMap::new())),
            tls_configs: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Inicializa cargando certs existentes en disco
    pub async fn init(&self) -> Result<()> {
        std::fs::create_dir_all(&self.config.certs_dir)
            .with_context(|| format!("No se pudo crear {}", self.config.certs_dir.display()))?;

        self.load_existing_certs().await?;
        Ok(())
    }

    /// Carga certificados PEM ya presentes en certs_dir
    async fn load_existing_certs(&self) -> Result<()> {
        let dir = &self.config.certs_dir;
        let read_dir = match std::fs::read_dir(dir) {
            Ok(d) => d,
            Err(_) => return Ok(()),
        };

        for entry in read_dir.flatten() {
            let path = entry.path();
            if path.extension().map(|e| e == "crt").unwrap_or(false) {
                if let Some(domain) = path.file_stem().and_then(|s| s.to_str()) {
                    let key_path = dir.join(format!("{}.key", domain));
                    if key_path.exists() {
                        match self.load_cert_info(domain, &path, &key_path) {
                            Ok(info) => {
                                if !info.is_expired() {
                                    info!(domain = %domain, expires = %info.expires_at, "Certificado cargado");
                                    self.store_cert(info).await?;
                                } else {
                                    warn!(domain = %domain, "Certificado expirado en disco; se renovará");
                                }
                            }
                            Err(e) => warn!(domain = %domain, error = %e, "Error al cargar certificado"),
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// Parsea la fecha de expiración de un PEM con x509-parser
    fn load_cert_info(&self, domain: &str, cert_path: &Path, key_path: &Path) -> Result<CertInfo> {
        let cert_pem = std::fs::read(cert_path)?;
        let (_, pem) = x509_parser::pem::parse_x509_pem(&cert_pem)
            .map_err(|e| anyhow::anyhow!("Error al parsear PEM: {:?}", e))?;
        let x509 = pem.parse_x509()
            .map_err(|e| anyhow::anyhow!("Error al parsear X.509: {:?}", e))?;

        let not_after = x509.validity().not_after.to_datetime();
        let expires_at = DateTime::from_timestamp(not_after.unix_timestamp(), 0)
            .unwrap_or_default();

        let issued_by = x509.issuer().to_string();

        Ok(CertInfo {
            domain: domain.to_string(),
            cert_path: cert_path.to_path_buf(),
            key_path: key_path.to_path_buf(),
            expires_at,
            issued_by,
        })
    }

    /// Almacena un CertInfo y construye el ServerConfig TLS asociado
    async fn store_cert(&self, info: CertInfo) -> Result<()> {
        let tls_cfg = self.build_tls_config(&info)?;
        let domain = info.domain.clone();
        self.certs.write().await.insert(domain.clone(), info);
        self.tls_configs.write().await.insert(domain, Arc::new(tls_cfg));
        Ok(())
    }

    /// Construye un rustls::ServerConfig a partir de PEM en disco
    fn build_tls_config(&self, info: &CertInfo) -> Result<TlsServerConfig> {
        let cert_pem = std::fs::read(&info.cert_path)?;
        let key_pem = std::fs::read(&info.key_path)?;

        let certs = rustls_pemfile::certs(&mut cert_pem.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .context("Error al parsear certificados PEM")?;

        let key = rustls_pemfile::private_key(&mut key_pem.as_slice())
            .context("Error al parsear clave privada")?
            .context("No se encontró clave privada")?;

        let cfg = TlsServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .context("Error al construir TlsServerConfig")?;

        Ok(cfg)
    }

    // ─── ACME ─────────────────────────────────

    /// Emite o renueva el certificado para `domain` via ACME HTTP-01
    pub async fn provision_cert(&self, domain: &str) -> Result<CertInfo> {
        let email = self.config.ssl_email.as_deref()
            .context("ssl_email no configurado; TLS automático requiere un email")?;

        info!(domain = %domain, "Iniciando provisión ACME...");

        let directory_url = self.config.acme_provider.directory_url();
        let info = acme::provision(domain, email, directory_url, &self.config.certs_dir).await
            .with_context(|| format!("Fallo en ACME para {}", domain))?;

        self.store_cert(info.clone()).await?;
        info!(domain = %domain, expires = %info.expires_at, "Certificado emitido/renovado");
        Ok(info)
    }

    /// Provisiona certificados para todos los dominios de `domains` que no tengan cert válido
    pub async fn ensure_certs(&self, domains: &[String]) -> Result<()> {
        for domain in domains {
            let needs_provision = {
                let certs = self.certs.read().await;
                match certs.get(domain) {
                    None => true,
                    Some(c) => c.expires_in_less_than(30),
                }
            };

            if needs_provision {
                if let Err(e) = self.provision_cert(domain).await {
                    error!(domain = %domain, error = %e, "No se pudo provisionar certificado");
                }
            }
        }
        Ok(())
    }

    /// Devuelve el TlsServerConfig para `domain`, o None si no hay cert
    pub async fn get_tls_config(&self, domain: &str) -> Option<Arc<TlsServerConfig>> {
        self.tls_configs.read().await.get(domain).cloned()
    }

    /// Bucle de renovación automática (ejecutar en background)
    pub async fn renewal_loop(&self, check_interval_secs: u64) {
        let interval = std::time::Duration::from_secs(check_interval_secs);
        loop {
            tokio::time::sleep(interval).await;

            let domains: Vec<String> = self.certs.read().await.keys().cloned().collect();
            for domain in domains {
                let needs = {
                    let certs = self.certs.read().await;
                    certs.get(&domain).map(|c| c.expires_in_less_than(30)).unwrap_or(false)
                };
                if needs {
                    info!(domain = %domain, "Renovando certificado (< 30 días para expirar)");
                    if let Err(e) = self.provision_cert(&domain).await {
                        error!(domain = %domain, error = %e, "Error en renovación de certificado");
                    }
                }
            }
        }
    }

    /// Construye un resolvedor SNI dinámico para hyper/rustls
    pub async fn build_sni_resolver(&self) -> Arc<DynamicSniResolver> {
        let configs = self.tls_configs.read().await.clone();
        Arc::new(DynamicSniResolver { configs })
    }
}

// ─────────────────────────────────────────────
//  Resolvedor SNI dinámico
// ─────────────────────────────────────────────

/// Implementa resolución SNI: selecciona el cert correcto según el ServerName TLS
pub struct DynamicSniResolver {
    configs: HashMap<String, Arc<TlsServerConfig>>,
}

impl DynamicSniResolver {
    /// Devuelve el ServerConfig TLS para el nombre de servidor SNI dado
    pub fn resolve(&self, server_name: &str) -> Option<Arc<TlsServerConfig>> {
        // Búsqueda exacta primero
        if let Some(cfg) = self.configs.get(server_name) {
            return Some(cfg.clone());
        }
        // Wildcard: *.example.com → sub.example.com
        if let Some(dot_pos) = server_name.find('.') {
            let wildcard = format!("*{}", &server_name[dot_pos..]);
            if let Some(cfg) = self.configs.get(&wildcard) {
                return Some(cfg.clone());
            }
        }
        // Fallback: primer certificado disponible
        self.configs.values().next().cloned()
    }
}

// ─────────────────────────────────────────────
//  Sub-módulo ACME interno
// ─────────────────────────────────────────────

mod acme {
    use super::CertInfo;
    use anyhow::{Context, Result};
    use chrono::{DateTime, Utc};
    use instant_acme::{
        Account, AuthorizationStatus, ChallengeType, Identifier, LetsEncrypt,
        NewAccount, NewOrder, OrderStatus,
    };
    use rcgen::{CertificateParams, DistinguishedName, KeyPair};
    use std::path::Path;
    use tokio::time::{sleep, Duration};
    use tracing::info;

    /// Challenge HTTP-01: almacena el token para que el proxy lo sirva
    static HTTP01_TOKENS: once_cell::sync::Lazy<
        tokio::sync::RwLock<std::collections::HashMap<String, String>>,
    > = once_cell::sync::Lazy::new(|| tokio::sync::RwLock::new(std::collections::HashMap::new()));

    pub async fn provision(
        domain: &str,
        email: &str,
        directory_url: &str,
        certs_dir: &Path,
    ) -> Result<CertInfo> {
        info!(domain = %domain, "Creando cuenta ACME...");

        // Crear o recuperar cuenta ACME
        let (account, _credentials) = Account::create(
            &NewAccount {
                contact: &[&format!("mailto:{}", email)],
                terms_of_service_agreed: true,
                only_return_existing: false,
            },
            directory_url,
            None,
        )
        .await
        .context("Fallo al crear cuenta ACME")?;

        // Crear orden
        let identifier = Identifier::Dns(domain.to_string());
        let mut order = account
            .new_order(&NewOrder { identifiers: &[identifier] })
            .await
            .context("Fallo al crear orden ACME")?;

        // Procesar autorizaciones
        let authorizations = order.authorizations().await.context("Fallo al obtener autorizaciones")?;

        for authz in &authorizations {
            match authz.status {
                AuthorizationStatus::Pending => {}
                AuthorizationStatus::Valid => continue,
                _ => anyhow::bail!("Estado de autorización inesperado: {:?}", authz.status),
            }

            // Buscar challenge HTTP-01
            let challenge = authz
                .challenges
                .iter()
                .find(|c| c.r#type == ChallengeType::Http01)
                .context("No se encontró challenge HTTP-01")?;

            let key_auth = order.key_authorization(challenge);

            // Registrar token para que el proxy lo sirva
            {
                let mut tokens = HTTP01_TOKENS.write().await;
                tokens.insert(challenge.token.clone(), key_auth.as_str().to_string());
            }

            // Notificar a ACME que estamos listos
            order.set_challenge_ready(&challenge.url).await?;

            // Esperar validación
            let mut delay = Duration::from_millis(500);
            for _ in 0..10 {
                sleep(delay).await;
                let state = order.refresh().await?;
                if state.status == OrderStatus::Ready || state.status == OrderStatus::Valid {
                    break;
                }
                delay *= 2;
            }

            // Limpiar token
            {
                let mut tokens = HTTP01_TOKENS.write().await;
                tokens.remove(&challenge.token);
            }
        }

        // Generar CSR con rcgen
        let key_pair = KeyPair::generate().context("Fallo al generar KeyPair")?;
        let mut params = CertificateParams::new(vec![domain.to_string()])
            .context("Fallo al crear CertificateParams")?;
        params.distinguished_name = DistinguishedName::new();

        let csr = params.serialize_request(&key_pair).context("Fallo al serializar CSR")?;

        order
            .finalize(csr.der())
            .await
            .context("Fallo al finalizar orden ACME")?;

        // Esperar emisión del certificado
        let cert_chain_pem = loop {
            sleep(Duration::from_secs(2)).await;
            if let Some(cert) = order.certificate().await? {
                break cert;
            }
        };

        // Persistir en disco
        let cert_path = certs_dir.join(format!("{}.crt", domain));
        let key_path = certs_dir.join(format!("{}.key", domain));

        std::fs::write(&cert_path, &cert_chain_pem)?;
        std::fs::write(&key_path, key_pair.serialize_pem())?;

        // Parsear fecha de expiración del primer cert de la cadena
        let expires_at = parse_expiry(&cert_chain_pem).unwrap_or_else(|| {
            Utc::now() + chrono::Duration::days(89)
        });

        Ok(CertInfo {
            domain: domain.to_string(),
            cert_path,
            key_path,
            expires_at,
            issued_by: "Let's Encrypt / ACME".to_string(),
        })
    }

    /// Obtiene un token HTTP-01 almacenado (usado por el proxy para servirlo)
    pub async fn get_http01_token(token: &str) -> Option<String> {
        HTTP01_TOKENS.read().await.get(token).cloned()
    }

    fn parse_expiry(pem: &str) -> Option<DateTime<Utc>> {
        let (_, p) = x509_parser::pem::parse_x509_pem(pem.as_bytes()).ok()?;
        let x = p.parse_x509().ok()?;
        let ts = x.validity().not_after.to_datetime().unix_timestamp();
        DateTime::from_timestamp(ts, 0)
    }
}

pub use acme::get_http01_token;

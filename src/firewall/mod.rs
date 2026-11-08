// firewall/mod.rs — Firewall de aplicación: allowlist/blocklist, rate limiting, DoS básico
use crate::config::FirewallConfig;
use anyhow::Result;
use governor::{
    clock::DefaultClock,
    middleware::NoOpMiddleware,
    state::{InMemoryState, NotKeyed},
    Quota, RateLimiter,
};
use std::{
    collections::HashSet,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    num::NonZeroU32,
    sync::Arc,
};
use tokio::sync::RwLock;
use tracing::{debug, warn};

// ─────────────────────────────────────────────
//  CIDR matcher simple (IPv4 + IPv6)
// ─────────────────────────────────────────────

#[derive(Debug, Clone)]
struct CidrEntry {
    addr: IpAddr,
    prefix_len: u8,
}

impl CidrEntry {
    fn parse(s: &str) -> Option<Self> {
        if let Some((ip, prefix)) = s.split_once('/') {
            let addr: IpAddr = ip.parse().ok()?;
            let prefix_len: u8 = prefix.parse().ok()?;
            Some(CidrEntry { addr, prefix_len })
        } else {
            // IP exacta
            let addr: IpAddr = s.parse().ok()?;
            let prefix_len = match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            };
            Some(CidrEntry { addr, prefix_len })
        }
    }

    fn contains(&self, ip: &IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(host)) => {
                let mask = !0u32 << (32 - self.prefix_len);
                (u32::from_be_bytes(net.octets()) & mask)
                    == (u32::from_be_bytes(host.octets()) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(host)) => {
                let mask = !0u128 << (128 - self.prefix_len);
                (u128::from_be_bytes(net.octets()) & mask)
                    == (u128::from_be_bytes(host.octets()) & mask)
            }
            _ => false,
        }
    }
}

// ─────────────────────────────────────────────
//  Decisión del firewall
// ─────────────────────────────────────────────

#[derive(Debug, PartialEq)]
pub enum FirewallDecision {
    Allow,
    Deny(DenyReason),
}

#[derive(Debug, PartialEq)]
pub enum DenyReason {
    Blocklisted,
    RateLimited,
    NoHost,
    BodyTooLarge,
    Forbidden,
}

impl DenyReason {
    pub fn http_status(&self) -> u16 {
        match self {
            DenyReason::Blocklisted => 403,
            DenyReason::RateLimited => 429,
            DenyReason::NoHost => 400,
            DenyReason::BodyTooLarge => 413,
            DenyReason::Forbidden => 403,
        }
    }

    pub fn message(&self) -> &'static str {
        match self {
            DenyReason::Blocklisted => "IP bloqueada",
            DenyReason::RateLimited => "Demasiadas peticiones",
            DenyReason::NoHost => "Host no especificado",
            DenyReason::BodyTooLarge => "Cuerpo demasiado grande",
            DenyReason::Forbidden => "Acceso denegado",
        }
    }
}

// ─────────────────────────────────────────────
//  Rate limiter por IP
// ─────────────────────────────────────────────

type IpRateLimiter = RateLimiter<NotKeyed, InMemoryState, DefaultClock, NoOpMiddleware>;

struct PerIpLimiter {
    limiters: RwLock<std::collections::HashMap<IpAddr, Arc<IpRateLimiter>>>,
    quota: Quota,
}

impl PerIpLimiter {
    fn new(rps: u32, burst: u32) -> Self {
        let quota = Quota::per_second(NonZeroU32::new(rps).unwrap_or(NonZeroU32::new(1).unwrap()))
            .allow_burst(NonZeroU32::new(burst).unwrap_or(NonZeroU32::new(1).unwrap()));
        Self {
            limiters: RwLock::new(std::collections::HashMap::new()),
            quota,
        }
    }

    async fn check(&self, ip: IpAddr) -> bool {
        // Obtener o crear limiter para esta IP
        {
            let read = self.limiters.read().await;
            if let Some(limiter) = read.get(&ip) {
                return limiter.check().is_ok();
            }
        }
        // Crear nuevo limiter para IP nueva
        let limiter = Arc::new(RateLimiter::direct(self.quota));
        let result = limiter.check().is_ok();
        self.limiters.write().await.insert(ip, limiter);
        result
    }

    /// Limpia IPs inactivas periódicamente (evitar memory leak)
    async fn cleanup(&self) {
        // Simplificado: limpiar todo (en producción usaríamos TTL)
        self.limiters.write().await.clear();
    }
}

// ─────────────────────────────────────────────
//  Firewall principal
// ─────────────────────────────────────────────

pub struct Firewall {
    config: FirewallConfig,
    allowlist: Vec<CidrEntry>,
    blocklist: Vec<CidrEntry>,
    rate_limiter: Arc<PerIpLimiter>,
}

impl Firewall {
    pub fn new(config: FirewallConfig) -> Self {
        let allowlist = config
            .allowlist
            .iter()
            .filter_map(|s| CidrEntry::parse(s))
            .collect();

        let blocklist = config
            .blocklist
            .iter()
            .filter_map(|s| CidrEntry::parse(s))
            .collect();

        let rate_limiter = Arc::new(PerIpLimiter::new(
            config.rate_limit_rps,
            config.rate_limit_burst,
        ));

        Self {
            config,
            allowlist,
            blocklist,
            rate_limiter,
        }
    }

    /// Evalúa una petición entrante
    pub async fn check(
        &self,
        ip: IpAddr,
        host: Option<&str>,
        content_length: Option<u64>,
    ) -> FirewallDecision {
        if !self.config.enabled {
            return FirewallDecision::Allow;
        }

        // 1. Allowlist: bypass total
        if self.is_allowed(&ip) {
            debug!(ip = %ip, "IP en allowlist, permitida");
            return FirewallDecision::Allow;
        }

        // 2. Blocklist
        if self.is_blocked(&ip) {
            warn!(ip = %ip, "IP en blocklist, bloqueada");
            return FirewallDecision::Deny(DenyReason::Blocklisted);
        }

        // 3. Host header requerido
        if self.config.block_no_host && host.map(|h| h.is_empty()).unwrap_or(true) {
            warn!(ip = %ip, "Petición sin Host header");
            return FirewallDecision::Deny(DenyReason::NoHost);
        }

        // 4. Tamaño máximo de body
        if self.config.max_body_mb > 0 {
            if let Some(len) = content_length {
                let max_bytes = self.config.max_body_mb * 1024 * 1024;
                if len > max_bytes {
                    warn!(ip = %ip, body_size = len, max = max_bytes, "Body demasiado grande");
                    return FirewallDecision::Deny(DenyReason::BodyTooLarge);
                }
            }
        }

        // 5. Rate limiting por IP
        if !self.rate_limiter.check(ip).await {
            warn!(ip = %ip, "Rate limit excedido");
            return FirewallDecision::Deny(DenyReason::RateLimited);
        }

        FirewallDecision::Allow
    }

    fn is_allowed(&self, ip: &IpAddr) -> bool {
        self.allowlist.iter().any(|c| c.contains(ip))
    }

    fn is_blocked(&self, ip: &IpAddr) -> bool {
        self.blocklist.iter().any(|c| c.contains(ip))
    }

    /// Bloquea una IP dinámicamente (útil para ban temporal)
    pub fn block_ip_dynamic(&mut self, ip: IpAddr) {
        let cidr = CidrEntry {
            addr: ip,
            prefix_len: match ip {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            },
        };
        self.blocklist.push(cidr);
        warn!(ip = %ip, "IP bloqueada dinámicamente");
    }

    /// Tarea de mantenimiento periódico (cleanup de rate limiters, etc.)
    pub async fn maintenance_loop(rate_limiter: Arc<PerIpLimiter>) {
        let mut interval = tokio::time::interval(std::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            rate_limiter.cleanup().await;
        }
    }
}

// ─────────────────────────────────────────────
//  Headers de seguridad automáticos
// ─────────────────────────────────────────────

/// Retorna los headers de seguridad HTTP estándar
pub fn security_headers() -> Vec<(&'static str, &'static str)> {
    vec![
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "SAMEORIGIN"),
        ("X-XSS-Protection", "1; mode=block"),
        ("Referrer-Policy", "strict-origin-when-cross-origin"),
        (
            "Permissions-Policy",
            "geolocation=(), microphone=(), camera=()",
        ),
        (
            "Strict-Transport-Security",
            "max-age=63072000; includeSubDomains; preload",
        ),
        (
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data: https:; \
             script-src 'self'; style-src 'self' 'unsafe-inline'",
        ),
    ]
}

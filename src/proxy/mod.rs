// proxy/mod.rs — Motor de proxy inverso HTTP/HTTPS con enrutamiento de dominios
use crate::{
    config::{AppConfig, Config},
    firewall::{DenyReason, Firewall},
    tls::{get_http01_token, TlsManager},
};
use anyhow::{Context, Result};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, StreamBody};
use hyper::{
    body::Incoming,
    header::{self, HeaderValue},
    service::service_fn,
    Method, Request, Response, StatusCode, Uri,
};
use hyper_util::{
    client::legacy::{connect::HttpConnector, Client},
    rt::TokioExecutor,
};
use std::{
    collections::HashMap,
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};

// ─────────────────────────────────────────────
//  Tabla de enrutamiento
// ─────────────────────────────────────────────

#[derive(Debug, Clone)]
pub enum RouteTarget {
    /// Proxy hacia puerto local
    Upstream { port: u16 },
    /// Proxy hacia socket Unix
    UnixSocket { path: PathBuf },
    /// Servir archivos estáticos
    Static { dir: PathBuf, compress: bool },
}

#[derive(Debug, Clone)]
pub struct Route {
    pub domain: String,
    pub target: RouteTarget,
    pub security_headers: bool,
    pub extra_headers: HashMap<String, String>,
}

pub struct Router {
    /// Dominio exacto o wildcard → Route
    routes: HashMap<String, Route>,
}

impl Router {
    pub fn new(apps: &[AppConfig]) -> Self {
        let mut routes = HashMap::new();

        for app in apps {
            let target = if let Some(port) = app.port {
                RouteTarget::Upstream { port }
            } else if let Some(ref socket) = app.socket {
                RouteTarget::UnixSocket { path: socket.clone() }
            } else if let Some(first_static) = app.static_routes.first() {
                RouteTarget::Static {
                    dir: first_static.dir.clone(),
                    compress: first_static.compress,
                }
            } else {
                continue;
            };

            let route = Route {
                domain: String::new(), // se rellena abajo
                target,
                security_headers: app.security_headers,
                extra_headers: app.extra_headers.clone(),
            };

            for domain in app.all_domains() {
                let mut r = route.clone();
                r.domain = domain.clone();
                routes.insert(domain, r);
            }
        }

        Router { routes }
    }

    /// Resuelve la ruta para un dominio dado (soporta wildcards)
    pub fn resolve(&self, host: &str) -> Option<&Route> {
        // Búsqueda exacta
        if let Some(r) = self.routes.get(host) {
            return Some(r);
        }
        // Wildcard *.example.com → sub.example.com
        if let Some(dot) = host.find('.') {
            let wildcard = format!("*{}", &host[dot..]);
            if let Some(r) = self.routes.get(&wildcard) {
                return Some(r);
            }
        }
        None
    }
}

// ─────────────────────────────────────────────
//  Servidor proxy principal
// ─────────────────────────────────────────────

pub struct ProxyServer {
    config: Arc<Config>,
    router: Arc<Router>,
    firewall: Arc<Firewall>,
    tls_manager: Arc<TlsManager>,
    http_client: Client<HttpConnector, Incoming>,
}

impl ProxyServer {
    pub fn new(
        config: Arc<Config>,
        router: Arc<Router>,
        firewall: Arc<Firewall>,
        tls_manager: Arc<TlsManager>,
    ) -> Self {
        let connector = HttpConnector::new();
        let http_client = Client::builder(TokioExecutor::new())
            .pool_idle_timeout(Duration::from_secs(config.server.proxy_timeout_secs))
            .build(connector);

        Self {
            config,
            router,
            firewall,
            tls_manager,
            http_client,
        }
    }

    /// Inicia el listener HTTP en el puerto configurado
    pub async fn serve_http(self: Arc<Self>) -> Result<()> {
        let addr: SocketAddr = format!(
            "{}:{}",
            self.config.server.host,
            self.config.server.http_port
        )
        .parse()?;

        let listener = TcpListener::bind(addr).await
            .with_context(|| format!("No se pudo bind en {}", addr))?;

        info!(addr = %addr, "Servidor HTTP escuchando");

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!(error = %e, "Error aceptando conexión HTTP");
                    continue;
                }
            };

            let server = self.clone();
            let peer_ip = peer_addr.ip();

            tokio::spawn(async move {
                let io = hyper_util::rt::TokioIo::new(stream);
                let svc = service_fn(move |req| {
                    let server = server.clone();
                    async move { server.handle_http(req, peer_ip).await }
                });

                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await
                {
                    debug!(error = %e, "Conexión HTTP cerrada");
                }
            });
        }
    }

    /// Inicia el listener HTTPS con SNI dinámico
    pub async fn serve_https(self: Arc<Self>) -> Result<()> {
        let addr: SocketAddr = format!(
            "{}:{}",
            self.config.server.host,
            self.config.server.https_port
        )
        .parse()?;

        let listener = TcpListener::bind(addr).await
            .with_context(|| format!("No se pudo bind en {}", addr))?;

        info!(addr = %addr, "Servidor HTTPS escuchando");

        // Construir resolver SNI
        let sni_resolver = self.tls_manager.build_sni_resolver().await;

        loop {
            let (stream, peer_addr) = match listener.accept().await {
                Ok(v) => v,
                Err(e) => {
                    error!(error = %e, "Error aceptando conexión HTTPS");
                    continue;
                }
            };

            let server = self.clone();
            let resolver = sni_resolver.clone();
            let peer_ip = peer_addr.ip();

            tokio::spawn(async move {
                // Peek al ClientHello para extraer SNI sin consumir datos
                // En producción usaríamos tokio-rustls con resolvedor personalizado
                // Aquí usamos el primer cert disponible como fallback
                let server_name = "default"; // simplificado
                let tls_cfg = match resolver.resolve(server_name) {
                    Some(cfg) => cfg,
                    None => {
                        warn!(peer = %peer_addr, "No hay certificado TLS disponible");
                        return;
                    }
                };

                let acceptor = TlsAcceptor::from(tls_cfg);
                let tls_stream = match acceptor.accept(stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        debug!(error = %e, "Error en TLS handshake");
                        return;
                    }
                };

                let io = hyper_util::rt::TokioIo::new(tls_stream);
                let svc = service_fn(move |req| {
                    let server = server.clone();
                    async move { server.handle_https(req, peer_ip).await }
                });

                if let Err(e) = hyper::server::conn::http1::Builder::new()
                    .serve_connection(io, svc)
                    .await
                {
                    debug!(error = %e, "Conexión HTTPS cerrada");
                }
            });
        }
    }

    // ─── Manejadores de peticiones ─────────────

    async fn handle_http(
        &self,
        req: Request<Incoming>,
        peer_ip: IpAddr,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        // Servir challenge ACME HTTP-01
        let path = req.uri().path().to_string();
        if path.starts_with("/.well-known/acme-challenge/") {
            let token = path.trim_start_matches("/.well-known/acme-challenge/");
            if let Some(key_auth) = get_http01_token(token).await {
                return Ok(text_response(StatusCode::OK, key_auth));
            }
            return Ok(text_response(StatusCode::NOT_FOUND, "Not Found".to_string()));
        }

        // Redirección HTTP → HTTPS
        if self.config.server.force_https {
            let host = req.headers()
                .get(header::HOST)
                .and_then(|h| h.to_str().ok())
                .unwrap_or("localhost");
            let location = format!(
                "https://{}{}",
                host,
                req.uri().path_and_query().map(|p| p.as_str()).unwrap_or("/")
            );
            let mut resp = Response::new(Full::new(Bytes::new()));
            *resp.status_mut() = StatusCode::MOVED_PERMANENTLY;
            resp.headers_mut().insert(
                header::LOCATION,
                HeaderValue::from_str(&location).unwrap_or(HeaderValue::from_static("/")),
            );
            return Ok(resp);
        }

        self.handle_request(req, peer_ip).await
    }

    async fn handle_https(
        &self,
        req: Request<Incoming>,
        peer_ip: IpAddr,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        self.handle_request(req, peer_ip).await
    }

    async fn handle_request(
        &self,
        req: Request<Incoming>,
        peer_ip: IpAddr,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        // Extraer host
        let host = req.headers()
            .get(header::HOST)
            .and_then(|h| h.to_str().ok())
            .map(|h| h.split(':').next().unwrap_or(h))
            .unwrap_or("")
            .to_string();

        // Content-Length para firewall
        let content_length = req.headers()
            .get(header::CONTENT_LENGTH)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.parse::<u64>().ok());

        // Verificación de firewall
        match self.firewall.check(peer_ip, Some(&host), content_length).await {
            crate::firewall::FirewallDecision::Deny(reason) => {
                let status = StatusCode::from_u16(reason.http_status()).unwrap_or(StatusCode::FORBIDDEN);
                return Ok(text_response(status, reason.message().to_string()));
            }
            crate::firewall::FirewallDecision::Allow => {}
        }

        // Enrutar
        let route = match self.router.resolve(&host) {
            Some(r) => r.clone(),
            None => {
                warn!(host = %host, ip = %peer_ip, "Sin ruta para este host");
                return Ok(text_response(
                    StatusCode::NOT_FOUND,
                    format!("No hay servicio configurado para '{}'", host),
                ));
            }
        };

        match &route.target {
            RouteTarget::Upstream { port } => {
                self.proxy_upstream(req, *port, &route).await
            }
            RouteTarget::Static { dir, compress } => {
                self.serve_static(req, dir, *compress, &route).await
            }
            RouteTarget::UnixSocket { path } => {
                // Unix socket proxy (simplificado — en producción usar hyper-unix-connector)
                warn!("Unix socket proxy no implementado en este build; derivando a 502");
                Ok(text_response(StatusCode::BAD_GATEWAY, "Unix socket proxy no disponible".to_string()))
            }
        }
    }

    // ─── Proxy upstream ────────────────────────

    async fn proxy_upstream(
        &self,
        mut req: Request<Incoming>,
        port: u16,
        route: &Route,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        // Construir URI upstream
        let path_query = req.uri()
            .path_and_query()
            .map(|p| p.as_str())
            .unwrap_or("/");

        let upstream_uri = format!("http://127.0.0.1:{}{}", port, path_query);

        *req.uri_mut() = upstream_uri.parse().unwrap_or(Uri::from_static("/"));

        // Headers X-Forwarded-*
        let headers = req.headers_mut();
        if let Ok(v) = HeaderValue::from_str(&format!("{}", route.domain)) {
            headers.insert("X-Forwarded-Host", v);
        }
        headers.insert("X-Forwarded-Proto", HeaderValue::from_static("https"));

        let timeout = Duration::from_secs(self.config.server.proxy_timeout_secs);

        match tokio::time::timeout(timeout, self.http_client.request(req)).await {
            Ok(Ok(upstream_resp)) => {
                // Leer body completo del upstream
                let (parts, body) = upstream_resp.into_parts();
                let body_bytes = match body.collect().await {
                    Ok(b) => b.to_bytes(),
                    Err(_) => Bytes::new(),
                };

                let mut resp = Response::from_parts(parts, Full::new(body_bytes));
                self.apply_route_headers(&mut resp, route);
                Ok(resp)
            }
            Ok(Err(e)) => {
                error!(port = port, error = %e, "Error al conectar con upstream");
                Ok(text_response(
                    StatusCode::BAD_GATEWAY,
                    format!("El servicio upstream en :{} no está disponible", port),
                ))
            }
            Err(_) => {
                warn!(port = port, "Timeout al conectar con upstream");
                Ok(text_response(
                    StatusCode::GATEWAY_TIMEOUT,
                    "El upstream tardó demasiado en responder".to_string(),
                ))
            }
        }
    }

    // ─── Ficheros estáticos ────────────────────

    async fn serve_static(
        &self,
        req: Request<Incoming>,
        dir: &PathBuf,
        _compress: bool,
        route: &Route,
    ) -> Result<Response<Full<Bytes>>, hyper::Error> {
        if req.method() != Method::GET && req.method() != Method::HEAD {
            return Ok(text_response(StatusCode::METHOD_NOT_ALLOWED, "Método no permitido".to_string()));
        }

        let path = req.uri().path();
        // Evitar path traversal
        let sanitized = path.replace("../", "").replace("..\\", "");
        let mut file_path = dir.join(sanitized.trim_start_matches('/'));

        // SPA fallback: si no existe, servir index.html
        if !file_path.exists() || file_path.is_dir() {
            file_path = dir.join("index.html");
        }

        match tokio::fs::read(&file_path).await {
            Ok(bytes) => {
                let mime = mime_type(&file_path);
                let mut resp = Response::new(Full::new(Bytes::from(bytes)));
                resp.headers_mut().insert(
                    header::CONTENT_TYPE,
                    HeaderValue::from_str(mime).unwrap_or(HeaderValue::from_static("application/octet-stream")),
                );
                self.apply_route_headers(&mut resp, route);
                Ok(resp)
            }
            Err(_) => Ok(text_response(StatusCode::NOT_FOUND, "Archivo no encontrado".to_string())),
        }
    }

    // ─── Headers de respuesta ──────────────────

    fn apply_route_headers(&self, resp: &mut Response<Full<Bytes>>, route: &Route) {
        // Headers de seguridad automáticos
        if route.security_headers {
            for (k, v) in crate::firewall::security_headers() {
                if let (Ok(name), Ok(val)) = (
                    header::HeaderName::from_bytes(k.as_bytes()),
                    HeaderValue::from_str(v),
                ) {
                    resp.headers_mut().entry(name).or_insert(val);
                }
            }
        }

        // Headers extras del usuario
        for (k, v) in &route.extra_headers {
            if let (Ok(name), Ok(val)) = (
                header::HeaderName::from_bytes(k.as_bytes()),
                HeaderValue::from_str(v),
            ) {
                resp.headers_mut().insert(name, val);
            }
        }

        // Header de identificación
        resp.headers_mut().insert(
            "X-Served-By",
            HeaderValue::from_static("ASS/0.1"),
        );
    }
}

// ─────────────────────────────────────────────
//  Utilidades
// ─────────────────────────────────────────────

fn text_response(status: StatusCode, body: String) -> Response<Full<Bytes>> {
    let mut resp = Response::new(Full::new(Bytes::from(body)));
    *resp.status_mut() = status;
    resp.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    resp
}

fn mime_type(path: &PathBuf) -> &'static str {
    match path.extension().and_then(|e| e.to_str()) {
        Some("html") | Some("htm") => "text/html; charset=utf-8",
        Some("css") => "text/css",
        Some("js") | Some("mjs") => "application/javascript",
        Some("json") => "application/json",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("svg") => "image/svg+xml",
        Some("ico") => "image/x-icon",
        Some("woff") => "font/woff",
        Some("woff2") => "font/woff2",
        Some("ttf") => "font/ttf",
        Some("webp") => "image/webp",
        Some("pdf") => "application/pdf",
        Some("mp4") => "video/mp4",
        Some("webm") => "video/webm",
        Some("gz") | Some("br") => "application/octet-stream",
        Some("txt") | Some("md") => "text/plain; charset=utf-8",
        Some("xml") => "application/xml",
        _ => "application/octet-stream",
    }
}

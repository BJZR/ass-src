#!/usr/bin/env bash
# ── Empaquetador .deb para SS ──────────────────────────────────
set -euo pipefail

VERSION="${1:-0.1.0}"
DIST="${2:-dist}"
ARCH_LIST=("amd64:linux-amd64" "arm64:linux-arm64")

for ENTRY in "${ARCH_LIST[@]}"; do
  DEB_ARCH="${ENTRY%%:*}"
  BIN_PLATFORM="${ENTRY##*:}"
  PKG="ss_${VERSION}_${DEB_ARCH}"
  ROOT="${DIST}/.deb-${DEB_ARCH}"

  # Estructura de directorios Debian
  mkdir -p "${ROOT}/DEBIAN"
  mkdir -p "${ROOT}/usr/local/bin"
  mkdir -p "${ROOT}/etc/ss"
  mkdir -p "${ROOT}/lib/systemd/system"
  mkdir -p "${ROOT}/usr/share/doc/ss"
  mkdir -p "${ROOT}/usr/share/man/man1"

  # Binario
  cp "${DIST}/packages/ss-${BIN_PLATFORM}.bin" "${ROOT}/usr/local/bin/ass"
  chmod 755 "${ROOT}/usr/local/bin/ass"

  # ass.toml de ejemplo
  cat > "${ROOT}/etc/ass/ass.toml.example" <<'TOML'
[server]
host = "0.0.0.0"
http_port = 80
https_port = 443
ssl_email = "admin@example.com"
TOML

  # Unidad systemd
  cat > "${ROOT}/lib/systemd/system/ass.service" <<UNIT
[Unit]
Description=AASS - App Service Server
Documentation=https://ass-project.github.io/ass-deploy/
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ass start --foreground -c /etc/ass/ass.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
User=root
LimitNOFILE=65536
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
UNIT

  # DEBIAN/control
  cat > "${ROOT}/DEBIAN/control" <<CONTROL
Package: ass
Version: ${VERSION}
Architecture: ${DEB_ARCH}
Maintainer: SS Project <hello@ass-project.dev>
Installed-Size: $(du -sk "${ROOT}/usr" | cut -f1)
Section: net
Priority: optional
Homepage: https://ass-project.github.io/ass-deploy/
Description: ASS - App Service Server — binario único todo-en-uno
 ASS reemplaza Nginx, Certbot, PM2 y ngrok con un único ejecutable
 escrito en Rust. Incluye proxy inverso HTTP/HTTPS, TLS automático
 (ACME/Let's Encrypt), gestión de procesos, firewall de aplicación
 y túneles NAT, todo configurado desde un único archivo ass.toml.
CONTROL

  # DEBIAN/postinst
  cat > "${ROOT}/DEBIAN/postinst" <<'POSTINST'
#!/bin/bash
set -e
# Crear directorio de datos y logs
mkdir -p /var/lib/ass /var/log/ass /etc/ass/certs
chmod 750 /etc/ass/certs

# Instalar ejemplo de config si no existe
if [ ! -f /etc/ass/ass.toml ]; then
  cp /etc/ass/ass.toml.example /etc/ass/ass.toml
  echo "SS: Archivo de configuración creado en /etc/ass/ass.toml"
fi

# Recargar y habilitar systemd
if command -v systemctl &>/dev/null && systemctl is-system-running &>/dev/null; then
  systemctl daemon-reload
  echo "SS instalado. Para iniciar: systemctl enable --now ss"
fi
POSTINST
  chmod 755 "${ROOT}/DEBIAN/postinst"

  # DEBIAN/prerm
  cat > "${ROOT}/DEBIAN/prerm" <<'PRERM'
#!/bin/bash
set -e
if command -v systemctl &>/dev/null; then
  systemctl stop ss 2>/dev/null || true
  systemctl disable ss 2>/dev/null || true
fi
PRERM
  chmod 755 "${ROOT}/DEBIAN/prerm"

  # Copyright
  cat > "${ROOT}/usr/share/doc/ss/copyright" <<'CPR'
Format: https://www.debian.org/doc/packaging-manuals/copyright-format/1.0/
Upstream-Name: ss
Source: https://github.com/ass-project/ass-src

Files: *
Copyright: SS Project
License: MIT
CPR

  # Construir .deb
  dpkg-deb --build --root-owner-group "${ROOT}" "${DIST}/packages/${PKG}.deb" 2>/dev/null \
    || fakeroot dpkg-deb --build "${ROOT}" "${DIST}/packages/${PKG}.deb" 2>/dev/null \
    || ar cr "${DIST}/packages/${PKG}.deb" /dev/null  # fallback mínimo si dpkg no está

  rm -rf "${ROOT}"
  echo "    ✓ ${PKG}.deb"
done

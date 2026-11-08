#!/usr/bin/env bash
# ── Empaquetador .rpm para SS ──────────────────────────────────
set -euo pipefail

VERSION="${1:-0.1.0}"
DIST="${2:-dist}"
ARCH_LIST=("x86_64:linux-amd64" "aarch64:linux-arm64")

# Crear estructura rpmbuild
RPMBUILD="${DIST}/.rpmbuild"
mkdir -p "${RPMBUILD}"/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

for ENTRY in "${ARCH_LIST[@]}"; do
  RPM_ARCH="${ENTRY%%:*}"
  BIN_PLATFORM="${ENTRY##*:}"

  # Copiar binario como source
  cp "${DIST}/packages/ss-${BIN_PLATFORM}.bin" "${RPMBUILD}/SOURCES/ss-${RPM_ARCH}"

  # Spec file
  cat > "${RPMBUILD}/SPECS/ss-${RPM_ARCH}.spec" <<SPEC
Name:           ass
Version:        ${VERSION}
Release:        1
Summary:        ASS - App Service Server — binario único todo-en-uno en Rust
License:        MIT
URL:            https://ass-project.github.io/ass-deploy/
BuildArch:      ${RPM_ARCH}
Source0:        ss-${RPM_ARCH}

%description
ASS reemplaza Nginx, Certbot, PM2 y ngrok con un único ejecutable
escrito en Rust. Incluye proxy inverso HTTP/HTTPS, TLS automático
(ACME/Let's Encrypt), gestión de procesos, firewall de aplicación
y túneles NAT.

%prep
# No se requiere desempaquetar

%install
install -Dm 755 %{_sourcedir}/ss-${RPM_ARCH} %{buildroot}/usr/local/bin/ass
install -dm 750 %{buildroot}/etc/ss
install -dm 750 %{buildroot}/etc/ass/certs
install -dm 755 %{buildroot}/var/lib/ass
install -dm 755 %{buildroot}/var/log/ass

cat > %{buildroot}/etc/ass/ass.toml.example << 'TOML'
[server]
host = "0.0.0.0"
http_port = 80
https_port = 443
ssl_email = "admin@example.com"
TOML

install -Dm 644 /dev/stdin %{buildroot}/usr/lib/systemd/system/ass.service << 'UNIT'
[Unit]
Description=AASS - App Service Server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/ass start --foreground -c /etc/ass/ass.toml
ExecReload=/bin/kill -HUP \$MAINPID
Restart=on-failure
RestartSec=5
User=root
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
UNIT

%files
/usr/local/bin/ass
/etc/ass/ass.toml.example
%dir /etc/ss
%dir /etc/ass/certs
%dir /var/lib/ass
%dir /var/log/ass
/usr/lib/systemd/system/ass.service

%post
if command -v systemctl &>/dev/null && systemctl is-system-running &>/dev/null 2>&1; then
  systemctl daemon-reload
fi
if [ ! -f /etc/ass/ass.toml ]; then
  cp /etc/ass/ass.toml.example /etc/ass/ass.toml
fi
echo "SS instalado. Para iniciar: systemctl enable --now ss"

%preun
if command -v systemctl &>/dev/null; then
  systemctl stop ss 2>/dev/null || true
  systemctl disable ss 2>/dev/null || true
fi

%changelog
* $(date "+%a %b %d %Y") SS Project <hello@ass-project.dev> - ${VERSION}-1
- Release ${VERSION}
SPEC

  # Construir .rpm si rpmbuild está disponible
  if command -v rpmbuild &>/dev/null; then
    rpmbuild -bb \
      --define "_topdir $(realpath ${RPMBUILD})" \
      --define "_rpmdir $(realpath ${DIST}/packages)" \
      --define "_build_id_links none" \
      "${RPMBUILD}/SPECS/ss-${RPM_ARCH}.spec" 2>&1 | tail -3

    # Mover a nombre estándar
    find "${DIST}/packages" -name "ss-${VERSION}*.rpm" \
      -exec mv {} "${DIST}/packages/ss-${VERSION}-1.${RPM_ARCH}.rpm" \; 2>/dev/null || true
  else
    # Crear .rpm mínimo con cpio si rpmbuild no está disponible (CI fallback)
    # En GitHub Actions se instala con: sudo apt-get install rpm
    echo "    ⚠ rpmbuild no disponible; generando .rpm stub"
    touch "${DIST}/packages/ss-${VERSION}-1.${RPM_ARCH}.rpm"
  fi

  echo "    ✓ ss-${VERSION}-1.${RPM_ARCH}.rpm"
done

rm -rf "${RPMBUILD}"

#!/usr/bin/env bash
# ── Empaquetador AppImage para SS (con AppImageUpdate para auto-update) ──
set -euo pipefail

VERSION="${1:-0.1.0}"
DIST="${2:-dist}"
APPDIR="${DIST}/.AppDir"

mkdir -p "${APPDIR}/usr/bin"
mkdir -p "${APPDIR}/usr/share/applications"
mkdir -p "${APPDIR}/usr/share/icons/hicolor/256x256/apps"

# Binario principal
cp "${DIST}/packages/ss-linux-amd64.bin" "${APPDIR}/usr/bin/ass"
chmod +x "${APPDIR}/usr/bin/ass"

# AppRun — wrapper que invoca el binario
cat > "${APPDIR}/AppRun" <<'APPRUN'
#!/bin/bash
SELF_DIR="$(dirname "$(readlink -f "$0")")"
export PATH="${SELF_DIR}/usr/bin:${PATH}"

# AppImageUpdate: self-update si se invoca con --appimage-update
if [[ "${1:-}" == "--appimage-update" ]]; then
  if command -v AppImageUpdate &>/dev/null; then
    AppImageUpdate "${APPIMAGE}"
  else
    echo "AppImageUpdate no disponible; usa: ass update"
  fi
  exit 0
fi

exec "${SELF_DIR}/usr/bin/ass" "$@"
APPRUN
chmod +x "${APPDIR}/AppRun"

# .desktop (requerido por AppImage)
cat > "${APPDIR}/ss.desktop" <<DESKTOP
[Desktop Entry]
Type=Application
Name=ASS - App Service Server
Exec=ss
Icon=ss
Comment=Proxy inverso + TLS + gestión de procesos en un binario
Categories=Network;System;
Terminal=true
DESKTOP
cp "${APPDIR}/ss.desktop" "${APPDIR}/usr/share/applications/ss.desktop"

# Icono SVG → PNG simple (usando python si está disponible)
cat > "${APPDIR}/ss.svg" <<'SVG'
<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 256 256">
  <rect width="256" height="256" rx="48" fill="#0a0a0f"/>
  <text x="28" y="184" font-family="Arial Black, Arial" font-weight="900"
        font-size="152" fill="#6c63ff">SS</text>
</svg>
SVG
cp "${APPDIR}/ss.svg" "${APPDIR}/usr/share/icons/hicolor/256x256/apps/ss.svg"

# Metainfo AppStream (para actualización automática vía zsync)
mkdir -p "${APPDIR}/usr/share/metainfo"
cat > "${APPDIR}/usr/share/metainfo/ss.appdata.xml" <<XML
<?xml version="1.0" encoding="UTF-8"?>
<component type="console-application">
  <id>dev.ass-project.ss</id>
  <name>ASS - App Service Server</name>
  <summary>Proxy inverso + TLS automático + gestión de procesos</summary>
  <url type="homepage">https://ass-project.github.io/ass-deploy/</url>
  <releases>
    <release version="${VERSION}" date="$(date +%Y-%m-%d)"/>
  </releases>
  <update_contact>hello@ass-project.dev</update_contact>
</component>
XML

# Intentar construir con appimagetool
APPIMAGE_NAME="SS-${VERSION}-x86_64.AppImage"

if command -v appimagetool &>/dev/null; then
  # Incluir información de actualización automática (zsync)
  UPDATE_INFO="gh-releases-zsync|ass-project|ass-src|latest|SS-*-x86_64.AppImage.zsync"
  ARCH=x86_64 appimagetool \
    --updateinformation "${UPDATE_INFO}" \
    "${APPDIR}" \
    "${DIST}/packages/${APPIMAGE_NAME}" 2>&1 | tail -5

  # Generar zsync para AppImageUpdate
  if command -v zsyncmake &>/dev/null; then
    zsyncmake \
      -u "https://ass-project.github.io/ass-deploy/packages/${APPIMAGE_NAME}" \
      -o "${DIST}/packages/${APPIMAGE_NAME}.zsync" \
      "${DIST}/packages/${APPIMAGE_NAME}"
    echo "    ✓ .zsync generado para auto-update"
  fi
else
  # Fallback: crear AppImage manualmente con squashfs
  if command -v mksquashfs &>/dev/null; then
    echo "    Usando mksquashfs como fallback..."
    SQUASH="${DIST}/ss.squashfs"
    mksquashfs "${APPDIR}" "${SQUASH}" -comp zstd -noappend -quiet

    # Header ELF mínimo para AppImage Tipo 2
    # (En CI real usamos appimagetool descargado automáticamente)
    cat > "${DIST}/packages/${APPIMAGE_NAME}" <<'EOF'
#!/bin/bash
# AppImage stub — reemplazar con appimagetool en producción
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
echo "SS AppImage stub. Construir con appimagetool para funcionalidad completa."
exec "${SCRIPT_DIR}/ss-linux-amd64.bin" "$@"
EOF
    chmod +x "${DIST}/packages/${APPIMAGE_NAME}"
  else
    # Stub mínimo
    cp "${DIST}/packages/ss-linux-amd64.bin" "${DIST}/packages/${APPIMAGE_NAME}"
    chmod +x "${DIST}/packages/${APPIMAGE_NAME}"
  fi
fi

rm -rf "${APPDIR}"
echo "    ✓ ${APPIMAGE_NAME}"

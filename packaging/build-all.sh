#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════
#  ASS — build-all.sh
#  Compila para todas las plataformas y genera todos los paquetes
#  Uso: ./packaging/build-all.sh [VERSION]
# ═══════════════════════════════════════════════════════════════
set -euo pipefail

VERSION="${1:-$(grep '^version' Cargo.toml | head -1 | sed 's/.*= *"//' | sed 's/"//')}"
DIST="dist"

echo "═══════════════════════════════════════"
echo "  SS Build System — v${VERSION}"
echo "═══════════════════════════════════════"

# Limpiar artefactos anteriores
rm -rf "${DIST}"
mkdir -p "${DIST}/packages"

# ─── Targets de compilación ─────────────────────────────────────
declare -A TARGETS=(
  ["linux-amd64"]="x86_64-unknown-linux-musl"
  ["linux-arm64"]="aarch64-unknown-linux-musl"
  ["darwin-amd64"]="x86_64-apple-darwin"
  ["darwin-arm64"]="aarch64-apple-darwin"
  ["windows-amd64"]="x86_64-pc-windows-gnu"
)

# ─── 1. Compilar binarios ────────────────────────────────────────
echo ""
echo "▶ Compilando binarios..."

for PLATFORM in "${!TARGETS[@]}"; do
  TARGET="${TARGETS[$PLATFORM]}"
  echo "  → ${PLATFORM} (${TARGET})"

  # Añadir target si no existe
  rustup target add "${TARGET}" 2>/dev/null || true

  # Compilar con cross si está disponible, sino cargo directo
  if command -v cross &>/dev/null; then
    cross build --release --target "${TARGET}"
  else
    cargo build --release --target "${TARGET}"
  fi

  # Copiar binario a dist/
  BIN_SRC="target/${TARGET}/release/ss"
  if [[ "${PLATFORM}" == windows* ]]; then
    BIN_SRC="${BIN_SRC}.exe"
    cp "${BIN_SRC}" "${DIST}/packages/ss-${PLATFORM}.exe"
  else
    cp "${BIN_SRC}" "${DIST}/packages/ss-${PLATFORM}.bin"
    chmod +x "${DIST}/packages/ss-${PLATFORM}.bin"
  fi
done

echo "  ✓ Binarios compilados"

# ─── 2. Paquete .deb ────────────────────────────────────────────
echo ""
echo "▶ Construyendo .deb..."
bash packaging/deb/build.sh "${VERSION}" "${DIST}"
echo "  ✓ .deb generado"

# ─── 3. Paquete .rpm ────────────────────────────────────────────
echo ""
echo "▶ Construyendo .rpm..."
bash packaging/rpm/build.sh "${VERSION}" "${DIST}"
echo "  ✓ .rpm generado"

# ─── 4. AppImage ────────────────────────────────────────────────
echo ""
echo "▶ Construyendo AppImage..."
bash packaging/appimage/build.sh "${VERSION}" "${DIST}"
echo "  ✓ AppImage generado"

# ─── 5. Checksums SHA-256 ───────────────────────────────────────
echo ""
echo "▶ Generando checksums..."
cd "${DIST}/packages"
sha256sum ./* > checksums.txt
cd - > /dev/null
echo "  ✓ checksums.txt generado"

# ─── 6. latest.json ─────────────────────────────────────────────
cat > "${DIST}/packages/latest.json" <<JSON
{
  "version": "${VERSION}",
  "date": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "packages": {
    "linux-amd64-bin":    "ss-linux-amd64.bin",
    "linux-arm64-bin":    "ss-linux-arm64.bin",
    "linux-amd64-deb":    "ss_${VERSION}_amd64.deb",
    "linux-arm64-deb":    "ss_${VERSION}_arm64.deb",
    "linux-amd64-rpm":    "ss-${VERSION}-1.x86_64.rpm",
    "linux-amd64-appimage": "SS-${VERSION}-x86_64.AppImage",
    "darwin-amd64-bin":   "ss-darwin-amd64.bin",
    "darwin-arm64-bin":   "ss-darwin-arm64.bin",
    "windows-amd64-exe":  "ss-windows-amd64.exe"
  }
}
JSON

echo ""
echo "═══════════════════════════════════════"
echo "  ✓ Build completo — dist/packages/"
echo ""
ls -lh "${DIST}/packages/"
echo "═══════════════════════════════════════"

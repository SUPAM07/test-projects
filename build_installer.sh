#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  AIUS v1.0 — Build Installer Package
#
#  Run this from your development machine to package the app for distribution.
#  Produces: aius-v1.0-linux-x86_64.tar.gz
#
#  Usage:  bash build_installer.sh [path/to/your/source/files]
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

VERSION="1.0"
PKG_NAME="aius-v${VERSION}-linux-x86_64"
BUILD_DIR="/tmp/aius_build/${PKG_NAME}"
SOURCE_DIR="${1:-$(pwd)}"

BOLD='\033[1m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { echo -e "${CYAN}[BUILD]${NC} $*"; }
ok()   { echo -e "${GREEN}[  OK ]${NC} $*"; }

echo -e "\n${BOLD}Building AIUS v${VERSION} installer package...${NC}\n"

# ── Clean build dir ────────────────────────────────────────────────────────────
rm -rf "$BUILD_DIR"
mkdir -p "${BUILD_DIR}/app"

# ── Copy installer scripts ──────────────────────────────────────────────────────
info "Copying installer..."
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cp "${SCRIPT_DIR}/install.sh" "${BUILD_DIR}/"
chmod 755 "${BUILD_DIR}/install.sh"

# ── Copy application source files ──────────────────────────────────────────────
info "Copying application files from: $SOURCE_DIR"

APP_FILES=(
    "ui_wiring.py"
    "tlv_parser1.py"
    "tlv_parser2.py"
    "json_writer.py"
    "redis_ts.py"
    "arp_poison.py"
    "attack_engine.py"
    "mitm.py"
    "gui_mitm_tab.py"
    "main_sniffer.py"
    "mms_handler.py"
    "goose_handler.py"
    "sv_handler.py"
    "aius_v1.ui"
    "embsys5.png"
    "iisc1.png"
)

for f in "${APP_FILES[@]}"; do
    src="${SOURCE_DIR}/${f}"
    if [[ -f "$src" ]]; then
        cp "$src" "${BUILD_DIR}/app/"
        ok "  $f"
    else
        echo "  WARNING: $f not found in $SOURCE_DIR — skipping"
    fi
done

# ── Write requirements.txt into the package ─────────────────────────────────────
cat > "${BUILD_DIR}/app/requirements.txt" << 'REQ'
scapy>=2.5.0
netfilterqueue>=1.1.0
redis[hiredis]>=5.0.0
PyQt5>=5.15.0
PyQt5-sip
REQ

# ── Write README into the package ───────────────────────────────────────────────
cat > "${BUILD_DIR}/README.txt" << 'README'
AIUS v1.0 — Attack & Intrusion Utility Suite
═════════════════════════════════════════════

INSTALL
  sudo bash install.sh

LAUNCH
  aius            (from terminal, any directory)
  Or: find "AIUS" in your application menu

UNINSTALL
  sudo bash install.sh --remove

REPAIR (reinstall Python deps only)
  sudo bash install.sh --repair

REQUIREMENTS
  • Linux x86_64 (Kali, Ubuntu 20.04+, Debian 11+, Parrot OS)
  • Python 3.10 or higher
  • Internet connection (first install only)
  • Root/sudo for MITM features (NFQueue, ARP, iptables)

CREDITS
  Developed by   : Ayush Chand Ramola
  Concept        : Kishan Baranwal  |  Co-guide: Rakshit R.
  Supervisor     : Prof. Haresh Dagale
  Sponsor        : PGCoE — PowerGrid Centre of Excellence in Cybersecurity
  © 2026 IISc / PGCoE
README

# ── Package ────────────────────────────────────────────────────────────────────
info "Packaging..."
cd /tmp/aius_build
tar -czf "${PKG_NAME}.tar.gz" "${PKG_NAME}/"
FINAL_PKG="/tmp/aius_build/${PKG_NAME}.tar.gz"
ok "Package created: $FINAL_PKG"

# Copy to source dir for convenience
cp "$FINAL_PKG" "${SOURCE_DIR}/"
ok "Copied to: ${SOURCE_DIR}/${PKG_NAME}.tar.gz"

# Show contents
echo ""
echo -e "${BOLD}Package contents:${NC}"
tar -tzf "$FINAL_PKG" | sed 's/^/  /'

echo ""
echo -e "${GREEN}${BOLD}Done! Distribute: ${PKG_NAME}.tar.gz${NC}"
echo ""
echo "  User install steps:"
echo "    tar -xzf ${PKG_NAME}.tar.gz"
echo "    cd ${PKG_NAME}"
echo "    sudo bash install.sh"
echo ""

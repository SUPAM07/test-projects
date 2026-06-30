#!/usr/bin/env bash
# AIUS v1.0 — Uninstaller
# Usage: sudo bash uninstall.sh

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; BOLD='\033[1m'; NC='\033[0m'
die()  { echo -e "${RED}[ERR]${NC} $*" >&2; exit 1; }
ok()   { echo -e "${GREEN}[ OK]${NC} $*"; }
step() { echo -e "  ▸  $*"; }

[[ $EUID -ne 0 ]] && die "Run as root: sudo bash uninstall.sh"

echo -e "\n${BOLD}Uninstalling AIUS v1.0...${NC}\n"

step "Stopping Redis if AIUS started it..."
pkill -f "redis-stack-server.*6379" 2>/dev/null || true

step "Removing application files..."
rm -rf  /opt/aius
rm -f   /usr/local/bin/aius
rm -f   /usr/share/applications/aius.desktop
rm -f   /usr/share/icons/hicolor/128x128/apps/aius.png
rm -f   /etc/sysctl.d/99-aius.conf
rm -f   /etc/sudoers.d/aius
rm -f   /usr/share/polkit-1/actions/io.aius.pkexec.policy

step "Refreshing caches..."
update-desktop-database 2>/dev/null || true
gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true
sysctl -p /etc/sysctl.conf 2>/dev/null || true

echo ""
ok "AIUS v1.0 has been removed."
echo ""

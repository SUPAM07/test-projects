#!/usr/bin/env bash
# ═══════════════════════════════════════════════════════════════════════════════
#  AIUS v1.0 — Attack & Intrusion Utility Suite
#  Installer Script
#
#  Supports: Kali Linux, Ubuntu 20.04+, Debian 11+, Parrot OS, BlackArch
#  Requires: x86_64, Python 3.10+, internet connection for first install
#
#  Usage:
#    sudo bash install.sh          # full install
#    sudo bash install.sh --repair # reinstall Python deps only
#    sudo bash install.sh --remove # uninstall
# ═══════════════════════════════════════════════════════════════════════════════

set -euo pipefail

# ── Identity ──────────────────────────────────────────────────────────────────
APP_NAME="AIUS"
APP_VERSION="1.0"
APP_FULL="AIUS v${APP_VERSION}"
APP_ID="aius"
APP_AUTHOR="Ayush Chand Ramola"
APP_DESC="IEC 61850 Attack & Intrusion Utility Suite"

# ── Install paths ─────────────────────────────────────────────────────────────
INSTALL_DIR="/opt/aius"
BIN_LAUNCHER="/usr/local/bin/aius"
DESKTOP_FILE="/usr/share/applications/aius.desktop"
ICON_DIR="/usr/share/icons/hicolor/128x128/apps"
ICON_FILE="${ICON_DIR}/aius.png"
SYSCTL_CONF="/etc/sysctl.d/99-aius.conf"
SUDOERS_FILE="/etc/sudoers.d/aius"

# ── Python virtualenv ─────────────────────────────────────────────────────────
VENV_DIR="${INSTALL_DIR}/venv"
PYTHON_MIN="3.10"

# ── Colours ───────────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
BLUE='\033[0;34m'; CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

# ── Helpers ───────────────────────────────────────────────────────────────────
info()    { echo -e "${CYAN}[INFO]${NC}  $*"; }
ok()      { echo -e "${GREEN}[ OK ]${NC}  $*"; }
warn()    { echo -e "${YELLOW}[WARN]${NC}  $*"; }
error()   { echo -e "${RED}[FAIL]${NC}  $*" >&2; }
die()     { error "$*"; exit 1; }
header()  { echo -e "\n${BOLD}${BLUE}━━━  $*  ━━━${NC}"; }
step()    { echo -e "${BOLD}  ▸  $*${NC}"; }

banner() {
cat << 'EOF'

     █████████   █████ █████  █████  █████████
  ███░░░░░███ ░░███ ░░███  ░░███  ███░░░░░███
 ░███    ░███  ░███  ░███   ░███ ░███    ░░░
 ░███████████  ░███  ░███   ░███ ░░█████████
 ░███░░░░░███  ░███  ░███   ░███  ░░░░░░░░███
 ░███    ░███  ░███  ░███   ░███  ███    ░███
 █████   █████ █████ ░░████████  ░░█████████
░░░░░   ░░░░░ ░░░░░   ░░░░░░░░    ░░░░░░░░░             v1.0

  Attack & Intrusion Utility Suite
  IEC 61850 / MMS Passive PCAP Editor + Live MITM Engine
  ─────────────────────────────────────────────────────
  Author     : Ayush Chand Ramola
  Concept    : Kishan Baranwal  |  Co-guide: Rakshit R.
  Supervisor : Prof. Haresh Dagale
  Sponsor    : PGCoE — PowerGrid Centre of Excellence in Cybersecurity
  ─────────────────────────────────────────────────────

EOF
}

# ── Root check ────────────────────────────────────────────────────────────────
check_root() {
    if [[ $EUID -ne 0 ]]; then
        die "This installer must be run as root.\n  Usage: sudo bash install.sh"
    fi
    # Record the real user who invoked sudo
    REAL_USER="${SUDO_USER:-$(logname 2>/dev/null || echo root)}"
    REAL_HOME=$(getent passwd "$REAL_USER" | cut -d: -f6)
    ok "Running as root (real user: $REAL_USER)"
}

# ── Detect distro ─────────────────────────────────────────────────────────────
detect_distro() {
    header "Detecting Linux Distribution"
    if [[ -f /etc/os-release ]]; then
        source /etc/os-release
        DISTRO_ID="${ID:-unknown}"
        DISTRO_LIKE="${ID_LIKE:-}"
        DISTRO_VERSION="${VERSION_ID:-}"
        DISTRO_NAME="${PRETTY_NAME:-unknown}"
    else
        die "/etc/os-release not found — unsupported distribution"
    fi

    info "Distribution: $DISTRO_NAME"

    # Determine package manager family
    case "$DISTRO_ID" in
        kali|parrot|debian|ubuntu|linuxmint|pop|zorin|elementary)
            PKG_FAMILY="apt"
            ;;
        *)
            # Check ID_LIKE fallback
            if echo "$DISTRO_LIKE" | grep -qiE "debian|ubuntu"; then
                PKG_FAMILY="apt"
            elif echo "$DISTRO_LIKE" | grep -qi "arch"; then
                PKG_FAMILY="pacman"
                warn "Arch-based distro detected — apt steps will be skipped"
            elif echo "$DISTRO_LIKE" | grep -qi "rhel|fedora"; then
                PKG_FAMILY="dnf"
                warn "RPM-based distro detected — apt steps will be skipped"
            else
                warn "Unknown distro '$DISTRO_ID' — will attempt apt-style install"
                PKG_FAMILY="apt"
            fi
            ;;
    esac

    ok "Package family: $PKG_FAMILY"
}

# ── Python version check ──────────────────────────────────────────────────────
check_python() {
    header "Checking Python Version"
    PYTHON_BIN=""
    for candidate in python3.12 python3.11 python3.10 python3; do
        if command -v "$candidate" &>/dev/null; then
            ver=$("$candidate" -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
            major=${ver%.*}; minor=${ver#*.}
            if [[ $major -ge 3 && $minor -ge 10 ]]; then
                PYTHON_BIN="$candidate"
                ok "Found $candidate ($ver)"
                break
            fi
        fi
    done
    if [[ -z "$PYTHON_BIN" ]]; then
        die "Python $PYTHON_MIN or higher is required but not found.\n  Install: sudo apt install python3.12"
    fi
}

# ── System packages ───────────────────────────────────────────────────────────
install_system_packages() {
    header "Installing System Packages"

    APT_PKGS=(
        # Core build + network
        python3-pip python3-venv python3-dev build-essential
        libnetfilter-queue-dev libnetfilter-queue1
        iptables net-tools iproute2 dsniff
        # Qt5
        python3-pyqt5 qtbase5-dev pyqt5-dev-tools
        libxcb-xinerama0 libxcb-cursor0
        # Redis Stack (includes TimeSeries module)
        lsb-release curl gnupg
        # Pcap
        libpcap-dev tcpdump
        # Scapy runtime deps
        libglib2.0-dev
    )

    PACMAN_PKGS=(
        python python-pip python-pyqt5
        libnetfilter_queue iptables
        redis
    )

    DNF_PKGS=(
        python3-pip python3-devel python3-pyqt5
        libnetfilter_queue-devel iptables
    )

    case "$PKG_FAMILY" in
        apt)
            step "Updating apt cache..."
            apt-get update -qq
            step "Installing apt packages..."
            DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
                "${APT_PKGS[@]}" 2>&1 | grep -E "^(Get|Inst|Err|WARNING)" || true
            ok "APT packages installed"
            ;;
        pacman)
            step "Installing pacman packages..."
            pacman -Sy --noconfirm "${PACMAN_PKGS[@]}" || warn "Some pacman packages failed"
            ;;
        dnf)
            step "Installing dnf packages..."
            dnf install -y "${DNF_PKGS[@]}" || warn "Some dnf packages failed"
            ;;
    esac
}

# ── Redis Stack (for TimeSeries module) ───────────────────────────────────────
install_redis_stack() {
    header "Installing Redis Stack"

    if command -v redis-stack-server &>/dev/null; then
        ok "redis-stack-server already installed"
        return
    fi

    if [[ "$PKG_FAMILY" != "apt" ]]; then
        warn "Redis Stack auto-install only supported on apt-based distros"
        warn "Install manually: https://redis.io/docs/getting-started/install-stack/"
        return
    fi

    step "Adding Redis official repository..."
    curl -fsSL https://packages.redis.io/gpg \
        | gpg --dearmor -o /usr/share/keyrings/redis-archive-keyring.gpg 2>/dev/null
    chmod 644 /usr/share/keyrings/redis-archive-keyring.gpg

    # Use codename; fall back to 'focal' for unknown distros (compatible)
    CODENAME=$(lsb_release -sc 2>/dev/null || echo "focal")
    # Map Kali's codename (which has no Redis repo) to latest Debian stable
    case "$DISTRO_ID" in
        kali)   CODENAME="bookworm" ;;
        parrot) CODENAME="bookworm" ;;
    esac

    echo "deb [signed-by=/usr/share/keyrings/redis-archive-keyring.gpg] \
https://packages.redis.io/deb ${CODENAME} main" \
        > /etc/apt/sources.list.d/redis.list

    apt-get update -qq 2>/dev/null || true

    if apt-get install -y redis-stack-server 2>/dev/null; then
        ok "redis-stack-server installed"
        # Disable autostart — AIUS manages it programmatically
        systemctl disable redis-stack-server 2>/dev/null || true
        systemctl stop    redis-stack-server 2>/dev/null || true
    else
        warn "redis-stack-server install failed — falling back to redis-server"
        apt-get install -y redis-server 2>/dev/null || warn "redis-server also failed"
        warn "TimeSeries features will be limited. See README for manual install."
    fi
}

# ── Python virtual environment + pip packages ─────────────────────────────────
install_python_deps() {
    header "Setting Up Python Environment"

    step "Creating virtualenv at $VENV_DIR..."
    "$PYTHON_BIN" -m venv --system-site-packages "$VENV_DIR"
    VENV_PIP="${VENV_DIR}/bin/pip"
    VENV_PYTHON="${VENV_DIR}/bin/python3"

    step "Upgrading pip..."
    "$VENV_PIP" install --quiet --upgrade pip

    step "Installing Python packages..."
    "$VENV_PIP" install --quiet \
        "scapy>=2.5.0" \
        "netfilterqueue>=1.1.0" \
        "redis[hiredis]>=5.0.0" \
        "PyQt5>=5.15.0" \
        "PyQt5-sip"

    ok "Python dependencies installed"

    # Verify critical imports
    step "Verifying imports..."
    "$VENV_PYTHON" -c "
from scapy.all import IP, TCP
import redis
from PyQt5 import QtWidgets
print('All imports OK')
" || die "Import verification failed — check Python environment"
    ok "All imports verified"
}

# ── Copy application files ─────────────────────────────────────────────────────
install_app_files() {
    header "Installing Application Files"

    step "Creating $INSTALL_DIR..."
    mkdir -p "$INSTALL_DIR"

    # Source is the directory containing this script
    SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

    step "Copying application files..."
    cp -r "${SCRIPT_DIR}/app/"* "$INSTALL_DIR/"
    chmod -R 755 "$INSTALL_DIR"

    ok "Application files copied to $INSTALL_DIR"
}

# ── System-level icon (SVG→PNG via Python) ────────────────────────────────────
install_icon() {
    header "Installing Application Icon"
    mkdir -p "$ICON_DIR"

    # Generate icon via Python (no ImageMagick dependency)
    "$VENV_DIR/bin/python3" - << 'PYEOF'
import sys, struct, zlib, base64

# Minimal 128x128 PNG generated entirely in Python — no Pillow needed
# Dark background (#0d1117) with blue AIUS text and a circuit motif

def make_png_128():
    W, H = 128, 128
    # Build raw RGBA pixel data
    pixels = []
    for y in range(H):
        row = []
        for x in range(W):
            # Background gradient
            bg = (13, 17, 23, 255)  # #0d1117

            # Outer ring
            cx, cy = W//2, H//2
            dx, dy = x-cx, y-cy
            dist = (dx*dx + dy*dy)**0.5
            if 58 <= dist <= 62:
                row.append((31, 111, 235, 255))   # #1f6feb ring
                continue
            # Inner ring
            if 44 <= dist <= 46:
                row.append((63, 185, 80, 180))    # #3fb950
                continue
            # Four corner dots
            for (ex, ey) in [(20,20),(108,20),(20,108),(108,108)]:
                if ((x-ex)**2+(y-ey)**2)**0.5 < 5:
                    row.append((212, 167, 44, 255))  # #d4a72c
                    break
            else:
                row.append(bg)
        pixels.append(row)

    # Draw "A" letter manually (pixel font 5x7 scaled 4x)
    letter = [
        [0,0,1,0,0],
        [0,1,0,1,0],
        [1,0,0,0,1],
        [1,1,1,1,1],
        [1,0,0,0,1],
        [1,0,0,0,1],
        [1,0,0,0,1],
    ]
    sx, sy, scale = 44, 44, 5
    for row_i, row_d in enumerate(letter):
        for col_i, on in enumerate(row_d):
            if on:
                for dy in range(scale):
                    for dx in range(scale):
                        px = sx + col_i*scale + dx
                        py = sy + row_i*scale + dy
                        if 0 <= px < W and 0 <= py < H:
                            pixels[py][px] = (88, 166, 255, 255)  # #58a6ff

    # Encode as PNG
    def chunk(name, data):
        c = struct.pack('>I', len(data)) + name + data
        crc = zlib.crc32(name + data) & 0xFFFFFFFF
        return c + struct.pack('>I', crc)

    raw = b''
    for row in pixels:
        raw += b'\x00'  # filter type none
        for r,g,b,a in row:
            raw += bytes([r,g,b,a])

    compressed = zlib.compress(raw, 9)
    png  = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', struct.pack('>IIBBBBB', W, H, 8, 2, 0, 0, 0)
                          .replace(struct.pack('>BB', 2, 0), struct.pack('>BBBBB', 8, 2, 0, 0, 0)))
    # Correct IHDR: width(4) height(4) bitdepth(1) colortype(1=RGB,2=RGB,6=RGBA) compression filter interlace
    ihdr = struct.pack('>II', W, H) + bytes([8, 6, 0, 0, 0])
    png  = b'\x89PNG\r\n\x1a\n'
    png += chunk(b'IHDR', ihdr)
    png += chunk(b'IDAT', compressed)
    png += chunk(b'IEND', b'')
    return png

icon_path = "/usr/share/icons/hicolor/128x128/apps/aius.png"
import os; os.makedirs(os.path.dirname(icon_path), exist_ok=True)
with open(icon_path, 'wb') as f:
    f.write(make_png_128())
print(f"Icon written to {icon_path}")
PYEOF
    ok "Icon installed"
}

# ── Root launcher wrapper ─────────────────────────────────────────────────────
install_launcher() {
    header "Installing System Launcher"

    # /usr/local/bin/aius — the command users type
    cat > "$BIN_LAUNCHER" << LAUNCHER
#!/usr/bin/env bash
# AIUS v1.0 launcher
# The app needs root for NFQueue, iptables, and ARP poisoning.
# If already root, run directly. Otherwise, re-exec with pkexec/sudo.

INSTALL_DIR="${INSTALL_DIR}"
VENV_PYTHON="\${INSTALL_DIR}/venv/bin/python3"
MAIN_SCRIPT="\${INSTALL_DIR}/ui_wiring.py"

# Detect display for GUI apps run as root
export DISPLAY="\${DISPLAY:-:0}"
export XAUTHORITY="\${XAUTHORITY:-\${HOME}/.Xauthority}"

# Qt platform fallback
export QT_QPA_PLATFORM="\${QT_QPA_PLATFORM:-xcb}"

run_app() {
    cd "\$INSTALL_DIR"
    exec "\$VENV_PYTHON" "\$MAIN_SCRIPT" "\$@"
}

if [[ \$EUID -eq 0 ]]; then
    run_app "\$@"
elif command -v pkexec &>/dev/null; then
    # pkexec preserves DISPLAY correctly for GUI
    exec pkexec --disable-internal-agent "\$VENV_PYTHON" "\$MAIN_SCRIPT" "\$@"
elif command -v sudo &>/dev/null; then
    exec sudo -E "\$VENV_PYTHON" "\$MAIN_SCRIPT" "\$@"
else
    echo "Error: AIUS requires root. Run: sudo aius"
    exit 1
fi
LAUNCHER
    chmod 755 "$BIN_LAUNCHER"
    ok "Launcher installed: $BIN_LAUNCHER"

    # PolicyKit policy for pkexec (allows launching from .desktop without terminal)
    POLKIT_DIR="/usr/share/polkit-1/actions"
    if [[ -d "$POLKIT_DIR" ]]; then
        cat > "${POLKIT_DIR}/io.aius.pkexec.policy" << 'POLICY'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE policyconfig PUBLIC
  "-//freedesktop//DTD PolicyKit Policy Configuration 1.0//EN"
  "http://www.freedesktop.org/standards/PolicyKit/1/policyconfig.dtd">
<policyconfig>
  <action id="io.aius.pkexec.run">
    <description>Run AIUS (requires root for NFQueue and ARP poisoning)</description>
    <message>AIUS needs administrator privileges for live MITM operations.</message>
    <icon_name>aius</icon_name>
    <defaults>
      <allow_any>auth_admin</allow_any>
      <allow_inactive>auth_admin</allow_inactive>
      <allow_active>auth_admin_keep</allow_active>
    </defaults>
    <annotate key="org.freedesktop.policykit.exec.path">/opt/aius/venv/bin/python3</annotate>
    <annotate key="org.freedesktop.policykit.exec.allow_gui">true</annotate>
  </action>
</policyconfig>
POLICY
        ok "PolicyKit policy installed"
    fi
}

# ── Desktop entry ─────────────────────────────────────────────────────────────
install_desktop_entry() {
    header "Installing Desktop Entry"

    cat > "$DESKTOP_FILE" << DESKTOP
[Desktop Entry]
Version=1.0
Type=Application
Name=AIUS v1.0
GenericName=IEC 61850 Attack Tool
Comment=Attack & Intrusion Utility Suite — IEC 61850/MMS PCAP Editor + Live MITM
Exec=aius
Icon=aius
Terminal=false
Categories=Network;Security;
Keywords=iec61850;mms;mitm;scada;pcap;security;
StartupNotify=true
StartupWMClass=AIUS
X-AIUS-Version=1.0
X-AIUS-Author=Ayush Chand Ramola
DESKTOP

    chmod 644 "$DESKTOP_FILE"
    # Refresh desktop database
    update-desktop-database 2>/dev/null || true
    gtk-update-icon-cache /usr/share/icons/hicolor 2>/dev/null || true
    ok "Desktop entry installed — AIUS appears in application menu"
}

# ── sudoers rule (optional — lets aius run without password prompt) ────────────
install_sudoers() {
    header "Configuring sudo Permissions"

    VENV_PY="${VENV_DIR}/bin/python3"

    # This allows all users in sudo/wheel group to run AIUS python without passwd
    cat > "$SUDOERS_FILE" << SUDOERS
# AIUS v1.0 — allow running without password prompt for MITM features
# Remove this file (/etc/sudoers.d/aius) to revoke.
%sudo ALL=(ALL) NOPASSWD: ${VENV_PY} ${INSTALL_DIR}/ui_wiring.py *
%wheel ALL=(ALL) NOPASSWD: ${VENV_PY} ${INSTALL_DIR}/ui_wiring.py *
SUDOERS

    chmod 440 "$SUDOERS_FILE"
    # Validate (visudo -c exits non-zero if syntax error)
    if visudo -c -f "$SUDOERS_FILE" &>/dev/null; then
        ok "Sudoers rule installed (no password needed for AIUS)"
    else
        warn "Sudoers syntax error — removing to be safe"
        rm -f "$SUDOERS_FILE"
    fi
}

# ── sysctl: enable ip_forward persistence ────────────────────────────────────
configure_sysctl() {
    header "Configuring Kernel Parameters"

    # ip_forward is toggled at runtime by arp_poison.py
    # We set it to 0 here as the safe default; the app enables it when needed
    cat > "$SYSCTL_CONF" << 'SYSCTL'
# AIUS v1.0 — kernel params
# ip_forward is managed at runtime by the MITM engine
net.ipv4.ip_forward = 0
# Prevent RST storms from the kernel on NFQUEUE-intercepted connections
net.ipv4.conf.all.accept_local = 1
SYSCTL

    sysctl -p "$SYSCTL_CONF" &>/dev/null || true
    ok "Kernel parameters configured"
}

# ── Capabilities on Python (alternative to full sudo) ────────────────────────
set_capabilities() {
    header "Setting Network Capabilities"

    VENV_PY="${VENV_DIR}/bin/python3"
    if command -v setcap &>/dev/null; then
        # CAP_NET_ADMIN  — iptables, NFQueue, ARP
        # CAP_NET_RAW    — raw socket (scapy sendp)
        # CAP_NET_BIND_SERVICE — bind to port 102 if needed
        setcap 'cap_net_admin,cap_net_raw,cap_net_bind_service+eip' "$VENV_PY" && \
            ok "Network capabilities set on $VENV_PY" || \
            warn "setcap failed — sudo will be used instead"
    else
        warn "setcap not found — sudo will be used instead"
    fi
}

# ── Verify installation ───────────────────────────────────────────────────────
verify_install() {
    header "Verifying Installation"

    local all_ok=true

    check_item() {
        if [[ -e "$1" ]]; then
            ok "$2"
        else
            error "MISSING: $2 ($1)"
            all_ok=false
        fi
    }

    check_item "$INSTALL_DIR/ui_wiring.py"       "Application files"
    check_item "$VENV_DIR/bin/python3"           "Python virtualenv"
    check_item "$VENV_DIR/bin/pip"               "pip in venv"
    check_item "$BIN_LAUNCHER"                   "System launcher (/usr/local/bin/aius)"
    check_item "$DESKTOP_FILE"                   "Desktop entry"
    check_item "$ICON_FILE"                      "Application icon"

    # Test that the venv python can import everything critical
    step "Testing imports..."
    if "${VENV_DIR}/bin/python3" -c "
import scapy.all, redis, PyQt5.QtWidgets
" 2>/dev/null; then
        ok "Critical Python imports OK"
    else
        warn "Some Python imports failed — run: sudo bash install.sh --repair"
        all_ok=false
    fi

    # Redis Stack
    if command -v redis-stack-server &>/dev/null; then
        ok "redis-stack-server available"
    else
        warn "redis-stack-server not found — TimeSeries features limited"
    fi

    if $all_ok; then
        echo ""
        echo -e "${GREEN}${BOLD}╔══════════════════════════════════════════════════╗${NC}"
        echo -e "${GREEN}${BOLD}║   AIUS v1.0 installed successfully!              ║${NC}"
        echo -e "${GREEN}${BOLD}║                                                  ║${NC}"
        echo -e "${GREEN}${BOLD}║   Launch:  aius                (terminal)        ║${NC}"
        echo -e "${GREEN}${BOLD}║            or find 'AIUS' in app menu            ║${NC}"
        echo -e "${GREEN}${BOLD}╚══════════════════════════════════════════════════╝${NC}"
        echo ""
    else
        echo ""
        warn "Installation completed with warnings. Run 'sudo bash install.sh --repair' to fix."
    fi
}

# ── Uninstall ─────────────────────────────────────────────────────────────────
do_remove() {
    header "Uninstalling AIUS v1.0"
    step "Removing application files..."
    rm -rf "$INSTALL_DIR"
    rm -f  "$BIN_LAUNCHER"
    rm -f  "$DESKTOP_FILE"
    rm -f  "$ICON_FILE"
    rm -f  "$SYSCTL_CONF"
    rm -f  "$SUDOERS_FILE"
    rm -f  "/usr/share/polkit-1/actions/io.aius.pkexec.policy"
    rm -f  "/etc/apt/sources.list.d/redis.list"
    rm -f  "/usr/share/keyrings/redis-archive-keyring.gpg"
    update-desktop-database 2>/dev/null || true
    ok "AIUS v1.0 removed"
    exit 0
}

# ── Repair (reinstall Python deps only) ──────────────────────────────────────
do_repair() {
    header "Repairing Python Dependencies"
    check_root
    detect_distro
    check_python
    install_python_deps
    ok "Repair complete"
    exit 0
}

# ═══════════════════════════════════════════════════════════════════════════════
# Main
# ═══════════════════════════════════════════════════════════════════════════════
main() {
    banner

    # Parse args
    case "${1:-}" in
        --remove|-r)  check_root; do_remove ;;
        --repair)     do_repair ;;
        --help|-h)
            echo "Usage: sudo bash install.sh [--remove | --repair | --help]"
            exit 0
            ;;
    esac

    check_root
    detect_distro
    check_python
    install_system_packages
    install_redis_stack
    install_python_deps
    install_app_files
    install_icon
    install_launcher
    install_desktop_entry
    install_sudoers
    configure_sysctl
    set_capabilities
    verify_install
}

main "$@"

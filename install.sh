#!/usr/bin/env bash
#
# HACKiT installer for Kali Linux (and other Debian-based distros).
#
# Installs HACKiT in an isolated environment (via pipx when available,
# falling back to --break-system-packages pip) so it doesn't touch the
# system Python, and puts a `hackit` command on your PATH.
#
set -euo pipefail

BOLD="\033[1m"
CYAN="\033[36m"
GREEN="\033[32m"
YELLOW="\033[33m"
RED="\033[31m"
RESET="\033[0m"

info()  { echo -e "${CYAN}==>${RESET} $1"; }
ok()    { echo -e "${GREEN}✓${RESET} $1"; }
warn()  { echo -e "${YELLOW}!${RESET} $1"; }
fail()  { echo -e "${RED}✗ $1${RESET}"; exit 1; }

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

echo -e "${BOLD}${CYAN}"
echo " ██╗  ██╗ █████╗  ██████╗██╗  ██╗██╗████████╗"
echo " ██║  ██║██╔══██╗██╔════╝██║ ██╔╝██║╚══██╔══╝"
echo " ███████║███████║██║     █████╔╝ ██║   ██║   "
echo " ██╔══██║██╔══██║██║     ██╔═██╗ ██║   ██║   "
echo " ██║  ██║██║  ██║╚██████╗██║  ██╗██║   ██║   "
echo " ╚═╝  ╚═╝╚═╝  ╚═╝ ╚═════╝╚═╝  ╚═╝╚═╝   ╚═╝   "
echo -e "${RESET}"
echo "HACKiT installer"
echo

# --- Python version check --------------------------------------------------
if ! command -v python3 >/dev/null 2>&1; then
    fail "python3 not found. Install it first: sudo apt install python3"
fi

PY_VERSION=$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')
PY_OK=$(python3 -c 'import sys; print(1 if sys.version_info >= (3, 10) else 0)')
if [ "$PY_OK" != "1" ]; then
    fail "Python 3.10+ required, found $PY_VERSION."
fi
ok "Python $PY_VERSION found"

# --- Ask about the optional GUI --------------------------------------------
INSTALL_GUI="n"
read -r -p "Install the optional graphical interface too (needs PyQt6)? [y/N] " ans || true
if [[ "${ans:-}" =~ ^[Yy]$ ]]; then
    INSTALL_GUI="y"
fi

EXTRAS=""
if [ "$INSTALL_GUI" = "y" ]; then
    EXTRAS="[gui]"
    if ! dpkg -s libxcb-cursor0 >/dev/null 2>&1; then
        info "Installing GUI system dependency libxcb-cursor0..."
        if command -v apt-get >/dev/null 2>&1; then
            sudo apt-get update -qq && sudo apt-get install -y libxcb-cursor0 || \
                warn "Couldn't auto-install libxcb-cursor0 — the GUI may fail to start until you do: sudo apt install libxcb-cursor0"
        fi
    fi
fi

# --- Install -----------------------------------------------------------------
if command -v pipx >/dev/null 2>&1; then
    info "Installing HACKiT with pipx (isolated environment, recommended)..."
    pipx install --force ".${EXTRAS}"
    ok "Installed via pipx"
elif python3 -m pip --version >/dev/null 2>&1; then
    warn "pipx not found — falling back to pip with --break-system-packages."
    warn "Consider installing pipx for a cleaner setup: sudo apt install pipx"
    python3 -m pip install --break-system-packages --upgrade ".${EXTRAS}"
    ok "Installed via pip"
else
    fail "Neither pipx nor pip is available. Install one and re-run this script."
fi

# --- Verify --------------------------------------------------------------
if command -v hackit >/dev/null 2>&1; then
    ok "hackit is on your PATH: $(command -v hackit)"
else
    warn "hackit installed but isn't on your current PATH."
    warn "If you used pipx, run: pipx ensurepath   (then restart your shell)"
fi

echo
echo -e "${BOLD}${GREEN}Done.${RESET} Run ${BOLD}hackit${RESET} to get started, or ${BOLD}hackit --help${RESET} for subcommands."
if [ "$INSTALL_GUI" = "y" ]; then
    echo -e "Launch the GUI any time with ${BOLD}hackit gui${RESET}."
fi

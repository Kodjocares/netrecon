#!/usr/bin/env bash
# NetRecon Installation Script
# Usage: bash scripts/install.sh

set -e

GREEN='\033[0;32m'
CYAN='\033[0;36m'
RED='\033[0;31m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${CYAN}"
echo " ███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
echo " ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
echo " ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
echo " ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
echo " ██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
echo " ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
echo -e "${NC}"
echo -e "  ${CYAN}NetRecon v3.0 — Advanced Network Intelligence Suite${NC}"
echo -e "  ${RED}For authorized security testing only${NC}"
echo ""

# Check Python version
echo -e "${CYAN}[*] Checking Python version...${NC}"
PYTHON=$(command -v python3 || command -v python)
if [ -z "$PYTHON" ]; then
    echo -e "${RED}[✗] Python 3 not found. Please install Python 3.10+${NC}"
    exit 1
fi

PY_VERSION=$($PYTHON -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
PY_MAJOR=$($PYTHON -c "import sys; print(sys.version_info.major)")
PY_MINOR=$($PYTHON -c "import sys; print(sys.version_info.minor)")

if [ "$PY_MAJOR" -lt 3 ] || ([ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]); then
    echo -e "${RED}[✗] Python 3.10+ required. Found: $PY_VERSION${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] Python $PY_VERSION${NC}"

# Check pip
echo -e "${CYAN}[*] Checking pip...${NC}"
if ! $PYTHON -m pip --version &>/dev/null; then
    echo -e "${RED}[✗] pip not found${NC}"
    exit 1
fi
echo -e "${GREEN}[✓] pip available${NC}"

# Create virtual environment
echo -e "${CYAN}[*] Creating virtual environment...${NC}"
$PYTHON -m venv venv
echo -e "${GREEN}[✓] Virtual environment created${NC}"

# Activate
source venv/bin/activate

# Upgrade pip
echo -e "${CYAN}[*] Upgrading pip...${NC}"
pip install --upgrade pip -q

# Install dependencies
echo -e "${CYAN}[*] Installing dependencies...${NC}"
pip install -r requirements.txt -q
echo -e "${GREEN}[✓] Dependencies installed${NC}"

# Check for root (optional features)
if [ "$EUID" -eq 0 ]; then
    echo -e "${GREEN}[✓] Running as root — all features available${NC}"
else
    echo -e "${YELLOW}[!] Not running as root — some features require sudo:${NC}"
    echo -e "    ${YELLOW}• Packet capture (--sniff, --ids, --monitor)${NC}"
    echo -e "    ${YELLOW}• SYN scan (--scan-type syn)${NC}"
    echo -e "    ${YELLOW}• ARP scan (--arp-scan)${NC}"
    echo -e "    ${YELLOW}• Auto-blocking (--block)${NC}"
fi

# Test import
echo -e "${CYAN}[*] Testing imports...${NC}"
python -c "
from tools.port_scanner import PortScanner
from tools.ids import IntrusionDetectionSystem
from tools.spyware_detector import SpywareDetector
from tools.ransomware_detector import RansomwareDetector
from tools.phishing_detector import PhishingDetector
from tools.ddos_detector import DDoSDetector
from tools.network_monitor import NetworkMonitor
print('All modules OK')
" && echo -e "${GREEN}[✓] All modules import successfully${NC}"

echo ""
echo -e "${GREEN}╔══════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║  NetRecon v3.0 installed successfully!                   ║${NC}"
echo -e "${GREEN}╚══════════════════════════════════════════════════════════╝${NC}"
echo ""
echo -e "  Activate env:  ${CYAN}source venv/bin/activate${NC}"
echo -e "  Quick start:   ${CYAN}python main.py --help${NC}"
echo -e "  Port scan:     ${CYAN}python main.py --scan-ports 192.168.1.1 -p 1-1024${NC}"
echo -e "  IDS mode:      ${CYAN}sudo python main.py --ids --interface eth0${NC}"
echo -e "  Monitor:       ${CYAN}sudo python main.py --monitor --interface eth0${NC}"
echo -e "  Full audit:    ${CYAN}sudo python main.py --full-audit TARGET -o report.html${NC}"
echo ""
echo -e "${RED}  ⚠  Use only on systems you own or have permission to test${NC}"
echo ""

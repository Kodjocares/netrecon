```
 ███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
```

<div align="center">

**Advanced Network Intelligence & Security Suite**

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Version](https://img.shields.io/badge/Version-3.0.0-cyan?style=flat-square)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

> ⚠️ **For authorized security testing only.** Use only on systems you own or have explicit written permission to test.

</div>

---

## What is NetRecon?

NetRecon is a modular, Python-based network security suite that brings together **11 detection and analysis modules** in a single CLI tool. From port scanning to ransomware detection, it covers the full spectrum of network security monitoring.

---

## Modules

| # | Module | Flag | Description |
|---|--------|------|-------------|
| 1 | **Port Scanner** | `--scan-ports` | TCP/UDP/SYN/FIN scan, OS fingerprint, banner grabbing, risk classification |
| 2 | **Packet Sniffer** | `--sniff IFACE` | Deep packet inspection, credential detection, protocol analysis |
| 3 | **Web Vuln Scanner** | `--vuln-scan` | SQLi, XSS, LFI, SSRF, security headers, SSL/TLS audit |
| 4 | **Network Recon** | `--recon` | DNS enum, WHOIS, subdomain discovery, ARP scan, traceroute |
| 5 | **Threat Detector** | `--detect-threats` | Behavioral anomaly detection, MITRE ATT&CK mapping, auto-blocking |
| 6 | **IDS** | `--ids` | 50+ attack signatures: exploits, scans, C2, brute force, lateral movement |
| 7 | **Spyware Detector** | `--detect-spyware` | RAT, stalkerware, keylogger, beaconing pattern detection |
| 8 | **Ransomware Detector** | `--detect-ransom` | C2 comms, SMB staging, lateral movement, double-extortion exfil |
| 9 | **Phishing Detector** | `--detect-phishing` | Typosquatting, homograph attacks, credential harvest, SMTP phishing |
| 10 | **DDoS Detector** | `--detect-ddos` | SYN/UDP/ICMP flood, amplification (DNS/NTP/Memcached), Slowloris |
| 11 | **Network Monitor** | `--monitor` | Real-time flow tracking, protocol breakdown, anomaly detection dashboard |

---

## Project Structure

```
netrecon/
│
├── main.py                        # CLI entry point — all flags, module routing
│
├── core/
│   ├── __init__.py
│   └── banner.py                  # ASCII banner & startup display
│
├── tools/                         # One file per module
│   ├── __init__.py
│   ├── port_scanner.py            # Multi-threaded TCP/UDP/SYN scanner
│   ├── packet_sniffer.py          # Scapy-based deep packet capture
│   ├── vuln_scanner.py            # Async web vulnerability scanner
│   ├── network_recon.py           # DNS/WHOIS/ARP/traceroute recon
│   ├── threat_detector.py         # Behavioral threat detection engine
│   ├── ids.py                     # Intrusion Detection System (50+ sigs)
│   ├── spyware_detector.py        # Spyware, RAT & stalkerware detection
│   ├── ransomware_detector.py     # Ransomware detection engine
│   ├── phishing_detector.py       # Phishing & typosquatting detection
│   ├── ddos_detector.py           # Multi-vector DDoS detection
│   └── network_monitor.py         # Real-time network monitor & analysis
│
├── utils/
│   ├── __init__.py
│   ├── logger.py                  # Logging configuration
│   └── report.py                  # TXT/JSON/HTML/CSV report generation
│
├── rules/
│   └── custom_rules_example.json  # Custom IDS rule format example
│
├── tests/
│   ├── __init__.py
│   └── test_suite.py              # Full pytest test suite (40+ tests)
│
├── scripts/
│   └── install.sh                 # One-command installation script
│
├── .github/
│   ├── workflows/
│   │   └── ci.yml                 # GitHub Actions CI (lint + test matrix)
│   └── ISSUE_TEMPLATE/
│       ├── bug_report.yml
│       └── feature_request.yml
│
├── .gitignore
├── LICENSE                        # MIT License
├── SECURITY.md                    # Vulnerability reporting policy
├── CONTRIBUTING.md                # Contribution guidelines
├── requirements.txt               # Runtime dependencies
├── requirements-dev.txt           # Dev/test dependencies
├── pyproject.toml                 # pytest + black + mypy config
└── README.md                      # This file
```

---

## Installation

### Quick Install (Recommended)

```bash
git clone https://github.com/Kodjocares/netrecon.git
cd netrecon
bash scripts/install.sh
source venv/bin/activate
```

### Manual Install

```bash
# 1. Clone
git clone https://github.com/Kodjocares/netrecon.git
cd netrecon

# 2. Create virtual environment
python3 -m venv venv
source venv/bin/activate          # Linux/macOS
# venv\Scripts\activate           # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Verify
python main.py --help
```

### System Requirements

| Requirement | Minimum | Recommended |
|-------------|---------|-------------|
| Python | 3.10 | 3.11+ |
| OS | Linux / macOS | Kali Linux / Ubuntu 22.04 |
| Privileges | User | Root (for raw sockets) |
| RAM | 256 MB | 1 GB+ |
| Network | Any | Promiscuous-capable interface |

### Root / Sudo Requirements

Some features require elevated privileges:

```bash
# Features needing sudo:
sudo python main.py --sniff eth0           # Packet capture
sudo python main.py --ids --interface eth0  # IDS live mode
sudo python main.py --monitor --interface eth0  # Network monitor
sudo python main.py --scan-ports TARGET --scan-type syn  # SYN scan
sudo python main.py --detect-threats --block  # Auto-block via iptables
```

Features that work **without** root: `--scan-ports` (TCP connect), `--vuln-scan`, `--recon`, `--detect-ransom` (offline assessment), `--detect-phishing` (DNS/HTTP analysis).

---

## Usage

### 1. Port Scanner

```bash
# Basic TCP scan
python main.py --scan-ports 192.168.1.1 -p 1-1024

# Full scan with banner grabbing and OS detection
sudo python main.py --scan-ports 192.168.1.1 -p 1-65535 --banner --os-detect --threads 500

# UDP scan on common service ports
sudo python main.py --scan-ports 192.168.1.1 --scan-type udp -p 53,123,161,500,1900

# SYN stealth scan (root required)
sudo python main.py --scan-ports 192.168.1.1 --scan-type syn -p 1-1024

# Save as HTML report
python main.py --scan-ports 192.168.1.1 -p 1-1024 -o scan_report.html --format html
```

### 2. Intrusion Detection System

```bash
# Live IDS monitoring (recommended: root)
sudo python main.py --ids --interface eth0 --duration 300

# With custom rules + minimum high alert level
sudo python main.py --ids --interface eth0 --rules rules/custom_rules_example.json --alert-level high

# Save IDS alerts to JSON
sudo python main.py --ids --interface eth0 -o ids_alerts.json --format json
```

### 3. Spyware Detection

```bash
# Monitor for spyware/RAT beaconing
sudo python main.py --detect-spyware --interface eth0 --duration 120

# Extended monitoring with low alert threshold
sudo python main.py --detect-spyware --interface eth0 --duration 600 --alert-level low
```

### 4. Ransomware Detection

```bash
# Live ransomware monitoring
sudo python main.py --detect-ransom --interface eth0

# With auto-blocking of detected C2 IPs
sudo python main.py --detect-ransom --interface eth0 --block
```

### 5. Phishing Detection

```bash
# Monitor DNS queries and HTTP traffic for phishing
sudo python main.py --detect-phishing --interface eth0 --duration 180

# Save phishing report
sudo python main.py --detect-phishing --interface eth0 -o phishing.html --format html
```

### 6. DDoS Detection

```bash
# Live DDoS monitoring
sudo python main.py --detect-ddos --interface eth0 --duration 60

# With auto-blocking of flood sources
sudo python main.py --detect-ddos --interface eth0 --block --alert-level high
```

### 7. Network Monitor

```bash
# Real-time dashboard (default 60s)
sudo python main.py --monitor --interface eth0

# Extended monitoring with anomaly detection
sudo python main.py --monitor --interface eth0 --duration 600 --baseline 300

# Save flow analysis report
sudo python main.py --monitor --interface eth0 --duration 120 -o flows.json --format json
```

### 8. Web Vulnerability Scanner

```bash
# Full web audit
python main.py --vuln-scan https://target.example.com --all-vulns

# Targeted checks
python main.py --vuln-scan https://target.example.com --sqli --xss --headers --ssl

# Deep crawl with LFI testing
python main.py --vuln-scan https://target.example.com --lfi --crawl-depth 3

# Save HTML report
python main.py --vuln-scan https://target.example.com --all-vulns -o vuln_report.html --format html
```

### 9. Network Reconnaissance

```bash
# Full domain recon
python main.py --recon example.com

# Subnet discovery
sudo python main.py --recon 192.168.1.0/24 --arp-scan

# DNS + WHOIS focused
python main.py --recon example.com --dns --whois
```

### 10. Packet Sniffer

```bash
# Capture on interface
sudo python main.py --sniff eth0 --duration 60

# With BPF filter
sudo python main.py --sniff eth0 --filter "tcp port 80 or port 443" --duration 120

# Save to pcap file
sudo python main.py --sniff eth0 --pcap capture.pcap --duration 300
```

### 11. Full Audit (All Modules)

```bash
# Complete security audit — runs all 8 phases
sudo python main.py --full-audit 192.168.1.1 -o full_audit.html --format html

# Quiet mode with JSON output for automation
sudo python main.py --full-audit 192.168.1.1 -q -o audit.json --format json
```

---

## Output Formats

```bash
# Plain text (default — readable in terminal)
python main.py --scan-ports TARGET -o report.txt

# JSON (machine-readable — great for CI/CD, SIEM integration)
python main.py --scan-ports TARGET -o report.json --format json

# HTML (styled dark-mode report — best for sharing)
python main.py --scan-ports TARGET -o report.html --format html

# CSV (for spreadsheet analysis)
python main.py --scan-ports TARGET -o report.csv --format csv
```

---

## Custom IDS Rules

Create a `.json` file in the `rules/` directory:

```json
[
  {
    "id": "CUSTOM-001",
    "name": "Cryptocurrency Miner",
    "severity": "medium",
    "category": "Resource Abuse",
    "protocol": "TCP",
    "dst_port": null,
    "payload_pattern": "(?i)(stratum\\+tcp|xmrig|nicehash)",
    "flags": null,
    "description": "Crypto mining traffic detected",
    "mitre": "T1496"
  }
]
```

Run with: `python main.py --ids --rules rules/my_rules.json`

**Rule fields:**

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique rule identifier |
| `name` | string | Human-readable name |
| `severity` | string | `info` / `low` / `medium` / `high` / `critical` |
| `category` | string | Alert category label |
| `protocol` | string | `TCP` / `UDP` / `ICMP` / `null` (any) |
| `dst_port` | int / null | Destination port filter |
| `payload_pattern` | string / null | Python regex on packet payload |
| `flags` | string / null | TCP flags filter (`S`, `SA`, `FPU`, `""`) |
| `rate_threshold` | object / null | `{"connections": N, "window_sec": S}` |
| `mitre` | string | MITRE ATT&CK technique ID |

---

## Running Tests

```bash
# Install dev dependencies
pip install -r requirements-dev.txt

# Run full test suite
pytest tests/ -v

# Run with coverage report
pytest tests/ --cov=tools --cov-report=html

# Run specific module tests
pytest tests/ -k "TestIDS" -v
pytest tests/ -k "TestDDoS" -v
pytest tests/ -k "TestRansomware" -v
```

---

## MITRE ATT&CK Coverage

| Tactic | Technique | Module |
|--------|-----------|--------|
| Reconnaissance | T1046 Network Service Discovery | IDS, Port Scanner |
| Initial Access | T1190 Exploit Public-Facing App | IDS, Web Vuln Scanner |
| Execution | T1059 Command & Scripting | IDS, Web Vuln Scanner |
| Persistence | T1071 Application Layer Protocol | Spyware, Ransomware |
| Credential Access | T1110 Brute Force | IDS, Threat Detector |
| Discovery | T1018 Remote System Discovery | IDS, Network Recon |
| Lateral Movement | T1021 Remote Services | IDS, Ransomware |
| Collection | T1056 Input Capture | Spyware |
| Command & Control | T1071 C2 via App Protocol | All detection modules |
| Exfiltration | T1048 Exfiltration Over Alt Protocol | IDS, Spyware, Ransomware |
| Impact | T1486 Data Encrypted for Impact | Ransomware |
| Impact | T1498 Network Denial of Service | DDoS |

---

## Troubleshooting

### `Operation not permitted` / Permission errors
```bash
# Run with sudo for raw socket features
sudo python main.py --ids --interface eth0
```

### `No module named 'scapy'`
```bash
pip install scapy
# On some systems:
sudo pip install scapy
```

### Interface not found
```bash
# List available interfaces
ip link show          # Linux
ifconfig              # macOS
# Use the correct interface name: eth0, ens33, wlan0, en0, etc.
```

### `DNS resolution failed`
```bash
pip install dnspython
```

### Scapy warnings about libpcap
```bash
# Linux
sudo apt-get install libpcap-dev

# macOS
brew install libpcap
```

---

## Legal & Ethics

This tool is intended **exclusively** for:
- Penetration testing on systems you own
- Authorized security assessments with written permission
- Network monitoring of your own infrastructure
- Security research in isolated lab environments

**Unauthorized use is illegal.** Applicable laws include:
- 🇺🇸 Computer Fraud and Abuse Act (18 U.S.C. § 1030)
- 🇬🇧 Computer Misuse Act 1990
- 🇪🇺 Directive 2013/40/EU
- 🇦🇺 Criminal Code Act 1995

The authors accept **zero liability** for misuse.

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for:
- How to add new detection modules
- Custom IDS rule format
- Coding standards (black, flake8, mypy)
- Pull request checklist

---

## License

MIT — see [LICENSE](LICENSE) for details.

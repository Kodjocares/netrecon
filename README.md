# ⬡ NetRecon — Advanced Network Intelligence Suite

> **For authorized security testing only.** Unauthorized scanning is illegal. Use only on systems you own or have explicit written permission to test.

---

## Overview

NetRecon is a modular Python-based network security toolkit combining five key capabilities into one unified CLI:

| Module | Capability |
|---|---|
| **Port Scanner** | TCP/UDP/SYN scanning, banner grabbing, OS fingerprinting, risk classification |
| **Packet Sniffer** | Deep packet inspection, protocol analysis, credential detection, threat signatures |
| **Web Vuln Scanner** | SQLi, XSS, LFI, SSRF, security headers, SSL/TLS audit |
| **Network Recon** | DNS enum, WHOIS, subdomain discovery, ARP scan, traceroute |
| **Threat Detector** | Real-time anomaly detection, MITRE ATT&CK mapping, auto-blocking |

---

## Requirements

- Python 3.10+
- Linux/macOS (root recommended for raw socket features)
- Network access to target

## Installation

```bash
# Clone and install
git clone https://github.com/yourorg/netrecon.git
cd netrecon

# Create virtual environment (recommended)
python3 -m venv venv
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt

# Optional: install as CLI tool
pip install -e .
```

---

## Usage

### Port Scanner

```bash
# TCP scan common ports
python main.py --scan-ports 192.168.1.1 -p 1-1024

# Full port range with banner grabbing + OS detection
python main.py --scan-ports 192.168.1.1 -p 1-65535 --banner --os-detect --threads 200

# UDP scan
python main.py --scan-ports 192.168.1.1 --scan-type udp -p 53,161,123,500

# Save report
python main.py --scan-ports 192.168.1.1 -p 1-1024 -o report.html --format html
```

### Packet Sniffer

```bash
# Capture on eth0 for 60 seconds
python main.py --sniff eth0 --duration 60

# With BPF filter + save to pcap
python main.py --sniff eth0 --duration 120 --filter "tcp port 80 or port 443" --pcap capture.pcap

# Capture and analyze traffic patterns
python main.py --sniff eth0 --duration 30 --analyze
```

### Web Vulnerability Scanner

```bash
# Full vulnerability scan
python main.py --vuln-scan https://target.example.com --all-vulns

# Specific checks only
python main.py --vuln-scan https://target.example.com --sqli --xss --headers --ssl

# Deep crawl + LFI testing
python main.py --vuln-scan https://target.example.com --lfi --crawl-depth 3
```

### Network Reconnaissance

```bash
# Full recon on domain
python main.py --recon example.com

# CIDR subnet discovery
python main.py --recon 192.168.1.0/24 --arp-scan

# DNS-focused recon
python main.py --recon example.com --dns --whois
```

### Threat Detection

```bash
# Live monitoring
python main.py --detect-threats --interface eth0 --alert-level high

# With auto-blocking (root required)
sudo python main.py --detect-threats --interface eth0 --block --alert-level medium
```

### Full Audit

```bash
# Complete audit: port scan + recon + vuln scan + traffic + threat assessment
python main.py --full-audit 192.168.1.1 -o full_audit.html --format html
```

---

## Output Formats

```bash
# Text (default)
-o report.txt --format txt

# JSON (machine-readable, great for CI/CD pipelines)
-o report.json --format json

# HTML (styled dark-mode report)
-o report.html --format html

# CSV (for spreadsheet import)
-o report.csv --format csv
```

---

## Architecture

```
netrecon/
├── main.py                 # CLI entrypoint & orchestration
├── core/
│   ├── __init__.py
│   └── banner.py           # Startup display
├── tools/
│   ├── __init__.py
│   ├── port_scanner.py     # Multi-threaded port scanner
│   ├── packet_sniffer.py   # Scapy-based packet capture
│   ├── vuln_scanner.py     # Web vulnerability scanner
│   ├── network_recon.py    # DNS/WHOIS/ARP/traceroute
│   └── threat_detector.py  # Threat detection engine
├── utils/
│   ├── __init__.py
│   ├── logger.py           # Logging setup
│   └── report.py           # Multi-format report generation
├── requirements.txt
├── setup.py
└── README.md
```

---

## Features In Detail

### Port Scanner
- **TCP Connect scan** — Reliable open port detection (no root needed)
- **SYN scan** — Half-open stealth scan (root required)
- **UDP scan** — UDP port probing
- **Banner grabbing** — Service version fingerprinting via response headers
- **OS fingerprinting** — TTL-based OS detection
- **Risk classification** — Ports classified as low/medium/high/critical with remediation notes
- **Concurrent scanning** — Configurable thread pool (default: 100 threads)

### Packet Sniffer
- **Protocol dissection** — TCP, UDP, ICMP, DNS, HTTP
- **Credential detection** — Flags cleartext passwords in HTTP traffic
- **Threat signatures** — SQLi, XSS, shell injection patterns in payloads
- **Behavioral analysis** — SYN flood, port scan, DNS flood detection
- **DNS monitoring** — Query logging and exfiltration pattern detection
- **Traffic statistics** — Top talkers, protocol breakdown, live dashboard
- **PCAP export** — Save captures for offline analysis in Wireshark

### Web Vulnerability Scanner
- **SQLi** — Error-based and time-based detection
- **Reflected XSS** — Payload reflection testing across all parameters
- **LFI/Path Traversal** — File inclusion testing on path parameters
- **SSRF** — Server-side request forgery probes
- **Security Headers** — CSP, HSTS, X-Frame-Options, cookie flags
- **SSL/TLS Audit** — Protocol version, cipher suite, certificate validity
- **Web Crawler** — Configurable-depth link and form discovery

### Network Recon
- **DNS Enumeration** — All record types (A, MX, NS, TXT, SOA, SRV, CAA, etc.)
- **Subdomain Discovery** — Wordlist-based enumeration of 50+ common subdomains
- **WHOIS** — Registrar, dates, nameservers, organization data
- **ARP Scan** — Local LAN host discovery with MAC addresses
- **Ping Sweep** — ICMP-based subnet host discovery fallback
- **Traceroute** — Network path mapping with latency

### Threat Detector
- **Port scan detection** — >20 unique ports/min triggers alert
- **Brute force detection** — SSH/RDP/SMB connection rate thresholds
- **Data exfiltration** — Large outbound transfer alerts (>50 MB)
- **DNS exfiltration** — Long hex subdomain pattern matching
- **ICMP sweep detection** — Ping sweep activity
- **Known bad IPs** — Threat intelligence IP blocklist matching
- **MITRE ATT&CK mapping** — Every alert tagged with technique ID
- **Auto-blocking** — Optional iptables rule injection (root required)
- **Threat scoring** — 0–100 risk score with severity weighting

---

## Extending NetRecon

### Adding Custom Threat Rules

```python
# In tools/threat_detector.py, add to THREAT_SIGNATURES:
"my_custom_rule": {
    "description": "Custom detection logic",
    "severity": "high",
    "threshold": 10,
}
```

### Adding Custom Vuln Payloads

```python
# In tools/vuln_scanner.py, extend the payload lists:
SQLI_PAYLOADS.append("your_custom_payload")
```

### Integrating Threat Intel Feeds

```python
# In tools/threat_detector.py, replace static sets with dynamic loading:
import requests

def load_threat_intel():
    # Example: AlienVault OTX
    resp = requests.get("https://otx.alienvault.com/api/v1/indicators/...")
    return set(resp.json().get("results", []))

KNOWN_BAD_IPS = load_threat_intel()
```

---

## Legal & Ethics

- **Only scan systems you own or have explicit written authorization to test**
- Unauthorized port scanning may violate the Computer Fraud and Abuse Act (US), Computer Misuse Act (UK), and similar laws worldwide
- This tool is provided for educational and authorized security testing purposes only
- The authors assume no liability for misuse

---

## License

MIT License — See LICENSE file for details.

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

TAGLINE = "Advanced Network Intelligence & Security Suite"
VERSION = "4.0.0"
MODULES = [
    ("Port Scanner",        "TCP/UDP/SYN scan, OS detection, banner grabbing"),
    ("Packet Sniffer",      "Deep packet inspection & protocol analysis"),
    ("Web Vuln Scanner",    "SQLi, XSS, LFI, SSRF, header & SSL auditing"),
    ("Network Recon",       "DNS enum, WHOIS, ARP scan, traceroute mapping"),
    ("Threat Detector",     "Real-time anomaly detection & threat intelligence"),
    ("IDS",                 "50+ attack signatures — exploits, scans, C2, brute force"),
    ("Spyware Detector",    "RAT, stalkerware, keylogger & beacon detection"),
    ("Ransomware Detector", "C2, lateral movement, staging & exfil detection"),
    ("Phishing Detector",   "Typosquatting, homograph, credential harvest detection"),
    ("DDoS Detector",       "SYN/UDP/ICMP flood, amplification, Slowloris, botnet"),
    ("Network Monitor",     "Real-time flow analysis, protocol breakdown, anomalies"),
    ("CVE Scanner",         "Map services to NVD CVEs + exploitability scores"),
    ("Malware Scanner",     "Hash file transfers vs VirusTotal + MalwareBazaar"),
    ("Honeypot",            "Deploy decoy services — zero false positives"),
    ("REST API Server",     "HTTP API for CI/CD integration & remote triggering"),
    ("Scheduled Scanner",   "Cron-style scans with diff-based email/Slack alerts"),
    ("PDF Reports",         "Professional pentest reports with remediation guidance"),
    ("Full Audit",          "All 17 modules — complete security assessment"),
]

ASCII_LOGO = """
 ███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
 ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
 ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
 ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
 ██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
 ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
"""

def print_banner():
    console.print(f"[bold cyan]{ASCII_LOGO}[/bold cyan]")
    console.print(f"  [bold cyan]{TAGLINE}[/bold cyan]  [dim]v{VERSION}[/dim]")
    console.print(f"  [dim]18 modules · 50+ IDS signatures · CVE database · REST API[/dim]\n")
    console.print(f"  [bold red]⚠  For authorized security testing only[/bold red]\n")
    console.print("  [dim]Modules:[/dim]")
    for i, (name, desc) in enumerate(MODULES):
        col = "cyan" if i % 3 == 0 else "green" if i % 3 == 1 else "yellow"
        console.print(f"    [{col}]•[/{col}] [white]{name:<22}[/white] [dim]{desc}[/dim]")
    console.print()

"""
Threat Detection Engine — Real-time anomaly detection, threat intelligence correlation,
behavioral analysis, and automated alerting.
"""

import asyncio
import time
import json
import re
import ipaddress
import collections
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Callable
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

# ─── Known bad indicators ─────────────────────────────────────────────────────
# (In production, load from threat intel feeds: AlienVault OTX, VirusTotal, etc.)
KNOWN_BAD_IPS: Set[str] = {
    "192.0.2.100",   # Example: known C2 server
    "198.51.100.50", # Example: Tor exit node
    "203.0.113.200", # Example: scanner IP
}

KNOWN_BAD_DOMAINS: Set[str] = {
    "malware.test",
    "phishing.example",
    "c2.evil.test",
}

# Port-based threat signatures
THREAT_SIGNATURES = {
    "port_scan": {
        "description": "Rapid port scanning detected",
        "severity": "high",
        "threshold": 20,   # unique ports per IP per minute
    },
    "ssh_brute": {
        "description": "SSH brute force attempt",
        "severity": "high",
        "port": 22,
        "threshold": 10,   # connections per minute
    },
    "rdp_attack": {
        "description": "RDP brute force / BlueKeep probe",
        "severity": "critical",
        "port": 3389,
        "threshold": 5,
    },
    "smb_attack": {
        "description": "SMB/EternalBlue probe",
        "severity": "critical",
        "port": 445,
        "threshold": 5,
    },
    "dns_exfil": {
        "description": "Potential DNS data exfiltration",
        "severity": "high",
        "pattern": r"[a-f0-9]{20,}\.",   # long hex subdomains
    },
    "c2_beacon": {
        "description": "Periodic C2 beacon pattern detected",
        "severity": "critical",
        "interval_variance": 5.0,   # seconds
    },
    "data_exfil": {
        "description": "Large outbound data transfer",
        "severity": "high",
        "bytes_threshold": 50 * 1024 * 1024,  # 50 MB
    },
    "icmp_sweep": {
        "description": "ICMP ping sweep / network scan",
        "severity": "medium",
        "threshold": 30,  # ICMP per minute from one IP
    },
}


@dataclass
class ThreatAlert:
    alert_id: str
    threat_type: str
    severity: str   # info / low / medium / high / critical
    source_ip: str
    destination: str
    description: str
    timestamp: float
    evidence: str = ""
    mitre_attack: str = ""   # MITRE ATT&CK technique
    blocked: bool = False

    def age(self) -> str:
        delta = time.time() - self.timestamp
        if delta < 60:
            return f"{delta:.0f}s ago"
        elif delta < 3600:
            return f"{delta/60:.0f}m ago"
        return f"{delta/3600:.1f}h ago"


@dataclass
class ThreatResults:
    start_time: float
    end_time: float = 0.0
    alerts: List[ThreatAlert] = field(default_factory=list)
    total_analyzed: int = 0
    blocked_ips: Set[str] = field(default_factory=set)
    threat_score: int = 0   # 0-100

    def by_severity(self, severity: str) -> List[ThreatAlert]:
        return [a for a in self.alerts if a.severity == severity]

    def critical_count(self) -> int:
        return len(self.by_severity("critical")) + len(self.by_severity("high"))


# MITRE ATT&CK technique mappings
MITRE_MAP = {
    "port_scan":   "T1046 — Network Service Discovery",
    "ssh_brute":   "T1110 — Brute Force",
    "rdp_attack":  "T1110.001 — Password Guessing",
    "smb_attack":  "T1021.002 — SMB/Windows Admin Shares",
    "dns_exfil":   "T1048.003 — DNS Exfiltration",
    "c2_beacon":   "T1071 — Application Layer Protocol C2",
    "data_exfil":  "T1030 — Data Transfer Size Limits",
    "icmp_sweep":  "T1018 — Remote System Discovery",
}


class ThreatDetector:
    """
    Real-time threat detection engine with behavioral analysis and threat intelligence.
    """

    def __init__(self, args):
        self.args = args
        self.results = ThreatResults(start_time=time.time())
        self._alert_counter = 0
        self._connection_tracker: Dict[str, List[float]] = collections.defaultdict(list)
        self._port_tracker: Dict[str, Set[int]] = collections.defaultdict(set)
        self._byte_tracker: Dict[str, int] = collections.defaultdict(int)
        self._icmp_tracker: Dict[str, List[float]] = collections.defaultdict(list)
        self._dns_subdomain_tracker: Dict[str, List[str]] = collections.defaultdict(list)
        self._callbacks: List[Callable] = []

    def _new_alert_id(self) -> str:
        self._alert_counter += 1
        return f"TID-{self._alert_counter:04d}"

    def _alert(self, threat_type: str, severity: str, src_ip: str, dst: str,
               description: str, evidence: str = "") -> ThreatAlert:
        """Create and record a new threat alert."""
        alert = ThreatAlert(
            alert_id=self._new_alert_id(),
            threat_type=threat_type,
            severity=severity,
            source_ip=src_ip,
            destination=dst,
            description=description,
            timestamp=time.time(),
            evidence=evidence,
            mitre_attack=MITRE_MAP.get(threat_type, ""),
        )

        # Auto-block if enabled and severity is critical/high
        if (hasattr(self.args, "block") and self.args.block and
                severity in ("critical", "high") and src_ip not in self.results.blocked_ips):
            self._block_ip(src_ip)
            alert.blocked = True

        self.results.alerts.append(alert)
        self._update_threat_score(severity)

        # Display immediate alert
        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}
        color = sev_colors.get(severity, "white")
        blocked_tag = " [bold green][BLOCKED][/bold green]" if alert.blocked else ""
        console.print(
            f"  [{color}]⚠ [{alert.alert_id}] {severity.upper()}[/{color}]{blocked_tag} — "
            f"[white]{description}[/white] [dim]({src_ip} → {dst})[/dim]"
        )

        return alert

    def _block_ip(self, ip: str):
        """Block IP using iptables (Linux, requires root)."""
        import subprocess
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True, capture_output=True
            )
            self.results.blocked_ips.add(ip)
            console.print(f"  [bold green]✓ Blocked:[/bold green] {ip} via iptables")
        except Exception as e:
            console.print(f"  [yellow]⚠ Could not block {ip}: {e}[/yellow]")

    def _update_threat_score(self, severity: str):
        """Increment threat score based on severity."""
        weights = {"info": 0, "low": 1, "medium": 5, "high": 15, "critical": 30}
        self.results.threat_score = min(100, self.results.threat_score + weights.get(severity, 0))

    def analyze_packet(self, src_ip: str, dst_ip: str, dst_port: int,
                       protocol: str, payload: bytes = b"", packet_len: int = 0):
        """
        Analyze a single packet/connection event and trigger alerts if needed.
        Called by the packet sniffer or other modules.
        """
        now = time.time()
        self.results.total_analyzed += 1

        # 1. Known bad IP check
        if src_ip in KNOWN_BAD_IPS:
            self._alert("threat_intel", "critical", src_ip, dst_ip,
                        "Connection from known malicious IP",
                        f"IP {src_ip} is in threat intelligence blocklist")

        # 2. Port scan detection
        self._port_tracker[src_ip].add(dst_port)
        self._connection_tracker[src_ip].append(now)
        # Clean old entries
        self._connection_tracker[src_ip] = [t for t in self._connection_tracker[src_ip] if now - t < 60]
        if len(self._port_tracker[src_ip]) > THREAT_SIGNATURES["port_scan"]["threshold"]:
            if not any(a.source_ip == src_ip and a.threat_type == "port_scan" for a in self.results.alerts[-10:]):
                self._alert("port_scan", "high", src_ip, dst_ip,
                            THREAT_SIGNATURES["port_scan"]["description"],
                            f"Scanned {len(self._port_tracker[src_ip])} unique ports")
            self._port_tracker[src_ip] = set()  # Reset after alert

        # 3. Brute force detection (SSH/RDP/SMB)
        for service, config in [("ssh_brute", 22), ("rdp_attack", 3389), ("smb_attack", 445)]:
            if dst_port == config:
                recent = [t for t in self._connection_tracker[src_ip] if now - t < 60]
                if len(recent) >= THREAT_SIGNATURES[service]["threshold"]:
                    if not any(a.source_ip == src_ip and a.threat_type == service for a in self.results.alerts[-5:]):
                        self._alert(service, THREAT_SIGNATURES[service]["severity"],
                                    src_ip, f"{dst_ip}:{dst_port}",
                                    THREAT_SIGNATURES[service]["description"],
                                    f"{len(recent)} attempts in last 60s")

        # 4. ICMP sweep
        if protocol == "ICMP":
            self._icmp_tracker[src_ip].append(now)
            self._icmp_tracker[src_ip] = [t for t in self._icmp_tracker[src_ip] if now - t < 60]
            if len(self._icmp_tracker[src_ip]) >= THREAT_SIGNATURES["icmp_sweep"]["threshold"]:
                if not any(a.source_ip == src_ip and a.threat_type == "icmp_sweep" for a in self.results.alerts[-5:]):
                    self._alert("icmp_sweep", "medium", src_ip, dst_ip,
                                THREAT_SIGNATURES["icmp_sweep"]["description"],
                                f"{len(self._icmp_tracker[src_ip])} ICMP packets in 60s")

        # 5. Data exfiltration (large outbound)
        self._byte_tracker[src_ip] += packet_len
        if self._byte_tracker[src_ip] > THREAT_SIGNATURES["data_exfil"]["bytes_threshold"]:
            if not any(a.source_ip == src_ip and a.threat_type == "data_exfil" for a in self.results.alerts[-3:]):
                mb = self._byte_tracker[src_ip] / 1024 / 1024
                self._alert("data_exfil", "high", src_ip, dst_ip,
                            THREAT_SIGNATURES["data_exfil"]["description"],
                            f"{mb:.1f} MB sent from {src_ip}")
            self._byte_tracker[src_ip] = 0

        # 6. DNS exfiltration pattern
        if protocol == "DNS" and dst_port == 53 and payload:
            payload_str = payload.decode("utf-8", errors="ignore")
            if re.search(THREAT_SIGNATURES["dns_exfil"]["pattern"], payload_str):
                self._alert("dns_exfil", "high", src_ip, dst_ip,
                            THREAT_SIGNATURES["dns_exfil"]["description"],
                            f"Suspicious subdomain pattern: {payload_str[:50]}")

    async def run_assessment(self, scan_data: Dict) -> None:
        """
        Run threat assessment on aggregated scan results from other modules.
        """
        console.print(f"\n[bold cyan]Threat Assessment[/bold cyan]\n")

        # Analyze port scan results
        if "open_ports" in scan_data:
            for port_info in scan_data.get("open_ports", []):
                if port_info.get("risk") in ("high", "critical"):
                    self._alert(
                        "exposed_service",
                        port_info["risk"],
                        scan_data.get("ip", "target"),
                        f"port {port_info['port']}",
                        f"High-risk service exposed: {port_info.get('service','?')} on port {port_info['port']}",
                        "; ".join(port_info.get("notes", []))
                    )

        # Analyze web vulnerabilities
        for vuln in scan_data.get("vulnerabilities", []):
            if vuln.get("severity") in ("critical", "high"):
                self._alert(
                    "web_vuln",
                    vuln["severity"],
                    "web_scanner",
                    vuln.get("url", ""),
                    vuln.get("vuln_type", "Web Vulnerability"),
                    vuln.get("evidence", "")
                )

        self.results.end_time = time.time()
        self._print_assessment()

    async def run_live(self):
        """Live threat monitoring mode (reads from network interface)."""
        console.print(f"\n[bold cyan]Live Threat Detection[/bold cyan] → Interface: [white]{self.args.interface}[/white]")
        console.print(f"  Alert level: [cyan]{self.args.alert_level}[/cyan] | "
                      f"Auto-block: [{'red]ENABLED' if getattr(self.args, 'block', False) else 'dim]disabled'}[/]\n")

        try:
            import scapy.all as scapy
            from scapy.layers.inet import IP, TCP, UDP, ICMP

            def pkt_handler(pkt):
                if not pkt.haslayer(IP):
                    return
                ip = pkt[IP]
                proto = "OTHER"
                dst_port = 0

                if pkt.haslayer(TCP):
                    proto = "TCP"
                    dst_port = pkt[TCP].dport
                elif pkt.haslayer(UDP):
                    proto = "UDP"
                    dst_port = pkt[UDP].dport
                elif pkt.haslayer(ICMP):
                    proto = "ICMP"

                payload = bytes(pkt.payload.payload) if hasattr(pkt.payload, "payload") else b""
                self.analyze_packet(ip.src, ip.dst, dst_port, proto, payload, len(pkt))

            console.print("[dim]Monitoring traffic... Press Ctrl+C to stop.[/dim]\n")
            scapy.sniff(iface=self.args.interface, prn=pkt_handler, store=False)

        except ImportError:
            console.print("[yellow]⚠ Scapy not available. Cannot run live capture.[/yellow]")
        except KeyboardInterrupt:
            pass
        finally:
            self.results.end_time = time.time()
            self._print_assessment()

    def _print_assessment(self):
        """Display threat assessment results."""
        console.print()
        r = self.results

        if not r.alerts:
            console.print("[green]✓ No threats detected.[/green]")
            return

        # Threat score gauge
        score = r.threat_score
        if score >= 70:
            score_color = "bold red"
            score_label = "CRITICAL"
        elif score >= 40:
            score_color = "red"
            score_label = "HIGH"
        elif score >= 20:
            score_color = "yellow"
            score_label = "MEDIUM"
        else:
            score_color = "cyan"
            score_label = "LOW"

        console.print(f"  Threat Score: [{score_color}]{score}/100 ({score_label})[/{score_color}]")

        table = Table(
            title=f"Threat Alerts ({len(r.alerts)})",
            box=box.ROUNDED,
            border_style="red",
            show_lines=True,
        )
        table.add_column("ID", style="dim", width=9)
        table.add_column("Severity", width=12)
        table.add_column("Type", style="white", min_width=20)
        table.add_column("Source", style="cyan")
        table.add_column("MITRE ATT&CK", style="dim", min_width=25)
        table.add_column("Evidence", style="dim", max_width=35)

        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan", "info": "dim"}

        for alert in sorted(r.alerts, key=lambda a: ["critical","high","medium","low","info"].index(a.severity)):
            color = sev_colors.get(alert.severity, "white")
            blocked = " [green][B][/green]" if alert.blocked else ""
            table.add_row(
                alert.alert_id,
                f"[{color}]{alert.severity.upper()}[/{color}]{blocked}",
                alert.threat_type,
                alert.source_ip,
                alert.mitre_attack or "—",
                alert.evidence[:50] if alert.evidence else "—",
            )

        console.print(table)

        if r.blocked_ips:
            console.print(f"\n  [bold green]Auto-blocked IPs:[/bold green] {', '.join(r.blocked_ips)}")

        console.print(
            f"\n  {len(r.alerts)} alerts | "
            f"[red]{r.critical_count()} critical/high[/red] | "
            f"Threat score: [{score_color}]{score}/100[/{score_color}]"
        )

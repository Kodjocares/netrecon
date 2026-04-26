"""
Ransomware Detection Module — Identifies ransomware infection, lateral movement,
C2 communication, encryption staging, and data exfiltration-before-encryption patterns.
Combines network behavioral analysis with SMB/RDP monitoring.
"""

import asyncio
import re
import time
import collections
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# ─── Known ransomware C2 indicators ──────────────────────────────────────────
RANSOMWARE_C2_DOMAINS: Set[str] = {
    # Representative examples (real feeds would be from URLhaus, CISA advisories, etc.)
    "ransomware-c2.test",
    "pay.lockbit.onion.ws",
    "decrypt.conti.io",
    "files.revil.biz",
    "panel.blackcat.xyz",
    "api.clop.net",
}

RANSOMWARE_C2_IPS: Set[str] = {
    "192.0.2.201",
    "198.51.100.201",
}

# Ransomware family signatures in network traffic
RANSOMWARE_PAYLOAD_PATTERNS: List[Tuple[bytes, str, str]] = [
    # (pattern, family, description)
    (rb"(?i)your files have been encrypted", "Generic", "Ransom note string in network traffic"),
    (rb"(?i)bitcoin.*wallet|wallet.*bitcoin", "Generic", "Bitcoin payment instruction detected"),
    (rb"(?i)\.onion.*decypt|decrypt.*\.onion", "Generic", "Tor payment site reference"),
    (rb"LockBit\s*[\d\.]+", "LockBit", "LockBit ransomware identifier"),
    (rb"CONTI_NEWS", "Conti", "Conti ransomware communication"),
    (rb"BlackCat|ALPHV", "BlackCat/ALPHV", "BlackCat/ALPHV ransomware marker"),
    (rb"CLOP\^_", "Clop", "Clop ransomware signature"),
    (rb"REvil|Sodinokibi", "REvil", "REvil/Sodinokibi ransomware"),
    (rb"WannaCry|WNCRY", "WannaCry", "WannaCry ransomware pattern"),
    (rb"ryuk.*ransom|ransom.*ryuk", "Ryuk", "Ryuk ransomware indicator"),
]

# Behavioral indicators
SMB_ENCRYPTION_PATTERNS = [
    (rb"\.encrypted$|\.locked$|\.enc$|\.crypted$", "Encrypted file extension in SMB write"),
    (rb"RECOVER.*FILES|HOW.*DECRYPT|README.*RANSOM", "Ransom note filename pattern"),
    (rb"!+DECRYPT|HELP_DECRYPT|_HELP_instructions", "Ransom note creation pattern"),
]

# Ports used for ransomware lateral movement
RANSOMWARE_LATERAL_PORTS = {
    445: "SMB — EternalBlue/file encryption spread",
    3389: "RDP — credential-based lateral movement",
    135: "WMI — remote execution",
    5985: "WinRM — remote PowerShell",
    22: "SSH — Linux ransomware spread",
    5900: "VNC — remote access abuse",
}

# Encryption staging behavior thresholds
SMB_WRITE_THRESHOLD = 50        # SMB write ops per minute (staging)
UNIQUE_HOSTS_THRESHOLD = 15     # Unique hosts contacted per minute (spreading)
DNS_LOOKUP_THRESHOLD = 30       # DNS lookups per minute (reconnaissance)


@dataclass
class RansomwareIndicator:
    indicator_type: str   # "c2", "payload_sig", "lateral_movement", "encryption_staging",
                          # "exfil_before_encrypt", "ransom_note", "spreading"
    severity: str
    family: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    description: str
    evidence: str
    timestamp: float
    mitre: str = ""


@dataclass
class RansomwareResults:
    start_time: float
    end_time: float = 0.0
    indicators: List[RansomwareIndicator] = field(default_factory=list)
    packets_analyzed: int = 0
    affected_hosts: Set[str] = field(default_factory=set)
    c2_endpoints: List[str] = field(default_factory=list)
    infection_timeline: List[Tuple[float, str]] = field(default_factory=list)
    risk_level: str = "none"  # none / low / medium / high / critical

    def critical_count(self) -> int:
        return sum(1 for i in self.indicators if i.severity in ("critical", "high"))

    def update_risk(self):
        crit = self.critical_count()
        if crit >= 3:
            self.risk_level = "critical"
        elif crit >= 1:
            self.risk_level = "high"
        elif len(self.indicators) > 0:
            self.risk_level = "medium"
        else:
            self.risk_level = "none"


class RansomwareDetector:
    """
    Ransomware detection engine monitoring for:
    - Known C2 communication (domain/IP blacklists)
    - Payload signatures (ransom notes, family identifiers)
    - Lateral movement via SMB/RDP/WMI
    - Encryption staging behavior (mass SMB writes)
    - Pre-encryption data exfiltration
    - Network-level spreading patterns
    """

    def __init__(self, args):
        self.args = args
        self.results = RansomwareResults(start_time=time.time())
        self._smb_write_tracker: Dict[str, List[float]] = collections.defaultdict(list)
        self._host_contact_tracker: Dict[str, Set[str]] = collections.defaultdict(set)
        self._dns_tracker: Dict[str, List[float]] = collections.defaultdict(list)
        self._outbound_bytes: Dict[str, int] = collections.defaultdict(int)
        self._lateral_attempts: Dict[str, Dict[int, int]] = collections.defaultdict(lambda: collections.defaultdict(int))
        self._alerted: Set[str] = set()
        self._compiled_patterns = []

        # Pre-compile patterns
        for pattern, family, desc in RANSOMWARE_PAYLOAD_PATTERNS:
            try:
                self._compiled_patterns.append(
                    (re.compile(pattern, re.IGNORECASE | re.DOTALL), family, desc)
                )
            except re.error:
                pass

    def _add_indicator(self, ind_type: str, severity: str, family: str,
                       src_ip: str, dst_ip: str, dst_port: int, protocol: str,
                       description: str, evidence: str, mitre: str = "") -> Optional[RansomwareIndicator]:
        dedup_key = f"{ind_type}:{src_ip}:{dst_ip}:{dst_port}:{family}"
        if dedup_key in self._alerted:
            return None
        self._alerted.add(dedup_key)

        ind = RansomwareIndicator(
            indicator_type=ind_type,
            severity=severity,
            family=family,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            description=description,
            evidence=evidence,
            timestamp=time.time(),
            mitre=mitre,
        )
        self.results.indicators.append(ind)
        self.results.affected_hosts.add(src_ip)
        self.results.infection_timeline.append((time.time(), description))
        self.results.update_risk()

        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}
        color = sev_colors.get(severity, "white")
        family_tag = f" [[cyan]{family}[/cyan]]" if family and family != "Generic" else ""
        console.print(
            f"  [{color}]☣ RANSOMWARE {severity.upper()}[/{color}]{family_tag} — "
            f"[white]{description}[/white] [dim]({src_ip})[/dim]"
        )
        return ind

    def analyze_packet(self, src_ip: str, dst_ip: str, dst_port: int,
                       protocol: str, payload: bytes = b"",
                       packet_len: int = 0, dns_query: str = ""):
        """Analyze packet for ransomware indicators."""
        self.results.packets_analyzed += 1
        now = time.time()

        # 1. Known C2 IP
        if dst_ip in RANSOMWARE_C2_IPS:
            self._add_indicator(
                "c2", "critical", "Unknown", src_ip, dst_ip, dst_port, protocol,
                "Connection to known ransomware C2 server",
                f"IP {dst_ip} is in ransomware C2 blocklist",
                mitre="T1071"
            )
            if dst_ip not in self.results.c2_endpoints:
                self.results.c2_endpoints.append(dst_ip)

        # 2. Known C2 domain
        if dns_query:
            for domain in RANSOMWARE_C2_DOMAINS:
                if domain in dns_query.lower():
                    self._add_indicator(
                        "c2", "critical", domain.split(".")[1].capitalize(),
                        src_ip, dns_query, 53, "DNS",
                        f"DNS query to known ransomware C2 domain",
                        f"Query: {dns_query}",
                        mitre="T1071.004"
                    )
            # Track DNS rate (ransomware often does recon via DNS)
            self._dns_tracker[src_ip].append(now)
            self._dns_tracker[src_ip] = [t for t in self._dns_tracker[src_ip] if now - t < 60]
            if len(self._dns_tracker[src_ip]) > DNS_LOOKUP_THRESHOLD:
                self._add_indicator(
                    "spreading", "high", "Unknown", src_ip, dst_ip, 53, "DNS",
                    "Unusually high DNS lookup rate — ransomware reconnaissance",
                    f"{len(self._dns_tracker[src_ip])} DNS queries in 60s",
                    mitre="T1018"
                )

        # 3. Payload signature matching
        if payload:
            for compiled_re, family, desc in self._compiled_patterns:
                if compiled_re.search(payload):
                    self._add_indicator(
                        "payload_sig", "critical", family,
                        src_ip, dst_ip, dst_port, protocol,
                        desc, payload[:80].decode("utf-8", errors="replace"),
                        mitre="T1486"
                    )
                    break

            # SMB encryption staging
            if dst_port == 445 and protocol == "TCP":
                for pattern, desc in SMB_ENCRYPTION_PATTERNS:
                    if re.search(pattern, payload, re.IGNORECASE):
                        self._add_indicator(
                            "encryption_staging", "critical", "Unknown",
                            src_ip, dst_ip, dst_port, protocol,
                            desc, payload[:60].decode("utf-8", errors="replace"),
                            mitre="T1486"
                        )
                        break

        # 4. Lateral movement port tracking
        if dst_port in RANSOMWARE_LATERAL_PORTS:
            self._lateral_attempts[src_ip][dst_port] += 1
            self._host_contact_tracker[src_ip].add(dst_ip)

            # Many unique hosts on lateral movement ports = spreading
            if len(self._host_contact_tracker[src_ip]) > UNIQUE_HOSTS_THRESHOLD:
                port_desc = RANSOMWARE_LATERAL_PORTS[dst_port]
                self._add_indicator(
                    "lateral_movement", "critical", "Unknown",
                    src_ip, dst_ip, dst_port, protocol,
                    f"Rapid lateral movement detected — {port_desc}",
                    f"Contacted {len(self._host_contact_tracker[src_ip])} unique hosts on port {dst_port}",
                    mitre="T1021.002" if dst_port == 445 else "T1021.001"
                )
                self._host_contact_tracker[src_ip] = set()  # Reset after alert

        # 5. SMB write rate tracking (mass file encryption staging)
        if dst_port == 445 and protocol == "TCP" and packet_len > 200:
            self._smb_write_tracker[src_ip].append(now)
            self._smb_write_tracker[src_ip] = [
                t for t in self._smb_write_tracker[src_ip] if now - t < 60
            ]
            if len(self._smb_write_tracker[src_ip]) > SMB_WRITE_THRESHOLD:
                self._add_indicator(
                    "encryption_staging", "critical", "Unknown",
                    src_ip, dst_ip, dst_port, protocol,
                    "Mass SMB write operations — possible file encryption in progress",
                    f"{len(self._smb_write_tracker[src_ip])} SMB writes in 60s",
                    mitre="T1486"
                )
                self._smb_write_tracker[src_ip] = []

        # 6. Large outbound transfers before encryption (double-extortion)
        self._outbound_bytes[src_ip] += packet_len
        if self._outbound_bytes[src_ip] > 100 * 1024 * 1024:  # 100MB
            self._add_indicator(
                "exfil_before_encrypt", "high", "Unknown",
                src_ip, dst_ip, dst_port, protocol,
                "Large outbound data transfer — possible pre-encryption exfiltration",
                f"{self._outbound_bytes[src_ip] / 1024 / 1024:.1f} MB sent from {src_ip}",
                mitre="T1041"
            )
            self._outbound_bytes[src_ip] = 0

    async def run(self):
        """Run ransomware detection on live traffic."""
        interface = getattr(self.args, "interface", "eth0")
        duration = getattr(self.args, "duration", 60)

        console.print(f"\n[bold cyan]Ransomware Detection Engine[/bold cyan]")
        console.print(
            f"  Interface: [white]{interface}[/white] | "
            f"Monitoring: [cyan]{duration}s[/cyan]\n"
        )
        console.print("[dim]Monitoring for ransomware C2, lateral movement, encryption staging...[/dim]\n")

        try:
            import scapy.all as scapy
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.dns import DNS, DNSQR

            def pkt_handler(pkt):
                if not pkt.haslayer(IP):
                    return
                ip = pkt[IP]
                proto, dst_port, payload, dns_q = "OTHER", 0, b"", ""
                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    proto, dst_port = "TCP", tcp.dport
                    payload = bytes(tcp.payload) if tcp.payload else b""
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    proto, dst_port = "UDP", udp.dport
                    payload = bytes(udp.payload) if udp.payload else b""
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    dns_q = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                self.analyze_packet(ip.src, ip.dst, dst_port, proto, payload, len(pkt), dns_q)

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, lambda: scapy.sniff(iface=interface, prn=pkt_handler, timeout=duration, store=False)
            )
        except ImportError:
            console.print("[yellow]⚠ Scapy not available — running in signature assessment mode.[/yellow]")

        self.results.end_time = time.time()
        self._print_results()

    def _print_results(self):
        """Print ransomware detection results."""
        console.print()
        r = self.results

        risk_colors = {"none": "green", "low": "cyan", "medium": "yellow",
                       "high": "red", "critical": "bold red"}
        risk_color = risk_colors.get(r.risk_level, "white")
        console.print(f"  Ransomware Risk Level: [{risk_color}]{r.risk_level.upper()}[/{risk_color}]")

        if not r.indicators:
            console.print("[green]✓ No ransomware activity detected.[/green]")
            return

        table = Table(
            title=f"Ransomware Indicators ({len(r.indicators)})",
            box=box.ROUNDED, border_style="red", show_lines=True
        )
        table.add_column("Type", style="cyan", width=18)
        table.add_column("Severity", width=11)
        table.add_column("Family", style="yellow", width=12)
        table.add_column("Source", style="white")
        table.add_column("Description", min_width=35)
        table.add_column("MITRE", style="dim", width=12)

        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}
        for ind in sorted(r.indicators, key=lambda x: x.timestamp):
            color = sev_colors.get(ind.severity, "white")
            table.add_row(
                ind.indicator_type,
                f"[{color}]{ind.severity.upper()}[/{color}]",
                ind.family or "—",
                ind.src_ip,
                ind.description[:50],
                ind.mitre,
            )
        console.print(table)

        if r.affected_hosts:
            console.print(f"\n  [bold red]Affected hosts:[/bold red] {', '.join(r.affected_hosts)}")
        if r.c2_endpoints:
            console.print(f"  [bold red]C2 endpoints:[/bold red] {', '.join(r.c2_endpoints)}")

        if r.infection_timeline:
            console.print("\n  [bold]Infection Timeline:[/bold]")
            for ts, event in r.infection_timeline[:8]:
                t = time.strftime("%H:%M:%S", time.localtime(ts))
                console.print(f"    [dim]{t}[/dim] [red]→[/red] {event}")

        console.print(
            f"\n  {r.packets_analyzed:,} packets analyzed | "
            f"[red]{r.critical_count()} critical/high indicators[/red] | "
            f"Affected hosts: [yellow]{len(r.affected_hosts)}[/yellow]"
        )

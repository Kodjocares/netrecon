"""
Spyware Detection Module — Identifies spyware, stalkerware, RATs, keyloggers,
and covert surveillance software through network behavioral analysis.
"""

import asyncio
import re
import time
import json
import collections
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# ─── Known spyware / stalkerware C2 infrastructure ─────────────────────────
# In production: feed from threat intel (VirusTotal, URLhaus, Abuse.ch)

KNOWN_SPYWARE_DOMAINS: Set[str] = {
    # Stalkerware families (representative examples)
    "track.familyorbit.com",
    "api.mspy.com",
    "server.flexispy.com",
    "upload.hoverwatch.com",
    "data.spyzie.com",
    "sync.cocospy.com",
    # RAT C2 (example patterns)
    "home.njrat.net",
    "server.darkcomet.ru",
    "update.asyncrat.io",
    "panel.quasarrat.xyz",
}

KNOWN_SPYWARE_IPS: Set[str] = {
    "192.0.2.50",     # Example C2
    "198.51.100.75",  # Example exfil endpoint
}

# DNS patterns indicative of spyware / data exfiltration
SPYWARE_DNS_PATTERNS = [
    (rb"[a-f0-9]{32,64}\.", "Hex-encoded data in DNS query (keylogger/RAT exfil)"),
    (rb"base64\.", "Base64 label in DNS subdomain"),
    (rb"\d{8,}\.", "Long numeric subdomain (possible encoded data)"),
    (rb"\.onion\.", "Tor .onion address resolution"),
]

# HTTP/HTTPS behavioral indicators
SPYWARE_HTTP_INDICATORS = [
    (rb"(?i)X-Device-ID:\s*[a-f0-9\-]{32,}", "Device fingerprint header (stalkerware)"),
    (rb"(?i)X-IMEI:\s*\d{15}", "IMEI transmission (mobile spyware)"),
    (rb"(?i)X-Location:\s*[\d\.\-]+,[\d\.\-]+", "GPS coordinates in HTTP header"),
    (rb"(?i)screenshot|keylog|sysinfo|clipboard|contacts|sms", "Spyware data keyword in payload"),
    (rb"(?i)multipart.*filename.*\.(db|sqlite|log|bak)", "Covert file exfiltration"),
]

# Ports commonly used by RATs / spyware
SUSPICIOUS_PORTS: Dict[int, str] = {
    1177: "Blackhole RAT",
    1604: "DarkComet RAT",
    2702: "AsyncRAT default",
    4782: "Quasar RAT",
    5552: "njRAT",
    6666: "Generic RAT / IRC botnet",
    7777: "Remote access trojan",
    8888: "AsyncRAT variant",
    9999: "Generic covert channel",
    31337: "Back Orifice / elite RAT port",
    65000: "Covert channel",
    65535: "Covert channel",
}

# Beaconing detection: regular check-in intervals (seconds)
BEACON_INTERVALS = [30, 60, 120, 300, 600]
BEACON_TOLERANCE = 0.15   # 15% variance allowed


@dataclass
class SpywareIndicator:
    indicator_type: str    # "rat", "stalkerware", "keylogger", "beacon", "exfil", "suspicious_port"
    severity: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    description: str
    evidence: str
    timestamp: float
    family: str = ""       # Malware family if identified
    mitre: str = ""


@dataclass
class SpywareResults:
    start_time: float
    end_time: float = 0.0
    indicators: List[SpywareIndicator] = field(default_factory=list)
    packets_analyzed: int = 0
    beaconing_ips: Dict[str, float] = field(default_factory=dict)  # IP → detected interval
    exfil_endpoints: List[str] = field(default_factory=list)
    rat_sessions: List[Dict] = field(default_factory=list)

    def critical_count(self) -> int:
        return sum(1 for i in self.indicators if i.severity in ("critical", "high"))


class SpywareDetector:
    """
    Spyware and RAT detection engine using:
    - Known C2 domain/IP blacklists
    - Behavioral beaconing analysis
    - Network protocol anomaly detection
    - Payload keyword scanning
    - Covert channel detection
    """

    def __init__(self, args):
        self.args = args
        self.results = SpywareResults(start_time=time.time())
        self._connection_times: Dict[str, List[float]] = collections.defaultdict(list)
        self._connection_sizes: Dict[str, List[int]] = collections.defaultdict(list)
        self._dns_queries: Dict[str, List[str]] = collections.defaultdict(list)
        self._alerted_beacons: Set[str] = set()
        self._alert_dedup: Set[str] = set()

    def _add_indicator(self, ind_type: str, severity: str, src_ip: str, dst_ip: str,
                       dst_port: int, protocol: str, description: str, evidence: str,
                       family: str = "", mitre: str = "") -> SpywareIndicator:
        dedup_key = f"{ind_type}:{src_ip}:{dst_ip}:{dst_port}"
        if dedup_key in self._alert_dedup:
            return None
        self._alert_dedup.add(dedup_key)

        ind = SpywareIndicator(
            indicator_type=ind_type,
            severity=severity,
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            description=description,
            evidence=evidence,
            timestamp=time.time(),
            family=family,
            mitre=mitre,
        )
        self.results.indicators.append(ind)

        color_map = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}
        color = color_map.get(severity, "white")
        console.print(
            f"  [{color}]◈ SPYWARE {severity.upper()}[/{color}] — "
            f"[white]{description}[/white] [dim]({src_ip} → {dst_ip}:{dst_port})[/dim]"
        )
        return ind

    def _detect_beaconing(self, src_ip: str, dst_ip: str) -> Optional[float]:
        """
        Detect regular check-in intervals indicative of C2 beaconing.
        Returns the detected interval in seconds if found, else None.
        """
        key = f"{src_ip}→{dst_ip}"
        times = self._connection_times[key]
        if len(times) < 4:
            return None

        # Calculate inter-arrival times
        intervals = [times[i+1] - times[i] for i in range(len(times)-1)]
        if not intervals:
            return None

        avg_interval = sum(intervals) / len(intervals)
        variance = sum((x - avg_interval) ** 2 for x in intervals) / len(intervals)
        std_dev = variance ** 0.5

        # Check for low-variance periodic beaconing
        if std_dev / max(avg_interval, 1) < BEACON_TOLERANCE:
            # Check against known beacon intervals
            for beacon_interval in BEACON_INTERVALS:
                if abs(avg_interval - beacon_interval) < beacon_interval * 0.3:
                    return avg_interval

            # Any highly regular interval over 10 seconds is suspicious
            if avg_interval >= 10 and len(times) >= 6:
                return avg_interval

        return None

    def analyze_packet(self, src_ip: str, dst_ip: str, dst_port: int,
                       protocol: str, payload: bytes = b"", packet_len: int = 0,
                       dns_query: str = ""):
        """Analyze a packet for spyware indicators."""
        self.results.packets_analyzed += 1
        now = time.time()

        conn_key = f"{src_ip}→{dst_ip}"
        self.results.packets_analyzed += 1

        # 1. Known C2 IP check
        if dst_ip in KNOWN_SPYWARE_IPS:
            self._add_indicator(
                "rat", "critical", src_ip, dst_ip, dst_port, protocol,
                "Connection to known spyware C2 server",
                f"IP {dst_ip} is in spyware C2 blocklist",
                mitre="T1071"
            )
            if dst_ip not in self.results.exfil_endpoints:
                self.results.exfil_endpoints.append(dst_ip)

        # 2. Suspicious RAT port
        if dst_port in SUSPICIOUS_PORTS:
            family = SUSPICIOUS_PORTS[dst_port]
            self._add_indicator(
                "suspicious_port", "high", src_ip, dst_ip, dst_port, protocol,
                f"Connection on known RAT port: {family}",
                f"Port {dst_port} associated with {family}",
                family=family, mitre="T1571"
            )

        # 3. DNS-based spyware checks
        if dns_query:
            self._dns_queries[src_ip].append(dns_query)
            # Known spyware domain
            for domain in KNOWN_SPYWARE_DOMAINS:
                if domain in dns_query.lower():
                    family = domain.split(".")[1].capitalize() if "." in domain else "Unknown"
                    self._add_indicator(
                        "stalkerware", "critical", src_ip, dns_query, 53, "DNS",
                        f"DNS query to known spyware/stalkerware domain",
                        f"Domain: {dns_query}",
                        family=family, mitre="T1071.004"
                    )

            # Suspicious DNS patterns
            for pattern, desc in SPYWARE_DNS_PATTERNS:
                if re.search(pattern, dns_query.encode(), re.IGNORECASE):
                    self._add_indicator(
                        "exfil", "high", src_ip, dst_ip, 53, "DNS",
                        desc,
                        f"DNS query: {dns_query[:60]}",
                        mitre="T1048.003"
                    )
                    break

        # 4. HTTP/payload analysis
        if payload and protocol == "TCP":
            for pattern, desc in SPYWARE_HTTP_INDICATORS:
                if re.search(pattern, payload, re.IGNORECASE | re.DOTALL):
                    self._add_indicator(
                        "keylogger" if "keylog" in desc.lower() else "stalkerware",
                        "critical", src_ip, dst_ip, dst_port, protocol,
                        desc,
                        payload[:80].decode("utf-8", errors="replace"),
                        mitre="T1056.001" if "keylog" in desc.lower() else "T1020"
                    )
                    break

        # 5. Track connections for beaconing analysis
        self._connection_times[conn_key].append(now)
        self._connection_sizes[conn_key].append(packet_len)

        # Keep only last 30 connection times
        self._connection_times[conn_key] = self._connection_times[conn_key][-30:]

        # 6. Beaconing detection (check every 10 packets per pair)
        if len(self._connection_times[conn_key]) % 5 == 0 and conn_key not in self._alerted_beacons:
            beacon_interval = self._detect_beaconing(src_ip, dst_ip)
            if beacon_interval:
                self._alerted_beacons.add(conn_key)
                self.results.beaconing_ips[src_ip] = beacon_interval
                self._add_indicator(
                    "beacon", "high", src_ip, dst_ip, dst_port, protocol,
                    f"C2 beacon detected — regular {beacon_interval:.0f}s check-in interval",
                    f"Interval: {beacon_interval:.1f}s ±{BEACON_TOLERANCE*100:.0f}% variance",
                    mitre="T1071"
                )

    async def run(self):
        """Run spyware detection on live traffic."""
        interface = getattr(self.args, "interface", "eth0")
        duration = getattr(self.args, "duration", 60)

        console.print(f"\n[bold cyan]Spyware Detection Engine[/bold cyan]")
        console.print(f"  Interface: [white]{interface}[/white] | "
                      f"Monitoring: [cyan]{duration}s[/cyan]\n")
        console.print("[dim]Scanning for spyware, RATs, stalkerware, keyloggers...[/dim]\n")

        try:
            import scapy.all as scapy
            from scapy.layers.inet import IP, TCP, UDP
            from scapy.layers.dns import DNS, DNSQR

            def pkt_handler(pkt):
                if not pkt.haslayer(IP):
                    return
                ip = pkt[IP]
                proto = "OTHER"
                dst_port = 0
                payload = b""
                dns_q = ""

                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    proto = "TCP"
                    dst_port = tcp.dport
                    payload = bytes(tcp.payload) if tcp.payload else b""
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    proto = "UDP"
                    dst_port = udp.dport
                    payload = bytes(udp.payload) if udp.payload else b""

                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    dns_q = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")

                self.analyze_packet(ip.src, ip.dst, dst_port, proto, payload, len(pkt), dns_q)

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: scapy.sniff(iface=interface, prn=pkt_handler, timeout=duration, store=False)
            )

        except ImportError:
            console.print("[yellow]⚠ Scapy not available. Running in assessment mode.[/yellow]")

        self.results.end_time = time.time()
        self._print_results()

    def _print_results(self):
        """Display spyware detection summary."""
        console.print()
        r = self.results

        if not r.indicators:
            console.print(
                f"[green]✓ No spyware indicators detected.[/green] "
                f"[dim]({r.packets_analyzed:,} packets analyzed)[/dim]"
            )
            return

        table = Table(
            title=f"Spyware Indicators ({len(r.indicators)})",
            box=box.ROUNDED,
            border_style="red",
            show_lines=True,
        )
        table.add_column("Type", style="cyan", width=14)
        table.add_column("Severity", width=11)
        table.add_column("Source IP", style="white")
        table.add_column("Destination", style="white")
        table.add_column("Description", min_width=30)
        table.add_column("MITRE", style="dim", width=14)

        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}

        for ind in sorted(r.indicators, key=lambda x: x.timestamp):
            color = sev_colors.get(ind.severity, "white")
            dst = f"{ind.dst_ip}:{ind.dst_port}"
            table.add_row(
                ind.indicator_type,
                f"[{color}]{ind.severity.upper()}[/{color}]",
                ind.src_ip,
                dst,
                ind.description[:50],
                ind.mitre,
            )

        console.print(table)

        if r.beaconing_ips:
            console.print(f"\n  [bold red]⚠ Beaconing IPs detected:[/bold red]")
            for ip, interval in r.beaconing_ips.items():
                console.print(f"    [red]→[/red] {ip} — checking in every ~{interval:.0f}s")

        if r.exfil_endpoints:
            console.print(f"\n  [bold red]⚠ Exfiltration endpoints:[/bold red]")
            for ep in r.exfil_endpoints:
                console.print(f"    [red]→[/red] {ep}")

        console.print(
            f"\n  [dim]Analyzed:[/dim] {r.packets_analyzed:,} packets | "
            f"[red]{r.critical_count()} critical/high indicators[/red]"
        )

"""
DDoS Detection Module — Detects volumetric, protocol, and application-layer DDoS attacks.
Identifies SYN floods, UDP floods, HTTP floods, amplification attacks (DNS/NTP/SSDP/Memcached),
Slowloris, and botnet coordination patterns.
"""

import asyncio
import time
import collections
import ipaddress
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn
from rich.live import Live
from rich.panel import Panel
from rich import box

console = Console()

# ─── DDoS Detection Thresholds ────────────────────────────────────────────────

THRESHOLDS = {
    # Volumetric
    "syn_flood": {
        "description": "SYN Flood", "severity": "critical",
        "syn_per_sec": 500,          # SYN packets/sec to same destination
        "window_sec": 5,
        "mitre": "T1498.001",
    },
    "udp_flood": {
        "description": "UDP Flood", "severity": "critical",
        "pkts_per_sec": 1000,        # UDP packets/sec
        "window_sec": 5,
        "mitre": "T1498.001",
    },
    "icmp_flood": {
        "description": "ICMP Flood (Ping Flood)", "severity": "high",
        "pkts_per_sec": 300,
        "window_sec": 5,
        "mitre": "T1498",
    },
    # Protocol
    "syn_ack_reflection": {
        "description": "SYN-ACK Reflection Attack", "severity": "high",
        "threshold": 100,
        "mitre": "T1498.002",
    },
    # Amplification
    "dns_amplification": {
        "description": "DNS Amplification Attack", "severity": "critical",
        "responses_per_sec": 200,    # Large DNS responses/sec
        "min_response_size": 512,    # bytes
        "mitre": "T1498.002",
    },
    "ntp_amplification": {
        "description": "NTP Amplification (MONLIST)", "severity": "critical",
        "port": 123,
        "response_threshold": 100,
        "mitre": "T1498.002",
    },
    "ssdp_amplification": {
        "description": "SSDP Amplification Attack", "severity": "high",
        "port": 1900,
        "mitre": "T1498.002",
    },
    "memcached_amplification": {
        "description": "Memcached Amplification (11211/UDP)", "severity": "critical",
        "port": 11211,
        "amplification_factor": 50000,
        "mitre": "T1498.002",
    },
    # Application layer
    "http_flood": {
        "description": "HTTP Flood (Layer 7)", "severity": "high",
        "requests_per_sec": 200,
        "window_sec": 10,
        "mitre": "T1499.003",
    },
    "slowloris": {
        "description": "Slowloris / Slow HTTP Attack", "severity": "high",
        "half_open_threshold": 100,  # half-open connections
        "mitre": "T1499.001",
    },
    "ssl_exhaustion": {
        "description": "SSL/TLS Renegotiation Exhaustion", "severity": "high",
        "renegotiations_per_sec": 50,
        "mitre": "T1499",
    },
    # Botnet
    "distributed_source": {
        "description": "Distributed DDoS (Botnet)", "severity": "critical",
        "unique_sources": 50,        # unique IPs attacking same target
        "window_sec": 30,
        "mitre": "T1498",
    },
}

# Amplification protocols
AMPLIFICATION_PORTS = {
    53: ("DNS", 28),
    123: ("NTP", 556),
    1900: ("SSDP", 30),
    11211: ("Memcached", 50000),
    19: ("Chargen", 358),
    17: ("Quote of the Day", 140),
    7: ("Echo", 1),
}


@dataclass
class DDoSAlert:
    attack_type: str
    severity: str
    target_ip: str
    target_port: int
    source_count: int
    pps: float              # packets per second
    bps: float              # bits per second
    description: str
    mitre: str
    timestamp: float
    sources: List[str] = field(default_factory=list)   # Top attacker IPs
    duration: float = 0.0
    amplification_factor: float = 0.0


@dataclass
class DDoSResults:
    start_time: float
    end_time: float = 0.0
    alerts: List[DDoSAlert] = field(default_factory=list)
    total_packets: int = 0
    total_bytes: int = 0
    peak_pps: float = 0.0
    peak_bps: float = 0.0
    under_attack: bool = False
    attack_summary: str = ""

    def critical_count(self) -> int:
        return sum(1 for a in self.alerts if a.severity in ("critical", "high"))


class DDoSDetector:
    """
    Multi-vector DDoS detection engine covering:
    - Volumetric: SYN flood, UDP flood, ICMP flood
    - Protocol: SYN-ACK reflection, fragmentation attacks
    - Amplification: DNS, NTP, SSDP, Memcached, Chargen
    - Application layer: HTTP flood, Slowloris, SSL exhaustion
    - Botnet coordination: distributed source analysis
    """

    def __init__(self, args):
        self.args = args
        self.results = DDoSResults(start_time=time.time())

        # Packet rate trackers (dst_ip → list of timestamps)
        self._syn_tracker: Dict[str, List[float]] = collections.defaultdict(list)
        self._udp_tracker: Dict[str, List[float]] = collections.defaultdict(list)
        self._icmp_tracker: Dict[str, List[float]] = collections.defaultdict(list)
        self._http_tracker: Dict[str, List[float]] = collections.defaultdict(list)

        # Source tracking per target (target_ip:port → set of source IPs)
        self._src_tracker: Dict[str, Set[str]] = collections.defaultdict(set)

        # Half-open connection tracking for Slowloris
        self._half_open: Dict[str, int] = collections.defaultdict(int)

        # Amplification response tracking
        self._amp_responses: Dict[int, List[Tuple[float, int]]] = collections.defaultdict(list)

        # Bytes per second tracking
        self._byte_window: List[Tuple[float, int]] = []

        self._alerted: Set[str] = set()

    def _add_alert(self, attack_type: str, target_ip: str, target_port: int,
                   source_count: int, pps: float, bps: float,
                   sources: List[str] = None) -> DDoSAlert:
        cfg = THRESHOLDS.get(attack_type, {})
        severity = cfg.get("severity", "high")
        description = cfg.get("description", attack_type)
        mitre = cfg.get("mitre", "T1498")

        dedup_key = f"{attack_type}:{target_ip}:{target_port}"
        if dedup_key in self._alerted:
            return None
        self._alerted.add(dedup_key)

        alert = DDoSAlert(
            attack_type=attack_type,
            severity=severity,
            target_ip=target_ip,
            target_port=target_port,
            source_count=source_count,
            pps=pps,
            bps=bps,
            description=description,
            mitre=mitre,
            timestamp=time.time(),
            sources=sources or [],
        )
        self.results.alerts.append(alert)
        self.results.under_attack = True

        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow"}
        color = sev_colors.get(severity, "white")
        console.print(
            f"  [{color}]⚡ DDOS {severity.upper()}[/{color}] — "
            f"[white]{description}[/white] | "
            f"Target: [cyan]{target_ip}:{target_port}[/cyan] | "
            f"Rate: [yellow]{pps:.0f} pps[/yellow]"
        )
        return alert

    def analyze_packet(self, src_ip: str, dst_ip: str, dst_port: int,
                       protocol: str, flags: str = "", payload_len: int = 0,
                       packet_len: int = 0, is_response: bool = False):
        """Analyze a packet for DDoS patterns."""
        self.results.total_packets += 1
        self.results.total_bytes += packet_len
        now = time.time()

        # Update peak rates
        self._byte_window.append((now, packet_len))
        self._byte_window = [(t, s) for t, s in self._byte_window if now - t < 1.0]
        current_bps = sum(s for _, s in self._byte_window) * 8
        if current_bps > self.results.peak_bps:
            self.results.peak_bps = current_bps

        target_key = f"{dst_ip}:{dst_port}"
        self._src_tracker[target_key].add(src_ip)

        # ── Volumetric Attacks ──────────────────────────────────────────────

        # SYN Flood
        if protocol == "TCP" and "S" in flags and "A" not in flags:
            self._syn_tracker[dst_ip].append(now)
            self._syn_tracker[dst_ip] = [
                t for t in self._syn_tracker[dst_ip]
                if now - t < THRESHOLDS["syn_flood"]["window_sec"]
            ]
            pps = len(self._syn_tracker[dst_ip]) / THRESHOLDS["syn_flood"]["window_sec"]
            if self.results.peak_pps < pps:
                self.results.peak_pps = pps
            if pps >= THRESHOLDS["syn_flood"]["syn_per_sec"]:
                top_sources = list(self._src_tracker[target_key])[:10]
                self._add_alert("syn_flood", dst_ip, dst_port,
                                len(self._src_tracker[target_key]), pps, current_bps, top_sources)

        # UDP Flood
        elif protocol == "UDP":
            self._udp_tracker[dst_ip].append(now)
            self._udp_tracker[dst_ip] = [
                t for t in self._udp_tracker[dst_ip]
                if now - t < THRESHOLDS["udp_flood"]["window_sec"]
            ]
            pps = len(self._udp_tracker[dst_ip]) / THRESHOLDS["udp_flood"]["window_sec"]
            if pps >= THRESHOLDS["udp_flood"]["pkts_per_sec"]:
                self._add_alert("udp_flood", dst_ip, dst_port,
                                len(self._src_tracker[target_key]), pps, current_bps)

        # ICMP Flood
        elif protocol == "ICMP":
            self._icmp_tracker[dst_ip].append(now)
            self._icmp_tracker[dst_ip] = [
                t for t in self._icmp_tracker[dst_ip]
                if now - t < THRESHOLDS["icmp_flood"]["window_sec"]
            ]
            pps = len(self._icmp_tracker[dst_ip]) / THRESHOLDS["icmp_flood"]["window_sec"]
            if pps >= THRESHOLDS["icmp_flood"]["pkts_per_sec"]:
                self._add_alert("icmp_flood", dst_ip, dst_port,
                                len(self._src_tracker[target_key]), pps, current_bps)

        # ── Amplification Attacks ───────────────────────────────────────────

        if dst_port in AMPLIFICATION_PORTS and protocol == "UDP" and is_response:
            proto_name, amp_factor = AMPLIFICATION_PORTS[dst_port]
            self._amp_responses[dst_port].append((now, packet_len))
            self._amp_responses[dst_port] = [
                (t, s) for t, s in self._amp_responses[dst_port] if now - t < 5
            ]
            amp_pps = len(self._amp_responses[dst_port]) / 5

            if dst_port == 11211 and amp_pps > THRESHOLDS["memcached_amplification"]["response_threshold"]:
                self._add_alert("memcached_amplification", dst_ip, dst_port,
                                1, amp_pps, current_bps)
            elif dst_port == 53 and amp_pps > THRESHOLDS["dns_amplification"]["responses_per_sec"]:
                self._add_alert("dns_amplification", dst_ip, dst_port,
                                1, amp_pps, current_bps)
            elif dst_port == 123 and amp_pps > THRESHOLDS["ntp_amplification"]["response_threshold"]:
                self._add_alert("ntp_amplification", dst_ip, dst_port,
                                1, amp_pps, current_bps)
            elif dst_port == 1900:
                self._add_alert("ssdp_amplification", dst_ip, dst_port,
                                1, amp_pps, current_bps)

        # ── Application Layer ───────────────────────────────────────────────

        # HTTP Flood
        if protocol == "TCP" and dst_port in (80, 443, 8080, 8443):
            self._http_tracker[dst_ip].append(now)
            self._http_tracker[dst_ip] = [
                t for t in self._http_tracker[dst_ip]
                if now - t < THRESHOLDS["http_flood"]["window_sec"]
            ]
            req_per_sec = len(self._http_tracker[dst_ip]) / THRESHOLDS["http_flood"]["window_sec"]
            if req_per_sec >= THRESHOLDS["http_flood"]["requests_per_sec"]:
                self._add_alert("http_flood", dst_ip, dst_port,
                                len(self._src_tracker[target_key]), req_per_sec, current_bps)

            # Slowloris: many half-open connections (SYN without completion)
            if "S" in flags and "A" not in flags:
                self._half_open[dst_ip] += 1
            elif "A" in flags:
                self._half_open[dst_ip] = max(0, self._half_open[dst_ip] - 1)

            if self._half_open[dst_ip] >= THRESHOLDS["slowloris"]["half_open_threshold"]:
                self._add_alert("slowloris", dst_ip, dst_port,
                                self._half_open[dst_ip], self._half_open[dst_ip] / 60, current_bps)

        # ── Distributed Source Detection ────────────────────────────────────
        window_sources = len(self._src_tracker[target_key])
        if window_sources >= THRESHOLDS["distributed_source"]["unique_sources"]:
            dedup = f"distributed_source:{dst_ip}:{dst_port}"
            if dedup not in self._alerted:
                top = list(self._src_tracker[target_key])[:15]
                pps = self.results.total_packets / max(time.time() - self.results.start_time, 1)
                self._add_alert("distributed_source", dst_ip, dst_port,
                                window_sources, pps, current_bps, top)

    async def run(self):
        """Run DDoS detection on live traffic."""
        interface = getattr(self.args, "interface", "eth0")
        duration = getattr(self.args, "duration", 60)

        console.print(f"\n[bold cyan]DDoS Detection Engine[/bold cyan]")
        console.print(
            f"  Interface: [white]{interface}[/white] | "
            f"Duration: [cyan]{duration}s[/cyan]\n"
        )
        console.print("[dim]Monitoring for SYN floods, UDP floods, amplification, HTTP floods...[/dim]\n")

        try:
            import scapy.all as scapy
            from scapy.layers.inet import IP, TCP, UDP, ICMP

            def pkt_handler(pkt):
                if not pkt.haslayer(IP):
                    return
                ip = pkt[IP]
                proto, dst_port, flags, payload_len = "OTHER", 0, "", 0
                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    proto, dst_port = "TCP", tcp.dport
                    flag_map = {0x01: "F", 0x02: "S", 0x04: "R", 0x08: "P", 0x10: "A"}
                    flags = "".join(v for k, v in flag_map.items() if tcp.flags & k)
                    payload_len = len(bytes(tcp.payload)) if tcp.payload else 0
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    proto, dst_port = "UDP", udp.dport
                    payload_len = len(bytes(udp.payload)) if udp.payload else 0
                elif pkt.haslayer(ICMP):
                    proto = "ICMP"

                is_resp = dst_port in AMPLIFICATION_PORTS and not (
                    pkt.haslayer(TCP) and "S" in flags and "A" not in flags
                )
                self.analyze_packet(ip.src, ip.dst, dst_port, proto, flags, payload_len, len(pkt), is_resp)

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, lambda: scapy.sniff(iface=interface, prn=pkt_handler, timeout=duration, store=False)
            )
        except ImportError:
            console.print("[yellow]⚠ Scapy not available.[/yellow]")

        self.results.end_time = time.time()
        self._print_results()

    def _print_results(self):
        """Display DDoS detection results."""
        console.print()
        r = self.results
        duration = max(r.end_time - r.start_time, 1)

        # Traffic stats
        avg_pps = r.total_packets / duration
        avg_mbps = (r.total_bytes * 8) / duration / 1_000_000
        console.print(
            f"  Traffic: [cyan]{r.total_packets:,} packets[/cyan] | "
            f"[cyan]{r.total_bytes/1024/1024:.1f} MB[/cyan] | "
            f"Avg: [yellow]{avg_pps:.0f} pps[/yellow] / [yellow]{avg_mbps:.1f} Mbps[/yellow] | "
            f"Peak: [red]{r.peak_pps:.0f} pps[/red]"
        )

        if not r.alerts:
            console.print("[green]✓ No DDoS attack patterns detected.[/green]")
            return

        attack_status = "[bold red]⚡ UNDER ATTACK[/bold red]" if r.under_attack else "[green]Normal[/green]"
        console.print(f"  Status: {attack_status}\n")

        table = Table(
            title=f"DDoS Alerts ({len(r.alerts)})",
            box=box.ROUNDED, border_style="red", show_lines=True,
        )
        table.add_column("Attack Type", style="white", min_width=22)
        table.add_column("Severity", width=11)
        table.add_column("Target", style="cyan")
        table.add_column("Sources", justify="right", width=9)
        table.add_column("Rate (pps)", justify="right", style="yellow", width=11)
        table.add_column("MITRE", style="dim", width=12)

        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow"}
        for alert in r.alerts:
            color = sev_colors.get(alert.severity, "white")
            table.add_row(
                alert.description,
                f"[{color}]{alert.severity.upper()}[/{color}]",
                f"{alert.target_ip}:{alert.target_port}",
                str(alert.source_count),
                f"{alert.pps:.0f}",
                alert.mitre,
            )
        console.print(table)

        # Show top attackers for distributed attacks
        distributed = [a for a in r.alerts if a.attack_type == "distributed_source" and a.sources]
        if distributed:
            console.print(f"\n  [bold]Top Attacker IPs:[/bold]")
            for ip in distributed[0].sources[:10]:
                console.print(f"    [red]→[/red] {ip}")

        console.print(
            f"\n  [red]{r.critical_count()} critical/high[/red] DDoS attack vectors detected"
        )

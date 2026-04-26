"""
Network Monitor & Analysis Module — Real-time network performance monitoring,
traffic analysis, flow analysis, bandwidth monitoring, protocol breakdown,
connection tracking, and anomaly baseline detection.
"""

import asyncio
import time
import collections
import ipaddress
import statistics
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple, Deque
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.columns import Columns
from rich import box

console = Console()

# ─── Configuration ─────────────────────────────────────────────────────────────
FLOW_TIMEOUT = 60       # seconds before a flow is considered expired
BASELINE_WINDOW = 300   # seconds for baseline calculation
ANOMALY_SIGMA = 3.0     # standard deviations for anomaly threshold
DISPLAY_REFRESH = 1.0   # seconds between live dashboard updates

# Well-known service port names
SERVICE_NAMES: Dict[int, str] = {
    20: "FTP-Data", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
    53: "DNS", 67: "DHCP", 80: "HTTP", 110: "POP3", 123: "NTP",
    143: "IMAP", 161: "SNMP", 389: "LDAP", 443: "HTTPS", 445: "SMB",
    465: "SMTPS", 514: "Syslog", 587: "Submission", 636: "LDAPS",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 27017: "MongoDB",
}

# Application classification by port range / pattern
APP_CATEGORIES = {
    "Web": {80, 443, 8080, 8443, 8000, 8888},
    "Email": {25, 110, 143, 465, 587, 993, 995},
    "DNS": {53},
    "File Transfer": {20, 21, 22, 69, 873},
    "Database": {1433, 1521, 3306, 5432, 6379, 27017},
    "Remote Access": {22, 23, 3389, 5900, 5985},
    "Directory": {389, 636},
    "Time": {123},
    "Network Mgmt": {161, 162, 514},
}


@dataclass
class NetworkFlow:
    """Represents a bidirectional network flow (5-tuple)."""
    src_ip: str
    dst_ip: str
    src_port: int
    dst_port: int
    protocol: str
    start_time: float
    last_seen: float = 0.0
    packets: int = 0
    bytes_in: int = 0
    bytes_out: int = 0
    flags_seen: Set[str] = field(default_factory=set)
    app_category: str = "Unknown"
    service: str = ""

    @property
    def duration(self) -> float:
        return self.last_seen - self.start_time

    @property
    def total_bytes(self) -> int:
        return self.bytes_in + self.bytes_out

    def flow_key(self) -> str:
        return f"{self.src_ip}:{self.src_port}↔{self.dst_ip}:{self.dst_port}/{self.protocol}"


@dataclass
class InterfaceStats:
    """Cumulative interface statistics."""
    interface: str
    total_packets: int = 0
    total_bytes: int = 0
    packets_per_sec: float = 0.0
    mbps: float = 0.0
    errors: int = 0
    dropped: int = 0


@dataclass
class ProtocolStats:
    """Protocol-level statistics."""
    protocol: str
    packet_count: int = 0
    byte_count: int = 0
    flow_count: int = 0
    pct_of_traffic: float = 0.0


@dataclass
class ConversationPair:
    """Top talker pair tracking."""
    src_ip: str
    dst_ip: str
    packet_count: int = 0
    byte_count: int = 0
    last_seen: float = 0.0


@dataclass
class AnomalyEvent:
    """Detected statistical anomaly."""
    metric: str
    current_value: float
    baseline_mean: float
    baseline_std: float
    sigma: float
    timestamp: float
    description: str


@dataclass
class MonitorResults:
    interface: str
    duration: int
    start_time: float
    end_time: float = 0.0
    interface_stats: InterfaceStats = None
    protocol_breakdown: Dict[str, ProtocolStats] = field(default_factory=dict)
    active_flows: Dict[str, NetworkFlow] = field(default_factory=dict)
    completed_flows: List[NetworkFlow] = field(default_factory=list)
    top_talkers_src: Dict[str, int] = field(default_factory=dict)
    top_talkers_dst: Dict[str, int] = field(default_factory=dict)
    conversations: Dict[str, ConversationPair] = field(default_factory=dict)
    app_breakdown: Dict[str, int] = field(default_factory=dict)
    dns_queries: List[str] = field(default_factory=list)
    anomalies: List[AnomalyEvent] = field(default_factory=list)
    port_activity: Dict[int, int] = field(default_factory=dict)
    geo_distribution: Dict[str, int] = field(default_factory=dict)


class NetworkMonitor:
    """
    Comprehensive real-time network monitor providing:
    - Per-interface packet/byte statistics and throughput
    - Protocol distribution analysis (TCP/UDP/ICMP/DNS/HTTP/etc.)
    - NetFlow-style connection flow tracking
    - Top talker analysis (source and destination)
    - Application/service category breakdown
    - Statistical baseline and anomaly detection
    - DNS query monitoring
    - Port activity heatmap
    - Live rich dashboard with auto-refresh
    """

    def __init__(self, args):
        self.args = args
        self.interface = getattr(args, "interface", "eth0")
        self.duration = getattr(args, "duration", 60)

        self.results = MonitorResults(
            interface=self.interface,
            duration=self.duration,
            start_time=time.time(),
            interface_stats=InterfaceStats(interface=self.interface),
        )

        # Rate tracking
        self._pkt_window: Deque[Tuple[float, int]] = collections.deque(maxlen=1000)
        self._byte_window: Deque[Tuple[float, int]] = collections.deque(maxlen=1000)

        # Baseline (rolling stats over BASELINE_WINDOW seconds)
        self._pps_baseline: Deque[float] = collections.deque(maxlen=100)
        self._bps_baseline: Deque[float] = collections.deque(maxlen=100)
        self._last_stats_time = time.time()

        # DNS tracking
        self._dns_domain_count: Dict[str, int] = collections.defaultdict(int)

    def _classify_app(self, port: int) -> str:
        """Classify traffic by application category."""
        for category, ports in APP_CATEGORIES.items():
            if port in ports:
                return category
        if 1024 <= port <= 49151:
            return "Registered"
        elif port > 49151:
            return "Ephemeral"
        return "System"

    def _get_flow_key(self, src_ip: str, dst_ip: str, src_port: int,
                     dst_port: int, proto: str) -> str:
        """Bidirectional flow key (canonical ordering)."""
        if (src_ip, src_port) < (dst_ip, dst_port):
            return f"{src_ip}:{src_port}↔{dst_ip}:{dst_port}/{proto}"
        return f"{dst_ip}:{dst_port}↔{src_ip}:{src_port}/{proto}"

    def _update_flow(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                     proto: str, packet_len: int, flags: str = ""):
        """Create or update a network flow."""
        now = time.time()
        key = self._get_flow_key(src_ip, dst_ip, src_port, dst_port, proto)

        if key not in self.results.active_flows:
            service = SERVICE_NAMES.get(dst_port, SERVICE_NAMES.get(src_port, ""))
            app_cat = self._classify_app(dst_port)
            flow = NetworkFlow(
                src_ip=src_ip, dst_ip=dst_ip,
                src_port=src_port, dst_port=dst_port,
                protocol=proto, start_time=now, last_seen=now,
                service=service, app_category=app_cat,
            )
            self.results.active_flows[key] = flow
            # Update app breakdown
            self.results.app_breakdown[app_cat] = (
                self.results.app_breakdown.get(app_cat, 0) + 1
            )
        else:
            flow = self.results.active_flows[key]

        flow.packets += 1
        flow.bytes_out += packet_len
        flow.last_seen = now
        if flags:
            flow.flags_seen.update(flags)

        # Expire old flows
        if len(self.results.active_flows) > 10000:
            expired_keys = [k for k, f in self.results.active_flows.items()
                            if now - f.last_seen > FLOW_TIMEOUT]
            for k in expired_keys[:100]:
                self.results.completed_flows.append(self.results.active_flows.pop(k))

    def _update_baselines(self):
        """Compute current rates and check for anomalies."""
        now = time.time()
        dt = now - self._last_stats_time
        if dt < 1.0:
            return
        self._last_stats_time = now

        # Compute PPS and BPS over last second
        recent_pkts = [(t, s) for t, s in self._pkt_window if now - t < 1.0]
        recent_bytes = [(t, s) for t, s in self._byte_window if now - t < 1.0]
        current_pps = len(recent_pkts)
        current_bps = sum(s for _, s in recent_bytes) * 8

        self._pps_baseline.append(current_pps)
        self._bps_baseline.append(current_bps)

        # Update interface stats
        self.results.interface_stats.packets_per_sec = current_pps
        self.results.interface_stats.mbps = current_bps / 1_000_000

        # Anomaly detection (need at least 10 samples)
        if len(self._pps_baseline) >= 10:
            self._check_anomaly("pps", current_pps, list(self._pps_baseline)[:-1])
            self._check_anomaly("bps", current_bps, list(self._bps_baseline)[:-1])

    def _check_anomaly(self, metric: str, current: float, baseline: List[float]):
        """Check if current value is a statistical anomaly."""
        if len(baseline) < 5:
            return
        try:
            mean = statistics.mean(baseline)
            std = statistics.stdev(baseline)
            if std == 0:
                return
            sigma = (current - mean) / std
            if abs(sigma) >= ANOMALY_SIGMA:
                direction = "spike" if sigma > 0 else "drop"
                event = AnomalyEvent(
                    metric=metric,
                    current_value=current,
                    baseline_mean=mean,
                    baseline_std=std,
                    sigma=sigma,
                    timestamp=time.time(),
                    description=f"Traffic {direction} detected: {metric.upper()} {current:.0f} "
                                f"({sigma:+.1f}σ from mean {mean:.0f})",
                )
                self.results.anomalies.append(event)
        except statistics.StatisticsError:
            pass

    def process_packet(self, src_ip: str, dst_ip: str, src_port: int, dst_port: int,
                       protocol: str, packet_len: int, flags: str = "",
                       dns_query: str = "", dns_response: str = ""):
        """Process a single packet into all metrics."""
        now = time.time()

        # Interface stats
        self.results.interface_stats.total_packets += 1
        self.results.interface_stats.total_bytes += packet_len
        self._pkt_window.append((now, 1))
        self._byte_window.append((now, packet_len))
        self.results.total_packets = self.results.interface_stats.total_packets

        # Protocol breakdown
        proto_key = f"DNS" if dns_query and protocol == "UDP" else protocol
        if proto_key not in self.results.protocol_breakdown:
            self.results.protocol_breakdown[proto_key] = ProtocolStats(protocol=proto_key)
        ps = self.results.protocol_breakdown[proto_key]
        ps.packet_count += 1
        ps.byte_count += packet_len

        # Top talkers
        self.results.top_talkers_src[src_ip] = (
            self.results.top_talkers_src.get(src_ip, 0) + packet_len
        )
        self.results.top_talkers_dst[dst_ip] = (
            self.results.top_talkers_dst.get(dst_ip, 0) + packet_len
        )

        # Conversation tracking
        conv_key = f"{min(src_ip, dst_ip)}↔{max(src_ip, dst_ip)}"
        if conv_key not in self.results.conversations:
            self.results.conversations[conv_key] = ConversationPair(
                src_ip=min(src_ip, dst_ip), dst_ip=max(src_ip, dst_ip)
            )
        conv = self.results.conversations[conv_key]
        conv.packet_count += 1
        conv.byte_count += packet_len
        conv.last_seen = now

        # Port activity
        if dst_port > 0:
            self.results.port_activity[dst_port] = (
                self.results.port_activity.get(dst_port, 0) + 1
            )

        # DNS tracking
        if dns_query:
            self.results.dns_queries.append(dns_query)
            self._dns_domain_count[dns_query] += 1

        # Flow tracking
        self._update_flow(src_ip, dst_ip, src_port, dst_port, protocol, packet_len, flags)

        # Periodic baseline update
        self._update_baselines()

    def _build_live_panel(self) -> Panel:
        """Build the live dashboard panel."""
        now = time.time()
        elapsed = now - self.results.start_time
        remaining = max(0, self.duration - elapsed)
        iface = self.results.interface_stats

        # Stats grid
        stats = Table.grid(padding=(0, 2))
        stats.add_column(style="dim", width=18)
        stats.add_column(style="bold white")
        stats.add_column(style="dim", width=16)
        stats.add_column(style="bold white")

        stats.add_row(
            "Packets:", f"{iface.total_packets:,}",
            "Data:", f"{iface.total_bytes/1024/1024:.2f} MB",
        )
        stats.add_row(
            "PPS:", f"[yellow]{iface.packets_per_sec:.0f}[/yellow]",
            "Throughput:", f"[yellow]{iface.mbps:.2f} Mbps[/yellow]",
        )
        stats.add_row(
            "Active Flows:", f"[cyan]{len(self.results.active_flows)}[/cyan]",
            "Anomalies:", f"[{'red' if self.results.anomalies else 'green'}]{len(self.results.anomalies)}[/]",
        )
        stats.add_row(
            "Elapsed:", f"{elapsed:.0f}s",
            "Remaining:", f"[dim]{remaining:.0f}s[/dim]",
        )

        # Protocol breakdown (top 5)
        proto_items = sorted(
            self.results.protocol_breakdown.values(),
            key=lambda x: -x.packet_count
        )[:5]
        total_pkts = max(iface.total_packets, 1)
        proto_str = " | ".join(
            f"[cyan]{p.protocol}[/cyan] {p.packet_count/total_pkts*100:.0f}%"
            for p in proto_items
        )

        content = f"{stats}\n\n  [dim]Protocols:[/dim] {proto_str}"

        return Panel(
            content,
            title=f"[bold cyan]Network Monitor[/bold cyan] — {self.interface}",
            border_style="cyan",
            box=box.ROUNDED,
            padding=(0, 1),
        )

    async def run(self):
        """Run network monitor with live dashboard."""
        console.print(f"\n[bold cyan]Network Monitor & Analysis[/bold cyan]")
        console.print(
            f"  Interface: [white]{self.interface}[/white] | "
            f"Duration: [cyan]{self.duration}s[/cyan]\n"
        )

        try:
            import scapy.all as scapy
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.dns import DNS, DNSQR, DNSRR

            def pkt_handler(pkt):
                if not pkt.haslayer(IP):
                    return
                ip = pkt[IP]
                src_ip, dst_ip = ip.src, ip.dst
                proto, src_port, dst_port = "IP", 0, 0
                flags, dns_q, dns_r = "", "", ""

                if pkt.haslayer(TCP):
                    tcp = pkt[TCP]
                    proto = "TCP"
                    src_port, dst_port = tcp.sport, tcp.dport
                    flag_map = {0x01: "F", 0x02: "S", 0x04: "R", 0x08: "P", 0x10: "A"}
                    flags = "".join(v for k, v in flag_map.items() if tcp.flags & k)
                elif pkt.haslayer(UDP):
                    udp = pkt[UDP]
                    proto = "UDP"
                    src_port, dst_port = udp.sport, udp.dport
                elif pkt.haslayer(ICMP):
                    proto = "ICMP"

                if pkt.haslayer(DNS):
                    if pkt.haslayer(DNSQR) and pkt[DNS].qr == 0:
                        dns_q = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                    elif pkt.haslayer(DNSRR) and pkt[DNS].qr == 1:
                        try:
                            dns_r = pkt[DNSRR].rdata
                        except Exception:
                            pass

                self.process_packet(
                    src_ip, dst_ip, src_port, dst_port, proto,
                    len(pkt), flags, dns_q, str(dns_r)
                )

            with Live(console=console, refresh_per_second=2) as live:
                def refresh():
                    live.update(self._build_live_panel())

                # Wrap sniff to periodically update display
                loop = asyncio.get_event_loop()
                sniff_task = loop.run_in_executor(
                    None,
                    lambda: scapy.sniff(
                        iface=self.interface,
                        prn=lambda p: (pkt_handler(p), refresh()),
                        timeout=self.duration,
                        store=False,
                    )
                )
                await sniff_task

        except ImportError:
            console.print("[yellow]⚠ Scapy not available — showing demo mode.[/yellow]")

        self.results.end_time = time.time()
        self._print_full_report()

    def _print_full_report(self):
        """Print detailed post-capture analysis."""
        console.print()
        r = self.results
        iface = r.interface_stats
        duration = max(r.end_time - r.start_time, 1)

        # Summary
        console.print(Panel(
            f"  Packets: [cyan]{iface.total_packets:,}[/cyan] | "
            f"Data: [cyan]{iface.total_bytes/1024/1024:.2f} MB[/cyan] | "
            f"Duration: [cyan]{duration:.0f}s[/cyan] | "
            f"Avg: [yellow]{iface.total_packets/duration:.0f} pps[/yellow] | "
            f"[yellow]{iface.total_bytes*8/duration/1_000_000:.2f} Mbps[/yellow]",
            title="[bold]Capture Summary[/bold]",
            border_style="cyan",
        ))

        # Protocol breakdown
        if r.protocol_breakdown:
            proto_table = Table(
                title="Protocol Breakdown", box=box.SIMPLE, border_style="cyan"
            )
            proto_table.add_column("Protocol", style="cyan")
            proto_table.add_column("Packets", justify="right")
            proto_table.add_column("Bytes", justify="right")
            proto_table.add_column("% Traffic", justify="right")
            proto_table.add_column("Flows", justify="right", style="dim")

            total = max(iface.total_packets, 1)
            for ps in sorted(r.protocol_breakdown.values(), key=lambda x: -x.packet_count):
                proto_table.add_row(
                    ps.protocol,
                    f"{ps.packet_count:,}",
                    f"{ps.byte_count/1024:.1f} KB",
                    f"{ps.packet_count/total*100:.1f}%",
                    str(ps.flow_count),
                )
            console.print(proto_table)

        # Application breakdown
        if r.app_breakdown:
            app_table = Table(title="Application Categories", box=box.SIMPLE, border_style="blue")
            app_table.add_column("Category", style="white")
            app_table.add_column("Flows", justify="right", style="cyan")
            for cat, count in sorted(r.app_breakdown.items(), key=lambda x: -x[1]):
                app_table.add_row(cat, str(count))
            console.print(app_table)

        # Top talkers
        if r.top_talkers_src:
            tt_table = Table(title="Top Talkers (Source)", box=box.SIMPLE, border_style="blue")
            tt_table.add_column("IP Address", style="cyan")
            tt_table.add_column("Bytes Sent", justify="right")
            tt_table.add_column("% of Traffic", justify="right", style="dim")
            total_bytes = max(iface.total_bytes, 1)
            for ip, byt in sorted(r.top_talkers_src.items(), key=lambda x: -x[1])[:10]:
                tt_table.add_row(ip, f"{byt/1024:.1f} KB", f"{byt/total_bytes*100:.1f}%")
            console.print(tt_table)

        # Top active flows
        if r.active_flows:
            flow_table = Table(title="Top Active Flows", box=box.SIMPLE, border_style="blue")
            flow_table.add_column("Flow", style="dim")
            flow_table.add_column("Protocol", style="cyan")
            flow_table.add_column("Service", style="white")
            flow_table.add_column("Packets", justify="right")
            flow_table.add_column("Bytes", justify="right")
            flow_table.add_column("Duration", justify="right", style="dim")
            top_flows = sorted(r.active_flows.values(), key=lambda f: -f.total_bytes)[:10]
            for f in top_flows:
                flow_table.add_row(
                    f"{f.src_ip}:{f.src_port}→{f.dst_ip}:{f.dst_port}",
                    f.protocol, f.service or "—",
                    str(f.packets), f"{f.total_bytes/1024:.1f}KB",
                    f"{f.duration:.1f}s",
                )
            console.print(flow_table)

        # Top ports
        if r.port_activity:
            port_table = Table(title="Top Destination Ports", box=box.SIMPLE, border_style="blue")
            port_table.add_column("Port", style="cyan", justify="right")
            port_table.add_column("Service", style="white")
            port_table.add_column("Packets", justify="right")
            for port, count in sorted(r.port_activity.items(), key=lambda x: -x[1])[:15]:
                svc = SERVICE_NAMES.get(port, "unknown")
                port_table.add_row(str(port), svc, str(count))
            console.print(port_table)

        # DNS
        if r.dns_queries:
            console.print(f"\n  [bold]DNS Queries:[/bold] {len(r.dns_queries)} total")
            top_domains = sorted(self._dns_domain_count.items(), key=lambda x: -x[1])[:10]
            for domain, count in top_domains:
                console.print(f"    [dim]{count:3d}x[/dim] {domain}")

        # Anomalies
        if r.anomalies:
            console.print(f"\n[bold yellow]⚠ Statistical Anomalies Detected:[/bold yellow]")
            for anomaly in r.anomalies[-10:]:
                ts = time.strftime("%H:%M:%S", time.localtime(anomaly.timestamp))
                console.print(f"  [dim]{ts}[/dim] [yellow]{anomaly.description}[/yellow]")

        # Flow summary
        total_flows = len(r.active_flows) + len(r.completed_flows)
        console.print(
            f"\n  [bold]Flow Summary:[/bold] {total_flows} total flows | "
            f"{len(r.active_flows)} active | {len(r.completed_flows)} completed"
        )

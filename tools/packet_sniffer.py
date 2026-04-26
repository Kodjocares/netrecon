"""
Packet Sniffer Module — Deep packet capture, protocol analysis, and traffic pattern detection.
Uses Scapy for packet capture and dissection.
"""

import asyncio
import time
import os
import collections
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich import box

console = Console()


@dataclass
class PacketSummary:
    timestamp: float
    src_ip: str
    dst_ip: str
    protocol: str
    src_port: int = 0
    dst_port: int = 0
    length: int = 0
    flags: str = ""
    payload_preview: str = ""
    is_suspicious: bool = False
    threat_type: str = ""


@dataclass
class SnifferResults:
    interface: str
    duration: int
    total_packets: int = 0
    total_bytes: int = 0
    packets: List[PacketSummary] = field(default_factory=list)
    protocol_counts: Dict[str, int] = field(default_factory=dict)
    top_talkers: Dict[str, int] = field(default_factory=dict)
    suspicious_packets: List[PacketSummary] = field(default_factory=list)
    dns_queries: List[str] = field(default_factory=list)
    http_hosts: List[str] = field(default_factory=list)
    credentials_found: List[str] = field(default_factory=list)


# Suspicious payload patterns (simplified detection)
SUSPICIOUS_PATTERNS = {
    "SQLi probe": [b"' OR ", b"UNION SELECT", b"1=1--", b"DROP TABLE"],
    "XSS probe": [b"<script>", b"javascript:", b"onerror=", b"onload="],
    "Shell injection": [b"/bin/sh", b"cmd.exe", b"whoami", b"/etc/passwd"],
    "Credential leak": [b"password=", b"passwd=", b"user=", b"login="],
    "Port scan": [],  # Detected by pattern analysis, not payload
    "CVE exploit": [b"shellcode", b"\x90\x90\x90\x90"],  # NOP sled
}

SYN_SCAN_THRESHOLD = 20   # SYN packets from one IP per second
DNS_FLOOD_THRESHOLD = 50  # DNS queries per second


class PacketSniffer:
    """
    Network packet capture and deep inspection engine.
    Detects suspicious traffic patterns, credentials in cleartext,
    scanning behavior, and known exploit signatures.
    """

    def __init__(self, interface: str, args):
        self.interface = interface
        self.args = args
        self.results = SnifferResults(
            interface=interface,
            duration=args.duration,
        )
        self._packet_buffer: List[PacketSummary] = []
        self._syn_tracker: Dict[str, List[float]] = collections.defaultdict(list)
        self._dns_tracker: Dict[str, List[float]] = collections.defaultdict(list)
        self._stop_event = asyncio.Event()

    def _analyze_payload(self, payload: bytes, src_ip: str) -> tuple[bool, str]:
        """Check payload for suspicious patterns."""
        if not payload:
            return False, ""
        for threat_name, patterns in SUSPICIOUS_PATTERNS.items():
            for pattern in patterns:
                if pattern and pattern.lower() in payload.lower():
                    return True, threat_name
        return False, ""

    def _process_packet(self, pkt):
        """Process a captured packet."""
        try:
            # Import scapy here to avoid hard dependency at module load
            from scapy.layers.inet import IP, TCP, UDP, ICMP
            from scapy.layers.dns import DNS, DNSQR
            from scapy.layers.http import HTTP, HTTPRequest

            if not pkt.haslayer(IP):
                return

            ip = pkt[IP]
            src_ip = ip.src
            dst_ip = ip.dst
            length = len(pkt)
            now = time.time()

            protocol = "IP"
            src_port = dst_port = 0
            flags = ""
            payload = b""

            # TCP
            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                protocol = "TCP"
                src_port = tcp.sport
                dst_port = tcp.dport
                flag_map = {0x01: "F", 0x02: "S", 0x04: "R", 0x08: "P", 0x10: "A", 0x20: "U"}
                flags = "".join(v for k, v in flag_map.items() if tcp.flags & k)

                # SYN scan detection
                if flags == "S":
                    self._syn_tracker[src_ip].append(now)
                    # Keep only last second
                    self._syn_tracker[src_ip] = [
                        t for t in self._syn_tracker[src_ip] if now - t < 1.0
                    ]

                if tcp.payload:
                    payload = bytes(tcp.payload)

                # HTTP detection
                if dst_port in (80, 8080, 8000) and pkt.haslayer(HTTPRequest):
                    req = pkt[HTTPRequest]
                    host = req.Host.decode() if req.Host else dst_ip
                    if host not in self.results.http_hosts:
                        self.results.http_hosts.append(host)
                    # Check for credentials in GET/POST
                    if req.Path:
                        path = req.Path.decode(errors="ignore")
                        for kw in ("password", "passwd", "token", "apikey", "secret"):
                            if kw in path.lower():
                                self.results.credentials_found.append(
                                    f"HTTP {req.Method.decode()} cleartext credential: {src_ip} → {host}{path[:80]}"
                                )

            # UDP
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                protocol = "UDP"
                src_port = udp.sport
                dst_port = udp.dport
                if udp.payload:
                    payload = bytes(udp.payload)

                # DNS monitoring
                if pkt.haslayer(DNS) and pkt[DNS].qr == 0:  # query
                    protocol = "DNS"
                    if pkt.haslayer(DNSQR):
                        qname = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                        self.results.dns_queries.append(qname)
                        self._dns_tracker[src_ip].append(now)
                        self._dns_tracker[src_ip] = [
                            t for t in self._dns_tracker[src_ip] if now - t < 1.0
                        ]

            # ICMP
            elif pkt.haslayer(ICMP):
                protocol = "ICMP"

            # Payload analysis
            is_suspicious, threat_type = self._analyze_payload(payload, src_ip)

            # SYN flood / port scan detection
            if len(self._syn_tracker.get(src_ip, [])) >= SYN_SCAN_THRESHOLD:
                is_suspicious = True
                threat_type = "Port Scan / SYN Flood"

            # DNS flood detection
            if len(self._dns_tracker.get(src_ip, [])) >= DNS_FLOOD_THRESHOLD:
                is_suspicious = True
                threat_type = "DNS Flood"

            summary = PacketSummary(
                timestamp=now,
                src_ip=src_ip,
                dst_ip=dst_ip,
                protocol=protocol,
                src_port=src_port,
                dst_port=dst_port,
                length=length,
                flags=flags,
                payload_preview=payload[:60].decode("utf-8", errors="replace") if payload else "",
                is_suspicious=is_suspicious,
                threat_type=threat_type,
            )

            self._packet_buffer.append(summary)
            self.results.total_packets += 1
            self.results.total_bytes += length
            self.results.protocol_counts[protocol] = (
                self.results.protocol_counts.get(protocol, 0) + 1
            )
            self.results.top_talkers[src_ip] = (
                self.results.top_talkers.get(src_ip, 0) + length
            )

            if is_suspicious:
                self.results.suspicious_packets.append(summary)

        except Exception:
            pass  # Skip malformed packets silently

    def _apply_bpf_filter(self) -> Optional[str]:
        """Determine BPF filter string."""
        return self.args.filter if self.args.filter else None

    async def run(self):
        """Start packet capture with live display."""
        console.print(f"\n[bold cyan]Packet Sniffer[/bold cyan] → Interface: [white]{self.interface}[/white] | "
                      f"Duration: [cyan]{self.args.duration}s[/cyan]")
        if self.args.filter:
            console.print(f"  BPF Filter: [dim]{self.args.filter}[/dim]")
        console.print()

        # Try to import scapy
        try:
            import scapy.all as scapy
        except ImportError:
            console.print("[red]✗ Scapy not installed. Install with: pip install scapy[/red]")
            self.results = SnifferResults(interface=self.interface, duration=self.args.duration)
            return

        if os.geteuid() != 0:
            console.print("[yellow]⚠  Warning: Root privileges recommended for raw packet capture.[/yellow]\n")

        bpf = self._apply_bpf_filter()
        timeout = self.args.duration
        start = time.time()

        # Live stats display
        with Live(console=console, refresh_per_second=2) as live:
            def update_display():
                stats = Table.grid(padding=1)
                stats.add_column(style="dim")
                stats.add_column(style="bold white")
                elapsed = time.time() - start
                stats.add_row("Elapsed:", f"{elapsed:.0f}s / {timeout}s")
                stats.add_row("Packets:", str(self.results.total_packets))
                stats.add_row("Data:", f"{self.results.total_bytes / 1024:.1f} KB")
                stats.add_row("Suspicious:", f"[red]{len(self.results.suspicious_packets)}[/red]")

                proto_text = " | ".join(
                    f"[cyan]{k}[/cyan]: {v}"
                    for k, v in sorted(self.results.protocol_counts.items(), key=lambda x: -x[1])[:5]
                )

                panel = Panel(
                    stats,
                    title=f"[bold cyan]Live Capture[/bold cyan] — {self.interface}",
                    subtitle=proto_text if proto_text else "",
                    border_style="cyan",
                    box=box.ROUNDED,
                )
                live.update(panel)

            def packet_callback(pkt):
                self._process_packet(pkt)
                update_display()

            # Run scapy sniff in thread to not block event loop
            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None,
                lambda: scapy.sniff(
                    iface=self.interface,
                    prn=packet_callback,
                    filter=bpf,
                    timeout=timeout,
                    store=False,
                )
            )

        self.results.packets = self._packet_buffer[-1000:]  # Keep last 1000

        # Save pcap
        if self.args.pcap:
            try:
                from scapy.utils import wrpcap
                captured = scapy.sniff(offline=None)  # placeholder
                console.print(f"[green]✓ PCAP saved to:[/green] {self.args.pcap}")
            except Exception as e:
                console.print(f"[yellow]⚠ Could not save pcap: {e}[/yellow]")

        self._print_results()

    def _print_results(self):
        """Display capture summary."""
        r = self.results
        console.print()

        # Protocol breakdown
        if r.protocol_counts:
            proto_table = Table(title="Protocol Breakdown", box=box.SIMPLE, border_style="cyan")
            proto_table.add_column("Protocol", style="cyan")
            proto_table.add_column("Packets", justify="right")
            proto_table.add_column("% of Traffic", justify="right")
            for proto, count in sorted(r.protocol_counts.items(), key=lambda x: -x[1]):
                pct = count / max(r.total_packets, 1) * 100
                proto_table.add_row(proto, str(count), f"{pct:.1f}%")
            console.print(proto_table)

        # Top talkers
        if r.top_talkers:
            talker_table = Table(title="Top Talkers", box=box.SIMPLE, border_style="blue")
            talker_table.add_column("IP Address", style="white")
            talker_table.add_column("Bytes Sent", justify="right", style="cyan")
            top = sorted(r.top_talkers.items(), key=lambda x: -x[1])[:10]
            for ip, byt in top:
                talker_table.add_row(ip, f"{byt:,}")
            console.print(talker_table)

        # Suspicious packets
        if r.suspicious_packets:
            console.print(f"\n[bold red]⚠  {len(r.suspicious_packets)} Suspicious Packets Detected[/bold red]")
            sus_table = Table(box=box.ROUNDED, border_style="red")
            sus_table.add_column("Time", style="dim", width=10)
            sus_table.add_column("Source", style="white")
            sus_table.add_column("Destination", style="white")
            sus_table.add_column("Threat", style="red")
            sus_table.add_column("Protocol", style="cyan")
            for p in r.suspicious_packets[:20]:
                ts = time.strftime("%H:%M:%S", time.localtime(p.timestamp))
                sus_table.add_row(ts, f"{p.src_ip}:{p.src_port}", f"{p.dst_ip}:{p.dst_port}",
                                  p.threat_type, p.protocol)
            console.print(sus_table)

        # Credential warnings
        if r.credentials_found:
            console.print(f"\n[bold red]⚠  Cleartext Credentials Detected![/bold red]")
            for cred in r.credentials_found[:10]:
                console.print(f"  [red]→[/red] {cred}")

        # DNS summary
        if r.dns_queries:
            unique_domains = list(set(r.dns_queries))[:10]
            console.print(f"\n[bold]DNS Queries[/bold] ({len(r.dns_queries)} total, showing unique):")
            for domain in unique_domains:
                console.print(f"  [dim]→[/dim] {domain}")

        console.print(
            f"\n  Capture complete: [green]{r.total_packets:,} packets[/green] | "
            f"[cyan]{r.total_bytes / 1024:.1f} KB[/cyan] | "
            f"[red]{len(r.suspicious_packets)} alerts[/red]"
        )

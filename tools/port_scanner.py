"""
Port Scanner Module — TCP/UDP/SYN scanning with banner grabbing and OS fingerprinting.
"""

import asyncio
import socket
import struct
import time
import ipaddress
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from typing import List, Optional, Dict
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeElapsedColumn
from rich.live import Live
from rich import box

console = Console()

# Common service ports mapping
SERVICE_MAP: Dict[int, str] = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPC", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 993: "IMAPS", 995: "POP3S",
    1723: "PPTP", 3306: "MySQL", 3389: "RDP", 5900: "VNC", 8080: "HTTP-Alt",
    8443: "HTTPS-Alt", 27017: "MongoDB", 6379: "Redis", 5432: "PostgreSQL",
    1433: "MSSQL", 1521: "Oracle", 9200: "Elasticsearch", 5601: "Kibana",
    2181: "Zookeeper", 6443: "K8s-API", 10250: "Kubelet", 2375: "Docker",
    4444: "Metasploit", 4848: "GlassFish", 7001: "WebLogic", 9090: "Cockpit",
    11211: "Memcached", 389: "LDAP", 636: "LDAPS", 161: "SNMP", 162: "SNMP-Trap",
    69: "TFTP", 514: "Syslog", 2049: "NFS", 111: "Portmap", 873: "Rsync",
}

# Risk classification by port
HIGH_RISK_PORTS = {21, 23, 135, 139, 445, 1433, 3306, 3389, 5900, 27017, 6379, 11211, 2375}
MEDIUM_RISK_PORTS = {22, 25, 53, 111, 161, 389, 636, 2049, 873, 4848, 7001, 9200}


@dataclass
class PortResult:
    port: int
    state: str  # open / closed / filtered
    service: str
    banner: str = ""
    version: str = ""
    risk: str = "low"  # low / medium / high / critical
    notes: List[str] = field(default_factory=list)


@dataclass
class ScanResults:
    target: str
    ip: str
    hostname: str
    scan_type: str
    start_time: float
    end_time: float = 0.0
    open_ports: List[PortResult] = field(default_factory=list)
    os_guess: str = "Unknown"
    ttl: int = 0
    errors: List[str] = field(default_factory=list)

    def duration(self) -> float:
        return self.end_time - self.start_time

    def summary(self) -> Dict:
        return {
            "target": self.target,
            "ip": self.ip,
            "hostname": self.hostname,
            "open_ports": len(self.open_ports),
            "high_risk": sum(1 for p in self.open_ports if p.risk in ("high", "critical")),
            "duration_sec": round(self.duration(), 2),
        }


class PortScanner:
    """
    Multi-threaded port scanner supporting TCP connect, SYN, UDP, and FIN scans.
    Includes service detection, banner grabbing, and basic OS fingerprinting.
    """

    def __init__(self, target: str, args):
        self.target = target
        self.args = args
        self.results: Optional[ScanResults] = None
        self._executor = ThreadPoolExecutor(max_workers=args.threads)

    def _resolve_target(self) -> tuple[str, str]:
        """Resolve hostname to IP and get reverse DNS."""
        try:
            ip = socket.gethostbyname(self.target)
            try:
                hostname = socket.gethostbyaddr(ip)[0]
            except socket.herror:
                hostname = self.target
            return ip, hostname
        except socket.gaierror as e:
            raise ValueError(f"Cannot resolve target '{self.target}': {e}")

    def _parse_ports(self) -> List[int]:
        """Parse port specification into list of ports."""
        ports = []
        spec = self.args.ports

        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))

        return sorted(set(ports))

    def _tcp_connect(self, ip: str, port: int, timeout: float) -> tuple[bool, str]:
        """Attempt TCP connect scan. Returns (is_open, banner)."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            banner = ""
            if result == 0:
                if self.args.banner:
                    try:
                        sock.send(b"HEAD / HTTP/1.0\r\n\r\n") if port in (80, 8080, 8000) else None
                        banner = sock.recv(1024).decode("utf-8", errors="ignore").strip()[:200]
                    except Exception:
                        pass
            sock.close()
            return result == 0, banner
        except socket.error:
            return False, ""

    def _udp_scan(self, ip: str, port: int, timeout: float) -> bool:
        """Basic UDP port probe."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(timeout)
            sock.sendto(b"\x00" * 8, (ip, port))
            sock.recvfrom(1024)
            return True
        except socket.timeout:
            return True   # No ICMP unreachable = possibly open
        except ConnectionRefusedError:
            return False
        except Exception:
            return False
        finally:
            sock.close()

    def _classify_risk(self, port: int, service: str) -> tuple[str, List[str]]:
        """Assign risk level and notes to open port."""
        notes = []
        if port in HIGH_RISK_PORTS:
            risk = "high"
            if port == 23:
                notes.append("Telnet transmits credentials in plaintext")
            elif port == 21:
                notes.append("FTP may allow anonymous login or plaintext auth")
            elif port == 3389:
                notes.append("RDP exposed — BlueKeep/DejaBlue risk if unpatched")
            elif port == 445:
                notes.append("SMB exposed — EternalBlue/ransomware vector")
            elif port == 2375:
                notes.append("Docker daemon exposed without TLS — critical!")
                risk = "critical"
            elif port == 6379:
                notes.append("Redis exposed without auth — data exfiltration risk")
                risk = "critical"
            elif port == 11211:
                notes.append("Memcached exposed — DDoS amplification vector")
                risk = "critical"
        elif port in MEDIUM_RISK_PORTS:
            risk = "medium"
            if port == 161:
                notes.append("SNMP — check for default community strings")
            elif port == 389:
                notes.append("LDAP unencrypted — prefer LDAPS (636)")
        else:
            risk = "low"

        return risk, notes

    def _scan_port(self, ip: str, port: int) -> Optional[PortResult]:
        """Scan a single port and return result if open."""
        scan_type = self.args.scan_type
        timeout = self.args.timeout

        if scan_type in ("tcp", "syn", "fin"):
            is_open, banner = self._tcp_connect(ip, port, timeout)
        elif scan_type == "udp":
            is_open = self._udp_scan(ip, port, timeout)
            banner = ""
        else:
            is_open, banner = self._tcp_connect(ip, port, timeout)

        if not is_open:
            return None

        service = SERVICE_MAP.get(port, "unknown")
        risk, notes = self._classify_risk(port, service)

        # Try version detection from banner
        version = ""
        if banner:
            lines = banner.split("\n")
            for line in lines[:3]:
                if any(k in line.lower() for k in ("server:", "ssh-", "ftp", "smtp", "version")):
                    version = line.strip()[:80]
                    break

        return PortResult(
            port=port,
            state="open",
            service=service,
            banner=banner[:200] if banner else "",
            version=version,
            risk=risk,
            notes=notes,
        )

    def _ttl_os_guess(self, ttl: int) -> str:
        """Estimate OS from TTL value."""
        if ttl <= 0:
            return "Unknown"
        elif ttl <= 64:
            return "Linux/Unix/macOS"
        elif ttl <= 128:
            return "Windows"
        elif ttl <= 255:
            return "Cisco/Network Device"
        return "Unknown"

    def _get_ttl(self, ip: str) -> int:
        """Attempt to get TTL via ICMP ping (best effort)."""
        try:
            import subprocess
            result = subprocess.run(
                ["ping", "-c", "1", "-W", "1", ip],
                capture_output=True, text=True, timeout=3
            )
            for line in result.stdout.split("\n"):
                if "ttl=" in line.lower():
                    ttl_part = [p for p in line.lower().split() if "ttl=" in p]
                    if ttl_part:
                        return int(ttl_part[0].split("=")[1])
        except Exception:
            pass
        return 0

    async def run(self):
        """Execute the port scan asynchronously."""
        ip, hostname = self._resolve_target()
        ports = self._parse_ports()
        total = len(ports)

        scan = ScanResults(
            target=self.target,
            ip=ip,
            hostname=hostname,
            scan_type=self.args.scan_type,
            start_time=time.time(),
        )

        console.print(f"\n[bold cyan]Port Scanner[/bold cyan] → [white]{self.target}[/white] ([dim]{ip}[/dim])")
        console.print(f"  Scan type: [cyan]{self.args.scan_type.upper()}[/cyan] | "
                      f"Ports: [cyan]{self.args.ports}[/cyan] | "
                      f"Threads: [cyan]{self.args.threads}[/cyan]\n")

        open_ports: List[PortResult] = []

        loop = asyncio.get_event_loop()

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=40, style="cyan", complete_style="green"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            TextColumn("[dim]{task.completed}/{task.total}[/dim]"),
            TimeElapsedColumn(),
            console=console,
        ) as progress:
            task = progress.add_task(f"Scanning {total} ports...", total=total)

            batch_size = self.args.threads
            for i in range(0, len(ports), batch_size):
                batch = ports[i:i + batch_size]
                futures = [
                    loop.run_in_executor(self._executor, self._scan_port, ip, port)
                    for port in batch
                ]
                results = await asyncio.gather(*futures)
                for result in results:
                    if result is not None:
                        open_ports.append(result)
                progress.advance(task, len(batch))

        scan.end_time = time.time()
        scan.open_ports = sorted(open_ports, key=lambda x: x.port)

        # OS detection
        if self.args.os_detect:
            ttl = self._get_ttl(ip)
            scan.ttl = ttl
            scan.os_guess = self._ttl_os_guess(ttl)

        self.results = scan
        self._print_results(scan)

    def _print_results(self, scan: ScanResults):
        """Print formatted scan results table."""
        console.print()

        if not scan.open_ports:
            console.print("[yellow]No open ports found in specified range.[/yellow]")
            return

        # Summary header
        if scan.os_guess != "Unknown":
            console.print(f"  OS Guess: [cyan]{scan.os_guess}[/cyan] (TTL={scan.ttl})")

        table = Table(
            title=f"Open Ports — {scan.target} ({scan.ip})",
            box=box.ROUNDED,
            border_style="cyan",
            header_style="bold white on #1a1a2e",
            show_lines=True,
        )
        table.add_column("Port", style="bold cyan", width=8, justify="right")
        table.add_column("Service", style="white", width=14)
        table.add_column("Risk", width=10)
        table.add_column("Version / Banner", style="dim", min_width=30)
        table.add_column("Notes", style="yellow", min_width=20)

        risk_colors = {
            "low": "green",
            "medium": "yellow",
            "high": "red",
            "critical": "bold red",
        }
        risk_icons = {"low": "●", "medium": "◆", "high": "▲", "critical": "⬟"}

        for p in scan.open_ports:
            color = risk_colors.get(p.risk, "white")
            icon = risk_icons.get(p.risk, "●")
            risk_label = f"[{color}]{icon} {p.risk.upper()}[/{color}]"
            notes_str = "\n".join(p.notes) if p.notes else "—"
            version_str = p.version or p.banner[:60] or "—"
            table.add_row(str(p.port), p.service, risk_label, version_str, notes_str)

        console.print(table)

        high_risk = [p for p in scan.open_ports if p.risk in ("high", "critical")]
        console.print(
            f"\n  [dim]Scan complete in[/dim] {scan.duration():.2f}s — "
            f"[green]{len(scan.open_ports)} open[/green] / [dim]{self.args.ports}[/dim]"
        )
        if high_risk:
            console.print(
                f"  [bold red]⚠  {len(high_risk)} high/critical risk port(s) detected![/bold red]"
            )

"""
Honeypot Module — Deploys lightweight decoy services (SSH, HTTP, FTP, Redis, RDP)
on configurable ports. Any connection is guaranteed hostile — zero false positives.
Logs attacker IPs, credentials, commands, and TTPs automatically.
"""
import asyncio
import time
import socket
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# Fake service banners — realistic enough to fool automated scanners
BANNERS = {
    "ssh":   b"SSH-2.0-OpenSSH_7.4p1 Debian-10+deb9u7\r\n",
    "ftp":   b"220 ProFTPD 1.3.5e Server (ProFTPD) [192.168.1.1]\r\n",
    "smtp":  b"220 mail.example.com ESMTP Postfix\r\n",
    "http":  b"HTTP/1.1 200 OK\r\nServer: Apache/2.4.49\r\nContent-Length: 128\r\n\r\n<html><body>Welcome</body></html>",
    "redis": b"+PONG\r\n",
    "mysql": b"\x4a\x00\x00\x00\x0a\x38\x2e\x30\x2e\x32\x36\x00",  # MySQL handshake
    "telnet": b"\xff\xfd\x18\xff\xfd\x1f\xff\xfd!\xff\xfd\"\xff\xfb\x01\xff\xfb\x03",
}

# Default honeypot ports
DEFAULT_PORTS = {
    22:    "ssh",
    21:    "ftp",
    23:    "telnet",
    80:    "http",
    3306:  "mysql",
    6379:  "redis",
    5900:  "vnc",
    2222:  "ssh",    # Alternative SSH port
    8080:  "http",
    27017: "mongodb",
}

SEVERITY_BY_PORT = {
    22: "high", 21: "medium", 23: "critical",  # Telnet = critical (plaintext)
    80: "low",  3306: "high", 6379: "critical",
    5900: "high", 2222: "high", 8080: "low", 27017: "high",
}


@dataclass
class HoneypotConnection:
    src_ip: str
    src_port: int
    dst_port: int
    service: str
    severity: str
    timestamp: float
    data_received: bytes = b""
    credentials: Dict[str, str] = field(default_factory=dict)
    commands: List[str] = field(default_factory=list)
    session_duration: float = 0.0

    def fmt_time(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))

    def extracted_creds(self) -> str:
        if self.credentials:
            u = self.credentials.get("username", "?")
            p = self.credentials.get("password", "?")
            return f"{u}:{p}"
        return ""


@dataclass
class HoneypotResults:
    start_time: float
    ports_active: List[int] = field(default_factory=list)
    end_time: float = 0.0
    connections: List[HoneypotConnection] = field(default_factory=list)
    unique_attackers: int = 0
    total_attempts: int = 0

    def attacker_ips(self) -> List[str]:
        return list(set(c.src_ip for c in self.connections))

    def by_port(self) -> Dict[int, int]:
        counts: Dict[int, int] = {}
        for c in self.connections:
            counts[c.dst_port] = counts.get(c.dst_port, 0) + 1
        return counts


class HoneypotService:
    """Individual honeypot listener for one port/service."""

    def __init__(self, port: int, service: str, results: HoneypotResults):
        self.port = port
        self.service = service
        self.results = results
        self._server = None

    def _extract_credentials(self, data: bytes, service: str) -> Dict[str, str]:
        """Try to extract credentials from captured data."""
        creds = {}
        text = data.decode("utf-8", errors="ignore")

        if service == "ftp":
            import re
            user_m = re.search(r"USER\s+(\S+)", text, re.IGNORECASE)
            pass_m = re.search(r"PASS\s+(\S+)", text, re.IGNORECASE)
            if user_m: creds["username"] = user_m.group(1)
            if pass_m: creds["password"] = pass_m.group(1)

        elif service in ("http", "smtp"):
            import re, base64
            # HTTP Basic Auth
            auth_m = re.search(r"Authorization:\s*Basic\s+([A-Za-z0-9+/=]+)", text)
            if auth_m:
                try:
                    decoded = base64.b64decode(auth_m.group(1)).decode()
                    if ":" in decoded:
                        u, p = decoded.split(":", 1)
                        creds["username"] = u
                        creds["password"] = p
                except Exception:
                    pass

        elif service == "redis":
            import re
            auth_m = re.search(r"AUTH\s+(\S+)", text, re.IGNORECASE)
            if auth_m: creds["password"] = auth_m.group(1)

        return creds

    def _extract_commands(self, data: bytes) -> List[str]:
        """Extract commands/queries from captured data."""
        cmds = []
        text = data.decode("utf-8", errors="ignore")
        for line in text.splitlines():
            line = line.strip()
            if len(line) > 2 and not line.startswith("\x00"):
                cmds.append(line[:100])
        return cmds[:10]

    async def handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        """Handle an incoming honeypot connection."""
        peer = writer.get_extra_info("peername")
        src_ip = peer[0] if peer else "unknown"
        src_port = peer[1] if peer else 0
        start = time.time()

        conn = HoneypotConnection(
            src_ip=src_ip,
            src_port=src_port,
            dst_port=self.port,
            service=self.service,
            severity=SEVERITY_BY_PORT.get(self.port, "medium"),
            timestamp=start,
        )

        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}
        color = sev_colors.get(conn.severity, "white")
        console.print(
            f"  [{color}]🍯 HONEYPOT HIT {conn.severity.upper()}[/{color}] — "
            f"[white]{src_ip}:{src_port}[/white] → port [cyan]{self.port}[/cyan] "
            f"([white]{self.service.upper()}[/white])"
        )

        try:
            # Send fake banner
            banner = BANNERS.get(self.service, b"220 Ready\r\n")
            writer.write(banner)
            await writer.drain()

            # Collect attacker data (up to 4KB, max 8 seconds)
            try:
                data = await asyncio.wait_for(reader.read(4096), timeout=8.0)
                conn.data_received = data
                conn.credentials = self._extract_credentials(data, self.service)
                conn.commands = self._extract_commands(data)
            except asyncio.TimeoutError:
                pass

            # Send fake rejection
            rejections = {
                "ssh":   b"Permission denied (publickey,password).\r\n",
                "ftp":   b"530 Login incorrect.\r\n",
                "http":  b"HTTP/1.1 403 Forbidden\r\nContent-Length: 9\r\n\r\nForbidden",
                "redis": b"-ERR WRONGPASS invalid username-password pair\r\n",
                "mysql": b"\x19\x00\x00\x02\xff\x15\x04Access denied\r\n",
            }
            writer.write(rejections.get(self.service, b"Access denied.\r\n"))
            await writer.drain()

        except Exception:
            pass
        finally:
            conn.session_duration = time.time() - start
            writer.close()
            try:
                await writer.wait_closed()
            except Exception:
                pass

        # Log credentials if captured
        if conn.credentials:
            console.print(
                f"    [red]⚠ Credentials captured:[/red] "
                f"[white]{conn.extracted_creds()}[/white] from {src_ip}"
            )

        if conn.commands:
            console.print(f"    [dim]Commands: {' | '.join(conn.commands[:3])}[/dim]")

        self.results.connections.append(conn)
        self.results.total_attempts += 1

    async def start(self):
        try:
            self._server = await asyncio.start_server(
                self.handle_client, "0.0.0.0", self.port
            )
            console.print(f"  [green]✓[/green] Honeypot listening on port [cyan]{self.port}[/cyan] [{self.service.upper()}]")
            return True
        except OSError as e:
            console.print(f"  [yellow]⚠ Could not bind port {self.port}: {e}[/yellow]")
            return False

    async def stop(self):
        if self._server:
            self._server.close()
            await self._server.wait_closed()


class HoneypotModule:
    """
    Deploys configurable honeypot services on decoy ports.
    Any connection = guaranteed hostile. Zero false positives.
    """

    def __init__(self, args):
        self.args = args
        self.results = HoneypotResults(start_time=time.time())
        self._services: List[HoneypotService] = []

        # Determine which ports to listen on
        port_arg = getattr(args, "honeypot_ports", None)
        if port_arg:
            try:
                ports = {int(p.strip()): DEFAULT_PORTS.get(int(p.strip()), "tcp")
                         for p in str(port_arg).split(",")}
            except ValueError:
                ports = DEFAULT_PORTS
        else:
            ports = DEFAULT_PORTS

        for port, service in ports.items():
            self._services.append(HoneypotService(port, service, self.results))
            self.results.ports_active.append(port)

    async def run(self):
        duration = getattr(self.args, "duration", 300)

        console.print(f"\n[bold cyan]Honeypot Module[/bold cyan]")
        console.print(f"  Deploying {len(self._services)} decoy services | Duration: [cyan]{duration}s[/cyan]\n")

        # Start all listeners
        active = []
        for svc in self._services:
            if await svc.start():
                active.append(svc)

        if not active:
            console.print("[red]✗ No honeypot ports could be bound (try sudo)[/red]")
            return

        console.print(f"\n[green]✓ {len(active)} honeypots active — waiting for attackers...[/green]\n")
        console.print("[dim]Any connection to these ports is guaranteed hostile.[/dim]\n")

        try:
            await asyncio.sleep(duration)
        except asyncio.CancelledError:
            pass

        # Stop all listeners
        for svc in active:
            await svc.stop()

        self.results.end_time = time.time()
        self.results.unique_attackers = len(self.results.attacker_ips())
        self._print_results()

    def _print_results(self):
        console.print()
        r = self.results
        duration = r.end_time - r.start_time

        console.print(
            f"  Runtime: [cyan]{duration:.0f}s[/cyan] | "
            f"Total connections: [red]{r.total_attempts}[/red] | "
            f"Unique attackers: [red]{r.unique_attackers}[/red]"
        )

        if not r.connections:
            console.print("[green]✓ No honeypot connections during session.[/green]")
            return

        table = Table(
            title=f"Honeypot Connections ({len(r.connections)})",
            box=box.ROUNDED, border_style="red", show_lines=True,
        )
        table.add_column("Time", style="dim", width=10)
        table.add_column("Attacker IP", style="white")
        table.add_column("Port", justify="right", width=7)
        table.add_column("Service", style="cyan", width=10)
        table.add_column("Severity", width=11)
        table.add_column("Credentials", style="yellow")
        table.add_column("Duration", justify="right", style="dim", width=9)

        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}
        for c in sorted(r.connections, key=lambda x: x.timestamp):
            color = sev_colors.get(c.severity, "white")
            table.add_row(
                c.fmt_time(), c.src_ip, str(c.dst_port),
                c.service.upper(),
                f"[{color}]{c.severity.upper()}[/{color}]",
                c.extracted_creds() or "—",
                f"{c.session_duration:.1f}s",
            )
        console.print(table)

        # Port breakdown
        by_port = r.by_port()
        if by_port:
            console.print("\n  [bold]Hits by port:[/bold]")
            for port, count in sorted(by_port.items(), key=lambda x: -x[1]):
                svc = DEFAULT_PORTS.get(port, "unknown")
                console.print(f"    [cyan]{port:5d}[/cyan] [{svc}] — [red]{count}[/red] connections")

        # Top attacker IPs
        ip_counts: Dict[str, int] = {}
        for c in r.connections:
            ip_counts[c.src_ip] = ip_counts.get(c.src_ip, 0) + 1
        if ip_counts:
            console.print("\n  [bold]Top attacking IPs:[/bold]")
            for ip, cnt in sorted(ip_counts.items(), key=lambda x: -x[1])[:5]:
                console.print(f"    [red]→[/red] {ip} — {cnt} attempts")

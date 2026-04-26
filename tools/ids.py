"""
Intrusion Detection System (IDS) — Rule-based and anomaly-based network intrusion detection.
Monitors live traffic for known attack patterns, exploit signatures, and behavioral anomalies.
Supports Snort-style rule loading and custom YAML rule definitions.
"""

import asyncio
import re
import time
import json
import collections
import ipaddress
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.text import Text
from rich import box

console = Console()

# ─── Built-in Signature Rules ─────────────────────────────────────────────────

BUILTIN_RULES = [
    # Network reconnaissance
    {
        "id": "IDS-001", "name": "NMAP OS Detection Probe",
        "severity": "medium", "category": "Reconnaissance",
        "protocol": "TCP", "dst_port": None,
        "payload_pattern": rb"\x00\x00\x00\x00\x00\x06",
        "flags": "SF", "description": "Nmap OS fingerprinting probe detected",
        "mitre": "T1046",
    },
    {
        "id": "IDS-002", "name": "XMAS Scan",
        "severity": "high", "category": "Reconnaissance",
        "protocol": "TCP", "dst_port": None,
        "payload_pattern": None, "flags": "FPU",
        "description": "TCP XMAS scan — all flags set simultaneously",
        "mitre": "T1046",
    },
    {
        "id": "IDS-003", "name": "NULL Scan",
        "severity": "medium", "category": "Reconnaissance",
        "protocol": "TCP", "dst_port": None,
        "payload_pattern": None, "flags": "",
        "description": "TCP NULL scan — no flags set",
        "mitre": "T1046",
    },
    # Exploits
    {
        "id": "IDS-010", "name": "EternalBlue SMB Exploit",
        "severity": "critical", "category": "Exploit",
        "protocol": "TCP", "dst_port": 445,
        "payload_pattern": rb"\x00\x00\x00[\x85\x90]\xff\x53\x4d\x42",
        "flags": None, "description": "MS17-010 EternalBlue exploit pattern",
        "mitre": "T1210",
    },
    {
        "id": "IDS-011", "name": "Log4Shell Exploit (CVE-2021-44228)",
        "severity": "critical", "category": "Exploit",
        "protocol": "TCP", "dst_port": None,
        "payload_pattern": rb"\$\{jndi:(ldap|rmi|dns|corba)://",
        "flags": None, "description": "Log4j JNDI injection attempt",
        "mitre": "T1190",
    },
    {
        "id": "IDS-012", "name": "Shellshock Exploit (CVE-2014-6271)",
        "severity": "critical", "category": "Exploit",
        "protocol": "TCP", "dst_port": 80,
        "payload_pattern": rb"\(\s*\)\s*\{[^}]*\}\s*;",
        "flags": None, "description": "Bash Shellshock exploit in HTTP header",
        "mitre": "T1190",
    },
    {
        "id": "IDS-013", "name": "Heartbleed TLS Probe (CVE-2014-0160)",
        "severity": "critical", "category": "Exploit",
        "protocol": "TCP", "dst_port": 443,
        "payload_pattern": rb"\x18\x03[\x01\x02\x03]\x00\x03\x01\x40\x00",
        "flags": None, "description": "OpenSSL Heartbleed memory read attempt",
        "mitre": "T1190",
    },
    # Web attacks
    {
        "id": "IDS-020", "name": "SQL Injection Attempt",
        "severity": "high", "category": "Web Attack",
        "protocol": "TCP", "dst_port": 80,
        "payload_pattern": rb"(?i)(union\s+select|or\s+1\s*=\s*1|drop\s+table|exec\s+xp_)",
        "flags": None, "description": "SQL injection payload in HTTP request",
        "mitre": "T1190",
    },
    {
        "id": "IDS-021", "name": "Directory Traversal",
        "severity": "high", "category": "Web Attack",
        "protocol": "TCP", "dst_port": 80,
        "payload_pattern": rb"(\.\./){3,}|%2e%2e%2f",
        "flags": None, "description": "Path traversal attack pattern",
        "mitre": "T1083",
    },
    {
        "id": "IDS-022", "name": "Command Injection",
        "severity": "critical", "category": "Web Attack",
        "protocol": "TCP", "dst_port": 80,
        "payload_pattern": rb"(?i)(;|\||\`|\$\()\s*(cat|ls|id|whoami|wget|curl|nc|bash|sh)\b",
        "flags": None, "description": "OS command injection in HTTP request",
        "mitre": "T1059",
    },
    # Malware C2
    {
        "id": "IDS-030", "name": "Metasploit Meterpreter",
        "severity": "critical", "category": "Malware C2",
        "protocol": "TCP", "dst_port": 4444,
        "payload_pattern": rb"\x4d\x5a\x90\x00",  # MZ header over network
        "flags": None, "description": "Metasploit Meterpreter reverse shell payload",
        "mitre": "T1071",
    },
    {
        "id": "IDS-031", "name": "Cobalt Strike Beacon",
        "severity": "critical", "category": "Malware C2",
        "protocol": "TCP", "dst_port": None,
        "payload_pattern": rb"(?i)(content-type: application/octet-stream.*\r\n){1}.*\x00\x00\x00\x00",
        "flags": None, "description": "Cobalt Strike beacon pattern detected",
        "mitre": "T1071.001",
    },
    # Brute force
    {
        "id": "IDS-040", "name": "SSH Brute Force",
        "severity": "high", "category": "Brute Force",
        "protocol": "TCP", "dst_port": 22,
        "rate_threshold": {"connections": 10, "window_sec": 60},
        "payload_pattern": None, "flags": None,
        "description": "Excessive SSH connection attempts",
        "mitre": "T1110",
    },
    {
        "id": "IDS-041", "name": "FTP Brute Force",
        "severity": "medium", "category": "Brute Force",
        "protocol": "TCP", "dst_port": 21,
        "rate_threshold": {"connections": 8, "window_sec": 60},
        "payload_pattern": None, "flags": None,
        "description": "FTP credential stuffing attempt",
        "mitre": "T1110",
    },
    # Lateral movement
    {
        "id": "IDS-050", "name": "SMB Lateral Movement",
        "severity": "high", "category": "Lateral Movement",
        "protocol": "TCP", "dst_port": 445,
        "payload_pattern": rb"(?i)PsExec|ADMIN\$|IPC\$",
        "flags": None, "description": "SMB-based lateral movement attempt",
        "mitre": "T1021.002",
    },
    {
        "id": "IDS-051", "name": "Pass-the-Hash (PTH) Attempt",
        "severity": "critical", "category": "Lateral Movement",
        "protocol": "TCP", "dst_port": 445,
        "payload_pattern": rb"\x60\x48\x06\x06\x2b\x06\x01\x05\x05\x02",  # NTLM SPNEGO
        "flags": None, "description": "NTLM Pass-the-Hash pattern detected",
        "mitre": "T1550.002",
    },
    # Data exfiltration
    {
        "id": "IDS-060", "name": "Large DNS TXT Exfil",
        "severity": "high", "category": "Exfiltration",
        "protocol": "UDP", "dst_port": 53,
        "payload_pattern": rb"[a-f0-9]{32,}\.(com|net|org|io)",
        "flags": None, "description": "DNS-based data exfiltration via encoded subdomains",
        "mitre": "T1048.003",
    },
    {
        "id": "IDS-061", "name": "ICMP Tunneling",
        "severity": "high", "category": "Exfiltration",
        "protocol": "ICMP", "dst_port": None,
        "payload_pattern": rb".{100,}",  # Unusually large ICMP payload
        "flags": None, "description": "ICMP payload exceeds normal size — possible tunnel",
        "mitre": "T1095",
    },
]


@dataclass
class IDSAlert:
    rule_id: str
    rule_name: str
    severity: str
    category: str
    src_ip: str
    dst_ip: str
    dst_port: int
    protocol: str
    description: str
    mitre: str
    timestamp: float
    payload_snippet: str = ""
    packet_count: int = 1
    suppressed: bool = False

    def fmt_time(self) -> str:
        return time.strftime("%H:%M:%S", time.localtime(self.timestamp))


@dataclass
class IDSResults:
    interface: str
    duration: int
    rules_loaded: int = 0
    packets_inspected: int = 0
    alerts: List[IDSAlert] = field(default_factory=list)
    suppressed_count: int = 0
    start_time: float = field(default_factory=time.time)
    end_time: float = 0.0

    def by_severity(self, sev: str) -> List[IDSAlert]:
        return [a for a in self.alerts if a.severity == sev]

    def by_category(self) -> Dict[str, int]:
        cats: Dict[str, int] = {}
        for a in self.alerts:
            cats[a.category] = cats.get(a.category, 0) + 1
        return dict(sorted(cats.items(), key=lambda x: -x[1]))


class IntrusionDetectionSystem:
    """
    Network Intrusion Detection System combining:
    - Signature-based detection (regex/byte pattern matching)
    - Rate-based detection (connection flooding, brute force)
    - Anomaly-based detection (protocol violations, unusual patterns)
    - Alert suppression (deduplication within time windows)
    """

    def __init__(self, args):
        self.args = args
        interface = getattr(args, "interface", "eth0")
        duration = getattr(args, "duration", 60)
        self.results = IDSResults(interface=interface, duration=duration)
        self._rules = list(BUILTIN_RULES)
        self._alert_suppress: Dict[str, float] = {}  # rule_id+src_ip → last_alert_time
        self._rate_tracker: Dict[str, List[float]] = collections.defaultdict(list)
        self._compiled_patterns: Dict[str, Optional[re.Pattern]] = {}
        self._alert_counter = 0
        self._live_display = None

        # Load custom rules
        rules_file = getattr(args, "rules", None)
        if rules_file and Path(rules_file).exists():
            self._load_custom_rules(rules_file)

        # Compile all patterns
        for rule in self._rules:
            pat = rule.get("payload_pattern")
            if pat:
                try:
                    self._compiled_patterns[rule["id"]] = re.compile(pat, re.DOTALL | re.IGNORECASE)
                except re.error:
                    self._compiled_patterns[rule["id"]] = None
            else:
                self._compiled_patterns[rule["id"]] = None

        self.results.rules_loaded = len(self._rules)

    def _load_custom_rules(self, path: str):
        """Load YAML/JSON custom rules from file."""
        try:
            import yaml
            with open(path) as f:
                custom = yaml.safe_load(f)
                if isinstance(custom, list):
                    self._rules.extend(custom)
                    console.print(f"  [green]✓[/green] Loaded {len(custom)} custom rules from {path}")
        except ImportError:
            try:
                with open(path) as f:
                    custom = json.load(f)
                    if isinstance(custom, list):
                        self._rules.extend(custom)
            except Exception as e:
                console.print(f"  [yellow]⚠ Could not load rules from {path}: {e}[/yellow]")

    def _should_suppress(self, rule_id: str, src_ip: str, window: float = 30.0) -> bool:
        """Suppress duplicate alerts within a time window."""
        key = f"{rule_id}:{src_ip}"
        last = self._alert_suppress.get(key, 0)
        if time.time() - last < window:
            self.results.suppressed_count += 1
            return True
        self._alert_suppress[key] = time.time()
        return False

    def _fire_alert(self, rule: Dict, src_ip: str, dst_ip: str, dst_port: int,
                    protocol: str, payload: bytes = b"") -> Optional[IDSAlert]:
        """Create and record an IDS alert."""
        if self._should_suppress(rule["id"], src_ip):
            return None

        # Filter by alert level
        level_order = ["info", "low", "medium", "high", "critical"]
        min_level = getattr(self.args, "alert_level", "medium")
        if level_order.index(rule["severity"]) < level_order.index(min_level):
            return None

        payload_snip = ""
        if payload:
            try:
                payload_snip = payload[:80].decode("utf-8", errors="replace").replace("\n", " ")
            except Exception:
                payload_snip = payload[:40].hex()

        self._alert_counter += 1
        alert = IDSAlert(
            rule_id=rule["id"],
            rule_name=rule["name"],
            severity=rule["severity"],
            category=rule["category"],
            src_ip=src_ip,
            dst_ip=dst_ip,
            dst_port=dst_port,
            protocol=protocol,
            description=rule["description"],
            mitre=rule.get("mitre", ""),
            timestamp=time.time(),
            payload_snippet=payload_snip,
        )
        self.results.alerts.append(alert)

        sev_colors = {
            "critical": "bold red", "high": "red",
            "medium": "yellow", "low": "cyan", "info": "dim"
        }
        color = sev_colors.get(rule["severity"], "white")
        console.print(
            f"  [{color}]▲ [{rule['id']}] {rule['severity'].upper()}[/{color}] "
            f"[white]{rule['name']}[/white] "
            f"[dim]{src_ip} → {dst_ip}:{dst_port}[/dim]"
        )
        return alert

    def inspect_packet(self, src_ip: str, dst_ip: str, dst_port: int,
                       protocol: str, flags: str = "", payload: bytes = b""):
        """
        Inspect a single packet against all loaded rules.
        Called per-packet from packet capture loop.
        """
        self.results.packets_inspected += 1
        now = time.time()

        for rule in self._rules:
            # Protocol filter
            rule_proto = rule.get("protocol")
            if rule_proto and rule_proto != protocol:
                continue

            # Port filter
            rule_port = rule.get("dst_port")
            if rule_port and rule_port != dst_port:
                continue

            # TCP flags check
            rule_flags = rule.get("flags")
            if rule_flags is not None and protocol == "TCP":
                if rule_flags == "FPU":  # XMAS: FIN+PSH+URG
                    if not ("F" in flags and "P" in flags and "U" in flags):
                        continue
                elif rule_flags == "SF":  # SYN+FIN (illegal)
                    if not ("S" in flags and "F" in flags):
                        continue
                elif rule_flags == "":  # NULL scan
                    if flags:
                        continue

            # Rate-based rule
            rate_cfg = rule.get("rate_threshold")
            if rate_cfg:
                rate_key = f"{rule['id']}:{src_ip}"
                self._rate_tracker[rate_key].append(now)
                self._rate_tracker[rate_key] = [
                    t for t in self._rate_tracker[rate_key]
                    if now - t < rate_cfg["window_sec"]
                ]
                if len(self._rate_tracker[rate_key]) >= rate_cfg["connections"]:
                    self._fire_alert(rule, src_ip, dst_ip, dst_port, protocol, payload)
                continue

            # Payload pattern match
            pattern = self._compiled_patterns.get(rule["id"])
            if pattern and payload:
                if pattern.search(payload):
                    self._fire_alert(rule, src_ip, dst_ip, dst_port, protocol, payload)
            elif not pattern and not rate_cfg:
                # Flag-only rule (already matched above)
                self._fire_alert(rule, src_ip, dst_ip, dst_port, protocol, payload)

    async def run(self):
        """Run IDS in live capture mode."""
        console.print(f"\n[bold cyan]Intrusion Detection System[/bold cyan]")
        console.print(f"  Interface: [white]{self.results.interface}[/white] | "
                      f"Rules: [cyan]{self.results.rules_loaded}[/cyan] | "
                      f"Duration: [cyan]{self.results.duration}s[/cyan]\n")

        try:
            import scapy.all as scapy
            from scapy.layers.inet import IP, TCP, UDP, ICMP
        except ImportError:
            console.print("[red]✗ Scapy required for IDS. Install: pip install scapy[/red]")
            return

        import os
        if os.geteuid() != 0:
            console.print("[yellow]⚠  Root privileges recommended for packet capture.[/yellow]\n")

        console.print("[dim]Monitoring for intrusions... Press Ctrl+C to stop.[/dim]\n")

        def pkt_handler(pkt):
            if not pkt.haslayer(IP):
                return
            ip = pkt[IP]
            proto = "OTHER"
            dst_port = 0
            flags = ""
            payload = b""

            if pkt.haslayer(TCP):
                tcp = pkt[TCP]
                proto = "TCP"
                dst_port = tcp.dport
                flag_map = {0x01: "F", 0x02: "S", 0x04: "R", 0x08: "P",
                            0x10: "A", 0x20: "U"}
                flags = "".join(v for k, v in flag_map.items() if tcp.flags & k)
                if tcp.payload:
                    payload = bytes(tcp.payload)
            elif pkt.haslayer(UDP):
                udp = pkt[UDP]
                proto = "UDP"
                dst_port = udp.dport
                if udp.payload:
                    payload = bytes(udp.payload)
            elif pkt.haslayer(ICMP):
                proto = "ICMP"
                if pkt[ICMP].payload:
                    payload = bytes(pkt[ICMP].payload)

            self.inspect_packet(ip.src, ip.dst, dst_port, proto, flags, payload)

        loop = asyncio.get_event_loop()
        await loop.run_in_executor(
            None,
            lambda: scapy.sniff(
                iface=self.results.interface,
                prn=pkt_handler,
                timeout=self.results.duration,
                store=False,
            )
        )

        self.results.end_time = time.time()
        self._print_results()

    def _print_results(self):
        """Display IDS session summary."""
        console.print()
        r = self.results

        if not r.alerts:
            console.print(
                f"[green]✓ No intrusions detected.[/green] "
                f"[dim]({r.packets_inspected:,} packets inspected)[/dim]"
            )
            return

        # Category breakdown
        cats = r.by_category()
        cat_str = " | ".join(f"[cyan]{c}[/cyan]: {n}" for c, n in cats.items())
        console.print(f"  Categories: {cat_str}")

        table = Table(
            title=f"IDS Alerts ({len(r.alerts)}) — {r.packets_inspected:,} packets inspected",
            box=box.ROUNDED,
            border_style="red",
            show_lines=True,
        )
        table.add_column("Time", style="dim", width=10)
        table.add_column("Rule ID", style="cyan", width=9)
        table.add_column("Severity", width=11)
        table.add_column("Name", style="white", min_width=22)
        table.add_column("Source", style="white")
        table.add_column("Category", style="dim")
        table.add_column("MITRE", style="dim", width=12)

        sev_colors = {
            "critical": "bold red", "high": "red",
            "medium": "yellow", "low": "cyan", "info": "dim"
        }

        for alert in sorted(r.alerts, key=lambda a: a.timestamp):
            color = sev_colors.get(alert.severity, "white")
            table.add_row(
                alert.fmt_time(),
                alert.rule_id,
                f"[{color}]{alert.severity.upper()}[/{color}]",
                alert.rule_name,
                f"{alert.src_ip}",
                alert.category,
                alert.mitre,
            )

        console.print(table)
        crit = len(r.by_severity("critical")) + len(r.by_severity("high"))
        console.print(
            f"\n  [dim]Suppressed duplicate alerts:[/dim] {r.suppressed_count} | "
            f"[red]{crit} critical/high[/red] alerts require immediate attention"
        )

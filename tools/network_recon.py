"""
Network Reconnaissance Module — DNS enumeration, WHOIS, ARP scanning, traceroute, service enumeration.
"""

import asyncio
import socket
import subprocess
import time
import ipaddress
from dataclasses import dataclass, field
from typing import List, Dict, Optional
from rich.console import Console
from rich.table import Table
from rich.tree import Tree
from rich import box

console = Console()

# Common DNS record types
DNS_RECORD_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "SOA", "CNAME", "PTR", "SRV", "CAA"]

# Common subdomains to bruteforce
COMMON_SUBDOMAINS = [
    "www", "mail", "ftp", "admin", "api", "dev", "staging", "test",
    "vpn", "remote", "portal", "cdn", "static", "assets", "blog",
    "shop", "store", "login", "auth", "oauth", "sso", "ldap",
    "smtp", "imap", "pop", "mx1", "mx2", "ns1", "ns2", "dns",
    "git", "gitlab", "github", "jenkins", "jira", "confluence",
    "monitor", "nagios", "zabbix", "kibana", "grafana", "elk",
    "backup", "old", "legacy", "demo", "beta", "app", "mobile",
]


@dataclass
class DNSRecord:
    record_type: str
    name: str
    value: str
    ttl: int = 0


@dataclass
class WhoisInfo:
    domain: str
    registrar: str = ""
    created: str = ""
    expires: str = ""
    updated: str = ""
    nameservers: List[str] = field(default_factory=list)
    org: str = ""
    country: str = ""
    raw: str = ""


@dataclass
class ARPHost:
    ip: str
    mac: str
    vendor: str = ""
    hostname: str = ""


@dataclass
class TracerouteHop:
    hop: int
    ip: str
    hostname: str = ""
    rtt_ms: float = 0.0


@dataclass
class ReconResults:
    target: str
    target_ip: str = ""
    dns_records: List[DNSRecord] = field(default_factory=list)
    subdomains: List[str] = field(default_factory=list)
    whois: Optional[WhoisInfo] = None
    arp_hosts: List[ARPHost] = field(default_factory=list)
    traceroute: List[TracerouteHop] = field(default_factory=list)
    open_services: Dict[str, str] = field(default_factory=dict)
    errors: List[str] = field(default_factory=list)


class NetworkRecon:
    """
    Passive and active network reconnaissance engine.
    DNS enum, WHOIS, ARP discovery, traceroute, service fingerprinting.
    """

    def __init__(self, target: str, args):
        self.target = target
        self.args = args
        self.results = ReconResults(target=target)

    async def _dns_enumerate(self) -> List[DNSRecord]:
        """Enumerate DNS records for target domain."""
        records = []
        try:
            import dns.resolver
            import dns.reversename

            # Extract domain from IP/CIDR
            try:
                ipaddress.ip_address(self.target)
                # Reverse DNS
                addr = dns.reversename.from_address(self.target)
                try:
                    ans = dns.resolver.resolve(addr, "PTR")
                    for r in ans:
                        records.append(DNSRecord("PTR", str(addr), str(r)))
                except Exception:
                    pass
                return records
            except ValueError:
                domain = self.target

            # Standard record enumeration
            for rtype in DNS_RECORD_TYPES:
                try:
                    answers = dns.resolver.resolve(domain, rtype, lifetime=5)
                    for r in answers:
                        records.append(DNSRecord(rtype, domain, str(r), answers.ttl))
                except Exception:
                    pass

        except ImportError:
            # Fallback: socket-based A record lookup
            try:
                answers = socket.getaddrinfo(self.target, None)
                for ans in answers:
                    records.append(DNSRecord("A", self.target, ans[4][0]))
            except Exception as e:
                self.results.errors.append(f"DNS: {e}")

        return records

    async def _subdomain_bruteforce(self, domain: str) -> List[str]:
        """Bruteforce common subdomains."""
        found = []
        loop = asyncio.get_event_loop()

        async def check_subdomain(sub: str):
            fqdn = f"{sub}.{domain}"
            try:
                await loop.run_in_executor(None, socket.gethostbyname, fqdn)
                found.append(fqdn)
            except socket.gaierror:
                pass

        tasks = [check_subdomain(sub) for sub in COMMON_SUBDOMAINS]
        await asyncio.gather(*tasks)
        return sorted(found)

    async def _whois_lookup(self, target: str) -> Optional[WhoisInfo]:
        """Perform WHOIS lookup."""
        try:
            import whois
            w = whois.whois(target)
            info = WhoisInfo(domain=target)
            info.registrar = str(w.registrar or "")
            info.org = str(w.org or "")
            info.country = str(w.country or "")
            info.raw = str(w.text or "")[:500]

            # Handle dates
            if w.creation_date:
                d = w.creation_date
                info.created = str(d[0] if isinstance(d, list) else d)
            if w.expiration_date:
                d = w.expiration_date
                info.expires = str(d[0] if isinstance(d, list) else d)
            if w.updated_date:
                d = w.updated_date
                info.updated = str(d[0] if isinstance(d, list) else d)

            if w.name_servers:
                ns = w.name_servers
                info.nameservers = list(ns) if isinstance(ns, list) else [str(ns)]

            return info

        except ImportError:
            # Fallback: system whois command
            try:
                result = subprocess.run(
                    ["whois", target], capture_output=True, text=True, timeout=15
                )
                info = WhoisInfo(domain=target, raw=result.stdout[:500])
                for line in result.stdout.split("\n"):
                    line_lower = line.lower()
                    if "registrar:" in line_lower and not info.registrar:
                        info.registrar = line.split(":", 1)[1].strip()
                    elif "creation date:" in line_lower and not info.created:
                        info.created = line.split(":", 1)[1].strip()
                    elif "registry expiry" in line_lower and not info.expires:
                        info.expires = line.split(":", 1)[1].strip()
                return info
            except Exception as e:
                self.results.errors.append(f"WHOIS: {e}")

        return None

    async def _arp_scan(self, network: str) -> List[ARPHost]:
        """ARP scan local network (requires root)."""
        hosts = []
        try:
            from scapy.layers.l2 import ARP, Ether
            from scapy.sendrecv import srp

            arp = ARP(pdst=network)
            ether = Ether(dst="ff:ff:ff:ff:ff:ff")
            packet = ether / arp

            result = srp(packet, timeout=3, verbose=False)[0]
            for sent, received in result:
                host = ARPHost(ip=received.psrc, mac=received.hwsrc)
                # Reverse DNS
                try:
                    host.hostname = socket.gethostbyaddr(received.psrc)[0]
                except Exception:
                    pass
                hosts.append(host)

        except ImportError:
            # Fallback: ping sweep
            try:
                net = ipaddress.ip_network(network, strict=False)
                loop = asyncio.get_event_loop()

                async def ping(ip_str: str):
                    result = await loop.run_in_executor(
                        None,
                        lambda: subprocess.run(
                            ["ping", "-c", "1", "-W", "1", ip_str],
                            capture_output=True, timeout=2
                        )
                    )
                    if result.returncode == 0:
                        host = ARPHost(ip=ip_str, mac="(ping only)")
                        try:
                            host.hostname = socket.gethostbyaddr(ip_str)[0]
                        except Exception:
                            pass
                        hosts.append(host)

                tasks = [ping(str(ip)) for ip in list(net.hosts())[:254]]
                await asyncio.gather(*tasks)

            except Exception as e:
                self.results.errors.append(f"ARP/Ping scan: {e}")

        except Exception as e:
            self.results.errors.append(f"ARP scan: {e}")

        return sorted(hosts, key=lambda h: ipaddress.ip_address(h.ip))

    async def _traceroute(self, target: str) -> List[TracerouteHop]:
        """Run system traceroute."""
        hops = []
        try:
            import platform
            cmd = ["traceroute", "-n", "-m", "20", target]
            if platform.system() == "Windows":
                cmd = ["tracert", "-d", "-h", "20", target]

            loop = asyncio.get_event_loop()
            result = await loop.run_in_executor(
                None,
                lambda: subprocess.run(cmd, capture_output=True, text=True, timeout=30)
            )

            for line in result.stdout.split("\n")[1:]:
                line = line.strip()
                if not line:
                    continue
                parts = line.split()
                if not parts or not parts[0].isdigit():
                    continue
                hop_num = int(parts[0])
                ip = next((p for p in parts[1:] if _is_ip(p)), "*")
                rtt = 0.0
                for p in parts:
                    try:
                        rtt = float(p.replace("ms", ""))
                        break
                    except ValueError:
                        pass

                hops.append(TracerouteHop(hop=hop_num, ip=ip, rtt_ms=rtt))

        except Exception as e:
            self.results.errors.append(f"Traceroute: {e}")

        return hops

    async def run(self):
        """Run configured recon modules."""
        console.print(f"\n[bold cyan]Network Recon[/bold cyan] → [white]{self.target}[/white]\n")

        # Resolve target
        try:
            self.results.target_ip = socket.gethostbyname(self.target)
        except Exception:
            self.results.target_ip = self.target

        tasks = []

        # DNS enumeration
        console.print("  [dim]→[/dim] DNS enumeration...")
        dns_records = await self._dns_enumerate()
        self.results.dns_records = dns_records

        # Is it a domain? Try subdomain enum
        try:
            ipaddress.ip_address(self.target)
        except ValueError:
            console.print("  [dim]→[/dim] Subdomain discovery...")
            subs = await self._subdomain_bruteforce(self.target)
            self.results.subdomains = subs

        # WHOIS
        if not hasattr(self.args, "whois") or self.args.whois or True:
            console.print("  [dim]→[/dim] WHOIS lookup...")
            self.results.whois = await self._whois_lookup(self.target)

        # ARP scan
        try:
            net = ipaddress.ip_network(self.target, strict=False)
            if net.prefixlen >= 16:
                console.print(f"  [dim]→[/dim] ARP/Ping sweep {self.target}...")
                self.results.arp_hosts = await self._arp_scan(self.target)
        except ValueError:
            pass

        # Traceroute
        console.print("  [dim]→[/dim] Traceroute...")
        self.results.traceroute = await self._traceroute(self.results.target_ip)

        self._print_results()

    def _print_results(self):
        """Display recon findings."""
        console.print()
        r = self.results

        # DNS Records
        if r.dns_records:
            dns_table = Table(title="DNS Records", box=box.ROUNDED, border_style="cyan")
            dns_table.add_column("Type", style="cyan", width=8)
            dns_table.add_column("Name", style="dim")
            dns_table.add_column("Value", style="white")
            dns_table.add_column("TTL", justify="right", style="dim", width=8)
            for rec in r.dns_records[:30]:
                dns_table.add_row(rec.record_type, rec.name, rec.value, str(rec.ttl))
            console.print(dns_table)

        # Subdomains
        if r.subdomains:
            console.print(f"\n[bold]Discovered Subdomains[/bold] ({len(r.subdomains)}):")
            for sub in r.subdomains:
                console.print(f"  [green]✓[/green] {sub}")

        # WHOIS
        if r.whois:
            w = r.whois
            console.print(f"\n[bold]WHOIS[/bold] — {w.domain}")
            if w.registrar:
                console.print(f"  Registrar: [white]{w.registrar}[/white]")
            if w.org:
                console.print(f"  Org: [white]{w.org}[/white]")
            if w.created:
                console.print(f"  Created: [white]{w.created}[/white]")
            if w.expires:
                console.print(f"  Expires: [white]{w.expires}[/white]")
            if w.nameservers:
                console.print(f"  Nameservers: {', '.join(w.nameservers[:4])}")

        # ARP hosts
        if r.arp_hosts:
            arp_table = Table(title=f"Live Hosts ({len(r.arp_hosts)})", box=box.ROUNDED, border_style="cyan")
            arp_table.add_column("IP", style="cyan")
            arp_table.add_column("MAC", style="dim")
            arp_table.add_column("Hostname", style="white")
            for h in r.arp_hosts:
                arp_table.add_row(h.ip, h.mac, h.hostname or "—")
            console.print(f"\n")
            console.print(arp_table)

        # Traceroute
        if r.traceroute:
            console.print(f"\n[bold]Traceroute[/bold] → {r.target}")
            for hop in r.traceroute:
                rtt_str = f"[dim]{hop.rtt_ms:.1f}ms[/dim]" if hop.rtt_ms else ""
                ip_str = hop.ip if hop.ip != "*" else "[dim]*[/dim]"
                console.print(f"  [cyan]{hop.hop:2d}[/cyan]  {ip_str}  {rtt_str}")

        if r.errors:
            for err in r.errors:
                console.print(f"  [yellow]⚠ {err}[/yellow]")


def _is_ip(s: str) -> bool:
    """Check if string looks like an IP address."""
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False

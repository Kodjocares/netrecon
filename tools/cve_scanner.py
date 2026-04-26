"""
CVE Scanner — Maps discovered services to known CVEs via NVD API and local cache.
Integrates with port scanner results to produce exploitability scores.
"""
import asyncio
import aiohttp
import json
import time
import re
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Tuple
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE_FILE = Path(".cve_cache.json")
CACHE_TTL = 86400  # 24 hours

# Built-in offline CVE signatures for common services
# Format: (service_pattern, version_pattern, cve_id, cvss, description)
OFFLINE_SIGNATURES: List[Tuple] = [
    ("apache", r"2\.4\.4[89]", "CVE-2021-41773", 9.8, "Path traversal and RCE in Apache 2.4.49-50"),
    ("apache", r"2\.4\.(1[0-9]|2[0-9]|3[0-9]|4[0-8])", "CVE-2021-40438", 9.0, "SSRF via mod_proxy in Apache"),
    ("openssh", r"[5-7]\.", "CVE-2023-38408", 9.8, "Remote code execution via ssh-agent forwarding"),
    ("openssh", r"[1-7]\.[0-9]", "CVE-2016-0777", 6.4, "Roaming feature information leak"),
    ("nginx", r"1\.(1[0-7]|[0-9])\.", "CVE-2021-23017", 7.7, "Off-by-one heap write in resolver"),
    ("iis", r"[5-9]\.|10\.0", "CVE-2017-7269", 10.0, "WebDAV buffer overflow — IIS 6.0"),
    ("mysql", r"[45]\.", "CVE-2012-2122", 7.5, "Authentication bypass via timing attack"),
    ("mysql", r"5\.[56]\.", "CVE-2016-6662", 9.0, "RCE via malicious config file"),
    ("postgresql", r"[89]\.|1[0-3]\.", "CVE-2019-10164", 8.8, "Stack overflow in SCRAM verifier"),
    ("redis", r"[2-6]\.", "CVE-2022-0543", 10.0, "Lua sandbox escape — RCE"),
    ("redis", r"[2-5]\.", "CVE-2015-8080", 7.5, "Integer overflow in Lua"),
    ("mongodb", r"[2-4]\.", "CVE-2019-2389", 5.9, "MITM via IP address spoofing"),
    ("elasticsearch", r"[0-6]\.", "CVE-2014-3120", 10.0, "Remote code execution via dynamic scripting"),
    ("log4j", r"2\.(0|1[0-4])\.", "CVE-2021-44228", 10.0, "Log4Shell — JNDI injection RCE"),
    ("spring", r"5\.[0-2]\.", "CVE-2022-22965", 9.8, "Spring4Shell — RCE via data binding"),
    ("tomcat", r"[7-9]\.|10\.[01]", "CVE-2020-1938", 9.8, "AJP Ghostcat — file read/RCE"),
    ("tomcat", r"[6-9]\.", "CVE-2019-0232", 8.1, "CGI Servlet RCE on Windows"),
    ("jenkins", r".*", "CVE-2019-1003000", 8.8, "Remote code execution via script security bypass"),
    ("vsftpd", r"2\.3\.4", "CVE-2011-2523", 10.0, "Backdoor in vsftpd 2.3.4"),
    ("samba", r"3\.[0-5]\.", "CVE-2017-7494", 9.8, "SambaCry — RCE via shared library"),
    ("openssl", r"1\.0\.", "CVE-2014-0160", 7.5, "Heartbleed — memory read"),
    ("openssl", r"1\.[01]\.", "CVE-2016-0800", 5.9, "DROWN — SSLv2 cross-protocol attack"),
    ("php", r"[5-7]\.[0-3]", "CVE-2019-11043", 9.8, "RCE in FPM/FastCGI with nginx"),
    ("drupal", r"[678]\.", "CVE-2018-7600", 9.8, "Drupalgeddon 2 — RCE"),
    ("wordpress", r"[34]\.", "CVE-2019-8943", 8.8, "Path traversal to RCE"),
    ("struts", r"2\.[0-5]\.", "CVE-2017-5638", 10.0, "Equifax breach — RCE via Content-Type"),
    ("jboss", r"[4-7]\.", "CVE-2017-12149", 9.8, "Deserialization RCE in JBoss"),
    ("exchange", r"201[56789]|2016|2019", "CVE-2021-26855", 9.8, "ProxyLogon — pre-auth SSRF"),
    ("citrix", r".*", "CVE-2019-19781", 9.8, "Citrix ADC — path traversal RCE"),
    ("pulse", r".*", "CVE-2019-11510", 10.0, "Pulse Secure VPN — arbitrary file read"),
    ("fortinet", r".*", "CVE-2018-13379", 9.8, "FortiOS SSL VPN path traversal"),
]

CVSS_SEVERITY = {
    (9.0, 10.0): ("CRITICAL", "#ff2d55"),
    (7.0, 8.9):  ("HIGH",     "#ff6b00"),
    (4.0, 6.9):  ("MEDIUM",   "#ffd600"),
    (0.0, 3.9):  ("LOW",      "#00e5ff"),
}

def cvss_label(score: float) -> Tuple[str, str]:
    for (lo, hi), (label, color) in CVSS_SEVERITY.items():
        if lo <= score <= hi:
            return label, color
    return "UNKNOWN", "#4a7a9b"


@dataclass
class CVEFinding:
    cve_id: str
    service: str
    version: str
    port: int
    cvss_score: float
    severity: str
    description: str
    source: str = "offline"
    published: str = ""
    exploit_available: bool = False


@dataclass
class CVEResults:
    start_time: float
    end_time: float = 0.0
    findings: List[CVEFinding] = field(default_factory=list)
    services_checked: int = 0
    api_hits: int = 0

    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity in ("CRITICAL", "HIGH"))

    def by_severity(self) -> Dict[str, List[CVEFinding]]:
        out: Dict[str, List[CVEFinding]] = {}
        for f in self.findings:
            out.setdefault(f.severity, []).append(f)
        return out


class CVEScanner:
    """
    CVE Scanner — correlates service banners with known vulnerabilities.
    Uses offline signatures for instant results + optional NVD API for live lookups.
    """

    def __init__(self, args):
        self.args = args
        self.results = CVEResults(start_time=time.time())
        self._cache: Dict[str, dict] = {}
        self._load_cache()
        self._seen: set = set()

    def _load_cache(self):
        if CACHE_FILE.exists():
            try:
                data = json.loads(CACHE_FILE.read_text())
                now = time.time()
                self._cache = {k: v for k, v in data.items()
                               if now - v.get("cached_at", 0) < CACHE_TTL}
            except Exception:
                self._cache = {}

    def _save_cache(self):
        try:
            CACHE_FILE.write_text(json.dumps(self._cache, indent=2))
        except Exception:
            pass

    def _normalize_banner(self, banner: str) -> Tuple[str, str]:
        """Extract service name and version from a banner string."""
        banner = banner.lower().strip()
        patterns = [
            (r"(apache)[/ ](\d+\.\d+\.?\d*)", "apache"),
            (r"(nginx)[/ ](\d+\.\d+\.?\d*)", "nginx"),
            (r"(openssh)[_/ ](\d+\.\d+\.?\d*)", "openssh"),
            (r"(openssl)[/ ](\d+\.\d+\.?\d*)", "openssl"),
            (r"(mysql|mariadb)[/ ](\d+\.\d+\.?\d*)", "mysql"),
            (r"(postgresql)[/ ](\d+\.\d+\.?\d*)", "postgresql"),
            (r"(redis)[/ ](\d+\.\d+\.?\d*)", "redis"),
            (r"(mongodb)[/ ](\d+\.\d+\.?\d*)", "mongodb"),
            (r"(php)[/ ](\d+\.\d+\.?\d*)", "php"),
            (r"(tomcat)[/ ](\d+\.\d+\.?\d*)", "tomcat"),
            (r"(jenkins)[/ ](\d+\.\d+\.?\d*)", "jenkins"),
            (r"(iis)[/ ](\d+\.\d+\.?\d*)", "iis"),
            (r"(vsftpd)[/ ](\d+\.\d+\.?\d*)", "vsftpd"),
            (r"(proftpd)[/ ](\d+\.\d+\.?\d*)", "proftpd"),
            (r"(samba)[/ ](\d+\.\d+\.?\d*)", "samba"),
            (r"(exchange)[/ ](\d+\.\d+\.?\d*)", "exchange"),
            (r"(spring)[/ ](\d+\.\d+\.?\d*)", "spring"),
            (r"(struts)[/ ](\d+\.\d+\.?\d*)", "struts"),
            (r"(drupal)[/ ](\d+\.\d+\.?\d*)", "drupal"),
            (r"(wordpress|wp)[/ ](\d+\.\d+\.?\d*)", "wordpress"),
        ]
        for pattern, name in patterns:
            m = re.search(pattern, banner)
            if m:
                return name, m.group(2)
        # Generic extraction
        m = re.search(r"([a-zA-Z][a-zA-Z0-9_-]+)[/ ](\d+\.\d+\.?\d*)", banner)
        if m:
            return m.group(1).lower(), m.group(2)
        return banner[:20], ""

    def check_service(self, port: int, banner: str, service_hint: str = "") -> List[CVEFinding]:
        """Check a service banner against offline CVE signatures."""
        findings = []
        service, version = self._normalize_banner(banner or service_hint)
        if not service:
            return findings

        self.results.services_checked += 1

        for (svc_pat, ver_pat, cve_id, cvss, desc) in OFFLINE_SIGNATURES:
            if svc_pat not in service:
                continue
            if version and ver_pat != ".*":
                if not re.search(ver_pat, version):
                    continue

            dedup = f"{cve_id}:{port}"
            if dedup in self._seen:
                continue
            self._seen.add(dedup)

            sev, color = cvss_label(cvss)
            finding = CVEFinding(
                cve_id=cve_id, service=service, version=version or "?",
                port=port, cvss_score=cvss, severity=sev,
                description=desc, source="offline",
            )
            findings.append(finding)
            self.results.findings.append(finding)

            console.print(
                f"  [{'bold red' if sev=='CRITICAL' else 'red' if sev=='HIGH' else 'yellow'}]"
                f"▲ {sev}[/] [{cve_id}] port {port}/{service} {version} "
                f"CVSS:{cvss} — {desc[:55]}"
            )

        return findings

    async def check_nvd_api(self, cve_id: str) -> Optional[dict]:
        """Fetch additional CVE details from NVD API."""
        if cve_id in self._cache:
            return self._cache[cve_id]

        use_api = getattr(self.args, "nvd_api", False)
        if not use_api:
            return None

        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(
                    NVD_API,
                    params={"cveId": cve_id},
                    timeout=aiohttp.ClientTimeout(total=5),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        vulns = data.get("vulnerabilities", [])
                        if vulns:
                            result = vulns[0].get("cve", {})
                            result["cached_at"] = time.time()
                            self._cache[cve_id] = result
                            self.results.api_hits += 1
                            self._save_cache()
                            return result
        except Exception:
            pass
        return None

    async def scan_services(self, services: List[Dict]):
        """
        Scan a list of services from port scanner results.
        services: [{"port": 80, "banner": "Apache/2.4.49", "service": "http"}, ...]
        """
        console.print(f"\n[bold cyan]CVE Scanner[/bold cyan]")
        console.print(f"  Checking {len(services)} services against {len(OFFLINE_SIGNATURES)} CVE signatures\n")

        for svc in services:
            port = svc.get("port", 0)
            banner = svc.get("banner", "") or svc.get("service", "")
            self.check_service(port, banner)
            await asyncio.sleep(0.01)

        # Optionally enrich with NVD API
        for finding in self.results.findings:
            await self.check_nvd_api(finding.cve_id)

        self.results.end_time = time.time()
        self._print_results()

    async def run(self):
        """Run CVE scanner against a target from args."""
        target = getattr(self.args, "target", "")
        console.print(f"\n[bold cyan]CVE Scanner — {target}[/bold cyan]")
        console.print("  Running port scan to discover services first...\n")

        from tools.port_scanner import PortScanner
        scanner = PortScanner(target, self.args)
        await scanner.run()

        services = []
        for result in getattr(scanner.results, "open_ports", []):
            services.append({
                "port": result.get("port", 0),
                "banner": result.get("banner", ""),
                "service": result.get("service", ""),
            })

        if services:
            await self.scan_services(services)
        else:
            console.print("[yellow]⚠ No open ports found to check for CVEs[/yellow]")
            self.results.end_time = time.time()

    def _print_results(self):
        console.print()
        r = self.results
        if not r.findings:
            console.print(f"[green]✓ No known CVEs matched {r.services_checked} services checked.[/green]")
            return

        table = Table(
            title=f"CVE Findings ({len(r.findings)}) — {r.services_checked} services checked",
            box=box.ROUNDED, border_style="red", show_lines=True,
        )
        table.add_column("CVE ID", style="cyan", width=18)
        table.add_column("Severity", width=11)
        table.add_column("CVSS", justify="center", width=7)
        table.add_column("Port", justify="right", width=7)
        table.add_column("Service", style="white", width=12)
        table.add_column("Description", min_width=40)

        sev_colors = {"CRITICAL": "bold red", "HIGH": "red", "MEDIUM": "yellow", "LOW": "cyan"}
        for f in sorted(r.findings, key=lambda x: -x.cvss_score):
            color = sev_colors.get(f.severity, "white")
            table.add_row(
                f.cve_id,
                f"[{color}]{f.severity}[/{color}]",
                f"[{color}]{f.cvss_score}[/{color}]",
                str(f.port),
                f"{f.service} {f.version}",
                f.description[:55],
            )
        console.print(table)
        console.print(
            f"\n  [red]{r.critical_count()} CRITICAL/HIGH CVEs[/red] require immediate patching"
        )

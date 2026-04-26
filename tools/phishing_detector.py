"""
Phishing Detection Module — Identifies phishing infrastructure, credential harvesting,
malicious redirects, typosquatting, and homograph attacks in network traffic.
"""

import asyncio
import re
import time
import socket
import difflib
import unicodedata
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set, Tuple
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box

console = Console()

# ─── Target brands for typosquatting detection ────────────────────────────────
PROTECTED_BRANDS: Dict[str, List[str]] = {
    "google": ["google.com", "gmail.com", "youtube.com"],
    "microsoft": ["microsoft.com", "office.com", "live.com", "hotmail.com", "outlook.com"],
    "apple": ["apple.com", "icloud.com"],
    "amazon": ["amazon.com", "aws.amazon.com"],
    "paypal": ["paypal.com"],
    "facebook": ["facebook.com", "instagram.com", "meta.com"],
    "netflix": ["netflix.com"],
    "bankofamerica": ["bankofamerica.com"],
    "chase": ["chase.com"],
    "wellsfargo": ["wellsfargo.com"],
    "linkedin": ["linkedin.com"],
    "dropbox": ["dropbox.com"],
    "github": ["github.com"],
    "twitter": ["twitter.com", "x.com"],
}

# All legitimate brand domains (flat set for fast lookup)
LEGITIMATE_DOMAINS: Set[str] = {
    d for domains in PROTECTED_BRANDS.values() for d in domains
}

# Phishing kit indicators in HTTP responses
PHISHING_PAGE_PATTERNS: List[Tuple[bytes, str, str]] = [
    (rb"(?i)(login|signin|verify).*password.*credit.?card", "generic", "Multi-field credential harvest form"),
    (rb"(?i)your account has been (suspended|compromised|locked)", "account_takeover", "Account suspension phishing lure"),
    (rb"(?i)verify.*identity.*ssn|social.security.*number", "identity", "SSN phishing attempt"),
    (rb"(?i)<input.*name=['\"]?(password|passwd|pass|pwd)['\"]?", "credential", "Password input field detected"),
    (rb"(?i)action=['\"]?https?://[^'\"\s]*(?!legit)", "form_steal", "Form posting to external domain"),
    (rb"(?i)document\.location\s*=|window\.location\s*=.*http", "redirect", "JavaScript redirect detected"),
    (rb"(?i)\.onion", "darkweb", "Tor hidden service reference"),
    (rb"(?i)urgently.*update.*payment|payment.*failed.*update", "payment", "Urgent payment phishing"),
    (rb"(?i)congratulations.*won|prize.*claim|lottery", "scam", "Prize/lottery scam content"),
]

# URL/domain red flags
SUSPICIOUS_URL_PATTERNS = [
    (r"(?i)(login|signin|secure|verify|account|update|confirm)\.((?!google|microsoft|apple|amazon|paypal|facebook|netflix|github|twitter|linkedin)[a-z0-9\-]+)\.(com|net|org|io|xyz|top|click|pw|tk)", "Credential phishing URL pattern"),
    (r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/(login|signin|account|verify|paypal|bank)", "IP-based phishing URL"),
    (r"(?i)(paypal|amazon|microsoft|google|apple|netflix)\.((?!com|co\.uk|de|fr|es|jp|com\.au)[a-z]{2,})\.", "Brand name in suspicious TLD"),
    (r"(?i)(paypal|amazon|microsoft|google|apple)-?(secure|verify|update|login)\.", "Brand with action word — typosquatting"),
    (r"(?i)https?://[^/]+(paypal|amazon|microsoft|google|apple)[^/]*\.[a-z]{2,}/", "Brand name in subdomain of foreign domain"),
]

# Email-delivered malware attachments (in SMTP traffic)
MALICIOUS_ATTACHMENT_EXTENSIONS = [
    b".exe", b".scr", b".bat", b".cmd", b".vbs", b".js", b".jse",
    b".wsf", b".wsh", b".msi", b".ps1", b".hta", b".jar", b".reg",
]

SMTP_PHISHING_PATTERNS = [
    (rb"(?i)Subject:.*urgent.*action|immediate.*action", "Urgency lure in email subject"),
    (rb"(?i)Subject:.*password.*expir|account.*suspend", "Password expiry phishing"),
    (rb"(?i)Content-Type:.*application/(octet-stream|zip|x-zip)", "Suspicious attachment type"),
    (rb"(?i)(invoice|receipt|order|shipment).*\.(exe|zip|js|vbs)", "Malicious attachment filename"),
]


@dataclass
class PhishingIndicator:
    indicator_type: str   # "typosquatting", "credential_harvest", "redirect", "smtp_phishing",
                          # "malicious_attachment", "homograph", "form_steal", "ip_phishing"
    severity: str
    url: str
    brand_targeted: str
    src_ip: str
    dst_ip: str
    description: str
    evidence: str
    timestamp: float
    confidence: float = 0.0   # 0.0–1.0


@dataclass
class PhishingResults:
    start_time: float
    end_time: float = 0.0
    indicators: List[PhishingIndicator] = field(default_factory=list)
    packets_analyzed: int = 0
    domains_analyzed: Set[str] = field(default_factory=set)
    phishing_domains: List[str] = field(default_factory=list)
    targeted_brands: Dict[str, int] = field(default_factory=dict)

    def critical_count(self) -> int:
        return sum(1 for i in self.indicators if i.severity in ("critical", "high"))


class PhishingDetector:
    """
    Network-level phishing detection engine:
    - Typosquatting and lookalike domain detection
    - Homograph attack detection (Unicode lookalikes)
    - Credential harvest page identification
    - SMTP phishing email analysis
    - Malicious attachment detection
    - Suspicious URL pattern matching
    - Brand impersonation via subdomain abuse
    """

    def __init__(self, args):
        self.args = args
        self.results = PhishingResults(start_time=time.time())
        self._alerted: Set[str] = set()
        self._compiled_url_patterns = [
            (re.compile(p, re.IGNORECASE), desc)
            for p, desc in SUSPICIOUS_URL_PATTERNS
        ]
        self._compiled_page_patterns = [
            (re.compile(pat, re.IGNORECASE | re.DOTALL), family, desc)
            for pat, family, desc in PHISHING_PAGE_PATTERNS
        ]

    def _add_indicator(self, ind_type: str, severity: str, url: str, brand: str,
                       src_ip: str, dst_ip: str, description: str, evidence: str,
                       confidence: float = 0.8) -> Optional[PhishingIndicator]:
        dedup_key = f"{ind_type}:{url}:{src_ip}"
        if dedup_key in self._alerted:
            return None
        self._alerted.add(dedup_key)

        ind = PhishingIndicator(
            indicator_type=ind_type, severity=severity,
            url=url, brand_targeted=brand, src_ip=src_ip, dst_ip=dst_ip,
            description=description, evidence=evidence,
            timestamp=time.time(), confidence=confidence,
        )
        self.results.indicators.append(ind)
        if url not in self.results.phishing_domains:
            self.results.phishing_domains.append(url[:80])
        if brand:
            self.results.targeted_brands[brand] = self.results.targeted_brands.get(brand, 0) + 1

        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}
        color = sev_colors.get(severity, "white")
        brand_tag = f" [yellow][{brand}][/yellow]" if brand else ""
        console.print(
            f"  [{color}]⚑ PHISHING {severity.upper()}[/{color}]{brand_tag} — "
            f"[white]{description}[/white] [dim]({url[:50]})[/dim]"
        )
        return ind

    def _detect_typosquatting(self, domain: str) -> Optional[Tuple[str, str, float]]:
        """
        Check if a domain is a typosquatting variant of a protected brand.
        Returns (brand_name, legitimate_domain, similarity_score) or None.
        """
        if not domain:
            return None

        # Strip www and TLD for comparison
        parts = domain.lower().replace("www.", "").split(".")
        if len(parts) < 2:
            return None
        domain_core = ".".join(parts[:-1])  # Remove TLD

        for brand, legit_domains in PROTECTED_BRANDS.items():
            for legit in legit_domains:
                legit_core = legit.split(".")[0]  # e.g. "paypal" from "paypal.com"

                # Exact legitimate domain — skip
                if domain.lower() in LEGITIMATE_DOMAINS:
                    return None

                # Similarity check
                similarity = difflib.SequenceMatcher(None, domain_core, legit_core).ratio()
                if 0.75 <= similarity < 1.0:
                    return (brand, legit, similarity)

                # Contains brand name but is not the legitimate domain
                if legit_core in domain_core and domain.lower() not in LEGITIMATE_DOMAINS:
                    return (brand, legit, 0.9)

        return None

    def _detect_homograph(self, domain: str) -> Optional[str]:
        """
        Detect homograph attacks (Unicode characters that look like ASCII).
        Returns ASCII representation if homograph detected.
        """
        try:
            ascii_domain = domain.encode("ascii").decode()
            return None  # Pure ASCII, not a homograph
        except UnicodeEncodeError:
            pass

        # Try to get IDNA representation
        try:
            idna = domain.encode("idna").decode()
            # Check if the IDNA form resembles a brand
            for brand in PROTECTED_BRANDS:
                if brand in idna.lower():
                    return idna
        except Exception:
            pass

        return None

    def analyze_dns_query(self, src_ip: str, dst_ip: str, domain: str):
        """Analyze a DNS query for phishing indicators."""
        if not domain:
            return
        self.results.domains_analyzed.add(domain)

        # Typosquatting
        typo_result = self._detect_typosquatting(domain)
        if typo_result:
            brand, legit, score = typo_result
            self._add_indicator(
                "typosquatting", "high",
                domain, brand, src_ip, dst_ip,
                f"Typosquatting domain resembles '{legit}' (score: {score:.0%})",
                f"Query for: {domain}",
                confidence=score,
            )

        # Homograph attack
        homograph = self._detect_homograph(domain)
        if homograph:
            self._add_indicator(
                "homograph", "critical",
                domain, "", src_ip, dst_ip,
                "Homograph attack — Unicode characters mimicking Latin letters",
                f"Domain: {domain} → IDNA: {homograph}",
                confidence=0.95,
            )

        # Suspicious URL patterns
        for pattern, desc in self._compiled_url_patterns:
            if pattern.search(domain):
                brand = next(
                    (b for b in PROTECTED_BRANDS if b in domain.lower()), ""
                )
                self._add_indicator(
                    "ip_phishing" if re.match(r"^\d+\.", domain) else "credential_harvest",
                    "high", domain, brand, src_ip, dst_ip, desc, f"Domain: {domain}"
                )
                break

    def analyze_http_payload(self, src_ip: str, dst_ip: str, url: str, payload: bytes):
        """Analyze HTTP response body for phishing page patterns."""
        if not payload:
            return
        self.results.packets_analyzed += 1

        for compiled_re, family, desc in self._compiled_page_patterns:
            if compiled_re.search(payload):
                brand = next(
                    (b for b in PROTECTED_BRANDS if b.encode() in payload.lower()[:500]), ""
                )
                self._add_indicator(
                    "credential_harvest" if "credential" in family or "form" in family else family,
                    "high" if "credential" in family else "medium",
                    url or dst_ip, brand, src_ip, dst_ip, desc,
                    payload[:80].decode("utf-8", errors="replace"),
                )
                break

    def analyze_smtp(self, src_ip: str, dst_ip: str, payload: bytes):
        """Analyze SMTP traffic for phishing emails."""
        if not payload:
            return
        for pattern, desc in SMTP_PHISHING_PATTERNS:
            if re.search(pattern, payload, re.IGNORECASE):
                self._add_indicator(
                    "smtp_phishing", "high",
                    f"{dst_ip}:25", "", src_ip, dst_ip,
                    desc, payload[:80].decode("utf-8", errors="replace"),
                )

        # Check for malicious attachments
        for ext in MALICIOUS_ATTACHMENT_EXTENSIONS:
            if ext in payload.lower():
                self._add_indicator(
                    "malicious_attachment", "critical",
                    f"{dst_ip}:25", "", src_ip, dst_ip,
                    f"Email with executable attachment: {ext.decode()}",
                    payload[:60].decode("utf-8", errors="replace"),
                )
                break

    def analyze_packet(self, src_ip: str, dst_ip: str, dst_port: int,
                       protocol: str, payload: bytes = b"", dns_query: str = ""):
        """Main packet analysis entry point."""
        self.results.packets_analyzed += 1

        if dns_query:
            self.analyze_dns_query(src_ip, dst_ip, dns_query)

        if payload and protocol == "TCP":
            if dst_port in (25, 465, 587):  # SMTP
                self.analyze_smtp(src_ip, dst_ip, payload)
            elif dst_port in (80, 8080, 443, 8443):  # HTTP/S
                # Try to extract URL from HTTP request
                url = ""
                host_match = re.search(rb"Host:\s*([^\r\n]+)", payload, re.IGNORECASE)
                path_match = re.search(rb"(?:GET|POST|PUT)\s+([^\s]+)", payload, re.IGNORECASE)
                if host_match and path_match:
                    url = f"{host_match.group(1).decode(errors='ignore')}{path_match.group(1).decode(errors='ignore')}"
                self.analyze_http_payload(src_ip, dst_ip, url, payload)

                # Check request URL for suspicious patterns
                if url:
                    for pattern, desc in self._compiled_url_patterns:
                        if pattern.search(url):
                            brand = next((b for b in PROTECTED_BRANDS if b in url.lower()), "")
                            self._add_indicator(
                                "credential_harvest", "high",
                                url, brand, src_ip, dst_ip, desc, f"URL: {url[:80]}"
                            )
                            break

    async def run(self):
        """Run phishing detection on live traffic."""
        interface = getattr(self.args, "interface", "eth0")
        duration = getattr(self.args, "duration", 60)

        console.print(f"\n[bold cyan]Phishing Detection Engine[/bold cyan]")
        console.print(
            f"  Interface: [white]{interface}[/white] | "
            f"Brands monitored: [cyan]{len(PROTECTED_BRANDS)}[/cyan] | "
            f"Duration: [cyan]{duration}s[/cyan]\n"
        )
        console.print("[dim]Scanning DNS queries, HTTP traffic, and SMTP for phishing...[/dim]\n")

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
                if pkt.haslayer(DNS) and pkt.haslayer(DNSQR):
                    dns_q = pkt[DNSQR].qname.decode(errors="ignore").rstrip(".")
                self.analyze_packet(ip.src, ip.dst, dst_port, proto, payload, dns_q)

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(
                None, lambda: scapy.sniff(iface=interface, prn=pkt_handler, timeout=duration, store=False)
            )
        except ImportError:
            console.print("[yellow]⚠ Scapy not available — running in passive mode.[/yellow]")

        self.results.end_time = time.time()
        self._print_results()

    def _print_results(self):
        """Display phishing detection results."""
        console.print()
        r = self.results

        if not r.indicators:
            console.print(
                f"[green]✓ No phishing activity detected.[/green] "
                f"[dim]({len(r.domains_analyzed)} domains analyzed)[/dim]"
            )
            return

        table = Table(
            title=f"Phishing Indicators ({len(r.indicators)})",
            box=box.ROUNDED, border_style="red", show_lines=True,
        )
        table.add_column("Type", style="cyan", width=18)
        table.add_column("Severity", width=11)
        table.add_column("Brand", style="yellow", width=12)
        table.add_column("URL / Domain", style="white", min_width=25)
        table.add_column("Description", min_width=30)
        table.add_column("Confidence", justify="right", width=10)

        sev_colors = {"critical": "bold red", "high": "red", "medium": "yellow", "low": "cyan"}
        for ind in sorted(r.indicators, key=lambda x: x.timestamp):
            color = sev_colors.get(ind.severity, "white")
            table.add_row(
                ind.indicator_type,
                f"[{color}]{ind.severity.upper()}[/{color}]",
                ind.brand_targeted or "—",
                ind.url[:40],
                ind.description[:45],
                f"{ind.confidence:.0%}",
            )
        console.print(table)

        if r.targeted_brands:
            brands_str = " | ".join(
                f"[yellow]{b}[/yellow]: {n}"
                for b, n in sorted(r.targeted_brands.items(), key=lambda x: -x[1])
            )
            console.print(f"\n  Targeted brands: {brands_str}")

        console.print(
            f"\n  {len(r.domains_analyzed)} domains analyzed | "
            f"[red]{r.critical_count()} critical/high[/red] | "
            f"{len(r.phishing_domains)} phishing domains identified"
        )

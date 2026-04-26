"""
Web Vulnerability Scanner — SQLi, XSS, LFI, SSRF, security headers, SSL/TLS analysis.
"""

import asyncio
import aiohttp
import ssl
import re
import urllib.parse
import time
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Set
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich import box

console = Console()

# ─── Test Payloads ─────────────────────────────────────────────────────────────

SQLI_PAYLOADS = [
    "' OR '1'='1",
    "' OR '1'='1' --",
    "\" OR \"1\"=\"1",
    "1; DROP TABLE users--",
    "1 UNION SELECT NULL,NULL,NULL--",
    "' AND SLEEP(5)--",
    "'; EXEC xp_cmdshell('whoami')--",
    "1' ORDER BY 1--",
    "1' ORDER BY 100--",
    "admin'--",
]

XSS_PAYLOADS = [
    "<script>alert('XSS')</script>",
    "<img src=x onerror=alert('XSS')>",
    "'\"><script>alert(1)</script>",
    "<svg onload=alert(1)>",
    "javascript:alert(1)",
    "<body onload=alert(1)>",
    "'-alert(1)-'",
    "<iframe src=javascript:alert(1)>",
]

LFI_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../../etc/passwd%00",
    "....//....//....//etc/passwd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "php://filter/convert.base64-encode/resource=index.php",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1/",
    "http://localhost/",
    "http://169.254.169.254/",          # AWS metadata
    "http://metadata.google.internal/", # GCP metadata
    "http://100.100.100.200/",          # Alibaba Cloud
    "dict://127.0.0.1:6379/INFO",       # Redis via SSRF
    "file:///etc/passwd",
    "gopher://127.0.0.1:25/",
]

# Security headers that should be present
SECURITY_HEADERS = {
    "Strict-Transport-Security": "HSTS not set — downgrade attacks possible",
    "X-Frame-Options": "Clickjacking protection missing",
    "X-Content-Type-Options": "MIME sniffing protection missing",
    "Content-Security-Policy": "CSP not set — XSS risk elevated",
    "X-XSS-Protection": "XSS filter header missing",
    "Referrer-Policy": "Referrer Policy not configured",
    "Permissions-Policy": "Permissions Policy not set",
}

# Headers that should NOT be exposed
SENSITIVE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-Generator"]


@dataclass
class Vulnerability:
    vuln_type: str
    severity: str   # info / low / medium / high / critical
    url: str
    parameter: str = ""
    payload: str = ""
    evidence: str = ""
    remediation: str = ""


@dataclass
class VulnResults:
    target: str
    start_time: float
    end_time: float = 0.0
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    scanned_urls: List[str] = field(default_factory=list)
    ssl_info: Dict = field(default_factory=dict)
    headers_analyzed: Dict = field(default_factory=dict)

    def by_severity(self, severity: str) -> List[Vulnerability]:
        return [v for v in self.vulnerabilities if v.severity == severity]

    def critical_count(self) -> int:
        return len(self.by_severity("critical")) + len(self.by_severity("high"))


class WebVulnScanner:
    """
    Async web vulnerability scanner covering OWASP Top 10 vectors.
    """

    def __init__(self, target: str, args):
        self.target = target.rstrip("/")
        if not self.target.startswith("http"):
            self.target = "https://" + self.target
        self.args = args
        self.results = VulnResults(target=self.target, start_time=time.time())
        self._session: Optional[aiohttp.ClientSession] = None
        self._visited: Set[str] = set()
        self._forms: List[Dict] = []

    async def _get_session(self) -> aiohttp.ClientSession:
        if self._session is None or self._session.closed:
            connector = aiohttp.TCPConnector(ssl=False)
            self._session = aiohttp.ClientSession(
                connector=connector,
                timeout=aiohttp.ClientTimeout(total=10),
                headers={"User-Agent": "NetRecon-Scanner/2.0 Security Audit"},
            )
        return self._session

    async def _fetch(self, url: str, method: str = "GET", data: Dict = None) -> Optional[aiohttp.ClientResponse]:
        """Fetch a URL, returning the response object."""
        try:
            session = await self._get_session()
            if method == "POST":
                return await session.post(url, data=data)
            else:
                return await session.get(url)
        except Exception:
            return None

    async def _crawl(self, url: str, depth: int = 0) -> List[str]:
        """Simple web crawler to discover URLs and forms."""
        if depth > self.args.crawl_depth or url in self._visited:
            return []
        self._visited.add(url)
        urls = [url]

        try:
            from bs4 import BeautifulSoup
            resp = await self._fetch(url)
            if not resp:
                return urls

            text = await resp.text()
            soup = BeautifulSoup(text, "html.parser")

            # Extract links
            for tag in soup.find_all("a", href=True):
                href = urllib.parse.urljoin(url, tag["href"])
                parsed = urllib.parse.urlparse(href)
                base = urllib.parse.urlparse(self.target)
                if parsed.netloc == base.netloc and href not in self._visited:
                    child_urls = await self._crawl(href, depth + 1)
                    urls.extend(child_urls)

            # Extract forms
            for form in soup.find_all("form"):
                action = urllib.parse.urljoin(url, form.get("action", url))
                method = form.get("method", "GET").upper()
                inputs = {}
                for inp in form.find_all(["input", "textarea", "select"]):
                    name = inp.get("name")
                    if name:
                        inputs[name] = inp.get("value", "test")
                if inputs:
                    self._forms.append({"action": action, "method": method, "inputs": inputs, "origin": url})

        except Exception:
            pass

        return urls

    async def _test_sqli(self, url: str, params: Dict) -> List[Vulnerability]:
        """Test URL parameters for SQL injection."""
        vulns = []
        sqli_errors = [
            "sql syntax", "mysql_fetch", "ora-01756", "sqlite error",
            "postgresql", "unclosed quotation", "syntax error", "sql error",
            "warning: mysql", "native client", "odbc", "jdbc",
        ]

        for param, value in params.items():
            for payload in SQLI_PAYLOADS[:5]:  # Limit for speed
                test_params = {**params, param: payload}
                test_url = f"{url}?{urllib.parse.urlencode(test_params)}"
                resp = await self._fetch(test_url)
                if not resp:
                    continue
                try:
                    text = (await resp.text()).lower()
                    for err in sqli_errors:
                        if err in text:
                            vulns.append(Vulnerability(
                                vuln_type="SQL Injection",
                                severity="critical",
                                url=test_url,
                                parameter=param,
                                payload=payload,
                                evidence=f"SQL error string detected: '{err}'",
                                remediation="Use parameterized queries / prepared statements. Never concatenate user input into SQL.",
                            ))
                            break
                except Exception:
                    pass

        return vulns

    async def _test_xss(self, url: str, params: Dict) -> List[Vulnerability]:
        """Test for reflected XSS."""
        vulns = []
        for param, value in params.items():
            for payload in XSS_PAYLOADS[:4]:
                test_params = {**params, param: payload}
                test_url = f"{url}?{urllib.parse.urlencode(test_params)}"
                resp = await self._fetch(test_url)
                if not resp:
                    continue
                try:
                    text = await resp.text()
                    if payload in text:
                        vulns.append(Vulnerability(
                            vuln_type="Reflected XSS",
                            severity="high",
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            evidence="Payload reflected unescaped in response",
                            remediation="HTML-encode all output. Implement CSP. Validate and sanitize inputs.",
                        ))
                        break
                except Exception:
                    pass

        return vulns

    async def _test_lfi(self, url: str) -> List[Vulnerability]:
        """Test for Local File Inclusion via path parameters."""
        vulns = []
        parsed = urllib.parse.urlparse(url)
        params = dict(urllib.parse.parse_qsl(parsed.query))

        file_params = [k for k in params if any(
            kw in k.lower() for kw in ("file", "path", "include", "page", "doc", "template", "load")
        )]

        for param in file_params:
            for payload in LFI_PAYLOADS[:4]:
                test_params = {**params, param: payload}
                test_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{urllib.parse.urlencode(test_params)}"
                resp = await self._fetch(test_url)
                if not resp:
                    continue
                try:
                    text = await resp.text()
                    if "root:x:" in text or "[extensions]" in text or "drivers" in text.lower():
                        vulns.append(Vulnerability(
                            vuln_type="Local File Inclusion (LFI)",
                            severity="critical",
                            url=test_url,
                            parameter=param,
                            payload=payload,
                            evidence="System file content detected in response",
                            remediation="Use allowlist for file paths. Never pass user input directly to filesystem functions.",
                        ))
                except Exception:
                    pass

        return vulns

    async def _analyze_headers(self, url: str) -> List[Vulnerability]:
        """Analyze HTTP security headers."""
        vulns = []
        resp = await self._fetch(url)
        if not resp:
            return vulns

        headers = {k.lower(): v for k, v in resp.headers.items()}
        self.results.headers_analyzed = dict(resp.headers)

        # Missing security headers
        for header, message in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                vulns.append(Vulnerability(
                    vuln_type=f"Missing Header: {header}",
                    severity="medium" if "CSP" in header or "HSTS" in header else "low",
                    url=url,
                    evidence=message,
                    remediation=f"Add '{header}' header to all HTTP responses.",
                ))

        # Information disclosure headers
        for header in SENSITIVE_HEADERS:
            if header.lower() in headers:
                vulns.append(Vulnerability(
                    vuln_type="Information Disclosure",
                    severity="low",
                    url=url,
                    evidence=f"Header '{header}: {headers[header.lower()]}' reveals technology stack",
                    remediation=f"Remove or obscure the '{header}' response header.",
                ))

        # Cookie security
        if "set-cookie" in headers:
            cookie = headers["set-cookie"]
            if "httponly" not in cookie.lower():
                vulns.append(Vulnerability(
                    vuln_type="Cookie Missing HttpOnly",
                    severity="medium",
                    url=url,
                    evidence="Session cookie lacks HttpOnly flag — XSS can steal it",
                    remediation="Set HttpOnly flag on all session cookies.",
                ))
            if "secure" not in cookie.lower():
                vulns.append(Vulnerability(
                    vuln_type="Cookie Missing Secure Flag",
                    severity="medium",
                    url=url,
                    evidence="Cookie can be transmitted over HTTP",
                    remediation="Set Secure flag on all session cookies.",
                ))
            if "samesite" not in cookie.lower():
                vulns.append(Vulnerability(
                    vuln_type="Cookie Missing SameSite",
                    severity="low",
                    url=url,
                    evidence="Cookie vulnerable to CSRF",
                    remediation="Set SameSite=Strict or SameSite=Lax on session cookies.",
                ))

        return vulns

    async def _analyze_ssl(self, url: str) -> Dict:
        """Analyze SSL/TLS configuration."""
        info = {}
        try:
            parsed = urllib.parse.urlparse(url)
            host = parsed.hostname
            port = parsed.port or 443

            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

            reader, writer = await asyncio.open_connection(host, port, ssl=ctx)
            ssl_obj = writer.get_extra_info("ssl_object")

            if ssl_obj:
                info["version"] = ssl_obj.version()
                info["cipher"] = ssl_obj.cipher()
                cert = ssl_obj.getpeercert()
                if cert:
                    info["subject"] = dict(x[0] for x in cert.get("subject", []))
                    info["issuer"] = dict(x[0] for x in cert.get("issuer", []))
                    info["expires"] = cert.get("notAfter", "Unknown")
                    info["san"] = cert.get("subjectAltName", [])

                # Warn on deprecated protocols
                version = info.get("version", "")
                if version in ("SSLv2", "SSLv3", "TLSv1", "TLSv1.1"):
                    self.results.vulnerabilities.append(Vulnerability(
                        vuln_type="Deprecated TLS/SSL Version",
                        severity="high",
                        url=url,
                        evidence=f"Server supports deprecated protocol: {version}",
                        remediation="Disable SSLv2, SSLv3, TLSv1.0, TLSv1.1. Use TLSv1.2+ only.",
                    ))

            writer.close()
            await writer.wait_closed()

        except Exception as e:
            info["error"] = str(e)

        self.results.ssl_info = info
        return info

    async def run(self):
        """Run all configured vulnerability checks."""
        console.print(f"\n[bold cyan]Web Vulnerability Scanner[/bold cyan] → [white]{self.target}[/white]\n")

        checks = []
        all_checks = self.args.all_vulns if hasattr(self.args, "all_vulns") else False

        with Progress(
            SpinnerColumn(style="cyan"),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(bar_width=30, style="cyan"),
            console=console,
        ) as progress:

            # Crawl
            crawl_task = progress.add_task("Crawling target...", total=None)
            urls = await self._crawl(self.target)
            self.results.scanned_urls = urls
            progress.update(crawl_task, description=f"Crawled [cyan]{len(urls)}[/cyan] URLs", completed=True)

            # Header analysis
            header_task = progress.add_task("Analyzing security headers...", total=None)
            header_vulns = await self._analyze_headers(self.target)
            self.results.vulnerabilities.extend(header_vulns)
            progress.update(header_task, completed=True, description=f"Headers: [{('red' if header_vulns else 'green')}]{len(header_vulns)} issues[/]")

            # SSL analysis
            if self.target.startswith("https") or (hasattr(self.args, "ssl") and self.args.ssl):
                ssl_task = progress.add_task("Analyzing SSL/TLS...", total=None)
                ssl_info = await self._analyze_ssl(self.target)
                progress.update(ssl_task, completed=True,
                                description=f"SSL: [cyan]{ssl_info.get('version', 'N/A')}[/cyan] | {ssl_info.get('cipher', ('—', '', ''))[0] if ssl_info.get('cipher') else 'N/A'}")

            # SQL injection
            if all_checks or (hasattr(self.args, "sqli") and self.args.sqli):
                sqli_task = progress.add_task("Testing SQL injection...", total=len(urls))
                for url in urls:
                    parsed = urllib.parse.urlparse(url)
                    params = dict(urllib.parse.parse_qsl(parsed.query))
                    if params:
                        vulns = await self._test_sqli(url, params)
                        self.results.vulnerabilities.extend(vulns)
                    progress.advance(sqli_task)
                sqli_vulns = [v for v in self.results.vulnerabilities if v.vuln_type == "SQL Injection"]
                progress.update(sqli_task, description=f"SQLi: [{'red' if sqli_vulns else 'green'}]{len(sqli_vulns)} found[/]")

            # XSS
            if all_checks or (hasattr(self.args, "xss") and self.args.xss):
                xss_task = progress.add_task("Testing XSS...", total=len(urls))
                for url in urls:
                    parsed = urllib.parse.urlparse(url)
                    params = dict(urllib.parse.parse_qsl(parsed.query))
                    if params:
                        vulns = await self._test_xss(url, params)
                        self.results.vulnerabilities.extend(vulns)
                    progress.advance(xss_task)
                xss_vulns = [v for v in self.results.vulnerabilities if "XSS" in v.vuln_type]
                progress.update(xss_task, description=f"XSS: [{'red' if xss_vulns else 'green'}]{len(xss_vulns)} found[/]")

            # LFI
            if all_checks or (hasattr(self.args, "lfi") and self.args.lfi):
                lfi_task = progress.add_task("Testing LFI...", total=len(urls))
                for url in urls:
                    vulns = await self._test_lfi(url)
                    self.results.vulnerabilities.extend(vulns)
                    progress.advance(lfi_task)

        if self._session and not self._session.closed:
            await self._session.close()

        self.results.end_time = time.time()
        self._print_results()

    def _print_results(self):
        """Display vulnerability findings."""
        console.print()

        if not self.results.vulnerabilities:
            console.print("[green]✓ No vulnerabilities detected.[/green]")
            return

        sev_colors = {
            "critical": "bold red",
            "high": "red",
            "medium": "yellow",
            "low": "cyan",
            "info": "dim white",
        }
        sev_icons = {"critical": "⬟", "high": "▲", "medium": "◆", "low": "●", "info": "ℹ"}

        table = Table(
            title=f"Vulnerabilities Found — {self.results.target}",
            box=box.ROUNDED,
            border_style="red",
            show_lines=True,
        )
        table.add_column("Severity", width=12)
        table.add_column("Type", style="white", min_width=25)
        table.add_column("URL / Parameter", style="dim", max_width=40)
        table.add_column("Evidence", max_width=45)

        for v in sorted(self.results.vulnerabilities, key=lambda x: ["critical","high","medium","low","info"].index(x.severity)):
            color = sev_colors.get(v.severity, "white")
            icon = sev_icons.get(v.severity, "●")
            url_short = v.url[:60] + "..." if len(v.url) > 60 else v.url
            table.add_row(
                f"[{color}]{icon} {v.severity.upper()}[/{color}]",
                v.vuln_type,
                url_short,
                v.evidence[:80],
            )

        console.print(table)

        # SSL info
        if self.results.ssl_info and "version" in self.results.ssl_info:
            ssl = self.results.ssl_info
            console.print(f"\n  [bold]SSL/TLS:[/bold] {ssl.get('version','?')} | Cipher: {ssl.get('cipher',['?'])[0]}")
            if "expires" in ssl:
                console.print(f"  Certificate expires: [cyan]{ssl['expires']}[/cyan]")

        critical = self.results.critical_count()
        console.print(
            f"\n  [bold]Total:[/bold] {len(self.results.vulnerabilities)} findings — "
            f"[{'red' if critical else 'green'}]{critical} critical/high[/]"
        )

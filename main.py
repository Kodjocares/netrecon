#!/usr/bin/env python3
"""
NetRecon v4.0 — Advanced Network Intelligence & Security Suite
18 modules total — for authorized security testing only.
"""

import argparse
import sys
import asyncio
from rich.console import Console
from rich.panel import Panel

from core.banner import print_banner
from tools.port_scanner        import PortScanner
from tools.packet_sniffer      import PacketSniffer
from tools.vuln_scanner        import WebVulnScanner
from tools.network_recon       import NetworkRecon
from tools.threat_detector     import ThreatDetector
from tools.ids                 import IntrusionDetectionSystem
from tools.spyware_detector    import SpywareDetector
from tools.ransomware_detector import RansomwareDetector
from tools.phishing_detector   import PhishingDetector
from tools.ddos_detector       import DDoSDetector
from tools.network_monitor     import NetworkMonitor
from tools.cve_scanner         import CVEScanner
from tools.malware_scanner     import MalwareHashScanner
from tools.honeypot            import HoneypotModule
from tools.api_server          import NetReconAPIServer
from tools.scheduler           import ScheduledScanner
from tools.pdf_report          import PDFReportGenerator
from utils.logger              import setup_logger
from utils.report              import ReportGenerator

console = Console()
logger  = setup_logger()


def parse_args():
    parser = argparse.ArgumentParser(
        description="NetRecon v4.0 — 18-Module Network Security Suite",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )

    parser.add_argument("target", nargs="?")

    # Original 11 modules
    parser.add_argument("--scan-ports",      action="store_true")
    parser.add_argument("--sniff",           metavar="IFACE")
    parser.add_argument("--vuln-scan",       action="store_true")
    parser.add_argument("--recon",           action="store_true")
    parser.add_argument("--detect-threats",  action="store_true")
    parser.add_argument("--ids",             action="store_true")
    parser.add_argument("--detect-spyware",  action="store_true")
    parser.add_argument("--detect-ransom",   action="store_true")
    parser.add_argument("--detect-phishing", action="store_true")
    parser.add_argument("--detect-ddos",     action="store_true")
    parser.add_argument("--monitor",         action="store_true")
    parser.add_argument("--full-audit",      action="store_true")

    # New v4.0 modules
    parser.add_argument("--cve-scan",     action="store_true", help="Map services to CVEs")
    parser.add_argument("--malware-scan", action="store_true", help="Hash-based malware detection")
    parser.add_argument("--honeypot",     action="store_true", help="Deploy decoy services")
    parser.add_argument("--api-server",   action="store_true", help="Start REST API server")
    parser.add_argument("--schedule",     action="store_true", help="Scheduled scan + alerting")
    parser.add_argument("--pdf-report",   metavar="FILE",      help="Generate PDF pentest report")

    # Port scanner
    parser.add_argument("-p", "--ports",   default="1-1024")
    parser.add_argument("--scan-type",     choices=["tcp","udp","syn","fin"], default="tcp")
    parser.add_argument("--threads",       type=int, default=100)
    parser.add_argument("--timeout",       type=float, default=1.0)
    parser.add_argument("--banner",        action="store_true")
    parser.add_argument("--os-detect",     action="store_true")

    # Capture
    parser.add_argument("--duration",      type=int, default=60)
    parser.add_argument("--filter",        metavar="BPF")
    parser.add_argument("--pcap",          metavar="FILE")
    parser.add_argument("--analyze",       action="store_true")

    # Web vuln
    parser.add_argument("--crawl-depth",   type=int, default=2)
    parser.add_argument("--sqli",          action="store_true")
    parser.add_argument("--xss",           action="store_true")
    parser.add_argument("--lfi",           action="store_true")
    parser.add_argument("--headers",       action="store_true")
    parser.add_argument("--ssl",           action="store_true")
    parser.add_argument("--all-vulns",     action="store_true")

    # Recon
    parser.add_argument("--dns",           action="store_true")
    parser.add_argument("--whois",         action="store_true")
    parser.add_argument("--traceroute",    action="store_true")
    parser.add_argument("--arp-scan",      action="store_true")

    # Detection
    parser.add_argument("--interface",     metavar="IFACE", default="eth0")
    parser.add_argument("--alert-level",   choices=["info","low","medium","high","critical"], default="medium")
    parser.add_argument("--block",         action="store_true")
    parser.add_argument("--rules",         metavar="FILE")

    # CVE
    parser.add_argument("--nvd-api",       action="store_true")
    parser.add_argument("--nvd-api-key",   default="")

    # Malware
    parser.add_argument("--vt-api-key",    default="")

    # Honeypot
    parser.add_argument("--honeypot-ports", metavar="PORTS")

    # API server
    parser.add_argument("--api-host",      default="127.0.0.1")
    parser.add_argument("--api-port",      type=int, default=8080)

    # Scheduler
    parser.add_argument("--schedule-module",   default="port")
    parser.add_argument("--schedule-target",   default="")
    parser.add_argument("--schedule-interval", type=float, default=24.0)
    parser.add_argument("--alert-email",       default="")
    parser.add_argument("--slack-webhook",     default="")
    parser.add_argument("--webhook-url",       default="")
    parser.add_argument("--run-now",           action="store_true")

    # Monitor
    parser.add_argument("--baseline",      type=int, default=300)
    parser.add_argument("--top-n",         type=int, default=10)

    # Output
    parser.add_argument("--output", "-o",  metavar="FILE")
    parser.add_argument("--format",        choices=["txt","json","html","csv"], default="html")
    parser.add_argument("--verbose", "-v", action="store_true")
    parser.add_argument("--quiet",  "-q",  action="store_true")

    return parser.parse_args()


async def _port(a,r):
    m=PortScanner(a.target,a); await m.run(); r.add_section("Port Scan",m.results); return m.results
async def _recon(a,r):
    m=NetworkRecon(a.target,a); await m.run(); r.add_section("Network Recon",m.results)
async def _vuln(a,r):
    m=WebVulnScanner(a.target,a); await m.run(); r.add_section("Web Vulnerabilities",m.results)
async def _sniffer(a,r):
    m=PacketSniffer(a.sniff or a.interface,a); await m.run(); r.add_section("Packet Capture",m.results)
async def _threats(a,r):
    m=ThreatDetector(a); await m.run_assessment(r.all_results()); r.add_section("Threat Assessment",m.results)
async def _ids(a,r):
    m=IntrusionDetectionSystem(a); await m.run(); r.add_section("IDS Alerts",m.results)
async def _spyware(a,r):
    m=SpywareDetector(a); await m.run(); r.add_section("Spyware Detection",m.results)
async def _ransomware(a,r):
    m=RansomwareDetector(a); await m.run(); r.add_section("Ransomware Detection",m.results)
async def _phishing(a,r):
    m=PhishingDetector(a); await m.run(); r.add_section("Phishing Detection",m.results)
async def _ddos(a,r):
    m=DDoSDetector(a); await m.run(); r.add_section("DDoS Detection",m.results)
async def _monitor(a,r):
    m=NetworkMonitor(a); await m.run(); r.add_section("Network Monitor",m.results)
async def _cve(a,r):
    m=CVEScanner(a); await m.run(); r.add_section("CVE Findings",m.results); return m.results
async def _malware(a,r):
    m=MalwareHashScanner(a); await m.run(); r.add_section("Malware Detection",m.results)
async def _honeypot(a,r):
    m=HoneypotModule(a); await m.run(); r.add_section("Honeypot",m.results)


async def run_full_audit(args, report):
    console.print("\n[bold cyan]NetRecon v4.0 — Full Security Audit (9 phases)[/bold cyan]\n")
    phases = [
        ("1/9","Port Scanning",          lambda: _port(args,report)),
        ("2/9","CVE Lookup",             lambda: _cve(args,report)),
        ("3/9","Network Reconnaissance", lambda: _recon(args,report)),
        ("4/9","Web Vulnerability Scan", lambda: _vuln(args,report)),
        ("5/9","Packet Capture",         lambda: _sniffer(args,report)),
        ("6/9","Intrusion Detection",    lambda: _ids(args,report)),
        ("7/9","Malware Detection",      lambda: _malware(args,report)),
        ("8/9","Spyware & Ransomware",   lambda: _ransomware(args,report)),
        ("9/9","Threat Assessment",      lambda: _threats(args,report)),
    ]
    for num, name, fn in phases:
        console.print(Panel(f"[bold]Phase {num}: {name}[/bold]", border_style="cyan", padding=(0,2)))
        await fn()
        console.print()


async def main():
    args = parse_args()
    if not args.quiet:
        print_banner()
    report = ReportGenerator()

    try:
        if args.full_audit:
            if not args.target: console.print("[red]Error:[/red] Target required."); sys.exit(1)
            await run_full_audit(args, report)
        elif args.scan_ports:
            if not args.target: console.print("[red]Error:[/red] Target required."); sys.exit(1)
            await _port(args, report)
            if args.cve_scan: await _cve(args, report)
        elif args.sniff:       await _sniffer(args, report)
        elif args.vuln_scan:
            if not args.target: console.print("[red]Error:[/red] Target URL required."); sys.exit(1)
            await _vuln(args, report)
        elif args.recon:
            if not args.target: console.print("[red]Error:[/red] Target required."); sys.exit(1)
            await _recon(args, report)
        elif args.detect_threats:
            m=ThreatDetector(args); await m.run_live(); report.add_section("Threat Detection",m.results)
        elif args.ids:          await _ids(args, report)
        elif args.detect_spyware:  await _spyware(args, report)
        elif args.detect_ransom:   await _ransomware(args, report)
        elif args.detect_phishing: await _phishing(args, report)
        elif args.detect_ddos:     await _ddos(args, report)
        elif args.monitor:         await _monitor(args, report)
        elif args.cve_scan:
            if not args.target: console.print("[red]Error:[/red] Target required."); sys.exit(1)
            await _cve(args, report)
        elif args.malware_scan:    await _malware(args, report)
        elif args.honeypot:        await _honeypot(args, report)
        elif args.api_server:
            server = NetReconAPIServer(args); await server.run()
        elif args.schedule:
            scheduler = ScheduledScanner(args)
            scheduler.add_task(
                name=f"{args.schedule_module} — {args.schedule_target or args.target or 'network'}",
                module=args.schedule_module,
                target=args.schedule_target or args.target or "",
                interval_hours=args.schedule_interval,
                alert_email=args.alert_email,
                slack_webhook=args.slack_webhook,
                webhook_url=args.webhook_url,
            )
            await scheduler.run()
        else:
            console.print(
                "[yellow]No module selected.[/yellow] Use [cyan]--help[/cyan] for options.\n\n"
                "Examples:\n"
                "  [dim]python main.py --scan-ports 192.168.1.1 --cve-scan[/dim]\n"
                "  [dim]sudo python main.py --honeypot --duration 300[/dim]\n"
                "  [dim]python main.py --api-server --api-port 8080[/dim]\n"
                "  [dim]sudo python main.py --full-audit 192.168.1.1 --pdf-report audit.pdf[/dim]"
            )
            sys.exit(0)

        # PDF report
        if args.pdf_report and report.has_data():
            gen = PDFReportGenerator(
                target=args.target or args.interface,
                scan_results={s["name"]: s.get("data",{}) for s in report.sections},
            )
            gen.save(args.pdf_report)

        # Standard report
        if args.output and report.has_data():
            report.save(args.output, fmt=args.format)
            console.print(f"\n[green]✓ Report saved:[/green] {args.output}")

    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠ Interrupted.[/yellow]")
        if report.has_data() and args.output:
            report.save(args.output, fmt=args.format)
    except PermissionError:
        console.print("[red]✗ Permission denied.[/red] Try [cyan]sudo python main.py ...[/cyan]")
        sys.exit(1)
    except Exception as e:
        logger.error(f"Fatal error: {e}", exc_info=args.verbose)
        console.print(f"[red]✗ Error: {e}[/red]")
        if args.verbose:
            import traceback; traceback.print_exc()
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())

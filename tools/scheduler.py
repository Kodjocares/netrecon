"""
Scheduled Scan & Alerting — Cron-style scheduling with diff-based alerting.
Runs scans automatically, compares with previous results, and notifies via
email/Slack/webhook only for NEW findings.
"""
import asyncio
import json
import time
import smtplib
import hashlib
from dataclasses import dataclass, field
from typing import List, Dict, Optional, Any
from pathlib import Path
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

SCHEDULE_DB = Path(".netrecon_schedules.json")
RESULTS_DB  = Path(".netrecon_results_history.json")


@dataclass
class ScheduledTask:
    task_id: str
    name: str
    module: str
    target: str
    cron: str           # e.g. "0 2 * * *" = 2am daily
    interval_hours: float
    alert_email: str = ""
    slack_webhook: str = ""
    webhook_url: str = ""
    last_run: float = 0.0
    next_run: float = 0.0
    run_count: int = 0
    enabled: bool = True


@dataclass
class ScanDiff:
    """Difference between two scan results."""
    new_findings: List[Dict] = field(default_factory=list)
    resolved_findings: List[Dict] = field(default_factory=list)
    unchanged: int = 0
    scan_time: float = field(default_factory=time.time)

    def has_changes(self) -> bool:
        return bool(self.new_findings or self.resolved_findings)

    def summary(self) -> str:
        parts = []
        if self.new_findings:
            parts.append(f"+{len(self.new_findings)} new")
        if self.resolved_findings:
            parts.append(f"-{len(self.resolved_findings)} resolved")
        if self.unchanged:
            parts.append(f"{self.unchanged} unchanged")
        return " | ".join(parts) if parts else "No changes"


class AlertDispatcher:
    """Sends notifications via email, Slack, and generic webhooks."""

    @staticmethod
    async def send_email(to_addr: str, subject: str, body: str,
                         smtp_host: str = "localhost", smtp_port: int = 25,
                         username: str = "", password: str = ""):
        """Send alert email."""
        if not to_addr:
            return False
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = subject
            msg["From"] = "netrecon@localhost"
            msg["To"] = to_addr

            html_body = f"""
<html><body style="font-family:monospace;background:#0a0e1a;color:#c8e6f0;padding:20px">
<h2 style="color:#00e5ff">⬡ NetRecon Alert</h2>
<pre style="color:#7fc9d8">{body}</pre>
</body></html>"""

            msg.attach(MIMEText(body, "plain"))
            msg.attach(MIMEText(html_body, "html"))

            def _send():
                with smtplib.SMTP(smtp_host, smtp_port, timeout=10) as server:
                    if username and password:
                        server.starttls()
                        server.login(username, password)
                    server.sendmail("netrecon@localhost", to_addr, msg.as_string())

            loop = asyncio.get_event_loop()
            await loop.run_in_executor(None, _send)
            console.print(f"  [green]✓ Email alert sent to {to_addr}[/green]")
            return True
        except Exception as e:
            console.print(f"  [yellow]⚠ Email failed: {e}[/yellow]")
            return False

    @staticmethod
    async def send_slack(webhook_url: str, text: str, findings: List[Dict]):
        """Send Slack notification via webhook."""
        if not webhook_url:
            return False
        try:
            import aiohttp
            blocks = [
                {"type": "header", "text": {"type": "plain_text", "text": "⬡ NetRecon Security Alert"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"```{text[:2000]}```"}},
            ]
            if findings:
                findings_text = "\n".join(
                    f"• [{f.get('severity','?').upper()}] {f.get('description', f.get('msg', ''))[:80]}"
                    for f in findings[:10]
                )
                blocks.append({
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"*New Findings:*\n{findings_text}"},
                })

            async with aiohttp.ClientSession() as session:
                await session.post(webhook_url, json={"blocks": blocks}, timeout=aiohttp.ClientTimeout(total=5))
            console.print(f"  [green]✓ Slack notification sent[/green]")
            return True
        except Exception as e:
            console.print(f"  [yellow]⚠ Slack failed: {e}[/yellow]")
            return False

    @staticmethod
    async def send_webhook(url: str, payload: Dict):
        """Send generic HTTP webhook (JSON POST)."""
        if not url:
            return False
        try:
            import aiohttp
            async with aiohttp.ClientSession() as session:
                await session.post(url, json=payload, timeout=aiohttp.ClientTimeout(total=5))
            console.print(f"  [green]✓ Webhook sent to {url[:40]}[/green]")
            return True
        except Exception as e:
            console.print(f"  [yellow]⚠ Webhook failed: {e}[/yellow]")
            return False


class ResultsStore:
    """Persists scan results and computes diffs."""

    def __init__(self):
        self._history: Dict[str, List[dict]] = {}
        self._load()

    def _load(self):
        if RESULTS_DB.exists():
            try:
                self._history = json.loads(RESULTS_DB.read_text())
            except Exception:
                self._history = {}

    def _save(self):
        try:
            RESULTS_DB.write_text(json.dumps(self._history, indent=2, default=str))
        except Exception:
            pass

    def _fingerprint(self, finding: Dict) -> str:
        """Create a stable fingerprint for a finding to detect duplicates."""
        key_fields = ["cve_id", "rule_id", "indicator_type", "attack_type",
                      "dst_port", "url", "domain", "src_ip"]
        parts = []
        for field in key_fields:
            if field in finding:
                parts.append(f"{field}={finding[field]}")
        if not parts:
            parts = [str(finding.get("description", ""))[:50]]
        return hashlib.md5("|".join(parts).encode()).hexdigest()[:12]

    def _extract_findings(self, results: Any) -> List[Dict]:
        """Extract a flat list of findings from any module results dict."""
        findings = []
        if not isinstance(results, dict):
            return findings
        for key in ["findings", "alerts", "indicators", "hits", "vulnerabilities"]:
            items = results.get(key, [])
            if isinstance(items, list):
                findings.extend(items)
        return findings

    def diff(self, task_id: str, new_results: Any) -> ScanDiff:
        """Compare new results against previous run."""
        diff = ScanDiff()
        new_findings = self._extract_findings(new_results)

        prev_runs = self._history.get(task_id, [])
        if not prev_runs:
            diff.new_findings = new_findings
            return diff

        prev_findings = prev_runs[-1].get("findings", [])
        prev_fps = {self._fingerprint(f) for f in prev_findings}
        new_fps  = {self._fingerprint(f) for f in new_findings}

        for f in new_findings:
            if self._fingerprint(f) not in prev_fps:
                diff.new_findings.append(f)

        for f in prev_findings:
            if self._fingerprint(f) not in new_fps:
                diff.resolved_findings.append(f)

        diff.unchanged = len(new_fps & prev_fps)
        return diff

    def store(self, task_id: str, results: Any):
        """Store results for future diffing."""
        findings = self._extract_findings(results) if isinstance(results, dict) else []
        if task_id not in self._history:
            self._history[task_id] = []
        self._history[task_id].append({
            "timestamp": time.time(),
            "findings":  findings,
        })
        # Keep last 30 runs per task
        self._history[task_id] = self._history[task_id][-30:]
        self._save()

    def get_history(self, task_id: str) -> List[dict]:
        return self._history.get(task_id, [])


class ScheduledScanner:
    """
    Scheduled scan engine:
    - Define tasks with module, target, and interval
    - Runs automatically at scheduled times
    - Diffs results against previous run
    - Sends email/Slack/webhook alerts ONLY for new findings
    """

    def __init__(self, args):
        self.args = args
        self._tasks: List[ScheduledTask] = []
        self._store = ResultsStore()
        self._dispatcher = AlertDispatcher()
        self._running = False

    def add_task(self, name: str, module: str, target: str,
                 interval_hours: float = 24.0,
                 alert_email: str = "", slack_webhook: str = "",
                 webhook_url: str = "") -> ScheduledTask:
        task = ScheduledTask(
            task_id=hashlib.md5(f"{name}{module}{target}".encode()).hexdigest()[:8],
            name=name, module=module, target=target,
            cron=f"every {interval_hours}h",
            interval_hours=interval_hours,
            alert_email=alert_email,
            slack_webhook=slack_webhook,
            webhook_url=webhook_url,
            next_run=time.time() + interval_hours * 3600,
        )
        self._tasks.append(task)
        console.print(
            f"  [green]✓ Task scheduled:[/green] [white]{name}[/white] — "
            f"{module} on {target} every {interval_hours}h"
        )
        return task

    async def _execute_task(self, task: ScheduledTask):
        """Run a single scheduled task."""
        from tools.api_server import _run_module, MockArgs

        console.print(f"\n[cyan]► Running scheduled task:[/cyan] {task.name} [{task.module}]")
        task.last_run = time.time()
        task.run_count += 1

        args = MockArgs(target=task.target)
        try:
            results = await _run_module(task.module, args)
        except Exception as e:
            console.print(f"  [red]✗ Task failed: {e}[/red]")
            return

        # Diff against previous run
        diff = self._store.diff(task.task_id, results)
        self._store.store(task.task_id, results)

        console.print(f"  Diff: [cyan]{diff.summary()}[/cyan]")

        # Only alert if there are new findings
        if diff.new_findings:
            await self._dispatch_alerts(task, diff, results)
        else:
            console.print("  [green]✓ No new findings — no alert sent[/green]")

        # Schedule next run
        task.next_run = time.time() + task.interval_hours * 3600

    async def _dispatch_alerts(self, task: ScheduledTask, diff: ScanDiff, results: Any):
        """Send alerts for new findings."""
        ts = time.strftime("%Y-%m-%d %H:%M:%S")
        summary_lines = [
            f"NetRecon Scheduled Scan Alert",
            f"Task: {task.name}",
            f"Module: {task.module}  Target: {task.target}",
            f"Time: {ts}",
            f"Changes: {diff.summary()}",
            "",
            "NEW FINDINGS:",
        ]
        for f in diff.new_findings[:20]:
            sev = f.get("severity", f.get("cvss_score", "?"))
            desc = f.get("description", f.get("msg", f.get("rule_name", str(f)[:60])))
            summary_lines.append(f"  [{sev}] {desc}")

        body = "\n".join(summary_lines)
        subject = f"[NetRecon] {len(diff.new_findings)} new findings — {task.name}"

        # Dispatch in parallel
        coros = []
        if task.alert_email:
            coros.append(self._dispatcher.send_email(task.alert_email, subject, body))
        if task.slack_webhook:
            coros.append(self._dispatcher.send_slack(task.slack_webhook, body, diff.new_findings))
        if task.webhook_url:
            coros.append(self._dispatcher.send_webhook(task.webhook_url, {
                "task": task.name, "module": task.module,
                "target": task.target, "new_findings": diff.new_findings,
                "summary": diff.summary(), "timestamp": ts,
            }))

        if coros:
            await asyncio.gather(*coros, return_exceptions=True)

    async def run(self):
        """Start the scheduler loop."""
        duration = getattr(self.args, "duration", 0)  # 0 = run indefinitely
        run_now = getattr(self.args, "run_now", False)

        console.print(f"\n[bold cyan]Scheduled Scanner[/bold cyan]")
        console.print(f"  Tasks: [white]{len(self._tasks)}[/white] | "
                      f"Mode: [cyan]{'continuous' if not duration else f'{duration}s'}[/cyan]\n")

        if not self._tasks:
            console.print("[yellow]⚠ No tasks scheduled. Use add_task() to add scans.[/yellow]")
            return

        self._running = True
        start = time.time()

        # Optionally run all tasks immediately
        if run_now:
            for task in self._tasks:
                if task.enabled:
                    await self._execute_task(task)

        while self._running:
            if duration and time.time() - start > duration:
                break

            now = time.time()
            for task in self._tasks:
                if task.enabled and now >= task.next_run:
                    await self._execute_task(task)

            await asyncio.sleep(60)  # Check every minute

        self._print_summary()

    def stop(self):
        self._running = False

    def _print_summary(self):
        console.print()
        if not self._tasks:
            return
        table = Table(title="Scheduled Task Summary", box=box.SIMPLE, border_style="cyan")
        table.add_column("Task", style="white")
        table.add_column("Module", style="cyan")
        table.add_column("Target")
        table.add_column("Runs", justify="right")
        table.add_column("Next Run", style="dim")
        for task in self._tasks:
            next_ts = time.strftime("%H:%M", time.localtime(task.next_run))
            table.add_row(task.name, task.module, task.target[:20], str(task.run_count), next_ts)
        console.print(table)

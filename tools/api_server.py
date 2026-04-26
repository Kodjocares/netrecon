"""
REST API Server — Wraps all NetRecon modules in a FastAPI HTTP server.
Enables remote scan triggering, CI/CD integration, and SIEM connectivity.
"""
import asyncio
import time
import json
import uuid
from dataclasses import dataclass, asdict, field
from typing import Dict, List, Optional, Any
from rich.console import Console

console = Console()

# ── Job tracking ──────────────────────────────────────────────────────────────
@dataclass
class ScanJob:
    job_id: str
    module: str
    target: str
    status: str        # queued / running / complete / failed
    created_at: float
    started_at: float = 0.0
    finished_at: float = 0.0
    results: Any = None
    error: str = ""

    def to_dict(self) -> dict:
        return {
            "job_id":      self.job_id,
            "module":      self.module,
            "target":      self.target,
            "status":      self.status,
            "created_at":  self.created_at,
            "started_at":  self.started_at,
            "finished_at": self.finished_at,
            "duration":    round(self.finished_at - self.started_at, 2) if self.finished_at else None,
            "error":       self.error,
            "results":     self.results,
        }


class MockArgs:
    """Minimal args object for module initialization via API."""
    def __init__(self, **kwargs):
        defaults = {
            "interface": "eth0", "duration": 60, "alert_level": "medium",
            "block": False, "verbose": False, "ports": "1-1024",
            "scan_type": "tcp", "threads": 100, "timeout": 1.0,
            "banner": True, "os_detect": False, "rules": None,
            "crawl_depth": 2, "all_vulns": True, "sqli": True,
            "xss": True, "lfi": False, "headers": True, "ssl": True,
            "dns": True, "whois": True, "traceroute": False, "arp_scan": False,
            "nvd_api": False, "vt_api_key": "",
            "honeypot_ports": None, "output": None, "format": "json",
        }
        defaults.update(kwargs)
        for k, v in defaults.items():
            setattr(self, k, v)


def _results_to_dict(results) -> dict:
    """Convert dataclass results to JSON-serializable dict."""
    try:
        if hasattr(results, "__dict__"):
            out = {}
            for k, v in results.__dict__.items():
                if isinstance(v, set):
                    out[k] = list(v)
                elif isinstance(v, bytes):
                    out[k] = v.hex()
                elif hasattr(v, "__dict__"):
                    out[k] = _results_to_dict(v)
                elif isinstance(v, list):
                    out[k] = [_results_to_dict(i) if hasattr(i, "__dict__") else i for i in v]
                else:
                    out[k] = v
            return out
        return str(results)
    except Exception:
        return {}


async def _run_module(module: str, args: MockArgs) -> Any:
    """Dispatch to the correct module and return results."""
    if module == "port":
        from tools.port_scanner import PortScanner
        m = PortScanner(args.target, args)
        await m.run()
        return _results_to_dict(m.results)

    elif module == "vuln":
        from tools.vuln_scanner import WebVulnScanner
        m = WebVulnScanner(args.target, args)
        await m.run()
        return _results_to_dict(m.results)

    elif module == "recon":
        from tools.network_recon import NetworkRecon
        m = NetworkRecon(args.target, args)
        await m.run()
        return _results_to_dict(m.results)

    elif module == "cve":
        from tools.cve_scanner import CVEScanner
        m = CVEScanner(args)
        await m.run()
        return _results_to_dict(m.results)

    elif module == "ids":
        from tools.ids import IntrusionDetectionSystem
        m = IntrusionDetectionSystem(args)
        await m.run()
        return _results_to_dict(m.results)

    elif module == "ddos":
        from tools.ddos_detector import DDoSDetector
        m = DDoSDetector(args)
        await m.run()
        return _results_to_dict(m.results)

    elif module == "phishing":
        from tools.phishing_detector import PhishingDetector
        m = PhishingDetector(args)
        await m.run()
        return _results_to_dict(m.results)

    elif module == "ransom":
        from tools.ransomware_detector import RansomwareDetector
        m = RansomwareDetector(args)
        await m.run()
        return _results_to_dict(m.results)

    elif module == "spyware":
        from tools.spyware_detector import SpywareDetector
        m = SpywareDetector(args)
        await m.run()
        return _results_to_dict(m.results)

    elif module == "monitor":
        from tools.network_monitor import NetworkMonitor
        m = NetworkMonitor(args)
        await m.run()
        return _results_to_dict(m.results)

    elif module == "malware":
        from tools.malware_scanner import MalwareHashScanner
        m = MalwareHashScanner(args)
        await m.run()
        return _results_to_dict(m.results)

    else:
        raise ValueError(f"Unknown module: {module}")


class NetReconAPIServer:
    """
    FastAPI-based REST server exposing all NetRecon modules via HTTP.

    Endpoints:
      GET  /health                   — Server status
      GET  /modules                  — List available modules
      POST /scan/{module}            — Trigger a scan (returns job_id)
      GET  /jobs/{job_id}            — Poll job status and results
      GET  /jobs                     — List all jobs
      DELETE /jobs/{job_id}          — Delete a job
      GET  /alerts                   — Aggregated alerts from last run

    Example:
      curl -X POST http://localhost:8080/scan/port \
           -H "Content-Type: application/json" \
           -d '{"target":"192.168.1.1","ports":"1-1024"}'
    """

    def __init__(self, args):
        self.args = args
        self.host = getattr(args, "api_host", "127.0.0.1")
        self.port = getattr(args, "api_port", 8080)
        self._jobs: Dict[str, ScanJob] = {}
        self._app = None

    def _build_app(self):
        try:
            from fastapi import FastAPI, HTTPException, Request
            from fastapi.middleware.cors import CORSMiddleware
            from fastapi.responses import JSONResponse
        except ImportError:
            console.print("[red]✗ FastAPI required: pip install fastapi uvicorn[/red]")
            return None

        app = FastAPI(
            title="NetRecon API",
            description="REST API for NetRecon v3.0 Network Security Suite",
            version="3.0.0",
        )

        app.add_middleware(
            CORSMiddleware,
            allow_origins=["*"],
            allow_methods=["*"],
            allow_headers=["*"],
        )

        @app.get("/health")
        async def health():
            return {
                "status": "operational",
                "version": "3.0.0",
                "uptime": time.time(),
                "jobs_queued": sum(1 for j in self._jobs.values() if j.status == "queued"),
                "jobs_running": sum(1 for j in self._jobs.values() if j.status == "running"),
            }

        @app.get("/modules")
        async def list_modules():
            return {
                "modules": [
                    {"id": "port",     "name": "Port Scanner",       "needs_target": True,  "needs_root": False},
                    {"id": "vuln",     "name": "Web Vuln Scanner",   "needs_target": True,  "needs_root": False},
                    {"id": "recon",    "name": "Network Recon",      "needs_target": True,  "needs_root": False},
                    {"id": "cve",      "name": "CVE Scanner",        "needs_target": True,  "needs_root": False},
                    {"id": "ids",      "name": "IDS",                "needs_target": False, "needs_root": True},
                    {"id": "ddos",     "name": "DDoS Detector",      "needs_target": False, "needs_root": True},
                    {"id": "phishing", "name": "Phishing Detector",  "needs_target": False, "needs_root": True},
                    {"id": "ransom",   "name": "Ransomware Detector","needs_target": False, "needs_root": True},
                    {"id": "spyware",  "name": "Spyware Detector",   "needs_target": False, "needs_root": True},
                    {"id": "monitor",  "name": "Network Monitor",    "needs_target": False, "needs_root": True},
                    {"id": "malware",  "name": "Malware Scanner",    "needs_target": False, "needs_root": True},
                ]
            }

        @app.post("/scan/{module}")
        async def trigger_scan(module: str, request: Request):
            body = {}
            try:
                body = await request.json()
            except Exception:
                pass

            job_id = str(uuid.uuid4())[:8]
            target = body.get("target", "")
            mock_args = MockArgs(target=target, **{
                k: v for k, v in body.items() if k != "target"
            })
            mock_args.target = target

            job = ScanJob(
                job_id=job_id,
                module=module,
                target=target,
                status="queued",
                created_at=time.time(),
            )
            self._jobs[job_id] = job

            # Run in background
            asyncio.create_task(self._execute_job(job, mock_args))
            return {"job_id": job_id, "status": "queued", "module": module}

        @app.get("/jobs")
        async def list_jobs():
            return {"jobs": [j.to_dict() for j in self._jobs.values()]}

        @app.get("/jobs/{job_id}")
        async def get_job(job_id: str):
            job = self._jobs.get(job_id)
            if not job:
                raise HTTPException(status_code=404, detail="Job not found")
            return job.to_dict()

        @app.delete("/jobs/{job_id}")
        async def delete_job(job_id: str):
            if job_id not in self._jobs:
                raise HTTPException(status_code=404, detail="Job not found")
            del self._jobs[job_id]
            return {"deleted": job_id}

        @app.get("/alerts")
        async def get_alerts():
            all_alerts = []
            for job in self._jobs.values():
                if job.status == "complete" and job.results:
                    alerts = job.results.get("alerts", job.results.get("findings", job.results.get("indicators", [])))
                    for a in (alerts or []):
                        if isinstance(a, dict):
                            a["job_id"] = job.job_id
                            a["module"] = job.module
                            all_alerts.append(a)
            return {"count": len(all_alerts), "alerts": all_alerts[-100:]}

        return app

    async def _execute_job(self, job: ScanJob, args: MockArgs):
        job.status = "running"
        job.started_at = time.time()
        try:
            job.results = await _run_module(job.module, args)
            job.status = "complete"
        except Exception as e:
            job.status = "failed"
            job.error = str(e)
        finally:
            job.finished_at = time.time()
        console.print(
            f"  [{'green' if job.status=='complete' else 'red'}]"
            f"Job {job.job_id} {job.status}[/] — {job.module} ({job.finished_at-job.started_at:.1f}s)"
        )

    async def run(self):
        """Start the REST API server."""
        try:
            import uvicorn
        except ImportError:
            console.print("[red]✗ uvicorn required: pip install uvicorn fastapi[/red]")
            return

        self._app = self._build_app()
        if not self._app:
            return

        console.print(f"\n[bold cyan]NetRecon REST API Server[/bold cyan]")
        console.print(f"  Listening on [white]http://{self.host}:{self.port}[/white]")
        console.print(f"  Docs: [cyan]http://{self.host}:{self.port}/docs[/cyan]\n")
        console.print("  Endpoints:")
        console.print("    GET  /health      — Server status")
        console.print("    GET  /modules     — Available modules")
        console.print("    POST /scan/port   — Trigger port scan")
        console.print("    GET  /jobs/:id    — Poll scan results")
        console.print("    GET  /alerts      — Aggregated alerts\n")

        config = uvicorn.Config(
            self._app,
            host=self.host,
            port=self.port,
            log_level="warning",
        )
        server = uvicorn.Server(config)
        await server.serve()

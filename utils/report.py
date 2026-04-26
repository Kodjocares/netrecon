"""
Report generation for NetRecon — supports TXT, JSON, HTML, and CSV output.
"""

import json
import time
import csv
import io
from dataclasses import dataclass, field, asdict
from typing import Dict, Any, List, Optional
from rich.console import Console

console = Console()


@dataclass
class ReportSection:
    name: str
    data: Any
    timestamp: float = field(default_factory=time.time)


class ReportGenerator:
    """Collects scan results and generates formatted reports."""

    def __init__(self):
        self.sections: List[ReportSection] = []
        self.metadata = {
            "tool": "NetRecon",
            "version": "2.0.0",
            "generated": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }

    def add_section(self, name: str, data: Any):
        self.sections.append(ReportSection(name=name, data=data))

    def has_data(self) -> bool:
        return len(self.sections) > 0

    def all_results(self) -> Dict:
        """Flatten all results into a single dict for cross-module analysis."""
        combined = {}
        for section in self.sections:
            if hasattr(section.data, "__dict__"):
                combined.update(section.data.__dict__)
            elif isinstance(section.data, dict):
                combined.update(section.data)
        return combined

    def _to_dict(self, obj: Any) -> Any:
        """Recursively convert dataclass/object to dict."""
        if obj is None:
            return None
        if hasattr(obj, "__dict__"):
            return {k: self._to_dict(v) for k, v in obj.__dict__.items()}
        if isinstance(obj, (list, tuple)):
            return [self._to_dict(i) for i in obj]
        if isinstance(obj, dict):
            return {k: self._to_dict(v) for k, v in obj.items()}
        if isinstance(obj, set):
            return list(obj)
        return obj

    def _generate_txt(self) -> str:
        lines = [
            "=" * 70,
            "  NETRECON SECURITY AUDIT REPORT",
            f"  Generated: {self.metadata['generated']}",
            "=" * 70,
            "",
        ]
        for section in self.sections:
            lines.append(f"\n{'─' * 60}")
            lines.append(f"  {section.name.upper()}")
            lines.append(f"{'─' * 60}")
            data = self._to_dict(section.data)
            lines.append(json.dumps(data, indent=2, default=str))

        lines.append("\n" + "=" * 70)
        lines.append("  END OF REPORT")
        lines.append("=" * 70)
        return "\n".join(lines)

    def _generate_json(self) -> str:
        report = {
            "metadata": self.metadata,
            "sections": [
                {
                    "name": s.name,
                    "timestamp": s.timestamp,
                    "data": self._to_dict(s.data),
                }
                for s in self.sections
            ],
        }
        return json.dumps(report, indent=2, default=str)

    def _generate_html(self) -> str:
        sections_html = ""
        for section in self.sections:
            data = json.dumps(self._to_dict(section.data), indent=2, default=str)
            sections_html += f"""
            <section>
                <h2>{section.name}</h2>
                <pre><code>{data}</code></pre>
            </section>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>NetRecon Security Report — {self.metadata['generated']}</title>
    <style>
        :root {{
            --bg: #0a0e1a;
            --surface: #111827;
            --border: #1e3a5f;
            --accent: #00d4ff;
            --text: #e2e8f0;
            --muted: #64748b;
            --critical: #ef4444;
            --high: #f97316;
            --medium: #eab308;
            --low: #22d3ee;
        }}
        * {{ box-sizing: border-box; margin: 0; padding: 0; }}
        body {{ background: var(--bg); color: var(--text); font-family: 'JetBrains Mono', 'Fira Code', monospace; padding: 2rem; }}
        header {{ border-bottom: 1px solid var(--border); padding-bottom: 1.5rem; margin-bottom: 2rem; }}
        header h1 {{ color: var(--accent); font-size: 1.8rem; letter-spacing: 0.1em; }}
        header .meta {{ color: var(--muted); font-size: 0.8rem; margin-top: 0.5rem; }}
        section {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px; padding: 1.5rem; margin-bottom: 1.5rem; }}
        section h2 {{ color: var(--accent); font-size: 1rem; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 1rem; }}
        pre {{ background: #060a13; border-radius: 4px; padding: 1rem; overflow-x: auto; font-size: 0.8rem; line-height: 1.6; color: #94a3b8; }}
        footer {{ text-align: center; color: var(--muted); font-size: 0.75rem; margin-top: 2rem; padding-top: 1rem; border-top: 1px solid var(--border); }}
    </style>
</head>
<body>
    <header>
        <h1>⬡ NETRECON // SECURITY AUDIT REPORT</h1>
        <div class="meta">Generated: {self.metadata['generated']} | NetRecon v{self.metadata['version']}</div>
    </header>
    {sections_html}
    <footer>NetRecon Security Intelligence Suite — Authorized use only</footer>
</body>
</html>"""

    def _generate_csv(self) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(["Section", "Key", "Value"])
        for section in self.sections:
            data = self._to_dict(section.data)
            if isinstance(data, dict):
                for k, v in data.items():
                    writer.writerow([section.name, k, json.dumps(v, default=str)])
        return output.getvalue()

    def save(self, filepath: str, fmt: str = "txt"):
        generators = {
            "txt": self._generate_txt,
            "json": self._generate_json,
            "html": self._generate_html,
            "csv": self._generate_csv,
        }
        gen = generators.get(fmt, self._generate_txt)
        content = gen()
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(content)

    def print_summary(self):
        """Print a brief executive summary to console."""
        console.print("\n[bold]── Report Summary ──[/bold]")
        for section in self.sections:
            console.print(f"  [cyan]✓[/cyan] {section.name}")

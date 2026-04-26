# Contributing to NetRecon

Thank you for your interest in contributing! This document covers how to get set up, coding standards, and the pull request process.

---

## Code of Conduct

By participating you agree to uphold responsible disclosure principles and ethical security research standards. Never test against systems you don't own or have explicit permission to test.

---

## Getting Started

### Fork and clone
```bash
git clone https://github.com/YOUR_USERNAME/netrecon.git
cd netrecon
git remote add upstream https://github.com/ORIGINAL_ORG/netrecon.git
```

### Set up dev environment
```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
pip install -r requirements-dev.txt
```

### Create a feature branch
```bash
git checkout -b feature/my-new-detection-module
```

---

## Project Structure

```
netrecon/
├── main.py              # CLI entry point — add new --flags here
├── core/                # Shared internals (banner, config)
├── tools/               # One file per detection module
├── utils/               # Shared utilities (logger, report)
├── rules/               # Custom IDS/detection rule files
├── tests/               # Pytest test suite
├── docs/                # Extended documentation
└── scripts/             # Helper/install scripts
```

---

## Adding a New Detection Module

1. Create `tools/my_module.py` with a class `MyModule(args)`
2. Implement `async def run(self)` and `self.results` dataclass
3. Add import and `--my-flag` argument in `main.py`
4. Wire it into `run_full_audit()` if appropriate
5. Add tests in `tests/test_my_module.py`
6. Document in `docs/modules/my_module.md`

### Module Template
```python
import asyncio
from dataclasses import dataclass, field
from typing import List
from rich.console import Console

console = Console()

@dataclass
class MyResults:
    start_time: float
    indicators: List[str] = field(default_factory=list)

class MyModule:
    def __init__(self, args):
        self.args = args
        self.results = MyResults(start_time=__import__('time').time())

    async def run(self):
        # Your detection logic here
        pass
```

---

## Adding Custom IDS Rules

Add a JSON file in `rules/` with this format:
```json
[
  {
    "id": "CUSTOM-001",
    "name": "My Custom Rule",
    "severity": "high",
    "category": "Custom",
    "protocol": "TCP",
    "dst_port": 1337,
    "payload_pattern": "evil_pattern",
    "description": "Detects evil traffic",
    "mitre": "T1059"
  }
]
```

Run with: `python main.py --ids --rules rules/my_rules.json`

---

## Coding Standards

- Python 3.10+ type hints throughout
- Dataclasses for all result objects
- `async/await` for all I/O operations
- Rich for all console output (no `print()`)
- Docstrings on all public classes and methods
- Max line length: 100 characters
- Run `black .` before submitting

---

## Pull Request Checklist

- [ ] Tests pass (`pytest tests/`)
- [ ] Code formatted (`black .`)
- [ ] New module documented
- [ ] No secrets, API keys, or pcap files committed
- [ ] LEGAL: only tested against systems you own
- [ ] PR description explains what the change does and why

---

## Reporting Vulnerabilities

Please do NOT open public issues for security vulnerabilities. Instead, email the maintainers directly or use GitHub's private security advisory feature.

"""
Config persistence for the DriftGuard CLI.

Precedence: environment variables > config file > defaults. Environment
variables win so CI pipelines can override without touching a config file
on disk (matches how most CLIs — aws-cli, gh, terraform — behave).
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, asdict
from pathlib import Path

CONFIG_DIR = Path.home() / ".driftguard"
CONFIG_FILE = CONFIG_DIR / "config.json"
DEFAULT_API_URL = "https://driftguard-endm.onrender.com"


@dataclass
class Config:
    api_url: str = DEFAULT_API_URL
    api_key: str | None = None

    @classmethod
    def load(cls) -> "Config":
        cfg = cls()
        if CONFIG_FILE.exists():
            try:
                data = json.loads(CONFIG_FILE.read_text())
                cfg.api_url = data.get("api_url", DEFAULT_API_URL)
                cfg.api_key = data.get("api_key")
            except (json.JSONDecodeError, OSError):
                pass  # corrupt config file — fall back to defaults rather than crash

        # Env vars always win — deliberate override for CI/scripting use.
        cfg.api_url = os.environ.get("DRIFTGUARD_API_URL", cfg.api_url)
        cfg.api_key = os.environ.get("DRIFTGUARD_API_KEY", cfg.api_key)
        return cfg

    def save(self) -> None:
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        CONFIG_FILE.write_text(json.dumps(asdict(self), indent=2))
        CONFIG_FILE.chmod(0o600)  # contains an API key — not world-readable

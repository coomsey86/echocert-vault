from __future__ import annotations
import json
import os
import hashlib
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)

def sha256_bytes(data: bytes) -> str:
    h = hashlib.sha256()
    h.update(data)
    return h.hexdigest()

def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()

def canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

def safe_write_text(path: Path, text: str) -> None:
    ensure_dir(path.parent)
    path.write_text(text, encoding="utf-8", newline="\n")

def safe_write_bytes(path: Path, data: bytes) -> None:
    ensure_dir(path.parent)
    path.write_bytes(data)

def read_text(path: Path) -> str:
    return path.read_text(encoding="utf-8")

def env_vault_dir(explicit: str | None = None) -> Path:
    if explicit:
        return Path(explicit).expanduser().resolve()
    home = Path(os.path.expanduser("~"))
    return (home / ".echocert_vault").resolve()

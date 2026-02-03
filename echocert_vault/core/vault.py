from __future__ import annotations
from pathlib import Path
from typing import Optional
import secrets
from .utils import ensure_dir, utc_now_iso, safe_write_text, env_vault_dir

def vault_root(vault_dir: Optional[str] = None) -> Path:
    return env_vault_dir(vault_dir)

def runs_dir(vault_dir: Optional[str] = None) -> Path:
    return vault_root(vault_dir) / "runs"

def init_vault(vault_dir: Optional[str] = None) -> Path:
    root = vault_root(vault_dir)
    ensure_dir(root)
    ensure_dir(runs_dir(vault_dir))
    meta = root / "vault.meta.json"
    if not meta.exists():
        safe_write_text(meta, '{"schema":"echocert-vault","version":"0.1.0"}\n')
    return root

def new_run_id() -> str:
    return f"{utc_now_iso().replace(':','').replace('.','').replace('+','').replace('-','')}_{secrets.token_hex(4)}"

def run_path(run_id: str, vault_dir: Optional[str] = None) -> Path:
    return runs_dir(vault_dir) / run_id

def artifact_path(run_id: str, name: str, vault_dir: Optional[str] = None) -> Path:
    return run_path(run_id, vault_dir) / "artifacts" / name

def events_path(run_id: str, vault_dir: Optional[str] = None) -> Path:
    return run_path(run_id, vault_dir) / "EVENTS.jsonl"

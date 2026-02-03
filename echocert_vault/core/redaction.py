from __future__ import annotations
import json
import shutil
from pathlib import Path
from typing import Optional, Iterable

from .utils import sha256_file, safe_write_text, utc_now_iso, ensure_dir
from .bundle import export_bundle

SENSITIVE_BASENAMES = {"prompt.txt", "output.txt", "output_edited.txt"}

def _redacted_placeholder(rel_path: str, sha256: str, byte_len: int) -> str:
    return (
        f"[REDACTED:{rel_path}]\n"
        f"sha256_commitment: {sha256}\n"
        f"bytes: {byte_len}\n"
        f"note: content withheld; verify commitment against original via private vault\n"
    )

def _iter_sensitive_files(root: Path) -> Iterable[Path]:
    for p in root.rglob("*"):
        if p.is_file() and p.name in SENSITIVE_BASENAMES:
            yield p

def stage_redacted_run(run_root: Path, mode: str = "public", out_dir: Optional[Path] = None) -> Path:
    if mode != "public":
        raise ValueError("mode must be 'public'")
    if not run_root.exists():
        raise FileNotFoundError(f"run_root not found: {run_root}")

    out_dir = out_dir or (run_root.parent / (run_root.name + "__redacted_public"))
    if out_dir.exists():
        shutil.rmtree(out_dir)
    shutil.copytree(run_root, out_dir)

    commitments = []
    for p in _iter_sensitive_files(out_dir):
        rel = p.relative_to(out_dir).as_posix()
        original_sha = sha256_file(p)
        byte_len = p.stat().st_size
        safe_write_text(p, _redacted_placeholder(rel, original_sha, byte_len))
        commitments.append({"path": rel, "sha256_commitment": original_sha, "bytes": byte_len})

    redaction = {
        "schema": "echocert-vault-redaction",
        "version": "0.2.2",
        "ts": utc_now_iso(),
        "mode": mode,
        "commitments": sorted(commitments, key=lambda x: x["path"]),
        "warning": "Public-safe bundle. Original content not included. Commitments allow later proof of match.",
    }
    safe_write_text(out_dir / "REDACTION.json", json.dumps(redaction, indent=2, ensure_ascii=False) + "\n")
    return out_dir

def export_redacted_bundle(run_root: Path, out_file: Path, sign: bool = False, vault_root: Optional[Path] = None) -> Path:
    staged = stage_redacted_run(run_root, mode="public")
    ensure_dir(out_file.parent)
    return export_bundle(staged, out_file, sign=sign, vault_root=vault_root)

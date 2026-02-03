from __future__ import annotations
import json
import zipfile
from pathlib import Path
from typing import Optional, Dict, Any

from .utils import sha256_bytes

def _load_redaction(z: zipfile.ZipFile) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(z.read("REDACTION.json").decode("utf-8"))
    except KeyError:
        return None

def _find_commitment(redaction: Dict[str, Any], path: str) -> Optional[Dict[str, Any]]:
    for c in redaction.get("commitments", []):
        if c.get("path") == path:
            return c
    return None

def prove_bytes(bundle_file: Path, path: str, data: bytes) -> Dict[str, Any]:
    candidate_sha = sha256_bytes(data)
    candidate_len = len(data)

    with zipfile.ZipFile(bundle_file, "r") as z:
        redaction = _load_redaction(z)
        if redaction is None:
            return {
                "ok": False,
                "error": "REDACTION.json missing (bundle is not a redaction pack)",
                "path": path,
                "candidate_sha256": candidate_sha,
                "candidate_bytes": candidate_len,
            }

        c = _find_commitment(redaction, path)
        if c is None:
            return {
                "ok": False,
                "error": "commitment not found for path",
                "path": path,
                "candidate_sha256": candidate_sha,
                "candidate_bytes": candidate_len,
                "known_paths": [x.get("path") for x in redaction.get("commitments", [])],
            }

        expected_sha = c.get("sha256_commitment")
        expected_bytes = c.get("bytes")

        sha_match = (candidate_sha == expected_sha)
        bytes_match = (candidate_len == expected_bytes) if isinstance(expected_bytes, int) else None
        ok = bool(sha_match and (bytes_match is True or bytes_match is None))

        return {
            "ok": ok,
            "path": path,
            "expected_commitment": expected_sha,
            "candidate_sha256": candidate_sha,
            "expected_bytes": expected_bytes,
            "candidate_bytes": candidate_len,
            "bytes_match": bytes_match,
            "note": "ok=true means the candidate matches the public commitment in REDACTION.json",
        }

def prove_text(bundle_file: Path, path: str, text: str) -> Dict[str, Any]:
    return prove_bytes(bundle_file, path, text.encode("utf-8"))

def prove_file(bundle_file: Path, path: str, file_path: Path) -> Dict[str, Any]:
    return prove_bytes(bundle_file, path, file_path.read_bytes())

from __future__ import annotations
import json
import zipfile
from pathlib import Path
from typing import Optional, Dict, Any, Union

from .prove import prove_bytes

def _load_json_from_zip(z: zipfile.ZipFile, name: str) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(z.read(name).decode("utf-8"))
    except KeyError:
        return None

def reveal_text(bundle_file: Path, path: str, text: str, out_file: Path) -> Dict[str, Any]:
    data = text.encode("utf-8")
    return reveal_bytes(bundle_file, path, data, out_file, disclosed_as="text")

def reveal_file(bundle_file: Path, path: str, file_path: Path, out_file: Path) -> Dict[str, Any]:
    data = file_path.read_bytes()
    return reveal_bytes(bundle_file, path, data, out_file, disclosed_as=str(file_path))

def reveal_bytes(bundle_file: Path, path: str, data: bytes, out_file: Path, disclosed_as: str) -> Dict[str, Any]:
    # 1) Prove candidate matches the public commitment
    prove = prove_bytes(bundle_file, path, data)

    # 2) Pull verify-like signals from bundle (signature presence)
    with zipfile.ZipFile(bundle_file, "r") as z:
        redaction = _load_json_from_zip(z, "REDACTION.json")
        signature = _load_json_from_zip(z, "SIGNATURE.json")
        manifest = _load_json_from_zip(z, "MANIFEST.json")

    packet = {
        "schema": "echocert-vault-reveal",
        "version": "0.2.4",
        "bundle": str(bundle_file),
        "path": path,
        "disclosed_as": disclosed_as,
        "candidate_bytes": len(data),
        "candidate_sha256": prove.get("candidate_sha256"),
        "expected_commitment": prove.get("expected_commitment"),
        "match_ok": bool(prove.get("ok")),
        "note": "This reveal packet discloses the content and proves it matches the public commitment.",
        "bundle_meta": {
            "has_redaction": redaction is not None,
            "has_signature": signature is not None,
            "has_manifest": manifest is not None,
        },
        "prove": prove,
    }

    # store disclosed content as UTF-8 text if possible, else base64 (keep simple: utf-8 or fallback)
    try:
        packet["disclosed_text_utf8"] = data.decode("utf-8")
        packet["disclosed_encoding"] = "utf-8"
    except UnicodeDecodeError:
        import base64
        packet["disclosed_b64"] = base64.b64encode(data).decode("ascii")
        packet["disclosed_encoding"] = "base64"

    out_file.parent.mkdir(parents=True, exist_ok=True)
    out_file.write_text(json.dumps(packet, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return packet

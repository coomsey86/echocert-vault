from __future__ import annotations
import json
import zipfile
from pathlib import Path
from typing import Dict, Any, List, Optional, Set
from .utils import sha256_file, safe_write_text, ensure_dir, canonical_json, sha256_bytes, utc_now_iso
from .events import read_events
from .hashchain import build_chain

EXCLUDE_FROM_MANIFEST: Set[str] = {"MANIFEST.json", "SIGNATURE.json"}

def _collect_files(run_root: Path) -> List[Path]:
    return [p for p in run_root.rglob("*") if p.is_file()]

def _collect_files_for_manifest(run_root: Path) -> List[Path]:
    files = []
    for p in _collect_files(run_root):
        rel = p.relative_to(run_root).as_posix()
        if rel in EXCLUDE_FROM_MANIFEST:
            continue
        files.append(p)
    return files

def make_manifest(run_root: Path) -> Dict[str, Any]:
    files = _collect_files_for_manifest(run_root)
    manifest_files = []
    for f in files:
        rel = f.relative_to(run_root).as_posix()
        manifest_files.append({"path": rel, "sha256": sha256_file(f), "bytes": f.stat().st_size})
    manifest_files.sort(key=lambda x: x["path"])
    manifest = {"schema": "echocert-vault-manifest", "version": "0.2.0", "files": manifest_files}
    manifest["manifest_sha256"] = sha256_bytes(canonical_json({k: manifest[k] for k in ("schema","version","files")}))
    return manifest

def write_chain_file(run_root: Path) -> None:
    events_file = run_root / "EVENTS.jsonl"
    events = read_events(events_file)
    chain = build_chain(events)
    lines = []
    prev = "0"*64
    for i, c in enumerate(chain, start=1):
        lines.append(f"{i}\tprev={prev}\tevent={c['event_hash']}\tchain={c['chain_hash']}")
        prev = c["chain_hash"]
    (run_root / "CHAIN.txt").write_text("\n".join(lines) + "\n", encoding="utf-8", newline="\n")

def write_signature_file(run_root: Path, manifest_sha256: str, signature_b64: str, public_key_pem_b64: str) -> None:
    sig = {
        "schema": "echocert-vault-signature",
        "version": "0.2.0",
        "ts": utc_now_iso(),
        "signed_manifest_sha256": manifest_sha256,
        "algorithm": "ed25519",
        "signature_b64": signature_b64,
        "public_key_pem_b64": public_key_pem_b64,
    }
    safe_write_text(run_root / "SIGNATURE.json", json.dumps(sig, indent=2, ensure_ascii=False) + "\n")

def export_bundle(run_root: Path, out_file: Path, sign: bool = False, vault_root: Optional[Path] = None) -> Path:
    ensure_dir(out_file.parent)

    # Payload first
    write_chain_file(run_root)

    # Manifest excludes MANIFEST + SIGNATURE to avoid self-reference mismatch
    manifest = make_manifest(run_root)
    safe_write_text(run_root / "MANIFEST.json", json.dumps(manifest, indent=2, ensure_ascii=False) + "\n")

    if sign:
        if vault_root is None:
            raise ValueError("vault_root is required when sign=True")
        from .signing import load_private, load_public, sign_manifest_sha256, pubkey_pem_b64
        priv = load_private(vault_root)
        pub = load_public(vault_root)
        if priv is None or pub is None:
            raise RuntimeError("Signing keys not found. Run: echocert-vault keygen")
        signature_b64 = sign_manifest_sha256(priv, manifest["manifest_sha256"])
        write_signature_file(run_root, manifest["manifest_sha256"], signature_b64, pubkey_pem_b64(pub))

    with zipfile.ZipFile(out_file, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for p in _collect_files(run_root):
            z.write(p, p.relative_to(run_root).as_posix())

    return out_file

def verify_bundle(bundle_file: Path) -> Dict[str, Any]:
    with zipfile.ZipFile(bundle_file, "r") as z:
        try:
            manifest = json.loads(z.read("MANIFEST.json").decode("utf-8"))
        except KeyError:
            return {"ok": False, "error": "MANIFEST.json missing"}

        missing, mismatches = [], []
        for entry in manifest.get("files", []):
            path = entry["path"]
            expected = entry["sha256"]
            try:
                data = z.read(path)
            except KeyError:
                missing.append(path)
                continue
            actual = sha256_bytes(data)
            if actual != expected:
                mismatches.append({"path": path, "expected": expected, "actual": actual})

        ok_hashes = (not missing and not mismatches)

        sig_report: Dict[str, Any] = {"signature_present": False}
        try:
            sig = json.loads(z.read("SIGNATURE.json").decode("utf-8"))
            sig_report["signature_present"] = True

            if sig.get("signed_manifest_sha256") != manifest.get("manifest_sha256"):
                sig_report["signature_ok"] = False
                sig_report["signature_error"] = "signed_manifest_sha256 does not match MANIFEST.json"
            else:
                from .signing import load_public_from_b64, verify_manifest_sha256
                pub = load_public_from_b64(sig["public_key_pem_b64"])
                sig_report["signature_ok"] = bool(
                    verify_manifest_sha256(pub, manifest["manifest_sha256"], sig["signature_b64"])
                )
        except KeyError:
            pass
        except Exception as e:
            sig_report["signature_ok"] = False
            sig_report["signature_error"] = str(e)

        ok = ok_hashes and (sig_report.get("signature_ok", True) is True)
        return {"ok": ok, "missing": missing, "mismatches": mismatches, "file_count": len(manifest.get("files", [])), **sig_report}

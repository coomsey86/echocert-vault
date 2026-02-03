from __future__ import annotations
import base64
from pathlib import Path
from typing import Optional, Dict
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives import serialization

def _b64(b: bytes) -> str:
    return base64.b64encode(b).decode("ascii")

def _b64d(s: str) -> bytes:
    return base64.b64decode(s.encode("ascii"))

def key_paths(vault_root: Path) -> Dict[str, Path]:
    keys_dir = vault_root / "keys"
    return {"dir": keys_dir, "priv": keys_dir / "ed25519_private.pem", "pub": keys_dir / "ed25519_public.pem"}

def keygen(vault_root: Path) -> Dict[str, str]:
    kp = key_paths(vault_root)
    kp["dir"].mkdir(parents=True, exist_ok=True)
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()

    priv_pem = priv.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    pub_pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    kp["priv"].write_bytes(priv_pem)
    kp["pub"].write_bytes(pub_pem)
    return {"private_key": str(kp["priv"]), "public_key": str(kp["pub"])}

def load_private(vault_root: Path) -> Optional[Ed25519PrivateKey]:
    kp = key_paths(vault_root)
    if not kp["priv"].exists():
        return None
    return serialization.load_pem_private_key(kp["priv"].read_bytes(), password=None)

def load_public(vault_root: Path) -> Optional[Ed25519PublicKey]:
    kp = key_paths(vault_root)
    if not kp["pub"].exists():
        return None
    return serialization.load_pem_public_key(kp["pub"].read_bytes())

def sign_manifest_sha256(priv: Ed25519PrivateKey, manifest_sha256: str) -> str:
    return _b64(priv.sign(manifest_sha256.encode("utf-8")))

def verify_manifest_sha256(pub: Ed25519PublicKey, manifest_sha256: str, signature_b64: str) -> bool:
    try:
        pub.verify(_b64d(signature_b64), manifest_sha256.encode("utf-8"))
        return True
    except Exception:
        return False

def pubkey_pem_b64(pub: Ed25519PublicKey) -> str:
    pem = pub.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return _b64(pem)

def load_public_from_b64(pem_b64: str) -> Ed25519PublicKey:
    return serialization.load_pem_public_key(_b64d(pem_b64))

from pathlib import Path
import shutil, hashlib, json, time

def sha256_file(p: Path) -> str:
    h = hashlib.sha256()
    with p.open("rb") as f:
        for chunk in iter(lambda: f.read(1024*1024), b""):
            h.update(chunk)
    return h.hexdigest()

root = Path.cwd()
pub = root / "demo_public_v2.ecv"
rev = root / "reveal_prompt.json"

if not pub.exists():
    raise SystemExit("[error] demo_public_v2.ecv missing in this folder")
if not rev.exists():
    raise SystemExit("[error] reveal_prompt.json missing in this folder")

stamp = time.strftime("%Y%m%d_%H%M%S")
pack = root / "publish_pack" / f"echocert_vault_proof_pack_{stamp}"
ex = pack / "examples"
ex.mkdir(parents=True, exist_ok=True)

shutil.copy2(pub, ex / pub.name)
shutil.copy2(rev, ex / rev.name)

sums = [
    f"{sha256_file(ex/pub.name)}  examples/{pub.name}",
    f"{sha256_file(ex/rev.name)}  examples/{rev.name}",
]
(pack / "SHA256SUMS.txt").write_text("\n".join(sums) + "\n", encoding="utf-8")

readme = f"""# EchoCert Vault  Proof Pack ({stamp})

Contains:
- examples/{pub.name}
- examples/{rev.name}
- SHA256SUMS.txt
- index.json

Quick verify (offline):
    echocert-vault verify .\\examples\\{pub.name}

Check reveal packet match_ok:
    python -c "import json; print(json.load(open(r'examples/{rev.name}','r',encoding='utf-8'))['match_ok'])"

Expected output: True
"""
(pack / "README.md").write_text(readme, encoding="utf-8")

index = {
    "schema": "echocert-vault-proof-pack",
    "created": stamp,
    "files": {
        "public_bundle": f"examples/{pub.name}",
        "reveal_packet": f"examples/{rev.name}",
        "sha256sums": "SHA256SUMS.txt",
        "readme": "README.md",
    },
}
(pack / "index.json").write_text(json.dumps(index, indent=2) + "\n", encoding="utf-8")

print("[ok] publish pack created:", pack)

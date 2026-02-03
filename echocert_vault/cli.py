from __future__ import annotations

import argparse
import json
from pathlib import Path

from .core.utils import utc_now_iso, safe_write_text, read_text
from .core.vault import init_vault, new_run_id, run_path, artifact_path, events_path, vault_root, runs_dir
from .core.events import append_event
from .core.diffing import unified_diff
from .core.bundle import export_bundle, verify_bundle


def cmd_init(args) -> int:
    root = init_vault(args.vault_dir)
    print(f"[ok] vault initialised: {root}")
    return 0


def cmd_keygen(args) -> int:
    root = init_vault(args.vault_dir)
    from .core.signing import keygen
    paths = keygen(root)
    print("[ok] keys generated")
    print(json.dumps(paths, indent=2, ensure_ascii=False))
    return 0


def cmd_record(args) -> int:
    init_vault(args.vault_dir)
    run_id = args.run_id or new_run_id()
    rp = run_path(run_id, args.vault_dir)
    rp.mkdir(parents=True, exist_ok=True)

    safe_write_text(artifact_path(run_id, "prompt.txt", args.vault_dir), args.prompt)
    safe_write_text(artifact_path(run_id, "output.txt", args.vault_dir), args.output)

    append_event(events_path(run_id, args.vault_dir), {
        "ts": utc_now_iso(),
        "type": "record",
        "run_id": run_id,
        "model": args.model or "unknown",
        "meta": {"source": args.source or "manual"},
    })

    safe_write_text(rp / "SUMMARY.json", json.dumps({
        "run_id": run_id,
        "created": utc_now_iso(),
        "model": args.model or "unknown",
        "status": "RECORDED",
    }, indent=2, ensure_ascii=False) + "\n")

    print(f"[ok] recorded run_id={run_id}")
    return 0


def cmd_decide(args) -> int:
    init_vault(args.vault_dir)
    run_id = args.run_id
    rp = run_path(run_id, args.vault_dir)
    if not rp.exists():
        raise SystemExit(f"[error] run not found: {run_id}")

    decision = args.decision.upper()
    if decision not in ("ACCEPT", "MODIFY", "REJECT"):
        raise SystemExit("[error] decision must be ACCEPT, MODIFY, or REJECT")

    if decision == "MODIFY":
        original = read_text(artifact_path(run_id, "output.txt", args.vault_dir))
        edited = args.edited_output or ""
        safe_write_text(artifact_path(run_id, "output_edited.txt", args.vault_dir), edited)
        safe_write_text(rp / "DIFF.patch", unified_diff(original, edited, "output.txt", "output_edited.txt"))

    append_event(events_path(run_id, args.vault_dir), {
        "ts": utc_now_iso(),
        "type": "decide",
        "run_id": run_id,
        "decision": decision,
        "note": args.note or "",
    })

    summary_path = rp / "SUMMARY.json"
    summary = json.loads(summary_path.read_text(encoding="utf-8")) if summary_path.exists() else {"run_id": run_id}
    summary["status"] = decision
    summary["decided"] = utc_now_iso()
    safe_write_text(summary_path, json.dumps(summary, indent=2, ensure_ascii=False) + "\n")

    print(f"[ok] decided run_id={run_id} decision={decision}")
    return 0


def cmd_export(args) -> int:
    init_vault(args.vault_dir)
    run_id = args.run_id
    rp = run_path(run_id, args.vault_dir)
    if not rp.exists():
        raise SystemExit(f"[error] run not found: {run_id}")

    out = Path(args.out).expanduser().resolve() if args.out else (Path.cwd() / f"{run_id}.ecv")
    vr = vault_root(args.vault_dir)

    export_bundle(rp, out, sign=bool(args.sign), vault_root=vr if args.sign else None)
    print(f"[ok] exported: {out}")
    if args.sign:
        print("[ok] signed: SIGNATURE.json added to bundle")
    return 0


def cmd_redact(args) -> int:
    init_vault(args.vault_dir)
    run_id = args.run_id
    rp = run_path(run_id, args.vault_dir)
    if not rp.exists():
        raise SystemExit(f"[error] run not found: {run_id}")

    out = Path(args.out).expanduser().resolve() if args.out else (Path.cwd() / f"{run_id}.public.ecv")
    vr = vault_root(args.vault_dir)

    from .core.redaction import export_redacted_bundle
    export_redacted_bundle(rp, out, sign=bool(args.sign), vault_root=vr if args.sign else None)

    print(f"[ok] redacted export: {out}")
    if args.sign:
        print("[ok] signed: SIGNATURE.json added to bundle")
    return 0


def cmd_prove(args) -> int:
    bundle = Path(args.bundle).expanduser().resolve()
    if not bundle.exists():
        raise SystemExit(f"[error] file not found: {bundle}")

    from .core.prove import prove_text, prove_file

    if args.text is not None:
        out = prove_text(bundle, args.path, args.text)
    else:
        fp = Path(args.file).expanduser().resolve()
        if not fp.exists():
            raise SystemExit(f"[error] file not found: {fp}")
        out = prove_file(bundle, args.path, fp)

    print(json.dumps(out, indent=2, ensure_ascii=False))
    return 0


def cmd_reveal(args) -> int:
    bundle = Path(args.bundle).expanduser().resolve()
    if not bundle.exists():
        raise SystemExit(f"[error] file not found: {bundle}")

    out_path = Path(args.out).expanduser().resolve()
    from .core.reveal import reveal_text, reveal_file

    if args.text is not None:
        packet = reveal_text(bundle, args.path, args.text, out_path)
    else:
        fp = Path(args.file).expanduser().resolve()
        if not fp.exists():
            raise SystemExit(f"[error] file not found: {fp}")
        packet = reveal_file(bundle, args.path, fp, out_path)

    print(f"[ok] reveal packet written: {out_path}")
    print(json.dumps({
        "match_ok": packet.get("match_ok"),
        "path": packet.get("path"),
        "candidate_sha256": packet.get("candidate_sha256"),
        "expected_commitment": packet.get("expected_commitment"),
        "out": str(out_path),
    }, indent=2, ensure_ascii=False))
    return 0


def cmd_verify(args) -> int:
    bundle = Path(args.bundle).expanduser().resolve()
    if not bundle.exists():
        raise SystemExit(f"[error] file not found: {bundle}")
    print(json.dumps(verify_bundle(bundle), indent=2, ensure_ascii=False))
    return 0


def cmd_list(args) -> int:
    init_vault(args.vault_dir)
    rd = runs_dir(args.vault_dir)
    runs = sorted([p.name for p in rd.iterdir() if p.is_dir()]) if rd.exists() else []
    print(json.dumps(runs, indent=2, ensure_ascii=False))
    return 0


def main() -> int:
    p = argparse.ArgumentParser(prog="echocert-vault", description="EchoCert Vault CLI")
    p.add_argument("--vault-dir", default=None, help="Override vault directory (default: ~/.echocert_vault)")
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("init", help="Initialise local vault"); s.set_defaults(func=cmd_init)
    s = sub.add_parser("keygen", help="Generate signing keys"); s.set_defaults(func=cmd_keygen)

    s = sub.add_parser("record", help="Record prompt/output into a run")
    s.add_argument("--run-id", default=None)
    s.add_argument("--model", default=None)
    s.add_argument("--source", default=None)
    s.add_argument("--prompt", required=True)
    s.add_argument("--output", required=True)
    s.set_defaults(func=cmd_record)

    s = sub.add_parser("decide", help="Attach a human decision to a run")
    s.add_argument("run_id")
    s.add_argument("decision")
    s.add_argument("--edited-output", default=None)
    s.add_argument("--note", default=None)
    s.set_defaults(func=cmd_decide)

    s = sub.add_parser("export", help="Export a run as a portable .ecv bundle")
    s.add_argument("run_id")
    s.add_argument("--out", default=None)
    s.add_argument("--sign", action="store_true")
    s.set_defaults(func=cmd_export)

    s = sub.add_parser("redact", help="Export a public-safe redacted .ecv bundle")
    s.add_argument("run_id")
    s.add_argument("--out", default=None)
    s.add_argument("--sign", action="store_true")
    s.set_defaults(func=cmd_redact)

    s = sub.add_parser("prove", help="Prove a private text/file matches a public commitment")
    s.add_argument("bundle")
    s.add_argument("--path", required=True)
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", default=None)
    g.add_argument("--file", default=None)
    s.set_defaults(func=cmd_prove)

    s = sub.add_parser("reveal", help="Write a reveal packet that discloses content and proves it matches the commitment")
    s.add_argument("bundle")
    s.add_argument("--path", required=True)
    s.add_argument("--out", required=True)
    g = s.add_mutually_exclusive_group(required=True)
    g.add_argument("--text", default=None)
    g.add_argument("--file", default=None)
    s.set_defaults(func=cmd_reveal)

    s = sub.add_parser("verify", help="Verify a .ecv bundle offline")
    s.add_argument("bundle")
    s.set_defaults(func=cmd_verify)

    s = sub.add_parser("list", help="List runs in the vault"); s.set_defaults(func=cmd_list)

    args = p.parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    raise SystemExit(main())

from __future__ import annotations
from typing import Dict, Any, List
from .utils import canonical_json, sha256_bytes

def event_hash(event: Dict[str, Any]) -> str:
    return sha256_bytes(canonical_json(event))

def chain_next(prev_chain_hash: str, event_h: str) -> str:
    payload = (prev_chain_hash + event_h).encode("utf-8")
    return sha256_bytes(payload)

def build_chain(events: List[Dict[str, Any]], genesis: str = "0"*64) -> List[Dict[str, str]]:
    out = []
    prev = genesis
    for e in events:
        eh = event_hash(e)
        ch = chain_next(prev, eh)
        out.append({"event_hash": eh, "chain_hash": ch})
        prev = ch
    return out

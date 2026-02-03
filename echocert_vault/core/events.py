from __future__ import annotations
import json
from pathlib import Path
from typing import Any, Dict, List
from .utils import canonical_json, ensure_dir

def append_event(events_path: Path, event: Dict[str, Any]) -> None:
    ensure_dir(events_path.parent)
    with events_path.open("ab") as f:
        f.write(canonical_json(event))
        f.write(b"\n")

def read_events(events_path: Path) -> List[Dict[str, Any]]:
    if not events_path.exists():
        return []
    events: List[Dict[str, Any]] = []
    with events_path.open("rb") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            events.append(json.loads(line.decode("utf-8")))
    return events

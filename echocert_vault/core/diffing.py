from __future__ import annotations
import difflib

def unified_diff(old: str, new: str, fromfile: str = "original", tofile: str = "modified") -> str:
    old_lines = old.splitlines(keepends=True)
    new_lines = new.splitlines(keepends=True)
    return "".join(difflib.unified_diff(old_lines, new_lines, fromfile=fromfile, tofile=tofile))

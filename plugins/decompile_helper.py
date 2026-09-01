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

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

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
typedef unsigned short     word;
typedef unsigned short     ushort;
typedef unsigned int       uint;
typedef unsigned int       dword;
typedef unsigned long      ulong;
typedef unsigned long long ulonglong;
typedef unsigned long long qword;

typedef void code(void);

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


def parse_signature(text):
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped or stripped.startswith("//"):
            continue
        m = re.match(r"^(.*?)\s+([\w.\-]+)\s*\((.*)\)\s*$", stripped)
        if m:
            return m.group(1).strip(), m.group(2), m.group(3).strip()
        break
    return None


def collect_functions(decomp_dir):
    funcs = []
    for path in sorted(decomp_dir.glob("*.c")):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        sig = parse_signature(text)
        if sig is None:
            continue
        funcs.append((sig[0], sig[1], sig[2], path))
    return funcs


def write_types(out_path):
    out_path.write_text(GHIDRA_TYPES_TEMPLATE, encoding="utf-8")
    return out_path


def write_compat(out_path):
    out_path.write_text(COMPAT_TEMPLATE, encoding="utf-8")
    return out_path


def write_prototypes(decomp_dir, out_path):
    lines = [
        "/* Auto-generated by decompile_helper.py. */",
        "#ifndef FUNCTION_PROTOTYPES_H",
        "#define FUNCTION_PROTOTYPES_H",
        "",
    ]
    seen = set()
    for ret, name, params, path in collect_functions(decomp_dir):
        if should_skip(path):
            continue
        if name in seen:
            continue
        seen.add(name)
        psig = f"extern {ret} {name}({params});"
        lines.append(psig)
    lines.append("")
    lines.append("#endif")
    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


def parse_elf(path):
    data = path.read_bytes()
    if data[:4] != b"\x7fELF" or data[4] != 2:
        return None
    segments = []
    phoff = struct.unpack_from("<Q", data, 0x20)[0]
    phentsize = struct.unpack_from("<H", data, 0x36)[0]
    phnum = struct.unpack_from("<H", data, 0x38)[0]
    for i in range(phnum):
        off = phoff + i * phentsize
        p_type = struct.unpack_from("<I", data, off)[0]
        p_offset = struct.unpack_from("<Q", data, off + 8)[0]
        p_vaddr = struct.unpack_from("<Q", data, off + 16)[0]
        p_filesz = struct.unpack_from("<Q", data, off + 32)[0]
        if p_type == 1:
            segments.append((p_vaddr, p_offset, p_filesz))

    globals_map = {}
    shoff = struct.unpack_from("<Q", data, 0x28)[0]
    shentsize = struct.unpack_from("<H", data, 0x3A)[0]
    shnum = struct.unpack_from("<H", data, 0x3C)[0]
    sections = []
    for i in range(shnum):
        o = shoff + i * shentsize
        sh_type = struct.unpack_from("<I", data, o + 4)[0]
        sh_offset = struct.unpack_from("<Q", data, o + 0x18)[0]
        sh_size = struct.unpack_from("<Q", data, o + 0x20)[0]
        sh_link = struct.unpack_from("<I", data, o + 0x28)[0]
        sh_entsize = struct.unpack_from("<Q", data, o + 0x38)[0]
        sections.append((sh_type, sh_offset, sh_size, sh_link, sh_entsize))
    for sh_type, sh_offset, sh_size, sh_link, sh_entsize in sections:
        if sh_type == 2:
            str_off = sections[sh_link][1]
            count = sh_size // sh_entsize
            for i in range(count):
                o = sh_offset + i * sh_entsize
                st_name, st_info = struct.unpack_from("<IB", data, o)
                st_value, st_size = struct.unpack_from("<QQ", data, o + 8)
                if (st_info & 0xF) != 1:
                    continue
                end = data.find(b"\x00", str_off + st_name)
                name = data[str_off + st_name:end].decode("utf-8", "replace")
                if not name or name.startswith("_") or "@" in name or "." in name:
                    continue
                globals_map[name] = (st_value, st_size)
            break

    def va_to_offset(va):
        for vaddr, offset, filesz in segments:
            if vaddr <= va < vaddr + filesz:
                return offset + (va - vaddr)
        return None

    return {
        "kind": "elf",
        "data": data,
        "va_to_offset": va_to_offset,
        "globals": globals_map,
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
    }


def collect_dat_refs(decomp_dir):
    addrs = set()
    pattern = re.compile(r"\bDAT_([0-9a-fA-F]+)\b")
    for path in decomp_dir.glob("*.c"):
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in pattern.finditer(text):
            addrs.add(m.group(1).lower())
    return sorted(addrs, key=lambda s: int(s, 16))


def collect_used_names(decomp_dir):
    names = set()
    ident = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
    for path in decomp_dir.glob("*.c"):
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


def guess_global_type(name, size, used_text):
    if re.search(r"\b" + re.escape(name) + r"\b\s*=\s*fopen", used_text) or \
       re.search(r"\b" + re.escape(name) + r"\b\s*[!=]=\s*(stdin|stdout|stderr)", used_text):
        return "FILE *%s" % name
    if size >= 64:
        return "char %s[0x%x]" % (name, size)
    if size == 8:
        return "long %s" % name
    if size == 4:
        return "int %s" % name
    if size == 2:
        return "short %s" % name
    if size == 1:
        return "char %s" % name
    return "unsigned char %s[0x%x]" % (name, size)


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


def referenced_globals(binary, decomp_dir):
    used = " ".join(
        p.read_text(encoding="utf-8", errors="replace")
        for p in decomp_dir.glob("*.c")
    )
    used_names = collect_used_names(decomp_dir)
    result = []
    for name, (addr, size) in sorted(binary["globals"].items()):
        if name not in used_names:
            continue
        result.append((name, addr, size, guess_global_type(name, size, used)))
    return result


def dat_entries(binary, decomp_dir):
    va_to_offset = binary["va_to_offset"]
    data = binary["data"]
    entries = []
    for hexstr in collect_dat_refs(decomp_dir):
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


def write_data_defs(binary, decomp_dir, out_path):
    lines = [
        "/* Auto-generated by decompile_helper.py. */",
        "#include \"ghidra_types.h\"",
        "",
    ]

    for hexstr, is_str, raw in dat_entries(binary, decomp_dir):
        if not raw:
            lines.append("/* DAT_%s: cannot map to file */" % hexstr)
            lines.append("unsigned char DAT_%s[16] = {0};" % hexstr)
        elif is_str:
            lines.append('const char DAT_%s[] = "%s";' % (hexstr, escape_bytes(raw)))
        else:
            body = ", ".join("0x%02x" % b for b in raw) or "0"
            lines.append("const unsigned char DAT_%s[] = {%s};" % (hexstr, body))
        lines.append("")

    for name, addr, size, decl in referenced_globals(binary, decomp_dir):
        lines.append("/* %s @ 0x%x (0x%x bytes) */" % (name, addr, size))
        lines.append("%s;" % decl)
        lines.append("")

    out_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return out_path


def write_globals(binary, decomp_dir, out_path):
    lines = [
        "/* Auto-generated by decompile_helper.py. */",
        "#ifndef GLOBALS_H",
        "#define GLOBALS_H",
        "",
        "#include \"ghidra_types.h\"",
        "",
    ]
    for name, addr, size, decl in referenced_globals(binary, decomp_dir):
        lines.append("/* %s @ 0x%x */" % (name, addr))
        lines.append("extern %s;" % decl)
        lines.append("")
    for hexstr, is_str, raw in dat_entries(binary, decomp_dir):
        ctype = "const char" if is_str else "const unsigned char"
        lines.append("extern %s DAT_%s[];" % (ctype, hexstr))
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
        "$objs = @()",
    ]
    for f in c_files:
        lines.append('& cl /nologo /utf-8 /w /c /I. /FI ghidra_types.h /FI compat.h /FI function_prototypes.h /FI globals.h "%s" /Fo"obj\\%s.obj"' % (f, Path(f).stem))
        lines.append('if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }')
        lines.append('$objs += "obj\\%s.obj"' % Path(f).stem)
    lines += [
        "New-Item -ItemType Directory -Force -Path obj | Out-Null",
        "& link /nologo /out:%s $objs data_defs.obj" % exe_name,
        "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }",
        'Write-Host "Built %s"' % exe_name,
    ]
    (out_dir / "build.ps1").write_text("\n".join(lines) + "\n", encoding="utf-8")


def do_all(binary_path, decomp_dir, out_dir):
    out_dir.mkdir(parents=True, exist_ok=True)
    binary = parse_elf(binary_path) or parse_pe(binary_path)
    if binary is None:
        sys.exit("Unsupported binary format: %s" % binary_path)

    kept = [p for p in sorted(decomp_dir.glob("*.c")) if not should_skip(p)]
    skipped = [p for p in sorted(decomp_dir.glob("*.c")) if should_skip(p)]

    write_types(out_dir / "ghidra_types.h")
    write_compat(out_dir / "compat.h")
    write_prototypes(decomp_dir, out_dir / "function_prototypes.h")
    write_globals(binary, decomp_dir, out_dir / "globals.h")
    write_data_defs(binary, decomp_dir, out_dir / "data_defs.c")

    for p in kept:
        (out_dir / p.name).write_bytes(p.read_bytes())

    write_makefile(out_dir, [p.name for p in kept] + ["data_defs.c"], "rebuilt.exe")
    write_build_ps1(out_dir, [p.name for p in kept] + ["data_defs.c"], "rebuilt.exe")

    print("Output: %s" % out_dir)
    print("  kept functions:    %d" % len(kept))
    print("  skipped stubs:     %d" % len(skipped))
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
            "decomp_build" / ("%s_build" % binary_path.stem)
        )
        do_all(binary_path, decomp_dir, out_dir)


if __name__ == "__main__":
    main()
